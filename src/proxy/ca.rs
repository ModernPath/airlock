//! The certificate authority behind proxy-tool TLS interception.
//!
//! One CA is generated per daemon, inside the async runtime and therefore
//! after daemonization — key generation is pure CPU and touches none of the
//! fork-sensitive startup path. The private key lives in memory only and dies
//! with the process; nothing needs to trust it across restarts, because its
//! only consumers are children the same daemon spawned.
//!
//! Two things keep a leaked key from being a general-purpose signing oracle:
//! the certificate is marked `CA:TRUE, pathlen:0`, and it carries X.509 Name
//! Constraints permitting only the DNS names the configured routes can reach.

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use thiserror::Error;
use time::{Duration as TimeDuration, OffsetDateTime};

use super::{HostPattern, ProxyPolicy};

/// How long the CA certificate stays valid. Longer than any daemon is
/// expected to live; a restart mints a fresh one anyway.
const CA_VALIDITY_DAYS: i64 = 365;

/// How long a minted leaf stays valid. Kept under Apple's 398-day ceiling for
/// TLS server certificates so a stricter verifier cannot object to it.
const LEAF_VALIDITY_DAYS: i64 = 30;

/// Backdating absorbs clock skew between the daemon and the tool, which on a
/// single host is small but not guaranteed to be zero.
const BACKDATE_HOURS: i64 = 1;

/// Upper bound on cached leaf certificates.
///
/// A route table is small, but a wildcard route makes the set of reachable
/// host names agent-controlled: `curl https://$RANDOM.example.com` mints a new
/// leaf every time. The cap turns that into bounded work rather than bounded
/// memory growth. Clearing wholesale on overflow is deliberate — an eviction
/// policy would be more state to audit for no practical gain.
const LEAF_CACHE_CAP: usize = 256;

/// Something went wrong minting or writing certificates.
#[derive(Debug, Error)]
pub enum CaError {
    /// Certificate generation failed.
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),

    /// rustls rejected the generated certificate or key.
    #[error("TLS configuration failed: {0}")]
    Rustls(#[from] rustls::Error),

    /// Writing the CA certificate to the runtime directory failed.
    #[error("failed to write CA certificate to {path}: {source}")]
    Write {
        /// The path that could not be written.
        path: std::path::PathBuf,
        /// The underlying I/O error.
        source: io::Error,
    },
}

/// A per-daemon MITM certificate authority plus its minted-leaf cache.
pub struct ProxyCa {
    /// Signs leaf certificates. Owns the CA private key.
    issuer: Issuer<'static, KeyPair>,
    /// PEM encoding of the CA certificate. Public by construction — this is
    /// what the tool is told to trust.
    cert_pem: String,
    /// One key shared by every leaf. Leaves are ephemeral and never leave the
    /// daemon's own TLS stack, so per-host keys would buy nothing.
    leaf_key: KeyPair,
    /// The same key in the DER form rustls wants, kept because `KeyPair` does
    /// not hand out a reusable `PrivateKeyDer`.
    leaf_key_der: PrivatePkcs8KeyDer<'static>,
    /// Host name → ready-to-use server config.
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl std::fmt::Debug for ProxyCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProxyCa { .. }")
    }
}

impl ProxyCa {
    /// Generate a CA constrained to the DNS names `policies` can reach.
    ///
    /// Returns `None` when no policy declares a route — a daemon with no proxy
    /// tool generates no CA and writes no certificate.
    pub fn generate<'a>(
        policies: impl Iterator<Item = &'a ProxyPolicy>,
    ) -> Result<Option<Self>, CaError> {
        let permitted = permitted_dns_names(policies);
        if permitted.is_empty() {
            return Ok(None);
        }

        let now = OffsetDateTime::now_utc();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name("Airlock proxy CA");
        params.not_before = now - TimeDuration::hours(BACKDATE_HOURS);
        params.not_after = now + TimeDuration::days(CA_VALIDITY_DAYS);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        // A permitted DNS subtree also covers the apex and every deeper label,
        // so `*.example.com` admits `example.com` and `a.b.example.com` too.
        // That is fine here: the constraint is the outer bound on what a
        // leaked key could ever sign, while route matching — which does
        // distinguish those names — remains the gate on what actually gets a
        // certificate minted.
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: permitted.into_iter().map(GeneralSubtree::DnsName).collect(),
            excluded_subtrees: Vec::new(),
        });

        let cert = params.self_signed(&key)?;
        let cert_pem = cert.pem();
        let issuer = Issuer::new(params, key);

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let leaf_key_der = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());

        Ok(Some(ProxyCa {
            issuer,
            cert_pem,
            leaf_key,
            leaf_key_der,
            cache: Mutex::new(HashMap::new()),
        }))
    }

    /// The CA certificate in PEM form.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Write the CA certificate where a sandboxed tool can read it.
    ///
    /// The file is world-readable (it is a public certificate) but is created
    /// fresh rather than truncated, so a leftover symlink from a crashed
    /// daemon cannot redirect the write.
    pub fn write_cert_pem(&self, path: &Path) -> Result<(), CaError> {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let write = || -> io::Result<()> {
            let _ = std::fs::remove_file(path);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(path)?;
            file.write_all(self.cert_pem.as_bytes())?;
            // `mode` on the open is subject to the process umask, and the
            // daemon's is whatever the operator's shell handed it. fchmod is
            // not, so this is what actually fixes the mode.
            file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
            file.sync_all()
        };
        write().map_err(|source| CaError::Write {
            path: path.to_path_buf(),
            source,
        })
    }

    /// A rustls server config presenting a leaf certificate for `host`.
    ///
    /// `host` is the CONNECT authority, never the client's SNI: the authority
    /// is what selected the route and what the upstream certificate will be
    /// checked against, so it is the only name the tool may be shown.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, CaError> {
        let key = host.to_ascii_lowercase();

        if let Some(config) = self.lock_cache().get(&key) {
            return Ok(Arc::clone(config));
        }

        let config = Arc::new(self.build_server_config(&key)?);

        let mut cache = self.lock_cache();
        if cache.len() >= LEAF_CACHE_CAP {
            cache.clear();
        }
        cache.insert(key, Arc::clone(&config));
        Ok(config)
    }

    fn lock_cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<ServerConfig>>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn build_server_config(&self, host: &str) -> Result<ServerConfig, CaError> {
        let leaf = self.mint_leaf(host)?;
        // The client trusts the CA directly, so the leaf alone is a complete
        // chain; sending the CA again would only add bytes.
        let chain = vec![leaf];
        let key = PrivateKeyDer::Pkcs8(self.leaf_key_der.clone_key());

        let mut config = ServerConfig::builder_with_provider(Arc::clone(&super::CRYPTO_PROVIDER))
            .with_protocol_versions(super::TLS_VERSIONS)?
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
        // HTTP/1.1 only: the request path the proxy vets is an HTTP/1.1 one.
        // Offering nothing else keeps a client from negotiating h2 and then
        // speaking a framing this proxy does not parse.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }

    /// Mint a server certificate for `host`, signed by the CA.
    fn mint_leaf(&self, host: &str) -> Result<CertificateDer<'static>, CaError> {
        let now = OffsetDateTime::now_utc();

        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name = distinguished_name(host);
        params.not_before = now - TimeDuration::hours(BACKDATE_HOURS);
        params.not_after = now + TimeDuration::days(LEAF_VALIDITY_DAYS);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;

        let cert = params.signed_by(&self.leaf_key, &self.issuer)?;
        Ok(CertificateDer::from(cert.der().to_vec()))
    }
}

/// The union of DNS names every route in `policies` can reach, deduplicated.
///
/// An exact route contributes its own name; a wildcard route contributes its
/// suffix, which as a Name Constraints subtree covers every label under it.
fn permitted_dns_names<'a>(policies: impl Iterator<Item = &'a ProxyPolicy>) -> Vec<String> {
    let mut names: Vec<String> = policies
        .flat_map(|policy| policy.routes.iter())
        .map(|route| match &route.host {
            HostPattern::Exact(name) => name.clone(),
            HostPattern::Wildcard(suffix) => suffix.clone(),
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::ProxyRoute;

    fn policy(hosts: &[&str]) -> ProxyPolicy {
        ProxyPolicy {
            routes: hosts
                .iter()
                .map(|h| ProxyRoute {
                    host: HostPattern::parse(h).unwrap(),
                    inject: None,
                    allow: Vec::new(),
                    deny: Vec::new(),
                })
                .collect(),
        }
    }

    pub(crate) fn test_ca() -> ProxyCa {
        ProxyCa::generate([policy(&["upstream.test"])].iter())
            .unwrap()
            .unwrap()
    }

    #[test]
    fn no_routes_means_no_ca() {
        assert!(ProxyCa::generate(std::iter::empty()).unwrap().is_none());
    }

    #[test]
    fn permitted_names_are_the_union_of_route_hosts() {
        let a = policy(&["*.googleapis.com", "api.example.com"]);
        let b = policy(&["api.example.com", "other.test"]);
        assert_eq!(
            permitted_dns_names([a, b].iter()),
            vec![
                "api.example.com".to_string(),
                "googleapis.com".to_string(),
                "other.test".to_string(),
            ]
        );
    }

    #[test]
    fn ca_certificate_carries_name_constraints_and_pathlen_zero() {
        let ca = ProxyCa::generate([policy(&["*.googleapis.com"])].iter())
            .unwrap()
            .unwrap();
        let pem = ca.cert_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));

        let der = pem_to_der(pem);
        // Name Constraints is OID 2.5.29.30 → DER 06 03 55 1D 1E.
        assert!(
            contains(&der, &[0x06, 0x03, 0x55, 0x1d, 0x1e]),
            "CA certificate must carry a nameConstraints extension"
        );
        // The permitted subtree is the wildcard's suffix, as an IA5String.
        assert!(
            contains(&der, b"googleapis.com"),
            "nameConstraints must permit the routed suffix"
        );
        // basicConstraints (2.5.29.19) with CA:TRUE and pathLenConstraint 0:
        // SEQUENCE { BOOLEAN TRUE, INTEGER 0 } == 30 06 01 01 FF 02 01 00.
        assert!(
            contains(&der, &[0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00]),
            "CA certificate must be CA:TRUE with pathlen:0"
        );
    }

    #[test]
    fn leaf_san_is_the_connect_authority() {
        let ca = test_ca();
        let der = ca.mint_leaf("upstream.test").unwrap().to_vec();
        assert!(
            contains(&der, b"upstream.test"),
            "leaf must carry the authority as a SAN"
        );
        assert!(
            !contains(&der, b"other.test"),
            "leaf must not carry any other name"
        );
    }

    #[test]
    fn leaf_configs_are_cached_per_host() {
        let ca = test_ca();
        let first = ca.server_config("upstream.test").unwrap();
        let second = ca.server_config("UPSTREAM.test").unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "host lookup must be case-insensitive and hit the cache"
        );
        assert_eq!(ca.lock_cache().len(), 1);
    }

    #[test]
    fn leaf_cache_is_capped() {
        let ca = test_ca();
        for i in 0..=LEAF_CACHE_CAP {
            ca.server_config(&format!("h{i}.upstream.test")).unwrap();
        }
        assert!(
            ca.lock_cache().len() <= LEAF_CACHE_CAP,
            "cache must not grow past its cap"
        );
    }

    #[test]
    fn leaf_offers_http11_only() {
        let ca = test_ca();
        let config = ca.server_config("upstream.test").unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn cert_pem_is_written_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("airlock-ca.pem");
        let ca = test_ca();
        ca.write_cert_pem(&path).unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), ca.cert_pem());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "the tool's sandbox must be able to read it");
    }

    #[test]
    fn cert_pem_write_replaces_a_leftover_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("airlock-ca.pem");
        std::fs::write(&path, "stale").unwrap();
        let ca = test_ca();
        ca.write_cert_pem(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), ca.cert_pem());
    }

    #[test]
    fn ca_private_key_never_reaches_the_pem() {
        let ca = test_ca();
        assert!(!ca.cert_pem().contains("PRIVATE KEY"));
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    fn pem_to_der(pem: &str) -> Vec<u8> {
        use base64::Engine;
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
