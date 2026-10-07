//! NDJSON wire protocol for the v2 daemon.
//!
//! One daemon serves every project through sessions ([Sessions] in
//! docs/airlock-v2-design.md). Two message families ride the same Unix
//! socket, split in code as well as on the wire because they are gated
//! differently: the *admin* family (`Register`, `Reload`, session
//! list/revoke/renew, `Tools`, `Logs`, `Stop`) needs `admin.token` and comes
//! only from a launcher outside any sandbox; the *session* family (`Exec`,
//! `List`, `Check`) needs a session token bound to a process tree. See
//! docs/airlock-v2-technical-guidance.md, "Two message families" and "A
//! principal on every request".
//!
//! Connection shape:
//! 1. The client sends [`ClientHello`] on the first line.
//! 2. The daemon answers with [`DaemonMessage::Hello`].
//! 3. The client sends exactly one [`Request`].
//! 4. For [`SessionRequest::Exec`], the client may follow with any number of
//!    [`StdinFrame::Stdin`] lines, then [`StdinFrame::StdinEof`]. These are
//!    not `SessionRequest` variants: a connection carries one `Request`, and
//!    `Stdin`/`StdinEof` are a separate, smaller vocabulary that only makes
//!    sense while an `Exec` is in flight.
//! 5. The daemon streams back zero or more [`DaemonMessage`] lines
//!    (`Stdout`/`Stderr`/...) ending in `Exit`, `Error`, or one of the
//!    admin-family responses.
//!
//! Every request-shaped type denies unknown fields
//! (docs/airlock-v2-technical-guidance.md, "Config on the wire fails
//! closed"): a daemon built against an older protocol version rejects a
//! request carrying a field it doesn't understand instead of silently
//! ignoring a policy the launcher expected enforced. [`PROTOCOL_VERSION`] is
//! the backstop that catches most of this earlier, in the handshake.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

// ─── Protocol version and frame limits ───────────────────────────────────────

/// The wire protocol version. Bumped whenever a message shape changes,
/// including the `Register` config payload. Two binaries with the same
/// value interoperate; the launcher's "incompatible daemon" error compares
/// this, not the binary version (docs/airlock-v2-technical-guidance.md,
/// "One protocol version, separate from the binary version").
pub const PROTOCOL_VERSION: u32 = 4;

/// NDJSON line cap for the session family, which comes from a sandboxed,
/// untrusted client.
pub const MAX_SESSION_LINE_BYTES: usize = 1024 * 1024;

/// NDJSON line cap for the admin family. `Register` carries a merged config,
/// an environment snapshot, a filtered `PATH` and secret values, so it needs
/// more room than the session cap; it is still bounded because the launcher
/// that sends it is trusted (docs/airlock-v2-technical-guidance.md, "Admin
/// frames have their own size limit").
pub const MAX_ADMIN_LINE_BYTES: usize = 16 * 1024 * 1024;

// ─── Wire config ──────────────────────────────────────────────────────────────

/// The merged config carried by `Register`/`Reload`: the TOML raw types,
/// normalized by the launcher (absolute paths, concrete secret sources). They
/// deny unknown fields at every level, so a daemon that does not know a field
/// rejects the request instead of ignoring a policy the launcher expected
/// enforced.
pub type WireConfig = crate::config::RawConfig;

// ─── NDJSON line encoding ─────────────────────────────────────────────────────

/// Serialize `value` as a single NDJSON line: compact JSON followed by `\n`.
///
/// `serde_json` escapes control characters (including raw newlines) inside
/// JSON strings, so a well-behaved `Serialize` impl can never produce an
/// embedded `\n`. The assertion exists to catch a future custom `Serialize`
/// impl that writes raw bytes some other way.
pub fn encode_line<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes =
        serde_json::to_vec(value).expect("protocol message types always serialize to JSON");
    assert!(
        !bytes.contains(&b'\n'),
        "serialized message must not contain an embedded newline"
    );
    bytes.push(b'\n');
    bytes
}

// ─── Parse errors for id/token types ─────────────────────────────────────────

/// Errors parsing a [`SessionId`], [`SessionToken`] or [`AdminToken`] from
/// its wire string form.
///
/// Deliberately carries no detail about *why* a token was malformed: unlike
/// a session id, a token string is sensitive, and echoing fragments of a
/// rejected one back in an error message is the kind of thing that ends up
/// in a log.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    /// Not 6 lowercase hex characters.
    #[error("invalid session id {0:?}: must be 6 lowercase hex characters")]
    InvalidSessionId(String),
    /// Not `airlock_<6 hex>_<43 base64url-no-pad>` decoding to 32 bytes.
    #[error("invalid session token")]
    InvalidSessionToken,
    /// Not 64 lowercase hex characters.
    #[error("invalid admin token")]
    InvalidAdminToken,
}

/// Lowercase-hex-encode `bytes`. Hand-rolled rather than pulling in a `hex`
/// crate for six lines of code; [`src/redact.rs`](../redact.rs) does the same.
fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

fn is_lowercase_hex_byte(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn is_base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Constant-time byte equality, used by every token's `PartialEq` so that
/// `==` on a token is never a timing side channel.
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

// ─── SessionId ────────────────────────────────────────────────────────────────

const SESSION_ID_LEN: usize = 6;

/// A session identifier: 6 lowercase hex characters.
///
/// Not secret — it is shown in `session list`, logged with every `exec`, and
/// is the first 6 characters an operator reads off a token. Only the token's
/// random part is a bearer credential.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SessionId(String);

impl SessionId {
    /// Generate a fresh random id. The daemon regenerates on collision; this
    /// function always returns a well-formed id, never a guaranteed-unique
    /// one.
    pub fn generate() -> Self {
        let mut buf = [0u8; SESSION_ID_LEN / 2];
        getrandom::fill(&mut buf).expect("the system RNG must be available");
        SessionId(hex_encode(&buf))
    }

    /// Parse a 6-lowercase-hex-character id.
    pub fn parse(s: &str) -> Result<Self, ProtocolError> {
        if s.len() == SESSION_ID_LEN && s.bytes().all(is_lowercase_hex_byte) {
            Ok(SessionId(s.to_string()))
        } else {
            Err(ProtocolError::InvalidSessionId(s.to_string()))
        }
    }

    /// The id as a plain string, e.g. for display or as a map key.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for SessionId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        SessionId::parse(&s).map_err(serde::de::Error::custom)
    }
}

// ─── SessionToken ─────────────────────────────────────────────────────────────

/// `airlock_`, then 6 lowercase hex chars (the session id), then `_`, then
/// 43 base64url-no-pad characters encoding 32 random bytes.
const TOKEN_PREFIX: &str = "airlock_";
const TOKEN_SECRET_LEN: usize = 43;
const TOKEN_SECRET_BYTES: usize = 32;

/// A session bearer token.
///
/// The prefix and embedded id let a secret scanner recognize the token and
/// let logs name the session without the secret part (UX doc, "Open UX
/// questions" — session id and token format). `Debug` prints only the id;
/// `PartialEq` compares the secret part in constant time, so `==` is never a
/// timing side channel and there is no faster-but-unsafe alternative to reach
/// for by mistake. The secret part zeroizes on drop.
pub struct SessionToken {
    id: SessionId,
    secret: Zeroizing<String>,
}

impl SessionToken {
    /// Mint a fresh token for `id` from 32 bytes of CSPRNG output.
    pub fn generate(id: SessionId) -> Self {
        let mut buf = [0u8; TOKEN_SECRET_BYTES];
        getrandom::fill(&mut buf).expect("the system RNG must be available");
        let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
        debug_assert_eq!(secret.len(), TOKEN_SECRET_LEN);
        SessionToken {
            id,
            secret: Zeroizing::new(secret),
        }
    }

    /// Parse `airlock_<id>_<secret>`, validating the fixed layout and that
    /// the secret decodes to exactly 32 bytes.
    ///
    /// Parses on raw bytes and only converts to `&str` after confirming
    /// every byte is ASCII in the expected ranges, so a malformed,
    /// adversary-controlled string can't panic this on a UTF-8 char
    /// boundary.
    pub fn parse(s: &str) -> Result<Self, ProtocolError> {
        let rest = s
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(ProtocolError::InvalidSessionToken)?;
        let bytes = rest.as_bytes();
        if bytes.len() != SESSION_ID_LEN + 1 + TOKEN_SECRET_LEN {
            return Err(ProtocolError::InvalidSessionToken);
        }
        let (id_bytes, tail) = bytes.split_at(SESSION_ID_LEN);
        let (sep, secret_bytes) = tail.split_at(1);
        let shape_ok = id_bytes.iter().copied().all(is_lowercase_hex_byte)
            && sep == b"_"
            && secret_bytes.iter().copied().all(is_base64url_byte);
        if !shape_ok {
            return Err(ProtocolError::InvalidSessionToken);
        }
        // Safe: every byte above was checked to be ASCII in a known range.
        let id_str = std::str::from_utf8(id_bytes).expect("validated ASCII above");
        let secret_str = std::str::from_utf8(secret_bytes)
            .expect("validated ASCII above")
            .to_string();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&secret_str)
            .map_err(|_| ProtocolError::InvalidSessionToken)?;
        if decoded.len() != TOKEN_SECRET_BYTES {
            return Err(ProtocolError::InvalidSessionToken);
        }
        Ok(SessionToken {
            id: SessionId(id_str.to_string()),
            secret: Zeroizing::new(secret_str),
        })
    }

    /// The session this token authenticates. Not secret.
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Render the full token string that crosses the socket. Named like
    /// `Secret::expose_secret` ([src/secrets.rs](../secrets.rs)) so every
    /// call site that exposes the value is grep-able.
    pub fn expose_secret(&self) -> String {
        format!("{TOKEN_PREFIX}{}_{}", self.id.0, *self.secret)
    }

    /// Constant-time equality. Same as `==`; provided under this name
    /// because call sites that compare a presented token against a stored
    /// one read better naming the property they rely on.
    pub fn ct_eq(&self, other: &SessionToken) -> bool {
        self == other
    }
}

impl PartialEq for SessionToken {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && ct_eq_bytes(self.secret.as_bytes(), other.secret.as_bytes())
    }
}

impl Eq for SessionToken {}

impl Clone for SessionToken {
    fn clone(&self) -> Self {
        SessionToken {
            id: self.id.clone(),
            secret: self.secret.clone(),
        }
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionToken")
            .field("id", &self.id)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl Serialize for SessionToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.expose_secret())
    }
}

impl<'de> Deserialize<'de> for SessionToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        SessionToken::parse(&s).map_err(serde::de::Error::custom)
    }
}

// ─── AdminToken ───────────────────────────────────────────────────────────────

const ADMIN_TOKEN_LEN: usize = 64;

/// The daemon's admin credential: 64 lowercase hex characters (32 random
/// bytes), written to `<runtime base>/admin.token` with mode 0600.
///
/// One per daemon, not per session, so unlike [`SessionToken`] it carries no
/// id. `Debug` never prints it. Zeroizes on drop.
pub struct AdminToken(Zeroizing<String>);

impl AdminToken {
    /// Mint a fresh token from 32 bytes of CSPRNG output.
    pub fn generate() -> Self {
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf).expect("the system RNG must be available");
        AdminToken(Zeroizing::new(hex_encode(&buf)))
    }

    /// Parse 64 lowercase hex characters.
    pub fn parse(s: &str) -> Result<Self, ProtocolError> {
        if s.len() == ADMIN_TOKEN_LEN && s.bytes().all(is_lowercase_hex_byte) {
            Ok(AdminToken(Zeroizing::new(s.to_string())))
        } else {
            Err(ProtocolError::InvalidAdminToken)
        }
    }

    /// The raw token string. Named like `Secret::expose_secret`
    /// ([src/secrets.rs](../secrets.rs)).
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Constant-time equality; see [`SessionToken::ct_eq`].
    pub fn ct_eq(&self, other: &AdminToken) -> bool {
        self == other
    }
}

impl PartialEq for AdminToken {
    fn eq(&self, other: &Self) -> bool {
        ct_eq_bytes(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl Eq for AdminToken {}

impl Clone for AdminToken {
    fn clone(&self) -> Self {
        AdminToken(self.0.clone())
    }
}

impl fmt::Debug for AdminToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AdminToken").field(&"[REDACTED]").finish()
    }
}

impl Serialize for AdminToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AdminToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        AdminToken::parse(&s).map_err(serde::de::Error::custom)
    }
}

// ─── Handshake ────────────────────────────────────────────────────────────────

/// The client's first line on every connection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientHello {
    /// Must equal [`PROTOCOL_VERSION`] for the connection to proceed.
    pub protocol: u32,
    /// The client binary's version, for the daemon's own diagnostics.
    pub version: String,
}

impl ClientHello {
    /// The hello this binary sends.
    pub fn current() -> Self {
        ClientHello {
            protocol: PROTOCOL_VERSION,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// How the daemon was started. Carried in [`DaemonMessage::Hello`] so a
/// launcher can decide whether it may replace an idle daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonMode {
    /// Started on demand by a launcher; exits after a grace period with no
    /// sessions.
    Automatic,
    /// Installed via `daemon install`; stays up with no sessions.
    Service,
    /// Started by `daemon start` by hand.
    Manual,
}

// ─── Auth and request envelope ───────────────────────────────────────────────

/// The credential on a [`Request`], resolved to a `Principal` by the Unix
/// listener before any handler runs (docs/airlock-v2-technical-guidance.md,
/// "A principal on every request").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Auth {
    /// A session token, checked against the session's process-tree binding.
    Session {
        /// The presented token.
        token: SessionToken,
    },
    /// The admin token, checked by constant-time comparison against
    /// `admin.token`.
    Admin {
        /// The presented token.
        token: AdminToken,
    },
}

/// The request body, tagged by family so the daemon can check it against
/// `auth.kind` before dispatch — a request whose family doesn't match its
/// auth kind is well-formed on the wire and refused at the handler, with
/// [`ErrorKind::Unauthorized`] (docs/airlock-v2-technical-guidance.md, "Two
/// message families").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum RequestBody {
    /// An admin-family request. Needs [`Auth::Admin`].
    Admin(AdminRequest),
    /// A session-family request. Needs [`Auth::Session`].
    Session(SessionRequest),
}

/// The one request a client sends per connection, after the handshake.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// The presented credential.
    pub auth: Auth,
    /// What's being asked.
    pub body: RequestBody,
}

/// Follows a [`SessionRequest::Exec`] request, one line per chunk, until
/// `StdinEof`. Not a `SessionRequest` variant: a connection carries exactly
/// one `Request`, and these frames only make sense while that `Exec` is
/// still running.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum StdinFrame {
    /// A chunk of stdin data to forward to the running child process.
    Stdin {
        /// The data chunk, encoded as a UTF-8 string.
        data: String,
    },
    /// The client has closed its stdin stream; the daemon closes the
    /// child's stdin pipe.
    StdinEof,
}

// ─── Session-family requests ─────────────────────────────────────────────────

/// A request served with a session token only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionRequest {
    /// Run a declared tool. Carries nothing that names the daemon's host
    /// beyond the working directory (docs/airlock-v2-technical-guidance.md,
    /// "`Exec` stays free of host-specific fields").
    Exec {
        /// The bare tool name as declared in `airlock.toml`.
        tool: String,
        /// Arguments to pass to the tool.
        args: Vec<String>,
        /// The client's working directory. Must lie under the session's
        /// root.
        cwd: PathBuf,
    },
    /// List the tools this session serves.
    List,
    /// Self-test this session and its sandbox; see `airlock agent check`
    /// (docs/airlock-v2-ux.md, "`airlock agent check`").
    Check,
}

// ─── Admin-family requests ───────────────────────────────────────────────────

/// Whether a session's agent runs in Airlock's own sandbox or one the
/// harness brought (docs/airlock-v2-design.md, "Registering a session").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxKind {
    /// Started by `airlock run`.
    Airlock,
    /// Started by `airlock session start`, under some other harness's
    /// sandbox or none.
    External,
}

/// What ends a session (docs/airlock-v2-design.md, "Lifetime").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionEnds {
    /// Ends when the `Register` connection closes.
    Lease,
    /// Ends `secs` seconds after registration; `0` means never.
    Ttl {
        /// Seconds until expiry, or `0` for no expiry.
        secs: u64,
    },
}

/// How the project root was discovered, so a `Reload` repeats exactly the
/// discovery a session started with rather than the current directory's
/// (docs/airlock-v2-design.md, "Reloading a session"). Wire form of
/// `config::DiscoveryMode`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireMode {
    /// Walked up from the current directory to find `airlock.toml` /
    /// `airlock.local.toml`.
    Default,
    /// `--config <path>`: that file only, root is its parent.
    ConfigFile {
        /// The explicit config file path.
        path: PathBuf,
    },
    /// `--no-project-config`: root is the canonical current directory, no
    /// project layer.
    NoProjectConfig,
}

/// Which config layer a file belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerKind {
    /// `$XDG_CONFIG_HOME/airlock/airlock.toml`.
    Global,
    /// `airlock.toml` in the project.
    Repo,
    /// `airlock.local.toml` in the project.
    Local,
    /// An explicit `--config <path>` file.
    ConfigFile,
    /// `airlock.toml` or `airlock.local.toml` in a directory above the
    /// project root that sets `cascade = true`.
    Parent,
}

/// One config file contributing to a session, identified by content hash so
/// the trust store and `session list`'s "config changed" can tell whether it
/// still matches what was approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireLayer {
    /// Which layer this file is.
    pub kind: LayerKind,
    /// Its path.
    pub path: PathBuf,
    /// Lowercase hex SHA-256 of its bytes.
    pub sha256: String,
}

/// One `PATH` entry the launcher's filtered `PATH` dropped, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DroppedPath {
    /// The entry as it appeared in `PATH`.
    pub entry: String,
    /// Why it was dropped: relative, inside the project, or writable from a
    /// sandbox.
    pub reason: String,
}

/// The anchor paths the launcher validated before registering, echoed back
/// so `agent check`'s probes test exactly what the launcher used
/// (docs/airlock-v2-design.md, "Agent integration").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireAnchors {
    /// The runtime directory base.
    pub runtime_base: PathBuf,
    /// The trust store directory.
    pub trust_store: PathBuf,
    /// The global config file path.
    pub global_config: PathBuf,
}

/// One resolved secret value, labeled for lookup by the tools that reference
/// it.
///
/// `value` has to cross the socket in the clear — the daemon needs the live
/// value to inject into a child's environment — so this type cannot prevent
/// exposure the way [`crate::secrets::Secret`] does for in-process storage.
/// What it does guarantee: `Debug` never prints it (so a stray `{:?}` of a
/// `RegisterPayload` or a log line built from one can't leak it), and the
/// byte buffer zeroizes on drop.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireSecret {
    /// The `[secrets.<label>]` name.
    pub label: String,
    /// The resolved value.
    pub value: Zeroizing<String>,
}

impl fmt::Debug for WireSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireSecret")
            .field("label", &self.label)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// The normalized config and resolved state a `Register` or `Reload` hands
/// to the daemon. Built entirely by the launcher, which has the user's
/// terminal and environment; the daemon never reads the environment itself
/// (docs/airlock-v2-design.md, "Registering a session").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterPayload {
    /// The project root.
    pub root: PathBuf,
    /// How that root was discovered.
    pub mode: WireMode,
    /// Every config file that contributed, with its content hash.
    pub layers: Vec<WireLayer>,
    /// The merged config. See [`WireConfig`].
    pub config: WireConfig,
    /// Every secret the config uses, already resolved.
    pub secrets: Vec<WireSecret>,
    /// The launcher's environment, minus variables consumed by
    /// `source = "env"`.
    pub env_snapshot: BTreeMap<String, String>,
    /// The filtered `PATH`, as absolute directories.
    pub path: Vec<PathBuf>,
    /// Entries the filter dropped from the launcher's `PATH`, and why.
    pub dropped_path: Vec<DroppedPath>,
    /// Every path a sandboxed tool may write to, used for the anchor-overlap
    /// check and `resolve_binary_in`'s project/grant refusal.
    pub write_grants: Vec<PathBuf>,
    /// The anchor paths the launcher validated.
    pub anchors: WireAnchors,
    /// SHA-256 of the normalized `[agent]` section, so `Reload` can report
    /// "agent settings changed" without carrying two full configs.
    pub agent_hash: String,
}

/// Register a new session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    /// The resolved state to build the session from.
    pub payload: RegisterPayload,
    /// Shown in `session list`; `--name`, or the harness's base name, or
    /// `shell` for `session start`.
    pub name: String,
    /// Whether the agent runs in Airlock's sandbox or an external one.
    pub sandbox: SandboxKind,
    /// What ends the session.
    pub ends: SessionEnds,
}

/// A request served with the admin token only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminRequest {
    /// Register a new session.
    ///
    /// Boxed: `RegisterRequest` carries the whole `RegisterPayload`, which
    /// otherwise makes this the dominant variant by a wide margin and bloats
    /// every `AdminRequest` (clippy's `large_enum_variant`). Boxing changes
    /// nothing about the JSON shape; serde deserializes the inner value and
    /// boxes it.
    Register(Box<RegisterRequest>),
    /// Apply approved config to a running session in one step.
    Reload {
        /// The session to reload.
        session: String,
        /// Its freshly resolved state.
        payload: Box<RegisterPayload>,
    },
    /// List every session on the daemon.
    ListSessions,
    /// End sessions without restarting the daemon.
    Revoke {
        /// Session ids, id prefixes or names.
        sessions: Vec<String>,
    },
    /// Restart a `session start` session's TTL.
    Renew {
        /// The session to renew.
        session: String,
        /// The new TTL in seconds, or the default if omitted.
        ttl_secs: Option<u64>,
    },
    /// List the tools a session serves, for `tools list --session`.
    Tools {
        /// The session to query.
        session: String,
    },
    /// Fetch ring-buffer log entries.
    Logs {
        /// Filter to one session, or all if omitted.
        session: Option<String>,
    },
    /// Stop the daemon.
    Stop,
}

// ─── Error kinds ──────────────────────────────────────────────────────────────

/// Why the daemon could not serve a request.
///
/// Mapped to exit codes 125, 126 and 127, the same convention `docker run`,
/// `env` and `chroot` use, so the common case of a tool itself exiting 1
/// never collides with "Airlock failed" (docs/airlock-v2-design.md,
/// "Clients", exit status table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// No `AIRLOCK_SESSION` was presented.
    NoSession,
    /// The session was revoked, or the daemon that held it stopped.
    SessionEnded,
    /// The session's TTL ran out.
    SessionExpired,
    /// The caller is not a descendant of the session's anchor process.
    OutsideProcessTree,
    /// `AIRLOCK_ADDR` does not answer.
    DaemonUnreachable,
    /// No tool by that name in this session.
    UnknownTool,
    /// The tool's binary is not on the session's `PATH`, or resolves inside
    /// the project or a write grant.
    BinaryUnusable,
    /// The secret's last refresh failed; the daemon keeps retrying on its
    /// own.
    StaleSecret,
    /// The request's working directory is outside the session's root.
    OutsideRoot,
    /// The request does not parse, or fails a protocol-level check
    /// (unknown field, bad frame size).
    Malformed,
    /// The auth kind does not match the request family, or a token or
    /// credential did not check out.
    Unauthorized,
    /// The session is already running its concurrent-`exec` cap.
    Busy,
    /// Client and daemon speak different, incompatible protocol versions.
    IncompatibleProtocol,
    /// A daemon-side bug or I/O failure unrelated to the caller's request.
    Internal,
}

impl ErrorKind {
    /// The exit code `exec` reports for this error.
    pub fn exit_code(self) -> u8 {
        match self {
            ErrorKind::UnknownTool => 127,
            ErrorKind::BinaryUnusable => 126,
            _ => 125,
        }
    }
}

// ─── Daemon-to-client messages ────────────────────────────────────────────────

/// How a session ends, as reported to a client (docs/airlock-v2-design.md,
/// "Lifetime").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EndsInfo {
    /// Held open by a `run` launcher at this PID.
    Lease {
        /// The launcher's PID.
        pid: i32,
    },
    /// Expires at this Unix time, from a `session start` TTL.
    Ttl {
        /// Unix timestamp of expiry.
        expires_unix: u64,
    },
    /// Never ends on its own (`--ttl 0`); only `revoke` or a daemon stop
    /// ends it.
    Never,
}

/// A session, as reported by `session list`, `tools list` and
/// `agent check`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionInfo {
    /// The session id.
    pub id: SessionId,
    /// Its name.
    pub name: String,
    /// Its project root.
    pub root: PathBuf,
    /// Unix time the session was registered.
    pub started_unix: u64,
    /// Number of `exec`s served.
    pub execs: u64,
    /// What ends it.
    pub ends: EndsInfo,
    /// Whether its agent runs in Airlock's sandbox or an external one.
    pub sandbox: SandboxKind,
    /// The config layers it was built from.
    pub layers: Vec<WireLayer>,
    /// How its root was discovered.
    pub mode: WireMode,
    /// Every path its tools or agent may write to. Only ever grows: a
    /// reload passes these back to the launcher, so `PATH` filtering and
    /// secret-command resolution keep refusing what the agent's sandbox,
    /// fixed at launch, can still write.
    pub write_grants: Vec<PathBuf>,
}

/// How a tool's declared env var is shown in `tools list`: the literal
/// static value, or the secret label that resolves it (never the secret
/// value itself).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum EnvDisplay {
    /// A literal value from the config.
    Static(String),
    /// Resolved from `[secrets.<label>]`.
    Secret(String),
}

/// One tool a session serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInfo {
    /// The bare tool name.
    pub name: String,
    /// Its `description`, if the config set one.
    pub description: Option<String>,
    /// Its declared environment, in display form.
    pub env: Vec<(String, EnvDisplay)>,
    /// Whether this is a proxy tool (credential-injecting HTTP proxy) rather
    /// than a spawned binary.
    pub proxy: bool,
}

/// A single entry in the daemon's ring-buffer log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogEntry {
    /// A human-readable timestamp string (e.g., ISO 8601 format).
    pub timestamp: String,
    /// The log message.
    pub message: String,
    /// The session this entry concerns, if any (`daemon logs --session`
    /// filters on it).
    pub session: Option<String>,
}

/// A message sent from the daemon to the client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DaemonMessage {
    /// The daemon's answer to [`ClientHello`].
    Hello {
        /// The daemon's protocol version.
        protocol: u32,
        /// The daemon binary's version.
        version: String,
        /// The daemon process's PID.
        pid: u32,
        /// How the daemon was started.
        mode: DaemonMode,
        /// Number of live sessions.
        sessions: u32,
    },
    /// A chunk of stdout output from the child process (after redaction).
    Stdout {
        /// The redacted output data.
        data: String,
    },
    /// A chunk of stderr output from the child process (after redaction).
    Stderr {
        /// The redacted error output data.
        data: String,
    },
    /// The child process has exited.
    Exit {
        /// The child's exit code. Conventionally 0 for success.
        code: i32,
    },
    /// The daemon could not fulfil the request.
    Error {
        /// Why.
        kind: ErrorKind,
        /// A human-readable description.
        message: String,
    },
    /// Answer to a successful `Register`.
    Registered {
        /// The new session's id.
        id: SessionId,
        /// Its bearer token.
        token: SessionToken,
        /// Path to the session's proxy CA certificate, if it has proxy
        /// tools.
        ca_path: Option<PathBuf>,
    },
    /// Answer to a successful `Reload`.
    Reloaded {
        /// The reloaded session's id.
        id: SessionId,
        /// Human-readable changes, e.g. `"tools +psql"`, `"-gh"`.
        changes: Vec<String>,
        /// Whether the session's `[agent]` section differs from what the
        /// running agent started with (it cannot be applied without a
        /// restart).
        agent_changed: bool,
    },
    /// Answer to `ListSessions`.
    Sessions {
        /// Every live session.
        sessions: Vec<SessionInfo>,
    },
    /// Answer to `List` or `Tools`.
    Tools {
        /// The session the tools belong to.
        session: SessionInfo,
        /// Its declared tools.
        tools: Vec<ToolInfo>,
    },
    /// Answer to `Check`.
    CheckResult {
        /// The checked session.
        session: SessionInfo,
        /// The daemon binary's version.
        version: String,
        /// The anchor paths to probe, when the client runs on the daemon's
        /// host. `None` over a transport where host-local probes don't
        /// apply.
        anchors: Option<WireAnchors>,
        /// Names (never values) of env vars any tool declares as a secret.
        secret_env_names: Vec<String>,
        /// Credential-store paths to probe for read access.
        credential_paths: Vec<PathBuf>,
    },
    /// Answer to `Logs`.
    LogsResponse {
        /// The log entries, ordered from oldest to newest.
        entries: Vec<LogEntry>,
    },
    /// Acknowledges a request with no other payload (`Revoke`, `Renew`,
    /// `Stop`).
    Ok,
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn to_json_line<T: Serialize>(value: &T) -> String {
        let json = serde_json::to_string(value).expect("serialization failed");
        assert!(
            !json.contains('\n'),
            "serialized JSON must not contain embedded newlines: {json}"
        );
        json
    }

    fn round_trip<T>(value: &T)
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let json = to_json_line(value);
        let recovered: T = serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(value, &recovered);
    }

    /// A deterministic, well-formed session token, for tests that need an
    /// exact JSON string rather than one built from random bytes.
    fn fixed_token(id: &str) -> SessionToken {
        SessionToken::parse(&format!(
            "{TOKEN_PREFIX}{id}_{}",
            "A".repeat(TOKEN_SECRET_LEN)
        ))
        .expect("fixed test token must parse")
    }

    // ── encode_line ─────────────────────────────────────────────────────

    #[test]
    fn encode_line_appends_newline() {
        let bytes = encode_line(&ClientHello {
            protocol: PROTOCOL_VERSION,
            version: "0.1.0".to_string(),
        });
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(
            bytes[..bytes.len() - 1]
                .iter()
                .filter(|&&b| b == b'\n')
                .count(),
            0
        );
    }

    #[test]
    fn constants_match_the_contract() {
        assert_eq!(PROTOCOL_VERSION, 4);
        assert_eq!(MAX_SESSION_LINE_BYTES, 1024 * 1024);
        assert_eq!(MAX_ADMIN_LINE_BYTES, 16 * 1024 * 1024);
    }

    // ── ClientHello ─────────────────────────────────────────────────────

    #[test]
    fn client_hello_round_trip() {
        round_trip(&ClientHello {
            protocol: 2,
            version: "0.1.0".to_string(),
        });
    }

    #[test]
    fn client_hello_exact_json_shape() {
        let hello = ClientHello {
            protocol: 2,
            version: "0.1.0".to_string(),
        };
        let json = to_json_line(&hello);
        assert_eq!(json, r#"{"protocol":2,"version":"0.1.0"}"#);
    }

    #[test]
    fn client_hello_rejects_unknown_field() {
        let json = r#"{"protocol":2,"version":"0.1.0","extra":true}"#;
        assert!(serde_json::from_str::<ClientHello>(json).is_err());
    }

    // ── SessionId ───────────────────────────────────────────────────────

    #[test]
    fn session_id_generate_is_well_formed() {
        let id = SessionId::generate();
        assert_eq!(id.as_str().len(), 6);
        assert!(id.as_str().bytes().all(is_lowercase_hex_byte));
    }

    #[test]
    fn session_id_generate_is_unlikely_to_collide() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert_ne!(a, b, "two freshly generated ids collided");
    }

    #[test]
    fn session_id_parse_round_trip() {
        let id = SessionId::parse("abc123").unwrap();
        assert_eq!(id.as_str(), "abc123");
        round_trip(&id);
    }

    #[test]
    fn session_id_rejects_uppercase() {
        assert!(SessionId::parse("ABC123").is_err());
    }

    #[test]
    fn session_id_rejects_wrong_length() {
        assert!(SessionId::parse("abc12").is_err());
        assert!(SessionId::parse("abc1234").is_err());
        assert!(SessionId::parse("").is_err());
    }

    #[test]
    fn session_id_rejects_non_hex() {
        assert!(SessionId::parse("abcxyz").is_err());
    }

    #[test]
    fn session_id_debug_shows_the_id() {
        let id = SessionId::parse("abc123").unwrap();
        assert!(format!("{id:?}").contains("abc123"));
    }

    #[test]
    fn session_id_serializes_as_plain_string() {
        let id = SessionId::parse("abc123").unwrap();
        assert_eq!(to_json_line(&id), "\"abc123\"");
    }

    // ── SessionToken ────────────────────────────────────────────────────

    #[test]
    fn session_token_generate_round_trips_through_wire_string() {
        let id = SessionId::parse("abc123").unwrap();
        let token = SessionToken::generate(id.clone());
        let rendered = token.expose_secret();
        assert!(rendered.starts_with("airlock_abc123_"));
        assert_eq!(rendered.len(), "airlock_".len() + 6 + 1 + 43);

        let parsed = SessionToken::parse(&rendered).unwrap();
        assert_eq!(parsed.id(), &id);
        assert_eq!(parsed, token);
    }

    #[test]
    fn session_token_serde_round_trip() {
        let token = fixed_token("abc123");
        let json = to_json_line(&token);
        assert_eq!(json, format!("\"airlock_abc123_{}\"", "A".repeat(43)));
        let back: SessionToken = serde_json::from_str(&json).unwrap();
        assert_eq!(back, token);
    }

    #[test]
    fn session_token_debug_never_prints_the_secret() {
        let token = fixed_token("abc123");
        let debug = format!("{token:?}");
        assert!(debug.contains("abc123"), "debug should show the id");
        assert!(
            !debug.contains(&"A".repeat(43)),
            "debug must never print the secret part: {debug}"
        );
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn session_token_ct_eq_true_for_equal_tokens() {
        let a = fixed_token("abc123");
        let b = fixed_token("abc123");
        assert!(a.ct_eq(&b));
        assert_eq!(a, b);
    }

    #[test]
    fn session_token_ct_eq_false_for_different_secrets() {
        let a = fixed_token("abc123");
        // A different, independently canonical 32-byte secret: built by
        // encoding actual bytes rather than hand-picking 43 characters,
        // since not every 43-character base64url string decodes cleanly to
        // exactly 32 bytes (the trailing character's unused low bits must
        // be zero).
        let other_secret =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xffu8; TOKEN_SECRET_BYTES]);
        let b = SessionToken::parse(&format!("airlock_abc123_{other_secret}")).unwrap();
        assert!(!a.ct_eq(&b));
        assert_ne!(a, b);
    }

    #[test]
    fn session_token_ct_eq_false_for_different_ids() {
        let a = fixed_token("abc123");
        let b = fixed_token("def456");
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn session_token_parse_rejects_bad_prefix() {
        assert!(SessionToken::parse(&format!("nope_abc123_{}", "A".repeat(43))).is_err());
    }

    #[test]
    fn session_token_parse_rejects_wrong_secret_length() {
        assert!(SessionToken::parse("airlock_abc123_tooshort").is_err());
    }

    #[test]
    fn session_token_parse_rejects_missing_separator() {
        // 6 + 43 chars with no underscore between id and secret.
        let glued: String = "abc123".to_string() + &"A".repeat(43);
        assert!(SessionToken::parse(&format!("airlock_{glued}")).is_err());
    }

    #[test]
    fn session_token_parse_does_not_panic_on_multibyte_input() {
        // Byte length can coincidentally match while containing non-ASCII
        // characters; parsing must reject this via a Result, never panic.
        let hostile = format!("airlock_{}_{}", "é".repeat(3), "A".repeat(43));
        assert!(SessionToken::parse(&hostile).is_err());
    }

    #[test]
    fn session_token_parse_rejects_non_canonical_base64() {
        // Valid charset and length, but a trailing character whose low bits
        // can't be zero for a clean 32-byte decode.
        let bad_tail = format!("airlock_abc123_{}B", "A".repeat(42));
        assert!(SessionToken::parse(&bad_tail).is_err());
    }

    // ── AdminToken ──────────────────────────────────────────────────────

    #[test]
    fn admin_token_generate_is_well_formed() {
        let token = AdminToken::generate();
        assert_eq!(token.expose_secret().len(), 64);
        assert!(token.expose_secret().bytes().all(is_lowercase_hex_byte));
    }

    #[test]
    fn admin_token_parse_round_trip() {
        let hex = "a".repeat(64);
        let token = AdminToken::parse(&hex).unwrap();
        assert_eq!(token.expose_secret(), hex);
        let json = to_json_line(&token);
        assert_eq!(json, format!("\"{hex}\""));
        let back: AdminToken = serde_json::from_str(&json).unwrap();
        assert_eq!(back, token);
    }

    #[test]
    fn admin_token_rejects_wrong_length() {
        assert!(AdminToken::parse(&"a".repeat(63)).is_err());
        assert!(AdminToken::parse(&"a".repeat(65)).is_err());
    }

    #[test]
    fn admin_token_rejects_uppercase() {
        assert!(AdminToken::parse(&"A".repeat(64)).is_err());
    }

    #[test]
    fn admin_token_debug_never_prints_the_value() {
        let hex = "b".repeat(64);
        let token = AdminToken::parse(&hex).unwrap();
        let debug = format!("{token:?}");
        assert!(
            !debug.contains(&hex),
            "debug must never print the token: {debug}"
        );
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn admin_token_ct_eq() {
        let a = AdminToken::parse(&"c".repeat(64)).unwrap();
        let b = AdminToken::parse(&"c".repeat(64)).unwrap();
        let c = AdminToken::parse(&"d".repeat(64)).unwrap();
        assert!(a.ct_eq(&b));
        assert_eq!(a, b);
        assert!(!a.ct_eq(&c));
        assert_ne!(a, c);
    }

    // ── Auth ────────────────────────────────────────────────────────────

    #[test]
    fn auth_session_round_trip() {
        round_trip(&Auth::Session {
            token: fixed_token("abc123"),
        });
    }

    #[test]
    fn auth_admin_round_trip() {
        round_trip(&Auth::Admin {
            token: AdminToken::parse(&"e".repeat(64)).unwrap(),
        });
    }

    #[test]
    fn auth_tag_is_kind() {
        let json = to_json_line(&Auth::Admin {
            token: AdminToken::parse(&"e".repeat(64)).unwrap(),
        });
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["kind"], "admin");
    }

    #[test]
    fn auth_rejects_unknown_field() {
        let json = format!(
            r#"{{"kind":"admin","token":"{}","extra":1}}"#,
            "e".repeat(64)
        );
        assert!(serde_json::from_str::<Auth>(&json).is_err());
    }

    // ── SessionRequest / Request ────────────────────────────────────────

    #[test]
    fn session_request_exec_round_trip() {
        round_trip(&SessionRequest::Exec {
            tool: "gh".to_string(),
            args: vec!["issue".to_string(), "list".to_string()],
            cwd: PathBuf::from("/home/user/project"),
        });
    }

    #[test]
    fn session_request_list_and_check_round_trip() {
        round_trip(&SessionRequest::List);
        round_trip(&SessionRequest::Check);
    }

    #[test]
    fn session_request_exec_rejects_unknown_field() {
        let json = r#"{"type":"exec","tool":"gh","args":[],"cwd":"/tmp","extra":1}"#;
        assert!(serde_json::from_str::<SessionRequest>(json).is_err());
    }

    #[test]
    fn exec_request_exact_json_shape() {
        let req = Request {
            auth: Auth::Session {
                token: fixed_token("abc123"),
            },
            body: RequestBody::Session(SessionRequest::Exec {
                tool: "gh".to_string(),
                args: vec!["issue".to_string(), "list".to_string()],
                cwd: PathBuf::from("/home/user/project"),
            }),
        };
        let json = to_json_line(&req);
        let expected = format!(
            r#"{{"auth":{{"kind":"session","token":"airlock_abc123_{}"}},"body":{{"family":"session","type":"exec","tool":"gh","args":["issue","list"],"cwd":"/home/user/project"}}}}"#,
            "A".repeat(43)
        );
        assert_eq!(json, expected);

        let back: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn request_rejects_unknown_top_level_field() {
        let json = format!(
            r#"{{"auth":{{"kind":"session","token":"airlock_abc123_{}"}},"body":{{"family":"session","type":"check"}},"extra":1}}"#,
            "A".repeat(43)
        );
        assert!(serde_json::from_str::<Request>(&json).is_err());
    }

    #[test]
    fn request_body_admin_round_trip() {
        let body = RequestBody::Admin(AdminRequest::ListSessions);
        round_trip(&body);
        let json = to_json_line(&body);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["family"], "admin");
        assert_eq!(parsed["type"], "list_sessions");
    }

    #[test]
    fn admin_session_family_mismatch_is_representable() {
        // Nothing in the type system stops building a request whose auth
        // kind doesn't match its body family: the daemon checks this at
        // runtime and reports it as an error. Constructing and round
        // tripping this combination demonstrates the wire format carries it.
        let mismatched = Request {
            auth: Auth::Admin {
                token: AdminToken::parse(&"f".repeat(64)).unwrap(),
            },
            body: RequestBody::Session(SessionRequest::Check),
        };
        round_trip(&mismatched);

        let refusal = DaemonMessage::Error {
            kind: ErrorKind::Unauthorized,
            message: "admin token presented for a session-family request".to_string(),
        };
        round_trip(&refusal);
        assert_eq!(ErrorKind::Unauthorized.exit_code(), 125);
    }

    // ── StdinFrame ──────────────────────────────────────────────────────

    #[test]
    fn stdin_frame_round_trip() {
        round_trip(&StdinFrame::Stdin {
            data: "hello\n".to_string(),
        });
        round_trip(&StdinFrame::StdinEof);
    }

    #[test]
    fn stdin_frame_rejects_unknown_field() {
        // `deny_unknown_fields` only has something to check for a variant
        // that carries fields; `Stdin` does, `StdinEof` does not.
        let json = r#"{"type":"stdin","data":"hi","extra":1}"#;
        assert!(serde_json::from_str::<StdinFrame>(json).is_err());
    }

    // ── AdminRequest variants ───────────────────────────────────────────

    #[test]
    fn admin_request_register_round_trip() {
        let payload = sample_register_payload();
        round_trip(&AdminRequest::Register(Box::new(RegisterRequest {
            payload,
            name: "claude".to_string(),
            sandbox: SandboxKind::Airlock,
            ends: SessionEnds::Lease,
        })));
    }

    #[test]
    fn admin_request_reload_round_trip() {
        round_trip(&AdminRequest::Reload {
            session: "abc123".to_string(),
            payload: Box::new(sample_register_payload()),
        });
    }

    #[test]
    fn admin_request_remaining_variants_round_trip() {
        round_trip(&AdminRequest::ListSessions);
        round_trip(&AdminRequest::Revoke {
            sessions: vec!["abc123".to_string()],
        });
        round_trip(&AdminRequest::Renew {
            session: "abc123".to_string(),
            ttl_secs: Some(3600),
        });
        round_trip(&AdminRequest::Renew {
            session: "abc123".to_string(),
            ttl_secs: None,
        });
        round_trip(&AdminRequest::Tools {
            session: "abc123".to_string(),
        });
        round_trip(&AdminRequest::Logs {
            session: Some("abc123".to_string()),
        });
        round_trip(&AdminRequest::Logs { session: None });
        round_trip(&AdminRequest::Stop);
    }

    fn sample_register_payload() -> RegisterPayload {
        RegisterPayload {
            root: PathBuf::from("/home/user/project"),
            mode: WireMode::Default,
            layers: vec![WireLayer {
                kind: LayerKind::Repo,
                path: PathBuf::from("/home/user/project/airlock.toml"),
                sha256: "f".repeat(64),
            }],
            config: crate::config::RawConfig::default(),
            secrets: vec![WireSecret {
                label: "GH_TOKEN".to_string(),
                value: Zeroizing::new("s3cret".to_string()),
            }],
            env_snapshot: BTreeMap::from([("HOME".to_string(), "/home/user".to_string())]),
            path: vec![PathBuf::from("/usr/bin")],
            dropped_path: vec![DroppedPath {
                entry: "node_modules/.bin".to_string(),
                reason: "inside the project".to_string(),
            }],
            write_grants: vec![PathBuf::from("/home/user/project/.cache")],
            anchors: WireAnchors {
                runtime_base: PathBuf::from("/tmp/airlock-501"),
                trust_store: PathBuf::from("/home/user/.local/state/airlock/trust"),
                global_config: PathBuf::from("/home/user/.config/airlock/airlock.toml"),
            },
            agent_hash: "a".repeat(64),
        }
    }

    // ── WireSecret ──────────────────────────────────────────────────────

    #[test]
    fn wire_secret_round_trip() {
        round_trip(&WireSecret {
            label: "GH_TOKEN".to_string(),
            value: Zeroizing::new("s3cret".to_string()),
        });
    }

    #[test]
    fn wire_secret_debug_never_prints_the_value() {
        let secret = WireSecret {
            label: "GH_TOKEN".to_string(),
            value: Zeroizing::new("s3cret".to_string()),
        };
        let debug = format!("{secret:?}");
        assert!(debug.contains("GH_TOKEN"));
        assert!(!debug.contains("s3cret"), "debug leaked the value: {debug}");
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn wire_secret_rejects_unknown_field() {
        let json = r#"{"label":"X","value":"y","extra":1}"#;
        assert!(serde_json::from_str::<WireSecret>(json).is_err());
    }

    // ── RegisterPayload fails closed ───────────────────────────────────

    #[test]
    fn register_payload_round_trip() {
        round_trip(&sample_register_payload());
    }

    #[test]
    fn register_payload_rejects_unknown_field() {
        let mut value = serde_json::to_value(sample_register_payload()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::json!(true));
        let result: Result<RegisterPayload, _> = serde_json::from_value(value);
        assert!(result.is_err());
    }

    // ── WireMode / LayerKind / SandboxKind / SessionEnds ───────────────

    #[test]
    fn wire_mode_round_trip() {
        round_trip(&WireMode::Default);
        round_trip(&WireMode::ConfigFile {
            path: PathBuf::from("/tmp/custom.toml"),
        });
        round_trip(&WireMode::NoProjectConfig);
    }

    #[test]
    fn layer_kind_round_trip_and_shape() {
        for kind in [
            LayerKind::Global,
            LayerKind::Repo,
            LayerKind::Local,
            LayerKind::ConfigFile,
            LayerKind::Parent,
        ] {
            round_trip(&kind);
        }
        assert_eq!(to_json_line(&LayerKind::ConfigFile), "\"config_file\"");
    }

    #[test]
    fn sandbox_kind_round_trip_and_shape() {
        round_trip(&SandboxKind::Airlock);
        round_trip(&SandboxKind::External);
        assert_eq!(to_json_line(&SandboxKind::Airlock), "\"airlock\"");
    }

    #[test]
    fn session_ends_round_trip() {
        round_trip(&SessionEnds::Lease);
        round_trip(&SessionEnds::Ttl { secs: 0 });
        round_trip(&SessionEnds::Ttl { secs: 43200 });
    }

    // ── DaemonMode / EndsInfo ───────────────────────────────────────────

    #[test]
    fn daemon_mode_round_trip() {
        round_trip(&DaemonMode::Automatic);
        round_trip(&DaemonMode::Service);
        round_trip(&DaemonMode::Manual);
    }

    #[test]
    fn ends_info_round_trip() {
        round_trip(&EndsInfo::Lease { pid: 4821 });
        round_trip(&EndsInfo::Ttl {
            expires_unix: 1_700_000_000,
        });
        round_trip(&EndsInfo::Never);
    }

    // ── EnvDisplay / ToolInfo ───────────────────────────────────────────

    #[test]
    fn env_display_round_trip_and_shape() {
        round_trip(&EnvDisplay::Static("https://example.com".to_string()));
        round_trip(&EnvDisplay::Secret("GH_TOKEN".to_string()));
        let json = to_json_line(&EnvDisplay::Secret("GH_TOKEN".to_string()));
        assert_eq!(json, r#"{"type":"secret","value":"GH_TOKEN"}"#);
    }

    #[test]
    fn tool_info_round_trip() {
        round_trip(&ToolInfo {
            name: "gh".to_string(),
            description: Some("GitHub CLI".to_string()),
            env: vec![
                (
                    "GH_TOKEN".to_string(),
                    EnvDisplay::Secret("GH_TOKEN".to_string()),
                ),
                (
                    "GH_HOST".to_string(),
                    EnvDisplay::Static("github.com".to_string()),
                ),
            ],
            proxy: false,
        });
        round_trip(&ToolInfo {
            name: "x".to_string(),
            description: None,
            env: vec![],
            proxy: true,
        });
    }

    // ── SessionInfo ─────────────────────────────────────────────────────

    fn sample_session_info() -> SessionInfo {
        SessionInfo {
            id: SessionId::parse("abc123").unwrap(),
            name: "claude".to_string(),
            root: PathBuf::from("/home/user/project"),
            started_unix: 1_700_000_000,
            execs: 12,
            ends: EndsInfo::Lease { pid: 4821 },
            sandbox: SandboxKind::Airlock,
            layers: vec![WireLayer {
                kind: LayerKind::Repo,
                path: PathBuf::from("/home/user/project/airlock.toml"),
                sha256: "f".repeat(64),
            }],
            mode: WireMode::Default,
            write_grants: vec![PathBuf::from("/home/user/.claude")],
        }
    }

    #[test]
    fn session_info_round_trip() {
        round_trip(&sample_session_info());
    }

    // ── DaemonMessage ───────────────────────────────────────────────────

    #[test]
    fn daemon_message_hello_round_trip_and_exact_shape() {
        let msg = DaemonMessage::Hello {
            protocol: 2,
            version: "0.1.0".to_string(),
            pid: 4821,
            mode: DaemonMode::Automatic,
            sessions: 0,
        };
        round_trip(&msg);
        let json = to_json_line(&msg);
        assert_eq!(
            json,
            r#"{"type":"hello","protocol":2,"version":"0.1.0","pid":4821,"mode":"automatic","sessions":0}"#
        );
    }

    #[test]
    fn daemon_message_error_round_trip_and_exact_shape() {
        let msg = DaemonMessage::Error {
            kind: ErrorKind::UnknownTool,
            message: "no tool named \"x\" in this session".to_string(),
        };
        round_trip(&msg);
        let json = to_json_line(&msg);
        assert_eq!(
            json,
            r#"{"type":"error","kind":"unknown_tool","message":"no tool named \"x\" in this session"}"#
        );
    }

    #[test]
    fn daemon_message_stdout_stderr_exit_round_trip() {
        round_trip(&DaemonMessage::Stdout {
            data: "out\n".to_string(),
        });
        round_trip(&DaemonMessage::Stderr {
            data: "err\n".to_string(),
        });
        round_trip(&DaemonMessage::Exit { code: 0 });
        round_trip(&DaemonMessage::Exit { code: 127 });
        round_trip(&DaemonMessage::Exit { code: -9 });
    }

    #[test]
    fn daemon_message_registered_round_trip() {
        round_trip(&DaemonMessage::Registered {
            id: SessionId::parse("abc123").unwrap(),
            token: fixed_token("abc123"),
            ca_path: Some(PathBuf::from("/tmp/airlock-501/ca/abc123.pem")),
        });
        round_trip(&DaemonMessage::Registered {
            id: SessionId::parse("abc123").unwrap(),
            token: fixed_token("abc123"),
            ca_path: None,
        });
    }

    #[test]
    fn daemon_message_reloaded_round_trip() {
        round_trip(&DaemonMessage::Reloaded {
            id: SessionId::parse("abc123").unwrap(),
            changes: vec!["tools +psql".to_string(), "-gh".to_string()],
            agent_changed: true,
        });
    }

    #[test]
    fn daemon_message_sessions_round_trip() {
        round_trip(&DaemonMessage::Sessions {
            sessions: vec![sample_session_info()],
        });
        round_trip(&DaemonMessage::Sessions { sessions: vec![] });
    }

    #[test]
    fn daemon_message_tools_round_trip() {
        round_trip(&DaemonMessage::Tools {
            session: sample_session_info(),
            tools: vec![ToolInfo {
                name: "gh".to_string(),
                description: None,
                env: vec![],
                proxy: false,
            }],
        });
    }

    #[test]
    fn daemon_message_check_result_round_trip() {
        round_trip(&DaemonMessage::CheckResult {
            session: sample_session_info(),
            version: "0.1.0".to_string(),
            anchors: Some(WireAnchors {
                runtime_base: PathBuf::from("/tmp/airlock-501"),
                trust_store: PathBuf::from("/home/user/.local/state/airlock/trust"),
                global_config: PathBuf::from("/home/user/.config/airlock/airlock.toml"),
            }),
            secret_env_names: vec!["GH_TOKEN".to_string()],
            credential_paths: vec![PathBuf::from("/home/user/.config/gh")],
        });
        round_trip(&DaemonMessage::CheckResult {
            session: sample_session_info(),
            version: "0.1.0".to_string(),
            anchors: None,
            secret_env_names: vec![],
            credential_paths: vec![],
        });
    }

    #[test]
    fn daemon_message_logs_response_and_ok_round_trip() {
        round_trip(&DaemonMessage::LogsResponse {
            entries: vec![LogEntry {
                timestamp: "2025-01-15T10:30:00Z".to_string(),
                message: "daemon started".to_string(),
                session: None,
            }],
        });
        round_trip(&DaemonMessage::LogsResponse { entries: vec![] });
        round_trip(&DaemonMessage::Ok);
    }

    #[test]
    fn log_entry_carries_session_id() {
        let entry = LogEntry {
            timestamp: "2025-01-15T10:30:00Z".to_string(),
            message: "exec gh issue list".to_string(),
            session: Some("abc123".to_string()),
        };
        round_trip(&entry);
        let json = to_json_line(&entry);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["session"], "abc123");
    }

    #[test]
    fn daemon_message_rejects_unknown_field() {
        let json = r#"{"type":"exit","code":0,"extra":1}"#;
        assert!(serde_json::from_str::<DaemonMessage>(json).is_err());
    }

    #[test]
    fn daemon_message_rejects_unknown_type() {
        let json = r#"{"type":"not_a_real_message"}"#;
        assert!(serde_json::from_str::<DaemonMessage>(json).is_err());
    }

    // ── ErrorKind exit codes ────────────────────────────────────────────

    #[test]
    fn error_kind_exit_code_table() {
        let cases = [
            (ErrorKind::NoSession, 125),
            (ErrorKind::SessionEnded, 125),
            (ErrorKind::SessionExpired, 125),
            (ErrorKind::OutsideProcessTree, 125),
            (ErrorKind::DaemonUnreachable, 125),
            (ErrorKind::UnknownTool, 127),
            (ErrorKind::BinaryUnusable, 126),
            (ErrorKind::StaleSecret, 125),
            (ErrorKind::OutsideRoot, 125),
            (ErrorKind::Malformed, 125),
            (ErrorKind::Unauthorized, 125),
            (ErrorKind::Busy, 125),
            (ErrorKind::IncompatibleProtocol, 125),
            (ErrorKind::Internal, 125),
        ];
        for (kind, code) in cases {
            assert_eq!(kind.exit_code(), code, "{kind:?}");
        }
    }

    #[test]
    fn error_kind_serializes_snake_case() {
        assert_eq!(
            to_json_line(&ErrorKind::OutsideProcessTree),
            "\"outside_process_tree\""
        );
        assert_eq!(
            to_json_line(&ErrorKind::IncompatibleProtocol),
            "\"incompatible_protocol\""
        );
    }

    // ── WireLayer / DroppedPath / WireAnchors ──────────────────────────

    #[test]
    fn wire_layer_round_trip() {
        round_trip(&WireLayer {
            kind: LayerKind::Local,
            path: PathBuf::from("/home/user/project/airlock.local.toml"),
            sha256: "0".repeat(64),
        });
    }

    #[test]
    fn dropped_path_round_trip() {
        round_trip(&DroppedPath {
            entry: ".".to_string(),
            reason: "relative".to_string(),
        });
    }

    #[test]
    fn wire_anchors_round_trip() {
        round_trip(&WireAnchors {
            runtime_base: PathBuf::from("/tmp/airlock-501"),
            trust_store: PathBuf::from("/home/user/.local/state/airlock/trust"),
            global_config: PathBuf::from("/home/user/.config/airlock/airlock.toml"),
        });
    }

    // ── No embedded newlines across the board ──────────────────────────

    #[test]
    fn no_embedded_newlines_in_any_v2_message() {
        let messages: Vec<DaemonMessage> = vec![
            DaemonMessage::Hello {
                protocol: 2,
                version: "0.1.0".to_string(),
                pid: 1,
                mode: DaemonMode::Manual,
                sessions: 1,
            },
            DaemonMessage::Stdout {
                data: "line one\nline two\n".to_string(),
            },
            DaemonMessage::Error {
                kind: ErrorKind::Malformed,
                message: "bad\nrequest".to_string(),
            },
            DaemonMessage::Ok,
        ];
        for msg in &messages {
            to_json_line(msg);
            encode_line(msg); // panics internally if a newline sneaks through
        }
    }
}
