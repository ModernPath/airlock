//! Egress policy for proxy tools.
//!
//! A proxy tool (`proxy = true` in `[tools.X]`) never receives secrets in its
//! environment. Instead its only network path is a daemon-side HTTP proxy that
//! decides, per request, whether the destination is allowed and which
//! credential header to attach. This module holds the declarative half of
//! that: the route table parsed from `[[tools.X.routes]]` and the matching
//! rules the proxy evaluates against it.
//!
//! Everything here is deny-by-default. A host with no route is unreachable, a
//! request a route's rules do not permit is refused, and a path the matcher
//! cannot reason about unambiguously is refused rather than guessed at.

pub mod ca;
pub mod server;

use thiserror::Error;

/// Headers a route may not inject: they frame the request or address the
/// proxy hop, so letting config set them would desync the proxy from the
/// upstream's view of the message.
const FORBIDDEN_INJECT_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Placeholder in `inject.value` that is replaced by the secret.
const SECRET_PLACEHOLDER: &str = "{secret}";

/// Why a `[[tools.X.routes]]` entry was rejected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouteError {
    /// The `host` pattern is not a plain DNS name or `*.`-prefixed DNS name.
    #[error("invalid host pattern {pattern:?}: {reason}")]
    InvalidHost {
        /// The offending pattern.
        pattern: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// An `allow` / `deny` entry is not of the form `METHOD /path`.
    #[error("invalid rule {rule:?}: {reason}")]
    InvalidRule {
        /// The offending rule.
        rule: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// The `inject` table is malformed.
    #[error("invalid inject spec: {reason}")]
    InvalidInject {
        /// Why it was rejected.
        reason: &'static str,
    },
}

// ─── Host patterns ────────────────────────────────────────────────────────────

/// A destination host a route applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// Matches exactly this (lowercased) DNS name.
    Exact(String),
    /// `*.suffix`: matches exactly one additional label in front of `suffix`.
    /// Holds the suffix without the leading `*.`.
    Wildcard(String),
}

impl HostPattern {
    /// Parse a `host` value from config.
    ///
    /// IP literals, ports, and schemes are rejected: a route names a DNS
    /// identity that the upstream TLS certificate is verified against, and
    /// none of those have one.
    pub fn parse(pattern: &str) -> Result<Self, RouteError> {
        let err = |reason| RouteError::InvalidHost {
            pattern: pattern.to_string(),
            reason,
        };

        let lowered = pattern.to_ascii_lowercase();
        let (wildcard, name) = match lowered.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, lowered.as_str()),
        };

        if name.is_empty() {
            return Err(err("host is empty"));
        }
        if name.len() > 253 {
            return Err(err("host exceeds 253 characters"));
        }

        let labels: Vec<&str> = name.split('.').collect();
        for label in &labels {
            if label.is_empty() || label.len() > 63 {
                return Err(err("each label must be 1-63 characters"));
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(err(
                    "only letters, digits, '-' and '.' are allowed (no scheme, port, path, or inner '*')",
                ));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(err("labels must not start or end with '-'"));
            }
        }
        // A numeric final label is how IPv4 literals (and their octal/hex-free
        // decimal forms) look; no real TLD is all digits.
        if labels[labels.len() - 1].bytes().all(|b| b.is_ascii_digit()) {
            return Err(err("IP literals are not allowed; use a DNS name"));
        }
        if wildcard && labels.len() < 2 {
            return Err(err(
                "wildcard must cover a registrable domain (e.g. \"*.example.com\", not \"*.com\")",
            ));
        }

        Ok(if wildcard {
            HostPattern::Wildcard(name.to_string())
        } else {
            HostPattern::Exact(name.to_string())
        })
    }

    /// Whether `host` (as taken from a CONNECT target or absolute URI, without
    /// port) falls under this pattern.
    pub fn matches(&self, host: &str) -> bool {
        // Patterns are ASCII-only, and the wildcard arm slices by byte offset.
        if !host.is_ascii() {
            return false;
        }
        let host = host.strip_suffix('.').unwrap_or(host);
        match self {
            HostPattern::Exact(name) => host.eq_ignore_ascii_case(name),
            HostPattern::Wildcard(suffix) => {
                // Compare from the right so `evil-example.com` cannot match
                // `*.example.com`: the byte before the suffix must be the dot
                // that ends exactly one leading label.
                let Some(split) = host.len().checked_sub(suffix.len() + 1) else {
                    return false;
                };
                let (label, rest) = host.split_at(split);
                !label.is_empty()
                    && !label.contains('.')
                    && rest.as_bytes()[0] == b'.'
                    && rest[1..].eq_ignore_ascii_case(suffix)
            }
        }
    }
}

impl std::fmt::Display for HostPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostPattern::Exact(name) => f.write_str(name),
            HostPattern::Wildcard(suffix) => write!(f, "*.{suffix}"),
        }
    }
}

// ─── Method / path rules ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    /// `*`: exactly one non-empty segment.
    One,
    /// `**`: zero or more trailing segments. Only valid as the last segment.
    Rest,
}

/// One `METHOD /path` entry from a route's `allow` or `deny` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRule {
    /// Uppercase method, or `None` for `*` (any method).
    method: Option<String>,
    segments: Vec<Segment>,
}

impl PathRule {
    /// Parse a rule such as `GET /v2/projects/*/locations/**`.
    pub fn parse(rule: &str) -> Result<Self, RouteError> {
        let err = |reason| RouteError::InvalidRule {
            rule: rule.to_string(),
            reason,
        };

        let Some((method, path)) = rule.split_once(' ') else {
            return Err(err("expected \"METHOD /path\""));
        };
        let method = if method == "*" {
            None
        } else if !method.is_empty() && method.bytes().all(|b| b.is_ascii_uppercase()) {
            Some(method.to_string())
        } else {
            return Err(err("method must be uppercase letters or \"*\""));
        };

        let Some(path) = path.strip_prefix('/') else {
            return Err(err("path must start with '/'"));
        };
        if path.contains(['?', '#', ' ']) {
            return Err(err(
                "path must not contain '?', '#' or spaces (rules match the path only)",
            ));
        }

        let raw: Vec<&str> = path.split('/').collect();
        let mut segments = Vec::with_capacity(raw.len());
        for (i, seg) in raw.iter().enumerate() {
            let last = i == raw.len() - 1;
            segments.push(match *seg {
                "**" if last => Segment::Rest,
                "**" => return Err(err("\"**\" is only allowed as the final segment")),
                "*" => Segment::One,
                "" if !last => return Err(err("path must not contain empty segments (\"//\")")),
                "." | ".." => return Err(err("path must not contain \".\" or \"..\" segments")),
                s if s.contains('*') => {
                    return Err(err("'*' must be a whole segment (\"*\" or \"**\")"));
                }
                // Request paths are percent-decoded before matching, so a
                // rule is always written in decoded form; an escape here
                // could never match anything.
                s if s.contains('%') => {
                    return Err(err(
                        "path must not contain percent-escapes (write the decoded form)",
                    ));
                }
                s => Segment::Literal(s.to_string()),
            });
        }

        Ok(PathRule { method, segments })
    }

    fn matches(&self, method: &str, path_segments: &[Vec<u8>]) -> bool {
        if let Some(m) = &self.method {
            // Case-insensitive so a `deny = ["DELETE /**"]` still bites if the
            // client sends `delete` and the upstream happens to accept it.
            if !m.eq_ignore_ascii_case(method) {
                return false;
            }
        }

        let mut rest = path_segments;
        for seg in &self.segments {
            match seg {
                Segment::Rest => return true,
                Segment::One => match rest.split_first() {
                    Some((s, tail)) if !s.is_empty() => rest = tail,
                    _ => return false,
                },
                Segment::Literal(lit) => match rest.split_first() {
                    Some((s, tail)) if s == lit.as_bytes() => rest = tail,
                    _ => return false,
                },
            }
        }
        rest.is_empty()
    }
}

/// Split a request path into percent-decoded segments for rule matching, or
/// `None` if the path is one the rules cannot be evaluated against safely.
///
/// The upstream will decode the path before routing it, so rules have to be
/// matched against the decoded form — otherwise `/%72epos` slips past a
/// `deny = ["DELETE /repos/**"]` and is served as `/repos`. Decoding is done
/// exactly once per segment. Anything whose meaning still depends on how
/// the upstream normalizes — an escape that yields a `/`, `\`, NUL or a
/// second-round `%`, a `.` / `..` segment, an empty segment, a malformed
/// escape — is refused rather than guessed at, since matching `allow` as one
/// path and being served as another is exactly the bypass the rules exist
/// to prevent.
fn split_request_path(path: &str) -> Option<Vec<Vec<u8>>> {
    let path = path.strip_prefix('/')?;
    if path.contains('\\') {
        return None;
    }

    let raw: Vec<&str> = path.split('/').collect();
    let last = raw.len() - 1;
    let mut segments = Vec::with_capacity(raw.len());
    for (i, seg) in raw.iter().enumerate() {
        let decoded = decode_segment(seg)?;
        if decoded.iter().any(|b| matches!(b, b'/' | b'\\' | b'%' | 0)) {
            return None;
        }
        if decoded == b"." || decoded == b".." || (decoded.is_empty() && i != last) {
            return None;
        }
        segments.push(decoded);
    }
    Some(segments)
}

/// Percent-decode one path segment, or `None` on a malformed escape (`%` not
/// followed by two hex digits).
fn decode_segment(seg: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(seg.len());
    let mut bytes = seg.bytes();
    while let Some(b) = bytes.next() {
        if b != b'%' {
            out.push(b);
            continue;
        }
        let hi = (bytes.next()? as char).to_digit(16)?;
        let lo = (bytes.next()? as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

// ─── Credential injection ─────────────────────────────────────────────────────

/// The header a route attaches to permitted requests.
///
/// Holds only the secret's *label*; the value is looked up in the secret store
/// per request so background refreshes take effect immediately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inject {
    /// Header name, as written in config.
    pub header: String,
    /// Literal text before the secret (e.g. `"Bearer "`).
    pub prefix: String,
    /// Literal text after the secret.
    pub suffix: String,
    /// Label of the `[secrets.<label>]` entry to insert.
    pub secret: String,
}

impl Inject {
    /// Validate an `inject = { header, value, secret }` table.
    ///
    /// Does not check that `secret` is declared; the caller owns the secrets
    /// table.
    pub fn parse(header: &str, value: &str, secret: &str) -> Result<Self, RouteError> {
        let err = |reason| RouteError::InvalidInject { reason };

        let is_token_char = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
        if header.is_empty() || !header.bytes().all(is_token_char) {
            return Err(err("header is not a valid HTTP header name"));
        }
        if FORBIDDEN_INJECT_HEADERS
            .iter()
            .any(|h| h.eq_ignore_ascii_case(header))
        {
            return Err(err(
                "header is a framing or hop-by-hop header and cannot be injected",
            ));
        }

        let Some((prefix, suffix)) = value.split_once(SECRET_PLACEHOLDER) else {
            return Err(err("value must contain the {secret} placeholder"));
        };
        if suffix.contains(SECRET_PLACEHOLDER) {
            return Err(err("value must contain {secret} exactly once"));
        }
        if prefix.contains(['{', '}']) || suffix.contains(['{', '}']) {
            return Err(err("{secret} is the only placeholder supported in value"));
        }
        // Visible ASCII and space only: anything else (notably CR/LF) would
        // let config smuggle extra headers into the upstream request.
        let is_value_char = |b: u8| b == b' ' || b.is_ascii_graphic();
        if !prefix.bytes().all(is_value_char) || !suffix.bytes().all(is_value_char) {
            return Err(err(
                "value must be printable ASCII (no control characters or newlines)",
            ));
        }

        if secret.is_empty() {
            return Err(err("secret label is empty"));
        }

        Ok(Inject {
            header: header.to_string(),
            prefix: prefix.to_string(),
            suffix: suffix.to_string(),
            secret: secret.to_string(),
        })
    }
}

// ─── Routes and policy ────────────────────────────────────────────────────────

/// One `[[tools.X.routes]]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRoute {
    /// Which destination hosts this route covers.
    pub host: HostPattern,
    /// Credential header to attach, if any. A route without `inject` makes a
    /// host reachable without authenticating to it.
    pub inject: Option<Inject>,
    /// If non-empty, a request must match at least one of these.
    pub allow: Vec<PathRule>,
    /// A request matching any of these is refused, regardless of `allow`.
    pub deny: Vec<PathRule>,
}

impl ProxyRoute {
    /// Whether a request with this method and path (no query string) may be
    /// forwarded. `deny` wins over `allow`; an empty `allow` permits anything
    /// not denied.
    pub fn permits(&self, method: &str, path: &str) -> bool {
        let Some(segments) = split_request_path(path) else {
            return false;
        };
        if self.deny.iter().any(|r| r.matches(method, &segments)) {
            return false;
        }
        self.allow.is_empty() || self.allow.iter().any(|r| r.matches(method, &segments))
    }
}

/// The full egress policy of one proxy tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyPolicy {
    /// Routes in declaration order. Host patterns are unique within a tool.
    pub routes: Vec<ProxyRoute>,
}

impl ProxyPolicy {
    /// The route governing `host`, or `None` if the host is unreachable.
    ///
    /// An exact route beats a wildcard one, so `api.example.com` can be given
    /// tighter rules (or a different credential) than `*.example.com`.
    pub fn find_route(&self, host: &str) -> Option<&ProxyRoute> {
        let matching = || self.routes.iter().filter(|r| r.host.matches(host));
        matching()
            .find(|r| matches!(r.host, HostPattern::Exact(_)))
            .or_else(|| matching().next())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn route(host: &str, allow: &[&str], deny: &[&str]) -> ProxyRoute {
        ProxyRoute {
            host: HostPattern::parse(host).unwrap(),
            inject: None,
            allow: allow.iter().map(|r| PathRule::parse(r).unwrap()).collect(),
            deny: deny.iter().map(|r| PathRule::parse(r).unwrap()).collect(),
        }
    }

    // ── HostPattern::parse ────────────────────────────────────────────────

    #[test]
    fn host_parse_exact_is_lowercased() {
        assert_eq!(
            HostPattern::parse("Run.GoogleAPIs.com").unwrap(),
            HostPattern::Exact("run.googleapis.com".to_string())
        );
    }

    #[test]
    fn host_parse_wildcard_strips_prefix() {
        assert_eq!(
            HostPattern::parse("*.googleapis.com").unwrap(),
            HostPattern::Wildcard("googleapis.com".to_string())
        );
    }

    #[test]
    fn host_parse_rejects_non_dns_forms() {
        for bad in [
            "",
            "*",
            "*.",
            "*.com",
            "https://example.com",
            "example.com:443",
            "example.com/path",
            "exa mple.com",
            "foo.*.example.com",
            "*foo.example.com",
            "-bad.example.com",
            "bad-.example.com",
            "a..example.com",
            "example.com.",
            "127.0.0.1",
            "*.0.0.1",
            "[::1]",
            "::1",
            "2130706433",
        ] {
            assert!(
                matches!(HostPattern::parse(bad), Err(RouteError::InvalidHost { .. })),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn host_display_round_trips() {
        for p in ["run.googleapis.com", "*.googleapis.com"] {
            assert_eq!(HostPattern::parse(p).unwrap().to_string(), p);
        }
    }

    // ── HostPattern::matches ──────────────────────────────────────────────

    #[test]
    fn exact_host_matches_case_insensitively_and_ignores_trailing_dot() {
        let p = HostPattern::parse("run.googleapis.com").unwrap();
        assert!(p.matches("run.googleapis.com"));
        assert!(p.matches("RUN.googleapis.com"));
        assert!(p.matches("run.googleapis.com."));
        assert!(!p.matches("xrun.googleapis.com"));
        assert!(!p.matches("a.run.googleapis.com"));
        assert!(!p.matches("run.googleapis.com.evil.test"));
    }

    #[test]
    fn wildcard_host_matches_exactly_one_label() {
        let p = HostPattern::parse("*.googleapis.com").unwrap();
        assert!(p.matches("run.googleapis.com"));
        assert!(p.matches("europe-west1-run.GoogleApis.com."));
        assert!(!p.matches("googleapis.com"), "bare domain");
        assert!(!p.matches(".googleapis.com"), "empty label");
        assert!(!p.matches("a.b.googleapis.com"), "two labels");
        assert!(!p.matches("evilgoogleapis.com"), "suffix without dot");
        assert!(!p.matches("run.googleapis.com.evil.test"));
        assert!(!p.matches(""));
        assert!(!p.matches("rün.googleapis.com"), "non-ASCII must not panic");
    }

    // ── PathRule::parse ───────────────────────────────────────────────────

    #[test]
    fn rule_parse_accepts_documented_forms() {
        for ok in [
            "GET /",
            "GET /**",
            "* /**",
            "POST /v2/projects/*/locations/*/services",
            "GET /v1/projects/*/secrets/*/versions/latest:access",
            "GET /v1/things/",
        ] {
            assert!(PathRule::parse(ok).is_ok(), "{ok:?} should parse");
        }
    }

    #[test]
    fn rule_parse_rejects_malformed() {
        for bad in [
            "",
            "GET",
            "/path",
            "get /path",
            "GET path",
            " /path",
            "GET  /path",
            "GET /a//b",
            "GET /a/../b",
            "GET /a/./b",
            "GET /a/**/b",
            "GET /a/b*",
            "GET /a?x=1",
            "GET /a#frag",
        ] {
            assert!(
                matches!(PathRule::parse(bad), Err(RouteError::InvalidRule { .. })),
                "{bad:?} should be rejected"
            );
        }
    }

    // ── ProxyRoute::permits ───────────────────────────────────────────────

    #[test]
    fn empty_rules_permit_everything_well_formed() {
        let r = route("example.com", &[], &[]);
        assert!(r.permits("GET", "/"));
        assert!(r.permits("DELETE", "/anything/at/all"));
    }

    #[test]
    fn allow_list_is_exhaustive() {
        let r = route(
            "example.com",
            &["GET /**", "POST /v2/projects/*/services"],
            &[],
        );
        assert!(r.permits("GET", "/v2/whatever"));
        assert!(r.permits("POST", "/v2/projects/p1/services"));
        assert!(!r.permits("POST", "/v2/projects/p1/services/extra"));
        assert!(!r.permits("POST", "/v2/projects/services"));
        assert!(!r.permits("POST", "/v2/projects//services"));
        assert!(!r.permits("DELETE", "/v2/projects/p1/services"));
    }

    #[test]
    fn deny_beats_allow() {
        let r = route("example.com", &["* /**"], &["DELETE /**", "* /admin/**"]);
        assert!(r.permits("GET", "/v1/x"));
        assert!(!r.permits("DELETE", "/v1/x"));
        assert!(!r.permits("GET", "/admin"));
        assert!(!r.permits("GET", "/admin/users"));
        assert!(r.permits("GET", "/administrator"));
    }

    #[test]
    fn method_match_is_case_insensitive() {
        let r = route("example.com", &[], &["DELETE /**"]);
        assert!(!r.permits("delete", "/x"));
        assert!(!r.permits("Delete", "/x"));
    }

    #[test]
    fn double_star_matches_zero_or_more_segments() {
        let r = route("example.com", &["GET /v1/**"], &[]);
        assert!(r.permits("GET", "/v1"));
        assert!(r.permits("GET", "/v1/"));
        assert!(r.permits("GET", "/v1/a/b/c"));
        assert!(!r.permits("GET", "/v10"));
        assert!(!r.permits("GET", "/"));
    }

    #[test]
    fn trailing_slash_is_significant_for_literal_rules() {
        let r = route("example.com", &["GET /v1/things"], &[]);
        assert!(r.permits("GET", "/v1/things"));
        assert!(!r.permits("GET", "/v1/things/"));
    }

    #[test]
    fn single_star_covers_custom_verb_suffix() {
        let r = route("example.com", &["POST /v1/secrets/*"], &[]);
        assert!(r.permits("POST", "/v1/secrets/latest:access"));
    }

    #[test]
    fn ambiguous_paths_are_refused_even_with_no_rules() {
        let r = route("example.com", &[], &[]);
        for bad in [
            "",
            "no-leading-slash",
            "/a/../b",
            "/a/./b",
            "/..",
            "/a//b",
            "//a",
            "/a/%2e%2e/b",
            "/a/%2E%2E/b",
            "/a/%2e/b",
            "/a%2Fb",
            "/a%5cb",
            "/a\\b",
            "/a%00",
            "/a%25b",
            "/a%252e%252e/b",
            "/a/%2",
            "/a/%zz",
            "/a/%",
            "/a/%2e%2",
        ] {
            assert!(!r.permits("GET", bad), "{bad:?} should be refused");
        }
    }

    #[test]
    fn percent_encoded_segments_match_their_decoded_form() {
        let r = route("api.github.com", &[], &["DELETE /repos/**"]);
        assert!(!r.permits("DELETE", "/repos/o/n"));
        assert!(
            !r.permits("DELETE", "/%72epos/o/n"),
            "encoded unreserved char"
        );
        assert!(
            !r.permits("DELETE", "/%72%65%70%6F%73/o/n"),
            "fully encoded"
        );
        assert!(
            !r.permits("DELETE", "/repos/o%20x/n"),
            "escape in a wildcard segment"
        );
        assert!(r.permits("GET", "/%72epos/o/n"));

        let r = route("example.com", &["GET /a-b/*"], &[]);
        assert!(r.permits("GET", "/a%2Db/x"));
        assert!(r.permits("GET", "/a-b/x%20y"));
        assert!(!r.permits("GET", "/a%2Db/x%2Fy"));
        assert!(!r.permits("GET", "/ab/x"));
    }

    #[test]
    fn rule_literals_refuse_percent_escapes() {
        let err = PathRule::parse("GET /a%20b").unwrap_err();
        assert!(matches!(err, RouteError::InvalidRule { .. }), "{err:?}");
    }

    #[test]
    fn dotted_names_are_not_mistaken_for_traversal() {
        let r = route("example.com", &[], &[]);
        assert!(r.permits("GET", "/v1/file.tar.gz"));
        assert!(r.permits("GET", "/v1/..."));
        assert!(r.permits("GET", "/.well-known/openid-configuration"));
    }

    // ── Inject::parse ─────────────────────────────────────────────────────

    #[test]
    fn inject_splits_value_around_placeholder() {
        let i = Inject::parse("Authorization", "Bearer {secret}", "gcp_token").unwrap();
        assert_eq!(i.header, "Authorization");
        assert_eq!(i.prefix, "Bearer ");
        assert_eq!(i.suffix, "");
        assert_eq!(i.secret, "gcp_token");

        let i = Inject::parse("X-Api-Key", "{secret}", "k").unwrap();
        assert_eq!((i.prefix.as_str(), i.suffix.as_str()), ("", ""));
    }

    #[test]
    fn inject_rejects_bad_headers() {
        for bad in [
            "",
            "Bad Header",
            "Bad:Header",
            "Host",
            "content-length",
            "Transfer-Encoding",
            "Proxy-Authorization",
            "Connection",
        ] {
            assert!(
                Inject::parse(bad, "{secret}", "k").is_err(),
                "header {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn inject_rejects_bad_values() {
        for bad in [
            "Bearer",
            "{secret}{secret}",
            "Bearer {token}",
            "{other} {secret}",
            "Bearer {secret}\r\nX-Evil: 1",
            "Bearer\t{secret}",
            "Bearer {secret}\u{e9}",
        ] {
            assert!(
                Inject::parse("Authorization", bad, "k").is_err(),
                "value {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn inject_rejects_empty_secret_label() {
        assert!(Inject::parse("Authorization", "Bearer {secret}", "").is_err());
    }

    // ── ProxyPolicy::find_route ───────────────────────────────────────────

    #[test]
    fn unrouted_host_is_unreachable() {
        let policy = ProxyPolicy {
            routes: vec![route("*.googleapis.com", &[], &[])],
        };
        assert!(policy.find_route("attacker.test").is_none());
        assert!(policy.find_route("googleapis.com").is_none());
    }

    #[test]
    fn exact_route_beats_wildcard_regardless_of_order() {
        let policy = ProxyPolicy {
            routes: vec![
                route("*.googleapis.com", &[], &[]),
                route("storage.googleapis.com", &["GET /**"], &[]),
            ],
        };
        let r = policy.find_route("storage.googleapis.com").unwrap();
        assert_eq!(
            r.host,
            HostPattern::Exact("storage.googleapis.com".to_string())
        );
        let r = policy.find_route("run.googleapis.com").unwrap();
        assert_eq!(r.host, HostPattern::Wildcard("googleapis.com".to_string()));
    }
}
