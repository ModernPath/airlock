//! Tests for the proxy runtime.
//!
//! Everything here is hermetic. The "upstream" is a local rustls server the
//! proxy is pointed at through [`Upstream::fixed`], which exists only under
//! `cfg(test)` — the production connector always resolves and applies the
//! SSRF filter, with no configuration that can turn it off.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use super::*;
use crate::proxy::ca::ProxyCa;
use crate::proxy::{HostPattern, Inject, PathRule, ProxyRoute};
use crate::secrets::{Secret, SecretSlot};

const UPSTREAM_HOST: &str = "upstream.test";

// ─── Fixtures ─────────────────────────────────────────────────────────────────

fn route(host: &str, allow: &[&str], inject: Option<Inject>) -> ProxyRoute {
    ProxyRoute {
        host: HostPattern::parse(host).unwrap(),
        inject,
        allow: allow.iter().map(|r| PathRule::parse(r).unwrap()).collect(),
        deny: Vec::new(),
    }
}

fn bearer() -> Inject {
    Inject::parse("X-Test-Secret", "tok-{secret}", "api_key").unwrap()
}

fn secret_store(label: &str, value: &str, healthy: bool) -> SecretStore {
    let health = if healthy {
        Health::Healthy
    } else {
        Health::Stale {
            reason: "refresh command exited 1".to_string(),
            since: Instant::now(),
        }
    };
    let mut map = HashMap::new();
    map.insert(
        label.to_string(),
        RwLock::new(SecretSlot {
            value: Arc::new(Secret::new(value.to_string())),
            health,
        }),
    );
    Arc::new(map)
}

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

fn root_store(ca: &ProxyCa) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(pem_to_der(
            ca.cert_pem(),
        )))
        .unwrap();
    roots
}

fn ca_for(hosts: &[&str]) -> Arc<ProxyCa> {
    let policy = ProxyPolicy {
        routes: hosts.iter().map(|h| route(h, &[], None)).collect(),
    };
    Arc::new(ProxyCa::generate([policy].iter()).unwrap().unwrap())
}

// ─── The local "upstream" ─────────────────────────────────────────────────────

/// A TLS server that reports back what it received: the request target and one
/// line per header. That is what lets a test see whether the credential
/// arrived and whether the query string survived.
struct TestUpstream {
    addr: SocketAddr,
    ca: Arc<ProxyCa>,
}

async fn start_upstream() -> TestUpstream {
    let ca = ca_for(&[UPSTREAM_HOST]);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(ca.server_config(UPSTREAM_HOST).unwrap());

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(|req: Request<Incoming>| async move {
                    let mut out = format!(
                        "{} {}\n",
                        req.method(),
                        req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("")
                    );
                    let mut names: Vec<_> = req
                        .headers()
                        .iter()
                        .map(|(n, v)| format!("{}: {}\n", n, v.to_str().unwrap_or("<binary>")))
                        .collect();
                    names.sort();
                    out.extend(names);
                    Ok::<_, Infallible>(Response::new(text_body(&out)))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });

    TestUpstream { addr, ca }
}

// ─── The harness ──────────────────────────────────────────────────────────────

struct Harness {
    session: ProxySession,
    ca: Arc<ProxyCa>,
    ring_buffer: RingBuffer,
}

impl Harness {
    async fn new(routes: Vec<ProxyRoute>, secrets: SecretStore) -> Self {
        let upstream = start_upstream().await;
        let ca = ca_for(&[UPSTREAM_HOST, "other.test"]);
        let ring_buffer = RingBuffer::new();
        let session = ProxySession::start_with_upstream(
            "curl".to_string(),
            ProxyPolicy { routes },
            Arc::clone(&ca),
            PathBuf::from("/nonexistent/airlock-ca.pem"),
            secrets,
            ring_buffer.clone(),
            Upstream::fixed(upstream.addr, root_store(&upstream.ca)),
        )
        .unwrap();
        Harness {
            session,
            ca,
            ring_buffer,
        }
    }

    /// The default fixture: one route for the upstream that injects a
    /// credential and permits `GET /**`.
    async fn default() -> Self {
        Self::new(
            vec![route(UPSTREAM_HOST, &["GET /**"], Some(bearer()))],
            secret_store("api_key", "s3cret-value", true),
        )
        .await
    }

    fn logs(&self) -> String {
        self.ring_buffer
            .entries()
            .into_iter()
            .map(|e| e.message)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn token(&self) -> String {
        // `http://airlock:<token>@127.0.0.1:<port>`
        let url = self.session.proxy_url();
        url.rsplit_once('@')
            .unwrap()
            .0
            .rsplit_once(':')
            .unwrap()
            .1
            .to_string()
    }

    async fn connect_raw(&self) -> hyper::client::conn::http1::SendRequest<ProxyBody> {
        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, self.session.port()))
            .await
            .unwrap();
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            // `with_upgrades` is what lets `hyper::upgrade::on` hand back the
            // CONNECT tunnel; without it the client cannot take the socket.
            let _ = conn.with_upgrades().await;
        });
        sender
    }

    /// Send one CONNECT and return the response without upgrading.
    async fn connect(&self, authority: &str, auth: Option<&str>) -> Response<Incoming> {
        let mut sender = self.connect_raw().await;
        let mut builder = Request::builder().method(Method::CONNECT).uri(authority);
        if let Some(auth) = auth {
            builder = builder.header(header::PROXY_AUTHORIZATION, auth);
        }
        sender
            .send_request(builder.body(empty_body()).unwrap())
            .await
            .unwrap()
    }

    fn auth(&self) -> String {
        basic_auth_header(&self.token())
    }

    /// Open a tunnel to `authority` and return a sender for requests inside it.
    async fn tunnel(&self, authority: &str) -> hyper::client::conn::http1::SendRequest<ProxyBody> {
        let mut sender = self.connect_raw().await;
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("{authority}:443"))
            .header(header::PROXY_AUTHORIZATION, self.auth())
            .body(empty_body())
            .unwrap();
        let response = sender.send_request(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "CONNECT should succeed");

        let upgraded = hyper::upgrade::on(response).await.unwrap();
        let connector = TlsConnector::from(Arc::new(client_config(root_store(&self.ca))));
        let name = ServerName::try_from(authority.to_string()).unwrap();
        let tls = connector
            .connect(name, TokioIo::new(upgraded))
            .await
            .expect("the tool must trust the airlock CA");

        let (inner, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        inner
    }
}

async fn read_body(response: Response<Incoming>) -> (StatusCode, String) {
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn get(target: &str, host: &str, extra: &[(&str, &str)]) -> Request<ProxyBody> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(target)
        .header(header::HOST, host);
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    builder.body(empty_body()).unwrap()
}

// ─── Proxy authentication ─────────────────────────────────────────────────────

#[tokio::test]
async fn connect_without_credentials_is_refused() {
    let h = Harness::default().await;
    let response = h.connect(&format!("{UPSTREAM_HOST}:443"), None).await;
    assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    assert!(response.headers().contains_key(header::PROXY_AUTHENTICATE));
}

#[tokio::test]
async fn connect_with_a_wrong_token_is_refused() {
    let h = Harness::default().await;
    let wrong = basic_auth_header(&"0".repeat(64));
    let response = h
        .connect(&format!("{UPSTREAM_HOST}:443"), Some(&wrong))
        .await;
    assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
}

#[tokio::test]
async fn tokens_are_per_exec() {
    let a = Harness::default().await;
    let b = Harness::default().await;
    assert_ne!(a.token(), b.token());
    let response = a
        .connect(&format!("{UPSTREAM_HOST}:443"), Some(&b.auth()))
        .await;
    assert_eq!(
        response.status(),
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "one exec's token must not open another's proxy"
    );
}

// ─── CONNECT vetting ──────────────────────────────────────────────────────────

#[tokio::test]
async fn connect_to_a_port_other_than_443_is_refused() {
    let h = Harness::default().await;
    let response = h
        .connect(&format!("{UPSTREAM_HOST}:8443"), Some(&h.auth()))
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(h.logs().contains("port 8443 is not 443"), "{}", h.logs());
}

#[tokio::test]
async fn connect_to_an_unrouted_host_is_refused() {
    let h = Harness::default().await;
    let response = h.connect("other.test:443", Some(&h.auth())).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(h.logs().contains("no route for host"), "{}", h.logs());
}

#[tokio::test]
async fn plain_http_proxying_is_refused() {
    let h = Harness::default().await;
    let mut sender = h.connect_raw().await;
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{UPSTREAM_HOST}/v1/things"))
        .header(header::HOST, UPSTREAM_HOST)
        .header(header::PROXY_AUTHORIZATION, h.auth())
        .body(empty_body())
        .unwrap();
    let response = sender.send_request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        h.logs().contains("plain HTTP proxying is not supported"),
        "{}",
        h.logs()
    );
}

// ─── Request vetting (pure) ───────────────────────────────────────────────────

fn parts(method: &str, target: &str, headers: &[(&str, &str)]) -> hyper::http::request::Parts {
    let mut builder = Request::builder().method(method).uri(target);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(()).unwrap().into_parts().0
}

#[test]
fn host_header_must_equal_the_connect_authority() {
    let r = route(UPSTREAM_HOST, &[], None);
    let ok = parts("GET", "/v1/x", &[("host", UPSTREAM_HOST)]);
    assert!(vet_request(&ok, UPSTREAM_HOST, &r).is_ok());

    let explicit_port = parts("GET", "/v1/x", &[("host", "upstream.test:443")]);
    assert!(vet_request(&explicit_port, UPSTREAM_HOST, &r).is_ok());

    let cased = parts("GET", "/v1/x", &[("host", "UPSTREAM.TEST")]);
    assert!(vet_request(&cased, UPSTREAM_HOST, &r).is_ok());

    for bad in ["evil.test", "upstream.test.evil.test", "upstream.test:8443"] {
        let fronted = parts("GET", "/v1/x", &[("host", bad)]);
        assert_eq!(
            vet_request(&fronted, UPSTREAM_HOST, &r).unwrap_err().status,
            StatusCode::BAD_REQUEST,
            "Host {bad:?} should not pass for authority {UPSTREAM_HOST:?}"
        );
    }
}

#[test]
fn missing_or_duplicated_host_is_refused() {
    let r = route(UPSTREAM_HOST, &[], None);
    let none = parts("GET", "/v1/x", &[]);
    assert_eq!(
        vet_request(&none, UPSTREAM_HOST, &r).unwrap_err().status,
        StatusCode::BAD_REQUEST
    );
    let two = parts(
        "GET",
        "/v1/x",
        &[("host", UPSTREAM_HOST), ("host", UPSTREAM_HOST)],
    );
    assert_eq!(
        vet_request(&two, UPSTREAM_HOST, &r).unwrap_err().status,
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn transfer_encoding_with_content_length_is_refused() {
    let r = route(UPSTREAM_HOST, &[], None);
    let smuggled = parts(
        "POST",
        "/v1/x",
        &[
            ("host", UPSTREAM_HOST),
            ("content-length", "5"),
            ("transfer-encoding", "chunked"),
        ],
    );
    let err = vet_request(&smuggled, UPSTREAM_HOST, &r).unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert!(err.reason.contains("Transfer-Encoding"));
}

#[test]
fn duplicate_content_length_is_refused() {
    let r = route(UPSTREAM_HOST, &[], None);
    let doubled = parts(
        "POST",
        "/v1/x",
        &[
            ("host", UPSTREAM_HOST),
            ("content-length", "5"),
            ("content-length", "6"),
        ],
    );
    assert_eq!(
        vet_request(&doubled, UPSTREAM_HOST, &r).unwrap_err().status,
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn absolute_form_inside_a_tunnel_is_refused() {
    let r = route(UPSTREAM_HOST, &[], None);
    let absolute = parts(
        "GET",
        "https://upstream.test/v1/x",
        &[("host", UPSTREAM_HOST)],
    );
    assert_eq!(
        vet_request(&absolute, UPSTREAM_HOST, &r)
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn rules_match_the_path_and_ignore_the_query() {
    let r = route(UPSTREAM_HOST, &["GET /v1/**"], None);
    let allowed = parts(
        "GET",
        "/v1/things?filter=/admin/x&page=2",
        &[("host", UPSTREAM_HOST)],
    );
    assert!(
        vet_request(&allowed, UPSTREAM_HOST, &r).is_ok(),
        "a query string must not be able to steer rule matching"
    );

    let denied = parts("GET", "/v2/things", &[("host", UPSTREAM_HOST)]);
    let err = vet_request(&denied, UPSTREAM_HOST, &r).unwrap_err();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
}

// ─── Forwarding ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_permitted_request_reaches_the_upstream_with_the_credential() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let (status, body) = read_body(
        tunnel
            .send_request(get("/v1/things", UPSTREAM_HOST, &[]))
            .await
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("x-test-secret: tok-s3cret-value"),
        "the upstream should have seen the injected credential, got:\n{body}"
    );
    assert!(h.logs().contains("allowed (200)"), "{}", h.logs());
}

#[tokio::test]
async fn a_client_supplied_copy_of_the_injected_header_is_replaced() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let (_, body) = read_body(
        tunnel
            .send_request(get(
                "/v1/things",
                UPSTREAM_HOST,
                &[("x-test-secret", "attacker-chosen")],
            ))
            .await
            .unwrap(),
    )
    .await;

    assert!(
        body.contains("x-test-secret: tok-s3cret-value"),
        "got:\n{body}"
    );
    assert!(
        !body.contains("attacker-chosen"),
        "the client's copy must not survive, got:\n{body}"
    );
    assert_eq!(
        body.matches("x-test-secret").count(),
        1,
        "the upstream must see exactly one copy, got:\n{body}"
    );
}

#[tokio::test]
async fn hop_by_hop_headers_do_not_reach_the_upstream() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let (_, body) = read_body(
        tunnel
            .send_request(get(
                "/v1/things",
                UPSTREAM_HOST,
                &[
                    ("proxy-authorization", "Basic c3B5Ong="),
                    ("proxy-connection", "keep-alive"),
                ],
            ))
            .await
            .unwrap(),
    )
    .await;

    assert!(!body.contains("proxy-authorization"), "got:\n{body}");
    assert!(!body.contains("proxy-connection"), "got:\n{body}");
}

#[tokio::test]
async fn the_query_string_is_forwarded_untouched_but_never_logged() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let (_, body) = read_body(
        tunnel
            .send_request(get("/v1/things?leak=deadbeef&page=2", UPSTREAM_HOST, &[]))
            .await
            .unwrap(),
    )
    .await;

    assert!(
        body.starts_with("GET /v1/things?leak=deadbeef&page=2\n"),
        "got:\n{body}"
    );
    let logs = h.logs();
    assert!(logs.contains("/v1/things"), "{logs}");
    assert!(
        !logs.contains("deadbeef"),
        "the query string may carry data and must stay out of the log: {logs}"
    );
}

#[tokio::test]
async fn a_denied_request_inside_a_tunnel_gets_403() {
    let h = Harness::new(
        vec![route(UPSTREAM_HOST, &["GET /v1/**"], Some(bearer()))],
        secret_store("api_key", "s3cret-value", true),
    )
    .await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let (status, body) = read_body(
        tunnel
            .send_request(get("/v2/things", UPSTREAM_HOST, &[]))
            .await
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("not permitted by the route"), "{body}");
}

#[tokio::test]
async fn a_forged_host_header_inside_a_tunnel_gets_400() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let (status, _) = read_body(
        tunnel
            .send_request(get("/v1/things", "other.test", &[]))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_stale_secret_fails_the_request_with_502() {
    let h = Harness::new(
        vec![route(UPSTREAM_HOST, &["GET /**"], Some(bearer()))],
        secret_store("api_key", "s3cret-value", false),
    )
    .await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let (status, body) = read_body(
        tunnel
            .send_request(get("/v1/things", UPSTREAM_HOST, &[]))
            .await
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.contains("stale"), "{body}");
    assert!(!body.contains("s3cret-value"), "{body}");
}

#[tokio::test]
async fn one_tunnel_serves_several_requests() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;

    let (first_status, first) = read_body(
        tunnel
            .send_request(get("/v1/one", UPSTREAM_HOST, &[]))
            .await
            .unwrap(),
    )
    .await;
    let (second_status, second) = read_body(
        tunnel
            .send_request(get("/v1/two", UPSTREAM_HOST, &[]))
            .await
            .unwrap(),
    )
    .await;

    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(second_status, StatusCode::OK);
    assert!(first.starts_with("GET /v1/one\n"), "{first}");
    assert!(second.starts_with("GET /v1/two\n"), "{second}");
    assert!(
        second.contains("x-test-secret: tok-s3cret-value"),
        "the credential is looked up per request, got:\n{second}"
    );
    assert_eq!(
        h.logs().matches("allowed (200)").count(),
        2,
        "both requests should be audited"
    );
}

#[tokio::test]
async fn the_secret_never_reaches_the_ring_buffer() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let _ = tunnel
        .send_request(get(
            "/v1/things",
            UPSTREAM_HOST,
            &[("x-test-secret", "attacker-chosen")],
        ))
        .await
        .unwrap();
    // Also exercise a denial, which formats a reason string.
    let _ = tunnel
        .send_request(get("/v1/../x", UPSTREAM_HOST, &[]))
        .await;

    let logs = h.logs();
    assert!(!logs.contains("s3cret-value"), "{logs}");
    assert!(!logs.contains("tok-"), "{logs}");
    assert!(!logs.contains("x-test-secret"), "{logs}");
    assert!(!logs.contains(&h.token()), "{logs}");
}

// ─── Header assembly ──────────────────────────────────────────────────────────

#[test]
fn the_credential_is_prefix_secret_suffix() {
    let inject = Inject::parse("Authorization", "Bearer {secret}!", "k").unwrap();
    let value = build_header_value(&inject, "abc").unwrap();
    assert_eq!(value.as_bytes(), b"Bearer abc!");
    assert!(
        value.is_sensitive(),
        "the credential header must be marked sensitive"
    );
}

#[test]
fn a_secret_that_cannot_be_a_header_value_is_rejected() {
    let inject = Inject::parse("Authorization", "Bearer {secret}", "k").unwrap();
    assert!(build_header_value(&inject, "line1\nline2").is_err());
}

#[test]
fn stripping_removes_every_copy_of_the_injected_header() {
    let inject = bearer();
    let mut headers = HeaderMap::new();
    headers.append("x-test-secret", HeaderValue::from_static("one"));
    headers.append("x-test-secret", HeaderValue::from_static("two"));
    headers.append("x-keep", HeaderValue::from_static("kept"));
    strip_forbidden_headers(&mut headers, Some(&inject));
    assert!(headers.get("x-test-secret").is_none());
    assert_eq!(headers.get("x-keep").unwrap(), "kept");
}

#[test]
fn content_length_survives_stripping() {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("7"));
    headers.insert(
        header::TRANSFER_ENCODING,
        HeaderValue::from_static("chunked"),
    );
    strip_forbidden_headers(&mut headers, None);
    assert_eq!(headers.get(header::CONTENT_LENGTH).unwrap(), "7");
    assert!(headers.get(header::TRANSFER_ENCODING).is_none());
}

// ─── Child environment ────────────────────────────────────────────────────────

#[tokio::test]
async fn the_child_environment_points_at_the_proxy_and_the_ca() {
    let h = Harness::default().await;
    let mut env: HashMap<String, String> = HashMap::new();
    // A tool-declared value must lose to the daemon's.
    env.insert("HTTPS_PROXY".to_string(), "http://elsewhere".to_string());
    env.insert("NO_PROXY".to_string(), "*".to_string());
    h.session.apply_env(&mut env);

    let expected = format!(
        "http://airlock:{}@127.0.0.1:{}",
        h.token(),
        h.session.port()
    );
    for name in PROXY_URL_VARS {
        assert_eq!(env[*name], expected, "{name}");
    }
    for name in NO_PROXY_VARS {
        assert_eq!(env[*name], "", "{name}");
    }
    for name in CA_BUNDLE_VARS {
        assert_eq!(env[*name], "/nonexistent/airlock-ca.pem", "{name}");
    }
}

// ─── SSRF address classification ──────────────────────────────────────────────

#[test]
fn only_globally_routable_addresses_are_dialled() {
    let refused = [
        // IPv4: unspecified, loopback, private, link-local (metadata), CGNAT,
        // multicast, broadcast, documentation, reserved, protocol assignments.
        "0.0.0.0",
        "0.1.2.3",
        "127.0.0.1",
        "127.0.0.53",
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "169.254.169.254",
        "169.254.0.1",
        "100.64.0.1",
        "100.127.255.255",
        "224.0.0.1",
        "239.255.255.250",
        "255.255.255.255",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "192.0.0.1",
        "198.18.0.1",
        "198.19.255.255",
        "240.0.0.1",
        // IPv6: unspecified, loopback, ULA, link-local, multicast,
        // documentation, NAT64, discard.
        "::",
        "::1",
        "fc00::1",
        "fd12:3456::1",
        "fe80::1",
        "febf::1",
        "ff02::1",
        "2001:db8::1",
        "64:ff9b::1",
        "100::1",
        // IPv4-mapped forms of the above.
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "::10.0.0.1",
        "::7f00:1",
    ];
    for addr in refused {
        assert!(
            !is_globally_routable(addr.parse().unwrap()),
            "{addr} must not be dialled"
        );
    }

    let allowed = [
        "1.1.1.1",
        "8.8.8.8",
        "142.250.74.14",
        "172.32.0.1",
        "100.63.255.255",
        "100.128.0.1",
        "2606:4700:4700::1111",
        "2a00:1450:4001:80e::200e",
        "::ffff:1.1.1.1",
    ];
    for addr in allowed {
        assert!(
            is_globally_routable(addr.parse().unwrap()),
            "{addr} should be dialled"
        );
    }
}

#[tokio::test]
async fn a_host_resolving_to_loopback_is_refused() {
    // `localhost` is the one name every machine resolves inward.
    let err = resolve_public("localhost", 443).await.unwrap_err();
    assert!(
        matches!(err, UpstreamError::Refused(_)),
        "got {err:?}, expected a refusal"
    );
}

// ─── A real HTTP client through the proxy ─────────────────────────────────────

/// Apple's system curl, through the proxy, trusting only the name-constrained
/// Airlock CA.
///
/// This is the end of the chain the design doc left open: a client built
/// against LibreSSL rather than rustls, driven only by the environment the
/// daemon sets, verifying an intercepted connection against a CA whose Name
/// Constraints permit exactly the routed suffix. It stays hermetic — curl
/// never resolves anything, because with a proxy set it hands the authority
/// to the proxy and the proxy's connector is the local test upstream.
#[tokio::test]
async fn system_curl_completes_a_request_through_the_proxy() {
    let curl = std::path::Path::new("/usr/bin/curl");
    if !curl.exists() {
        return;
    }

    let h = Harness::default().await;
    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("airlock-ca.pem");
    h.ca.write_cert_pem(&ca_path).unwrap();

    let mut env: HashMap<String, String> = HashMap::new();
    h.session.apply_env(&mut env);
    // apply_env points at the session's own (nonexistent) path; the bundle the
    // daemon writes is what a real child reads, so point at the real file.
    for name in CA_BUNDLE_VARS {
        env.insert((*name).to_string(), ca_path.display().to_string());
    }

    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("/usr/bin/curl")
            .args([
                "-sS",
                "--max-time",
                "20",
                &format!("https://{UPSTREAM_HOST}/v1/things?page=2"),
            ])
            .env_clear()
            .envs(&env)
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "curl failed: {stderr}\nstdout: {stdout}"
    );
    assert!(
        stdout.starts_with("GET /v1/things?page=2\n"),
        "got:\n{stdout}"
    );
    assert!(
        stdout.contains("x-test-secret: tok-s3cret-value"),
        "the credential must reach the upstream, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("proxy-authorization"),
        "the proxy token must not be forwarded upstream, got:\n{stdout}"
    );
}

/// The same client, asking for a host no route covers.
#[tokio::test]
async fn system_curl_is_refused_for_an_unrouted_host() {
    let curl = std::path::Path::new("/usr/bin/curl");
    if !curl.exists() {
        return;
    }

    let h = Harness::default().await;
    let mut env: HashMap<String, String> = HashMap::new();
    h.session.apply_env(&mut env);

    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("/usr/bin/curl")
            .args(["-sS", "--max-time", "20", "https://other.test/v1/things"])
            .env_clear()
            .envs(&env)
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(
        !output.status.success(),
        "an unrouted host must not produce a successful request"
    );
    assert!(h.logs().contains("no route for host"), "{}", h.logs());
}

// ─── Lifetime ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn dropping_the_session_closes_the_listener() {
    let h = Harness::default().await;
    let port = h.session.port();
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok(),
        "the listener should be up while the session lives"
    );

    drop(h);
    // The abort takes effect at the next scheduling point.
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_err(),
        "dropping the session must take the proxy port down with it"
    );
}

#[tokio::test]
async fn dropping_the_session_closes_open_tunnels() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let (status, _) = read_body(
        tunnel
            .send_request(get("/v1/before", UPSTREAM_HOST, &[]))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    drop(h);
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(
        tunnel
            .send_request(get("/v1/after", UPSTREAM_HOST, &[]))
            .await
            .is_err(),
        "a tunnel must not keep attaching credentials after its exec has ended"
    );
}

#[test]
fn connect_authority_is_canonicalized() {
    let authority = "Api.Example.COM.:443".parse().unwrap();
    assert_eq!(
        split_authority(&authority),
        Some(("api.example.com".to_string(), 443))
    );
    let no_port = "api.example.com".parse().unwrap();
    assert_eq!(split_authority(&no_port), None);
}
