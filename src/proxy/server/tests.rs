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
const SECRET_LABEL: &str = "api_key";
const SECRET_VALUE: &str = "s3cret-value";
const PLACEHOLDER: &str = "[REDACTED:api_key]";
/// Literal text the injected header wraps the secret in, so a test can take
/// the secret back out of what the upstream received.
const INJECT_PREFIX: &str = "tok-";

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
    Inject::parse("X-Test-Secret", "tok-{secret}", SECRET_LABEL).unwrap()
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

/// The daemon's live redactor handle, built over the same store the proxy
/// injects from — which is how the real daemon builds it.
fn live_redactor(secrets: &SecretStore) -> Arc<RwLock<Arc<Redactor>>> {
    let values: Vec<(String, Arc<Secret<String>>)> = secrets
        .iter()
        .map(|(name, slot)| {
            let slot = slot.read().unwrap();
            (name.clone(), Arc::clone(&slot.value))
        })
        .collect();
    let refs: Vec<(&str, &Secret<String>)> = values
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_ref()))
        .collect();
    Arc::new(RwLock::new(Arc::new(Redactor::new(refs).unwrap())))
}

fn encode_base64(value: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
}

fn encode_url(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn encode_hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
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

/// Every request the upstream received, recorded out of band.
///
/// The proxy redacts what it forwards, so an echo that comes back through the
/// proxy can no longer tell a test what the upstream actually saw. This can.
type Seen = Arc<std::sync::Mutex<Vec<String>>>;

/// A TLS server that reports back what it received: the request target and one
/// line per header. Paths other than the default select a canned response
/// shape — a compressed body, a leaking header, a body delivered in pieces —
/// so that each thing the response path has to cope with has an upstream that
/// produces it.
struct TestUpstream {
    addr: SocketAddr,
    ca: Arc<ProxyCa>,
    seen: Seen,
}

/// What the upstream received, as `METHOD target` followed by sorted headers.
fn request_summary(req: &Request<Incoming>) -> String {
    let mut out = format!(
        "{} {}\n",
        req.method(),
        req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("")
    );
    let mut headers: Vec<_> = req
        .headers()
        .iter()
        .map(|(n, v)| format!("{}: {}\n", n, v.to_str().unwrap_or("<binary>")))
        .collect();
    headers.sort();
    out.extend(headers);
    out
}

/// The secret the proxy injected, recovered from the credential header. The
/// upstream learns it the same way a real one would: it was sent the thing.
fn injected_secret(req: &Request<Incoming>) -> String {
    req.headers()
        .get("x-test-secret")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix(INJECT_PREFIX))
        .unwrap_or("")
        .to_string()
}

/// A body whose frames arrive one at a time from a task, so that a secret can
/// be made to straddle a frame boundary and a long download can be stopped
/// half-way. The channel holds one frame, so a reader that stops reading stops
/// the sender.
struct FramedBody(tokio::sync::mpsc::Receiver<Vec<u8>>);

impl Body for FramedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        match self.get_mut().0.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => Poll::Ready(Some(Ok(Frame::data(Bytes::from(chunk))))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn framed_body(chunks: Vec<Vec<u8>>) -> ProxyBody {
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    tokio::spawn(async move {
        for chunk in chunks {
            if tx.send(chunk).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    FramedBody(rx).boxed()
}

fn status_only(status: StatusCode, headers: &[(&str, &str)]) -> Response<ProxyBody> {
    let mut response = Response::new(empty_body());
    *response.status_mut() = status;
    for (name, value) in headers {
        response.headers_mut().insert(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    response
}

async fn upstream_response(req: Request<Incoming>, seen: Seen) -> Response<ProxyBody> {
    let summary = request_summary(&req);
    seen.lock().unwrap().push(summary.clone());
    let secret = injected_secret(&req);

    match req.uri().path() {
        // The credential in every encoding the redactor knows.
        "/encoded" => Response::new(text_body(&format!(
            "b64 {} url {} hex {}",
            encode_base64(&secret),
            encode_url(&secret),
            encode_hex(&secret)
        ))),
        // The credential cut in half across two frames.
        "/frames" => {
            let (head, tail) = secret.split_at(secret.len() / 2);
            Response::new(framed_body(vec![
                b"start ".to_vec(),
                head.as_bytes().to_vec(),
                format!("{tail} end").into_bytes(),
            ]))
        }
        // The credential in header values rather than the body.
        "/header-leak" => {
            let mut response = Response::new(text_body("see the headers"));
            response.headers_mut().insert(
                "location",
                HeaderValue::from_str(&format!("https://{UPSTREAM_HOST}/next?token={secret}"))
                    .unwrap(),
            );
            response.headers_mut().insert(
                "set-cookie",
                HeaderValue::from_str(&format!("session={secret}; Path=/")).unwrap(),
            );
            response
        }
        // The credential in the status line's reason phrase.
        "/reason-leak" => {
            let mut response = Response::new(text_body("see the status line"));
            response.extensions_mut().insert(
                hyper::ext::ReasonPhrase::try_from(format!("OK {secret}").into_bytes()).unwrap(),
            );
            response
        }
        // An upstream that ignores `Accept-Encoding: identity`.
        "/gzip" => {
            let mut response = Response::new(text_body(&format!("not really gzip, but {secret}")));
            response
                .headers_mut()
                .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
            response
        }
        // A partial representation, which a range request would have asked for.
        "/partial" => {
            let mut response = Response::new(text_body(&secret));
            *response.status_mut() = StatusCode::PARTIAL_CONTENT;
            response.headers_mut().insert(
                header::CONTENT_RANGE,
                HeaderValue::from_static("bytes 0-11/24"),
            );
            response
        }
        // Tens of megabytes with the credential buried in the middle.
        "/large" => {
            let filler = vec![b'x'; 4 * 1024 * 1024];
            let mut chunks: Vec<Vec<u8>> = vec![filler.clone(); 4];
            chunks.push(secret.into_bytes());
            chunks.extend(std::iter::repeat_n(filler, 4));
            Response::new(framed_body(chunks))
        }
        "/no-content" => status_only(StatusCode::NO_CONTENT, &[]),
        "/not-modified" => status_only(StatusCode::NOT_MODIFIED, &[("content-length", "42")]),
        _ => Response::new(text_body(&summary)),
    }
}

async fn start_upstream() -> TestUpstream {
    let ca = ca_for(&[UPSTREAM_HOST]);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(ca.server_config(UPSTREAM_HOST).unwrap());
    let seen: Seen = Arc::new(std::sync::Mutex::new(Vec::new()));

    let accepted = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let seen = Arc::clone(&accepted);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(move |req: Request<Incoming>| {
                    let seen = Arc::clone(&seen);
                    async move { Ok::<_, Infallible>(upstream_response(req, seen).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });

    TestUpstream { addr, ca, seen }
}

// ─── The harness ──────────────────────────────────────────────────────────────

struct Harness {
    session: ProxySession,
    ca: Arc<ProxyCa>,
    ring_buffer: RingBuffer,
    secrets: SecretStore,
    redactor: Arc<RwLock<Arc<Redactor>>>,
    seen: Seen,
}

impl Harness {
    async fn new(routes: Vec<ProxyRoute>, secrets: SecretStore) -> Self {
        let upstream = start_upstream().await;
        let ca = ca_for(&[UPSTREAM_HOST, "other.test"]);
        let ring_buffer = RingBuffer::new();
        let redactor = live_redactor(&secrets);
        let session = ProxySession::start_with_upstream(
            "curl".to_string(),
            ProxyPolicy { routes },
            Arc::clone(&ca),
            PathBuf::from("/nonexistent/airlock-ca.pem"),
            Arc::clone(&secrets),
            Arc::clone(&redactor),
            ring_buffer.clone(),
            Upstream::fixed(upstream.addr, root_store(&upstream.ca)),
        )
        .unwrap();
        Harness {
            session,
            ca,
            ring_buffer,
            secrets,
            redactor,
            seen: upstream.seen,
        }
    }

    /// The default fixture: one route for the upstream that injects a
    /// credential and permits `GET /**`.
    async fn default() -> Self {
        Self::new(
            vec![route(UPSTREAM_HOST, &["GET /**"], Some(bearer()))],
            secret_store(SECRET_LABEL, SECRET_VALUE, true),
        )
        .await
    }

    /// What the upstream received, as it received it.
    fn seen(&self) -> String {
        self.seen.lock().unwrap().join("\n")
    }

    /// Stand in for a background refresh: swap the stored value and rebuild
    /// the redactor, exactly as [`crate::refresh::refresh_once`] does.
    fn refresh_secret(&self, value: &str) {
        {
            let mut slot = self.secrets[SECRET_LABEL].write().unwrap();
            slot.value = Arc::new(Secret::new(value.to_string()));
        }
        *self.redactor.write().unwrap() = Arc::clone(&live_redactor(&self.secrets).read().unwrap());
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
async fn connect_beyond_the_tunnel_limit_is_refused_before_upgrading() {
    let h = Harness::default().await;
    let mut open = Vec::with_capacity(MAX_CONCURRENT_TUNNELS);
    for _ in 0..MAX_CONCURRENT_TUNNELS {
        open.push(h.tunnel(UPSTREAM_HOST).await);
    }
    let response = h
        .connect(&format!("{UPSTREAM_HOST}:443"), Some(&h.auth()))
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(h.logs().contains("tunnels already open"), "{}", h.logs());

    drop(open);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let response = h
        .connect(&format!("{UPSTREAM_HOST}:443"), Some(&h.auth()))
        .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "closing a tunnel frees its slot"
    );
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

#[test]
fn vet_connect_returns_the_canonical_host_or_a_denial() {
    let policy = ProxyPolicy {
        routes: vec![route(UPSTREAM_HOST, &[], None)],
    };
    let vet = |method: Method, target: &str| {
        vet_connect(&method, &target.parse::<Uri>().unwrap(), &policy)
    };

    assert_eq!(
        vet(Method::CONNECT, "Upstream.TEST:443").unwrap(),
        UPSTREAM_HOST
    );

    for (method, target, status) in [
        (Method::GET, "http://upstream.test/", StatusCode::FORBIDDEN),
        (Method::CONNECT, "upstream.test:8443", StatusCode::FORBIDDEN),
        (Method::CONNECT, "other.test:443", StatusCode::FORBIDDEN),
        (Method::CONNECT, "upstream.test", StatusCode::BAD_REQUEST),
    ] {
        let denial = vet(method.clone(), target).unwrap_err();
        assert_eq!(
            denial.status, status,
            "{method} {target}: {}",
            denial.reason
        );
    }
}

#[tokio::test]
async fn a_malformed_connect_target_is_audited() {
    let h = Harness::default().await;
    let response = h.connect("upstream.test", Some(&h.auth())).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        h.logs().contains("malformed CONNECT target"),
        "{}",
        h.logs()
    );
}

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
        h.seen().contains("x-test-secret: tok-s3cret-value"),
        "the upstream should have seen the injected credential, got:\n{}",
        h.seen()
    );
    assert!(
        body.contains(&format!("x-test-secret: tok-{PLACEHOLDER}")),
        "the echo of it must come back redacted, got:\n{body}"
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

    let seen = h.seen();
    assert!(
        seen.contains("x-test-secret: tok-s3cret-value"),
        "got:\n{seen}"
    );
    assert!(
        !seen.contains("attacker-chosen"),
        "the client's copy must not survive, got:\n{seen}"
    );
    assert_eq!(
        seen.matches("x-test-secret").count(),
        1,
        "the upstream must see exactly one copy, got:\n{seen}"
    );
    assert!(!body.contains(SECRET_VALUE), "got:\n{body}");
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
    assert_eq!(
        h.seen().matches("x-test-secret: tok-s3cret-value").count(),
        2,
        "the credential is looked up per request, got:\n{}",
        h.seen()
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

// ─── Response redaction ───────────────────────────────────────────────────────

// Everything the upstream sends back goes through the redactor, so a test
// asserting on a response is asserting on what the *tool* would have written
// to a file. `h.seen()` is the only window onto the unredacted truth.

fn request(method: Method, target: &str, extra: &[(&str, &str)]) -> Request<ProxyBody> {
    let mut builder = Request::builder()
        .method(method)
        .uri(target)
        .header(header::HOST, UPSTREAM_HOST);
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    builder.body(empty_body()).unwrap()
}

/// A harness whose route permits every method, for HEAD and the canned
/// response endpoints.
async fn any_method_harness() -> Harness {
    Harness::new(
        vec![route(UPSTREAM_HOST, &["* /**"], Some(bearer()))],
        secret_store(SECRET_LABEL, SECRET_VALUE, true),
    )
    .await
}

/// Read a response body frame by frame, returning the byte count and whether
/// any window of the stream ever spelled the secret out.
async fn scan_body(response: Response<Incoming>) -> (usize, bool) {
    let mut body = response.into_body();
    let mut total = 0;
    let mut leaked = false;
    // A window wide enough that a secret straddling two frames is still seen.
    let mut window: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.unwrap();
        let Ok(data) = frame.into_data() else {
            continue;
        };
        total += data.len();
        window.extend_from_slice(&data);
        if String::from_utf8_lossy(&window).contains(SECRET_VALUE) {
            leaked = true;
        }
        let keep = window.len().saturating_sub(64);
        window.drain(..keep);
    }
    (total, leaked)
}

#[tokio::test]
async fn an_echoed_credential_is_redacted_in_the_response_body() {
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
    assert!(!body.contains(SECRET_VALUE), "got:\n{body}");
    assert!(body.contains(PLACEHOLDER), "got:\n{body}");
    // Byte-for-byte what the single-shot redactor makes of what the upstream
    // sent: streaming must not change the result.
    let expected = h
        .redactor
        .read()
        .unwrap()
        .redact_bytes(format!("{}\n", h.seen()).as_bytes());
    assert_eq!(body.as_bytes(), expected.as_slice());
}

#[tokio::test]
async fn encoded_spellings_of_the_secret_are_redacted() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let (_, body) = read_body(
        tunnel
            .send_request(get("/encoded", UPSTREAM_HOST, &[]))
            .await
            .unwrap(),
    )
    .await;

    for encoded in [
        encode_base64(SECRET_VALUE),
        encode_url(SECRET_VALUE),
        encode_hex(SECRET_VALUE),
    ] {
        assert!(!body.contains(&encoded), "{encoded} survived in:\n{body}");
    }
    assert_eq!(body.matches(PLACEHOLDER).count(), 3, "got:\n{body}");
}

#[tokio::test]
async fn a_secret_split_across_upstream_frames_is_redacted() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let (_, body) = read_body(
        tunnel
            .send_request(get("/frames", UPSTREAM_HOST, &[]))
            .await
            .unwrap(),
    )
    .await;

    assert_eq!(body, format!("start {PLACEHOLDER} end"), "got:\n{body}");
}

#[tokio::test]
async fn secrets_in_response_header_values_are_redacted() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let response = tunnel
        .send_request(get("/header-leak", UPSTREAM_HOST, &[]))
        .await
        .unwrap();

    let location = response.headers()[header::LOCATION].to_str().unwrap();
    let cookie = response.headers()["set-cookie"].to_str().unwrap();
    assert_eq!(
        location,
        format!("https://{UPSTREAM_HOST}/next?token={PLACEHOLDER}")
    );
    assert_eq!(cookie, format!("session={PLACEHOLDER}; Path=/"));
    assert!(
        h.logs().contains("with 2 header value(s) redacted"),
        "{}",
        h.logs()
    );
}

#[tokio::test]
async fn the_upstream_content_length_is_not_forwarded() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let response = tunnel
        .send_request(get("/v1/things", UPSTREAM_HOST, &[]))
        .await
        .unwrap();

    assert!(
        response.headers().get(header::CONTENT_LENGTH).is_none(),
        "a length computed before redaction would be wrong; hyper must chunk instead"
    );
    // Reading to the end must neither truncate nor hang.
    let (_, body) = read_body(response).await;
    assert!(body.ends_with('\n'), "got:\n{body}");
}

#[tokio::test]
async fn a_head_response_keeps_its_length_and_carries_no_body() {
    let h = any_method_harness().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let response = tunnel
        .send_request(request(Method::HEAD, "/v1/things", &[]))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get(header::CONTENT_LENGTH).is_some(),
        "on a bodiless response the length is metadata and must survive"
    );
    let (_, body) = read_body(response).await;
    assert!(body.is_empty(), "a HEAD response has no body, got:\n{body}");
}

#[tokio::test]
async fn bodiless_statuses_pass_through() {
    let h = any_method_harness().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;

    let (status, body) = read_body(
        tunnel
            .send_request(get("/no-content", UPSTREAM_HOST, &[]))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_empty());

    // The proxy keeps the upstream's `Content-Length` on a 304 — hyper then
    // drops it on the wire, as it does for every 204 and 304 it writes. What
    // matters here is that nothing is framed as a body and nothing hangs.
    let response = tunnel
        .send_request(get("/not-modified", UPSTREAM_HOST, &[]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    let (_, body) = read_body(response).await;
    assert!(body.is_empty());
}

#[tokio::test]
async fn a_compressed_response_fails_closed() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let (status, body) = read_body(
        tunnel
            .send_request(get("/gzip", UPSTREAM_HOST, &[]))
            .await
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.contains("content-encoded"), "got:\n{body}");
    assert!(
        !body.contains(SECRET_VALUE) && !body.contains("not really gzip"),
        "no byte of an unreadable body may be forwarded, got:\n{body}"
    );
    assert!(h.logs().contains("content-encoded"), "{}", h.logs());
}

#[tokio::test]
async fn a_partial_response_fails_closed() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let (status, body) = read_body(
        tunnel
            .send_request(get("/partial", UPSTREAM_HOST, &[]))
            .await
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.contains("byte range"), "got:\n{body}");
    assert!(!body.contains(SECRET_VALUE), "got:\n{body}");
}

#[tokio::test]
async fn the_client_accept_encoding_is_replaced_and_ranges_are_stripped() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let _ = tunnel
        .send_request(get(
            "/v1/things",
            UPSTREAM_HOST,
            &[
                ("accept-encoding", "gzip, deflate, br"),
                ("range", "bytes=0-99"),
                ("if-range", "\"etag\""),
            ],
        ))
        .await
        .unwrap();

    let seen = h.seen();
    assert!(seen.contains("accept-encoding: identity"), "got:\n{seen}");
    assert!(!seen.contains("gzip"), "got:\n{seen}");
    assert!(!seen.contains("range:"), "got:\n{seen}");
}

#[tokio::test]
async fn a_large_body_streams_through_redacted() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let response = tunnel
        .send_request(get("/large", UPSTREAM_HOST, &[]))
        .await
        .unwrap();

    let (total, leaked) = scan_body(response).await;
    assert!(!leaked, "the secret must not survive a 33 MB stream");
    assert_eq!(
        total,
        32 * 1024 * 1024 + PLACEHOLDER.len(),
        "every filler byte must arrive, and the secret must arrive replaced"
    );
    assert!(
        h.logs()
            .contains("response body: 1 secret occurrence(s) redacted"),
        "{}",
        h.logs()
    );
}

#[tokio::test]
async fn a_secret_refreshed_mid_session_is_redacted_in_the_next_response() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;

    let (_, first) = read_body(
        tunnel
            .send_request(get("/v1/one", UPSTREAM_HOST, &[]))
            .await
            .unwrap(),
    )
    .await;
    assert!(first.contains(PLACEHOLDER), "got:\n{first}");

    h.refresh_secret("rotated-value");

    let (_, second) = read_body(
        tunnel
            .send_request(get("/v1/two", UPSTREAM_HOST, &[]))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        h.seen().contains("x-test-secret: tok-rotated-value"),
        "the proxy must inject the fresh value, got:\n{}",
        h.seen()
    );
    assert!(
        !second.contains("rotated-value"),
        "and must redact the value it just injected, got:\n{second}"
    );
    assert!(second.contains(PLACEHOLDER), "got:\n{second}");
}

#[tokio::test]
async fn dropping_the_session_ends_a_response_body_mid_stream() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let response = tunnel
        .send_request(get("/large", UPSTREAM_HOST, &[]))
        .await
        .unwrap();
    let mut body = response.into_body();

    let first = body.frame().await.expect("a first frame").unwrap();
    assert!(first.data_ref().is_some());

    drop(h);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut delivered = 0;
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => delivered += frame.data_ref().map_or(0, |d| d.len()),
            Err(_) => break,
        }
    }
    assert!(
        delivered < 32 * 1024 * 1024,
        "a cancelled session must stop the upstream read, not drain it"
    );
}

// ─── Response handling (pure) ─────────────────────────────────────────────────

fn response_parts(status: StatusCode, headers: &[(&str, &str)]) -> hyper::http::response::Parts {
    let mut builder = Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(()).unwrap().into_parts().0
}

#[test]
fn only_a_plain_whole_representation_is_forwarded() {
    assert!(vet_response(&response_parts(StatusCode::OK, &[])).is_ok());
    assert!(
        vet_response(&response_parts(
            StatusCode::OK,
            &[("content-encoding", "identity")]
        ))
        .is_ok()
    );
    assert!(
        vet_response(&response_parts(
            StatusCode::OK,
            &[("transfer-encoding", "chunked")]
        ))
        .is_ok()
    );

    for bad in [
        vec![("content-encoding", "gzip")],
        vec![("content-encoding", "br")],
        vec![("content-encoding", "zstd")],
        vec![("content-encoding", "deflate")],
        vec![("content-encoding", "gzip, identity")],
        vec![
            ("content-encoding", "identity"),
            ("content-encoding", "gzip"),
        ],
        vec![("transfer-encoding", "gzip, chunked")],
        vec![("content-range", "bytes 0-9/100")],
    ] {
        assert!(
            vet_response(&response_parts(StatusCode::OK, &bad)).is_err(),
            "{bad:?} should fail closed"
        );
    }
    assert!(vet_response(&response_parts(StatusCode::PARTIAL_CONTENT, &[])).is_err());
}

#[test]
fn only_bodiless_responses_keep_their_length() {
    assert!(carries_no_body(&Method::HEAD, StatusCode::OK));
    assert!(carries_no_body(&Method::GET, StatusCode::NO_CONTENT));
    assert!(carries_no_body(&Method::GET, StatusCode::NOT_MODIFIED));
    assert!(carries_no_body(&Method::GET, StatusCode::CONTINUE));
    assert!(!carries_no_body(&Method::GET, StatusCode::OK));
    assert!(!carries_no_body(&Method::POST, StatusCode::CREATED));
}

#[test]
fn every_header_value_is_scanned_and_an_unrebuildable_one_is_dropped() {
    let secret = Secret::new("abc".to_string());
    let redactor = Redactor::new([("KEY", &secret)]).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(header::LOCATION, HeaderValue::from_static("/next?t=abc"));
    headers.append("set-cookie", HeaderValue::from_static("a=abc"));
    headers.append("set-cookie", HeaderValue::from_static("b=plain"));
    headers.insert("x-clean", HeaderValue::from_static("nothing here"));

    assert_eq!(redact_header_values(&mut headers, &redactor), 2);
    assert_eq!(headers[header::LOCATION], "/next?t=[REDACTED:KEY]");
    let cookies: Vec<_> = headers
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(cookies, vec!["a=[REDACTED:KEY]", "b=plain"]);
    assert_eq!(headers["x-clean"], "nothing here");
}

#[test]
fn the_upstream_request_asks_for_a_plain_whole_representation() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, br"),
    );
    headers.insert(header::RANGE, HeaderValue::from_static("bytes=0-99"));
    headers.insert(header::IF_RANGE, HeaderValue::from_static("\"etag\""));

    demand_a_plain_full_response(&mut headers);

    assert_eq!(headers[header::ACCEPT_ENCODING], "identity");
    assert!(headers.get(header::RANGE).is_none());
    assert!(headers.get(header::IF_RANGE).is_none());
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
        h.seen().contains("x-test-secret: tok-s3cret-value"),
        "the credential must reach the upstream, got:\n{}",
        h.seen()
    );
    assert!(
        !stdout.contains(SECRET_VALUE),
        "but must not come back, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("proxy-authorization"),
        "the proxy token must not be forwarded upstream, got:\n{stdout}"
    );
}

/// The file-write path the design record left open: `curl -o` puts the
/// response body straight into the sandbox root, where the agent reads it
/// without the daemon's stdout redaction ever touching it. What lands there
/// must already be redacted, because the proxy redacted it.
#[tokio::test]
async fn system_curl_writes_a_file_that_does_not_contain_the_secret() {
    let curl = std::path::Path::new("/usr/bin/curl");
    if !curl.exists() {
        return;
    }

    let h = Harness::default().await;
    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("airlock-ca.pem");
    h.ca.write_cert_pem(&ca_path).unwrap();
    let out_path = dir.path().join("out.json");
    let header_path = dir.path().join("headers.txt");

    let mut env: HashMap<String, String> = HashMap::new();
    h.session.apply_env(&mut env);
    for name in CA_BUNDLE_VARS {
        env.insert((*name).to_string(), ca_path.display().to_string());
    }

    let args = vec![
        "-sS".to_string(),
        "--max-time".to_string(),
        "20".to_string(),
        "--compressed".to_string(),
        "-o".to_string(),
        out_path.display().to_string(),
        "--dump-header".to_string(),
        header_path.display().to_string(),
        format!("https://{UPSTREAM_HOST}/header-leak"),
    ];
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("/usr/bin/curl")
            .args(&args)
            .env_clear()
            .envs(&env)
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "curl failed: {stderr}");

    let written = std::fs::read_to_string(&out_path).unwrap();
    let headers = std::fs::read_to_string(&header_path).unwrap();
    assert!(
        h.seen().contains("x-test-secret: tok-s3cret-value"),
        "the upstream must still have been authenticated"
    );
    assert!(
        !written.contains(SECRET_VALUE) && !headers.contains(SECRET_VALUE),
        "nothing curl wrote may hold the secret:\nbody: {written}\nheaders: {headers}"
    );
    assert!(
        headers.contains(PLACEHOLDER),
        "the leaking headers must arrive redacted, got:\n{headers}"
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

#[tokio::test]
async fn a_secret_in_the_reason_phrase_is_not_forwarded() {
    let h = Harness::default().await;
    let mut tunnel = h.tunnel(UPSTREAM_HOST).await;
    let response = tunnel
        .send_request(get("/reason-leak", UPSTREAM_HOST, &[]))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .extensions()
            .get::<hyper::ext::ReasonPhrase>()
            .is_none(),
        "the upstream's reason phrase is free text the redactor never sees"
    );
}
