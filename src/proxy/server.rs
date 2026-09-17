//! The per-exec HTTPS interception proxy that fronts a proxy tool.
//!
//! One listener is bound on an ephemeral loopback port for the lifetime of one
//! `airlock exec`, carrying only that tool's routes. The tool is pointed at it
//! through `HTTPS_PROXY` and told to trust the daemon's CA; the sandbox pins
//! the tool's egress to that one port, so the proxy is the tool's entire view
//! of the network.
//!
//! The load-bearing invariant is that **the tool never holds a secret**. The
//! credential is attached here, after the request has left the tool, so
//! everything the agent can read out of the tool's process, files or memory is
//! worthless. Egress pinning is the second layer, not the first.
//!
//! The CONNECT authority is the single source of truth for a request: it
//! selects the route, names the leaf certificate the tool is shown, is the
//! name resolved and dialled, and is the name the upstream certificate is
//! verified against. A forged `Host`, a forged SNI, `curl --resolve` and
//! `curl --connect-to` cannot make any two of those disagree.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::ServerName;
use subtle::ConstantTimeEq;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::{CancellationToken, DropGuard};
use zeroize::Zeroize;

use crate::daemon::RingBuffer;
use crate::redact::{Redactor, StreamRedactor};
use crate::secrets::{Health, SecretStore};

use super::ca::ProxyCa;
use super::{Inject, ProxyPolicy, ProxyRoute};

// ─── Bounds on what the peer controls ─────────────────────────────────────────

/// The only upstream port a route may reach. TLS interception is the whole
/// design; a non-443 CONNECT is refused rather than guessed at.
const UPSTREAM_PORT: u16 = 443;

/// Time a connection may take to deliver a complete set of request headers.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Cap on hyper's per-connection read buffer, which bounds the size of a
/// request line plus header block.
const MAX_HEADER_BYTES: usize = 32 * 1024;

/// Time a TLS handshake may take, in either direction.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Time an upstream TCP connect may take.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Concurrent CONNECT tunnels one exec may hold open. Each tunnel owns a TLS
/// session in both directions, so this is the memory bound on a tool that
/// opens connections in a loop.
const MAX_CONCURRENT_TUNNELS: usize = 32;

/// Proxy-auth username. The password is the per-exec token.
const PROXY_USER: &str = "airlock";

/// Environment variables the daemon sets for a proxy tool, pointing it at the
/// proxy and at the CA it must trust. Config validation reserves these names
/// so a tool cannot declare them itself.
const PROXY_URL_VARS: &[&str] = &[
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];
const NO_PROXY_VARS: &[&str] = &["NO_PROXY", "no_proxy"];
const CA_BUNDLE_VARS: &[&str] = &[
    "CURL_CA_BUNDLE",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
];

/// Hop-by-hop headers stripped before forwarding upstream. `Content-Length` is
/// deliberately *not* in this list: some APIs reject a chunked upload, so a
/// client-declared length is passed through rather than re-derived.
const HOP_BY_HOP_HEADERS: &[HeaderName] = &[
    header::CONNECTION,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

/// Body type shared by forwarded responses and the proxy's own error replies.
type ProxyBody = BoxBody<Bytes, hyper::Error>;

// ─── Per-exec session ─────────────────────────────────────────────────────────

/// A live proxy listener bound for the lifetime of one child process.
///
/// Dropping the session closes the listener and every connection and tunnel
/// under it. Holding it in a local of the exec handler therefore ties the
/// proxy's lifetime to the child's on *every* exit path — normal exit,
/// timeout, kill, client disconnect — without each of them having to remember
/// to tear it down.
///
/// Aborting the accept task alone would not do that: connections and tunnels
/// run as tasks of their own, and a process that escaped the child's process
/// group could keep a tunnel — and the credential it attaches — alive after
/// the exec had ended. The token reaches all of them.
pub struct ProxySession {
    port: u16,
    proxy_url: String,
    ca_path: PathBuf,
    task: JoinHandle<()>,
    _shutdown: DropGuard,
}

impl Drop for ProxySession {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl ProxySession {
    /// Bind a listener and start serving `policy` on it.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        tool: String,
        policy: ProxyPolicy,
        ca: Arc<ProxyCa>,
        ca_path: PathBuf,
        secrets: SecretStore,
        redactor: Arc<RwLock<Arc<Redactor>>>,
        ring_buffer: RingBuffer,
    ) -> std::io::Result<Self> {
        Self::start_with_upstream(
            tool,
            policy,
            ca,
            ca_path,
            secrets,
            redactor,
            ring_buffer,
            Upstream::public(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_with_upstream(
        tool: String,
        policy: ProxyPolicy,
        ca: Arc<ProxyCa>,
        ca_path: PathBuf,
        secrets: SecretStore,
        redactor: Arc<RwLock<Arc<Redactor>>>,
        ring_buffer: RingBuffer,
        upstream: Upstream,
    ) -> std::io::Result<Self> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        // The *bound* port, never a configured one: the listener asked for an
        // ephemeral port and the sandbox rule must name what it actually got.
        let port = listener.local_addr()?.port();
        let listener = TcpListener::from_std(listener)?;

        let shutdown = CancellationToken::new();
        let token = random_token();
        let proxy_url = format!("http://{PROXY_USER}:{token}@{}:{port}", Ipv4Addr::LOCALHOST);

        let ctx = Arc::new(ProxyContext {
            tool,
            policy,
            ca,
            secrets,
            redactor,
            ring_buffer,
            expected_auth: basic_auth_header(&token),
            upstream,
            tunnels: Arc::new(Semaphore::new(MAX_CONCURRENT_TUNNELS)),
            shutdown: shutdown.clone(),
        });

        Ok(ProxySession {
            port,
            proxy_url,
            ca_path,
            task: tokio::spawn(accept_loop(listener, ctx)),
            _shutdown: shutdown.drop_guard(),
        })
    }

    /// The loopback port the tool is allowed to reach.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The per-exec proxy URL, including the token. Tests read it to build a
    /// client; nothing else needs it, because [`Self::apply_env`] is the only
    /// way it reaches a child.
    #[cfg(test)]
    pub(crate) fn proxy_url(&self) -> &str {
        &self.proxy_url
    }

    /// Overlay the daemon-owned proxy variables onto a child environment.
    ///
    /// Applied after the tool's own `env`, so it wins: these names decide
    /// whether the tool talks to the proxy at all.
    pub fn apply_env(&self, env: &mut HashMap<String, String>) {
        let ca_path = self.ca_path.to_string_lossy().into_owned();
        for name in PROXY_URL_VARS {
            env.insert((*name).to_string(), self.proxy_url.clone());
        }
        // Empty rather than absent: an inherited `NO_PROXY` must not be able
        // to carve a direct-connect exception out of the proxy.
        for name in NO_PROXY_VARS {
            env.insert((*name).to_string(), String::new());
        }
        // The bundle holds only the Airlock CA. Every connection the tool can
        // make is intercepted, so public roots buy nothing — and leaving them
        // out means a direct connection that somehow escaped the sandbox would
        // still fail to verify.
        for name in CA_BUNDLE_VARS {
            env.insert((*name).to_string(), ca_path.clone());
        }
    }
}

// ─── Shared per-exec state ────────────────────────────────────────────────────

struct ProxyContext {
    tool: String,
    policy: ProxyPolicy,
    ca: Arc<ProxyCa>,
    secrets: SecretStore,
    /// The daemon's live redactor, not a snapshot of it. A tool runs for
    /// minutes and a refreshed token is injected from the *next* request on,
    /// so a redactor snapshotted when the session started would not know the
    /// value the proxy is now attaching.
    redactor: Arc<RwLock<Arc<Redactor>>>,
    ring_buffer: RingBuffer,
    /// The full `Proxy-Authorization` value this exec accepts.
    expected_auth: String,
    upstream: Upstream,
    tunnels: Arc<Semaphore>,
    /// Cancelled when the owning [`ProxySession`] is dropped.
    shutdown: CancellationToken,
}

impl ProxyContext {
    /// Record one proxied request. Never the query string (it may carry data)
    /// and never a header value.
    fn audit(&self, method: &Method, host: &str, path: &str, decision: &str) {
        self.ring_buffer.log(format!(
            "proxy [{}] {method} {host}{path} -> {decision}",
            self.tool
        ));
    }

    /// The redactor to apply to one response, taken when that response's
    /// headers arrive. The two generations a refresh leaves behind cover a
    /// swap that lands between this snapshot and the end of the body.
    fn redactor(&self) -> Arc<Redactor> {
        Arc::clone(&self.redactor.read().unwrap_or_else(|e| e.into_inner()))
    }
}

// ─── Accept loop ──────────────────────────────────────────────────────────────

async fn accept_loop(listener: TcpListener, ctx: Arc<ProxyContext>) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _peer)) => stream,
            Err(e) => {
                ctx.ring_buffer
                    .log(format!("proxy [{}] accept error: {e}", ctx.tool));
                // Back off so a persistently failing accept cannot spin.
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        let ctx = Arc::clone(&ctx);
        // One task per connection. A panic anywhere in the request path is
        // caught by tokio at the task boundary and cannot reach the daemon.
        tokio::spawn(async move {
            let shutdown = ctx.shutdown.clone();
            let service = service_fn(move |req| handle_proxy_request(req, Arc::clone(&ctx)));
            let serve = http1_builder()
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades();
            tokio::select! {
                _ = shutdown.cancelled() => {}
                _ = serve => {}
            }
        });
    }
}

fn http1_builder() -> hyper::server::conn::http1::Builder {
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        // hyper enforces `header_read_timeout` through a Timer it does not
        // provide itself; without one it panics rather than time out.
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_buf_size(MAX_HEADER_BYTES);
    builder
}

// ─── Outer request handling (cleartext, on the loopback port) ─────────────────

/// Handle one request arriving on the proxy port itself.
///
/// Only `CONNECT <host>:443` gets anywhere. A plain `GET http://…` proxy
/// request is refused outright: the credential must never be attached to a
/// cleartext request.
async fn handle_proxy_request(
    req: Request<Incoming>,
    ctx: Arc<ProxyContext>,
) -> Result<Response<ProxyBody>, Infallible> {
    // A loopback TCP port has no file mode — any local user can connect to it,
    // unlike the daemon's 0700 Unix socket. The token is what keeps another
    // user from racing an exec and having the daemon sign their requests. It
    // is visible to the tool, which is fine: it grants nothing the agent does
    // not already have through `airlock exec`.
    if !authorized(req.headers(), &ctx.expected_auth) {
        return Ok(auth_required());
    }

    if req.method() != Method::CONNECT {
        let host = req.uri().host().unwrap_or("-").to_string();
        ctx.audit(
            req.method(),
            &host,
            req.uri().path(),
            "denied: plain HTTP proxying is not supported",
        );
        return Ok(refuse(
            StatusCode::FORBIDDEN,
            "airlock proxy: only CONNECT to an https:// host is supported",
        ));
    }

    // For CONNECT the request-target *is* the authority; there is no path.
    let Some((host, port)) = req.uri().authority().and_then(split_authority) else {
        return Ok(refuse(
            StatusCode::BAD_REQUEST,
            "airlock proxy: malformed CONNECT target",
        ));
    };

    if port != UPSTREAM_PORT {
        ctx.audit(
            req.method(),
            &host,
            "",
            &format!("denied: port {port} is not {UPSTREAM_PORT}"),
        );
        return Ok(refuse(
            StatusCode::FORBIDDEN,
            "airlock proxy: only port 443 may be reached",
        ));
    }

    if ctx.policy.find_route(&host).is_none() {
        ctx.audit(req.method(), &host, "", "denied: no route for host");
        return Ok(refuse(
            StatusCode::FORBIDDEN,
            "airlock proxy: no route permits this host",
        ));
    }

    let tunnel_ctx = Arc::clone(&ctx);
    tokio::spawn(async move {
        let shutdown = tunnel_ctx.shutdown.clone();
        let tunnel = async {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => run_tunnel(upgraded, host, Arc::clone(&tunnel_ctx)).await,
                Err(e) => tunnel_ctx.ring_buffer.log(format!(
                    "proxy [{}] CONNECT upgrade failed: {e}",
                    tunnel_ctx.tool
                )),
            }
        };
        tokio::select! {
            _ = shutdown.cancelled() => {}
            _ = tunnel => {}
        }
    });

    Ok(Response::new(empty_body()))
}

/// Terminate TLS for one CONNECT tunnel and serve the requests inside it.
async fn run_tunnel(upgraded: hyper::upgrade::Upgraded, host: String, ctx: Arc<ProxyContext>) {
    let Ok(_permit) = Arc::clone(&ctx.tunnels).try_acquire_owned() else {
        ctx.ring_buffer.log(format!(
            "proxy [{}] refused a tunnel to {host}: {MAX_CONCURRENT_TUNNELS} already open",
            ctx.tool
        ));
        return;
    };

    // The leaf names the CONNECT authority. The client's SNI is never read.
    let server_config = match ctx.ca.server_config(&host) {
        Ok(config) => config,
        Err(e) => {
            ctx.ring_buffer.log(format!(
                "proxy [{}] could not mint a certificate for {host}: {e}",
                ctx.tool
            ));
            return;
        }
    };

    let accept = TlsAcceptor::from(server_config).accept(TokioIo::new(upgraded));
    let tls = match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, accept).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            ctx.ring_buffer
                .log(format!("proxy [{}] TLS handshake failed: {e}", ctx.tool));
            return;
        }
        Err(_) => {
            ctx.ring_buffer
                .log(format!("proxy [{}] TLS handshake timed out", ctx.tool));
            return;
        }
    };

    let service = service_fn(move |req| {
        let ctx = Arc::clone(&ctx);
        let host = host.clone();
        async move { handle_tunneled_request(req, host, ctx).await }
    });
    // No `with_upgrades`: nothing inside a tunnel may upgrade again.
    let _ = http1_builder()
        .serve_connection(TokioIo::new(tls), service)
        .await;
}

// ─── Inner request handling (inside the tunnel) ───────────────────────────────

/// Why a request was refused, and with what status.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Denial {
    pub(crate) status: StatusCode,
    pub(crate) reason: &'static str,
}

const fn deny(status: StatusCode, reason: &'static str) -> Denial {
    Denial { status, reason }
}

/// Decide whether a request inside a tunnel to `authority` may be forwarded.
///
/// Pure and total: everything it needs is the request head, the authority the
/// tunnel was opened to, and the route that authority selected.
pub(crate) fn vet_request(
    parts: &hyper::http::request::Parts,
    authority: &str,
    route: &ProxyRoute,
) -> Result<(), Denial> {
    // Inside a tunnel the request-target is origin-form. An absolute-form
    // target would give the request a second, disagreeing notion of its
    // destination.
    if parts.uri.scheme().is_some() || parts.uri.authority().is_some() {
        return Err(deny(
            StatusCode::BAD_REQUEST,
            "denied: request-target must be origin-form",
        ));
    }

    // No domain fronting: the name in the message must be the name the tunnel
    // was opened to, and thus the name the route was chosen for.
    match host_header(&parts.headers) {
        Some(host) if host_matches_authority(host, authority) => {}
        Some(_) => {
            return Err(deny(
                StatusCode::BAD_REQUEST,
                "denied: Host header does not match the CONNECT authority",
            ));
        }
        None => {
            return Err(deny(
                StatusCode::BAD_REQUEST,
                "denied: missing or duplicated Host header",
            ));
        }
    }

    // Request smuggling: two disagreeing framings, or two lengths.
    if parts.headers.contains_key(header::TRANSFER_ENCODING)
        && parts.headers.contains_key(header::CONTENT_LENGTH)
    {
        return Err(deny(
            StatusCode::BAD_REQUEST,
            "denied: Transfer-Encoding and Content-Length are both present",
        ));
    }
    if parts.headers.get_all(header::CONTENT_LENGTH).iter().count() > 1 {
        return Err(deny(
            StatusCode::BAD_REQUEST,
            "denied: duplicate Content-Length",
        ));
    }

    // Rules match the path only. The query string is forwarded untouched but
    // never matched against and never logged — it may carry data.
    if !route.permits(parts.method.as_str(), parts.uri.path()) {
        return Err(deny(
            StatusCode::FORBIDDEN,
            "denied: method and path are not permitted by the route",
        ));
    }

    Ok(())
}

async fn handle_tunneled_request(
    req: Request<Incoming>,
    host: String,
    ctx: Arc<ProxyContext>,
) -> Result<Response<ProxyBody>, Infallible> {
    let (mut parts, body) = req.into_parts();

    // The tunnel could only be opened for a routed host, so this is the same
    // route CONNECT matched; looking it up again keeps the decision next to
    // the request it governs.
    let Some(route) = ctx.policy.find_route(&host) else {
        return Ok(refuse(
            StatusCode::FORBIDDEN,
            "airlock proxy: no route permits this host",
        ));
    };

    let path = parts.uri.path().to_string();
    if let Err(denial) = vet_request(&parts, &host, route) {
        ctx.audit(&parts.method, &host, &path, denial.reason);
        return Ok(refuse(denial.status, denial.reason));
    }

    strip_forbidden_headers(&mut parts.headers, route.inject.as_ref());
    demand_a_plain_full_response(&mut parts.headers);

    if let Some(inject) = &route.inject {
        match self::inject_credential(&ctx.secrets, inject, &mut parts.headers) {
            Ok(()) => {}
            Err(reason) => {
                ctx.audit(&parts.method, &host, &path, reason);
                return Ok(refuse(StatusCode::BAD_GATEWAY, reason));
            }
        }
    }

    let method = parts.method.clone();
    match ctx
        .upstream
        .send(&host, Request::from_parts(parts, body))
        .await
    {
        Ok(response) => Ok(forward_response(response, method, host, path, &ctx)),
        Err(e) => {
            ctx.audit(&method, &host, &path, &format!("upstream error: {e}"));
            Ok(refuse(
                StatusCode::BAD_GATEWAY,
                "airlock proxy: upstream request failed",
            ))
        }
    }
}

// ─── Response handling ────────────────────────────────────────────────────────

/// Hand one upstream response back to the tool, redacted.
///
/// Every header value and every body byte goes through the same automaton the
/// tool's stdout goes through, so the plaintext secret never exists inside the
/// sandbox at all — not in a `-o` file, not in `--dump-header` output, not in
/// a trace. Redaction on the way out is not optional here any more than it is
/// on stdout, so there is no configuration that turns it off.
fn forward_response(
    response: Response<Incoming>,
    method: Method,
    host: String,
    path: String,
    ctx: &Arc<ProxyContext>,
) -> Response<ProxyBody> {
    let (mut parts, body) = response.into_parts();

    if let Err(reason) = vet_response(&parts) {
        // `body` is dropped unread. An opaque body is exactly the case where
        // forwarding would put bytes the redactor cannot see into the tool's
        // hands, so the response is refused rather than passed through.
        ctx.audit(&method, &host, &path, reason);
        return refuse(StatusCode::BAD_GATEWAY, reason);
    }

    for name in HOP_BY_HOP_HEADERS {
        parts.headers.remove(name);
    }
    let redactor = ctx.redactor();
    let header_redactions = redact_header_values(&mut parts.headers, &redactor);

    let bodiless = carries_no_body(&method, parts.status);
    if !bodiless {
        // A placeholder is not the length of the secret it replaces, and the
        // body has not been read yet, so an upstream `Content-Length` is
        // unknowable here and wrong the moment anything matches. Dropping it
        // leaves hyper to frame the response as chunked, which is always
        // available on HTTP/1.1. On a bodiless response the length describes
        // the representation rather than bytes on the wire, so it is kept.
        parts.headers.remove(header::CONTENT_LENGTH);
    }

    let mut decision = format!("allowed ({})", parts.status.as_u16());
    if header_redactions > 0 {
        decision.push_str(&format!(
            " with {header_redactions} header value(s) redacted"
        ));
    }
    ctx.audit(&method, &host, &path, &decision);

    let body: ProxyBody = if bodiless {
        empty_body()
    } else {
        RedactedBody {
            inner: body,
            stream: StreamRedactor::new(redactor),
            ended: false,
            audit: ResponseAudit {
                ctx: Arc::clone(ctx),
                method,
                host,
                path,
            },
        }
        .boxed()
    };
    Response::from_parts(parts, body)
}

/// Whether an upstream response may be forwarded at all.
///
/// The redactor reads bytes, not formats. Anything that leaves the body as
/// something other than its plain, whole representation — a compressed
/// `Content-Encoding`, a transfer coding hyper has not already undone, or a
/// byte range that could begin in the middle of a secret — fails closed
/// instead of reaching the tool unexamined. Airlock does not decompress: a
/// decoder in the response path would be a second parser of attacker-supplied
/// bytes for no security gain, since the request already demands `identity`.
fn vet_response(parts: &hyper::http::response::Parts) -> Result<(), &'static str> {
    if let Some(encoding) = parts.headers.get(header::CONTENT_ENCODING)
        && !encoding.as_bytes().eq_ignore_ascii_case(b"identity")
    {
        return Err("denied: upstream response is content-encoded and cannot be redacted");
    }
    for coding in parts.headers.get_all(header::TRANSFER_ENCODING) {
        if !coding.as_bytes().eq_ignore_ascii_case(b"chunked") {
            return Err("denied: upstream response uses a transfer coding that cannot be redacted");
        }
    }
    if parts.status == StatusCode::PARTIAL_CONTENT
        || parts.headers.contains_key(header::CONTENT_RANGE)
    {
        return Err("denied: upstream response is a byte range, which may split a secret");
    }
    Ok(())
}

/// Replace every secret occurrence in every response header value.
///
/// All values, not a chosen subset: a `Location` carrying the token in a
/// query string, a `Set-Cookie` minted from it, and a debug header some API
/// adds are the same problem, and the set of header names an upstream may use
/// is not knowable in advance.
fn redact_header_values(headers: &mut HeaderMap, redactor: &Redactor) -> usize {
    let mut redactions = 0;
    let mut clean = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers.iter() {
        let redacted = redactor.redact_bytes(value.as_bytes());
        if redacted == value.as_bytes() {
            clean.append(name.clone(), value.clone());
            continue;
        }
        redactions += 1;
        // A redacted value that will not rebuild is dropped. The one outcome
        // that must not happen is the original going out instead.
        if let Ok(value) = HeaderValue::from_bytes(&redacted) {
            clean.append(name.clone(), value);
        }
    }
    *headers = clean;
    redactions
}

/// Whether the response has no body on the wire, in which case there is
/// nothing to redact and a `Content-Length` describes the representation the
/// request asked about rather than bytes being sent.
fn carries_no_body(method: &Method, status: StatusCode) -> bool {
    *method == Method::HEAD
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
}

/// The upstream body, redacted frame by frame on its way to the tool.
///
/// Nothing is buffered beyond the partial match at the end of a frame, so a
/// multi-gigabyte download costs what a small one costs, and no thread or task
/// sits behind it: the tool's own read rate drives the polls, the polls drive
/// the upstream reads, and a slow tool slows the upstream instead of filling
/// the daemon's memory. Dropping it — a disconnected tool, a cancelled
/// session — drops the upstream body with it.
struct RedactedBody {
    inner: Incoming,
    stream: StreamRedactor,
    ended: bool,
    audit: ResponseAudit,
}

/// What the body needs to report its own redaction count once it ends. The
/// count only — never a matched byte.
struct ResponseAudit {
    ctx: Arc<ProxyContext>,
    method: Method,
    host: String,
    path: String,
}

impl Body for RedactedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        loop {
            if this.ended {
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => {
                    this.ended = true;
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    // Trailers are dropped rather than forwarded: they arrive
                    // after the tool has already been handed the body, and no
                    // request reaches the upstream asking for them.
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    let redacted = this.stream.push(&data);
                    // A frame that was entirely held back as a possible
                    // partial match yields nothing yet; poll again rather
                    // than emit an empty frame.
                    if redacted.is_empty() {
                        continue;
                    }
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(redacted)))));
                }
                Poll::Ready(None) => {
                    this.ended = true;
                    let tail = this.stream.finish();
                    if tail.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(tail)))));
                }
            }
        }
    }
}

impl Drop for RedactedBody {
    /// The second audit line for a request, written when the body ends.
    ///
    /// It belongs here rather than at end-of-stream so that a body the tool
    /// abandoned half-way still reports what it had replaced. The first line
    /// went out when the headers arrived and is not held back for this.
    fn drop(&mut self) {
        let redactions = self.stream.redactions();
        if redactions == 0 {
            return;
        }
        self.audit.ctx.audit(
            &self.audit.method,
            &self.audit.host,
            &self.audit.path,
            &format!("response body: {redactions} secret occurrence(s) redacted"),
        );
    }
}

// ─── Header handling ──────────────────────────────────────────────────────────

/// Constrain the upstream request so that its response is something the
/// redactor can read.
///
/// `Accept-Encoding: identity` replaces whatever the tool asked for: a gzip,
/// br or zstd body is opaque to a byte-pattern scanner, and an upstream that
/// compresses anyway is refused rather than forwarded. `Range` and `If-Range`
/// go because a range may begin in the middle of a secret — the pattern would
/// be split across two responses the proxy never sees together, and the tool
/// would reassemble the plaintext in a file. Stripping them makes the
/// upstream send the whole representation, which is the form redaction is
/// sound on.
fn demand_a_plain_full_response(headers: &mut HeaderMap) {
    headers.insert(
        header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    headers.remove(header::RANGE);
    headers.remove(header::IF_RANGE);
}

/// Remove hop-by-hop headers and every client-supplied copy of the header this
/// route injects.
///
/// Dropping the client's copies is what makes the injected credential
/// authoritative: the agent cannot pre-seed an `Authorization` header and have
/// the upstream see two.
pub(crate) fn strip_forbidden_headers(headers: &mut HeaderMap, inject: Option<&Inject>) {
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }
    // `Proxy-Connection` is not a registered header name constant.
    headers.remove("proxy-connection");
    if let Some(inject) = inject
        && let Ok(name) = HeaderName::from_bytes(inject.header.as_bytes())
    {
        headers.remove(&name);
    }
}

/// Look the secret up and attach the credential header.
///
/// The lookup happens per request, so a background refresh takes effect on the
/// next request and a `Stale` slot fails this one — the same way a stale slot
/// fails an ordinary exec.
fn inject_credential(
    secrets: &SecretStore,
    inject: &Inject,
    headers: &mut HeaderMap,
) -> Result<(), &'static str> {
    let Some(slot_lock) = secrets.get(&inject.secret) else {
        return Err("denied: injected secret is not declared");
    };
    let slot = slot_lock.read().unwrap_or_else(|e| e.into_inner());
    if matches!(slot.health, Health::Stale { .. }) {
        return Err("denied: injected secret is stale (last refresh failed)");
    }

    let name = HeaderName::from_bytes(inject.header.as_bytes())
        .map_err(|_| "denied: injected header name is invalid")?;
    let value = build_header_value(inject, slot.value.expose_secret())
        .map_err(|_| "denied: injected header value is invalid")?;
    headers.insert(name, value);
    Ok(())
}

/// Assemble `prefix + secret + suffix` into a buffer that is wiped afterwards.
///
/// Never `format!`: a formatting temporary would leave a copy of the secret in
/// a buffer nobody can reach to zero. The resulting `HeaderValue` still holds
/// the bytes until hyper drops it — that is unavoidable while the request is
/// in flight — but it is marked sensitive so nothing logs it.
fn build_header_value(
    inject: &Inject,
    secret: &str,
) -> Result<HeaderValue, hyper::header::InvalidHeaderValue> {
    let mut buf = Vec::with_capacity(inject.prefix.len() + secret.len() + inject.suffix.len());
    buf.extend_from_slice(inject.prefix.as_bytes());
    buf.extend_from_slice(secret.as_bytes());
    buf.extend_from_slice(inject.suffix.as_bytes());

    let built = HeaderValue::from_bytes(&buf);
    buf.zeroize();

    let mut value = built?;
    value.set_sensitive(true);
    Ok(value)
}

/// The single `Host` header value, or `None` if it is missing or duplicated.
fn host_header(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::HOST).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    first.to_str().ok()
}

/// Whether a `Host` header names the same authority the tunnel was opened to.
/// The explicit `:443` form is accepted because it is the same authority
/// written out in full.
fn host_matches_authority(host: &str, authority: &str) -> bool {
    let host = host
        .strip_suffix(":443")
        .unwrap_or(host)
        .trim_end_matches('.');
    host.eq_ignore_ascii_case(authority.trim_end_matches('.'))
}

/// Split a CONNECT authority into host and port. A CONNECT target always
/// carries an explicit port, and only DNS names are routable, so an IP literal
/// simply fails to match any route later.
///
/// The host is reduced to one canonical spelling — lowercase, no root dot —
/// because it goes on to name the leaf certificate and key the leaf cache, and
/// `Example.com.` must not be a different certificate from `example.com`.
fn split_authority(authority: &hyper::http::uri::Authority) -> Option<(String, u16)> {
    let port = authority.port_u16()?;
    let host = authority.host().to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host).to_string();
    Some((host, port))
}

// ─── Proxy authentication ─────────────────────────────────────────────────────

/// 32 bytes of CSPRNG output, hex-encoded so it can sit in a URL userinfo
/// field without escaping.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
    let token = bytes.iter().map(|b| format!("{b:02x}")).collect();
    bytes.zeroize();
    token
}

fn basic_auth_header(token: &str) -> String {
    use base64::Engine;
    let credentials = base64::engine::general_purpose::STANDARD
        .encode(format!("{PROXY_USER}:{token}").as_bytes());
    format!("Basic {credentials}")
}

fn authorized(headers: &HeaderMap, expected: &str) -> bool {
    let Some(offered) = headers.get(header::PROXY_AUTHORIZATION) else {
        return false;
    };
    offered.as_bytes().ct_eq(expected.as_bytes()).into()
}

// ─── Canned responses ─────────────────────────────────────────────────────────

fn empty_body() -> ProxyBody {
    Full::new(Bytes::new())
        .map_err(|e: Infallible| match e {})
        .boxed()
}

fn text_body(text: &str) -> ProxyBody {
    Full::new(Bytes::from(format!("{text}\n")))
        .map_err(|e: Infallible| match e {})
        .boxed()
}

fn refuse(status: StatusCode, reason: &str) -> Response<ProxyBody> {
    let mut response = Response::new(text_body(reason));
    *response.status_mut() = status;
    response
}

fn auth_required() -> Response<ProxyBody> {
    let mut response = refuse(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "airlock proxy: bad or missing proxy credentials",
    );
    response.headers_mut().insert(
        header::PROXY_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"airlock\""),
    );
    response
}

// ─── Upstream ─────────────────────────────────────────────────────────────────

/// Where an upstream connection goes and how its certificate is checked.
struct Upstream {
    tls: Arc<rustls::ClientConfig>,
    target: Target,
}

enum Target {
    /// Resolve the host and refuse anything that is not globally routable.
    PublicDns,
    /// Tests only: dial this fixed address instead of resolving. Production
    /// never constructs it, so the SSRF filter has no production bypass.
    #[cfg(test)]
    Fixed(SocketAddr),
}

impl Upstream {
    fn public() -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Upstream {
            tls: Arc::new(client_config(roots)),
            target: Target::PublicDns,
        }
    }

    /// A connector that dials one fixed address and trusts one root, so a test
    /// can point a route at a local TLS server.
    #[cfg(test)]
    fn fixed(addr: SocketAddr, roots: rustls::RootCertStore) -> Self {
        Upstream {
            tls: Arc::new(client_config(roots)),
            target: Target::Fixed(addr),
        }
    }

    async fn send(
        &self,
        host: &str,
        req: Request<Incoming>,
    ) -> Result<Response<Incoming>, UpstreamError> {
        let stream = self.connect(host).await?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(UpstreamError::Http)?;
        // The connection driver must be polled for the exchange to progress.
        // It ends when the response body is done or the task is dropped.
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender.send_request(req).await.map_err(UpstreamError::Http)
    }

    /// Open a verified TLS connection to `host`.
    ///
    /// One connection per request rather than a pool: the request path is
    /// security-critical and a shared upstream connection would have to carry
    /// the proof that two requests that shared it were vetted identically.
    async fn connect(
        &self,
        host: &str,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, UpstreamError> {
        let addr = match self.target {
            #[cfg(test)]
            Target::Fixed(addr) => addr,
            // Resolved once here and dialled as a concrete `SocketAddr`, so
            // there is no second lookup a rebinding answer could slip into
            // between the check and the connect.
            Target::PublicDns => resolve_public(host, UPSTREAM_PORT).await?,
        };

        let tcp = tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(UpstreamError::Io)?;
        let _ = tcp.set_nodelay(true);

        let name = ServerName::try_from(host.to_string())
            .map_err(|_| UpstreamError::Refused("host is not a valid DNS name"))?;
        let handshake = TlsConnector::from(Arc::clone(&self.tls)).connect(name, tcp);
        tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, handshake)
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(UpstreamError::Io)
    }
}

/// TLS 1.2 is the floor; the upstream certificate is verified against public
/// roots for the CONNECT authority, not for anything the client claimed.
fn client_config(roots: rustls::RootCertStore) -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("TLS 1.2 and 1.3 are compiled in")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[derive(Debug, thiserror::Error)]
enum UpstreamError {
    #[error("{0}")]
    Refused(&'static str),
    #[error("timed out")]
    Timeout,
    #[error("{0}")]
    Io(std::io::Error),
    #[error("{0}")]
    Http(hyper::Error),
}

/// Resolve `host` and return the address to dial, refusing the whole
/// resolution if any answer points somewhere that is not globally routable.
///
/// Refusing outright rather than picking a public answer out of a mixed set
/// makes the failure visible: a public API never has a private address, so a
/// mixed answer means either a misconfiguration or an attempt to walk the
/// daemon into the host's own network.
async fn resolve_public(host: &str, port: u16) -> Result<SocketAddr, UpstreamError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(UpstreamError::Io)?
        .collect();

    if addrs.iter().any(|addr| !is_globally_routable(addr.ip())) {
        return Err(UpstreamError::Refused(
            "host resolves to a private, loopback, link-local or otherwise non-routable address",
        ));
    }
    addrs
        .into_iter()
        .next()
        .ok_or(UpstreamError::Refused("host did not resolve"))
}

/// Whether an address is one the daemon will dial on a tool's behalf.
///
/// Everything reserved, private, or otherwise local is out: the daemon runs
/// with the host's network position, and a route is for a public API, so any
/// answer pointing inward is an attempt to borrow that position.
pub(crate) fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_globally_routable_v4(v4),
        IpAddr::V6(v6) => is_globally_routable_v6(v6),
    }
}

fn is_globally_routable_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()          // 169.254.0.0/16, incl. 169.254.169.254
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0                      // 0.0.0.0/8 "this network"
        || (a == 100 && (64..128).contains(&b))  // 100.64.0.0/10 CGNAT
        || (a == 192 && b == 0 && c == 0)        // 192.0.0.0/24 IETF protocol
        || (a == 198 && (b == 18 || b == 19))    // 198.18.0.0/15 benchmarking
        || a >= 240) // 240.0.0.0/4 reserved
}

fn is_globally_routable_v6(ip: Ipv6Addr) -> bool {
    // An IPv4-mapped answer is judged as the IPv4 address it carries, so
    // `::ffff:10.0.0.1` is refused for the same reason `10.0.0.1` is.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_globally_routable_v4(v4);
    }

    let segments = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || segments[..6] == [0; 6]            // ::/96 deprecated IPv4-compatible
        || (segments[0] & 0xfe00) == 0xfc00   // fc00::/7 unique local
        || (segments[0] & 0xffc0) == 0xfe80   // fe80::/10 link local
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)  // 2001:db8::/32 docs
        || (segments[0] == 0x0064 && segments[1] == 0xff9b)  // 64:ff9b::/96 NAT64
        || (segments[0] == 0x0100 && segments[1..4] == [0, 0, 0])) // 100::/64 discard
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
