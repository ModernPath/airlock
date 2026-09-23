# Architecture

Airlock is a single Rust binary that operates in two modes: **daemon** (long-running, holds secrets, spawns tools) and **client** (short-lived, connects to the daemon, proxies I/O). Both modes are compiled into the same binary and selected by the CLI subcommand.

## Module map

```
src/
├── main.rs       CLI entry point and command dispatch
├── config.rs     Config discovery, TOML parsing, path resolution
├── secrets.rs    Secret<T> wrapper, pluggable secret sources, env clearing
├── refresh.rs    Background secret refresh task, exponential-backoff retry
├── policy.rs     ToolPolicy / AgentPolicy construction, CWD validation
├── proxy.rs      Proxy-tool egress policy: route table, host / path matching
│   ├── ca.rs     Per-daemon MITM CA: name constraints, leaf minting and cache
│   └── server.rs Per-exec interception proxy: CONNECT, vetting, injection
├── redact.rs     Aho-Corasick automaton, streaming redaction
├── sandbox.rs    SandboxBackend trait, macOS Seatbelt, Linux Landlock
├── exec.rs       Binary resolution, env construction, child spawn
├── run.rs        Agent process orchestrator for `airlock run`
├── daemon.rs     Daemonization, accept loop, exec orchestration
├── client.rs     Socket connection, stdio proxying, NDJSON streaming
├── protocol.rs   ClientMessage / DaemonMessage wire types
└── lib.rs        Module declarations
```

## Startup sequence

The `main()` function is intentionally **synchronous** — no `#[tokio::main]`, no async runtime. This is critical because daemonization requires forking, and forking after tokio spawns background threads leaves those threads in an undefined state in the child.

```
main()
 │
 ├─ parse CLI args (clap)
 │
 ├─ "daemon start" or "daemon run"
 │   │
 │   └─ synchronous_startup()         ← all pre-fork work
 │       ├─ harden_process()          ← RLIMIT_CORE=0, PR_SET_DUMPABLE=0 (Linux)
 │       ├─ config::load_config()     ← O_NOFOLLOW + fstat; refuses $HOME root
 │       ├─ cleanup stale PID/socket
 │       ├─ secrets::collect_secrets()
 │       ├─ secrets::clear_secret_env_vars()
 │       ├─ Redactor::new()           ← build Aho-Corasick automaton
 │       ├─ umask(0o077) + UnixListener::bind() + restore umask
 │       ├─ verify_socket_permissions()  ← refuse start if not 0o700
 │       │
 │       ├─ [daemon start] daemonize()
 │       │   ├─ pipe for readiness (carries success, or the startup error)
 │       │   ├─ fork #1: parent waits on pipe
 │       │   ├─ setsid()
 │       │   ├─ fork #2: intermediate exits
 │       │   ├─ redirect stdio → /dev/null
 │       │   ├─ chdir("/")
 │       │   └─ signal readiness → parent exits 0
 │       │      (a failure before that point is written into the pipe
 │       │       instead; the parent prints it and exits 1 — the grandchild
 │       │       has no stderr, so the pipe is its only voice)
 │       │
 │       └─ enter_async_runtime()
 │           ├─ convert std::UnixListener → tokio::UnixListener
 │           ├─ write PID file
 │           ├─ install SIGTERM handler
 │           └─ accept loop
 │
 ├─ "daemon stop"
 │   └─ read PID file, send SIGTERM, poll for exit (10s)
 │
 ├─ "exec -- <tool> [args...]"
 │   └─ client::run_exec()
 │       ├─ connect to Unix socket
 │       ├─ send ClientMessage::Exec
 │       ├─ proxy stdin → socket, socket → stdout/stderr
 │       └─ exit with child's exit code
 │
 ├─ "run [--no-daemon] -- <command> [args...]"
 │   └─ run::run_agent()
 │       ├─ load config (discover or explicit --config path)
 │       ├─ [default] daemon::synchronous_startup()  ← embedded daemon
 │       │   └─ same startup sequence as "daemon start" but in-process
 │       ├─ build_agent_policy()    ← AgentPolicy for the harness sandbox
 │       ├─ sandbox::build_profile() ← Seatbelt (macOS) / Landlock (Linux)
 │       ├─ construct clean env (passthrough_env + [agent.env] entries)
 │       ├─ spawn agent with sandbox applied in pre_exec
 │       ├─ forward SIGTERM / SIGHUP to agent; enforce optional timeout
 │       └─ [default] stop embedded daemon on agent exit
 │
 ├─ "status"
 │   └─ probe socket liveness (ground truth); PID file only enriches output
 │
 ├─ "list"
 │   └─ parse config, print each tool's env (static + secret-backed)
 │
 ├─ "logs"
 │   └─ connect to socket, send ClientMessage::Logs, print entries
 │
 └─ "init"
     └─ write default airlock.toml template
```

## Daemon internals

### State

The daemon's shared state is wrapped in `Arc` for concurrent access across connection handlers:

| Component | Type | Purpose |
|-----------|------|---------|
| Config | `Arc<Config>` | Parsed `airlock.toml` (immutable after startup) |
| Secrets | `SecretStore` = `Arc<HashMap<String, RwLock<SecretSlot>>>` | Per-label slot holding `Arc<Secret<String>>` plus refresh health; the map is fixed at startup, slot contents swap on refresh |
| Redactor | `Arc<RwLock<Arc<Redactor>>>` | Aho-Corasick automaton for output redaction; refresh tasks swap the inner `Arc`. A connection snapshots it for the child's stdout/stderr; a proxy session carries the handle itself and snapshots per response |
| Ring buffer | `Arc<Mutex<RingBuffer>>` | Last 1000 log entries (`VecDeque<LogEntry>`) |
| Child registry | `Arc<Mutex<HashSet<u32>>>` | PIDs of currently running children |

### Connection handling

Each accepted connection is spawned as a `tokio::spawn(handle_connection(...))` task. The handler reads one `ClientMessage` from the socket:

- **`Exec`** → full tool execution flow (see below)
- **`Logs`** → returns ring buffer contents as `DaemonMessage::LogsResponse`

### Exec flow (per-connection)

```
Client sends: {"type":"exec","tool":"gh","args":["repo","list"],"cwd":"/home/user/project"}

Daemon handler:
 1. Validate tool exists in config
 2. Validate CWD is within sandbox root
 3. Resolve binary: walk PATH for "gh" → "/usr/bin/gh"
 4. Build child env: walk tool.env in declared (alphabetical) order, resolving
    Static(s) as-is and SecretRef(label) via the in-memory secret store; then
    layer the essential pass-through set (PATH, HOME, TERM, USER, TZ, and the
    standard LC_* locale family — see exec::ESSENTIAL_VARS)
 5. Proxy tools only: bind a proxy listener on 127.0.0.1:0, then overlay the
    daemon-owned HTTPS_PROXY / NO_PROXY / *_CA_* variables on top of step 4.
    The ProxySession is held for the rest of the handler; dropping it aborts
    the serve task, so every exit path takes the proxy down with the child.
 6. Resolve timeout (per-tool override or global default)
 7. Build ToolPolicy (merge sandbox root + global + tool paths), with
    network = ProxyOnly(port) for a proxy tool and Full otherwise
 8. Build SandboxProfile (SBPL on macOS, Landlock on Linux)
 9. spawn(ExecRequest { binary, args, work_dir, env, sandbox_profile, timeout })
10. Register child PID in ChildRegistry

11. Concurrent select! loop:
    ├── child exit        → collect exit code, break
    ├── stdout chunk      → redact → DaemonMessage::Stdout → socket
    ├── stderr chunk      → redact → DaemonMessage::Stderr → socket
    ├── client message    → stdin data → child stdin pipe
    │                     → stdin_eof  → close child stdin
    ├── stdin timeout (2s)→ auto-close child stdin
    └── exec timeout      → SIGTERM → 5s → SIGKILL

12. Drain remaining stdout/stderr
13. Send DaemonMessage::Exit { code } or DaemonMessage::Error
14. Unregister child PID
```

### Proxy tools

A proxy tool holds no secret. Its only network path is a proxy the daemon
binds for that one execution, which attaches the credential after the request
has left the tool. Rationale and threat model:
[docs/proxy-tools-design.md](docs/proxy-tools-design.md) and
[SECURITY.md](SECURITY.md#proxy-tools).

The CA is generated once per daemon in `async_main` — inside the runtime, after
the fork, so the synchronous-startup invariant is untouched — and shared as an
`Arc` across connections. Its key stays in memory; only the certificate is
written, to `{sandbox_root}/airlock-ca.pem`.

```
child (curl)                     daemon                         upstream
    │                              │                                │
    │ CONNECT api.example.com:443  │                                │
    │  Proxy-Authorization: Basic  │                                │
    ├─────────────────────────────►│ constant-time token compare    │
    │                              │ port == 443?                   │
    │                              │ find_route(host)?              │
    │◄─────────────────────────────┤ 200, or 407 / 403              │
    │                              │                                │
    │ ── TLS handshake ───────────►│ leaf minted for the CONNECT    │
    │    (client SNI ignored)      │ authority, ALPN http/1.1       │
    │                              │                                │
    │ GET /v1/things?page=2        │                                │
    │  Host: api.example.com       │                                │
    ├─────────────────────────────►│ Host == authority?             │
    │                              │ no TE+CL, no dup CL?           │
    │                              │ route.permits(method, path)?   │
    │                              │ strip client's copy of the     │
    │                              │   inject header + hop-by-hop   │
    │                              │ secret store lookup (Stale→502)│
    │                              │ attach prefix+secret+suffix    │
    │                              │ force Accept-Encoding:identity,│
    │                              │   strip Range / If-Range       │
    │                              │ resolve host, refuse non-      │
    │                              │   routable addrs, dial that    │
    │                              │   exact SocketAddr             │
    │                              ├───── TLS ≥1.2, public roots ──►│
    │                              │◄──────── response head ────────┤
    │                              │ content-encoded / odd framing /│
    │                              │   206?  → 502, body unread     │
    │                              │ redact every header value      │
    │                              │ drop Content-Length unless the │
    │                              │   response is bodiless         │
    │◄──── redacted, chunked ──────┤◄──── body frames streamed ─────┤
    │                              │ audit: method, host, path,     │
    │                              │   decision, status, redaction  │
    │                              │   counts (no query, no header  │
    │                              │   values, no matched bytes)    │
```

The response never reaches the tool unexamined. Header values and body both go
through the redactor, so what `curl -o` writes into the sandbox was already
redacted — see [SECURITY.md](SECURITY.md#response-redaction) for what that
covers and what fails closed.

Meanwhile the sandbox holds the other end: the profile permits a TCP connect to
that port and nothing else — no DNS, no other destination — so a tool that
ignores `HTTPS_PROXY` gets nowhere.

### Redaction pipeline

The redaction pipeline bridges async I/O (tokio) with the synchronous Aho-Corasick streaming API:

```
tokio async reader task
    │
    │ reads child stdout/stderr in chunks
    ▼
std::sync::mpsc::Sender
    │
    ▼
spawn_blocking(redact_stream)
    │ ChannelReader (impl Read over mpsc::Receiver)
    │   → Aho-Corasick try_stream_replace_all
    │   → ChannelWriter (impl Write over tokio mpsc::Sender)
    ▼
tokio::sync::mpsc::Receiver
    │
    ▼
select! loop → NDJSON → Unix socket → client
```

This design keeps the automaton's streaming state machine on a dedicated blocking thread (via `spawn_blocking`) while the daemon's main loop remains fully async.

The proxy's response path does not use this bridge. It already holds the bytes
as owned frames handed to it by hyper, so it drives a `StreamRedactor` — an
incremental redactor that keeps between chunks only the bytes a pattern could
still be starting in, and whose output for any chunking is what `redact_bytes`
makes of the whole input — directly from `poll_frame`. No thread and no channel
per response: hyper's polling is the backpressure, and dropping the response
stops the upstream read.

Both paths take their redactor from the same `Arc<RwLock<Arc<Redactor>>>`. A
connection snapshots it once for the child's stdout and stderr, which are
framed against the secrets the child was spawned with. A proxy response
snapshots it per response, because the proxy injects whatever the store holds
at that moment and a token refreshed mid-exec must be redacted on the way
back.

## Wire protocol

Communication uses **NDJSON** (newline-delimited JSON) over the Unix domain socket. Each message is a single JSON line with a `"type"` discriminator field.

### Client → Daemon

```json
{"type":"exec","tool":"gh","args":["repo","list"],"cwd":"/home/user/project"}
{"type":"stdin","data":"input line\n"}
{"type":"stdin_eof"}
{"type":"logs"}
```

### Daemon → Client

```json
{"type":"stdout","data":"output line\n"}
{"type":"stderr","data":"error line\n"}
{"type":"exit","code":0}
{"type":"error","message":"unknown tool: bad-tool"}
{"type":"logs_response","entries":[{"timestamp":"...","message":"..."}]}
```

The `ClientMessage` and `DaemonMessage` enums are separate Rust types, ensuring at compile time that each side of the socket only sends one family and receives the other.

## Config discovery

`airlock.toml` is found by walking upward from the current working directory toward `$HOME`:

1. Check CWD for `airlock.toml`
2. Check parent directory
3. Continue until reaching `$HOME` (inclusive)
4. Stop at the first file found

**Ownership check**: The file must be owned by the current effective UID. This prevents a shared `/tmp` directory from being used to inject a crafted config.

**TOCTOU-safe read**: Discovery and load both go through an `O_NOFOLLOW` open followed by `fstat` on the fd. Symlinks, non-regular files, and files whose UID changes between the walk and the read are rejected. A 1 MiB size cap bounds allocation.

**Home-directory refusal**: If the discovered config sits directly at `$HOME`, `load_config` returns `HomeRootNotAllowed` unless the config contains `allow_home_root = true`. Without the opt-in, a stray `airlock.toml` in the home directory would otherwise make the entire home directory the sandbox root.

### Path resolution

Paths in the config are resolved relative to the **sandbox root** (the directory containing `airlock.toml`):

| Input | Resolution |
|-------|-----------|
| `~/foo` | `$HOME/foo` |
| `relative/path` | `<sandbox_root>/relative/path` |
| `/absolute/path` | `/absolute/path` (unchanged) |

### Derived paths

From the sandbox root, two paths are derived automatically:

- **Socket**: `<sandbox_root>/airlock.sock`
- **PID file**: `<sandbox_root>/airlock.pid`

## Secret sources

`[secrets.<label>]` is a top-level table where each entry declares one secret
by a logical label and a pluggable source. At daemon startup, `collect_secrets`
walks the table and resolves every entry into a `Secret<String>` keyed by label.

| `source`    | Resolution                                                                              |
|-------------|-----------------------------------------------------------------------------------------|
| `"env"`     | Read the daemon env var named by `from`.                                                |
| `"command"` | Spawn `command` (argv, no shell), wait up to `timeout`, trim trailing newlines.         |

Command sources run **before** daemonization completes and are **not**
sandboxed — `airlock.toml` is already trusted. Failures are batched: the
operator sees every missing env var or failed command in one error.

When a `command` secret declares `refresh = N`, a dedicated tokio task is
spawned in the async runtime to re-run the command every `N` seconds and swap
the in-memory value. The redactor is rebuilt on each successful refresh and
keeps both the new and previous-generation values for one cycle, so output
captured just before the swap is still redacted. The rebuilt redactor is
swapped in *before* the new value is published to the slot: the proxy reads
the slot per request, so any other order would let an echoing upstream hand
the fresh credential back through a redactor that has never seen it. On
failure, the slot's
health flips to `Stale`, the previous value is retained but the exec path
refuses to inject it, and the task retries with exponential backoff capped
at `refresh_max_backoff` until the upstream recovers.

`tools.X.env` maps env var names to values. A bare string is a static
passthrough (not redacted, since it's not a secret); an inline table
`{ secret = "label" }` is resolved against the label map built above.

### Credential derivation at the boundary

A `command` source is more than a fetch mechanism. Because the command runs
on the trusted side with the daemon's ambient environment and filesystem, it
can use credentials the sandbox will never see to *derive* the credentials
the sandbox gets. The canonical case is cloud impersonation:

```
   daemon process (trusted, unsandboxed)
   ┌──────────────────────────────────────────────────────────────────────┐
   │  ambient: ~/.config/gcloud — the operator's own login, broad scope   │
   │                                                                      │
   │  refresh task ──▶ spawn  gcloud auth print-access-token              │
   │  (every N s)              --impersonate-service-account=<narrow SA>  │
   │                             │ stdout, trimmed                        │
   │                             ▼                                        │
   │                    SecretStore[label] = Secret<String>               │
   │                    (the derived token only — the ambient credential  │
   │                     is never copied into the store)                  │
   └──────────────────────────┬───────────────────────────────────────────┘
                              │ exec::build_env, at spawn
                              ▼
   sandboxed tool: receives only the derived token; ~/.config/gcloud is
   outside its filesystem policy unless a tool explicitly grants the path
```

Two consequences shape the design:

- **The store never holds the broad credential.** `collect_secrets` stores
  the command's stdout and nothing else. The operator's session stays
  wherever the CLI keeps it — readable by the daemon's spawned command
  through ordinary file permissions, invisible to tools unless a tool policy
  grants that path.
- **Expiry is a feature, not a failure mode.** Derived tokens are short-lived
  by construction, which is why `refresh` exists. A refresh that fails flips
  the slot to `Stale` and the exec path refuses to inject it — running a tool
  with an expired or half-rotated credential is treated as worse than not
  running it.

Refresh slot health, per refreshable secret:

```
startup ──▶ Healthy ──(refresh fails)──▶ Stale ──(refresh succeeds)──▶ Healthy
              │                            │
              │ exec: inject current value │ exec: error "secret X is stale"
              │                            │ retry after 5 s, 10 s, 20 s …
              │                            │ capped at refresh_max_backoff
```

## Platform support

| Feature | macOS | Linux |
|---------|-------|-------|
| Daemon (fork, socket, signals) | Yes | Yes |
| Filesystem sandbox | Apple Seatbelt (SBPL) | Landlock LSM (kernel 5.13+) |
| Sandbox failure mode | Hard error | Hard error (no silent degradation) |
| Process groups | `setpgid` | `setpgid` |

On unsupported platforms, the sandbox is a no-op (only `setpgid` in `pre_exec`), but the daemon still functions for development/testing.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime (process, I/O, signals, timers, networking) |
| `tokio-util` | `LinesCodec` for bounded NDJSON line framing on the socket |
| `tokio-stream` | `StreamExt` adapters over `FramedRead` |
| `clap` | CLI argument parsing (derive macros) |
| `serde` / `serde_json` | NDJSON serialization |
| `toml` | Config parsing |
| `aho-corasick` | Multi-pattern string matching for redaction |
| `base64` | Base64 encoding of secret variants |
| `percent-encoding` | URL-encoding of secret variants |
| `libc` | POSIX syscalls (fork, setsid, kill, setpgid, dup2, etc.) and signal constants |
| `rustix` | Typed safe wrappers for `umask`, `setrlimit`, `prctl`, `test_kill_process` |
| `zeroize` | Backs `Secret<T>` drop semantics (zero on drop) |
| `anyhow` / `thiserror` | Error handling |
| `landlock` | Linux Landlock LSM, filesystem and TCP rules (Linux-only) |
| `rustls` / `tokio-rustls` | TLS in both directions of the proxy (ring provider, installed explicitly) |
| `rcgen` | Proxy CA and leaf certificate generation |
| `hyper` / `hyper-util` / `http-body-util` | HTTP/1.1 server and client for the proxy |
| `bytes` | Body buffers on the proxy path |
| `webpki-roots` | Public trust anchors for upstream verification |
| `time` | Certificate validity windows |
| `getrandom` | CSPRNG for the per-exec proxy token |
| `subtle` | Constant-time comparison of the proxy token |

## Build

```bash
cargo build --release
```

Requires Rust 2024 edition. The build script (`build.rs`) captures the git commit hash and dirty flag, embedded in the `--version` output.

## Tests

Unit tests are co-located in each module (`#[cfg(test)]` blocks). Integration tests live in `tests/`:

| Test file | Coverage |
|-----------|----------|
| `exec_integration.rs` | Process spawn, sandbox confinement, stdio |
| `exec_e2e_integration.rs` | Full daemon→client exec flow |
| `daemon_integration.rs` | Daemon startup, PID file, socket |
| `redact_e2e_integration.rs` | End-to-end redaction (all encodings) |
| `cli_integration.rs` | CLI binary: start, stop, status, list, logs, init, run |
| `logs_integration.rs` | Ring buffer log retrieval |
| `stdin_integration.rs` | Stdin forwarding through daemon |
| `timeout_integration.rs` | Per-tool timeout enforcement |
| `disconnect_integration.rs` | Client disconnect → child cleanup |
| `concurrent_integration.rs` | Concurrent exec requests |
| `shutdown_integration.rs` | SIGTERM graceful shutdown with children |
| `run_integration.rs` | `airlock run`: embedded daemon, agent sandbox, env isolation |

Environment-sensitive tests use an `EnvGuard` RAII helper with a global mutex to serialize access to `std::env`.

```bash
cargo test
```
