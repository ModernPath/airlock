# Architecture

Airlock is a single Rust binary that operates in two modes: **daemon** (long-running, one per user, holds every session's secrets, spawns tools) and **client** (short-lived: a **launcher** that registers a session, or `exec`/`tools list`/`agent check` that use one). Both modes are compiled into the same binary and selected by the CLI subcommand.

See [docs/airlock-v2-design.md](docs/airlock-v2-design.md) for why this shape was chosen over a daemon per project; this document describes what shipped.

## Module map

```
src/
├── main.rs         CLI entry point and command dispatch
├── runtime_dir.rs   Per-user runtime base: location, validation, derived paths
├── anchors.rs       Trust store / global config / tool-state base: XDG resolution, validation against write grants
├── process_tree.rs  Peer PID/uid of a Unix connection, parent-chain walk, token-binding check
├── layers.rs        Config layer discovery (global/repo/local), merge rules, provenance
├── config.rs        Raw TOML types, per-file parsing and validation, wire (daemon-side) config resolution
├── kits.rs          Agent kits: built-in/user-defined definitions, validation, pure expansion (launcher-only)
├── trust.rs         Trust store, approval state, escaped diff rendering, prompts
├── protocol.rs      Wire types: Hello, Request/Auth, two request families, ErrorKind, exit-code mapping
├── session.rs        In-daemon session state: policy, secrets, redactor, binding, lease/TTL
├── secrets.rs       Secret<T> wrapper, pluggable secret sources, filtered-PATH-aware command resolution
├── refresh.rs       Background secret refresh task, exponential-backoff retry
├── policy.rs        ToolPolicy / AgentPolicy construction, CWD validation, write-grant collection
├── proxy.rs          Proxy-tool egress policy: route table, host / path matching
│   ├── ca.rs         Per-daemon MITM CA: name constraints, leaf minting and cache
│   └── server.rs     Daemon-side interception proxy, one per exec request: CONNECT, vetting, injection
├── redact.rs        Aho-Corasick automaton, streaming redaction; the daemon-wide last-pass redactor
├── sandbox.rs       SandboxBackend trait, macOS Seatbelt, Linux Landlock
├── exec.rs          Filtered PATH, binary resolution and location check, env construction, child spawn
├── run.rs           `airlock run`: launcher + agent sandbox orchestration
├── launcher.rs       Shared launcher steps: discover, approve, resolve secrets, `Register`/`Reload`
├── daemon.rs        Daemonization, accept loop, per-connection dispatch across sessions
├── agent.rs          `airlock agent check` / `agent hook`
├── inspect.rs        `airlock config` / `airlock status` rendering
├── service.rs        `airlock daemon install`/`uninstall` (launchd / systemd user unit)
├── client.rs        Socket connection, stdio proxying, NDJSON streaming
└── lib.rs           Module declarations
```

## Startup sequence

The `main()` function is intentionally **synchronous** — no `#[tokio::main]`, no async runtime. This is critical because daemonization requires forking, and forking after tokio spawns background threads leaves those threads in an undefined state in the child. See [src/daemon.rs:14-19](src/daemon.rs#L14-L19).

```
main()
 │
 ├─ parse CLI args (clap)
 │
 ├─ "daemon start [--foreground|--automatic]"
 │   │
 │   └─ synchronous_startup()         ← all pre-fork work
 │       ├─ harden_process()          ← RLIMIT_CORE=0, PR_SET_DUMPABLE=0 (Linux)
 │       ├─ runtime_dir::locate() + create_and_validate()  ← per-user base, outside every project
 │       ├─ acquire_startup_lock(airlock.lock)  ← exclusive flock, held for the daemon's life;
 │       │                                        a losing concurrent `daemon start` gets
 │       │                                        StartInProgress and exits 75, not an error
 │       ├─ cleanup stale PID/socket (in the runtime dir, not the project; safe to treat a
 │       │  socket with no PID file as stale now, since the lock rules out a concurrent starter)
 │       ├─ write admin.token (32 random bytes, mode 0600)
 │       ├─ umask(0o077) + UnixListener::bind() + restore umask
 │       ├─ verify_socket_permissions()  ← refuse start if not 0o700
 │       │
 │       ├─ [daemon start] daemonize()   ← same double fork + readiness pipe as v1
 │       │
 │       └─ enter_async_runtime()
 │           ├─ convert std::UnixListener → tokio::UnixListener
 │           ├─ write PID file
 │           ├─ install SIGTERM handler
 │           └─ accept loop, no sessions yet
 │
 ├─ "run [--profile NAME] [--kit NAME]... [-- CMD...]"
 │   └─ run::run_agent()
 │       ├─ launcher::register_session()   ← discover, approve, resolve secrets (see below);
 │       │  also validates and expands this run's active kits (kits::expand_all) and folds
 │       │  their write dirs/files into write_grants before the anchor/PATH checks run
 │       ├─ build_agent_policy() + sandbox::build_profile(), kit read/write paths added on top
 │       ├─ build_agent_env(), kit env applied on top (overriding passthrough/[agent.env])
 │       ├─ spawn agent with AIRLOCK_ADDR / AIRLOCK_SESSION set, sandbox applied in pre_exec
 │       ├─ hold the `Register` connection open as the session's lease
 │       ├─ forward SIGTERM / SIGHUP to agent; enforce optional timeout
 │       └─ on agent exit, close the lease connection (daemon revokes the session)
 │
 ├─ "session start" / "session reload" / "trust" / "config" / "status"
 │   └─ launcher-family commands; same discover/approve path as `run`, different endpoint
 │
 ├─ "exec -- <tool> [args...]" / "tools list" / "agent check"
 │   └─ client::run_exec() / ...
 │       ├─ read AIRLOCK_ADDR / AIRLOCK_SESSION only — no discovery, no admin.token
 │       ├─ connect to the socket, send a session-family Request
 │       └─ proxy stdin → socket, socket → stdout/stderr; exit with the tool's status or 125/126/127
 │
 └─ "init" / "daemon stop/restart/logs/install/uninstall"
     └─ as the names suggest; see docs/airlock-v2-ux.md for the full surface
```

## Config layering and registration

A **launcher** (`airlock run`, `session start`, `session reload`, and `trust`/`config`/`status` for inspection) is the only code that reads project config. The daemon never does. The steps, shared by `src/launcher.rs`:

1. **Discover.** Walk up from the working directory to `$HOME` for the first directory holding `airlock.toml` or `airlock.local.toml` ([src/layers.rs](src/layers.rs) `load_layers`), or use exactly the `--config` file, or (`--no-project-config`) skip project discovery and use only the global layer. Each file is read once (`read_config_securely`): the same bytes are hashed for the trust store and parsed for merging.
2. **Approve.** Compare each repo/local file's hash against the trust store ([src/trust.rs](src/trust.rs)). An unapproved file's diff (or full contents, for a first approval) is shown, escaped against ANSI/bidi/zero-width tricks, and the launcher asks `Trust this version and continue? [y/N]` on a terminal, or refuses on a non-terminal. The global layer needs no approval — it is protected by the [anchor checks](#protecting-the-anchors) instead.
3. **Merge.** `src/layers.rs::merge` combines the three layers: lists union, `agent.env` is per-key highest-wins, a project tool replaces a same-named global one (visibly), a local tool replaces a repo one only with `override = true`, and a secret label crosses from repo to local to global only through an explicit local binding (`from = "global"`). Validation (undeclared secret refs, proxy tool shape, …) runs on the merged result, so a user is never asked to approve a file that would fail anyway.
4. **Resolve secrets.** Every `source = "env"` reads the launcher's own environment; every `source = "command"` is spawned by the launcher, not the daemon, on the trusted side. Command argv\[0\] and every tool binary are resolved against a **filtered `PATH`**: the launcher's `PATH` with relative entries and anything inside the project root or a write grant dropped, and the resolved path re-checked after canonicalization. This closes the gap where an approved `airlock.toml` names a command, but a planted binary on a writable `PATH` entry is what actually runs.
5. **Register.** The launcher sends a `Register` request over the admin channel: the project root, the merged config (as `RawConfig`, the same `deny_unknown_fields` TOML types the files parse into — a field the daemon doesn't recognize is rejected, not ignored), the layer hashes, the resolved secret values, an environment snapshot and the filtered `PATH`, a session name, and whether the agent runs in Airlock's own sandbox or an external one. The daemon answers with a session id and a 32-byte token; the launcher drops its `Secret<T>` values once this succeeds.

`session reload` repeats steps 1–4 for one or more running sessions and sends `Reload`; the daemon compiles a new policy and swaps it into the session in one step. The session keeps its id and token. The agent's own sandbox settings (`[agent]`) cannot change on a running process, so a reload that touches them is applied to everything else and reported as "agent settings changed; restart to apply".

### Kits

Kits ([src/kits.rs](src/kits.rs)) add a language toolchain's cache access to `airlock run`'s agent sandbox — a layer orthogonal to the harness profile. They are purely a `run`-time, launcher-side concept: `layers::merge` validates and resolves `[kits.*]`/`agent.kits` but **never puts the `[kits.*]` option tables on the wire** (`agent.kits`, the plain name list, does ride along on `RawAgentConfig`, unused by the daemon, so it and the resolved option tables both feed the agent hash `session reload` checks). `kits::expand_all` is the one pure function that turns an active kit list into concrete paths and env — called from `launcher::prepare` (for `run`) and from `inspect::config_cmd`'s own display, never from `layers::merge`, which reads no environment by design. A kit's write dirs/files are folded into `write_grants` before the anchor and filtered-`PATH` checks in step 4 above, so no separate check was needed for them.

## Sessions

One daemon serves every project a user has. A **session** binds a client to one project root, its approved config, and the secrets resolved for it — see [docs/airlock-v2-design.md#sessions](docs/airlock-v2-design.md#sessions) for the full design.

| Component | Type (indicative) | Purpose |
|---|---|---|
| Sessions | `DashMap<SessionId, Arc<Session>>` or equivalent | Every registered session; the token resolves to exactly one `Arc<Session>` |
| `Session` | struct | id, token, root, `RwLock<Arc<SessionPolicy>>` (compiled tools/secrets/proxy routes, swapped whole by `Reload`), process-tree binding, lease-or-TTL, exec counter |
| Admin credential | `admin.token`, mode 0600 in the runtime dir | Required by `Register`, `Reload`, `session list/revoke/renew`, `tools list --session`, `status`, `daemon logs/stop/restart`. No sandbox can read it. |
| Global redactor | `Arc<RwLock<Arc<Redactor>>>` built from every live session's secrets | A last-pass safety net: after a session's own redactor, output also passes this one, so a bug that put another session's secret in the wrong place still gets masked |

**Request handling.** A connection first exchanges a version `Hello`, then sends one `Request { auth, body }`. `auth` is `{"kind": "session", "token": ...}` or `{"kind": "admin", "token": ...}`; the listener resolves it to a `Principal` (peer uid check, and for a session token the [token-binding](#token-binding) check) before any handler runs, and refuses a request whose family doesn't match its auth kind. `body` is one of two enums:

- **Session family** — `Exec { tool, args, cwd }`, `Stdin`/`StdinEof`, `List`, `Check`. Resolved through the session's own `Arc<Session>`; nothing here ever consults a global map keyed by secret label.
- **Admin family** — `Register`, `Reload`, `ListSessions`, `Revoke`, `Renew`, `Tools { session }`, `Logs`, `Stop`. Gated on `admin.token`.

**Error kinds.** `Error { kind, message }`, where `kind` is an enum — `NoSession`, `SessionEnded`, `SessionExpired`, `OutsideProcessTree`, `DaemonUnreachable`, `UnknownTool`, `BinaryUnusable`, `StaleSecret`, `OutsideRoot`, `Busy`, `IncompatibleProtocol`, `Malformed`, `Unauthorized`, `Internal` — mapped to exit codes in one place: `UnknownTool` → 127, `BinaryUnusable` → 126, everything else → 125. See [docs/airlock-v2-technical-guidance.md](docs/airlock-v2-technical-guidance.md) for why kinds are an enum rather than formatted strings.

### Exec flow (per-connection, within a session)

```
Client sends: {"auth":{"kind":"session","token":"airlock_7f3a9c_..."},
               "body":{"type":"exec","tool":"gh","args":["repo","list"],"cwd":"/home/user/project"}}

Daemon handler:
 1. Resolve the token to a Session (constant-time compare); check the caller
    descends from the session's anchor process (token binding, see below).
 2. Validate tool exists in the session's current SessionPolicy; validate CWD
    is within the session's root.
 3. Resolve binary on the session's filtered PATH; refuse if it resolves
    inside the root or a write grant (same check the launcher ran at Register).
 4. Build child env: tool.env in alphabetical order (a `BTreeMap`, not
    declaration order), Static(s) as-is and SecretRef(label) via the
    session's secret store; then the essential pass-through set (PATH,
    HOME, TERM, USER, TZ, LC_*).
 5. Proxy tools only: bind a loopback proxy listener for this exec, overlay
    the daemon-owned HTTPS_PROXY / CA variables.
 6. Resolve timeout and `access` level (`tools.<name>.access`, else the
    config's top-level default, else `ToolAccess::Default`); build ToolPolicy
    and SandboxProfile (SBPL / Landlock).
 7. spawn, register child PID, run the concurrent I/O loop (stdout/stderr
    redacted through the session's own redactor, then the global one; stdin;
    timeout → SIGTERM → SIGKILL), same as v1.
 8. Send Exit{code} or Error{kind, message}.
```

A per-session cap on concurrent `exec`s (16; the 17th is refused with `Busy`) keeps one agent from starving the others sharing the daemon.

### Token binding

A session token sits in every process the harness starts, and a same-uid process outside any sandbox can read another process's environment (`ps eww` on macOS, `/proc/<pid>/environ` on Linux). So the daemon binds each session to a **process tree**, not just a token: on every connection it takes the peer PID off the socket (`LOCAL_PEERPID` / `SO_PEERCRED`, [src/process_tree.rs](src/process_tree.rs)) and walks the parent chain, checking it against the session's recorded anchor process (PID + start time, so a reused PID can't match). For `run` the anchor is the launcher, alive exactly as long as the lease; for `session start` it's the shell that ran it. A copied token is then useless outside the tree it was issued to.

### Lifetime

| Started by | Ends when |
|---|---|
| `airlock run` | its **lease** closes — the `Register` connection stays open for the life of the launcher; the daemon holds a task that waits for EOF (close-on-exec, so the agent never inherits it) and revokes the session on close. The kernel closes the descriptor however the launcher dies, so nothing can leak a session past a dead launcher. |
| `airlock session start` | its **TTL** (default 12h, `session renew` restarts it without changing the token) runs out, or it's revoked |

### Lifecycle

Two modes, same daemon binary: **automatic** (the first launcher that finds none starts one with the existing double-fork/readiness-pipe sequence; it exits after a grace period with no sessions) and **service** (`airlock daemon install` writes a launchd agent / systemd user unit running `daemon start --foreground`; never idle-exits). Because every session's secrets, environment snapshot and filtered `PATH` travel with `Register`, the daemon's own environment is irrelevant in either mode.

**Version handshake.** Every connection starts with `Hello{protocol, version}` / `Hello{protocol, version, pid, mode, sessions}`. An automatic daemon outlives the binary that started it, so a launcher that finds an idle daemon of another version restarts it; a busy one keeps serving with a note, unless the protocol version is incompatible, in which case the launcher refuses and points to `daemon restart`.

## Protecting the anchors

Three locations decide what the daemon trusts and how clients reach it, each resolved from XDG variables and then validated ([src/anchors.rs](src/anchors.rs)):

| Anchor | Default | Approved? |
|---|---|---|
| runtime base | see [runtime_dir.rs](src/runtime_dir.rs); never taken from the environment | n/a — holds the socket, PID file, `admin.token`, proxy CAs |
| trust store | `$XDG_STATE_HOME/airlock/trust` | holds the approved copies |
| global config | `$XDG_CONFIG_HOME/airlock/airlock.toml` | no — protected by this check instead |

Each is checked before use: owned by the effective uid, mode 0700 (or non-group/other-writable for the global file), not a symlink, outside the project root, and outside every sandbox write grant from every layer — including unapproved ones, and including `--allow-write` and built-in profile paths. The one exception is macOS `$TMPDIR`, which the runtime base may sit under, because the Seatbelt deny rule (below) carves it back out. The same check runs the other way at config load: a write grant that covers an anchor is a config error. This closes the path where a repo's `mise.toml` or `.envrc` redirects `XDG_STATE_HOME` into the project on `cd` — the redirect lands somewhere the agent still can't write.

## Daemon internals (within one session)

Everything in this section is unchanged in substance from a single-tenant daemon; it now runs per-session rather than per-process.

### Proxy tools

A proxy tool holds no secret. Its only network path is a proxy the daemon
binds for that one execution, which attaches the credential after the request
has left the tool. Rationale and threat model:
[docs/proxy-tools-design.md](docs/proxy-tools-design.md) and
[SECURITY.md](SECURITY.md#proxy-tools).

The CA is generated once per daemon in `Daemon::start` — inside the runtime, after
the fork, so the synchronous-startup invariant is untouched — and shared as an
`Arc` across connections. Its key stays in memory; only the certificate is
written, to `<runtime base>/ca/<session-id>.pem`, readable only by that
session's proxy tools.

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

Running each session's proxy in its own process, rather than in the shared daemon, is tracked as [F10](docs/airlock-v2-design.md#follow-ups) — today the proxy is the largest piece of untrusted-input parsing (hyper, rustls) in a process that now holds every project's secrets, not just one.

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

Both paths take their redactor from the session's own `Arc<RwLock<Arc<Redactor>>>`, then from the daemon-wide last-pass redactor described under [Sessions](#sessions). An exec snapshots its session's redactor once, right after it reads the secrets the child is spawned with; a refresh swaps the redactor before it publishes a new value, so that snapshot knows every value in the child's environment. A proxy response snapshots per response, because the proxy injects whatever the store holds at that moment and a token refreshed mid-exec must be redacted on the way back.

## Wire protocol

Communication uses **NDJSON** (newline-delimited JSON) over the Unix domain socket. A connection opens with a `Hello` exchange, then exactly one `Request`; an `Exec` request continues with `Stdin`/`StdinEof` lines until `Exit`.

```json
{"protocol":2,"version":"0.6.0"}
{"protocol":2,"version":"0.6.0","pid":48211,"mode":"automatic","sessions":2}

{"auth":{"kind":"session","token":"airlock_7f3a9c_..."},
 "body":{"type":"exec","tool":"gh","args":["repo","list"],"cwd":"/home/user/project"}}
{"type":"stdin","data":"input line\n"}
{"type":"stdin_eof"}

{"type":"stdout","data":"output line\n"}
{"type":"stderr","data":"error line\n"}
{"type":"exit","code":0}
{"type":"error","kind":"unknown_tool","message":"no tool named \"bad-tool\" in this session"}
```

Session-family lines are capped at 1 MiB, as in v1. Admin-family lines (chiefly `Register`, which carries a config, secret values, an environment snapshot and a filtered `PATH`) have their own, larger cap, since they come only from a trusted launcher. Request and reply types are separate Rust enums per family, so the compiler enforces which side sends what; see [docs/airlock-v2-technical-guidance.md](docs/airlock-v2-technical-guidance.md) for why the two-family split and the error-kind enum are worth keeping even though v2 has only one transport.

## Secret sources

`[secrets.<label>]` is a top-level table where each entry declares one secret
by a logical label and a pluggable source, resolved once by the **launcher**
at `Register` (never by the daemon, and never from the daemon's own
environment):

| `source`    | Resolution                                                                              |
|-------------|-----------------------------------------------------------------------------------------|
| `"env"`     | Read the launcher's env var named by `from` (default: the label).                      |
| `"command"` | Spawn `command` (argv, no shell) on the filtered `PATH`, wait up to `timeout`, trim trailing newlines. |

Command sources run on the trusted side and are **not** sandboxed — the config is already approved. Failures are batched: the user sees every missing env var or failed command in one error, before anything is registered.

When a `command` secret declares `refresh = N`, the daemon (not the launcher, which has already exited for a `session start` session) spawns a task to re-run the command every `N` seconds, using the session's stored environment snapshot and filtered `PATH` — never the daemon's own. The redactor is rebuilt on each successful refresh and keeps both the new and previous-generation values for one cycle, so output captured just before the swap is still redacted. The rebuilt redactor is swapped in *before* the new value is published to the slot. On failure, the slot's health flips to `Stale`, the previous value is retained but the exec path refuses to inject it, and the task retries with exponential backoff capped at `refresh_max_backoff`.

`tools.X.env` maps env var names to values. A bare string is a static
passthrough (not redacted, since it's not a secret); an inline table
`{ secret = "label" }` is resolved against the session's secret store.

### Credential derivation at the boundary

A `command` source is more than a fetch mechanism. Because it runs on the
trusted side with the launcher's ambient environment and filesystem, it can
use credentials the sandbox will never see to *derive* the credentials the
sandbox gets:

```
   launcher process (trusted, your terminal)
   ┌──────────────────────────────────────────────────────────────────────┐
   │  ambient: ~/.config/gcloud — the operator's own login, broad scope   │
   │                                                                      │
   │  resolve, then Register ──▶ spawn  gcloud auth print-access-token    │
   │                                       --impersonate-service-account=…│
   │                                         │ stdout, trimmed            │
   │                                         ▼                            │
   │                            value travels once, over the socket       │
   └──────────────────────────┬───────────────────────────────────────────┘
                              │ daemon stores it in the session's SecretStore;
                              │ re-runs the same command on `refresh`, with the
                              │ session's own snapshot — never its own env
                              ▼
   sandboxed tool: receives only the derived token; ~/.config/gcloud is
   outside its filesystem policy unless a tool explicitly grants the path
```

Two consequences shape the design:

- **The store never holds the broad credential.** Only the command's stdout is stored. The operator's session stays wherever the CLI keeps it — readable by the launcher's spawned command through ordinary file permissions, invisible to tools unless a tool policy grants that path.
- **Expiry is a feature, not a failure mode.** Derived tokens are short-lived by construction, which is why `refresh` exists. A refresh that fails flips the slot to `Stale` and the exec path refuses to inject it.

Refresh slot health, per refreshable secret:

```
Register ──▶ Healthy ──(refresh fails)──▶ Stale ──(refresh succeeds)──▶ Healthy
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
| Token binding peer info | `LOCAL_PEERPID` / `proc_pidinfo` | `SO_PEERCRED` / `/proc/<pid>/stat` |

On unsupported platforms, the sandbox is a no-op (only `setpgid` in `pre_exec`), but the daemon still functions for development/testing.

### Tool filesystem baseline: `ToolAccess`

A tool's `ToolPolicy` carries an `access` level ([src/sandbox.rs](src/sandbox.rs)) that governs only the built-in filesystem baseline layered under a tool's own grants (project root, `[filesystem]`, `extra_read`/`extra_write`, its own binary, a proxy tool's CA) — `None` is the bare minimum to exec and exit (the dynamic linker, the shared library cache, `/dev/null`), `System` is the fixed baseline every tool got before `access` existed, and `Default` (the fallback when config sets nothing) adds the read-only toolchain roots in `TOOLCHAIN_ROOTS`. The agent's own `AgentPolicy` has no `access` field; it always gets the `None` + `System` baseline unconditionally, same as before. See [README.md](README.md#access-how-much-of-the-system-a-tools-sandbox-sees) for the config surface and [SECURITY.md](SECURITY.md) for the tradeoffs of each level.

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
| `ring` | SHA-256 for config hashing and project ids (already present transitively through rustls/rcgen) |
| `similar` | Unified diffs for the trust-approval prompt |
| `rcgen` | Proxy CA and leaf certificate generation |
| `hyper` / `hyper-util` / `http-body-util` | HTTP/1.1 server and client for the proxy |
| `bytes` | Body buffers on the proxy path |
| `webpki-roots` | Public trust anchors for upstream verification |
| `time` | Certificate validity windows |
| `getrandom` | CSPRNG for session tokens, `admin.token` and the per-exec proxy token |
| `subtle` | Constant-time comparison of tokens |

## Build

```bash
cargo build --release
```

Requires Rust 2024 edition. The build script (`build.rs`) captures the git commit hash and dirty flag, embedded in the `--version` output, and sets `cfg(no_nested_sandbox)` when the build itself runs inside an Airlock sandbox or with `AIRLOCK_NO_NESTED_SANDBOX=1` — see [CLAUDE.md](CLAUDE.md) for what that gates in the test suite.

## Tests

Unit tests are co-located in each module (`#[cfg(test)]` blocks). Integration tests live in `tests/`, extended for v2 with session registration, reload, trust-store and layer-merge coverage alongside the v1 suites (exec, daemon startup, redaction, CLI, logs, stdin, timeout, disconnect, concurrency, shutdown, `run`). `tests/examples_parse.rs` loads every file in `examples/` through the public `airlock::layers` / `airlock::config` API as its intended layer kind, so an example that doesn't parse under the real schema fails CI without needing a sandbox.

Environment-sensitive tests use an `EnvGuard` RAII helper with a global mutex to serialize access to `std::env`. Tests that apply an OS sandbox are `#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]` — see [CLAUDE.md](CLAUDE.md#tests).

```bash
cargo test
```
