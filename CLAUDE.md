# Airlock — agent guide

## Commit policy

- Use conventional commits (`feat:`, `fix:`, `refactor:`, `chore:`, etc.) with a scope where it fits (`refactor(daemon): ...`).
- **Never add `Co-Authored-By:` trailers** (Claude or otherwise). Commit messages should read as the user's own authorship.
- Body should explain the *why*, not restate the diff. Reference file paths with `[name](path#Lline)` format when useful.

## What this project is

A Rust credential broker for AI agents. A long-running **daemon** holds secrets in memory; a short-lived **client** (`airlock exec`) connects over a Unix socket and asks the daemon to run a tool. The daemon spawns the tool with secrets injected as env vars, sandboxes the child (Seatbelt on macOS, Landlock on Linux), and streams back redacted stdout/stderr as NDJSON.

Read [README.md](README.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [SECURITY.md](SECURITY.md) for the full picture. Outstanding security work is in [TODO.md](TODO.md).

## Codebase invariants — do not break these

- **`main()` is synchronous.** No `#[tokio::main]`. Daemonization forks; forking after tokio spawns runtime threads leaves them in undefined state in the child. The entire `synchronous_startup()` must complete before any tokio runtime exists. See [src/daemon.rs:14-19](src/daemon.rs#L14-L19).
- **Double-fork with readiness pipe.** `daemon start` returns only after one of two things: the grandchild signals that it accepts connections, or `daemon start` prints the grandchild's startup error and exits non-zero. Every startup step in `async_main` that can fail runs before the readiness signal and must send its error through the pipe. It must never fail silently. See `daemonize` and `ReadinessPipe` in [src/daemon.rs](src/daemon.rs).
- **The trust boundary is the session token, not the socket alone.** One daemon serves every project a user has; the socket is reachable by any process of that uid, including an agent sandboxed for a *different* project. A connection proves nothing until it presents a session token, minted only by a launcher holding `admin.token`. The runtime directory is still mode `0700`, verified post-bind/post-create in [src/runtime_dir.rs](src/runtime_dir.rs) — necessary, but never sufficient on its own; never authorize a request from the socket connection alone.
- **Session isolation is structural, not a matter of care.** Hold these in every change touching `daemon.rs`, `session.rs` or a request handler:
  - **A session handle is the only path to that session's secrets, config and policy.** A handler takes `Arc<Session>` (resolved from the token before the handler runs) and reads only through it — no global map keyed by secret label or project root, no lookup outside its own session.
  - **No `std::env::var`/`set_var`/`remove_var`/`current_dir` outside startup code, ever, once a session is registered.** Everything a request needs travels with `Register`/`Reload` and is read from the `Session`, never the daemon's own process environment. Enforced by a clippy `disallowed-methods` lint — a regression fails CI, not just review.
  - **A daemon-wide last-pass redactor runs after each session's own**, built from every live session's secrets — the backstop if a bug ever let one session's secret reach another's output. It only removes text; it doesn't excuse a leak into the wrong session's tool *environment*, which the first two rules exist to prevent.
- **Secrets are wrapped in `Secret<T>`** ([src/secrets.rs](src/secrets.rs)) which zeroizes on drop and refuses to `Debug`-print. Never log a `Secret` value, never put one in a `format!`.
- **Pre-exec closures must be async-signal-safe and zero-alloc.** The closure passed to `Command::pre_exec()` in [src/exec.rs](src/exec.rs) — no allocation, no mutex, no `println!`, only raw libc calls. Errors from pre-exec abort the spawn.
- **Redaction is mandatory on the output path.** All bytes leaving the daemon to the client go through the Aho-Corasick redactor in [src/redact.rs](src/redact.rs), including base64 / URL-encoded / hex variants of secrets.

## Tests

- Most logic lives in `cargo test --lib`. All hermetic.
- `tests/cli_integration.rs` and other sandbox-spawning integration tests carry `#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]` — a sandbox can't nest a sandbox. `build.rs` sets `cfg(no_nested_sandbox)` when the build itself runs inside an Airlock sandbox (`AIRLOCK_SANDBOX=1`) or with `AIRLOCK_NO_NESTED_SANDBOX=1` (the Nix flake sets it). A plain `cargo test` outside Airlock, including CI (Linux), runs them — CI is otherwise unchanged, no macOS job, no `--include-ignored`. If you're an agent and see these skipped, that's expected; ask the user to run `cargo test` from their own terminal to exercise them.
- Some `client.rs` tests read the real stdin of the process. Run `cargo test < /dev/null`, or they can hang on an inherited pipe that never closes.
- Toolchain (Rust, Landlock headers, etc.) comes from `nix develop`; run `nix develop -c cargo test` if `cargo` isn't already on `PATH`.

## Top-level docs — keep in sync with the code

These four docs each cover a different audience. When a change touches their subject matter, update them in the same commit — don't let them drift.

- **[SKILL.md](SKILL.md)** — agent-facing usage guide. Update when CLI surface (`airlock exec/tools/agent ...`), `airlock.toml` schema, exit codes, or redaction behavior change. Triggers: diffs in [src/main.rs](src/main.rs), [src/protocol.rs](src/protocol.rs), [src/config.rs](src/config.rs), user-visible parts of [src/redact.rs](src/redact.rs).
- **[README.md](README.md)** — human-facing intro, tagline, install, quick start. Update when the value proposition, supported platforms, install steps, or top-level usage examples change.
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — how the pieces fit (daemon/client split, fork sequence, sandbox model, redaction pipeline). Update when module boundaries, the daemonize flow, sandbox mechanism, or socket protocol shape change.
- **[SECURITY.md](SECURITY.md)** — threat model, trust boundaries, mitigations, known-bad patterns (curl exfiltration, base32/hex encoding, file writes, etc.). Update when a new threat is considered, a mitigation lands or is removed, or the trust boundary moves.

## Style

- Comments: explain *why* something non-obvious, never *what* the code already says. Don't add change logs ("added for X", "fix for issue Y") in source — that belongs in commit messages.
- Prefer editing existing files. Don't create new modules without need.
- Don't add error handling for cases that can't happen, don't add fallback paths "just in case".
