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
- **Double-fork with readiness pipe.** `daemon start` returns to the user only after the grandchild signals it's accepting connections. See [src/daemon.rs:506-572](src/daemon.rs#L506-L572).
- **Trust boundary is the Unix socket.** The daemon is trusted; the client is not. Socket is mode `0700` and verified post-bind ([src/daemon.rs:416-435](src/daemon.rs#L416-L435)) — refuse to start if filesystem doesn't honor it.
- **Secrets are wrapped in `Secret<T>`** ([src/secrets.rs](src/secrets.rs)) which zeroizes on drop and refuses to `Debug`-print. Never log a `Secret` value, never put one in a `format!`.
- **Pre-exec closures must be async-signal-safe and zero-alloc.** The closure passed to `Command::pre_exec()` in [src/exec.rs](src/exec.rs) — no allocation, no mutex, no `println!`, only raw libc calls. Errors from pre-exec abort the spawn.
- **Redaction is mandatory on the output path.** All bytes leaving the daemon to the client go through the Aho-Corasick redactor in [src/redact.rs](src/redact.rs), including base64 / URL-encoded / hex variants of secrets.

## Tests

- Most logic lives in `cargo test --lib` (223 tests). All hermetic.
- `tests/cli_integration.rs` spawns the real `airlock` binary and runs `daemon start/stop/status`. **These might fail in the Claude Code sandbox**

## Top-level docs — keep in sync with the code

These four docs each cover a different audience. When a change touches their subject matter, update them in the same commit — don't let them drift.

- **[SKILL.md](SKILL.md)** — agent-facing usage guide. Update when CLI surface (`airlock list/exec/daemon ...`), `airlock.toml` schema, exit codes, or redaction behavior change. Triggers: diffs in [src/main.rs](src/main.rs), [src/protocol.rs](src/protocol.rs), [src/config.rs](src/config.rs), user-visible parts of [src/redact.rs](src/redact.rs).
- **[README.md](README.md)** — human-facing intro, tagline, install, quick start. Update when the value proposition, supported platforms, install steps, or top-level usage examples change.
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — how the pieces fit (daemon/client split, fork sequence, sandbox model, redaction pipeline). Update when module boundaries, the daemonize flow, sandbox mechanism, or socket protocol shape change.
- **[SECURITY.md](SECURITY.md)** — threat model, trust boundaries, mitigations, known-bad patterns (curl exfiltration, base32/hex encoding, file writes, etc.). Update when a new threat is considered, a mitigation lands or is removed, or the trust boundary moves.

## Style

- Comments: explain *why* something non-obvious, never *what* the code already says. Don't add change logs ("added for X", "fix for issue Y") in source — that belongs in commit messages.
- Prefer editing existing files. Don't create new modules without need.
- Don't add error handling for cases that can't happen, don't add fallback paths "just in case".
