# Airlock TODO

## Airlock v2 follow-ups

[docs/airlock-v2-design.md](docs/airlock-v2-design.md) tracks the items that
came out of designing and implementing v2 but weren't blocking. Each has its
own write-up there; this is just the index so they aren't lost:

- **[F1](docs/airlock-v2-design.md#follow-ups) — ownership checks and XDG
  handling for the anchors.** "Owned by the effective uid" proves nothing
  against the agent, which runs as the same uid; only "outside every write
  grant" actually protects an anchor from it. Revisit whether the ownership
  and mode checks pull their weight, or whether anchors should come from the
  passwd home directory instead of honoring XDG at all.
- **[F2](docs/airlock-v2-design.md#follow-ups) — the global config under
  home-manager.** home-manager links `~/.config/airlock/airlock.toml` into
  `/nix/store`, root-owned, so the ownership check refuses it today. Decide
  whether to accept root ownership or check only that no sandbox can write
  the file.
- **[F3](docs/airlock-v2-design.md#follow-ups) — review a policy diff, not
  only a byte diff.** A unified diff hides which TOML table a line belongs
  to and doesn't catch confusable characters. Show the effective merged-policy
  change next to the byte diff; mark comment-only edits as no-op.
- **[F6](docs/airlock-v2-design.md#follow-ups) — every git worktree needs
  its own first approval.** Agent workflows create worktrees often. Consider
  accepting a file whose bytes match a copy already approved for the same
  git common dir.
- **[F7](docs/airlock-v2-design.md#follow-ups) — runtime dir lifetime.**
  `systemd-logind` deletes `/run/user/<uid>` at logout, orphaning a daemon
  started over ssh; a systemd user service stops at logout without
  `loginctl enable-linger`. Check macOS's periodic temp cleanup against a
  long-running daemon's PID file too.
- **[F10](docs/airlock-v2-design.md#follow-ups) — run each session's proxy
  in its own process.** The proxy is the largest piece of untrusted-input
  parsing (hyper, rustls) in a daemon that now holds every project's
  secrets, not just one. A per-session proxy process would need only the
  credentials for its own routes.
- **[F11](docs/airlock-v2-design.md#follow-ups) — network transport.** The
  v2 protocol keeps this possible (see
  [airlock-v2-technical-guidance.md](docs/airlock-v2-technical-guidance.md))
  but doesn't implement it. Needs TLS, tokens bound to a client TLS identity
  instead of a process tree, and an answer for where tools run.
- **[V1](docs/airlock-v2-design.md#planned-for-v21) — dynamic shell
  completion.** Designed in
  [airlock-v2-ux.md](docs/airlock-v2-ux.md#shell-completion) but deferred:
  `airlock completions <bash|zsh>` calling back into the daemon on every
  TAB for tool names and session ids. Pins `clap_complete`'s
  `unstable-dynamic` feature.

## Security backlog

These items came out of the April 2026 security review. See
`~/.claude/plans/expressive-squishing-conway.md` for the full review context.

Airlock v2 resolved the socket peer-authentication item in this section (a
session token, checked against the caller's process tree, replaces
uid-only socket trust — see [SECURITY.md](SECURITY.md#sessions)) and added a
peer-uid check as part of resolving the auth principal on every connection.
The items below are unrelated to the v2 session/config work and are still
open.

### Per-child resource limits (`setrlimit`)

**What.** Apply conservative `setrlimit` calls inside the child's pre-exec
closure to bound the blast radius of a misbehaving or malicious tool.

- Unconditional: `RLIMIT_CORE = 0` (no core dumps; matches the daemon's own
  hardening and prevents secret bytes leaking via a child core dump).
- Configurable per-tool, with sensible defaults:
  - `RLIMIT_AS` — address-space cap.
  - `RLIMIT_CPU` — CPU-seconds cap.
  - `RLIMIT_NPROC` — max processes for this uid.
  - `RLIMIT_NOFILE` — max open fds.

**Constraints.** The child's pre-exec closure must use raw `libc::setrlimit`
(async-signal-safe). See [src/exec.rs:585-622](src/exec.rs#L585-L622) for the
existing pre-exec blocks on Linux and macOS.

**Config schema.** Likely a `[tools.X.limits]` table in `airlock.toml`; see
[src/config.rs](src/config.rs).

### Set `PR_SET_DUMPABLE = 0` in the child (Linux)

**What.** Add `prctl(PR_SET_DUMPABLE, 0)` to the child's pre-exec closure on
Linux, alongside the existing `PR_SET_NO_NEW_PRIVS` and landlock calls in
[src/exec.rs:596-605](src/exec.rs#L596-L605).

**Why.** The daemon already sets `DUMPABLE=0` on itself
([src/daemon.rs:496](src/daemon.rs#L496)), but the child inherits dumpable
across fork and execve resets it to `/proc/sys/fs/suid_dumpable` (typically
1). The running tool therefore has `/proc/<pid>/environ`, `/proc/<pid>/mem`,
and `/proc/<pid>/maps` readable by any same-UID process for its lifetime —
which is the window the secrets-via-env note in `SECURITY.md` describes.
Setting `DUMPABLE=0` in the child reverts those `/proc` files to root
ownership and also blocks same-UID ptrace under yama. It does not eliminate
the same-UID threat (an attacker could still race during the brief
post-execve window before any further hardening, and root is unaffected),
but it materially shrinks the exposure for the common case.

**Constraints.** Must be async-signal-safe and zero-alloc. Single
`libc::prctl` call, same shape as the existing `PR_SET_NO_NEW_PRIVS` line.
Order it after `setpgid` and before `PR_SET_NO_NEW_PRIVS` so a `prctl`
failure aborts the spawn before any privilege-affecting state changes.

**Follow-up.** Update the "Secrets visible via `/proc/<child_pid>/environ`"
section in `SECURITY.md` once landed, since the residual risk narrows to
root and to brief race windows rather than any same-UID peer.

### Per-tool Unix socket access

**What.** Let a tool config declare specific Unix-domain sockets it may
`connect()` / `bind()` (e.g. `/var/run/docker.sock`, `$SSH_AUTH_SOCK`,
language-server IPC sockets) without routing that intent through the
generic `extra_read` filesystem list.

**Why.** Today the macOS profile unconditionally emits `(allow
network-outbound)` and `(allow network-bind (local unix-socket))` for
`NetworkAccess::Full` ([src/sandbox.rs:889](src/sandbox.rs#L889)), and a
non-proxy tool's `network` is hardcoded to `NetworkAccess::Full`
([src/policy.rs:171-180](src/policy.rs#L171-L180)). So AF_UNIX `connect()` is
wide open at the syscall layer — the only gate is file-read on the
socket inode, which users currently have to express via `extra_read`.
That works as ergonomics but is cosmetic as isolation: a tool asking
for socket A effectively gets the whole AF_UNIX space.

**Prior art.** `anthropic-experimental/sandbox-runtime` exposes two
explicit fields on its network config:

```ts
allowUnixSockets?: string[]      // macOS only — specific socket paths
allowAllUnixSockets?: boolean    // opt-out: allow all
```

For each allowed path it emits three scoped SBPL rules:

```lisp
(allow system-socket    (socket-domain AF_UNIX))                          ; socket() — path-less, global
(allow network-bind     (local  unix-socket (subpath "/var/run/foo")))    ; bind()
(allow network-outbound (remote unix-socket (subpath "/var/run/foo")))    ; connect()
```

If neither field is set, AF_UNIX is blocked by default. On Linux they
explicitly punt: seccomp cannot filter by socket path, so the option is
documented as macOS-only.

**Proposed shape for Airlock.**

- Add `sockets = ["/var/run/..."]` to `[tools.X]` in `airlock.toml`
  (next to `extra_write` on the raw type, [src/config.rs:684](src/config.rs#L684))
  and a matching `Vec<PathBuf>` on [`ToolConfig`](src/config.rs#L859) and
  [`ToolPolicy`](src/sandbox.rs#L51).
- On macOS, replace the blanket `(allow network-outbound)` and
  `(allow network-bind (local unix-socket))` in
  [`emit_network_rules`](src/sandbox.rs#L741) with per-path
  `(remote unix-socket (subpath ...))` / `(local unix-socket (subpath ...))`
  rules, and scope `system-socket` to `(socket-domain AF_UNIX)` only
  when the list is non-empty. Inet outbound stays under the existing
  `NetworkAccess::Full` gate.
- On Linux, document it as macOS-only (matching sandbox-runtime) and
  treat the field as a no-op under Landlock. Revisit if we ever add a
  seccomp layer with BPF socket filtering.

**Constraints.** Rules must be emitted in a deterministic order and
all paths sanitized with the existing `escape_path` /
`ControlCharacterInPath` guards in [src/sandbox.rs](src/sandbox.rs).
Keep the `mDNSResponder` block in `emit_network_rules` gated on inet
access only — it's DNS resolution, not Unix-socket.

**Security note.** This tightens the default: tools that today rely on
ambient AF_UNIX reach (e.g. anything that happens to talk to a
pasteboard helper or a system agent via Unix socket) would break until
they declare the path. Worth a migration note in `SECURITY.md` and an
update to `SKILL.md` describing the new field.

## Feature backlog

### Multi-value command sources

**What.** Let one `[secrets.<label>]` command populate several labels from
a single invocation — parse a JSON document on stdout and bind named fields
to labels.

**Why.** Minting scoped credentials (README: "Minting scoped credentials")
works today for providers that hand back one token per call: GCP access
tokens, GitHub App installation tokens. AWS does not. `aws sts assume-role`
returns `AccessKeyId`, `SecretAccessKey`, and `SessionToken` as a coupled
triple from one STS call; declaring three `command` secrets would mint
three unrelated sessions whose values don't match. The obvious workaround —
a wrapper script that caches the triple on disk so three invocations agree
— puts short-lived credentials in a plaintext file, which is the thing
Airlock exists to avoid. Until this lands, AWS users are limited to scoped
static keys.

**Proposed shape.**

```toml
[secrets.aws-session]
source  = "command"
command = ["aws", "sts", "assume-role",
           "--role-arn", "arn:aws:iam::123456789012:role/agent-readonly",
           "--role-session-name", "airlock",
           "--query", "Credentials", "--output", "json"]
format  = "json"
refresh = 3000

[secrets.aws-session.fields]
AWS_ACCESS_KEY_ID     = "AccessKeyId"
AWS_SECRET_ACCESS_KEY = "SecretAccessKey"
AWS_SESSION_TOKEN     = "SessionToken"
```

Each field becomes a label resolvable from `[tools.X.env]`. A refresh swaps
every field of one source atomically, and the redactor tracks two
generations of each field.

**Constraints.** Every field value must feed the redactor, encoded variants
included, exactly like a single-value secret. `Stale` applies to the whole
source, never per field — a half-refreshed triple is worse than a stale one.
`format = "json"` is the only parser; no shell, no templating of argv.
