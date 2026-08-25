# Airlock TODO

## Security backlog

These items came out of the April 2026 security review. See
`~/.claude/plans/expressive-squishing-conway.md` for the full review context.

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
(async-signal-safe). See [src/exec.rs:402-435](src/exec.rs#L402-L435) for the
existing pre-exec blocks on Linux and macOS.

**Config schema.** Likely a `[tools.X.limits]` table in `airlock.toml`; see
[src/config.rs](src/config.rs).

### Peer credential check on socket accept

**What.** On each `accept()`, verify the peer UID matches the daemon's EUID
and reject otherwise. Airlock currently relies entirely on socket mode `0700`
(verified at startup) for peer authentication.

- Linux: `getsockopt(SO_PEERCRED)`.
- macOS: `getpeereid` / `LOCAL_PEERCRED`.

**Why defer.** Defense-in-depth only: a same-UID attacker who can bypass the
socket mode already has significant access. Worth adding eventually but not
urgent given the existing mode check and the `verify_socket_permissions`
refusal at startup.

Ref: [src/daemon.rs:606-621](src/daemon.rs#L606-L621).

### Set `PR_SET_DUMPABLE = 0` in the child (Linux)

**What.** Add `prctl(PR_SET_DUMPABLE, 0)` to the child's pre-exec closure on
Linux, alongside the existing `PR_SET_NO_NEW_PRIVS` and landlock calls in
[src/exec.rs:413-433](src/exec.rs#L413-L433).

**Why.** The daemon already sets `DUMPABLE=0` on itself
([src/daemon.rs:549](src/daemon.rs#L549)), but the child inherits dumpable
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
network-outbound)` and `(allow network-bind (local unix-socket))` when
`requires_network` is true ([src/sandbox.rs:634-672](src/sandbox.rs#L634-L672)),
and `requires_network` itself is hardcoded to `true` for every tool
([src/policy.rs:156](src/policy.rs#L156)). So AF_UNIX `connect()` is
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
  ([src/config.rs:397](src/config.rs#L397)) and a matching
  `Vec<PathBuf>` on [`ToolConfig`](src/config.rs#L518) and
  [`ToolPolicy`](src/sandbox.rs#L36).
- On macOS, replace the blanket `(allow network-outbound)` and
  `(allow network-bind (local unix-socket))` in
  [`emit_network_rules`](src/sandbox.rs#L634) with per-path
  `(remote unix-socket (subpath ...))` / `(local unix-socket (subpath ...))`
  rules, and scope `system-socket` to `(socket-domain AF_UNIX)` only
  when the list is non-empty. Inet outbound stays under the existing
  `requires_network` gate.
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
