# Runtime directory and layered config — design proposal

**Status:** proposal. The blocking items in [Open questions and
follow-ups](#open-questions-and-follow-ups) are resolved. Nothing here is
implemented yet. Today's behavior is
described in [ARCHITECTURE.md](../ARCHITECTURE.md) and
[SECURITY.md](../SECURITY.md).

This document is the design record: what changes, why, and which
alternatives were rejected. When it ships, the user-facing reference will
be [README.md](../README.md) and [SKILL.md](../SKILL.md).

## Problem

Two separate problems share one fix: the project directory should hold only
config, and no runtime state or trust decisions.

**Runtime files live in the project.** The daemon writes `airlock.sock`,
`airlock.pid` and `airlock-ca.pem` next to `airlock.toml`, in the sandbox
root. That directory is read-write for the agent and for every tool
([src/policy.rs](../src/policy.rs), `sandbox_root` is always in
`read_write_paths`). So:

- The agent or any tool can delete or replace the socket, the PID file or
  the proxy CA certificate while the daemon runs. Replacing the CA only
  breaks proxy tools. It exposes no credential, because the tool→proxy leg
  carries none. It is still tampering we should not allow.
- The files show up in `git status`. Every project needs `.gitignore`
  entries for them, and they are easy to commit by accident.

**There is one config file, and it is shared.** `airlock.toml` is checked in
and describes the team's tools. It also has to say where each secret comes
from, and that is personal: one user reads `GH_TOKEN` from 1Password,
another from `gh auth token`. A user who wants an extra tool of their own
has nowhere to put it except the shared file.

Layering personal config over shared config raises a trust question that
does not exist today: the shared file is written by whoever can land a PR,
and by the agent itself. Today Airlock simply trusts whatever
`airlock.toml` says at daemon start.

## Goals

- Socket, PID file and CA certificate live outside the project directory,
  in a per-user location the agent and tools cannot write.
- A user can layer personal config over the repo's config: bind secret
  sources, add personal tools, adjust the agent sandbox.
- The daemon never acts on a project config file the user has not
  approved. That includes a file the agent edited. Editing is allowed and
  sometimes useful, but the user reviews the diff and approves it again.
- No sandbox, the agent's or a tool's, can write the approval record, the
  global config or the runtime directory, or redirect Airlock to a copy it
  wrote.

## Non-goals

- Backwards compatibility. Airlock is pre-1.0. Old in-project runtime files
  are not migrated; users delete them.
- Reloading a running session. An approved config change applies to
  sessions started after the approval. Running sessions keep the config
  they started with.
- Protecting against an agent that runs outside `airlock run`. Such an agent
  is the user, as far as the OS is concerned.
- Protecting against agent-written code that the user runs outside the
  sandbox: git hooks, `core.fsmonitor`, `.envrc`, mise hooks, build scripts,
  tests. That code runs as the user and can rewrite any anchor, but it can
  equally read the user's credentials directly, so it defeats Airlock's core
  promise before it reaches the trust store. See [B1](#blocking).
- A network transport. This proposal implements Unix sockets only, but
  keeps the protocol free of anything that would rule out TCP later (see
  [Transport](#transport)).

## Overview

- **One daemon per user**, serving every project through
  [sessions](#sessions). A launcher in the user's terminal (`airlock run`,
  `airlock session`) loads and approves a project's config, resolves its
  secrets, and registers a session. The agent gets a session token, and the
  daemon serves it only that project.
- **Runtime dir:** `/run/user/<uid>/airlock/` on Linux, the per-user temp
  dir from `confstr` on macOS. Neither comes from the environment. The
  directory is owned by the user and has mode 0700.
- **Three config layers**, lowest to highest precedence:
  1. **global:** `$XDG_CONFIG_HOME/airlock/airlock.toml`
  2. **repo:** `airlock.toml` in the project root
  3. **local:** `airlock.local.toml` in the project root (gitignored)
- **Trust:** the repo and local files must each match a byte-for-byte copy
  the user approved with `airlock trust`. The global file needs no approval.
- **Anchors:** the trust store, the global config and the runtime dir are
  refused if they sit where the agent can write.

## Runtime directory

### Location

| Platform | Base | Fallback |
|---|---|---|
| Linux | `/run/user/<uid>/airlock`, when `/run/user/<uid>` exists, is owned by the uid and has mode 0700 | `/tmp/airlock-<uid>` |
| macOS | `confstr(_CS_DARWIN_USER_TEMP_DIR)` + `airlock` | none |

The base ignores `TMPDIR` and `XDG_RUNTIME_DIR`. Both vary between shells of
the same user: agent harnesses, Nix shells and tmux change `TMPDIR`, and
`sudo -u`, cron and some ssh and container setups leave `XDG_RUNTIME_DIR`
unset. A base taken from either would let two shells disagree about where the
daemon lives (see [B6](#blocking)).

The daemon is per user, so the base holds one set of files:

| File | Purpose |
|---|---|
| `airlock.sock` | client socket |
| `airlock.pid` | PID file |
| `admin.token` | credential for registering [sessions](#sessions), mode 0600, unreadable from every sandbox |
| `ca/<session-id>.pem` | a session's proxy CA certificate, when its config has a proxy tool |

Both bases are per-user and cleared on reboot, which suits a socket and a PID
file. The paths are short enough for `sun_path`: the canonical macOS
per-user temp dir is about 52 bytes, so the socket path comes to about 75 of
the 104 allowed bytes.

The Linux fallback sits in shared `/tmp` under a predictable name. Another
user who creates it first only makes the validation below fail, so the
daemon refuses to start, and it gains no access. A config that grants write
access to `/tmp` is refused on a system that uses the fallback, by the
[anchor check](#protecting-the-anchors).

### Validation

The daemon creates `<base>` and `<base>/ca` with mode 0700. Before using
either, whether it just created it or found it, it checks with `lstat` that:

- it is a directory, not a symlink,
- it is owned by the effective uid,
- `mode & 0o077 == 0`.

If any check fails, the daemon refuses to start and names the directory and
the failed check. The existing post-bind socket mode check
([src/daemon.rs](../src/daemon.rs)) stays.

The runtime base is also one of the [anchors](#protecting-the-anchors), so
it must not fall under any sandbox write grant.

### Sandbox access

| Who | Needs |
|---|---|
| Agent (`airlock exec`, `airlock list` inside `airlock run`) | connect to `airlock.sock`; never read `admin.token` |
| Proxy tools | read their own session's `ca/<session-id>.pem`, a new entry in their `read_paths` |
| Ordinary tools | nothing |

No sandbox gets write access to the runtime dir.

- **macOS:** the Seatbelt baseline grants read-write to all of `$TMPDIR`
  ([src/sandbox.rs](../src/sandbox.rs), "$TMPDIR (per-session scratch)"),
  which is normally the same directory as the base. Every profile, agent and
  tool, therefore ends with `(deny file-write* (subpath "<base>"))` and
  `(deny file-read* (literal "<base>/admin.token"))`. Tools keep their
  scratch space but cannot write Airlock's subtree or register sessions. The
  denies are the **last** rules in the profile: in SBPL the last matching
  rule wins, so any allow emitted after them would re-allow the path. That
  includes `agent.filesystem.write`, `extra_write`, `--allow-write` and
  built-in profile rules.
- **Linux:** Landlock is allow-only and cannot carve a subtree out of a
  grant. Neither `/run/user/<uid>` nor `/tmp` is granted by default, and
  the anchor check refuses any config or `--allow-write` that would grant
  the base.

### Stale state and migration

Stale-state cleanup works as today (`check_and_cleanup_stale_state`), but in
the runtime dir. Nothing looks for runtime files in the project directory
any more. Users delete leftover `airlock.sock`, `airlock.pid` and
`airlock-ca.pem`, and the matching `.gitignore` lines.

## Config layers

### The three files

| Layer | Path | Approved? | Who writes it |
|---|---|---|---|
| global | `$XDG_CONFIG_HOME/airlock/airlock.toml` (default `~/.config/airlock/airlock.toml`, on macOS too) | no | the user |
| repo | `<root>/airlock.toml` | yes | the team, PR authors, the agent |
| local | `<root>/airlock.local.toml` | yes | the user, the agent |

The local file sits in the project directory, where the agent can write, so
it is approved exactly like the repo file.

### Discovery

Discovery walks up from the working directory to `$HOME` (inclusive), as
today. The first directory holding an `airlock.toml` **or** an
`airlock.local.toml` owned by the effective uid is the project root. Either
file marks the project, so Airlock can be used in a repo whose team has not
adopted it. The project root is the sandbox root, with the same meaning as
now.

With no project file found, Airlock fails as today, however much global
config exists.

### `--config <path>`

Exactly that one file: no global layer and no local layer. The project root
is the file's parent directory, as today. The file still has to be approved.

### `--no-project-config`

This replaces `airlock run --no-config` and `AIRLOCK_SANDBOX_ROOT`. The
empty-config mode those provided is removed.

- Valid wherever discovery runs: `run`, `session exec`, `session start`
  and `status`. `exec` and `list` do no discovery, since they use their
  session.
- Ignores `airlock.toml` and `airlock.local.toml` even if present.
- The project root is the canonical working directory. The config is the
  global layer alone, which may be absent (an empty config).
- With no repo or local file, there is nothing to approve.
- The agent finds the daemon through its [session](#sessions), as in every
  other mode, so a working directory that moves does not matter.

### Merge rules

Each layer is parsed on its own, then the layers are merged, then the
existing validation runs on the merged result. For example, "a proxy tool
must not hold a secret" is checked against the merged tools.

| Item | Rule |
|---|---|
| `[tools.<name>]` | Must be defined in exactly one layer. A duplicate is a config error naming both files, so a personal tool cannot silently shadow a team tool, or the reverse. |
| `[secrets.<label>]` | See [Secret labels across layers](#secret-labels-across-layers). |
| `filesystem.read`, `filesystem.write` | union |
| `agent.passthrough_env` | union |
| `agent.filesystem.read`, `agent.filesystem.write` | union |
| `agent.env.<VAR>` | per key, highest layer wins |
| `timeout`, `agent.timeout` | highest layer that sets it |
| `allow_home_root` | Honored in global or local. In the repo layer it is a config error. |

### Secret labels across layers

A secret reference crosses layers only where the user says so in an
approved file.

- **Repo items** (tools, `agent.env`) may reference only labels the repo
  layer declares. In the repo layer `source` is optional: a label without
  one says "this project needs `GH_TOKEN`" and leaves the binding to the
  user.
- **Global items** may reference only global labels.
- **Local items** may reference any label.
- **The local layer binds repo labels.** A local `[secrets.<label>]` for a
  label the repo declares replaces the repo's spec whole, either with its
  own `source` or with `from = "global"`, which uses the global binding of
  the same name. `from` and `source` are mutually exclusive.
- **The global layer never serves a repo label on its own.** A global
  `[secrets.GH_TOKEN]` and a repo `[secrets.GH_TOKEN]` are two separate
  bindings until the local file links them.
- A repo label with no source and no local binding is a startup error that
  names the label and suggests `from = "global"` or a `source`.

The opt-in is what the user approves. A PR that adds a tool taking
`OPENAI_API_KEY` gets the repo's own binding, or none. It gets the user's
1Password entry only after the user approves a local line that says so.

```toml
# airlock.local.toml
[secrets.GH_TOKEN]
from = "global"
```

**Relative paths.** Paths in the repo and local layers resolve against the
project root, as today. A relative path in the global layer is a config
error: the file applies to every project, so a relative path would mean
something different in each. `~` and `{sandbox_root}` work in all layers.

## Trust

### What is approved

- **The repo and local files, each on its own.** A file is approved when its
  current bytes equal the copy recorded by `airlock trust`. This is the
  whole file: an edited comment needs approval again too.
- **The `--config` file.** Same rule.
- **Not the global file.** It is the user's own file, outside every
  project. It is protected by the [anchor checks](#protecting-the-anchors)
  instead.

### Trust store

```
$XDG_STATE_HOME/airlock/trust/<id>/     (default ~/.local/state/airlock/trust/<id>/, mode 0700)
    root                  canonical project root
    airlock.toml          approved copy of the repo file
    airlock.local.toml    approved copy of the local file
    <name>.toml           approved copy of a --config file named <name>.toml
```

Each copy is stored under the approved file's name. Every approved file sits
in the project root, since `--config` makes the file's parent the root, so
`<id>` plus the name identify the file's canonical path. A `--config` file
that is itself named `airlock.toml` in a project root is the repo file and
shares its slot.

`<id>` is the first 16 hex characters of the SHA-256 of the canonical
project root. The stored copy is the record: the check compares SHA-256 of the current bytes with SHA-256 of the
copy. Keeping the copy instead of just a hash is what makes the refusal able
to show a diff.

A project that moves to a new path gets a new `<id>` and needs approval
again.

### When approval is checked

Wherever config is loaded, and that is only when a session starts: `airlock
run`, `session exec` and `session start`. The daemon itself never reads
project config.

- **In the user's terminal.** The launcher checks approval before it
  registers the session, so the refusal and diff print straight to the
  user.
- **No gap between check and use.** Each file is read once with
  `read_config_securely`. The same bytes are hashed, compared and parsed,
  and the parsed result is what the launcher registers.

`exec` and `list` use a session whose config was approved when it started,
so they do not check again.

### Refusal

If any layer is unapproved, startup refuses and exits non-zero. For each
unapproved file it prints either a unified diff against the approved copy or,
for a file never approved, its full contents. It ends by pointing to
`airlock trust`.

The printed text is escaped before output: control characters, ANSI escapes,
bidirectional overrides (U+202A–U+202E, U+2066–U+2069) and zero-width
characters are shown as `\u{…}`. TOML accepts bidi and zero-width characters
in strings and comments. Without escaping, an agent could write a diff that
reads differently from what it does.

### `airlock trust`

1. Discovers the same layers a session start would. It honors `--config` and
   refuses `--no-project-config`, since there would be nothing to approve.
2. For each repo or local file that differs from its approved copy, prints
   the escaped diff (or the full file) and asks `Trust <path>? [y/N]`.
3. On `y`, writes the exact bytes it showed to the trust store: a temp file
   and `rename` in the same directory.
4. If sessions for this project are running, prints a note that they keep
   the previous config and that new sessions use the approved one.

On a non-terminal, it refuses unless `--yes` is given. `--yes` approves
without prompting, for scripted setup.

### After approval

A running session keeps the config it started with. The session records the
SHA-256 of every layer it loaded, including the global file. `airlock status`
and `session list` compare those with the files on disk and mark a session
`config changed since the session started` when they differ. Starting a new
session picks up the approved config. The daemon does not restart.

## Sessions

One daemon per user serves every project. A session binds a client to one
project: its root, its approved config and the secrets resolved for it. The
daemon authenticates clients by uid, and the agent runs as the user, so the
socket alone proves nothing ([B4](#blocking)). `exec` and `list` are served
only with a session token, and only a process outside every sandbox can
register a session.

### Admin credential

At start, before the readiness signal, the daemon writes 32 random bytes to
`<base>/admin.token` with mode 0600. A restart replaces it. No sandbox can
read it: Landlock never grants the runtime dir, and every Seatbelt profile
denies it (see [Sandbox access](#sandbox-access)). Session registration,
`session list`, `session revoke`, `status`, `logs` and `daemon stop` need it.
`exec` and `list` never read it.

### Registering a session

The launcher (`airlock run`, `session exec` or `session start`) does
everything that needs the user's terminal or the project's environment, and
then hands the result to the daemon:

1. Discovers the layers from the current directory, checks approval and
   merges them, as in [Trust](#trust).
2. Resolves every secret the config uses. `source = "command"` runs here, so
   a 1Password or `gcloud` prompt reaches the user. `source = "env"` reads
   the launcher's own environment. This is what `synchronous_startup` does
   today.
3. Builds the [filtered `PATH`](#blocking) (B2) and an environment snapshot
   of the launcher, without the variables consumed by `source = "env"`.
4. Starts the daemon if none is running (see [Lifecycle](#lifecycle)).
5. Sends a `Register` request with the admin credential: the root, the
   merged config, the layer hashes, the secret values, the snapshot and the
   filtered `PATH`. The daemon builds the session's redactor, policy and
   proxy, and answers with a session id and a 32-byte random token.

The launcher holds secret values in `Secret<T>` and drops them once
`Register` succeeds. Refresh commands run later in the daemon, with the
session's snapshot and filtered `PATH`, never the daemon's own environment.

### Commands

| Command | Does |
|---|---|
| `airlock session exec -- <harness…>` | Registers a session, runs the harness with `AIRLOCK_ADDR` and `AIRLOCK_SESSION` set, and revokes the session when the harness exits. |
| `airlock session start` | Registers a session and prints the `export` lines, for harnesses that cannot be wrapped, such as an IDE extension. |
| `airlock session list` | Lists sessions: id, root, start time, number of `exec`s, and whether the config changed since the session started. |
| `airlock session revoke <id>` / `--all` | Ends sessions without restarting the daemon. |

`airlock run` registers and revokes its session the same way as
`session exec`. It no longer embeds a daemon of its own, so any number of
agents can run in one project at the same time.

### Scope

The directory a session is started in decides what it can reach. Discovery
runs from there as for every other command, and the session serves only
that root's approved config. A subdirectory with its own `airlock.toml` is
a separate project, and a session started there gets that project. The
daemon takes the root and config from the session, never from the request,
so an agent that changes directory keeps the scope it started with. The
request's working directory must still lie under the session's root, as
today.

Sessions are independent. Two sessions for the same project resolve their
own secrets and can run different approved configs, for example an old
session next to a new one started after an approval, or a `--config` file
next to the default one. Sharing secrets between sessions of one project
may come later as an optimization.

### Lifetime

Sessions live in daemon memory only. A session ends when it is revoked, when
`session exec` or `run` sees its harness exit, or when the daemon stops.
A token that the agent stashed, or that a leftover background process
still holds, stops working with it. Its secrets, redactor and proxy are
dropped, and its CA file is deleted.

### Lifecycle

Two modes, with the same daemon:

- **Automatic (default).** The first launcher that finds no daemon starts
  one, with the existing double fork and readiness pipe, before the
  launcher creates any tokio runtime. An automatically started daemon
  exits after a short grace period with no sessions.
- **Service.** `airlock daemon install` writes a launchd agent or a systemd
  user unit that runs `airlock daemon run` in the foreground. A service
  daemon stays up with no sessions. `airlock daemon uninstall` removes it.

The daemon's own environment does not matter in either mode, because
everything a session needs comes with `Register`. `daemon start`, `daemon
stop` and `daemon status` stay for manual control.

### Session isolation

All sessions share one process. Inside a session nothing changes from
today. The new risk is one session's request, tool or output reaching
another session's secrets. The design rules below keep that a structural
property rather than a matter of care, and implementation must hold them.

- **The session is the only path to sensitive state.** The token resolves
  to an `Arc<Session>` holding the config, secret store, redactor, policy,
  environment snapshot, filtered `PATH` and proxy. Request handlers receive
  only that handle. No global map holds secrets or config, and nothing
  looks a secret up by label outside its session.
- **No process-global state after startup.** Today the request path reads
  the process environment: `PATH` in `resolve_binary`
  ([src/exec.rs](../src/exec.rs)), `TMPDIR` in the Seatbelt builder, and
  `source = "env"` and `clear_secret_env_vars` in
  [src/secrets.rs](../src/secrets.rs). All of it moves into the session. A
  clippy `disallowed-methods` rule forbids `std::env::var`, `set_var`,
  `remove_var` and `current_dir` outside startup code, so a regression fails
  CI.
- **A last-pass global redactor.** After a session's own redactor, output
  also passes an automaton built from every live session's secrets. It
  masks another session's secret in output even if a bug put it there.
  Redaction only removes text, so it discloses nothing. It does not cover a
  secret leaked into another session's tool environment, which the first
  rule has to prevent.
- **Per-session limits** on concurrent `exec`s and output rate, so one agent
  cannot starve the others. A panic unwinds and ends only its task.

The proxy is the largest attack surface in the process: hyper and rustls
parse input from sandboxed tools and from upstream servers. A memory-safety
bug there would now reach every project's secrets, where today it reaches
one. Moving each session's proxy to its own process is [F10](#follow-ups).

### Clients

`exec` and `list` take the address and token from `AIRLOCK_ADDR` and
`AIRLOCK_SESSION` and nothing else. They do not fall back to `admin.token`
or to discovery. A user who wants to run `exec` by hand starts a shell
with `airlock session exec -- $SHELL`. Every `exec` is logged with its
session id.

### Transport

`AIRLOCK_ADDR` is a URI. This proposal implements `unix://<path>` only. The
design keeps a TCP transport open:

- **Authorization is the session token, not the uid.** Peer uid and the
  socket's mode 0700 stay as a check on the Unix transport, but no decision
  depends on them.
- **Requests carry no file descriptors.** They carry no other host-local
  handles either, so any byte stream can carry the protocol.
- **Registration stays local.** `admin.token` is read from the daemon's
  filesystem, so only a launcher on the daemon's host can register a
  session. A remote agent receives a token that was registered there.

A TCP transport needs TLS, and probably tokens bound to the client's TLS
identity, since a token on the network is a bearer credential. It also meets
a limit that a socket hides: tools run on the daemon's host, against the
project root and working directory on that host. See [F11](#follow-ups).

### Under another harness

The session token reaches the agent through its environment, so a
harness can deny reads of the whole runtime base without breaking Airlock.
It has to: `admin.token` is protected from Airlock's own sandboxes only. A
harness that lets the agent read `<base>` lets it register sessions for any
project. SECURITY.md states this, with the path to deny.

### Commands refused inside the sandbox

`trust`, `session`, `daemon` and `run` refuse when `AIRLOCK_SANDBOX=1`, with
a clear error. The agent can unset the variable, so this is a convenience
only. What actually stops the agent is that it cannot write the trust store
(see below) or read `admin.token`. A daemon the agent starts itself cannot
create its socket in the runtime base, and anywhere else it runs with the
agent's own access, so it gains nothing.

## Protecting the anchors

Three locations decide what the daemon trusts and how clients reach it:

| Anchor | Default |
|---|---|
| trust store | `$XDG_STATE_HOME/airlock/trust` → `~/.local/state/airlock/trust` |
| global config | `$XDG_CONFIG_HOME/airlock/airlock.toml` → `~/.config/airlock/airlock.toml` |
| runtime base | see [Location](#location); not taken from the environment |

The XDG variables are honored. That makes the environment an attack path. The
agent cannot set the environment of the user's shell directly, but it can edit
files that shells load from the repo:

```toml
# mise.toml in the repo. mise trusts by path by default, so this edit applies
# the next time the user cd's in, with no prompt.
[env]
XDG_STATE_HOME = "{{config_root}}/.cache/state"
```

A committed `.envrc` does the same once the user has allowed it with direnv.
The user's next `airlock run` would then read a trust store the agent wrote.
Redirecting `XDG_CONFIG_HOME` is worse: the global layer is not approved at
all.

Each anchor is therefore checked before use, after canonicalization:

1. **Ownership and mode.**
   - Trust store and runtime base: owned by the effective uid, mode 0700,
     not a symlink.
   - Global config file and its directory: owned by the effective uid, not
     group- or world-writable.
2. **Outside the project root.**
3. **Outside every sandbox write grant.** That means `filesystem.write`,
   every tool's `extra_write` and `agent.filesystem.write` from **every
   layer, including unapproved ones**; `airlock run --allow-write`; and
   built-in profile write paths. The one exception is macOS `$TMPDIR` for
   the runtime base, which the Seatbelt deny rule carves out.

The same check runs from the other side at config load: a write grant that
covers an anchor is a config error. So an agent that edits `airlock.toml` to
grant itself write access to `~/.local/state/airlock` gets refused twice:
the edit needs approval, and even once approved the grant is rejected.

With these checks, a redirected XDG variable can only point somewhere the
agent cannot write. Nothing it controls ends up in the trust store or the
global layer.

## `airlock list` through the daemon

`list` stops reading config files. It sends a new `List` request over the
socket, and the daemon answers from the session's merged, approved
config. The output format stays the same.

- The agent sandbox never needs read access to the global config or the
  trust store.
- The list matches what `exec` will accept.
- `list` now requires a running daemon and a [session](#sessions), and
  without either it fails with the usual connection hint. [SKILL.md](../SKILL.md) currently says the
  opposite and changes with this.

## Threat walkthrough

| Attack | Outcome |
|---|---|
| Agent edits `airlock.toml` or `airlock.local.toml` | The next session start refuses with a diff. The user approves or reverts. Running sessions are unaffected. |
| A PR changes `airlock.toml`, and the user pulls it | Same. |
| Agent hides a change with ANSI or bidi tricks | The diff is escaped, so the hidden characters are visible. |
| Agent runs `airlock trust` | Refused by the `AIRLOCK_SANDBOX` check. If the agent unsets the variable, writing the trust store fails because no sandbox has a write grant covering it. |
| Agent writes the trust store directly | Same: no write grant. |
| Agent grants itself write access to an anchor through a config edit | The edit needs approval, and the grant is a config error anyway. |
| Agent redirects `XDG_STATE_HOME` or `XDG_CONFIG_HOME` through repo-level env tooling | The anchor is inside the project or under a write grant, so it is refused. |
| Agent in project A tries to use project B's tools | Its session is bound to A's root and config. Registering a session for B needs `admin.token`, which no sandbox can read. |
| A daemon bug lets session A reach session B's state | The session handle is the only path to secrets, and process-env reads are linted out. If B's secret still reaches A's output, the global redactor masks it. |
| Agent stashes its session token for later | The token stops working when the harness exits or the session is revoked. |
| Agent replaces the socket, PID file or CA certificate | The runtime dir is not writable: Linux never grants it, and macOS denies it explicitly. |
| Agent starts its own daemon, session or `airlock run` | Refused (convenience only). If forced, the daemon cannot create its socket in the runtime base, and a session cannot be registered without `admin.token`. |
| Agent stops the user's daemon or revokes sessions | Refused (convenience only), and `daemon stop` and `session revoke` need `admin.token`. |
| Agent plants code the user later runs outside the sandbox (hook, `.envrc`, build script) | Not prevented; a [non-goal](#non-goals). That code can rewrite the anchors, and it can also read the user's credentials directly. |

## Worked examples

### Three layers and the merged result

`~/.config/airlock/airlock.toml` (global):

```toml
[secrets.GH_TOKEN]
source  = "command"
command = ["op", "read", "op://Private/GitHub/token"]

[tools.aws]
description = "AWS CLI"
[tools.aws.env]
AWS_PROFILE = "personal"

[agent]
passthrough_env = ["COLORTERM"]
```

`~/src/app/airlock.toml` (repo, approved):

```toml
timeout = 120

[secrets.GH_TOKEN]
source = "env"

[tools.gh]
description = "GitHub CLI"
[tools.gh.env]
GH_TOKEN = { secret = "GH_TOKEN" }

[filesystem]
read = ["/opt/homebrew/share"]

[agent]
passthrough_env = ["NO_COLOR"]
[agent.env]
LOG_LEVEL = "info"
```

`~/src/app/airlock.local.toml` (local, approved):

```toml
[secrets.GH_TOKEN]
source  = "command"
command = ["gh", "auth", "token"]

[tools.psql]
description = "Postgres shell"
[tools.psql.env]
PGSERVICE = "app-dev"

[agent.env]
LOG_LEVEL = "debug"
```

Merged:

| Item | Value | From |
|---|---|---|
| `timeout` | `120` | repo |
| `secrets.GH_TOKEN` | command `gh auth token` | local (replaces repo's `env`; global's `op read` would apply only through `from = "global"`) |
| tools | `aws`, `gh`, `psql` | global, repo, local |
| `filesystem.read` | `/opt/homebrew/share` | repo |
| `agent.passthrough_env` | `COLORTERM`, `NO_COLOR` | union |
| `agent.env.LOG_LEVEL` | `debug` | local |

This example also shows why the local layer exists. The global 1Password
binding does not reach the repo's `GH_TOKEN` on its own. The local file binds
it, here with its own `command`; `from = "global"` would have used the
1Password entry instead.

### Duplicate tool

```
$ airlock session start
error: tool "gh" is defined in both ~/.config/airlock/airlock.toml and ~/src/app/airlock.toml;
       a tool may be defined in only one layer
```

### Refusal after an edit

```
$ airlock run --profile claude
error: ~/src/app/airlock.toml has changed since you last trusted it

--- trusted
+++ ~/src/app/airlock.toml
@@ -10,5 +10,6 @@
 GH_TOKEN = { secret = "GH_TOKEN" }

 [filesystem]
 read = ["/opt/homebrew/share"]
+write = ["~/.ssh"]

Review the change, then run `airlock trust`.
```

### Approving

```
$ airlock trust
~/src/app/airlock.toml has changed since you last trusted it:

--- trusted
+++ ~/src/app/airlock.toml
@@ -10,5 +10,6 @@
 ...

Trust this version? [y/N] y
trusted ~/src/app/airlock.toml
note: 1 running session for ~/src/app keeps the previous config; new sessions use this one
```

The first approval of a file shows its full contents:

```
$ airlock trust
~/src/app/airlock.local.toml is not trusted yet. Contents:

[secrets.GH_TOKEN]
source  = "command"
command = ["gh", "auth", "token"]
...

Trust this file? [y/N]
```

### A redirected anchor

```
$ airlock run --profile claude
error: trust store ~/src/app/.cache/state/airlock/trust is inside the project root ~/src/app
       (from XDG_STATE_HOME=~/src/app/.cache/state); refusing to use it
```

### Inside the sandbox

```
$ airlock trust
error: `airlock trust` cannot run inside an Airlock sandbox; run it from your own terminal
```

### A directory with no project config

```
$ cd ~/scratch/experiment
$ airlock run --no-project-config --profile claude
```

This uses `~/scratch/experiment` as the root and the global layer as the
whole config.

## Decisions

| Question | Chosen | Rejected | Why |
|---|---|---|---|
| Why move runtime files | Tamper resistance; keep them out of the repo | Filesystem quirks, sharing across worktrees | The first two are the problems we actually have. |
| Runtime dir location | Per-user temp root, not from the environment (`/run/user/<uid>`, macOS `confstr`) | `XDG_RUNTIME_DIR` / `TMPDIR`; `~/.local/state`; configurable path | Cleared on reboot, per-user, short enough for `sun_path`, and the same in every shell of the user. |
| Daemon topology | One daemon per user; sessions bound to a root and its approved config | One daemon per project; a relay router with per-session worker processes | One listener per host, which a network transport needs, and config changes apply to new sessions without a restart. Isolation between sessions is structural (see [Session isolation](#session-isolation)). |
| Session state | Per session, resolved by the launcher in the user's terminal | Shared per root and config; resolved by the daemon | Secret prompts reach the user, `source = "env"` sees the project's shell, and sessions stay independent. |
| Daemon lifecycle | Automatic start and idle exit by default; optional launchd/systemd service | Only one of them | No setup by default; an always-on service for users who want it and for a future network listener. |
| Proxy placement | In the daemon for now | Per-session process in the first cut | Keeps the first cut small. The proxy parses untrusted input, so moving it out is tracked as F10. |
| Trust model for the repo file | Trusted after review | Untrusted (secrets only from personal config); fully trusted | Approved config can do everything it does today, and a change needs review again. |
| Approval unit | Whole-file bytes | Normalized security-relevant content; per-item approval | Simplest thing to get right, with nothing to normalize or audit. |
| What approved repo config may do | Everything, as today | No secret sources; suggested sources only | Keeps a single-file setup working. The local layer covers personal bindings. |
| Personal config location | Global and per-project local | Global only; local only | Global for bindings shared across projects, local for per-project overrides. |
| Local file location | In the project, approved | Outside the project (`~/.config/airlock/projects/<id>.toml`); in the project with sandbox write denied | Kept next to the repo file where users expect it. Approval handles the agent being able to write it. |
| Precedence | global < repo < local | repo < global < local | Same order as git config. |
| Tool collision | Error | Higher layer replaces it; field merge | A silently shadowed tool is a security surprise. |
| Secret collision | Local replaces a repo label's spec whole; global reaches a repo label only through local `from = "global"` | Highest layer wins; global rebinds repo labels automatically; approve the cross-layer binding map | A repo label must not resolve to a personal secret without an approved opt-in. Rebinding stays one line per label. |
| Everything else | Lists union, maps per key, scalars highest | Whole-section replace; additive only | Predictable, and a personal layer can still override a value. |
| Unapproved file | Refuse, show diff against a stored copy | Refuse with no diff; interactive prompt at start | The user reviews exactly what changed, and startup stays non-interactive. |
| `airlock trust` UX | Diff, then y/N; `--yes` for scripts | Approve silently; no `--yes` | Review happens where the approval happens. |
| Protecting approval | Sandbox cannot write the trust store; `trust` refuses in the sandbox | Terminal confirmation as the control | An agent with a pty can answer a prompt, so only the sandbox is a real control. |
| Global file approval | None, protected by the anchor checks | Approve it like the repo file | It is the user's own file, outside every project. |
| Anchor paths | Honor XDG, then validate | Ignore the environment and use the passwd home | Conventional, and the validation closes the redirect attack. |
| Project without config | Requires `airlock.toml` or `airlock.local.toml`; `--no-project-config` opts out | Global-only by default | Using Airlock in an arbitrary directory is explicit. |
| `--no-config` | Becomes `--no-project-config` (global layer only) | Keep both | An empty config has no real use. |
| `--config <path>` | That file only, still approved | Replaces only the repo layer; skips approval too | An explicit file means exactly that file. Skipping approval would reopen the hole. |
| `list` | Asks the daemon | Reads the files; daemon with file fallback | Shows what is actually served, and keeps config dirs out of the agent sandbox. |
| After approval | New sessions use it; running sessions keep theirs, and `status` marks them | `trust` reloads running sessions | A running agent's tools do not change under it, and a new session costs little. |
| Commands refused in the sandbox | `trust`, `session`, `daemon`, `run` | `trust` only | Clear errors for things an agent has no business doing. |
| Client authentication | Sessions registered with a 0600 `admin.token` no sandbox can read; scoped by the directory they start in; `AIRLOCK_ADDR` is a URI | Uid only; one token per daemon in the agent's environment; per-session tool allowlist | The agent is the same uid. A per-daemon token lives too long and cannot tell agents apart. A subset of one project's tools is rarely needed. |
| Migration | None | A transition release that checks both locations | Pre-1.0. |

## Prior art: `mise trust`

[mise](https://github.com/jdx/mise) gates project config behind
`mise trust` (read at `59d5cdb`, `src/config/config_file/mod.rs`):

- **Trust by path by default.** A symlink in
  `~/.local/state/mise/trusted-configs/` marks a config root as trusted.
  Later edits are trusted automatically.
- **Paranoid mode is trust by content.** It stores a SHA-256 of the whole
  file beside the symlink and checks it on every load. It keeps no copy, so
  it cannot show a diff.
- **Implicit trust in several cases.**
  - `mise run`, `exec`, `install` and `watch` trust their active config
    automatically.
  - CI trusts everything.
  - A linked worktree inherits trust from the main checkout.
  - `MISE_YES` / `--yes` answers the prompt.
  - "Safe" configs (only tool versions and plain tasks) need no trust.
- **The environment can move or bypass trust.** `MISE_STATE_DIR` and
  `XDG_STATE_HOME` move the store. `MISE_TRUSTED_CONFIG_PATHS` trusts whole
  path prefixes.

mise's threat is cloning or `cd`-ing into a hostile repo. Airlock's threat is
a process running as the user that edits files after they were trusted. So
Airlock takes paranoid mode's content binding and adds the stored copy for
diffs. It drops trust by path, implicit trust, the worktree and CI shortcuts,
and exemptions for "safe" files, because each would let an agent's edit take
effect without review. mise's environment overrides show why Airlock
validates the anchor locations instead of trusting the variables.

## Open questions and follow-ups

A review of this proposal against the code found the items below. Items
marked **blocking** must be resolved, in this document, before
implementation starts: either the design as written does not deliver a
stated goal, or it does not work. The follow-ups can land after the first
implementation, or be decided during it.

| # | Item | Status |
|---|---|---|
| B1 | The agent can run code outside the sandbox through project files | resolved: goal narrowed |
| B2 | Approval covers the config, not the code it runs | resolved: filtered `PATH`, binary location check |
| B3 | The repo layer can reference personal secrets | resolved: local opt-in |
| B4 | Any daemon of the user is reachable from any sandbox | resolved: sessions |
| B5 | `exec` inside `airlock run` cannot find the socket on Linux | resolved by B4 |
| B6 | `$TMPDIR` is not a stable per-user base on macOS | resolved: base ignores the environment |
| B7 | The Seatbelt deny must be the last rule, in every profile | resolved |
| B8 | `--config <path>` has no slot in the trust store | resolved: copies keyed by file name |
| F1 | Ownership checks and XDG handling for the anchors | follow-up |
| F2 | The global config under home-manager | follow-up |
| F3 | Review a policy diff, not only a byte diff | follow-up |
| F4 | Precedence for secret sources | resolved by B3 |
| F5 | Tool collisions have no way out | follow-up |
| F6 | Every worktree needs its own first approval | follow-up |
| F7 | Runtime dir lifetime | follow-up |
| F8 | `list` under `airlock run --no-daemon` | follow-up |
| F9 | Deny agent writes to `.git/hooks/` on macOS | follow-up |
| F10 | Run each session's proxy in its own process | follow-up |
| F11 | Network transport | follow-up |
| Q1 | One daemon per user instead of one per project | resolved: one daemon per user |

### Blocking

**B1. The agent can run code outside the sandbox through project files.**
The sandbox root is read-write for the agent, and nothing in it is
protected. The agent can write `.git/hooks/*`, `.git/config`
(`core.fsmonitor` runs on every `git status`), `.envrc`, `mise.toml`
(`[hooks] enter` runs on `cd`), `Makefile` or `package.json` scripts. Each
runs later as the user, unsandboxed. That code can write the trust store
and the global config directly, or put a fake `airlock` first on `PATH` so
the user's next `airlock trust` is the agent's.

The mise example in [Protecting the anchors](#protecting-the-anchors) is one
case of this class. Validating the XDG variables closes that case only.
Until the class is addressed, the goal "the approval record, the global
config and the runtime directory cannot be forged or redirected by the
agent" does not hold.

**Resolved: narrow the goal.** This class predates the proposal. Code the
user runs outside the sandbox can read `~/.config/gh/hosts.yml` or call
`op read` itself, which already defeats secret isolation. The trust store
cannot be held to a higher standard than the secrets it guards. Denying the
known paths would not close the class either: build scripts, tests and
source code run as the user whenever the user builds, ordinary git use
(`git push -u`, `git remote add`) writes `.git/config`, and Landlock cannot
carve paths out of the root grant.

- The goal now reads: no sandbox can write or redirect the anchors. With
  the existing approval goal, this means an unreviewed config change does
  not take effect through Airlock.
- SECURITY.md gains a "does not protect against" entry for agent-written
  code the user runs outside the sandbox. It complements the existing
  "Agent harness escape" entry, which covers the agent itself running
  outside one.
- The XDG anchor validation stays. It is cheap, and it covers the one
  vector that needs no code execution: mise applying a path-trusted `[env]`
  edit on `cd`.
- [F9](#follow-ups) adds a macOS-only deny for `.git/hooks/` as defense in
  depth.

**B2. Approval covers the config, not the code it runs.** Approving the
bytes of `airlock.toml` does not approve the programs they name.

- `source = "command"` runs unsandboxed with the daemon's environment and
  working directory ([src/secrets.rs](../src/secrets.rs)). An approved
  `command = ["./scripts/token.sh"]` runs whatever the agent last wrote to
  that script. So does a bare `op` when direnv or mise has put a project
  directory on the daemon's `PATH`. With `refresh`, it runs again long after
  approval.
- Tool binaries are resolved on the daemon's `PATH` at request time
  (`resolve_binary` in [src/exec.rs](../src/exec.rs)). A planted `gh` in an
  agent-writable `PATH` directory receives `GH_TOKEN`.

Unlike B1, the daemon runs this code itself, with no user action, so it is
in scope.

**Resolved:**

1. **A filtered `PATH`.** At session start the launcher takes its own
   `PATH` and drops relative entries and every entry inside the project root or a
   write grant. Write grants means the same set as the [anchor
   check](#protecting-the-anchors). The filtered `PATH` is used to resolve
   tool binaries and secret commands' `argv[0]`, and is the `PATH` handed to
   tools and secret commands. Without the last part, `gh` could run a
   planted `git` that inherits `GH_TOKEN`. Entries are dropped, not refused:
   a direnv or mise setup with `node_modules/.bin` on `PATH` is common, and
   refusing would break it for no gain. A "binary not found" error lists the
   entries that were dropped.
2. **A location check on the resolved binary.** The resolved tool binary
   and the secret command's resolved `argv[0]` are canonicalized and
   refused if they land inside the root or a write grant. This catches a
   symlink on a safe `PATH` entry that points into the project. An
   `argv[0]` containing `/` goes through the same check, so
   `command = ["./scripts/token.sh"]` is a config error.
3. **Interpreter arguments stay open.** In `["bash", "scripts/token.sh"]`
   the command is approved but the script it reads is not. A scan of the
   arguments would catch that case and miss `--flagfile=./x`, which gives
   false confidence. SECURITY.md's Config safety section documents it
   instead: an argument that names a project file runs whatever is in that
   file at the time.

**B3. The repo layer can reference personal secrets.** [Merge
rules](#merge-rules) lets a tool in any layer reference a secret label from
any layer. A PR can add `[agent.env] X = { secret = "PERSONAL_OPENAI" }` and
the agent receives the raw value, because `build_agent_env` in
[src/run.rs](../src/run.rs) resolves secret references. It can equally add
a networked tool that takes the secret. The reviewer sees a label name, not
that it resolves to the user's password manager.

Restricting the repo to labels it declares is not enough on its own. A PR
can declare `[secrets.OPENAI_API_KEY] source = "env"`, and if personal
layers rebound repo labels automatically, it would get the user's global
binding anyway. The gap is a binding that crosses layers without approval.

**Resolved: personal bindings need a local opt-in.** See [Secret labels
across layers](#secret-labels-across-layers). Repo items reference only repo
labels. A global binding reaches a repo label only through
`from = "global"` in the approved local file. The user approves that
crossing explicitly, once per label per project.

**B4. Any daemon of the user is reachable from any sandbox.** The daemon
authenticates clients by uid alone, and the agent runs as the user.

- macOS: the agent can read all of `$TMPDIR` and has unrestricted outbound
  network. `$TMPDIR/airlock/` lists every project's daemon, and each `root`
  file names its project.
- Linux: Landlock does not mediate `connect` on pathname sockets. The id is
  a hash of a guessable path.

So the agent in project A can drive project B's daemon and run B's tools
with B's secrets. `AIRLOCK_ROOT` makes this easier than the
[`--no-project-config`](#--no-project-config) section says: it skips
discovery, so it reaches projects the agent cannot even read.

**Resolved: [sessions](#sessions).** A token the daemon hands out over the
socket is not enough: the agent is the same uid and could ask for one too.
Registering a session needs `admin.token`, which no Airlock sandbox can
read. A single per-daemon token in the agent's environment was also considered. It would
stay valid for the daemon's lifetime, could not tell two agents apart, and
needed a file fallback for other harnesses that defeated the protection.
Tools never see a session token, since they get a clean environment.

**B5. `exec` inside `airlock run` cannot find the socket on Linux.** The
agent's environment is an allowlist (`build_agent_env` in
[src/run.rs](../src/run.rs)). It carries `TMPDIR` but not
`XDG_RUNTIME_DIR`. Inside the sandbox the client falls back to
`${TMPDIR:-/tmp}/airlock-<uid>`, while the daemon listens under
`/run/user/<uid>`. An `[agent.env]` entry that sets `TMPDIR` breaks it on
macOS too.

**Resolved by B4.** Every session exports `AIRLOCK_ADDR` with the exact
address, and the client does no discovery of its own. A nested `airlock.toml`
under the agent's working directory cannot redirect it either.

**B6. `$TMPDIR` is not a stable per-user base on macOS.** `$TMPDIR` varies
per shell: agent harnesses set it to `/private/tmp`, and Nix shells and tmux
change it. As a result:

- A daemon started in one shell is invisible from another, and `daemon
  start` there starts a second daemon for the same project. Stale-state
  detection does not catch it, because it looks in a different directory.
- With `TMPDIR=/private/tmp` the base is `/private/tmp/airlock`, shared by
  all users. The Linux fallback has a `-<uid>` suffix, the macOS row does
  not. The first user to create it locks the others out.
- A long `$TMPDIR` can push the socket path past the 104-byte `sun_path`
  limit.
- The daemon's `$TMPDIR` and the one the Seatbelt profile was built from can
  differ, so the deny rule can target the wrong directory.

**Resolved: the base ignores the environment on both platforms.** See
[Location](#location). macOS uses `confstr(_CS_DARWIN_USER_TEMP_DIR)`.
Linux has the same problem with `XDG_RUNTIME_DIR`, so it uses
`/run/user/<uid>` directly and falls back to `/tmp/airlock-<uid>`. With
[sessions](#sessions) the agent no longer computes the path, but
launchers in different shells still have to find the same daemon, and the
Seatbelt deny has to target the directory the daemon uses.

**B7. The Seatbelt deny must be the last rule, in every profile.** Verified
with `sandbox-exec`: the last matching rule wins, so a `deny` followed by a
broader `allow` for the same path is re-allowed. The deny cannot sit right
after the `$TMPDIR` allow as [Sandbox access](#sandbox-access) says:
`agent.filesystem.write` or `--allow-write $TMPDIR` is emitted later, and
the anchor exception for macOS `$TMPDIR` permits exactly those grants. The
deny must follow every allow, including the profile rules. Tool profiles
need it too, since a tool's `extra_write` can grant `$TMPDIR` under the same
exception.

**Resolved.** [Sandbox access](#sandbox-access) now puts the denies last, in
every agent and tool profile. A test should build each profile with a
`$TMPDIR` write grant and check that the denies come after it.

**B8. `--config <path>` has no slot in the trust store.** The trust store
keeps one `airlock.toml` and one `airlock.local.toml` per project id, and
the id comes from the project root. `--config ./airlock.staging.toml` in the
project root has the same id as the repo file. Which slot it uses is
unspecified: either the two approvals overwrite each other, or one of them
is checked against the wrong copy.

**Resolved: copies are keyed by file name.** See [Trust store](#trust-store).
`--config ./airlock.staging.toml` is approved as `airlock.staging.toml`, next
to the repo file's copy. Each session carries its own config, so a session
on the staging config can run next to one on the default config.

### Follow-ups

**F1. Ownership checks and XDG handling for the anchors.** The agent runs as
the user, so "owned by the effective uid" proves nothing against it. Only
"outside every write grant" protects an anchor from the agent; the
ownership and mode checks protect against other users. The attacks
that redirect an XDG variable need code running in the user's shell (B1).
Consider the rejected alternative, taking the anchors from the passwd home
directory, which removes the redirect class and the validation that comes
with it.

**F2. The global config under home-manager.** home-manager links
`~/.config/airlock/airlock.toml` into `/nix/store`, which root owns, so the
ownership check refuses it. A root-owned, read-only file is safer than a
user-owned one. Accept root ownership, or check only that no sandbox can
write the file.

**F3. Review a policy diff, not only a byte diff.** A unified diff often
hides which TOML table a changed line belongs to, top-level dotted keys can
set any table, and escaping does not catch confusable characters such as a
Cyrillic letter in a proxy route host. Show the change in the effective
merged policy next to the byte diff. That also marks comment-only edits as
"no effective change", which reduces approval fatigue. Approval stays on
bytes.

**F4. Precedence for secret sources.** Resolved by B3. Global does not
override or rebind repo labels. The local file binds them, with
`from = "global"` as the one-line way to reuse a global binding.

**F5. Tool collisions have no way out.** A personal `gh` in the global file
breaks startup in the first repo that also defines `gh`, and the user
can only remove their own. Decide whether the local layer may explicitly
replace a repo tool, or the global tool yields to the project.

**F6. Every worktree needs its own first approval.** Agent workflows create
worktrees often, and each is a new root and a new id. Consider accepting a
file whose bytes match a copy already approved for the same git common dir.

**F7. Runtime dir lifetime.** systemd-logind deletes `/run/user/<uid>` at
logout, which orphans a daemon started over ssh, and a systemd user service
stops at logout unless lingering is enabled. On macOS, check whether the
periodic temp cleanup removes a long-running daemon's PID file.

**F8. `list` under `airlock run --no-daemon`.** `list` now needs a daemon,
and this mode has none. Decide whether `list` fails there or `run` answers it
another way.

**F9. Deny agent writes to `.git/hooks/` on macOS.** Hooks fire on commit
with no review step, and agents rarely need to write them. Seatbelt can deny
`<root>/.git/hooks` after the root grant, subject to the ordering rule in
B7. This is defense in depth, not a guarantee: Linux cannot express it, and
`core.fsmonitor` in `.git/config` stays open. Worktrees keep hooks in the
common dir, which may lie outside the root.

**F10. Run each session's proxy in its own process.** The proxy parses HTTP
and TLS from sandboxed tools and from upstream servers. In the shared daemon,
a memory-safety bug there reaches every session's secrets. A per-session
proxy process needs only the credentials for its own routes, which makes it
a natural cut. The daemon core is then left with NDJSON over serde as its
only untrusted input.

**F11. Network transport.** [Transport](#transport) keeps it possible. What
it needs:

- TLS on the listener, and tokens bound to the client's TLS identity.
- An answer for where tools run. Today they run on the daemon's host, against
  that host's project root and working directory. Ordinary tools need the
  checkout there, through a shared filesystem with path mapping. Proxy tools
  need only HTTP, so they are the natural first remote case.

### Q1. One daemon per user

**Resolved: one daemon per user.** Sessions (B4) made a per-project daemon
unnecessary for authentication. The single daemon was chosen for the rest:

- One listener per host, which a future network transport needs.
- An approved config applies to new sessions without restarting anything.
- `airlock run` stops embedding a daemon, so several agents can run in one
  project. Today the second one is refused unless a standalone daemon
  happens to be running.

The costs, and how the design answers them:

- **One process holds every project's secrets.** See [Session
  isolation](#session-isolation): the session handle as the only path, no
  process env after startup, a global last-pass redactor, per-session limits,
  and F10 for the proxy. A relay router with per-session worker processes was
  considered. It keeps process isolation, but adds IPC and process
  management. The multi-tenant design keeps that isolation only where
  untrusted parsing happens (F10).
- **The daemon's environment is not the project's.** The launcher resolves
  secrets and sends the environment snapshot and filtered `PATH` with
  `Register`.
- **Loading has to happen in the user's terminal.** It happens at session
  registration, in the launcher, and never on an agent's first `exec`.
- **A crash or upgrade ends every session.** This is accepted. Sessions are
  cheap to start again.

## To verify during implementation

- The agent can connect to `airlock.sock` in a directory it has no file
  grants for: under Seatbelt with the agent's network rules, and under
  Landlock, which does not mediate `connect` on pathname sockets.

## Docs to update when this ships

- **SKILL.md:**
  - `airlock trust`
  - `airlock session`; `exec` and `list` need `AIRLOCK_ADDR` and `AIRLOCK_SESSION`
  - `airlock daemon install/uninstall`; the daemon starts automatically
  - `airlock list` needs the daemon
  - `--no-project-config` replaces `--no-config`
  - `airlock.local.toml` and the global file
  - secret labels across layers, `from = "global"`, optional repo `source`
- **README.md:** quick start without runtime `.gitignore` entries; personal
  config.
- **ARCHITECTURE.md:** one daemon per user and sessions, registration by
  the launcher (config load, approval, secret resolution), session
  isolation, lifecycle modes, runtime dir, config layering and merge,
  `Register` and `List` requests.
- **SECURITY.md:** the trust model, the anchors and their validation, and
  the runtime dir replacing sandbox-root runtime files. Config safety: the
  filtered `PATH`, the binary location check, and interpreter arguments
  that name project files. Sessions replace uid-only socket authentication;
  other harnesses must deny reads of the runtime base. A "does not protect
  against" entry for agent-written code run outside the sandbox.
- **CLAUDE.md:** the trust boundary invariant (session token, not the
  socket alone), the session isolation rules, and the socket invariant's
  file references.
