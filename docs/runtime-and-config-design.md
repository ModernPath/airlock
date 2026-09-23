# Runtime directory and layered config — design proposal

**Status:** proposal. Nothing here is implemented yet. Today's behavior is
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
- The approval record, the global config and the runtime directory cannot
  be forged or redirected by the agent.

## Non-goals

- Backwards compatibility. Airlock is pre-1.0. Old in-project runtime files
  are not migrated; users delete them.
- Hot reload. A config change, approved or not, takes effect when the daemon
  restarts.
- Protecting against an agent that runs outside `airlock run`. Such an agent
  is the user, as far as the OS is concerned.
- Sharing a daemon between worktrees or checkouts of one repo.

## Overview

- **Runtime dir:** `$XDG_RUNTIME_DIR/airlock/<id>/` on Linux,
  `$TMPDIR/airlock/<id>/` on macOS. `<id>` is derived from the canonical
  project root. The directory is owned by the user and has mode 0700.
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

| Platform | Base | Fallback when the variable is unset |
|---|---|---|
| Linux | `$XDG_RUNTIME_DIR/airlock` | `${TMPDIR:-/tmp}/airlock-<uid>` |
| macOS | `$TMPDIR/airlock` | `confstr(_CS_DARWIN_USER_TEMP_DIR)` + `airlock` |

Each project gets `<base>/<id>/`, where `<id>` is the first 16 hex characters
of the SHA-256 of the canonical project root. Inside it:

| File | Purpose |
|---|---|
| `airlock.sock` | client socket |
| `airlock.pid` | PID file |
| `airlock-ca.pem` | proxy CA certificate (when a proxy tool is configured) |
| `root` | the canonical project root, as text |

`root` makes `daemon status` able to say which project a runtime dir belongs
to. It also catches an `<id>` collision: if `root` exists and names a
different project, the daemon refuses to start instead of sharing the
directory.

Both bases are per-user and cleared on reboot, which suits a socket and a PID
file. The paths are short enough for `sun_path`: a canonical macOS
`$TMPDIR` is about 55 bytes, so the socket path comes to about 92 of the 104
allowed bytes.

### Validation

The daemon creates `<base>` and `<base>/<id>` with mode 0700. Before using
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
| Agent (`airlock exec`, `airlock list` inside `airlock run`) | connect to `airlock.sock` |
| Proxy tools | read `airlock-ca.pem`, a new entry in their `read_paths` |
| Ordinary tools | nothing |

No sandbox gets write access to the runtime dir.

- **macOS:** the Seatbelt baseline grants read-write to all of `$TMPDIR`
  ([src/sandbox.rs](../src/sandbox.rs), "$TMPDIR (per-session scratch)").
  The profile therefore adds `(deny file-write* (subpath "<base>"))`
  *after* that allow, so tools keep their scratch space but lose write
  access to Airlock's subtree.
- **Linux:** Landlock is allow-only and cannot carve a subtree out of a
  grant. `$XDG_RUNTIME_DIR` is not granted by default, and the anchor check
  refuses any config or `--allow-write` that would grant it.

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

- Global flag, valid on `run`, `daemon`, `exec`, `list`, `status` and `logs`.
- Ignores `airlock.toml` and `airlock.local.toml` even if present.
- The project root is the canonical working directory. The config is the
  global layer alone, which may be absent (an empty config).
- With no repo or local file, there is nothing to approve.
- `airlock run --no-project-config` exports the root to the agent as
  `AIRLOCK_ROOT`. `exec` and `list` inside the sandbox use it to find the
  daemon, because the agent's working directory may move. An agent that
  changes `AIRLOCK_ROOT` reaches only daemons it could reach anyway by
  changing directory.

### Merge rules

Each layer is parsed on its own, then the layers are merged, then the
existing validation runs on the merged result. For example, "a proxy tool
must not hold a secret" is checked against the merged tools.

| Item | Rule |
|---|---|
| `[tools.<name>]` | Must be defined in exactly one layer. A duplicate is a config error naming both files, so a personal tool cannot silently shadow a team tool, or the reverse. |
| `[secrets.<label>]` | The highest layer that defines the label wins, and its spec replaces the lower ones whole. This is how a user rebinds a source. |
| `filesystem.read`, `filesystem.write` | union |
| `agent.passthrough_env` | union |
| `agent.filesystem.read`, `agent.filesystem.write` | union |
| `agent.env.<VAR>` | per key, highest layer wins |
| `timeout`, `agent.timeout` | highest layer that sets it |
| `allow_home_root` | Honored in global or local. In the repo layer it is a config error. |

A tool in any layer may reference a secret label defined in any layer.

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
```

`<id>` is the same project id as the runtime dir. The stored copy is the
record: the check compares SHA-256 of the current bytes with SHA-256 of the
copy. Keeping the copy instead of just a hash is what makes the refusal able
to show a diff.

A project that moves to a new path gets a new `<id>` and needs approval
again.

### When approval is checked

Wherever the daemon loads config: `daemon start`, `daemon restart`, `daemon run`
(foreground) and `airlock run` with its embedded daemon.

- **Before the fork.** The check runs in `synchronous_startup`, before
  daemonizing, so the refusal and diff print straight to the user's
  terminal.
- **No gap between check and use.** Each file is read once with
  `read_config_securely`. The same bytes are hashed, compared and parsed.

`exec` and `list` talk to a daemon whose config was approved when it started,
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

1. Discovers the same layers `daemon start` would. It honors `--config` and
   refuses `--no-project-config`, since there would be nothing to approve.
2. For each repo or local file that differs from its approved copy, prints
   the escaped diff (or the full file) and asks `Trust <path>? [y/N]`.
3. On `y`, writes the exact bytes it showed to the trust store: a temp file
   and `rename` in the same directory.
4. If a daemon for this project is running, prints a note that it still runs
   the previous config and needs a restart.

On a non-terminal, it refuses unless `--yes` is given. `--yes` approves
without prompting, for scripted setup.

### After approval

The running daemon keeps the config it started with. It records the SHA-256
of every layer it loaded, including the global file. `airlock status` compares
those with the files on disk and reports `config changed since the daemon
started` when they differ.

### Commands refused inside the sandbox

`trust`, `daemon start`, `daemon stop`, `daemon restart` and `run` refuse
when
`AIRLOCK_SANDBOX=1`, with a clear error. The agent can unset the variable, so
this is a convenience only. What actually stops the agent is that it cannot
write the trust store (see below). A daemon the agent starts itself runs
inside the agent's sandbox with the agent's own access, so it gains nothing.

## Protecting the anchors

Three locations decide what the daemon trusts and how clients reach it:

| Anchor | Default |
|---|---|
| trust store | `$XDG_STATE_HOME/airlock/trust` → `~/.local/state/airlock/trust` |
| global config | `$XDG_CONFIG_HOME/airlock/airlock.toml` → `~/.config/airlock/airlock.toml` |
| runtime base | see [Location](#location) |

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
socket, and the daemon answers from the merged, approved config it is
actually serving. The output format stays the same.

- The agent sandbox never needs read access to the global config or the
  trust store.
- The list matches what `exec` will accept.
- `list` now requires a running daemon, and without one it fails with the
  usual connection hint. [SKILL.md](../SKILL.md) currently says the
  opposite and changes with this.

## Threat walkthrough

| Attack | Outcome |
|---|---|
| Agent edits `airlock.toml` or `airlock.local.toml` | Next daemon start refuses with a diff. The user approves or reverts. |
| A PR changes `airlock.toml`, and the user pulls it | Same. |
| Agent hides a change with ANSI or bidi tricks | The diff is escaped, so the hidden characters are visible. |
| Agent runs `airlock trust` | Refused by the `AIRLOCK_SANDBOX` check. If the agent unsets the variable, writing the trust store fails because no sandbox has a write grant covering it. |
| Agent writes the trust store directly | Same: no write grant. |
| Agent grants itself write access to an anchor through a config edit | The edit needs approval, and the grant is a config error anyway. |
| Agent redirects `XDG_STATE_HOME` or `XDG_CONFIG_HOME` through repo-level env tooling | The anchor is inside the project or under a write grant, so it is refused. |
| Agent replaces the socket, PID file or CA certificate | The runtime dir is not writable: Linux never grants it, and macOS denies it explicitly. |
| Agent starts its own daemon or `airlock run` | Refused (convenience only). If forced, it runs inside the agent's sandbox with no more access than the agent has. |
| Agent stops the user's daemon | Refused (convenience only). At worst this denies service. |

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
| `secrets.GH_TOKEN` | command `gh auth token` | local (replaces repo's `env`, which replaced global's `op read`) |
| tools | `aws`, `gh`, `psql` | global, repo, local |
| `filesystem.read` | `/opt/homebrew/share` | repo |
| `agent.passthrough_env` | `COLORTERM`, `NO_COLOR` | union |
| `agent.env.LOG_LEVEL` | `debug` | local |

This example also shows why the local layer exists. With global < repo, the
repo's `source = "env"` overrides the user's global 1Password binding. A user
who wants their own binding in this project puts it in `airlock.local.toml`.

### Duplicate tool

```
$ airlock daemon start
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
note: the daemon for ~/src/app is still running the previous config; restart it to apply this one
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
| Runtime dir location | Per-user temp root (`XDG_RUNTIME_DIR` / `TMPDIR`) | `~/.local/state`; configurable path | Cleared on reboot, per-user, short enough for `sun_path`. |
| Daemon identity | Canonical project root | Git common dir; merged-config hash | Keeps one daemon per checkout, as today. A config hash would make every edit a new daemon. |
| Trust model for the repo file | Trusted after review | Untrusted (secrets only from personal config); fully trusted | Approved config can do everything it does today, and a change needs review again. |
| Approval unit | Whole-file bytes | Normalized security-relevant content; per-item approval | Simplest thing to get right, with nothing to normalize or audit. |
| What approved repo config may do | Everything, as today | No secret sources; suggested sources only | Keeps a single-file setup working. The local layer covers personal bindings. |
| Personal config location | Global and per-project local | Global only; local only | Global for bindings shared across projects, local for per-project overrides. |
| Local file location | In the project, approved | Outside the project (`~/.config/airlock/projects/<id>.toml`); in the project with sandbox write denied | Kept next to the repo file where users expect it. Approval handles the agent being able to write it. |
| Precedence | global < repo < local | repo < global < local | Same order as git config. |
| Tool collision | Error | Higher layer replaces it; field merge | A silently shadowed tool is a security surprise. |
| Secret collision | Higher layer replaces the spec whole | Error; field merge | Rebinding sources is the main reason for layering. |
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
| After approval | Restart needed; `status` shows the config is stale | `trust` reloads the daemon | No reload path exists, and adding one (secrets, redactor, CA) is a project of its own. |
| Commands refused in the sandbox | `trust`, `daemon start/stop/restart`, `run` | `trust` only | Clear errors for things an agent has no business doing. |
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

## To verify during implementation

- A Seatbelt `deny` placed after a broader `allow` for the same operation
  wins (last matching rule), so the `$TMPDIR` carve-out works as written.
- The agent can connect to `airlock.sock` in a directory it has no file
  grants for: under Seatbelt with the agent's network rules, and under
  Landlock, which does not mediate `connect` on pathname sockets.

## Docs to update when this ships

- **SKILL.md:**
  - `airlock trust`
  - `airlock list` needs the daemon
  - `--no-project-config` replaces `--no-config`
  - `airlock.local.toml` and the global file
- **README.md:** quick start without runtime `.gitignore` entries; personal
  config.
- **ARCHITECTURE.md:** runtime dir, config layering and merge, trust check
  in `synchronous_startup`, `List` request.
- **SECURITY.md:** the trust model, the anchors and their validation, and
  the runtime dir replacing sandbox-root runtime files.
- **CLAUDE.md:** the socket invariant's file references.
