# Airlock v2 — design proposal

One daemon per user with sessions, a runtime directory outside the
project, layered config, and approval of project config.

**Status:** implemented. The blocking items in [Open questions and
follow-ups](#open-questions-and-follow-ups) are resolved, and this design has
shipped. Current behavior is described in [ARCHITECTURE.md](../ARCHITECTURE.md),
[SECURITY.md](../SECURITY.md), [README.md](../README.md) and
[SKILL.md](../SKILL.md); this document and
[airlock-v2-ux.md](airlock-v2-ux.md) remain the design and surface record of
why it looks the way it does.

This document is the design record: what changes, why, and which
alternatives were rejected. The user-facing surface (commands and their
options, messages, harness hooks, and the examples) is in
[airlock-v2-ux.md](airlock-v2-ux.md). Its changes U1–U16 to this design are
accepted and incorporated here, except U14, which is
[planned for v2.1](#planned-for-v21). When it ships, the user-facing reference
will be [README.md](../README.md) and [SKILL.md](../SKILL.md).

The choice of one daemon per user is re-examined against a future central
daemon in [airlock-v2-topology.md](airlock-v2-topology.md). Its proposals
are not folded in yet. The protocol and data model shapes that keep that
path open while implementing this design are in
[airlock-v2-technical-guidance.md](airlock-v2-technical-guidance.md).

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
- Applying config changes to a running session on their own. A running
  session keeps its config until the user reloads it with
  [`session reload`](#reloading-a-session).
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
  `airlock session start`) loads and approves a project's config, resolves
  its secrets, and registers a session. The agent gets a session token, and
  the daemon serves it only that project.
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
| Agent (`airlock exec`, `airlock tools list`, `airlock agent check` inside `airlock run`) | connect to `airlock.sock`; never read `admin.token` |
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

### Tool filesystem access levels

Separately from the runtime dir, a tool's sandbox also gets a *built-in*
filesystem baseline sized by a new `access` level — `tools.<name>.access`,
falling back to a top-level `access` default, falling back to
`ToolAccess::Default` when neither is set (merge rule: highest layer that
sets it wins, same as `timeout`). It governs only this baseline; the
project root, `[filesystem]`, `extra_read`/`extra_write`, the tool's own
binary, and a proxy tool's CA are granted at every level, unchanged.

- **`none`** — the dynamic linker, the shared library cache, and
  `/dev/null`. The bare minimum to exec and exit.
- **`system`** — `none` plus the fixed baseline every tool got before this
  setting existed (`/usr/lib`, `/usr/bin`, `/etc`, `/dev/{null,zero,random,
  urandom}`, ... on macOS; the Linux equivalent via Landlock).
- **`default`** — `system` plus read-only toolchain roots (`/nix/store`,
  `/opt/homebrew`, `/usr/local`, `/opt/local`, `/home/linuxbrew/.linuxbrew`
  — one shared constant, `TOOLCHAIN_ROOTS` in
  [src/sandbox.rs](../src/sandbox.rs)). **This is the default when `access`
  is unset anywhere** — a deliberate widening over the pre-`access`
  baseline, approved so Nix- and Homebrew-built tools stop failing with
  `dyld`/`ld.so` "blocked by sandbox" without per-tool `extra_read` entries.

The agent's own profile is never governed by `access` — it keeps the
`none` + `system` baseline unconditionally, exactly as before. See
[SECURITY.md](../SECURITY.md#tool-access-levels) for the per-level
tradeoffs and [README.md](../README.md#access-how-much-of-the-system-a-tools-sandbox-sees)
for the config surface.

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

`--config` is not a global option. It exists only on the commands that
discover config: `run`, `trust`, `config`, `status`, `session start` and
`session reload`. `exec` and `tools list` use their session and read no
files, so a `--config` there would be a silent no-op.

### `--no-project-config`

This replaces `airlock run --no-config` and `AIRLOCK_SANDBOX_ROOT`. The
empty-config mode those provided is removed.

- Valid wherever discovery runs: `run`, `config`, `status`,
  `session start` and `session reload`. `exec` and `tools list` do no
  discovery, since they use their session.
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
| `[tools.<name>]` | See [Tools across layers](#tools-across-layers). |
| `[secrets.<label>]` | See [Secret labels across layers](#secret-labels-across-layers). |
| `filesystem.read`, `filesystem.write` | union |
| `agent.passthrough_env` | union |
| `agent.filesystem.read`, `agent.filesystem.write` | union |
| `agent.env.<VAR>` | per key, highest layer wins |
| `timeout`, `agent.timeout` | highest layer that sets it |
| `access` (top-level) | highest layer that sets it; see [Tool filesystem access levels](#tool-filesystem-access-levels) |
| `allow_home_root` | Honored in global or local. In the repo layer it is a config error. |
| `agent.kits` | union across layers (see [Kits](#kits)) |
| `[kits.<name>]` | Honored in global or local, local wins whole by name. In the repo layer it is a config error. Launcher-only — never part of the wire config. |

### Tools across layers

A tool replaces another only where an approved file says so, or where the
user's own global tool gives way to the project.

- **Global and project.** A project tool (repo or local) replaces a global
  tool of the same name. The global layer is the user's default for every
  project, and a project that declares the same tool knows what it needs.
  The replacement is not silent: `airlock config` shows the global tool as
  `replaced by repo`, and `run -v` prints it.
- **Repo and local.** A duplicate is a config error naming both files,
  unless the local tool says `override = true`. Then the local tool
  replaces the repo's whole, and the user approves that line with the local
  file. `override = true` on a tool the repo does not define is a config
  error, so a stale override cannot linger unnoticed.
- **Never the reverse.** The global layer cannot replace a project tool,
  and the repo layer cannot replace a local one. A personal tool must not
  silently shadow a team tool, and the global file is not approved.

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
  lists each such label and points to `airlock init --local`.
- `[secrets.<label>]` takes an optional `description` in every layer. A
  repo label without a source is a request to each user, and the
  description tells them what to supply. The startup error and
  `init --local` show it.

`airlock init --local` writes `airlock.local.toml` with a stub per repo
label that has no source. A label the global layer binds gets
`from = "global"`; any other gets commented `command` and `env` examples
under its description. In a repo without an `airlock.toml`, whose team has
not adopted Airlock, it writes a standalone skeleton instead: a commented
secret and tool, as `init` writes for `airlock.toml`. The stub is an
ordinary local file: the user approves it like any other.

`init --local` warns if git does not ignore the file. The warning suggests
adding `airlock.local.toml` to git's global excludes file
(`~/.config/git/ignore`, or `core.excludesFile`) once, which covers every
repo, including those whose `.gitignore` the user does not own. This only
prevents an accidental commit; it is not a control, and the file holds
references, not secret values.

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
something different in each. `~`, `{sandbox_root}` and `{tool_state}` work
in all layers.

### Tool state outside the project

Many tools need a writable config directory (`GH_CONFIG_DIR`,
`CLOUDSDK_CONFIG`, `KUBECONFIG`). Pointing it at `{sandbox_root}/.config/…`
keeps the user's real config out of the tool sandbox, but puts tool state
in the project, where the agent can read it and git sees it.

`{tool_state}` in a tool's static `env` resolves to
`$XDG_CACHE_HOME/airlock/<id>/<tool>` (default
`~/.cache/airlock/<id>/<tool>`), where `<id>` is the project id from the
[trust store](#trust-store). The daemon creates it with mode 0700 on first
use and adds it to that tool's write paths. No other tool and no agent
sandbox is granted it. Like an anchor, it is refused if it resolves inside
the project root, so a redirected `XDG_CACHE_HOME` cannot move it there. It
must not overlap an anchor either.

```toml
[tools.gh.env]
GH_TOKEN      = { secret = "GH_TOKEN" }
GH_CONFIG_DIR = "{tool_state}"
```

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
    airlock.toml          approved copy of the repo file, mode 0600
    airlock.local.toml    approved copy of the local file, mode 0600
    <name>.toml           approved copy of a --config file named <name>.toml, mode 0600
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

Wherever config is loaded for a session, and that is only in a launcher:
`airlock run`, `session start` and `session reload`. The daemon itself
never reads project config.

- **In the user's terminal.** The launcher checks approval before it
  registers the session, so the prompt or refusal and the diff reach the
  user directly.
- **No gap between check and use.** Each file is read once with
  `read_config_securely`. The same bytes are hashed, compared and parsed,
  and the parsed result is what the launcher registers.
- **Validation first.** The launcher parses and validates the merged
  config before it asks about any file, so the user is never asked to
  approve a file that would fail anyway.

`exec` and `tools list` use a session whose config was approved when it
started or was last reloaded, so they do not check again.

### Unapproved files at session start

If any layer is unapproved, the launcher shows, for each such file, either a
unified diff against the approved copy or, for a file never approved, its
full contents. Then:

- **On a terminal**, it asks `Trust this version and continue? [y/N]`, one
  file at a time. `y` records the approval exactly as `airlock trust` does
  and continues. `n` on any file stops the launcher before anything
  starts, and it exits 125 with `not trusted; nothing started`, as for
  any other reason Airlock did not start the agent.
- **On a non-terminal**, it refuses, exits 125 and points to
  `airlock trust`. Startup stays non-interactive for scripts.

The prompt is exactly as safe as `airlock trust`. The control is that no
sandbox can write the trust store and no sandbox can run a launcher, not
the terminal: an agent with a pty can answer a prompt too. Without the
prompt, refuse, `trust`, run again would be three commands for one
decision, on the most common path: every edit of the user's own local file
goes through it.

The printed text is escaped before output: control characters, ANSI escapes,
bidirectional overrides (U+202A–U+202E, U+2066–U+2069) and zero-width
characters are shown as `\u{…}`. TOML accepts bidi and zero-width characters
in strings and comments. Without escaping, an agent could write a diff that
reads differently from what it does.

A `from = "global"` line approves a link to a binding the prompt does not
otherwise show. So the prompt annotates each such line with the global
source it resolves to at that moment:

```
 [secrets.GH_TOKEN]
 from = "global"       # → global: command op read op://Private/GitHub/token
```

The annotation is display only. It is not part of the approved bytes, so a
later change to the global binding needs no new approval: the global file
is the user's own.

### `airlock trust`

1. Discovers the same layers a session start would. It honors `--config` and
   refuses `--no-project-config`, since there would be nothing to approve.
2. For each repo or local file that differs from its approved copy, prints
   the escaped diff (or the full file) and asks `Trust <path>? [y/N]`.
3. On `y`, writes the exact bytes it showed to the trust store: a temp file
   and `rename` in the same directory.
4. If sessions for this project are running, names them and says that
   they keep the previous config until `airlock session reload`.

On a non-terminal, it refuses unless `--yes` or `--expect-sha256` is
given.

- `--yes` approves every changed file without prompting, for scripted
  setup.
- `--expect-sha256 <hash>` (repeatable) approves a changed file only if
  its SHA-256 equals one of the given hashes, and fails otherwise. This
  pins the exact content a script or workflow expects.

In CI the trust store is usually empty on every run, so each run is a
first approval. `trust --yes` there means the review of the commit under
test is the approval, and it must run before any agent starts in the job,
so an agent's edit in the same job is never approved. `--expect-sha256`
removes even that window.

`trust` exists to approve ahead of time and from scripts. Launchers ask the
same question when they need to.

### After approval

A running session keeps the config it had. The session records the
SHA-256 of every layer it loaded, including the global file. `airlock status`
and `session list` compare those with the files on disk and mark a session
`config changed` when they differ. So does `exec` when it refuses an
undeclared tool, and `agent check`, so the agent can tell the user. Starting
a new session picks up the approved config, and so does reloading a running
one. The daemon does not restart.

### Reloading a session

`airlock session reload [ID…]` applies approved config to running sessions,
so an agent that added a tool can use it without being restarted and losing
its context. Without IDs it reloads every session for the project in the
current directory.

The reload is a launcher: it discovers, validates and approves the config,
prompting as at session start, and resolves the secrets in the user's
terminal. It then sends a `Reload` request with the admin credential. The
daemon builds the new redactor, policy and proxy, and swaps them into the
session in one step. The session keeps its id and token, so the agent keeps
working. It prints what changed per session, such as `tools +psql`.

- **Discovery comes from the session, not the current directory.** Each
  session records its root and mode (default, `--config <path>`,
  `--no-project-config`), and the reload loads exactly that again. IDs
  select sessions; the current directory only picks the default set.
- **The agent's own settings do not change.** The agent's sandbox profile,
  `agent.env`, `agent.passthrough_env`, `agent.filesystem` and
  `agent.timeout` were applied when the agent process started, and a
  running process cannot get a new sandbox. The reload applies everything
  else (tools, secrets, filesystem grants for tools, proxy routes,
  timeouts) and prints `agent settings changed; restart the agent to apply
  them` for a session whose `[agent]` differs.
- **An `exec` in flight finishes on the config it started with.** Each
  request takes its own reference to the session's state, so a swap never
  changes a running tool.

Tools change only when the user asks: the reason running sessions keep
their config holds.

## Sessions

One daemon per user serves every project. A session binds a client to one
project: its root, its approved config and the secrets resolved for it. The
daemon authenticates clients by uid, and the agent runs as the user, so the
socket alone proves nothing ([B4](#blocking)). `exec`, `tools list` and
`agent check` are served only with a session token, and only a process
outside every sandbox can register a session.

### Admin credential

At start, before the readiness signal, the daemon writes 32 random bytes to
`<base>/admin.token` with mode 0600. A restart replaces it. No sandbox can
read it: Landlock never grants the runtime dir, and every Seatbelt profile
denies it (see [Sandbox access](#sandbox-access)). Session registration and
reload, `session list`, `session revoke`, `tools list --session`, `status`,
`daemon logs`, `daemon stop` and `daemon restart` need it. `exec`,
`tools list` without `--session` and `agent check` never read it.

### Registering a session

The launcher (`airlock run` or `session start`) does
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
   merged config, the layer hashes, the secret values, the snapshot, the
   filtered `PATH`, a name, and the agent's sandbox kind. The daemon builds
   the session's redactor, policy and proxy, and answers with a session id
   and a 32-byte random token.

The name is what `session list`, `trust` and `reload` show. `--name` sets
it; the default is the harness command's base name, or `shell` for
`session start`. The sandbox kind is `airlock` for `airlock run` and
`external` for `session start`. It decides what the
[harness hook](#agent-integration) tests.

The daemon also records the session's [anchor process](#token-binding):
the peer PID of the `Register` connection for `run`, and that process's
parent, the user's shell, for `session start`. It takes the PID from the
socket, not from the request.

The launcher holds secret values in `Secret<T>` and drops them once
`Register` succeeds. Refresh commands run later in the daemon, with the
session's snapshot and filtered `PATH`, never the daemon's own environment.

### Commands

| Command | Does |
|---|---|
| `airlock run [-- <harness…>]` | Registers a session, runs the harness in Airlock's agent sandbox with `AIRLOCK_ADDR` and `AIRLOCK_SESSION` set, and holds the session's [lease](#lifetime) until the harness exits. |
| `airlock run --no-session -- <harness…>` | Airlock's sandbox only. No session and no daemon; `exec` and `tools list` fail inside it as they do anywhere without a session. |
| `airlock session start` | Registers a session and prints the `export` lines, for a harness that `run` cannot start: an IDE extension, or a harness with its own sandbox. Ends after `--ttl` (default 12h; `0` means until revoked). |
| `airlock session renew <ID> [--ttl]` | Restarts a `session start` session's TTL. The token stays the same, so the harness keeps working. |
| `airlock session list` | Lists sessions: id, name, root, start time, number of `exec`s, whether the config changed, and what ends it (`held by airlock run, PID 4821` or `expires in 6h`). |
| `airlock session reload [ID…]` | Applies approved config to running sessions. See [Reloading a session](#reloading-a-session). |
| `airlock session revoke <ID…>` / `--here` / `--all` | Ends sessions without restarting the daemon. |

Sessions are addressed by id, unique id prefix or unique name.

`run` always runs the harness in Airlock's sandbox. A harness with its own
sandbox, such as Claude Code with `--sandbox`, gets its session from
`session start` like an IDE. Airlock's and Claude Code's Seatbelt profiles
cannot nest, and a `run` mode without any sandbox would be one flag away
from `claude --dangerously-skip-permissions` running bare. `run` no longer
embeds a daemon of its own, so any number of agents can run in one project
at the same time.

`session start` prints, on stderr, that the harness's own sandbox must meet
the [external sandbox requirements](#under-another-harness) (`-q` drops
the note). Everything started from that shell inherits the token: in an
editor, every extension and integrated terminal. An editor started from
the Dock or a launcher, not from that shell, gets no session.

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
next to the default one. The user notices one cost: a second session runs
the secret commands again, so 1Password or `gcloud` prompts appear again,
and a minted token is minted and refreshed once per session. Sharing
secrets between sessions of one project may come later as an
optimization.

### Lifetime

Sessions live in daemon memory only. A session ends when its owner goes
away, when it is revoked, or when the daemon stops. A token that the agent
stashed, or that a leftover background process still holds, stops working
with it. Its secrets, redactor and proxy are dropped, and its CA file is
deleted.

Any number of processes use a session at once: every `exec` is its own
connection, and the harness, its parallel tool calls and its subagents all
hold the same token. The session is the unit of permission, not of
identity, so the daemon keeps no list of attached clients. It keeps only
what ends the session:

| Started by | Ends when |
|---|---|
| `airlock run` | its lease closes |
| `airlock session start` | its TTL runs out |

**The lease.** `airlock run` keeps the connection it sent `Register` on
open for as long as the harness runs. The daemon holds a task per lease
that waits for EOF and then revokes the session. The kernel closes a
process's descriptors however it dies, by exit, panic, SIGKILL or the OOM
killer, so a launcher cannot die and leave its session behind, and a local
socket needs no heartbeat.

- The descriptor is close-on-exec, so the harness does not inherit it.
  Otherwise the lease would last as long as any descendant of the harness,
  and the agent would hold a connection admitted with `admin.token`.
- The daemon accepts no further request on a lease connection. Reload and
  revoke come over their own connections. A second request on a lease is a
  protocol error and ends the session.
- The launcher outlives the harness. It forwards SIGHUP, SIGINT and SIGTERM
  to the harness, waits for it to exit, and only then closes. A closed
  terminal sends SIGHUP to both, so the order holds.
- Lease connections have no idle timeout.
- The launcher sees EOF when the daemon stops, and prints that the
  agent's session has ended in the user's terminal.

A harness that outlives a SIGKILLed launcher loses its session. That is
rare, and the harness is then an orphan nobody manages.

**The TTL.** A `session start` launcher exits once it has printed the
exports, so nothing holds a lease. The TTL is what ends a forgotten
session; without it, the token would stay valid, and the automatic daemon
would keep running, indefinitely. The default of 12 hours is one working
day. `session renew` restarts it without changing the token, so an editor
started from that shell keeps working. An `exec` on an expired session
exits 125 with a message saying it expired and that the user can renew it
with `airlock session renew`.

### Token binding

A session token is in the environment of every process the harness starts.
A process of the same uid outside Airlock's sandbox can read another
process's environment: through `KERN_PROCARGS2` (`ps eww`) on macOS, and
`/proc/<pid>/environ` on Linux. So an agent under an external sandbox that
allows process inspection, or any unsandboxed process of the user, can
copy another agent's token. Airlock's agent profile allows `process-info*`
only for `same-sandbox`, so its own agents cannot read each other's.

The daemon therefore binds each token to a process tree. On every
connection that presents a token, it takes the peer PID from the socket
(`LOCAL_PEERPID` on macOS, `SO_PEERCRED` on Linux) and walks the parent
chain (`proc_pidinfo` on macOS, `/proc/<pid>/stat` on Linux). The request
is served only if the session's anchor process is an ancestor. The anchor
is recorded with its start time, so a reused PID does not match.

- For `run`, the anchor is the launcher, which lives exactly as long as the
  lease.
- For `session start`, the anchor is the shell that ran it. Everything
  started from that shell matches.
- A process that detaches from the tree (a double fork, `setsid` with a
  reparent to init or launchd) loses access. An agent's tool calls do not
  do that.
- The binding is a check on the Unix transport only, like peer uid. A
  network transport needs tokens bound to the client's TLS identity
  instead ([F11](#follow-ups)).

A stolen token is then useless outside the tree it was issued to. The
binding does not help against a process inside the tree, which already
holds the token legitimately.

### Lifecycle

Two modes, with the same daemon:

- **Automatic (default).** The first launcher that finds no daemon starts
  one, with the existing double fork and readiness pipe, before the
  launcher creates any tokio runtime. An automatically started daemon
  exits after a short grace period with no sessions.
- **Service.** `airlock daemon install` writes a launchd agent or a systemd
  user unit that runs `airlock daemon start --foreground`. A service
  daemon stays up with no sessions. `airlock daemon uninstall` removes it.

The daemon's own environment does not matter in either mode, because
everything a session needs comes with `Register`. `daemon start`
(`--foreground` for service managers and debugging), `daemon stop`,
`daemon restart` and `daemon logs` stay for manual control. `stop` and
`restart` end every session, so on a terminal they name the sessions and
ask first; on a non-terminal they refuse while sessions exist unless
`--yes` is given. `airlock status` reports whether the daemon runs, so
there is no `daemon status`.

**Versions.** An automatic daemon outlives the binary that started it, so
every connection starts with a version handshake. A launcher that finds an
idle daemon of another version restarts it. A busy one keeps serving its
sessions, with a note to the user, and is replaced once idle, unless the
protocol is incompatible. Then the launcher refuses and points to
`airlock daemon restart`.

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
- **A per-session cap on concurrent `exec`s**, so one agent cannot starve
  the others. A panic unwinds and ends only its task.

The proxy is the largest attack surface in the process: hyper and rustls
parse input from sandboxed tools and from upstream servers. A memory-safety
bug there would now reach every project's secrets, where today it reaches
one. Moving each session's proxy to its own process is [F10](#follow-ups).

### Clients

`exec`, `tools list` and `agent check` take the address and token from
`AIRLOCK_ADDR` and `AIRLOCK_SESSION` and nothing else. They do not fall
back to `admin.token` or to discovery. A user who wants to run `exec` by
hand starts a shell with `airlock run -- $SHELL` (sandboxed), or runs
`eval "$(airlock session start)"` in an unsandboxed one. Every `exec` is
logged with its session id.

`tools list --session <ID>` is the one exception: run from the user's
terminal, it reads `admin.token` to show what another session serves.

**Exit status.** `exec` exits with the tool's status, and with 125, 126 or
127 when Airlock itself fails, as `docker run`, `env` and `chroot` do. Exit
1 is the most common tool failure, so it cannot also mean "Airlock failed".

| Exit | Meaning |
|---|---|
| 125 | Airlock could not run the tool: no session, session ended, daemon unreachable, stale secret, working directory outside the root |
| 126 | The tool is declared, but its binary cannot be used: not on the session's `PATH`, or inside the root or a write grant. The message names the `PATH` entries that were dropped and why, and suggests installing the tool outside the project (Homebrew, mise, Nix). There is no override: approving the config does not approve a binary the agent can rewrite ([B2](#blocking)). |
| 127 | No tool by that name in this session |

`run` exits with the agent's status, or 125 when Airlock cannot start it.
Airlock's own messages start with `airlock:` on stderr, which tells them
apart from a tool that exits 125–127 itself.

### Transport

`AIRLOCK_ADDR` is a URI. This proposal implements `unix://<path>` only. The
design keeps a TCP transport open:

- **Authorization starts from the session token, not the uid.** Peer uid,
  the socket's mode 0700 and the [token binding](#token-binding) to a
  process tree are extra checks that only the Unix transport can make.
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

A harness started from a `session start` shell runs in its own sandbox, or
in none. Airlock's protections for the agent then depend on that sandbox,
which must:

| Must | Why |
|---|---|
| Deny reads of the runtime base | `admin.token` is protected from Airlock's own sandboxes only. A harness that lets the agent read it lets the agent register sessions for any project. The token reaches the agent through its environment, so denying the whole base breaks nothing. |
| Deny writes to the runtime base, the trust store and the global config | The agent must not replace the socket or CA, approve its own config, or edit the unapproved global layer. |
| Deny reads of the user's credential stores (`~/.config/gh`, `~/.config/gcloud`, `~/.aws`, `~/.kube`, the keychain) | Otherwise the agent reads the credentials Airlock brokers, directly. |
| Deny inspecting other processes | Otherwise the agent can read other processes' environments. [Token binding](#token-binding) makes a copied session token useless, but other secrets in other environments are not covered. |

The harness also inherits the whole environment of the shell it started
from, unlike under `run`, which passes an allowlist. Start it from a shell
without secrets in its environment, not from inside `op run`.

SECURITY.md carries this list, with a Claude Code sandbox configuration
that meets it. `airlock config --paths` prints the exact paths on this
machine. `session start` points to the list each time (`-q` drops it), and
[`agent check`](#agent-integration) tests it from the agent's shell.

### Commands refused inside the sandbox

`run`, `trust`, `status`, `session` and `daemon` refuse when
`AIRLOCK_SANDBOX=1`, with an error that says they need the user's terminal.
For `status`, the error points to `agent check`, which shows the agent its
own session. The agent can unset the variable, so this is a convenience
only. What actually stops the agent is that it cannot write the trust store
(see below) or read `admin.token`. A daemon the agent starts itself cannot
create its socket in the runtime base, and anywhere else it runs with the
agent's own access, so it gains nothing.

With `AIRLOCK_SANDBOX=1`, `airlock --help` lists only the commands that
work there. The help says so and names the hidden
commands, so a user in a sandboxed shell sees why one is missing. A hidden
command's own `--help` still works and starts by saying it needs the
user's terminal. In a `session start` shell the variable is not set, and
help is complete.

`init` and `config` work inside the sandbox. `init` writes a project file
that still needs approval, so an agent can draft a config for the user to
review. `init --global` is refused there like `trust`, and hidden from
help: the global file needs no approval, so nothing would review what the
agent wrote. The sandbox cannot write it anyway, but the refusal says why.
`config` shows the global layer as unreadable when the sandbox cannot read
it.

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

## Inspecting config and sessions

Three layers and several sessions raise two different questions: what do
the files say, and what does a running agent get. Each has its own command,
and the agent's view of its own session is a third.

| Command | Answers | Reads |
|---|---|---|
| `airlock config` | What the next session start would load: the merged config from the current files, the layer each secret, tool and setting comes from, and each file's approval state. Items from a file that is not approved are marked `(unapproved)`; a global tool a project tool replaces is marked `replaced by repo`. `--paths` prints the layer, trust store, runtime and tool state paths. | The files. No daemon or session. Secret values never appear. Inside the sandbox, a global layer it cannot read shows as `not readable from this sandbox`. |
| `airlock tools list` | What a session serves. Inside a session, its own tools; from the user's terminal, `--session <ID>` names one. | The daemon, through a `List` request. |
| `airlock status` | The daemon (running, PID, version, how it started), this project's layers and approval state, and the sessions here and in total. Exits 0 when the daemon runs, 3 when it does not. | Both, with `admin.token`. User's terminal only. |

`tools list` replaces `list`, which stops reading config files. The daemon
answers from the session's merged, approved config, in today's output
format.

- The agent sandbox never needs read access to the global config or the
  trust store.
- The list matches what `exec` will accept.
- `tools list` needs a running daemon and a [session](#sessions), and
  without either it fails with the usual message. [SKILL.md](../SKILL.md)
  currently says the opposite and changes with this.
- Under `run --no-session` there is no session, so it fails there with the
  same message as anywhere else.

The commands are grouped by who runs them. The user's commands sit at the
top level. What the agent and its harness run sits under `airlock agent`.
`exec` and `tools list` serve both.

## Agent integration

Whether the agent uses `airlock exec` should not depend on it reading
SKILL.md. An agent that never loads the skill, or loses it in a
compaction, runs `gh` directly, gets "not logged in", and works around it.
Two commands put the facts in the agent's context through its harness:

- **`airlock agent check`** verifies the session and self-tests the
  sandbox of the process that runs it. Each probe is a single `open` that
  is expected to fail; nothing is read.

  | Check | Passes when |
  |---|---|
  | Session | `AIRLOCK_SESSION` is set and the daemon accepts it |
  | Daemon | it answers on `AIRLOCK_ADDR`, at a compatible version |
  | `admin.token` | opening it for reading fails |
  | Runtime dir, trust store, global config dir | creating a file in each fails |
  | Environment | no variable named as a secret in any tool's `env` is set; the daemon supplies the names through `List`, never the values |
  | Credential stores | opening each tool's `extra_read` paths and the well-known stores (`~/.config/gh`, `~/.config/gcloud`, `~/.aws`, `~/.kube`) for reading fails; a warning, not a failure, since `claude-relaxed` opens some on purpose. A path that does not exist is skipped. |
  | Config | the project files' hashes match the session's; reported, not a failure |

  The client computes none of the paths. The launcher records the runtime
  base, the trust store and the global config path it validated in the
  session at `Register`, and the daemon returns them with the session
  check, so the probes test exactly the paths the launcher used. An agent
  environment that lacks the XDG variables cannot send the probes to the
  wrong place. The probes assume the client runs on the daemon's host; a
  network transport ([F11](#follow-ups)) skips them. Exit 0 if every check
  passes, 1 if one fails, 125 without a session.
- **`airlock agent hook <harness>`** adapts `check` and `tools list` to
  one harness's hook protocol. It reads the hook event from stdin, always
  exits 0, and prints nothing in a project without Airlock config, so it
  can sit in a user-wide harness config. `claude-code` answers Claude
  Code's SessionStart event, which fires on start, resume, `/clear` and
  compaction. `text` prints the same context as plain text for any harness
  that shows a start command's output to the agent.
  `--print-settings` prints the hook configuration, so docs and binary
  cannot drift. `run --profile claude` passes it to Claude Code with
  `--settings`.

A pass catches a misconfigured sandbox. It proves nothing against a
hostile agent, which could fake the output, and the guarantees still come
from the sandbox. Under `airlock run` the harness and its hooks run inside
Airlock's sandbox, so the hook's self-test tests the agent's sandbox. For an
`external` session a hook may run outside the harness's sandbox, so the
hook skips the probes, lists the tools, and asks the agent to run
`agent check` once with its own, sandboxed, shell tool.

The agent can remove a hook from a project's `.claude/settings.json`. That
is acceptable: the hook is guidance, and no security property depends on
it.

A PreToolUse hook that denies a direct `gh` and suggests the `airlock exec`
form is left out. It costs a daemon round trip per shell command and needs
a command parser that is never complete.

## Kits

`airlock run`'s agent gets a fixed baseline, plus whatever the harness
profile (`--profile claude`/`claude-relaxed`) adds. **Kits** are a separate,
composable layer on top: what a *kind of work* needs — a language
toolchain and its package caches — independent of the harness. Kits apply
only to `airlock run`'s agent sandbox and env. They never reach a tool
sandbox, and never apply to `session start` (an external harness owns that
sandbox).

```toml
[agent]
kits = ["rust", "node"]     # any layer; union across layers

[kits.rust]                 # options for a built-in kit; global or local layer only
mode = "isolated"           # the default; or "shared"

[kits.bazel]                # a user-defined kit; global or local layer only
read  = ["~/.bazelrc"]
write = ["~/.cache/bazel"]
env   = { BAZEL_OUTPUT_USER_ROOT = "{kit_state}/out" }
```

Built-in kits: `rust`, `node`, `python`, `go`, `elixir`. Their `[kits.<name>]`
table accepts only `mode`. A user-defined kit's table accepts `read`,
`write` and `env` instead (no `mode` — it has no isolated/shared concept of
its own). `[kits.*]` sits in the same restricted slot as `allow_home_root`:
global or local only, a config error in the repo layer — a teammate's
checked-in `airlock.toml` must not decide what the agent may write in your
home. `agent.kits` itself has no such restriction and unions across every
layer, the same as `agent.passthrough_env`.

**`[kits.*]` is a launcher-only concept and never reaches the wire config
the daemon runs against** — `layers::merge` validates and resolves it, but
`MergedConfig::to_wire()` always clears it. `agent.kits` (just the list of
names) does ride along on `RawAgentConfig`, harmlessly unused by the
daemon, so that it — and the resolved `[kits.*]` option tables alongside it
— contribute to the agent hash `session reload` uses to decide whether to
print "restart the agent to apply them".

### Modes

- **isolated** (the default). Airlock creates a per-project directory,
  `{kit_state}` = `<tool_state_base>/kits/<project-id>/<kit>` — a sibling
  tree of [`{tool_state}`](#tool-state-outside-the-project)
  (`<tool_state_base>/<project-id>/<tool>`; a project id is 16 hex
  characters, so it can never collide with the literal `kits`) — and points
  the toolchain's own cache/home env vars at it. The agent gets read-write
  access to that directory only; it never writes the user's real caches.
  Created with mode 0700 the way a tool's `{tool_state}` dir is, and
  validated the same way (refused if it resolves inside the project root or
  overlaps an anchor).
- **shared**. No env override; the agent gets write access to the real
  cache locations instead. Each location is resolved from the launcher's
  environment snapshot when the user has already set the tool's own
  variable (`CARGO_HOME`, `npm_config_cache`, `GOPATH`, ...), otherwise the
  platform default. Missing cache dirs are created (mode 0700) — Landlock
  can only grant a path that exists.

Kit env (isolated built-ins and user-defined kits; a shared built-in sets
none) is applied after the environment snapshot and the passthrough env,
so a `CARGO_HOME` the user passes through cannot defeat isolation.

### Built-in kit definitions

A kit never grants write to binaries or config files — writing to
`~/.cargo/bin`, `~/.cargo/config.toml` or `~/.npmrc` would hand the agent
a way to run code the user later runs unsandboxed. In shared mode a kit
does grant *read* of the toolchain's user config and registry credentials,
so the user's settings, private registries and publishing work for the
agent; package-registry tokens are accepted as readable by the agent.
Isolated mode grants none of these.

| Kit | Reads | Isolated env | Shared writes |
|---|---|---|---|
| `rust` | `~/.rustup`, `~/.cargo/bin`; shared mode also `CARGO_HOME/config.toml` and `credentials.toml` (and the legacy extensionless names) | `CARGO_HOME` | `~/.cargo/registry`, `~/.cargo/git`, plus `.package-cache`/`.package-cache-mutate`/`.global-cache`/`.global-cache-journal` as individual files under `CARGO_HOME` |
| `node` | `~/.nvm`, `~/.volta`, fnm's dir, `~/.bun/bin`; shared mode also the user npmrc (`~/.npmrc` or `NPM_CONFIG_USERCONFIG`) and `~/.yarnrc.yml` | `npm_config_cache`, `YARN_CACHE_FOLDER`, `npm_config_store_dir`, `BUN_INSTALL_CACHE_DIR`, `COREPACK_HOME` | the real dirs for each |
| `python` | `~/.pyenv`, `~/.local/share/uv/python`; shared mode also `pip.conf` (`PIP_CONFIG_FILE`, the platform location, legacy `~/.pip`), `~/.config/uv/uv.toml` and `~/.pypirc` | `PIP_CACHE_DIR`, `UV_CACHE_DIR`, `POETRY_CACHE_DIR` | the platform cache defaults |
| `go` | `~/go/bin`, `~/sdk` | `GOMODCACHE`, `GOCACHE`, and `GOPATH` (not just the two caches — `go install`'s output and the sumdb cache live under `GOPATH` with no env var of their own) | `$GOPATH/pkg/{mod,sumdb}`, `GOCACHE`'s platform default |
| `elixir` | `~/.asdf`, `~/.kiex` | `MIX_HOME`, `HEX_HOME`, `REBAR_CACHE_DIR` (plus `MIX_ARCHIVES` pointed read-only at the real `~/.mix/archives`, and `~/.mix/elixir` read-only for the already-installed rebar3 escript, so the agent does not need to `mix local.hex`/`local.rebar` again) | reads real `~/.mix` (never writes it — archives and escripts are code and binaries, like `~/.cargo/bin`); writes `~/.hex/packages` and the rebar3 cache only; reads `~/.hex/hex.config` (repo settings and the Hex API key) but never writes it. |

Missing read paths are skipped; isolated-mode subdirectories are created up
front. See [`src/kits.rs`](../src/kits.rs) for the exact expansion
(`expand_all`, a pure function of home, the env snapshot, the platform, the
project id and `tool_state_base` — unit-tested for every kit, both modes,
both platforms).

### Config errors

Each with a clear message, checked in `crate::layers::merge` (placement
and table shape) or `crate::kits` (everything that needs the active kit
list — called from `crate::launcher::prepare`, and from `airlock config`'s
own display, which expands kits exactly like `airlock run` does):

- `[kits.*]` in the repo layer.
- `read`/`write`/`env` on a built-in kit; `mode` on a user-defined kit; an
  unrecognized `mode` value.
- `{tool_state}` anywhere in a kit's `read`, `write` or `env` — the agent
  must never see tool state.
- An unknown name in `agent.kits` (lists every known kit: the built-ins
  plus any `[kits.<name>]` table).
- An `[agent.env]` key a listed kit's env also sets ("set by kit rust; drop
  one of them").

### Integration points

- `crate::launcher::prepare` validates, resolves the active kit list
  (`agent.kits` plus `airlock run --kit <name>`, repeatable and additive),
  and expands it. A kit's write dirs/files are folded into `write_grants`
  before `anchors::validate` and `exec::filter_path` run, so the existing
  anchor checks and the [B2](#blocking) binary-location check already cover
  them — no separate check was needed. Kit dirs are created after trust,
  like `{tool_state}` dirs.
- `crate::run` adds the kit's read paths (filtered by existence, like
  `detect_toolchain_paths`) and read-write paths to the `AgentPolicy`, and
  applies kit env on top of the already-built agent env. `airlock run -v`
  names the active kits and their modes.
- `airlock config` shows the active kits with layer provenance, mode, and
  the same expanded paths/env `airlock run` would use.
- `session start` calls the same `prepare`, computing kit expansion for no
  reason it uses — simpler than branching, and harmless, since an external
  harness's own sandbox is what actually runs.

## Threat walkthrough

| Attack | Outcome |
|---|---|
| Agent edits `airlock.toml` or `airlock.local.toml` | The next session start or reload shows the diff in the user's terminal and asks, or refuses on a non-terminal. The user approves or reverts. Running sessions are unaffected until reloaded. |
| A PR changes `airlock.toml`, and the user pulls it | Same. |
| Agent hides a change with ANSI or bidi tricks | The diff is escaped, so the hidden characters are visible. |
| Agent runs `airlock trust` | Refused by the `AIRLOCK_SANDBOX` check. If the agent unsets the variable, writing the trust store fails because no sandbox has a write grant covering it. |
| Agent writes the trust store directly | Same: no write grant. |
| Agent grants itself write access to an anchor through a config edit | The edit needs approval, and the grant is a config error anyway. |
| Agent redirects `XDG_STATE_HOME` or `XDG_CONFIG_HOME` through repo-level env tooling | The anchor is inside the project or under a write grant, so it is refused. |
| Agent in project A tries to use project B's tools | Its session is bound to A's root and config. Registering a session for B needs `admin.token`, which no sandbox can read. |
| A daemon bug lets session A reach session B's state | The session handle is the only path to secrets, and process-env reads are linted out. If B's secret still reaches A's output, the global redactor masks it. |
| Agent stashes its session token for later | The token stops working when the harness exits, the session's TTL runs out, or the session is revoked. |
| A process outside the agent's tree copies its token (an agent under a lax external sandbox reads another's environment) | Not served: the [token binding](#token-binding) requires the caller to descend from the session's anchor process. Unix transport only. |
| The launcher is killed | The lease connection closes and the daemon revokes the session. |
| Agent replaces the socket, PID file or CA certificate | The runtime dir is not writable: Linux never grants it, and macOS denies it explicitly. |
| Agent starts its own daemon, session or `airlock run` | Refused (convenience only). If forced, the daemon cannot create its socket in the runtime base, and a session cannot be registered without `admin.token`. |
| Agent stops the user's daemon, or revokes or reloads sessions | Refused (convenience only), and `daemon stop`, `session revoke` and `session reload` need `admin.token`. |
| Agent removes the harness hook | Allowed. The hook is guidance; nothing depends on it for security. |
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

A global `gh` gives way to the repo's, and `airlock config` says so:

```
tools
  gh    repo    GitHub CLI       (replaces global)
```

A local `gh` next to the repo's is an error until the local file says it
means it:

```
$ airlock run --profile claude
error: tool "gh" is defined in both ~/src/app/airlock.toml and ~/src/app/airlock.local.toml;
       add `override = true` to the tool in airlock.local.toml to replace the repo's
```

### A changed file at session start

```
$ airlock run --profile claude
~/src/app/airlock.toml has changed since you last trusted it:

--- trusted
+++ ~/src/app/airlock.toml
@@ -10,5 +10,6 @@
 GH_TOKEN = { secret = "GH_TOKEN" }

 [filesystem]
 read = ["/opt/homebrew/share"]
+write = ["~/.ssh"]

Trust this version and continue? [y/N] n
not trusted; nothing started
```

On a non-terminal the launcher prints the same diff, then
`run \`airlock trust\` in a terminal to approve it`, and exits 125.

### Approving ahead of time, and reloading

```
$ airlock trust
~/src/app/airlock.toml has changed since you last trusted it:

--- trusted
+++ ~/src/app/airlock.toml
@@ -14,3 +14,8 @@
 ...

Trust this version? [y/N] y
trusted ~/src/app/airlock.toml
2 sessions for ~/src/app use the previous config: 7f3a9c "claude", b20e51 "codex"
run `airlock session reload` to apply it to them

$ airlock session reload
reloaded 7f3a9c "claude": tools +psql
reloaded b20e51 "codex": tools +psql
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
| Daemon topology | One daemon per user; sessions bound to a root and its approved config | One daemon per project; a relay router with per-session worker processes | One listener per host, which a network transport needs, and config changes apply to new sessions without a restart. Isolation between sessions is structural (see [Session isolation](#session-isolation)). Compared against a central daemon in [airlock-v2-topology.md](airlock-v2-topology.md). |
| Session state | Per session, resolved by the launcher in the user's terminal | Shared per root and config; resolved by the daemon | Secret prompts reach the user, `source = "env"` sees the project's shell, and sessions stay independent. |
| Daemon lifecycle | Automatic start and idle exit by default; optional launchd/systemd service | Only one of them | No setup by default; an always-on service for users who want it and for a future network listener. |
| Proxy placement | In the daemon for now | Per-session process in the first cut | Keeps the first cut small. The proxy parses untrusted input, so moving it out is tracked as F10. |
| Trust model for the repo file | Trusted after review | Untrusted (secrets only from personal config); fully trusted | Approved config can do everything it does today, and a change needs review again. |
| Approval unit | Whole-file bytes | Normalized security-relevant content; per-item approval | Simplest thing to get right, with nothing to normalize or audit. |
| What approved repo config may do | Everything, as today | No secret sources; suggested sources only | Keeps a single-file setup working. The local layer covers personal bindings. |
| Personal config location | Global and per-project local | Global only; local only | Global for bindings shared across projects, local for per-project overrides. |
| Local file location | In the project, approved | Outside the project (`~/.config/airlock/projects/<id>.toml`); in the project with sandbox write denied | Kept next to the repo file where users expect it. Approval handles the agent being able to write it. |
| Precedence | global < repo < local | repo < global < local | Same order as git config. |
| Tool collision | A project tool replaces a global one, shown in `config`; repo against local is an error unless the local tool says `override = true` | Always an error; highest layer wins; field merge | A silently shadowed team tool is a security surprise, but an error with no way out breaks every repo that declares the user's global `gh`. Each replacement is either the user's own default giving way, or an approved line. |
| Secret collision | Local replaces a repo label's spec whole; global reaches a repo label only through local `from = "global"` | Highest layer wins; global rebinds repo labels automatically; approve the cross-layer binding map | A repo label must not resolve to a personal secret without an approved opt-in. Rebinding stays one line per label. |
| Everything else | Lists union, maps per key, scalars highest | Whole-section replace; additive only | Predictable, and a personal layer can still override a value. |
| Unapproved file | Show the diff against a stored copy; on a terminal ask and continue, on a non-terminal refuse | Refuse with no diff; always refuse and point to `trust` | The user reviews exactly what changed. Refuse, `trust`, run again is three commands for the most common decision, and the prompt is as safe as `trust`'s. Scripts stay non-interactive. |
| `airlock trust` UX | Diff, then y/N; `--yes` for scripts | Approve silently; no `--yes` | Review happens where the approval happens. |
| Protecting approval | Sandbox cannot write the trust store; `trust` refuses in the sandbox | Terminal confirmation as the control | An agent with a pty can answer a prompt, so only the sandbox is a real control. |
| Global file approval | None, protected by the anchor checks | Approve it like the repo file | It is the user's own file, outside every project. |
| Anchor paths | Honor XDG, then validate | Ignore the environment and use the passwd home | Conventional, and the validation closes the redirect attack. |
| Project without config | Requires `airlock.toml` or `airlock.local.toml`; `--no-project-config` opts out | Global-only by default | Using Airlock in an arbitrary directory is explicit. |
| `--no-config` | Becomes `--no-project-config` (global layer only) | Keep both | An empty config has no real use. |
| `--config <path>` | That file only, still approved | Replaces only the repo layer; skips approval too | An explicit file means exactly that file. Skipping approval would reopen the hole. |
| `tools list` | Asks the daemon | Reads the files; daemon with file fallback | Shows what is actually served, and keeps config dirs out of the agent sandbox. |
| Inspecting the files | `airlock config`, with the layer behind each item | `tools list` only | `tools list` shows what a session serves, not what the files say. Three layers raise "where does this come from?", as `git config --show-origin` answers. |
| Command grouping | User's commands at the top level; the agent's under `airlock agent`; `exec` and `tools list` for both | Everything at the top level | The agent's plumbing does not sit next to the user's commands. |
| After approval | New sessions use it; running sessions keep theirs until the user runs `session reload`, and `status` marks them | `trust` reloads running sessions; no reload at all | A running agent's tools change only when the user asks, and an agent that added a tool does not lose its context to a restart. |
| Commands refused in the sandbox | `run`, `trust`, `status`, `session`, `daemon`; help inside the sandbox hides them and says so | `trust` only; same help everywhere | Clear errors for things an agent has no business doing, and an agent reading the help is not shown commands it cannot use. |
| Wrapping a harness | `airlock run` always sandboxes; a harness with its own sandbox uses `session start` | A separate `session exec`; `run --no-sandbox` | One verb starts an agent, and no flag runs one with no sandbox at all. `session exec` would give `exec` two meanings. |
| Exit status | 125 Airlock failed, 126 binary unusable, 127 no such tool | Exit 1 for every Airlock error | 1 is also the most common tool failure. Same convention as `docker run`, `env` and `chroot`. |
| Session lifetime | `run`: a lease on the `Register` connection; `session start`: `--ttl`, default 12h, with `session renew` | Ends only when `run` sees the harness exit; daemon watches the harness PID; until revoked | The kernel closes a dead launcher's socket, so nothing outlives it, with no platform-specific process watching. A forgotten `session start` would otherwise keep a token valid indefinitely; renew keeps an editor working past a day. |
| Copied tokens | Bound to the anchor process's tree by peer PID | Acknowledge only | An external sandbox that allows process inspection exposes every token in reach. The binding makes a copy useless outside its tree. |
| Tool state | `{tool_state}` under `$XDG_CACHE_HOME/airlock` | `{sandbox_root}/.config/…` | Keeps tool state out of the project, the agent's reach and `git status`. |
| Approving in CI | `trust --yes`, or `--expect-sha256` to pin content | `--yes` only | A pinned hash approves exactly what the workflow expects. |
| Daemon version skew | Handshake; restart an idle daemon, note on a busy one, refuse if incompatible | Not handled | An automatic daemon outlives the binary that started it. |
| Agent learns its tools | SessionStart hook through `airlock agent hook`, installed by `--profile claude` | SKILL.md alone; a PreToolUse hook | The hook delivers the facts on every start and compaction. A PreToolUse hook costs a round trip per command and needs a complete command parser. |
| `--config` scope | Only on commands that discover config | A global option | On `exec` and `tools list` it would be a silent no-op. |
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
| F5 | Tool collisions have no way out | resolved: global yields; local `override = true` |
| F6 | Every worktree needs its own first approval | follow-up |
| F7 | Runtime dir lifetime | follow-up |
| F8 | `list` under `airlock run --no-daemon` | resolved: `--no-session` has no session, so `tools list` fails as anywhere else |
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

**Resolved: both.** See [Tools across layers](#tools-across-layers). A
global tool yields to a project tool, visibly; a local tool replaces a repo
tool only with `override = true`.

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

**Resolved.** `--no-daemon` is renamed `--no-session`. There is no session
under it, so `tools list` fails with the same message as anywhere else
without one.

**F9. Deny agent writes to `.git/hooks/` on macOS.** Hooks fire on commit
with no review step, and agents rarely need to write them. Seatbelt can deny
`<root>/.git/hooks` after the root grant, subject to the ordering rule in
B7. This is defense in depth, not a guarantee: Linux cannot express it, and
`core.fsmonitor` in `.git/config` stays open. Worktrees keep hooks in the
common dir, which may lie outside the root.

**Implemented**, in scope for the first release rather than deferred: see
[macOS — Apple Seatbelt](../SECURITY.md#macos--apple-seatbelt-sbpl) and
["`.git/hooks` write denial (F9)"](../SECURITY.md#git-hooks-write-denial-f9)
in SECURITY.md.

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

[airlock-v2-topology.md](airlock-v2-topology.md) describes the central
daemon this transport serves, and what v2 keeps possible for it.

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
  process env after startup, a global last-pass redactor, a per-session
  cap on concurrent `exec`s, and F10 for the proxy. A relay router with per-session worker processes was
  considered. It keeps process isolation, but adds IPC and process
  management. The multi-tenant design keeps that isolation only where
  untrusted parsing happens (F10).
- **The daemon's environment is not the project's.** The launcher resolves
  secrets and sends the environment snapshot and filtered `PATH` with
  `Register`.
- **Loading has to happen in the user's terminal.** It happens at session
  registration, in the launcher, and never on an agent's first `exec`.
- **A crash or restart ends every session.** This is accepted. Sessions are
  cheap to start again. An upgrade does not force a restart: a busy daemon
  keeps serving until it is idle, unless the protocol changed (see
  [Lifecycle](#lifecycle)).

## Planned for v2.1

Designed, but not part of the first implementation. Each item keeps its
design record and lands in its own PR after v2 ships.

| # | Feature | Design record |
|---|---|---|
| V1 | **Dynamic shell completion.** `airlock completions <bash\|zsh>` prints a script that calls back into `airlock` on each TAB, so `exec -- <TAB>` completes the session's tools and `session revoke <TAB>` completes session ids, and hands off to the tool's own completion after `exec -- <tool>`. | [UX: Shell completion](airlock-v2-ux.md#shell-completion) |

V1 is deferred because it pins clap_complete's `unstable-dynamic` feature,
sends a daemon request on every TAB, and needs hand-written shell
delegation. Nothing in the daemon, the sessions or the trust model depends
on it, so it adds no risk to v2 by waiting.

## To verify during implementation

- The agent can connect to `airlock.sock` in a directory it has no file
  grants for: under Seatbelt with the agent's network rules, and under
  Landlock, which does not mediate `connect` on pathname sockets.
- Seatbelt's `process-info*` with `(target same-sandbox)` means the same
  sandbox instance, not every process with the same profile text. If not,
  two Airlock-sandboxed agents can read each other's environment; the
  [token binding](#token-binding) still holds, but other variables do not.
- Editors started from a `session start` shell descend from it. `code .`
  may hand off to a running instance or start through launchd, which
  breaks the [token binding](#token-binding). If so, document which
  editors work and how to start them.

## Docs to update when this ships

- **SKILL.md:**
  - `airlock tools list` replaces `airlock list` and needs a session
  - `exec`, `tools list` and `agent check` need `AIRLOCK_ADDR` and
    `AIRLOCK_SESSION`; the session section
  - exit codes 125, 126 and 127 and what to do with each
  - `airlock agent check`
  - after editing the config: ask the user to run `airlock trust` and
    `airlock session reload`; never run the user's commands
  - the daemon starts on demand; `airlock daemon install/uninstall`
  - `--no-project-config` replaces `--no-config`
  - `airlock.local.toml` and the global file
  - secret labels across layers, `from = "global"`, optional repo `source`,
    `description`
- **README.md:** how it works with the launcher, quick start without
  `daemon start` or runtime `.gitignore` entries, supplying secrets through
  `airlock run`, team and personal config (`airlock.local.toml`, the global
  file, `from = "global"`, `init --local`), approving config, harness
  hooks, the command reference, troubleshooting. `{tool_state}` in the
  quick start and examples, and the global git excludes line for
  `airlock.local.toml`.
- **ARCHITECTURE.md:** one daemon per user and sessions, registration by
  the launcher (config load, approval, secret resolution), session
  isolation, lifecycle modes and the version handshake, runtime dir,
  config layering and merge, `Register`, `Reload` and `List` requests,
  the session lease and token binding.
- **SECURITY.md:** the trust model, the anchors and their validation, and
  the runtime dir replacing sandbox-root runtime files. Config safety: the
  filtered `PATH`, the binary location check, and interpreter arguments
  that name project files. Sessions replace uid-only socket authentication;
  token binding to the anchor process's tree; the external sandbox
  requirements from [Under another harness](#under-another-harness), with
  a Claude Code sandbox configuration that meets them, and `agent check`
  that tests them. A "does not protect against" entry for agent-written
  code run outside the sandbox.
- **CLAUDE.md:** the trust boundary invariant (session token, not the
  socket alone), the session isolation rules, and the socket invariant's
  file references.

## Implementation notes

Points this doc and [airlock-v2-ux.md](airlock-v2-ux.md) left open, or where
the shipped code settled on something narrower or different from what was
proposed:

- **Test-only overrides are `cfg(debug_assertions)`, not an environment
  check at runtime.** `AIRLOCK_TEST_RUNTIME_DIR` (runtime base) and
  `AIRLOCK_TEST_IDLE_EXIT_SECS` (the automatic daemon's idle-exit grace
  period) only compile into debug builds
  ([src/runtime_dir.rs](../src/runtime_dir.rs),
  [src/daemon.rs](../src/daemon.rs)). A release build has no code path that
  reads either variable, so "ignores the environment" ([Location](#location))
  holds even against a build-time environment that controls what a release
  binary links against.
- **The launcher starts an automatic daemon by re-executing itself**, not by
  forking in-process: `std::env::current_exe()` spawns
  `airlock daemon start --automatic` (a hidden flag) and waits for it to
  exit, reusing the existing double-fork-and-readiness-pipe sequence
  unchanged ([src/launcher.rs](../src/launcher.rs)). This keeps the fork
  sequence to the one path `daemon start` already hardens, instead of a
  second in-process fork with its own pre-tokio-runtime constraints.
- **Unknown keys are an error at the top level too**, not only inside
  `[tools.*]` and `[secrets.*]`. The RawConfig types use
  `#[serde(deny_unknown_fields)]` at every level including the root, so a v1
  top-level flatten catch-all does not exist in v2: a typo'd top-level key
  fails config load instead of being silently dropped.
- **`{tool_state}` is computed and created by the launcher**, not the
  daemon, as `$XDG_CACHE_HOME/airlock/<project-id>/<tool>` with mode 0700,
  before `Register` ([src/launcher.rs](../src/launcher.rs)). The daemon only
  ever receives the already-resolved, already-created path.
- **The exec cap is a concurrency limit, not a lifetime count.** 16 is the
  number of `exec`s a session may have *in flight at once*, enforced with a
  `tokio::sync::Semaphore` per session ([src/session.rs](../src/session.rs));
  a 17th concurrent request is refused with `Busy` (exit 125). A session can
  run far more than 16 execs over its life, serially.
- **Hook dedup relies on Claude Code deduping identical commands**, so
  `--profile claude` injects exactly the same `airlock agent hook
  claude-code` command string as the block `--print-settings` prints,
  rather than a marker variable or a generated id, so a hand-added hook and
  the profile's hook collapse into one.
- **[F9](#git-hooks-write-denial-f9) shipped** as a macOS-only Seatbelt
  deny on `<root>/.git/hooks`, on both the agent and tool profiles, ordered
  after every allow alongside the runtime-base and `admin.token` denies.
- **The [open UX questions](airlock-v2-ux.md#open-ux-questions) resolved
  mostly as proposed.** Session id and token format shipped exactly as
  sketched there (6-hex id, `airlock_<id>_<43 base64url characters>`); the
  idle grace period shipped at the proposed 5 minutes; `airlock trust`
  stayed separate from `session reload`, as the doc's own leaning; `daemon
  install` while a daemon runs took the simpler of the two options (it
  tells the user to run `daemon restart`); long diffs get no pager. The one
  exception is worktree dedup, which is still open as
  [F6](#follow-ups) rather than resolved. (This is a different list from the
  numbered gaps in [airlock-v2-questions.md](airlock-v2-questions.md), which
  this doc's own worked examples and sections already answer inline.)
- **`Session::policy` is `RwLock<Arc<SessionPolicy>>`**
  ([src/session.rs](../src/session.rs)), not the `ArcSwap<SessionPolicy>`
  sketched in
  [airlock-v2-technical-guidance.md](airlock-v2-technical-guidance.md#session-state).
  A `RwLock` needed no extra dependency and reload is rare enough that the
  write-lock contention `ArcSwap` avoids was never a concern worth the
  additional crate.
- **The process-tree anchor for a `session start` session is the *parent*
  of the `session start` process**, not the process itself — because
  `eval "$(airlock session start)"` execs `session start` as a direct child
  of the interactive shell with no extra fork, that parent is ordinarily
  the shell the user ran it in. Piping the command through anything else
  (`airlock session start | cat`, or capturing its output in a script that
  `eval`s it in a different shell) forces bash to fork a pipeline subshell
  to run `session start` in; that subshell becomes the anchor and is gone
  the instant the pipe closes, so every later request fails with
  `OutsideProcessTree` even though the token is otherwise valid. Neither
  doc called this out explicitly; it follows from [Token
  binding](#token-binding) but is easy to trip over, so README.md and
  SECURITY.md now say it directly.
- **[Kits](#kits)' `[kits.*]` option tables never reach the wire config**,
  unlike almost everything else `layers::merge` produces. Only `agent.kits`
  (the plain name list) rides on `RawAgentConfig`, unused by the daemon,
  solely so it — together with the resolved `[kits.*]` tables, hashed
  alongside it in `crate::launcher::prepare` — changes the agent hash
  `session reload` checks. Expansion itself (`crate::kits::expand_all`) is
  a pure function of home, the env snapshot, the platform, the project id
  and `tool_state_base`, called only from `prepare` (for `airlock run`) and
  from `airlock config`'s own display — never from `layers::merge`, which
  by design never reads the environment.
- **Tool `access` levels shipped as proposed in [Tool filesystem access
  levels](#tool-filesystem-access-levels)**, added after the rest of this
  doc: the macOS `none` baseline (dyld plus the shared cache) was
  determined empirically with `sandbox-exec`, not derived from any existing
  Seatbelt documentation — `/usr/lib/dyld` plus
  `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld` (with
  `/System/Library/dyld` as a pre-cryptex fallback) is both necessary and
  sufficient for `/bin/echo hi` to run.
