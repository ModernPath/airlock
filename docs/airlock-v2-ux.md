# Airlock v2 — user experience

What the user and the agent see when [Airlock v2](airlock-v2-design.md)
ships: the commands and their options, their output and errors, the
harness hooks, and the examples. The README, SKILL.md and SECURITY.md
changes are listed in the design doc's
[Docs to update when this ships](airlock-v2-design.md#docs-to-update-when-this-ships).

**Status:** implemented, companion to [airlock-v2-design.md](airlock-v2-design.md).
The design doc decides the mechanism. This doc decides the surface, and the
surface described here has shipped. Where the surface needed the mechanism
to change, the change is listed in
[Changes to the design](#changes-to-the-design) and marked **(U<n>)** where
it appears. U1–U16 are accepted and incorporated into the design doc,
except U14, which is [planned for v2.1](airlock-v2-design.md#planned-for-v21).

Paths in transcripts use `~`. The macOS runtime dir is shortened to
`$RUNTIME`, which is `/var/folders/…/T/airlock`.

## Principles

- **One verb to start an agent.** `airlock run` is the command a user
  learns first and uses daily. Everything else is setup, inspection or
  repair.
- **The terminal is where decisions happen.** Approval, secret prompts and
  error explanations reach the user in the terminal they typed the command
  in. Nothing the agent does produces a prompt.
- **The agent gets messages it can relay.** Every error `exec` and `tools list`
  print says what happened and what the user has to do, in words the agent
  can pass on verbatim.
- **Quiet when it works.** `airlock run` prints nothing before the agent
  starts unless something needs the user. `-v` shows the steps.
- **No state in the project.** `git status` shows `airlock.toml` and, if
  someone forgot `.gitignore`, `airlock.local.toml`. Nothing else.
- **Agent commands are separate from the user's.** What the agent and its
  harness run sits under `airlock agent`. `exec` and `tools list` serve
  both. Inside the sandbox, help hides what only works in the user's
  terminal, and says that it does.
- **The agent learns its tools from the harness, not only from the skill.**
  A harness hook tells the agent at start which tools it must run through
  Airlock. See [Harness hooks](#harness-hooks).

## Who runs what

| Where | Commands | Needs |
|---|---|---|
| User's terminal | `run`, `init`, `trust`, `config`, `status`, `session …`, `daemon …` | nothing; the daemon starts on demand |
| Both | `exec`, `tools list` | a session; or, for `tools list --session`, the user's terminal |
| The agent | `agent check` | `AIRLOCK_ADDR` and `AIRLOCK_SESSION`, set by the session |
| The harness, as a hook | `agent hook claude-code` | same; prints nothing in a project without Airlock |
| Refused inside the sandbox | `run`, `trust`, `status`, `session`, `daemon`, `init --global` | — |

`init` and `config` are allowed inside the sandbox. `init` writes a
project file that still needs approval, so an agent can draft a config for
the user to review. `init --global` is refused: the global file needs no
approval, so nothing would review it. `config` shows the global layer as
unreadable if the sandbox cannot read it.

## Command surface

```
airlock run [--profile NAME] [-- CMD...]     start an agent with a session, sandboxed
airlock init [--local | --global]            write a starter config
airlock trust [-y]                           review and approve project config
airlock config                               merged config, with the layer each part comes from
airlock status                               daemon, project config and sessions
airlock exec -- TOOL [ARGS...]               run a declared tool through the session
airlock tools list [--session ID]            tools a session serves
airlock agent check                          (agent) verify the session, self-test the sandbox
airlock agent hook claude-code               (harness) SessionStart hook
airlock session start | renew | list | reload | revoke
airlock daemon start [--foreground] | stop | restart | logs | install | uninstall
```

Changes from today:

| Today | v2 |
|---|---|
| `airlock daemon start` before anything works | The daemon starts on demand. `daemon start` is for manual control. |
| `airlock run` embeds a daemon | `run` registers a session with the per-user daemon. Several agents per project work. |
| `airlock run --no-daemon` | `airlock run --no-session` (U2) |
| — | A harness with its own sandbox gets its session from `session start`, like an IDE. `run` always sandboxes. |
| `airlock run --no-config` + `AIRLOCK_SANDBOX_ROOT` | `--no-project-config` |
| `--config` on every command | Only on commands that discover config: `run`, `trust`, `config`, `status`, `session start/reload` (U10) |
| `airlock list` reads `airlock.toml` | `airlock tools list` asks the daemon about the current session, or any session with `--session` (U5). `airlock config` reads the files (U4). |
| `airlock status`: is a daemon up | `status` shows daemon, project layers, approval state and sessions |
| `airlock daemon run` | `airlock daemon start --foreground` (U15) |
| `airlock logs` | `airlock daemon logs` (U15) |
| — | `trust`, `config`, `session`, `daemon install/uninstall`, `agent check`, `agent hook` |
| Help is the same everywhere | Inside the sandbox, help lists only the commands that work there, and names the hidden ones (U16) |
| The agent learns about Airlock from SKILL.md alone | A SessionStart hook puts the session state and tool list in the agent's context (U13) |

## Changes to the design

Each item changed something [airlock-v2-design.md](airlock-v2-design.md)
had decided or left open. All are accepted, and the design doc now
describes them. The table stays as the record of what changed and why.

| # | Change | Design before | Why |
|---|---|---|---|
| U1 | `airlock run` and `session start` show the diff and ask `Trust this version and continue? [y/N]` on a terminal. On a non-terminal they refuse as the design says. | Refuse, print the diff, point to `airlock trust`; "interactive prompt at start" rejected. | Refuse → `trust` → run again is three commands for one decision, and it is the most common path: every edit of the user's own local file goes through it. The prompt is exactly as safe as `airlock trust`'s: the control is that no sandbox can write the trust store, not the terminal. Startup stays non-interactive for scripts. |
| U2 | Fold `session exec` into `airlock run --no-sandbox`. Rename `--no-daemon` to `--no-session`. | `session exec -- <harness>` next to `run`. | `airlock exec` runs a tool; `airlock session exec` would run an agent. Two meanings of `exec` in one CLI. `run` with two switches (sandbox, session) covers all four cases with one verb. Resolves F8: under `--no-session` there is no session, so `tools list` fails with the same message as anywhere else. Later revised: `--no-sandbox` is removed, and a harness with its own sandbox uses `session start` (questions G5). |
| U3 | `airlock init --local` writes `airlock.local.toml` with a binding stub per repo secret label, using `from = "global"` where the global layer binds the label. Validation runs before the approval prompt. | Not covered. | Joining a team repo otherwise means reading the repo file, finding unbound labels, and writing TOML by hand. Validating first means the user is never asked to approve a file that would fail anyway. |
| U4 | New `airlock config`: the merged config with the layer each item comes from and each file's approval state. Reads the files; no daemon or session. | `list` asks the daemon; nothing for the human side. | Three layers raise "where does this come from?" (as `git config --show-origin` answers). `tools list` shows what a session serves, not what the files say. |
| U5 | Commands are grouped by audience. `list` becomes `tools list`, which serves the current session, or with `--session <ID or name>` any session from the user's terminal. The agent's own commands go under `airlock agent`: `agent check` and `agent hook`. `status` stays the user's view. | `list` at the top level, session only; `status` for both. | The agent's plumbing should not sit next to the user's commands, and the user should be able to see what a running agent can use. The session's view of itself belongs to `agent check`, so `status` needs no second mode. |
| U6 | `airlock session reload [ID…]`, run by the user: loads and approves config, resolves secrets, swaps the session's config. The token stays valid. | Non-goal: running sessions keep their config until they end. | An agent that adds a tool to `airlock.toml` otherwise has to be restarted to use it, losing its context. The design's concern, that tools change under a running agent, holds: they change only when the user asks. |
| U7 | `exec` and `run` exit with 125 when Airlock itself fails, 126 when a declared tool's binary cannot be used, and 127 when no such tool is declared. | Exit 1 for every Airlock error. | 1 is also the most common tool failure. Same convention as `docker run`, `env` and `chroot`. SKILL.md can say "125 means tell the user". |
| U8 | `session start` takes `--ttl` (default 12h; `0` means until revoked). | Ends on revoke or daemon stop only. | A forgotten `session start` keeps a token valid, and an automatic daemon running, indefinitely. |
| U9 | Version handshake on connect. A launcher that finds an idle daemon of another version restarts it. A busy one keeps serving, with a note, unless the protocol is incompatible. | Not covered. | An automatic daemon outlives the binary it was started from. |
| U10 | `--config` is not global; `daemon status` is dropped. | `--config` global; `daemon status` kept. | `exec` and `tools list` ignore files, so a `--config` there is a silent no-op. One status command is enough. |
| U11 | `--name` on `run` and `session start`. Default: the harness command's base name, or `shell`. | Sessions have only an id. | `session list` and `trust` notes need something a person recognizes. |
| U12 | Optional `description` on `[secrets.<label>]`. | Not in the schema. | A repo label without a source is a request to each user. The description tells them what to supply. |
| U13 | `airlock agent check` (session check and sandbox self-test) and `airlock agent hook claude-code` (SessionStart: check, then list tools into the agent's context). The session records whether the agent runs in Airlock's sandbox or an external one. `--profile claude` installs the hook. | Not covered. | Whether the agent uses `airlock exec` depends on it reading SKILL.md. A hook delivers the same facts on every start and after every compaction, and catches a broken sandbox before the agent's first `exec`. |
| U14 | **Deferred to v2.1.** `airlock completions <bash\|zsh>`: a dynamic completion script that asks the daemon for tool names and session ids, and hands off to the tool's own completion after `exec -- <tool>`. Nix and release tarballs install it. | Not covered. | `exec -- <TAB>` is where completion helps most, and only the session knows the tool names. A static script also goes stale on upgrade. Deferred because it pins an unstable clap_complete feature, calls the daemon on every TAB and needs hand-written shell delegation, and nothing in v2 depends on it. |
| U15 | `airlock daemon run` becomes `airlock daemon start --foreground`; `airlock logs` becomes `airlock daemon logs`. | `daemon run`; `logs` at the top level. | "run" then always means starting an agent. Logs are daemon administration, rarely needed, and do not belong at the top level. |
| U16 | With `AIRLOCK_SANDBOX=1`, `airlock --help` lists only the commands that work there. The help says so and names the hidden commands. A hidden command's own `--help` still works, and starts by saying it needs the user's terminal. | Same help everywhere. | An agent that reads the help should not be shown commands it cannot use. A user in a sandboxed shell has to see why a command is missing. |

## Journeys

### First run in a personal project

```
$ cd ~/src/app
$ airlock init
created ~/src/app/airlock.toml
edit it to declare your tools, then run `airlock run --profile claude`
```

The user edits the starter into:

```toml
[secrets.GH_TOKEN]
source  = "command"
command = ["gh", "auth", "token"]

[tools.gh]
description = "GitHub CLI"
[tools.gh.env]
GH_TOKEN      = { secret = "GH_TOKEN" }
GH_CONFIG_DIR = "{tool_state}"
```

```
$ airlock run --profile claude
~/src/app/airlock.toml is not trusted yet. Contents:

    [secrets.GH_TOKEN]
    source  = "command"
    command = ["gh", "auth", "token"]
    …

Trust this file and continue? [y/N] y
trusted ~/src/app/airlock.toml
```

Claude Code starts. Behind the prompt, `airlock run` resolved `GH_TOKEN`,
started the daemon and registered a session. Nothing else was printed.
With `-v`:

```
$ airlock run -v --profile claude
airlock: project ~/src/app (repo: trusted)
airlock: resolving GH_TOKEN (gh)… done
airlock: started daemon, PID 48211, exits when idle
airlock: session 7f3a9c "claude" registered, 1 tool
airlock: sandbox: claude profile, root ~/src/app
```

If a secret command takes more than a second, the `resolving` line prints
without `-v` too, so a 1Password or `gcloud` prompt that appears has
context.

Claude starts with the SessionStart hook's context already in place: the
session is active, the self-test passed, and `gh` runs through
`airlock exec` ([Harness hooks](#harness-hooks)).

Inside the agent:

```
$ airlock tools list
gh
  GitHub CLI
  GH_TOKEN = <secret "GH_TOKEN">
  GH_CONFIG_DIR = "/Users/me/.cache/airlock/3f9a1c2b7d4e8a60/gh"

$ airlock exec -- gh auth status
github.com
  ✓ Logged in to github.com account me (GH_TOKEN)
  - Token: [REDACTED:GH_TOKEN]
```

When Claude exits, the session ends and `airlock run` exits with Claude's
exit code. Five minutes later the daemon exits too.

### Joining a team repo

The team's `airlock.toml` declares labels and leaves the bindings to each
user:

```toml
[secrets.GH_TOKEN]
description = "GitHub token with read access to acme/app"

[secrets.CLOUDFLARE_API_TOKEN]
description = "Cloudflare token, Zone:Read on acme.dev"

[tools.gh]
…
```

The user's global config already binds `GH_TOKEN` for every project:

```toml
# ~/.config/airlock/airlock.toml
[secrets.GH_TOKEN]
source  = "command"
command = ["op", "read", "op://Private/GitHub/token"]
```

```
$ git clone git@github.com:acme/app ~/src/app && cd ~/src/app
$ airlock run --profile claude
error: 2 secrets in ~/src/app/airlock.toml have no source:
  GH_TOKEN              GitHub token with read access to acme/app
  CLOUDFLARE_API_TOKEN  Cloudflare token, Zone:Read on acme.dev
the project leaves these to you. `airlock init --local` creates
airlock.local.toml with a stub for each.

$ airlock init --local
created ~/src/app/airlock.local.toml
  GH_TOKEN              from = "global" (your global config binds it)
  CLOUDFLARE_API_TOKEN  not bound: edit airlock.local.toml
airlock.local.toml is ignored by git
```

The generated file:

```toml
# Your bindings for this project. Keep it out of git.
# Run `airlock config` to see the merged result.

# GitHub token with read access to acme/app
[secrets.GH_TOKEN]
from = "global"

# Cloudflare token, Zone:Read on acme.dev
# Uncomment one:
# [secrets.CLOUDFLARE_API_TOKEN]
# source  = "command"
# command = ["op", "read", "op://Private/Cloudflare/token"]
#
# [secrets.CLOUDFLARE_API_TOKEN]
# source = "env"        # read from the environment of `airlock run`
```

If `airlock.local.toml` is not ignored, the last line instead reads:

```
warning: airlock.local.toml is not ignored by git. To ignore it in every repo:
         echo airlock.local.toml >> ~/.config/git/ignore
```

The global excludes file (or the file `core.excludesFile` names) covers
repos whose `.gitignore` the user does not own, and every later clone.

After the user fills in the Cloudflare binding:

```
$ airlock run --profile claude
~/src/app/airlock.toml is not trusted yet. Contents:
    …
Trust this file and continue? [y/N] y
trusted ~/src/app/airlock.toml

~/src/app/airlock.local.toml is not trusted yet. Contents:

    [secrets.GH_TOKEN]
    from = "global"       # → global: command op read op://Private/GitHub/token
    …

Trust this file and continue? [y/N] y
trusted ~/src/app/airlock.local.toml
```

The user approves each file on its own. Declining either stops the run,
with exit status 125. The `# →` note shows what `from = "global"` resolves
to. It is not part of the file, and not part of what is approved.

### A repo whose team has not adopted Airlock

```
$ cd ~/src/upstream-lib
$ airlock init --local
created ~/src/upstream-lib/airlock.local.toml (no airlock.toml here, so a standalone config)
warning: airlock.local.toml is not ignored by git. To ignore it in every repo:
         echo airlock.local.toml >> ~/.config/git/ignore
```

The file is a skeleton like the one `airlock init` writes: a commented
secret and tool. The user fills it in and runs `airlock run` as usual. It
is approved like any local file, and nothing lands in the team's
`.gitignore`.

### Every day

```
$ airlock run --profile claude
```

Nothing to approve, so nothing is printed before Claude starts. A second
agent in the same project, in another terminal, works the same way and gets
its own session:

```
$ airlock run -- codex
```

The second session resolves its own secrets, so any 1Password or `gcloud`
prompt appears again, and a minted token is minted and refreshed for each
session.

```
$ airlock status
daemon    running, PID 48211, started on demand 2h ago
address   unix://$RUNTIME/airlock.sock

project   ~/src/app
  global  ~/.config/airlock/airlock.toml   user file
  repo    airlock.toml                     trusted
  local   airlock.local.toml               trusted

sessions  2 here, 3 in total
  7f3a9c  claude  10:42  14 execs
  b20e51  codex   11:30   2 execs
```

To see what a running agent can use, from the user's terminal:

```
$ airlock tools list --session codex
session b20e51 "codex" for ~/src/app
gh
  GitHub CLI
  GH_TOKEN = <secret "GH_TOKEN">
  ...
```

`--session` takes an ID, a unique ID prefix, or a unique session name.

### The agent changes the config

The agent adds a `psql` tool to `airlock.toml` and tries it:

```
$ airlock exec -- psql -c 'select 1'
airlock: no tool named "psql" in this session
airlock: airlock.toml changed after this session started. Changes apply
         once the user approves them (`airlock trust`) and reloads the
         session (`airlock session reload`).
$ echo $?
127
```

The client can say this because the session carries the hash of each layer
it loaded, and the agent can read the project files. SKILL.md tells the
agent to report the change to the user.

In the user's terminal:

```
$ airlock trust
~/src/app/airlock.toml has changed since you last trusted it:

--- trusted
+++ ~/src/app/airlock.toml
@@ -14,3 +14,8 @@
 GH_TOKEN = { secret = "GH_TOKEN" }
+
+[tools.psql]
+description = "Postgres shell"
+[tools.psql.env]
+PGSERVICE = "app-dev"

Trust this version? [y/N] y
trusted ~/src/app/airlock.toml
2 sessions for ~/src/app use the previous config: 7f3a9c "claude", b20e51 "codex"
run `airlock session reload` to apply it to them

$ airlock session reload
reloaded 7f3a9c "claude": tools +psql
reloaded b20e51 "codex": tools +psql
```

The agent's next `airlock tools list` shows `psql`. Without U6, the user would
end the agent and start it again. With Claude Code, `airlock run --profile
claude -- claude --continue` keeps the conversation.

An edit that adds something the user did not expect is the case approval
exists for:

```
$ airlock run --profile claude
~/src/app/airlock.toml has changed since you last trusted it:

--- trusted
+++ ~/src/app/airlock.toml
@@ -10,5 +10,6 @@
 [filesystem]
 read = ["/opt/homebrew/share"]
+write = ["~/.ssh"]

Trust this version and continue? [y/N] n
not trusted; nothing started
```

Text that could hide a change is escaped, so it cannot fool the user:

```
+description = "GitHub CLI\u{202E}"
```

### A harness with its own sandbox, or an IDE

`airlock run` always runs the agent in Airlock's sandbox. A harness that
brings its own, such as Claude Code with `--sandbox`, or an IDE extension
that no command can wrap, gets its session from `session start`:

```
$ eval "$(airlock session start --name claude)"
session 7f3a9c "claude" for ~/src/app, expires in 12h
note: this harness runs in its own sandbox, or none. It must deny reads of
      $RUNTIME and keep the agent away from your credential stores; see
      https://github.com/ModernPath/airlock/blob/main/SECURITY.md#external-sandboxes
$ claude --sandbox
```

`session start` prints the export lines to stdout and the notes to stderr,
so `eval` sees only the exports:

```
export AIRLOCK_ADDR='unix://$RUNTIME/airlock.sock'
export AIRLOCK_SESSION='airlock_7f3a9c_<43 random characters>'
```

`-q` drops the note once the harness is set up. `--format fish` and
`--format json` cover other shells and scripts.

The harness inherits this shell's whole environment, unlike under
`airlock run`. Start it from a plain shell, not from inside `op run`.

For an editor:

```
$ eval "$(airlock session start --name vscode)"
$ code .
```

Everything the editor starts inherits the token: every extension and
every integrated terminal. If the editor is already running, `code .`
opens a window in the running instance, which keeps the environment it
started with, so quit it first. An editor started from the Dock gets no
session; its agent's hook says so.

The session is bound to this shell's process tree: a process that does not
descend from the shell cannot use the token, even if it copies it. It ends
after 12 hours. Before then, `session renew` restarts the clock without
changing the token, so the editor keeps working:

```
$ airlock session renew vscode
renewed 7f3a9c "vscode", expires in 12h
```

An expired session is gone, with its secrets. The agent's next `exec`
says so, and the user starts a new session and restarts the editor from
that shell.

A shell where the user can run `airlock exec` by hand:

```
$ airlock run -- $SHELL                          # sandboxed, as the agent sees it
$ eval "$(airlock session start --name shell)"   # in this shell, unsandboxed
```

### No project config

```
$ cd ~/scratch/experiment
$ airlock run --profile claude
error: no airlock.toml or airlock.local.toml in ~/scratch/experiment or a parent directory up to ~
`airlock init` creates one here, or `--no-project-config` runs with your global config only

$ airlock run --no-project-config --profile claude
```

### Upgrading Airlock

The daemon runs until it is idle, so it can outlive an upgrade (U9):

```
$ brew upgrade airlock
$ airlock run --profile claude
note: the daemon runs airlock 0.5.0 and this is 0.6.0. It keeps serving its
      2 sessions; it is replaced when it is idle, or now with `airlock daemon restart`.
```

If the daemon has no sessions, the launcher restarts it without a note. If
the protocols are incompatible, the launcher refuses:

```
error: the running daemon (airlock 0.5.0) cannot serve this airlock (0.6.0)
`airlock daemon restart` replaces it and ends its 2 sessions
```

### An always-on daemon

```
$ airlock daemon install
wrote ~/Library/LaunchAgents/ai.modernpath.airlock.plist
loaded it: the daemon now starts at login and keeps running without sessions
```

```
$ airlock daemon install            # Linux
wrote ~/.config/systemd/user/airlock.service
enabled and started airlock.service
note: systemd stops user services at logout. To keep the daemon running,
      run `loginctl enable-linger`.
```

`airlock status` then shows `daemon running, PID 811, launchd service`.

### Stopping things

```
$ airlock session revoke b20e51
ended b20e51 "codex"

$ airlock daemon stop
this ends 2 sessions: 7f3a9c "claude" (~/src/app), c3d2e1 "vscode" (~/src/infra)
Stop the daemon? [y/N] y
daemon stopped
```

On a non-terminal, `daemon stop` and `restart` refuse when sessions exist,
unless `--yes` is given. An agent whose session ended sees:

```
$ airlock exec -- gh pr list
airlock: this session has ended (revoked by the user, or the daemon stopped).
         Ask the user to start a new session.
```

## Harness hooks

SKILL.md tells the agent to run `airlock tools list` and use `airlock exec`. An
agent that does not load the skill, or loses it in a compaction, runs `gh`
directly, gets "not logged in", and works around it. A harness hook puts
the facts in the agent's context without relying on the agent (U13).

Two commands, both under `airlock agent` because the agent and its
harness run them, not the user:

- **`airlock agent check`** is the engine, and works anywhere: it verifies
  the session and self-tests the sandbox of the process that runs it. The
  agent can run it by hand, and so can the user in a session shell.
- **`airlock agent hook <harness>`** adapts `check` and `tools list` to
  one harness's hook protocol. It reads the hook event from stdin and
  writes what that harness expects. `claude-code` is the first adapter.
  Others follow the harnesses that have hooks.

### What `airlock agent check` verifies

| Check | Passes when | Why |
|---|---|---|
| Session | `AIRLOCK_SESSION` is set and the daemon accepts it | Everything else depends on it. |
| Daemon | it answers on `AIRLOCK_ADDR`, at a compatible version | Catches a stopped or stale daemon early. |
| `admin.token` | opening it for reading fails | A readable token lets the agent register sessions for any project ([Under another harness](airlock-v2-design.md#under-another-harness)). The file is opened, never read. |
| Runtime dir | creating a file in it fails | The agent must not replace the socket or CA. A file that was created is removed at once. |
| Trust store | creating a file in it fails | The agent must not approve its own config. |
| Global config dir | creating a file in it fails | The global layer is not approved, so it must not be writable. |
| Environment | no variable named in any tool's `env` as a secret is set in this process | A tool secret in the agent's environment means it was passed some other way, for example by `--passthrough-env`. The daemon supplies the names through `List`, never the values. |
| Credential stores | opening each tool's `extra_read` paths and `~/.config/gh`, `~/.config/gcloud`, `~/.aws`, `~/.kube` for reading fails | A warning, not a failure: `claude-relaxed` opens some on purpose. A readable store means the agent can take the credentials Airlock brokers directly. Paths that do not exist are skipped. |
| Config | the project files' hashes match the session's | Not a failure. Reported so the agent can tell the user the config changed. |

The client computes none of the paths. The daemon returns the runtime
base, the trust store and the global config path the launcher validated
for this session, so the probes test the same paths the launcher used.
Every probe is a single `open` that is expected to fail. Nothing is read.

**What a pass means.** The checks run in the process that runs
`airlock agent check`, with that process's sandbox. They catch a misconfigured
sandbox. They do not prove anything against a hostile agent, which could
fake the output. The guarantees still come from the sandbox itself.

**Which sandbox is tested.** The session records how the agent was started:
`airlock` for `airlock run`, `external` for `session start`.

- Under `airlock run`, the harness and its hooks run inside Airlock's
  sandbox, so a hook's self-test tests the agent's sandbox.
- Under an external sandbox, a hook may run outside that sandbox. Claude
  Code's own sandbox applies to the commands the agent runs, not
  necessarily to hooks. The hook then skips the probes, lists the tools,
  and asks the agent to run `airlock agent check` once with its own shell tool,
  which is sandboxed.

### `airlock agent check`

```
$ airlock agent check
session   7f3a9c "claude" for ~/src/app
daemon    answers, airlock 0.6.0
sandbox   Airlock's
  ok      admin.token cannot be read
  ok      runtime dir cannot be written
  ok      trust store cannot be written
  ok      global config cannot be written
  ok      no tool secret in this environment
  ok      credential stores cannot be read
tools     gh, psql, tofu
```

A failure names the check and what the user has to fix:

```
$ airlock agent check
session   7f3a9c "vscode" for ~/src/app
daemon    answers, airlock 0.6.0
sandbox   external
  FAIL    $RUNTIME/admin.token can be read. The harness's sandbox must deny
          reads of $RUNTIME, or this agent can start sessions for any project.
  ok      runtime dir cannot be written
  ...
  warn    ~/.config/gcloud can be read. The agent can use your gcloud login
          directly; deny it in the harness's sandbox.
$ echo $?
1
```

Exit status: 0 if every check passes, 1 if a check fails, 125 if there is
no session or the daemon does not answer.

### `airlock agent hook claude-code`

Handles Claude Code's SessionStart event. It reads the event JSON from stdin and
always exits 0, so its output reaches Claude as context, not as a hook
error.

**SessionStart.** Runs `check`, then `tools list`. Claude Code fires it on
startup, on resume, after `/clear` and after compaction, so the tool list
comes back after the context is compacted. When everything passes:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "SessionStart",
    "additionalContext": "Airlock is active for this project (session 7f3a9c, sandbox self-test passed).\n\nThese tools hold credentials. Run them only through Airlock, as `airlock exec -- <tool> [args...]`:\n\n  gh    GitHub CLI\n  psql  Postgres shell\n  tofu  OpenTofu\n\nRunning them directly fails: their credentials are not in your environment. Secrets in their output appear as [REDACTED:NAME]; that is expected. `airlock tools list` shows details. Other commands run directly as usual."
  }
}
```

The other outcomes:

| State | Context for Claude | Message for the user (`systemMessage`) |
|---|---|---|
| No session, no Airlock config in the project | none, and no output | none |
| No session, but the project has `airlock.toml` | "This project uses Airlock, but this agent was not started with `airlock run`, so tools that need credentials are unavailable. Tell the user. Do not look for credentials yourself." | "Airlock: this agent has no session. Start it with `airlock run`." |
| Session ended, or the daemon does not answer | the `exec` error message, and "tell the user" | the same message |
| A self-test check fails | "Airlock's sandbox self-test failed: <check>. Do not use `airlock exec` until the user fixes it. Tell the user." No tool list. | "Airlock sandbox self-test failed: <check>" |
| External sandbox | the success context with its first sentence saying the harness provides the sandbox (not self-tested), plus "Before your first `airlock exec`, run `airlock agent check` with your shell tool and report any FAIL to the user." | none |
| Config changed since the session started | the success context, plus the config-changed note from [The agent changes the config](#the-agent-changes-the-config) | none |

Printing nothing outside Airlock projects means the hook can sit in the
user-wide `~/.claude/settings.json` without effect elsewhere.

Claude Code also offers a PreToolUse hook, which could deny a direct
`gh pr list` and answer with the `airlock exec` form. It is left out for
now. The SessionStart context is expected to be enough, and a hook on
every shell command costs a daemon round trip per call and needs a command
parser that is never complete.

### Installing the hook

`airlock run --profile claude` installs it. The profile's default command
becomes:

```
claude --dangerously-skip-permissions --settings '<hook JSON>'
```

A user who passes their own command after `--`, or uses another way to
start Claude Code, adds the hook to `~/.claude/settings.json` (all
projects) or to the project's `.claude/settings.json` (committed for the
team):

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [{ "type": "command", "command": "airlock agent hook claude-code" }] }
    ]
  }
}
```

`airlock agent hook claude-code --print-settings` prints this block, so the docs
and the binary cannot drift apart.

The agent can edit a project's `.claude/settings.json` and remove the hook.
That is acceptable: the hook is guidance, and nothing depends on it for
security.

### Other harnesses

Without a hook adapter, the generic form works in any harness that runs a
command at start and shows its output to the agent:

```
$ airlock agent hook text
```

It prints the same context as the SessionStart hook, as plain text, and
exits 0.

## Shell completion

**Status:** deferred to v2.1
([design](airlock-v2-design.md#planned-for-v21)). The design below is
complete and lands in its own PR after v2 ships.

`airlock completions <bash|zsh>` prints a completion script for the shell
(U14). The script is a thin registration: on each TAB it calls back into
`airlock`, which computes the candidates. So completions know the current
session's tools and the running sessions, and an installed script does not
go stale when an upgrade adds a flag.

### Installing

| Shell | Per session (`~/.bashrc`, `~/.zshrc`) | As a file |
|---|---|---|
| bash | `source <(airlock completions bash)` | `airlock completions bash > ~/.local/share/bash-completion/completions/airlock` (bash-completion loads it on first use) |
| zsh | `source <(airlock completions zsh)`, after `compinit` | `airlock completions zsh > ~/.zfunc/_airlock`, with `fpath+=(~/.zfunc)` before `compinit` |

Packages install the file, so most users never run `completions`:

- **Nix:** `postInstall` runs `installShellCompletion --cmd airlock` with
  the output of `$out/bin/airlock completions bash` and `zsh`.
- **Release tarballs:** `completions/airlock.bash` and
  `completions/_airlock` next to the binary, generated by the release
  build.

### What completes

| Position | Candidates | From |
|---|---|---|
| `airlock <TAB>` | subcommands; inside a sandbox (`AIRLOCK_SANDBOX=1`) only the ones that work there: `exec`, `tools`, `agent`, `config`, `init`, `completions` (U16) | static |
| `airlock exec -- <TAB>` | the session's tools, with descriptions | a `List` request with the session token; nothing without a session |
| `airlock exec -- gh <TAB>` | `gh`'s own completion, as if the line started with `gh` | delegation: zsh `_normal`, bash `_command_offset` |
| `airlock run -- <TAB>` | commands, then that command's own completion | delegation |
| `--profile` | `claude`, `claude-relaxed`, with descriptions | static |
| `--config` | `*.toml` files | the shell's file completion |
| `--allow-read`, `--allow-write` | paths | the shell's file completion |
| `--passthrough-env` | names of exported variables | the shell |
| `session renew`, `session reload`, `session revoke`, `tools list --session`, `daemon logs --session` | session ids, with name, project and start time | the daemon, with `admin.token`; outside the sandbox only |
| `agent hook` | `claude-code`, `text` | static |
| `session start --format` | `sh`, `fish`, `json` | static |

In zsh, descriptions appear next to candidates:

```
$ airlock exec -- <TAB>
gh    -- GitHub CLI
psql  -- Postgres shell
tofu  -- OpenTofu

$ airlock session revoke <TAB>
7f3a9c  -- claude  ~/src/app    10:42
b20e51  -- codex   ~/src/app    11:30
c3d2e1  -- vscode  ~/src/infra  09:05
```

bash shows only the candidates themselves, which is a bash limitation.

Tool names complete in any shell with a session: one started with
`airlock run -- $SHELL`, or after `eval "$(airlock session start)"`. Agents
do not press TAB, so completion is for the user's own shells.

### Rules for the completer

Completion runs on every TAB, so it has to be fast and have no side
effects:

- It never starts the daemon, resolves secrets, prompts, or checks
  approval. It only asks a running daemon.
- Each daemon request has a 300 ms timeout. On any error it offers no
  candidates and prints nothing: output on stderr would garble the
  prompt line.
- It uses a blocking `std` socket, not a tokio runtime, and runs before
  anything else in `main()`.
- A `List` request from completion is not logged as an `exec`.

**Delegated completion runs the tool's own completer directly.** For
`airlock exec -- gh pr <TAB>`, zsh calls `_gh`, which runs `gh __complete`
from the shell's `PATH`. That `gh` runs without Airlock's credentials and
outside the tool sandbox. Subcommands and flags complete; anything that
needs the API, such as PR numbers, completes to nothing. It runs no more
than typing `gh` in the same shell would, so it adds no new exposure (the
design's [B1](airlock-v2-design.md#blocking) non-goal covers a planted
`gh` on the user's `PATH`).

### Implementation

- `clap_complete`'s `CompleteEnv` provides the call-back protocol
  (`COMPLETE=zsh airlock -- …`). `ArgValueCandidates` supplies tool names
  and session ids.
- Both sit behind clap_complete's `unstable-dynamic` feature, so pin the
  minor version.
- The `--` delegation is not part of `CompleteEnv`. `airlock completions`
  wraps its script in a few lines per shell that hand off to `_normal` or
  `_command_offset` after `exec -- <tool>` and `run --`.
- The fallback, if `unstable-dynamic` turns out to be unusable: static
  `clap_complete::generate` scripts plus a hidden `airlock __complete
  <tools|sessions>` that hand-written shell functions call.
- Tests drive the completer with `COMPLETE=bash` and `COMPLETE=zsh` against
  a mock daemon. They check the candidates with a session, without a
  session, inside the sandbox, and when the daemon does not answer.

`clap_complete` also supports fish, elvish and PowerShell through the same
mechanism. They are not tested and not documented until someone needs
them.

## Options

The help text is written with the code. This section records the options
each command takes and the decisions behind them, so nothing here needs to
stay in sync with a verbatim draft.

The top-level help groups commands by who runs them (U5): *Start an
agent* (`run`, `init`, `trust`, `config`, `status`), *Use tools* (`exec`,
`tools`), *Manage* (`session`, `daemon`) and *For the agent and its
harness* (`agent`). clap has no subcommand headings, so this needs a
custom `help_template`, and a test checks that every subcommand appears in
it. The footer points to `airlock init`, then `airlock run --profile
claude`. With `AIRLOCK_SANDBOX=1` the help lists only `exec`, `tools`,
`agent`, `init` and `config`, says so first, and names the hidden commands
(U16). A hidden command's own `--help` still works and starts by saying it
needs the user's terminal. In a `session start` shell the variable is not
set, and the help is complete.

| Command | Options | Notes |
|---|---|---|
| `run [-- CMD...]` | `--profile <claude\|claude-relaxed>`; `--allow-read`, `--allow-write`, `--passthrough-env` (repeatable); `--name`; `--no-session`; `--config PATH`; `--no-project-config`; `-v`; `-q` | `CMD` is optional with `--profile`. Exits with the agent's status, or 125 when Airlock could not start it. `-v` reports each step before the agent starts; `-q` drops notes and warnings. |
| `exec -- TOOL [ARGS...]` | none | No shell: `$VARS`, globs, pipes and redirects in `ARGS` are passed literally. Reads `AIRLOCK_ADDR` and `AIRLOCK_SESSION`. Exits with the tool's status, or 125, 126 or 127 as in [Messages](#messages). A tool can exit with those too; Airlock's own errors start with `airlock:` on stderr. |
| `tools list` | `--session <ID>`: an id, a unique id prefix or a unique name; needs the user's terminal | `airlock tools` alone is `tools list`. With `--session`, a first line names the session. |
| `agent check` | `-q` prints only failures | Exit 0, 1 when a check fails, 125 without a session. |
| `agent hook <claude-code\|text>` | `--print-settings` prints the hook configuration and exits | Always exits 0. |
| `trust` | `--config PATH`; `-y`, `--yes`; `--expect-sha256 HASH` (repeatable) | On a non-terminal, refuses without `--yes` or `--expect-sha256`. |
| `init` | `--local`; `--global` | Fails if the file exists. `--global` is refused inside the sandbox. |
| `config` | `--config PATH`; `--no-project-config`; `--paths` | Reads the files; no daemon or session. Output below. |
| `status` | `--config PATH`; `--no-project-config` | Exit 0 when the daemon runs, 3 when it does not: the LSB and `systemctl status` convention, since a stopped daemon is normal in v2. |
| `session start` | `--name` (default `shell`); `--ttl DURATION` (default `12h`, `0` for never); `--format <sh\|fish\|json>`; `--config PATH`; `--no-project-config`; `-q` | Exports on stdout, notes on stderr. |
| `session renew <ID>` | `--ttl DURATION` (default: the session's) | Only for `session start` sessions. |
| `session list` | `--here` | Columns: id, name, project, started, execs, what ends it, note (`config changed`). |
| `session reload [ID...]` | `--all` | Without ids, every session for the project in the current directory. |
| `session revoke <ID>...` | `--here`; `--all` | An id prefix is enough when it is unique. |
| `daemon start` | `--foreground` | `--foreground` stays attached and logs to stderr; it is what the launchd agent and the systemd unit run. |
| `daemon stop`, `daemon restart` | `-y`, `--yes` | Ask first on a terminal when sessions exist; refuse on a non-terminal without `--yes`. |
| `daemon logs` | `--session <ID>` | |
| `daemon install`, `daemon uninstall` | none | |

`daemon --help` says that `run` and `session start` start the daemon when
it is not running, and that a daemon started that way exits after
5 minutes with no sessions.

`airlock config` output:

```
$ airlock config
layers
  global  ~/.config/airlock/airlock.toml   user file
  repo    ~/src/app/airlock.toml           trusted
  local   ~/src/app/airlock.local.toml     changed since trusted

secrets
  GH_TOKEN              local → global   command: op read op://Private/GitHub/token     (unapproved)
  CLOUDFLARE_API_TOKEN  local            command: op read op://Private/Cloudflare/token (unapproved)

tools
  aws   global  AWS CLI
  gh    repo    GitHub CLI       GH_TOKEN = <secret "GH_TOKEN">
  psql  local   Postgres shell                                     (unapproved)

settings
  timeout                120          repo
  filesystem.read        /opt/homebrew/share   repo
  agent.passthrough_env  COLORTERM    global
                         NO_COLOR     repo
  agent.env.LOG_LEVEL    "debug"      local (overrides repo)      (unapproved)

airlock.local.toml changed since you trusted it; the next session start asks about it.
```

## Messages

The user sees the messages for launcher commands, and the agent sees the
ones for `exec`, `tools list` and `agent check`. Every agent-facing message names the user
action, so the agent can relay it without interpreting it.

### Launcher (`run`, `session start`, `session reload`)

| Situation | Message | Exit |
|---|---|---|
| No project config | `error: no airlock.toml or airlock.local.toml in <dir> or a parent directory up to ~` + hint for `init` / `--no-project-config` | 125 |
| Invalid TOML or config | `error: <file>:<line>: <problem>`; nothing is approved | 125 |
| Tool in repo and local | `error: tool "gh" is defined in both <repo> and <local>; add \`override = true\` to the tool in airlock.local.toml to replace the repo's` | 125 |
| `override = true` on a tool the repo does not define | `error: <local>: tool "gh" sets override, but the repo defines no "gh"` | 125 |
| Repo label without a binding | lists labels with descriptions + `airlock init --local` hint | 125 |
| Global item uses a repo label | `error: <global>: tool "x" uses secret "Y", which your global config does not declare` | 125 |
| Unapproved file, terminal | diff or full file, `Trust this version and continue? [y/N]` (U1); on `n`, `not trusted; nothing started` | 125 on `n` |
| Unapproved file, no terminal | diff or full file + `run \`airlock trust\` in a terminal to approve it` | 125 |
| Anchor redirected | `error: trust store <path> is inside the project root <root> (from XDG_STATE_HOME=…); refusing to use it` | 125 |
| Write grant covers an anchor | `error: <file>: filesystem.write "<path>" covers <anchor>; Airlock's own files cannot be writable from a sandbox` | 125 |
| Secret command fails | `error: secret GH_TOKEN: \`op read …\` exited with 1:` + its stderr, indented | 125 |
| Runtime dir check fails | `error: runtime dir <path> is owned by uid 502, not you (501)`, and similar per check | 125 |
| Daemon version skew | note or error as in [Upgrading Airlock](#upgrading-airlock) | 0 / 125 |
| Run inside the sandbox | `error: \`airlock run\` cannot run inside an Airlock sandbox; run it from your own terminal` | 125 |
| `status` inside the sandbox | `error: \`airlock status\` needs your own terminal. Inside a session, \`airlock agent check\` shows this session.` | 125 |

### Agent (`exec`, `tools list`, `agent check`)

| Situation | Message | Exit |
|---|---|---|
| No `AIRLOCK_SESSION` | `airlock: no Airlock session. The user starts one with \`airlock run\`; this process was not started that way.` | 125 |
| Session ended or unknown | `airlock: this session has ended (revoked by the user, or the daemon stopped). Ask the user to start a new session.` | 125 |
| Session expired | `airlock: this session expired. Ask the user to start a new one, or to renew sessions before they expire with \`airlock session renew\`.` | 125 |
| Caller outside the session's process tree | `airlock: this process was not started from the session's agent or shell, so it cannot use the session.` | 125 |
| Daemon unreachable | `airlock: the daemon at <addr> does not answer. Ask the user to check \`airlock status\`.` | 125 |
| Undeclared tool | `airlock: no tool named "x" in this session` + config-changed hint when a layer's hash differs | 127 |
| Binary not found | `airlock: tool "tofu" is declared, but no \`tofu\` is on the session's PATH` + the dropped `PATH` entries and why, and: install the tool outside the project (Homebrew, mise, Nix) | 126 |
| Binary in the project | `airlock: tool "gh" resolves to ~/src/app/bin/gh, inside the project; refusing to run it. Install it outside the project (Homebrew, mise, Nix).` There is no override. | 126 |
| Stale secret | `airlock: secret "X" is stale (last refresh failed: …). The user needs to fix its source; Airlock retries on its own.` | 125 |
| Working dir outside root | `airlock: <cwd> is outside this session's project ~/src/app` | 125 |
| Self-test failure (`agent check`) | `FAIL <what> can be <read/written>.` + the fix, as in [`airlock agent check`](#airlock-agent-check) | 1 |

## Examples

`examples/` today has single-file configs whose headers say to start the
daemon with `airlock daemon start`, and two shell scripts that wrap
`daemon start` in `op run` and Vault.

| File | v2 |
|---|---|
| `github-only.toml`, `github-and-opentofu.toml`, `kubernetes.toml`, `cloud-providers.toml`, `gcp-*.toml` | Same content. The header says how to run it: copy it to `airlock.toml`, then `airlock run --profile claude`, and approve it when asked. `source = "env"` examples show `op run -- airlock run`. |
| `1password-startup.sh`, `vault-startup.sh` | Removed. Replaced by `secret-sources.toml`: command sources for 1Password, Vault, `gh auth token` and `gcloud`, plus the `op run -- airlock run` line for `env` sources. |
| `team/airlock.toml` (new) | A repo file: labels with `description` and no `source`, tools, `[agent]`. |
| `team/airlock.local.toml` (new) | One user's bindings: `from = "global"` for one label, a `command` for another, a personal tool. |
| `team/global.toml` (new) | A `~/.config/airlock/airlock.toml`: global bindings, a personal `aws` tool, `agent.passthrough_env`. |
| `team/README.md` (new) | The three files, the merged result (the table from the design doc's worked example), and the onboarding transcript from [Joining a team repo](#joining-a-team-repo). |

Header comment for a single-file example:

```toml
# Minimal setup: GitHub CLI only
#
# Use it:
#   cp examples/github-only.toml airlock.toml
#   airlock run --profile claude        # asks you to trust the file the first time
#
# Inside the agent:
#   airlock exec -- gh repo list
#   airlock exec -- gh issue list --label bug
```

## Open UX questions

- **Session id and token format.** The proposal: a 6-hex id, and a token
  `airlock_<id>_<43 base64url characters>`. The prefix lets secret
  scanners recognize the token, and logs can name the session without
  the secret part. Is the prefix worth the length?
- **Idle grace period.** 5 minutes is a guess. It should be long enough
  that two quick `airlock run`s share a daemon, and short enough that a
  forgotten daemon goes away.
- **Should `airlock trust` offer to reload sessions?** One more prompt
  (`Reload 2 running sessions now? [y/N]`) against a separate command.
  This doc keeps it separate.
- **`daemon install` while an automatic daemon runs.** Either the service
  waits for the socket to free up, or `install` tells the user to run
  `daemon restart`. The second is simpler. The first keeps sessions alive.
- **Worktrees (F6).** When a file is byte-identical to a copy approved for
  the same git common dir, the prompt could say `identical to the file you
  trusted in ~/src/app; trust it here too? [Y/n]`. That cuts the cost without
  implicit trust.
- **Long diffs.** Page through `$PAGER` when the diff is longer than the
  terminal? The escaping already happens before output, so the pager
  cannot interpret anything.
- **Is `--settings` the right injection point?** Verify that
  `claude --settings` merges hooks with the user's own settings rather than
  replacing them. Also decide what happens when the user has also
  installed the hook in `settings.json`: the tool list would arrive twice.
  `airlock agent hook` could set a marker variable on its first run and stay
  silent on the second.
- **Should a failed self-test block `exec`?** Today the hook only tells
  the agent and the user. The daemon could refuse `exec` for a session
  whose self-test failed. But the agent could simply skip the test, and an
  external harness sandbox cannot be tested from the hook, so it would be a
  convenience only.
- **Completion inside the agent sandbox (v2.1).** A sandboxed
  `airlock run -- $SHELL` loads the user's `.zshrc` only if the sandbox
  can read it. `claude-relaxed` allows that; `claude` does not. Either
  document `--allow-read ~/.zshrc`, or accept that completion works only in
  unsandboxed session shells.
- **Policy diff (F3).** When it lands, the prompt shows the effective
  change above the byte diff, and a comment-only edit says so.
