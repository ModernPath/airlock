# Airlock v2 — user experience

What the user and the agent see when [Airlock v2](airlock-v2-design.md)
ships: the commands, their help text, their output and errors, and the
README, SKILL.md and examples that describe them.

**Status:** proposal, companion to [airlock-v2-design.md](airlock-v2-design.md).
The design doc decides the mechanism. This doc decides the surface. Where
the surface needed the mechanism to change, the change is listed in
[Changes to the design](#changes-to-the-design) and marked **(U<n>)** where
it appears. U1–U16 are accepted and incorporated into the design doc.

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
| User's terminal | `run`, `init`, `trust`, `config`, `status`, `session …`, `daemon …`, `completions` | nothing; the daemon starts on demand |
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
airlock completions <bash|zsh>               shell completion script
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
| No shell completion | `completions bash/zsh`, with tool names and session ids completed from the daemon (U14) |
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
| U14 | `airlock completions <bash\|zsh>`: a dynamic completion script that asks the daemon for tool names and session ids, and hands off to the tool's own completion after `exec -- <tool>`. Nix and release tarballs install it. | Not covered. | `exec -- <TAB>` is where completion helps most, and only the session knows the tool names. A static script also goes stale on upgrade. |
| U15 | `airlock daemon run` becomes `airlock daemon start --foreground`; `airlock logs` becomes `airlock daemon logs`. | `daemon run`; `logs` at the top level. | "run" then always means starting an agent. Logs are daemon administration, rarely needed, and do not belong at the top level. |
| U16 | With `AIRLOCK_SANDBOX=1`, `airlock --help` and completion list only the commands that work there. The help says so and names the hidden commands. A hidden command's own `--help` still works, and starts by saying it needs the user's terminal. | Same help everywhere. | An agent that reads the help should not be shown commands it cannot use. A user in a sandboxed shell has to see why a command is missing. |

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

The client computes the runtime dir and anchor paths the way the launcher
does: the runtime base from `confstr` or `/run/user/<uid>`, and the anchors
from the XDG variables. Every probe is a single `open` that is expected to
fail. Nothing is read.

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
| External sandbox | the tool list, plus "Before your first `airlock exec`, run `airlock agent check` with your shell tool and report any FAIL to the user." | none |
| Config changed since the session started | the tool list, plus the config-changed note from [The agent changes the config](#the-agent-changes-the-config) | none |

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

### `airlock completions --help`

```
Print a shell completion script

Usage: airlock completions <SHELL>

The script calls back into airlock for candidates, so it completes your
session's tool names after `airlock exec --` and session ids after
`airlock session revoke`, and stays current across upgrades.

Arguments:
  <SHELL>  [possible values: bash, zsh]

Install:
  bash  source <(airlock completions bash)                 in ~/.bashrc
  zsh   source <(airlock completions zsh)                  in ~/.zshrc, after compinit
        or: airlock completions zsh > ~/.zfunc/_airlock    with fpath+=(~/.zfunc)
```

## Help text

The top-level help groups commands by who runs them. clap has no
subcommand headings, so this needs a custom `help_template`. A test checks
that every subcommand appears in it.

### `airlock --help`

```
Airlock — credential broker for AI agents. Tools get your secrets; the agent never does.

Usage: airlock <COMMAND>

Start an agent:
  run          Run an AI agent with access to this project's tools
  init         Create a starter config
  trust        Review and approve this project's config files
  config       Show the merged config and where each part comes from
  status       Show the daemon, this project's config, and its sessions

Use tools:
  exec         Run a declared tool through your session
  tools        List the tools a session can run

Manage:
  session      Start, list, reload and end sessions
  daemon       Start, stop or install the per-user daemon; its logs
  completions  Print a bash or zsh completion script

For the agent and its harness:
  agent        Check the session and sandbox; answer harness hooks

Options:
  -h, --help     Print help
  -V, --version  Print version

Get started: `airlock init`, then `airlock run --profile claude`.
Docs: https://github.com/ModernPath/airlock
```

### `airlock --help` inside the sandbox

With `AIRLOCK_SANDBOX=1`, the help lists only the commands that work there.
It says so first and names what it hid (U16):

```
Airlock — credential broker for AI agents. Tools get your secrets; the agent never does.

You are inside an Airlock sandbox (AIRLOCK_SANDBOX=1), so this help lists
only the commands that work here. Hidden because they need your own
terminal: run, trust, status, session, daemon.

Usage: airlock <COMMAND>

Use tools:
  exec         Run a declared tool through your session
  tools        List the tools a session can run

For the agent and its harness:
  agent        Check the session and sandbox; answer harness hooks

Config:
  init         Create a starter config
  config       Show the merged config and where each part comes from
  completions  Print a bash or zsh completion script

Options:
  -h, --help     Print help
  -V, --version  Print version
```

A hidden command's own help still works, so a user who knows the command
is not left guessing:

```
$ airlock session --help
Not available inside an Airlock sandbox: run it from your own terminal.

Start, list, reload and end sessions
…
```

In a `session start` shell, `AIRLOCK_SANDBOX` is not set, and the help is
the full one.

### `airlock run --help`

```
Run an AI agent with access to this project's tools

Usage: airlock run [OPTIONS] [-- <COMMAND>...]

Loads this project's config (your global config, airlock.toml and
airlock.local.toml), asks you to approve any file that changed, resolves
its secrets and starts a session. The agent runs in an OS sandbox with
AIRLOCK_ADDR and AIRLOCK_SESSION set, so `airlock exec` and
`airlock tools list` work inside it. The session ends when the agent exits.

The daemon starts if it is not running.

Arguments:
  [COMMAND]...  The agent command and its arguments. Optional with --profile

Sandbox:
      --profile <NAME>         Sandbox rules, default command and hooks for a known agent
                               [possible values: claude, claude-relaxed]
      --allow-read <PATH>      Let the agent read PATH (repeatable)
      --allow-write <PATH>     Let the agent read and write PATH (repeatable)
      --passthrough-env <VAR>  Pass VAR from this shell to the agent (repeatable)

Session:
      --name <NAME>            Name shown by `airlock session list` [default: command name]
      --no-session             Sandbox only; `airlock exec` does not work inside

Config:
      --config <PATH>          Use exactly this file: no global or local config
      --no-project-config      Ignore airlock.toml and airlock.local.toml; use the global config

  -v, --verbose                Report each step before the agent starts
  -q, --quiet                  Do not print notes or warnings
  -h, --help                   Print help

Exit status: the agent's, or 125 if Airlock could not start it.

Examples:
  airlock run --profile claude
  airlock run --profile claude -- claude --continue
  airlock run -- codex
  op run --env-file=.env.op -- airlock run --profile claude

For a harness with its own sandbox, or an IDE, see `airlock session start`.
```

The session lasts as long as `airlock run` holds its connection to the
daemon. If `airlock run` is killed, the session ends with it.

### `airlock exec --help`

```
Run a declared tool

Usage: airlock exec -- <TOOL> [ARGS]...

Asks the daemon to run TOOL from this session's config. TOOL runs in its
own sandbox with its secrets injected; its output comes back with secret
values replaced by [REDACTED:NAME]. There is no shell: $VARS, globs, pipes
and redirects in ARGS are passed literally.

Works inside a session: an agent started with `airlock run`, or a shell
after `airlock session start`.

Exit status:
  the tool's own, or
  125  Airlock could not run it: no session, session ended, daemon unreachable,
       stale secret
  126  TOOL is declared but its binary cannot be used
  127  no tool named TOOL in this session

Environment:
  AIRLOCK_ADDR     daemon address, set by the session
  AIRLOCK_SESSION  session token, set by the session

Examples:
  airlock exec -- gh pr list
  cat body.json | airlock exec -- gh api /repos/acme/app/issues --input -
```

A tool can also exit with 125 to 127. Airlock's own errors always start
with `airlock:` on stderr.

### `airlock tools --help`

```
List the tools a session can run

Usage: airlock tools <COMMAND>

Commands:
  list  List the tools a session can run

`airlock tools` with no command is `airlock tools list`.
```

```
List the tools a session can run

Usage: airlock tools list [OPTIONS]

Asks the daemon, so the list matches what `airlock exec` accepts. Inside a
session, lists that session's tools. From your own terminal, pass
--session to see what a running agent can use. To read the config files
instead, use `airlock config`.

Options:
      --session <SESSION>  A session ID, unique ID prefix or unique name; needs your own terminal
  -h, --help               Print help
```

Inside a session, the output format does not change. With `--session`, a
first line names the session.

### `airlock agent --help`

```
Check the session and sandbox; answer harness hooks

The agent and its harness run these, not you. You can run `agent check`
yourself in a session shell to test a sandbox.

Usage: airlock agent <COMMAND>

Commands:
  check  Verify the session and self-test the sandbox
  hook   Answer a harness hook, e.g. Claude Code's SessionStart
```

```
Verify the session and self-test the sandbox

Usage: airlock agent check [OPTIONS]

Checks that this process has a working Airlock session, and that its
sandbox keeps it away from Airlock's own files: it cannot read admin.token
or write the runtime dir, the trust store or the global config, and no
tool secret is in its environment. Each probe only opens a file and
expects the open to fail.

The checks test the sandbox of the process that runs them. Run this from
the agent's own shell to test the agent's sandbox.

Options:
  -q, --quiet  Print only failures
  -h, --help   Print help

Exit status: 0 if all checks pass, 1 if one fails, 125 without a session.
```

```
Answer a harness hook

Usage: airlock agent hook <HARNESS>

Reads the harness's hook event from stdin, runs `airlock agent check` and
`airlock tools list`, and answers in the harness's hook format. On session
start the agent learns which tools to run through `airlock exec`. Prints
nothing in a project that does not use Airlock. Always exits 0.

Harnesses:
  claude-code  SessionStart hook
  text         Plain text on session start, for any other harness

Options:
      --print-settings  Print the hook configuration for the harness, then exit
  -h, --help            Print help

`airlock run --profile claude` installs the claude-code hook for you.
```

### `airlock trust --help`

```
Review and approve this project's config files

Usage: airlock trust [OPTIONS]

Shows each of airlock.toml and airlock.local.toml that differs from the copy
you approved, as a diff (or in full, the first time), and asks whether to
trust it. A session refuses to start with a file you have not approved.
`airlock run` asks the same question when it needs to; use `trust` to
approve ahead of time.

Running sessions keep their config until you reload them with
`airlock session reload`.

Options:
      --config <PATH>          Approve exactly this file
  -y, --yes                    Approve without asking, for scripted setup
      --expect-sha256 <HASH>   Approve a changed file only if its SHA-256 is HASH
                               (repeatable); fail otherwise. For CI and scripts
  -h, --help                   Print help

In CI, run it before any agent starts in the job, so nothing an agent wrote
can be approved.
```

### `airlock init --help`

```
Create a starter config

Usage: airlock init [--local | --global]

Without options, writes airlock.toml in the current directory, with
commented examples. It fails if one exists.

Options:
      --local   Write airlock.local.toml next to the project's airlock.toml, with a
                binding stub for each secret the project leaves to you. Without an
                airlock.toml, write a standalone starter
      --global  Write ~/.config/airlock/airlock.toml, your config for every project.
                Not available inside an Airlock sandbox
  -h, --help    Print help

`airlock run` asks you to approve a new project file before it is used.
```

### `airlock config --help`

```
Show the merged config and where each part comes from

Usage: airlock config [OPTIONS]

Reads the config files directly, so it needs no daemon or session. Shows
what the next session start would load: each layer's approval state, and
for every secret, tool and setting, the layer that set it. Items from a
file you have not approved are marked (unapproved). Secret values are never
shown.

Options:
      --config <PATH>        Show exactly this file
      --no-project-config    Show the global config only
      --paths                Print the layer, trust store, runtime and tool state paths, then exit
  -h, --help                 Print help
```

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

### `airlock status --help`

```
Show the daemon, this project's config, and its sessions

Usage: airlock status [OPTIONS]

Needs your own terminal. Inside a session, `airlock agent check` shows the
session.

Exit status: 0 if the daemon is running, 3 if it is not.

Options:
      --config <PATH>        Check exactly this file
      --no-project-config    Skip the project section
  -h, --help                 Print help
```

Exit status 3 follows the LSB and `systemctl status` convention. A daemon
that is not running is normal in v2, not an error.

### `airlock session --help`

```
Start, list, reload and end sessions

A session lets one agent use `airlock exec` for one project. `airlock run`
starts and ends one for you; use these commands for anything else.

Usage: airlock session <COMMAND>

Commands:
  start   Start a session and print the environment variables for it
  renew   Restart a session's TTL; the token stays the same
  list    List sessions
  reload  Apply approved config changes to running sessions
  revoke  End sessions
```

```
Start a session and print the environment variables for it

Usage: airlock session start [OPTIONS]

For a harness that `airlock run` cannot start: an IDE extension, or an
agent that runs in its own sandbox:

  eval "$(airlock session start)"

then start the harness from the same shell. Only processes started from
this shell can use the session. It ends when you revoke it, when its TTL
runs out (`airlock session renew` restarts it), or when the daemon stops.

The harness's own sandbox must deny reads of the runtime dir and keep the
agent away from your credential stores. `airlock config --paths` prints
the paths.

Options:
      --name <NAME>          Name shown by `airlock session list` [default: shell]
      --ttl <DURATION>       End the session after DURATION, e.g. 30m, 8h; 0 for never [default: 12h]
      --format <FORMAT>      [default: sh] [possible values: sh, fish, json]
      --config <PATH>        Use exactly this file: no global or local config
      --no-project-config    Use the global config only
  -q, --quiet                Do not print the sandbox note
  -h, --help                 Print help
```

```
Restart a session's TTL

Usage: airlock session renew <ID> [--ttl <DURATION>]

The token stays the same, so the harness keeps working. Only for sessions
from `session start`; an `airlock run` session lasts as long as its agent.

Options:
      --ttl <DURATION>  New TTL from now [default: the session's TTL]
```

```
List sessions

Usage: airlock session list [--here]

Options:
      --here  Only sessions for the project in the current directory
```

```
$ airlock session list
ID      NAME    PROJECT      STARTED  EXECS  ENDS                 NOTE
7f3a9c  claude  ~/src/app    10:42       14  with run, PID 48530
b20e51  codex   ~/src/app    11:30        2  with run, PID 49102  config changed
c3d2e1  vscode  ~/src/infra  09:05        0  in 6h
```

```
Apply approved config changes to running sessions

Usage: airlock session reload [ID]... [--all]

Loads each session's config again, the same way it was started (same
project, same --config or --no-project-config), asks about unapproved
files, resolves secrets, and applies it. Each session keeps its token, so
its agent keeps working. Without ID, reloads every session for the project
in the current directory.

Changes to [agent] settings (the agent's sandbox and environment) cannot
reach a running agent. The reload applies everything else and says when
the agent needs a restart.
```

```
End sessions

Usage: airlock session revoke <ID>... | --here | --all

The agent's next `airlock exec` fails with "this session has ended". An ID
prefix is enough when it is unique.
```

### `airlock daemon --help`

```
Start, stop or install the per-user daemon

You rarely need these. `airlock run` and `airlock session start` start the
daemon when it is not running, and a daemon started that way exits after
5 minutes with no sessions.

Usage: airlock daemon <COMMAND>

Commands:
  start      Start the daemon; it keeps running without sessions
  stop       Stop the daemon. Ends every session
  restart    Stop the daemon and start it again. Ends every session
  logs       Show recent daemon log entries
  install    Run the daemon as a launchd agent (macOS) or systemd user service (Linux)
  uninstall  Remove the service that `install` set up
```

```
Start the daemon; it keeps running without sessions

Usage: airlock daemon start [OPTIONS]

Options:
      --foreground  Stay in the foreground and log to stderr, for service managers
                    and debugging
  -h, --help        Print help
```

```
Show recent daemon log entries

Usage: airlock daemon logs [OPTIONS]

Options:
      --session <SESSION>  Only entries for this session
  -h, --help               Print help
```

`stop` and `restart` take `-y, --yes`. The launchd agent and the systemd
unit that `install` writes run `airlock daemon start --foreground`.

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

## Agent-facing guide (SKILL.md)

`exec` does not change. `list` becomes `tools list`, and the agent's own
check is `agent check`. What also changes is where the daemon comes from,
what the errors mean, and what happens after the agent edits the config. Draft of the changed SKILL.md sections:

> ### List available tools
>
> ```
> airlock tools list
> ```
>
> Shows the tools your session can run, with their descriptions and the
> environment they run with. Secret-backed entries appear as
> `<secret "label">`. The list comes from the daemon, so it is exactly what
> `airlock exec` accepts.
>
> ### Execute a tool
>
> *(usage unchanged)*
>
> `airlock exec` exits with the tool's exit code. Three codes mean Airlock
> itself could not run the tool, and its message starts with `airlock:`:
>
> | Exit | Meaning | What to do |
> |---|---|---|
> | 125 | No session, session ended, daemon unreachable, stale secret | Report the message to the user verbatim. Do not retry in a loop. |
> | 126 | The tool is declared but its binary cannot be used | Report the message to the user. |
> | 127 | No tool by that name | Check `airlock tools list`. Run tools that are not listed directly, without Airlock. |
>
> ### Your session
>
> The user started you with an Airlock session. Its address and token are
> in `AIRLOCK_ADDR` and `AIRLOCK_SESSION`. Do not print, copy or store the
> token. It is useless outside this session and stops working when you
> exit, but it is still a credential.
>
> If `AIRLOCK_SESSION` is not set, you were not started through Airlock, and
> `airlock exec` cannot work. Tell the user.
>
> `airlock agent check` shows your session's project, tests your sandbox,
> and says whether the config changed after the session started.
>
> ### Changing the Airlock config
>
> You may edit `airlock.toml` or `airlock.local.toml`, for example to
> declare a tool the task needs. Your change does not take effect on its
> own. The user has to approve it and reload your session. After an edit,
> tell the user what you changed and why, and ask them to run, in their own
> terminal:
>
> ```
> airlock trust
> airlock session reload
> ```
>
> Do not run `airlock trust`, `airlock run`, `airlock status`,
> `airlock session` or `airlock daemon` yourself. They need the user's
> terminal: `airlock --help` inside the sandbox hides them and says so, and
> running them anyway is refused.
>
> ### Checking your setup
>
> ```
> airlock agent check
> ```
>
> Verifies your session and tests that your sandbox keeps you away from
> Airlock's own files. If your harness already told you at start that
> Airlock is active and its self-test passed, you do not need to run it.
> Otherwise run it once before your first `airlock exec`, and report any
> `FAIL` line to the user verbatim.
>
> ## Workflow for AI Agents
>
> 1. Run `airlock tools list` to discover available tools, unless your harness
>    already listed them at start.
> 2. Run `airlock exec -- <tool> [args...]` to invoke a tool.
> 3. If you see `[REDACTED:NAME]` in output, that is expected. Do not try
>    to recover or work around redacted values.
> 4. If `airlock exec` exits with 125 or 126, report its message to the
>    user verbatim. Do not try to start the daemon or a session.
> 5. For tools not listed by `airlock tools list`, run them directly without
>    Airlock.
> 6. If you need a tool that is not declared, propose the config change,
>    make it if the user agrees, and ask the user to approve it and reload
>    the session.

The skill's frontmatter description also changes, from "run `airlock list`
to discover available tools" to: "Use when a task needs a tool that
`airlock tools list` shows; works inside an agent started with `airlock run`."

## README.md

The README keeps its order. These sections change.

### How it works

The diagram gains the launcher. Secrets come from the launcher, not from
the daemon's environment:

```
 your terminal
┌──────────────────────────────────────────────────┐
│  airlock run                                     │  reads airlock.toml + your config,
│                                                  │  asks you to approve changes,
│                                                  │  resolves secrets (op, gcloud, env)
└────────────────────────┬─────────────────────────┘
                         │ registers a session
                         ▼
┌──────────────────────────────────────────────────┐
│  airlock daemon  (one per user, starts on demand)│  ← secrets live here, per session
└──────────┬──────────────────────────▲────────────┘
           │ spawns the tool in its   │ airlock exec -- gh pr list
           │ sandbox, secrets in env; │ (session token)
           │ streams redacted output  │
           ▼                          │
┌─────────────────────┐    ┌──────────┴───────────────┐
│ gh · tofu · gcloud  │    │ agent, in its sandbox     │  ← sees only [REDACTED:NAME]
└─────────────────────┘    └───────────────────────────┘
```

Steps:

1. Declare tools and the secrets they need in `airlock.toml`.
2. `airlock run` loads the config, asks you to approve anything that
   changed, resolves the secrets in your terminal (so a 1Password or
   `gcloud` prompt reaches you), and starts a session with the daemon.
3. The agent runs `airlock exec -- gh pr list`. The daemon runs `gh` in its
   sandbox with the secret injected and streams back redacted output.

### Quick start

```bash
cargo build --release          # or download a release binary
airlock init                   # starter airlock.toml in the current directory
```

```toml
[secrets.GH_TOKEN]
source  = "command"
command = ["gh", "auth", "token"]   # or ["op", "read", "op://Private/GitHub/token"]

[tools.gh]
description = "GitHub CLI"
[tools.gh.env]
GH_TOKEN      = { secret = "GH_TOKEN" }
GH_CONFIG_DIR = "{tool_state}"
```

```bash
airlock run --profile claude   # shows the file, asks you to trust it, starts Claude Code
```

Inside, the agent runs `airlock exec -- gh pr list`. `gh` keeps its state
under `{tool_state}`, outside the project. Add `airlock.local.toml` to
git's global excludes file once (`~/.config/git/ignore`). Nothing else
Airlock writes ends up in the project.

### Supplying secrets

`source = "command"` stays the recommended way. `source = "env"` reads the
environment of `airlock run`, so the wrapper pattern keeps working:

```bash
GH_TOKEN="op://Employee/GH_TOKEN/credential" op run -- airlock run --profile claude
secretspec run -- airlock run --profile claude
```

The `airlock daemon start` variants go away.

### Team and personal config (new section)

- The three files and their precedence: a table that links the design
  doc's merge rules.
- The team pattern: the repo declares labels with a `description` and no
  `source`. Each user binds them in `airlock.local.toml`, often with
  `from = "global"`. `airlock init --local` writes the stubs.
- Why the global config does not apply to a repo label on its own: one
  paragraph, linking SECURITY.md.
- `airlock config` to see the result.

### Harness hooks (new section)

What the SessionStart hook does, the fact that `--profile claude`
installs it, and the `settings.json` block (the output of
`airlock agent hook claude-code --print-settings`) for everyone else.
`airlock agent check` for verifying a harness's own sandbox. The README's
"Where Airlock fits" list gains one line: the hook is how the agent learns
which tools go through Airlock.

### Approving config (new section)

One screen: why approval exists (the agent can edit the files), what the
prompt looks like, `airlock trust` for ahead of time and for scripts,
`airlock session reload`, and that the global file needs no approval.

### Configuration

The first paragraph changes from "home to the Unix socket and PID file" to
"Airlock keeps its runtime files outside the project; `airlock config
--paths` shows where". `[secrets.<label>]` gains `description`, and `from`
gains the value `"global"` in the local file. Tools gain
`override = true` in the local file, and the rule that a project tool
replaces a global one. Paths and templating gain `{tool_state}`. The
`airlock run` section loses `--no-config` and `AIRLOCK_SANDBOX_ROOT`, and
gains `--no-project-config`. A harness with its own sandbox moves to a
"Harness with its own sandbox, or an IDE" paragraph on `session start`,
linking SECURITY.md's external sandbox requirements.

### Command reference

```bash
airlock init [--local|--global]    # starter config
airlock run [flags] [-- <cmd>]     # start an agent with a session; the daemon starts on demand
airlock trust                      # review and approve airlock.toml / airlock.local.toml
airlock config                     # merged config and where each part comes from
airlock status                     # daemon, approval state, sessions
airlock exec -- <tool> [args...]   # (inside a session) run a declared tool
airlock tools list [--session ID]  # tools a session can run
airlock agent check                # (inside a session) verify the session, self-test the sandbox
airlock agent hook claude-code     # Claude Code hook; `--print-settings` shows how to install it
airlock session start|renew|list|reload|revoke
airlock daemon start [--foreground]|stop|restart|logs|install|uninstall
airlock completions bash|zsh       # shell completion; see "Shell completion"
```

### Install

After the binary, one line per shell for completion (the
[Installing](#installing) table). Nix and release tarball users already
have the file.

### Troubleshooting

New entries:

- **`no Airlock session`** in the agent: it was not started with
  `airlock run`, or the harness drops `AIRLOCK_*` variables. Claude Code's
  own sandbox passes them through. Check other harnesses' docs.
- **`… has changed since you last trusted it`** in a script or CI: approve
  with `airlock trust --yes` before the agent starts, or pin the content
  with `airlock trust --expect-sha256 <hash>`.
- **The agent cannot see a new tool**: `airlock session reload`.
- **Where are the socket and logs?** `airlock config --paths`.
- **After an upgrade**, `airlock status` shows the daemon's version.

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
- **Completion inside the agent sandbox.** A sandboxed
  `airlock run -- $SHELL` loads the user's `.zshrc` only if the sandbox
  can read it. `claude-relaxed` allows that; `claude` does not. Either
  document `--allow-read ~/.zshrc`, or accept that completion works only in
  unsandboxed session shells.
- **Policy diff (F3).** When it lands, the prompt shows the effective
  change above the byte diff, and a comment-only edit says so.
