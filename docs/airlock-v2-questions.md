# Airlock v2 — developer questions

Questions a developer is likely to ask when they first meet Airlock v2.
They mix "how do I use this" with "why is it built this way". Answers
belong in the README, SKILL.md and the
[design](airlock-v2-design.md) and [UX](airlock-v2-ux.md) docs. This list
is for checking that those docs cover them.

Each question has a short answer drawn from the v1 [README](../README.md),
the design doc and the UX doc, with links to where the answer lives, and a
coverage mark:

- **Covered:** the docs answer it.
- **Partial:** the docs answer part of it, or answer it only in the design
  record, not in a user-facing draft.
- **Gap:** the docs do not answer it, or contradict each other.

The gaps are collected in [Gaps](#gaps) at the end.

## Getting started

1. What is the smallest setup that lets my agent run `gh` without ever
   seeing my GitHub token?

   An `airlock.toml` with a `GH_TOKEN` secret (`source = "command"`,
   `command = ["gh", "auth", "token"]`) and a `gh` tool that takes it, then
   `airlock run --profile claude` and approve the file when asked. No daemon
   start, no `.gitignore` lines. The `claude` profile keeps `~/.config/gh`
   and the keychain out of the agent's reach.
   ([UX: First run](airlock-v2-ux.md#first-run-in-a-personal-project),
   [README: Security model](../README.md#security-model))

   **Covered.** See gap G13 on `GH_CONFIG_DIR` inside the project.

2. Do I need to start the daemon before `airlock run`, and how do I know
   whether one is running?

   No. The first launcher that finds no daemon starts one, and it exits
   after a grace period with no sessions. `airlock status` shows it, and
   exits 0 when it runs, 3 when it does not. Inside the agent,
   `airlock agent check` shows whether the daemon answers.
   ([Design: Lifecycle](airlock-v2-design.md#lifecycle),
   [UX: Options](airlock-v2-ux.md#options))

   **Covered.**

3. Where do my secrets come from: the environment, a command like `op read`,
   or somewhere else? Which should I choose?

   Two sources, as in v1: `source = "command"` runs a command in your
   terminal at session start, and `source = "env"` reads the environment
   of `airlock run` (not the daemon's any more). A local file can also bind
   a repo label to your global binding with `from = "global"`.
   ([README: Supplying secrets](../README.md#supplying-secrets),
   [Design: Registering a session](airlock-v2-design.md#registering-a-session))

   **Partial.** The docs list the options but do not say why `command` is
   preferred or when `env` is the better fit (G9).

4. Why does `airlock run` show me my own `airlock.toml` and ask me to trust
   it, when I just wrote the file myself?

   The agent can write that file too, and Airlock cannot tell who wrote
   the bytes. Approval binds the exact bytes you saw, so a file nobody
   approved is shown in full the first time.
   ([Design: Goals](airlock-v2-design.md#goals),
   [Design: What is approved](airlock-v2-design.md#what-is-approved))

   **Partial.** The reason is in the design record. The README section
   that would explain it to a user ("Approving config") is only an outline
   in the UX doc.

5. How do I use Airlock in a repository whose team has not adopted it?

   Put an `airlock.local.toml` in the project root. Either file marks the
   project, and the local file may declare its own secrets and tools. For a
   one-off directory, `--no-project-config` uses the global config alone.
   ([Design: Discovery](airlock-v2-design.md#discovery),
   [Design: `--no-project-config`](airlock-v2-design.md#--no-project-config))

   **Partial.** No journey shows it, `airlock init --local` is only
   described for a repo that has an `airlock.toml`, and the advice to add
   the file to `.gitignore` edits a file the team owns (G7).

## Sessions

6. What exactly is a session, and how is it different from the daemon?

   The daemon is one process per user that serves every project. A session
   binds one agent to one project: its root, its approved config, the
   secrets resolved for it, and a token. `exec` and `tools list` work only
   with a session token.
   ([Design: Sessions](airlock-v2-design.md#sessions),
   [UX: Options](airlock-v2-ux.md#options))

   **Covered.**

7. Why does every agent need its own session instead of just connecting to
   the daemon's socket?

   The agent runs as your uid, so reaching the socket proves nothing. On
   Linux, Landlock does not even mediate `connect` on the socket. Without
   sessions, an agent in project A could run project B's tools with B's
   secrets. Registering a session needs `admin.token`, which no Airlock
   sandbox can read, and a token per agent can end with that agent.
   ([Design: B4](airlock-v2-design.md#blocking),
   [Design: Decisions, client authentication](airlock-v2-design.md#decisions))

   **Partial.** Only in the design record. It is listed for SECURITY.md
   and ARCHITECTURE.md but not drafted.

8. How do I run two agents in the same project at the same time, and do they
   share secrets?

   Run `airlock run` in a second terminal. Each gets its own session. They
   do not share secrets: each session resolves its own, and sharing is a
   possible later optimization.
   ([UX: Every day](airlock-v2-ux.md#every-day),
   [Design: Scope](airlock-v2-design.md#scope))

   **Partial.** The docs do not say what the user notices: a second
   1Password or `gcloud` prompt, and two sets of minted tokens refreshing
   on their own schedules (G10).

9. What happens to a running agent's session when I close the terminal,
   restart the daemon, or upgrade Airlock?

   - **Closing the terminal:** `airlock run` sees its harness exit and
     revokes the session. A `session start` session lives on until its
     TTL, a revoke, or a daemon stop.
   - **Restarting the daemon:** every session ends. The agent's next
     `exec` says the session has ended. `daemon stop` and `restart` ask
     first when sessions exist.
   - **Upgrading:** a busy daemon keeps serving its sessions on the old
     version and is replaced when idle. If the protocol is incompatible,
     the launcher refuses until you run `daemon restart`.

   ([Design: Lifetime](airlock-v2-design.md#lifetime),
   [UX: Stopping things](airlock-v2-ux.md#stopping-things),
   [UX: Upgrading Airlock](airlock-v2-ux.md#upgrading-airlock))

   **Partial.** No doc says how `airlock run` handles SIGHUP, or what
   happens to a session when the launcher dies without seeing the harness
   exit (G3). After a daemon restart there is no way back into the session
   except restarting the agent; `--continue` is mentioned only for reload.

10. How do I give a session to an IDE extension that I cannot start through
    `airlock run`?

    `eval "$(airlock session start --name vscode)"`, then start the editor
    from that shell. Quit the editor first if it is already running, since
    a new window inherits the running instance's environment.
    `--format fish|json` covers other shells.
    ([UX: A harness with its own sandbox, or an IDE](airlock-v2-ux.md#a-harness-with-its-own-sandbox-or-an-ide))

    **Partial.** `session start` prints no warning that the IDE's sandbox
    must deny the runtime dir, although `--no-sandbox` does for the same
    risk. The docs also do not say that every extension and terminal in
    the editor inherits the token (G6).

11. Why does a session end when the harness exits, and why does a
    `session start` session expire after 12 hours?

    So a token the agent stashed, or a background process left behind,
    stops working when the agent is gone. A `session start` session has no
    harness to watch, so the TTL bounds a forgotten one. Without it the
    token stays valid, and the automatic daemon keeps running, indefinitely.
    ([Design: Lifetime](airlock-v2-design.md#lifetime), [Design: Commands](airlock-v2-design.md#commands))

    **Partial.** Why 12 hours is not argued, and the docs do not say what a
    user does when an IDE session expires mid-work (G11).

## Config layers and trust

12. What goes in `airlock.toml`, what goes in `airlock.local.toml`, and
    what goes in `~/.config/airlock/airlock.toml`?

    - **Repo (`airlock.toml`):** the team's tools, and the secret labels
      they need, with a `description` and usually no `source`.
    - **Local (`airlock.local.toml`, gitignored):** your bindings for the
      repo's labels (often `from = "global"`), personal tools for this
      project, and agent overrides.
    - **Global:** bindings and tools you use in every project, and agent
      settings such as `passthrough_env`. Relative paths are an error here.

    ([Design: The three files](airlock-v2-design.md#the-three-files),
    [Design: Worked examples](airlock-v2-design.md#worked-examples),
    [UX: Joining a team repo](airlock-v2-ux.md#joining-a-team-repo))

    **Covered.**

13. Why can't my global 1Password binding for `GH_TOKEN` serve the repo's
    `GH_TOKEN` automatically, without a line in `airlock.local.toml`?

    A PR could then declare a label that matches one of your global
    bindings and get your personal secret, and the reviewer would see only
    a label name. The local line is the approved opt-in, once per label per
    project.
    ([Design: B3](airlock-v2-design.md#blocking),
    [Design: Secret labels across layers](airlock-v2-design.md#secret-labels-across-layers))

    **Covered** in the design. The README paragraph is only planned. See
    G12 on `init --local` writing these lines for you.

14. Why is a tool defined in two layers an error instead of the higher layer
    winning?

    A silently shadowed tool is a security surprise: a personal tool could
    replace a team tool, or the reverse, without anyone noticing.
    ([Design: Merge rules](airlock-v2-design.md#merge-rules),
    [Design: Decisions](airlock-v2-design.md#decisions))

    **Gap.** The reason is covered, but F5 is open: there is no way out of
    the error. A global `gh` breaks every repo that also declares `gh`, and
    `gh` is the docs' main example (G4).

15. Why does approval cover the whole file byte for byte, so that even a
    comment change has to be approved again?

    It is the simplest rule to get right, with nothing to normalize or
    audit. TOML has dotted keys, and comments and strings can hide bidi or
    zero-width characters. F3 plans to show the effective policy change next
    to the byte diff and mark comment-only edits, while approval stays on
    bytes.
    ([Design: Decisions, approval unit](airlock-v2-design.md#decisions),
    [Design: F3](airlock-v2-design.md#follow-ups))

    **Covered.**

16. Why doesn't the global config file need approval when the repo and
    local files do?

    It is your own file, outside every project. Instead of approval it is
    protected by the anchor checks: it must lie outside the project and
    outside every sandbox write grant, so no sandbox can write it.
    ([Design: Protecting the anchors](airlock-v2-design.md#protecting-the-anchors))

    **Partial.** The docs allow `init` inside the sandbox because it
    writes a file that still needs approval, which is false for
    `init --global` (G8). F2 (home-manager) is open.

17. My agent added a tool to `airlock.toml`. How does it get to use that
    tool without me restarting it and losing its context?

    The agent's `exec` fails with 127 and a note that the config changed.
    You run `airlock trust`, then `airlock session reload`. The session keeps
    its token, and the agent's next `tools list` shows the new tool.
    ([UX: The agent changes the config](airlock-v2-ux.md#the-agent-changes-the-config), [Design: Reloading a session](airlock-v2-design.md#reloading-a-session))

    **Partial.** The docs do not say which settings a reload can change:
    the agent's own sandbox and environment are fixed when the agent starts
    (G2).

18. How do I approve config in CI or a setup script where nobody can answer
    a prompt?

    `airlock trust --yes`. On a non-terminal, `trust` refuses without it,
    and `run` refuses an unapproved file and points to `trust`.
    ([Design: `airlock trust`](airlock-v2-design.md#airlock-trust),
    [UX: Messages](airlock-v2-ux.md#messages))

    **Covered** after G14: `--expect-sha256` pins the content, and the
    design says `--yes` must run before any agent starts in the job, and
    why an ephemeral CI trust store makes every run a first approval.

19. How do I see the merged config, and which layer each setting came from?

    `airlock config`. It reads the files, needs no daemon, and shows each
    layer's approval state and the layer behind every secret, tool and
    setting. `--paths` prints the layer, trust store and runtime paths.
    ([UX: Options](airlock-v2-ux.md#options), [Design: Inspecting config and sessions](airlock-v2-design.md#inspecting-config-and-sessions))

    **Partial.** When a file changed since approval, the docs do not say
    whether `config` merges the current bytes or the approved copy (G15).

## Sandboxing and security

20. Why does the agent get a different sandbox from the tools it runs?

    They do different jobs. The agent needs wide read access to reason
    about code and no credentials. A tool needs one credential and its own
    config files. A misbehaving tool can expose at most the secret it was
    handed, and that is redacted before the agent reads it.
    ([README: Security model](../README.md#security-model))

    **Covered** (unchanged from v1).

21. Why do the socket, PID file and CA certificate live outside the project
    directory now?

    The project directory is writable by the agent and every tool, so they
    could replace the socket, PID file or proxy CA. The files also showed
    up in `git status`. One daemon per user also needs one place outside
    any project.
    ([Design: Problem](airlock-v2-design.md#problem),
    [Design: Runtime directory](airlock-v2-design.md#runtime-directory))

    **Covered.**

22. What stops the agent from approving its own config change, or from
    pointing Airlock at a trust store it wrote itself?

    No sandbox can write the trust store, and a write grant that covers it
    is a config error. `trust` refuses under `AIRLOCK_SANDBOX=1`, but that
    is only a convenience. XDG variables are honored, but an anchor inside
    the project or under a write grant is refused. A terminal prompt is not
    the control: an agent with a pty can answer one.
    ([Design: Protecting the anchors](airlock-v2-design.md#protecting-the-anchors),
    [Design: Threat walkthrough](airlock-v2-design.md#threat-walkthrough))

    **Covered.**

23. I already run Claude Code with its own sandbox. What do I give up with
    `airlock run --no-sandbox`, and what does that sandbox have to deny?

    `--no-sandbox` is removed. A harness with its own sandbox gets its
    session from `eval "$(airlock session start)"`, like an IDE. Compared
    with `airlock run`, you give up Airlock's agent sandbox and its denies,
    `AIRLOCK_SANDBOX=1` with its help and refusals, the filtered agent
    environment, the automatic hook install, and the session ending with
    the harness (it lasts until its TTL instead). The harness's sandbox
    must deny reads of the runtime dir, writes to the runtime dir, trust
    store and global config, reads of your credential stores, and
    inspection of other processes.
    ([Design: Commands](airlock-v2-design.md#commands),
    [Design: Under another harness](airlock-v2-design.md#under-another-harness),
    [UX: A harness with its own sandbox, or an IDE](airlock-v2-ux.md#a-harness-with-its-own-sandbox-or-an-ide))

    **Covered** after G5. The question's wording predates the removal.

24. Why does Airlock filter my `PATH` and refuse a tool binary that lives
    inside the project?

    Approval covers the config, not the programs it names. A `gh` planted
    in an agent-writable `PATH` entry would receive `GH_TOKEN`, and an
    approved `command = ["./scripts/token.sh"]` would run whatever the
    agent last wrote there. Writable entries are dropped from `PATH`, and a
    binary that resolves into the project or a write grant is refused.
    ([Design: B2](airlock-v2-design.md#blocking), [UX: Messages, agent](airlock-v2-ux.md#agent-exec-tools-list-agent-check))

    **Partial.** The reason is covered. The docs do not say what to do when
    a project legitimately ships its tool in the repo, such as
    `node_modules/.bin` or a pinned `bin/terraform` (G16).

25. Since one daemon now holds every project's secrets, what keeps one
    project's session from reaching another project's secrets?

    The session handle is the only path to secrets and config, and no
    global map holds them. Process-environment reads after startup are
    linted out. A last-pass redactor built from every live session's
    secrets masks any that leak into another session's output. Each session
    has its own cap on concurrent `exec`s. The proxy is the remaining shared risk, and F10
    moves it to its own process.
    ([Design: Session isolation](airlock-v2-design.md#session-isolation), [Design: Q1](airlock-v2-design.md#q1-one-daemon-per-user))

    **Partial.** Covers the daemon side. Not covered: one agent reading
    another agent's session token from that agent's process environment
    (G3b).

26. What does Airlock deliberately *not* protect against, such as git hooks
    or build scripts that the agent wrote and I later run?

    - Code the agent wrote that you later run outside the sandbox: git
      hooks, `core.fsmonitor`, `.envrc`, mise hooks, build scripts and
      tests. F9 adds a macOS-only `.git/hooks` deny as defense in depth.
    - An agent that runs outside `airlock run`.
    - Destructive actions through a tool: the token's scope decides those.
    - Interpreter arguments that name a project file.
    - From v1: redaction is best-effort, tools have unrestricted network,
      and local root can read daemon memory.

    ([Design: Non-goals](airlock-v2-design.md#non-goals),
    [Design: B1, B2](airlock-v2-design.md#blocking),
    [README: What you get, Known limits](../README.md#what-you-get))

    **Covered**, across three docs. The single SECURITY.md entry is planned.

## Agent integration and day-to-day use

27. How does my agent find out which tools it must run through
    `airlock exec`, if it never reads SKILL.md?

    A SessionStart hook (`airlock agent hook claude-code`) puts the session
    state and the tool list in the agent's context on start, resume,
    `/clear` and compaction. `--profile claude` installs it. Other setups
    add the `settings.json` block that `--print-settings` prints, and other
    harnesses can use `airlock agent hook text`.
    ([UX: Harness hooks](airlock-v2-ux.md#harness-hooks), [Design: Agent integration](airlock-v2-design.md#agent-integration))

    **Partial.** Claude Code only. `airlock run -- codex` appears as an
    everyday example but gets no hook, and the docs name no other harness
    that `hook text` fits (G17). Whether `--settings` merges with the
    user's own hooks is an open question.

28. What does `airlock agent check` actually test, and why can't a passing
    result prove that the agent is contained?

    It checks the session and daemon, that `admin.token` cannot be opened,
    that the runtime dir, trust store and global config cannot be written,
    that no tool secret name is set in its environment, and whether the
    config changed. It tests only the process that runs it: a hostile agent
    could fake the output, and under an external sandbox the hook may run
    outside that sandbox.
    ([UX: What `airlock agent check` verifies](airlock-v2-ux.md#what-airlock-agent-check-verifies))

    **Covered.** It does not probe the user's credential stores
    (`~/.config/gh`, `~/.config/gcloud`), which is the core promise (G18).

29. Why does `airlock exec` exit with 125, 126 or 127 for some failures
    instead of 1?

    Exit 1 is the most common tool failure, so it cannot also mean "Airlock
    failed". 125 means Airlock could not run the tool (tell the user), 126
    that the binary cannot be used, and 127 that no such tool is declared.
    This follows `docker run`, `env` and `chroot`. Airlock's own messages
    start with `airlock:`.
    ([Design: Clients](airlock-v2-design.md#clients),
    [UX: Options](airlock-v2-ux.md#options))

    **Covered.** See G19 on `run` exiting 1 when you decline approval.

30. Why are `airlock status`, `airlock trust` and `airlock session` missing
    from `airlock --help` when I run it inside the sandbox?

    With `AIRLOCK_SANDBOX=1`, help lists only commands that work there and
    names the hidden ones. Those need your terminal: they read
    `admin.token` or write the trust store, which no sandbox can. A hidden
    command's own `--help` still works.
    ([Design: Commands refused inside the sandbox](airlock-v2-design.md#commands-refused-inside-the-sandbox),
    [UX: Options](airlock-v2-ux.md#options))

    **Covered.**

## Gaps

Each gap was reviewed with a proposal, an alternative and "ignore". The
decisions are written into the [design](airlock-v2-design.md) and
[UX](airlock-v2-ux.md) docs, except where a gap is ignored.

| # | Gap | Decision | Where |
|---|---|---|---|
| G1 | U1–U16 not folded into the design | Folded in; the UX table stays as the record | design throughout |
| G2 | What `session reload` can change | Applies everything but `[agent]`, and says when the agent needs a restart. Reuses the session's recorded root and mode. An `exec` in flight finishes on the old config. | [Reloading a session](airlock-v2-design.md#reloading-a-session) |
| G3 | A session outlives a launcher that dies | `airlock run` holds a lease: the `Register` connection stays open, close-on-exec, and the daemon revokes the session on EOF. The launcher forwards signals and closes last. | [Lifetime](airlock-v2-design.md#lifetime) |
| G3b | Token theft between agents through process inspection | Acknowledged, and tokens are bound to the anchor process's tree by peer PID. Two items to verify: Seatbelt `same-sandbox` semantics, and editors descending from the shell. | [Token binding](airlock-v2-design.md#token-binding) |
| G4 | Tool collisions have no way out (F5) | A project tool replaces a global one, visibly; repo against local stays an error unless the local tool says `override = true` | [Tools across layers](airlock-v2-design.md#tools-across-layers) |
| G5 | `--no-sandbox` contract | `--no-sandbox` removed; `session start` serves harnesses with their own sandbox; an external sandbox checklist | [Commands](airlock-v2-design.md#commands), [Under another harness](airlock-v2-design.md#under-another-harness) |
| G6 | IDE sessions | `session start` warns about the external sandbox; docs say what inherits the token and that a Dock-launched editor gets none | [Commands](airlock-v2-design.md#commands), [UX journey](airlock-v2-ux.md#a-harness-with-its-own-sandbox-or-an-ide) |
| G7 | Repos without Airlock | `init --local` writes a standalone skeleton; the warning suggests git's global excludes file | [Secret labels across layers](airlock-v2-design.md#secret-labels-across-layers), [UX journey](airlock-v2-ux.md#a-repo-whose-team-has-not-adopted-airlock) |
| G8 | `init --global` inside the sandbox | Refused, and hidden from help | [Commands refused inside the sandbox](airlock-v2-design.md#commands-refused-inside-the-sandbox) |
| G9 | Choosing a secret source | Ignored | — |
| G10 | Two sessions in one project | Documented: secret commands run again per session | [Scope](airlock-v2-design.md#scope), [UX: Every day](airlock-v2-ux.md#every-day) |
| G11 | Session TTL | 12h is one working day; `session renew` keeps the token; expiry has its own message | [Lifetime](airlock-v2-design.md#lifetime) |
| G12 | `from = "global"` hides the binding in the prompt | The prompt annotates each line with the global source; display only | [Unapproved files at session start](airlock-v2-design.md#unapproved-files-at-session-start) |
| G13 | `GH_CONFIG_DIR` inside the project | `{tool_state}` placeholder under `$XDG_CACHE_HOME/airlock/<id>/<tool>` | [Tool state outside the project](airlock-v2-design.md#tool-state-outside-the-project) |
| G14 | CI approval | `trust --expect-sha256 <hash>`; `--yes` before any agent starts | [`airlock trust`](airlock-v2-design.md#airlock-trust) |
| G15 | `config` on a changed file | Shows what the next session start would load, marks `(unapproved)`, and says when the global layer is unreadable | [Inspecting config and sessions](airlock-v2-design.md#inspecting-config-and-sessions) |
| G16 | Project-local tool binaries | No override; the 126 error suggests installing outside the project | [Clients](airlock-v2-design.md#clients) |
| G17 | Harnesses other than Claude Code | Ignored | — |
| G18 | `agent check` and credential stores | Warning-level read probes for tools' `extra_read` paths and the well-known stores | [Agent integration](airlock-v2-design.md#agent-integration) |
| G19 | Exit status on declined approval | 125, `not trusted; nothing started` | [Unapproved files at session start](airlock-v2-design.md#unapproved-files-at-session-start) |

### Answered only in the design record

Q4, Q7, Q13, Q24 and Q25 are answered in the design doc's decisions and
blocking items, which a user will not read. The design doc's
[Docs to update when this ships](airlock-v2-design.md#docs-to-update-when-this-ships)
lists the README and SECURITY.md sections that will carry them.
