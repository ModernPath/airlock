# airlock

Credential broker for AI agents — tools get your secrets, the agent never does.

An AI coding agent needs `gh`, `tofu`, `gcloud`, `kubectl` to do real work, and those tools need credentials. Hand the agent a token and it sits in the agent's environment, its shell history, and every line of output it reads. Airlock takes the token out of the agent's reach: a per-user daemon holds secrets in memory and injects them only into the specific tool processes that need them, runs each tool in an OS sandbox, and redacts its output before the agent sees it.

Airlock brokers credentials for the tools your agent *runs*, not just the APIs it *calls*. The CLI authenticates exactly as it always has — the agent simply never holds the key.

## Contents

- [What you get](#what-you-get)
- [How it works](#how-it-works)
- [Where Airlock fits](#where-airlock-fits)
- [Security model](#security-model)
- [Quick start](#quick-start)
- [Supplying secrets](#supplying-secrets)
- [Team and personal config](#team-and-personal-config)
- [Approving config](#approving-config)
- [Sessions](#sessions)
- [Harness hooks](#harness-hooks)
- [An always-on daemon](#an-always-on-daemon)
- [Minting scoped credentials](#minting-scoped-credentials)
- [Configuration](#configuration)
- [Kits](#kits)
- [Command reference](#command-reference)
- [Troubleshooting](#troubleshooting)
- [Building](#building)
- [Further reading](#further-reading)
- [How Airlock compares](#how-airlock-compares)
- [License](#license)

## What you get

- **Tool secrets never reach the agent.** They exist in the daemon's memory (zeroized on drop) and in the tool process's environment — nowhere else. Not in the agent's env, not in its output.
- **Scoped, short-lived credentials without long-lived keys.** The daemon can *mint* a token from your own session — impersonate a read-only service account, for instance — and re-mint it before it expires. Your admin login never enters the sandbox; the tool gets a token that can only do what you decided; the agent gets neither. See [Minting scoped credentials](#minting-scoped-credentials).
- **Redacted output.** Secret values are stripped from stdout/stderr — raw, base64, URL-encoded, and hex forms — and replaced with `[REDACTED:NAME]`.
- **Sandboxed tools and agent.** Every tool, and the agent itself under `airlock run`, gets deny-by-default filesystem access (macOS Seatbelt, Linux Landlock) and a minimal environment.
- **Nothing in the project but config.** The daemon's socket, PID file and proxy CA live in a per-user runtime directory outside any project. `git status` shows only `airlock.toml` and, if you forgot to ignore it, `airlock.local.toml`.
- **Any secret source.** 1Password, Vault, cloud secret managers, plain env vars, or any command that prints a token.

What Airlock does *not* do: stop the agent from doing destructive things *through* a tool. If the token can delete repos, `gh repo delete` works. Airlock keeps the token from leaking; the token's scope decides what it can do — which is why minting narrow tokens matters. Full threat model in [SECURITY.md](SECURITY.md).

## How it works

One daemon per user serves every project on your machine. `airlock run` is a **launcher**: it runs in your terminal, loads and approves a project's config, resolves its secrets, and hands the result to the daemon as a **session**. The agent gets a session token and a sandbox; the daemon serves that session only the one project.

```
┌──────────────────────────────┐    ┌──────────────────────────────────┐
│  env vars at `airlock run`   │    │  command sources                 │
│  op run · secretspec · vault │    │  op read · gcloud auth            │
│  · plain exports             │    │  print-access-token · …           │
└──────────────┬───────────────┘    └────────────────┬─────────────────┘
               │ read once by the launcher,           │ spawned by the launcher,
               │ held only for `Register`              │ re-run by the daemon on
               ▼                                       │ its own `refresh` schedule
          ┌──────────────────────────────────────────────────┐
          │              airlock daemon (per user)            │  ← secrets live here (in memory)
          │         one session per registered project        │
          │                 Unix socket API                   │
          └─────────────────────────┬────────────────────────┘
                                    │ spawns tool in sandbox with secrets injected;
                                    │ streams back redacted stdout/stderr
                                    ▼
          ┌──────────────────────────────────────────────────┐
          │          airlock exec  (client / agent)          │  ← no access to secrets
          │                                                  │     sees only [REDACTED:NAME]
          └──────────────────────────────────────────────────┘
```

1. Declare tools and the secrets they need in `airlock.toml`.
2. `airlock run` resolves every secret in your terminal: `env` sources are read from the launcher's own environment, `command` sources are spawned there, re-run on a schedule by the daemon if `refresh` is set. Neither reaches the daemon's own environment — the launcher sends values once, over the socket, and the daemon never reads its own `$PATH` or env for this.
3. The agent runs `airlock exec -- gh pr list`. The daemon injects the secrets into a minimal child environment, spawns `gh` inside the sandbox, and streams back redacted output.

Only tools that need credentials go through Airlock. `grep`, `cargo`, `npm`, `make` and the rest run directly through the agent's own sandbox. `git` goes either way: run it directly for reads and local commits; declare it as a tool when signed commits or HTTPS pushes need a GPG key or credential-helper token.

## Where Airlock fits

Airlock is one layer of a defense-in-depth stack:

1. **Secret storage** — 1Password, Vault, a cloud secret manager. Never `.env` files or shell history.
2. **Scoped tokens** — fine-grained PATs, least-privilege service accounts. **This is the layer that limits damage.** Airlock can mint these for you ([below](#minting-scoped-credentials)).
3. **Airlock** — credential isolation at runtime: secrets in memory, injected per tool, output redacted.
4. **Agent harness sandbox** — `airlock run`, Claude Code's `--sandbox`, Docker, nsjail, bubblewrap. Without it, the agent could read the daemon's memory or connect to the socket directly. `airlock run` provides this directly; a harness with its own sandbox gets a session a different way — see [Sessions](#sessions).

## Security model

Airlock splits your machine into three zones with different levels of trust:

```
┌─ your session (no sandbox) ─────────────────────────────────────────┐
│  airlock daemon — runs as you, outside any sandbox                  │
│  holds secrets in memory · uses your real logins to mint tokens     │
│                                                                     │
│   ┌─ agent sandbox ───────────┐    ┌─ tool sandbox (per exec) ───┐  │
│   │  claude / codex / …       │    │  gh · gcloud · kubectl · …  │  │
│   │  sees: project files,     │───▶│  sees: project files, its   │  │
│   │  redacted tool output     │    │  own config, and only the   │  │
│   │  never sees: secrets      │    │  secret it was declared for │  │
│   └───────────────────────────┘    └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

- **The daemon is trusted and runs unsandboxed, as you.** That is deliberate: it needs your real `gcloud` login or `op` session to mint scoped tokens, and it is the one place raw secrets live. The agent can reach it only over a Unix socket, and only with a **session token** it was handed at start — the socket's permissions alone are not the authorization boundary, because every process on your machine shares your uid. See [Sessions](#sessions).
- **The agent gets a sandbox shaped for an agent.** Read/write to the project and its own state directory, nothing else — no `~/.ssh`, no keychain, no daemon memory. `airlock run` provides this; Claude Code's own `--sandbox` or a container works too.
- **Each tool gets its own sandbox, shaped for that tool.** This is the part most setups skip. `gh` sees the repo and its own config dir but not `~/.config/gcloud`; `gcloud` gets the reverse. A compromised or misbehaving tool can expose at most the one secret it was handed — and even that is redacted before the agent reads it.
- **The project holds only config.** No socket, no PID file, no CA certificate, and no record of what you've approved. Those live in a per-user runtime directory, a trust store and a global config file, all outside the project and outside every sandbox's write grants.

Two sandboxes because the agent and the tools have different jobs: the agent needs wide read access to reason about code but no credentials; a tool usually needs one credential plus its own config files. Even the config files can be kept out of your real home directory, and out of the project — `{tool_state}` (see [Configuration](#configuration)) gives each tool a private directory the agent can't read and `git status` never sees.

Full threat model, the external-sandbox requirements for a harness like Claude Code's own `--sandbox`, and what Airlock does *not* protect against: [SECURITY.md](SECURITY.md).

## Quick start

```bash
cargo build --release          # or download a release binary (Linux amd64, macOS arm64)
airlock init                   # writes a starter airlock.toml in the current directory
```

A minimal `airlock.toml`:

```toml
[secrets.GH_TOKEN]
source = "env"                 # read GH_TOKEN from the launcher's environment

[tools.gh]
description = "GitHub CLI"

[tools.gh.env]
GH_TOKEN      = { secret = "GH_TOKEN" }
GH_CONFIG_DIR = "{tool_state}"   # project-local gh state, outside the project and the agent's reach
```

Edit it, then start the agent:

```bash
$ GH_TOKEN="ghp_xxxx" airlock run --profile claude
airlock.toml is not trusted yet. Contents:

    [secrets.GH_TOKEN]
    source = "env"
    …

Trust this file and continue? [y/N] y
trusted airlock.toml
```

That's it: no `airlock daemon start`, nothing to add to `.gitignore`. The first `airlock run` in a project starts the daemon on demand (it exits again once nothing uses it) and asks you to approve `airlock.toml`, once per version of the file. Claude starts inside its own sandbox with a session already registered; `gh` runs through `airlock exec`.

Inside the agent:

```
$ airlock exec -- gh auth status
github.com
  ✓ Logged in to github.com account acme (GH_TOKEN)
  - Token: [REDACTED:GH_TOKEN]
```

Every later `airlock run` in the project is quiet unless something changed:

```bash
$ airlock run --profile claude
```

More configs in [`examples/`](examples/). For a scripted, end-to-end tour — config layers, approval, a redacted `exec`, `agent check`, the sandboxed `airlock run` path — run [`examples/demo/demo.sh`](examples/demo/demo.sh).

## Supplying secrets

Each `[secrets.<label>]` entry is either read from the launcher's environment at session start (`source = "env"`) or produced by a command the launcher runs (`source = "command"`). Either way, the value is sent to the daemon once, over the socket, and never touches the daemon's own process environment.

```bash
# 1Password CLI
GH_TOKEN="op://Employee/GH_TOKEN/credential" op run -- airlock run --profile claude

# secretspec
secretspec run -- airlock run --profile claude

# Hashicorp Vault, or any shell
GH_TOKEN=$(vault kv get -field=token secret/github) airlock run --profile claude
```

Or skip the environment entirely and let the launcher fetch the value:

```toml
[secrets.GH_TOKEN]
source  = "command"
command = ["op", "read", "op://Employee/GH_TOKEN/credential"]   # argv list, no shell
```

Add `refresh` and the daemon re-runs the same command in the background to mint short-lived tokens. See [`examples/secret-sources.toml`](examples/secret-sources.toml) for ready-made `command` sources (1Password, Vault, `gh auth token`, `gcloud`) and the `op run -- airlock run` pattern.

## Team and personal config

A real project has three layers, lowest to highest precedence:

| Layer | Path | Checked in? | Approved? |
|---|---|---|---|
| **global** | `~/.config/airlock/airlock.toml` | no, it's yours | no — protected by anchor checks instead |
| **repo** | `airlock.toml` | yes | yes |
| **local** | `airlock.local.toml` | no, gitignored | yes |

The repo file is the team's: it declares tools and the secret labels they need, but it does not have to say *where* your copy of a secret comes from — one teammate reads `GH_TOKEN` from 1Password, another runs `gh auth token`. Leave `source` out of a repo `[secrets.<label>]` and add a `description`; each user binds it locally:

```toml
# airlock.toml (repo, checked in)
[secrets.GH_TOKEN]
description = "GitHub token with read access to acme/app"
```

Your global config binds things you use in every project:

```toml
# ~/.config/airlock/airlock.toml (global, yours)
[secrets.GH_TOKEN]
source  = "command"
command = ["op", "read", "op://Private/GitHub/token"]
```

A global binding does not automatically apply to a repo label — that would let a PR reach into your password manager without your say. You opt in per project, per label, in the local file:

```bash
$ cd ~/src/app && airlock init --local
created ~/src/app/airlock.local.toml
  GH_TOKEN  from = "global" (your global config binds it)
airlock.local.toml is ignored by git
```

`airlock init --local` writes a stub: `from = "global"` for any label your global config already binds, and a commented `command`/`env` example for the rest. Edit it, approve it like any other file. In a repo whose team hasn't adopted Airlock, `airlock init --local` instead writes a standalone skeleton — a commented secret and tool, like `airlock init` writes for `airlock.toml` — and nothing lands in the team's `.gitignore`.

Since `airlock.local.toml` is personal, ignore it once for every repo instead of editing each project's `.gitignore`:

```bash
echo airlock.local.toml >> ~/.config/git/ignore
```

(`airlock init --local` warns if it isn't ignored yet, and prints this line.)

A tool defined in both the repo and local files is a config error unless the local tool sets `override = true` — the user approves that line along with the file. A personal tool in your global config quietly gives way to a project tool of the same name; `airlock config` shows the layer each tool and secret comes from.

## Approving config

The daemon never acts on a project config file you haven't approved — including one the agent edited. `airlock.toml` and `airlock.local.toml` are each approved on their own, by the exact bytes.

```bash
$ airlock trust
~/src/app/airlock.toml has changed since you last trusted it:

--- trusted
+++ ~/src/app/airlock.toml
@@ -14,3 +14,8 @@
 ...
+[tools.psql]
+description = "Postgres shell"

Trust this version? [y/N] y
trusted ~/src/app/airlock.toml
```

`airlock run` and `airlock session start` ask the same question inline, the first time they see an unapproved file, so you don't need a separate `trust` step for every edit of your own `airlock.local.toml`. On a non-interactive shell they refuse instead and point you at `airlock trust`.

Control characters, ANSI escapes and bidirectional/zero-width Unicode in the diff are shown escaped (`\u{202e}`), so an agent can't hide a change by making the diff read differently from what it does.

For scripts and CI:

```bash
airlock trust --yes                              # approve every changed file, no prompt
airlock trust --expect-sha256 <hash>             # approve only if the file matches exactly
```

In CI the trust store is usually empty on every run, so `trust --yes` there means the review of the commit under test *is* the approval — run it before any agent starts in the job. `--expect-sha256` pins the exact bytes a workflow expects, closing even that window.

The global file needs no approval: it's yours, outside every project, and protected the same way the runtime directory and trust store are — no sandbox can write it or redirect Airlock to a copy it wrote. See [SECURITY.md](SECURITY.md) for the anchor checks behind that.

A running agent keeps the config it started with even after you approve a change — nothing changes under it until you ask:

```bash
$ airlock session reload
reloaded 7f3a9c "claude": tools +psql
```

## Sessions

`airlock run` is a **launcher**: it loads and approves config, resolves secrets, registers a session with the daemon, and runs the agent inside Airlock's own sandbox for as long as the session lasts. Several agents can run against the same project at once, each with its own session and its own resolved secrets.

A harness with its own sandbox — Claude Code's own `--sandbox`, or an IDE extension `airlock run` can't wrap — gets a session a different way:

```bash
$ eval "$(airlock session start --name claude)"
session 7f3a9c "claude" for ~/src/app, expires in 12h
note: this harness runs in its own sandbox, or none. It must deny reads of
      the runtime directory and keep the agent away from your credential
      stores; see SECURITY.md#external-sandboxes
$ claude --sandbox
```

`session start` prints `export AIRLOCK_ADDR=...` / `export AIRLOCK_SESSION=...` on stdout (so `eval` picks them up) and the note above on stderr. Everything started from that shell inherits the session — every extension, every integrated terminal in an editor launched from it. It lasts 12 hours by default (`--ttl`, `0` for until revoked); `airlock session renew` restarts the clock without changing the token.

Run `eval "$(airlock session start)"` directly in the shell that will use the session — that shell is the token's anchor. Piping the output through another command, as in `eval "$(airlock session start | cat)"`, anchors the session to that pipeline's own short-lived subshell instead; the subshell exits the moment the pipe finishes, so every later `exec` fails with "this process was not started from the session's agent or shell" even though the token looks valid. See [Token binding](SECURITY.md#token-binding).

| Command | Does |
|---|---|
| `airlock session start` | Registers a session, prints the exports. |
| `airlock session renew <ID>` | Restarts a `session start` session's TTL. |
| `airlock session list` | Lists sessions: id, name, project, started, number of `exec`s, what ends it, whether the config has changed. |
| `airlock session reload [ID...]` | Applies approved config to running sessions, without restarting the agent. |
| `airlock session revoke <ID...>` / `--here` / `--all` | Ends sessions. |

A token is bound to the process tree it was issued to, so copying it out of another process's environment is useless outside that tree — see [SECURITY.md](SECURITY.md#token-binding).

## Harness hooks

`airlock run --profile claude` installs a Claude Code `SessionStart` hook that tells the agent, in its own context, that Airlock is active and which tools to use — on every start, resume, `/clear` and compaction, not only when it happens to read [SKILL.md](SKILL.md). To do this, the profile's default command passes `claude --dangerously-skip-permissions --settings '<hook JSON>'`: `--settings` carries the hook plus `"sandbox":{"enabled":false}`, since Claude Code's own `sandbox-exec` wrapper can't nest inside Airlock's — the outer Seatbelt profile already confines the agent, and `--dangerously-skip-permissions` is safe here for the same reason: Airlock's sandbox, not Claude's own permission prompts, is the boundary. Starting Claude another way, add the hook to `~/.claude/settings.json` or the project's `.claude/settings.json` yourself:

```bash
airlock agent hook claude-code --print-settings
```

prints the exact JSON block to paste in, so the docs and the binary can't drift apart. The agent can remove the hook; nothing security-relevant depends on it.

## An always-on daemon

By default the daemon starts on the first `airlock run` or `session start` and exits a few minutes after its last session ends. For a daemon that survives across sessions — useful if you use `session start` from several shells across a day — install it as a service:

```bash
$ airlock daemon install
wrote ~/Library/LaunchAgents/ai.modernpath.airlock.plist
loaded it: the daemon now starts at login and keeps running without sessions
```

On Linux this writes a systemd user unit; `loginctl enable-linger` keeps it running after you log out. `airlock daemon uninstall` removes it. `airlock status` shows how the daemon was started.

## Minting scoped credentials

You are logged into your cloud provider with broad permissions. You want an agent to inspect deployed systems — pods, rollouts, load balancers — but not modify them, and certainly not as *you*. The usual fix is a long-lived key for a read-only service account: now you have a key to store, rotate, and worry about.

With Airlock you skip the key. The daemon uses your session to mint a token *as* the read-only account, hands only that token to the sandboxed tools, and re-mints it before it expires:

```toml
# Resolved once at session registration, then re-run by the daemon every
# 50 min. Runs on the trusted side with the launcher's environment, so it
# can read ~/.config/gcloud — the sandboxed tools cannot.
[secrets.CLOUDSDK_AUTH_ACCESS_TOKEN]
source  = "command"
command = [
  "gcloud", "auth", "print-access-token",
  "--impersonate-service-account=agent-readonly@my-project.iam.gserviceaccount.com",
]
env     = { CLOUDSDK_CORE_ACCOUNT = "you@example.com" }   # which of your accounts impersonates
timeout = 30
refresh = 3000                                            # tokens live 1 h
refresh_max_backoff = 600

[tools.gcloud.env]
CLOUDSDK_AUTH_ACCESS_TOKEN = { secret = "CLOUDSDK_AUTH_ACCESS_TOKEN" }
CLOUDSDK_CONFIG = "{tool_state}"   # sandboxed gcloud never sees ~/.config/gcloud

[tools.kubectl.env]                                    # GKE auth plugin resolves the same env
CLOUDSDK_AUTH_ACCESS_TOKEN = { secret = "CLOUDSDK_AUTH_ACCESS_TOKEN" }
CLOUDSDK_CONFIG = "{tool_state}"
KUBECONFIG      = "{sandbox_root}/.kube/config"   # written by gcloud, read by kubectl — see below
```

`{tool_state}` is exclusive to the tool that declares it — nothing else, not even another tool, can read it. `CLOUDSDK_CONFIG` only needs to be its own tool's cache, so each tool above gets a private one. `KUBECONFIG`, written once by `gcloud container clusters get-credentials` and read by `kubectl`, has to be shared between the two tools, so it stays under `{sandbox_root}` — the project directory, which every tool can already reach.

| | Your admin credentials | The minted read-only token |
|---|---|---|
| Airlock daemon | ambient, via `~/.config/gcloud` — never copied into the secret store | in memory, zeroized on drop |
| `gcloud` / `kubectl` in the sandbox | **no** — path is outside their filesystem policy | injected as an env var at spawn |
| The agent | **no** | **no** — sees `[REDACTED:CLOUDSDK_AUTH_ACCESS_TOKEN]` |

The permission boundary is the service account's IAM bindings. Airlock doesn't enforce it; it makes sure nothing *broader* ever reaches the sandbox.

**Minting failures fail closed.** If your gcloud session expires overnight, the next re-mint fails, the secret is marked stale, and `airlock exec -- gcloud …` returns an error naming the stale secret instead of running with a dead token. The daemon retries with exponential backoff (5 s, 10 s, 20 s … capped at `refresh_max_backoff`) and recovers on its own once you `gcloud auth login` again.

The pattern fits any CLI that prints one short-lived token to stdout — GitHub App installation tokens, Vault dynamic secrets, most OAuth access tokens. **AWS is the exception:** `aws sts assume-role` returns three coupled values and a `command` source yields one. Until multi-value sources land ([TODO.md](TODO.md)), use scoped static keys as in [`examples/cloud-providers.toml`](examples/cloud-providers.toml). The full GCP walkthrough with IAM setup is in [`examples/gcp-impersonation.toml`](examples/gcp-impersonation.toml).

## Configuration

A project needs `airlock.toml` or `airlock.local.toml` somewhere between the current directory and `$HOME` (discovery walks up, as today); its directory is the **sandbox root** — always read-write for tools, and the base every relative path in the config resolves against. `--no-project-config` runs with only your global config, for a directory with no project file.

> Don't put `airlock.toml` directly in `$HOME` — that makes your entire home directory the sandbox root. Airlock refuses to start unless the config sets `allow_home_root = true` (only honored in the global or local layer).

```toml
timeout = 120                  # global tool timeout in seconds (default: 300)
access  = "default"            # default sandbox filesystem baseline for every tool (see below)

[filesystem]                   # paths beyond the baseline, for every tool
write = ["/tmp"]

[secrets.GH_TOKEN]
source = "env"                 # `from` defaults to the label

[secrets.CLOUDFLARE_API_TOKEN]
source  = "command"
command = ["op", "read", "op://Infrastructure/Cloudflare/api_token"]

[tools.gh]
extra_read = ["~/.config/gh"]
timeout = 60

[tools.gh.env]
GH_TOKEN = { secret = "GH_TOKEN" }
GH_HOST  = "github.com"

[tools.tofu]
extra_read  = ["~/.terraform.d"]
extra_write = [".terraform", "terraform.tfstate"]

[tools.tofu.env]
CLOUDFLARE_API_TOKEN = { secret = "CLOUDFLARE_API_TOKEN" }
TF_INPUT             = "0"
```

Unknown keys are a config error at every level, in every layer — a typo fails loudly instead of being silently ignored.

### `[secrets.<label>]`

| Field                 | Applies to | Description |
|-----------------------|------------|-------------|
| `source`              | all        | `"env"` or `"command"`. Optional in the repo layer only: a label with no `source` says "this project needs this secret" and leaves the binding to each user — see [Team and personal config](#team-and-personal-config). |
| `from`                | `env`; or any layer as `from = "global"` | For `source = "env"`, the launcher env var to read; defaults to the label. In the local layer only, `from = "global"` instead reuses the global config's binding of the same label, and is mutually exclusive with `source`. |
| `command`             | `command`  | Argv list to spawn; trimmed stdout becomes the value. No shell. |
| `timeout`             | `command`  | Seconds to wait for the command. Default 10. |
| `refresh`             | `command`  | Seconds between background re-runs. Omit to fetch once at session start. |
| `refresh_max_backoff` | `command`  | Cap on backoff between failed refreshes. Defaults to `refresh`. |
| `env`                 | `command`  | `NAME = "value"` map applied when spawning the command. |
| `env_clear`           | `command`  | `true` gives the command a completely empty environment — no `PATH`, no `HOME`. Add back what it needs via `env`. |
| `description`         | all        | Shown in the "needs a source" error and by `airlock init --local`. |

> **Command sources run unsandboxed, on the trusted side**, with the launcher's environment and filesystem (never the daemon's own). That is what lets them derive narrow credentials from broad ones. Only configure commands you would run yourself at the shell.

### `[tools.<name>]`

| Field         | Description |
|---------------|-------------|
| `env`         | `NAME = value` map. A bare string is static; `{ secret = "label" }` resolves a secret. |
| `description` | Shown by `airlock tools list`. |
| `extra_read`  | Additional read-only paths. |
| `extra_write` | Additional read-write paths. |
| `timeout`     | Per-tool timeout in seconds; overrides the global value. |
| `access`      | Sandbox filesystem baseline for this tool; overrides the top-level `access`. One of `"none"`, `"system"`, `"default"` — see below. |
| `override`    | Local layer only. Replaces the repo's tool of the same name whole; a config error if the repo defines no such tool. |
| `proxy`       | `true` marks a *proxy tool*. See [Proxy tools](#proxy-tools). A proxy tool needs at least one route and may not have secrets in `env`. |
| `routes`      | `[[tools.<name>.routes]]`. Each route names a host the proxy tool may reach, an optional credential header to attach, and optional `METHOD /path` allow/deny rules. |

> **Only declare purpose-built CLIs as tools.** Never declare shells (`bash`), interpreters (`python`, `node`), or any tool where the agent controls the request. If the agent can script the tool, it can transform secrets past the redactor or upload `/proc/self/environ`. `curl` is the one exception, and only as a [proxy tool](#proxy-tools). A proxy tool never holds a secret, so it has no secret to leak. See [SECURITY.md](SECURITY.md#tool-selection-what-should-and-should-not-be-an-airlock-tool).

#### `access`: how much of the system a tool's sandbox sees

Every tool's sandbox always gets its own binary, the project root (read-write), `[filesystem]`, and its own `extra_read`/`extra_write` — `access` governs only the *built-in* filesystem baseline layered on top of that:

| Level       | Gets |
|-------------|------|
| `"none"`    | Just the dynamic linker and shared library cache (so the binary can start) plus `/dev/null`. Nothing else of the system. |
| `"system"`  | `"none"` plus today's baseline: system libraries, binaries, shared data, and configuration (`/usr/lib`, `/usr/bin`, `/etc`, `/dev/{null,zero,random,urandom}`, ...). |
| `"default"` | `"system"` plus read-only `/nix/store`, `/opt/homebrew`, `/usr/local`, `/opt/local`, and `/home/linuxbrew/.linuxbrew` — the common toolchain install roots. **The default when `access` is unset**, at the top level or per tool. |

Set the top-level `access` to change the project default, or a tool's own `access` to override it for just that tool — a config error names the three valid levels if either is misspelled.

### Proxy tools

Use a proxy tool when the API you need has no CLI. A proxy tool is a general HTTP client, such as `curl`. Its only network path is a proxy inside the daemon. The proxy attaches the credential *after* the request has left the tool. So the tool never holds a secret, and nothing the agent can read out of the tool is useful to an attacker.

```toml
# Minted on the trusted side, refreshed before expiry. The tool never sees it.
[secrets.gcp_token]
source  = "command"
command = ["gcloud", "auth", "print-access-token",
           "--impersonate-service-account=agent-ro@my-project.iam.gserviceaccount.com"]
refresh = 3000

[tools.curl]
description = "HTTP client for Google Cloud REST APIs (authenticated automatically)"
proxy = true

[[tools.curl.routes]]
host   = "*.googleapis.com"
inject = { header = "Authorization", value = "Bearer {secret}", secret = "gcp_token" }
allow  = ["* /v2/projects/my-project/**"]
deny   = ["DELETE /**"]
```

Each `allow` and `deny` rule has the form `METHOD /path`. `*` as the method matches any method. In the path, `*` matches exactly one segment, and `**` (last segment only) matches the rest of the path. The proxy checks a request in this order:

1. If the request matches any `deny` rule, the proxy refuses it. This is true even if an `allow` rule also matches.
2. If `allow` is empty, the proxy allows the request.
3. Otherwise the request must match at least one `allow` rule. A request that matches neither list is refused.

In the example above, `allow` limits the tool to one project, and `deny` removes `DELETE` from that. Without `deny`, you would have to list each allowed method.

The proxy refuses a request that carries an `X-HTTP-Method-Override`, `X-HTTP-Method` or `X-Method-Override` header. Google APIs and many frameworks take the method from that header instead of the request line, so it would let a `POST` bypass `deny = ["DELETE /**"]`.

The agent then uses ordinary URLs from the API docs:

```bash
airlock exec -- curl -s https://run.googleapis.com/v2/projects/my-project/locations/-/services
```

A complete, read-only setup for Cloud Trace, Monitoring (including PromQL) and Logging is in [`examples/gcp-observability-curl.toml`](examples/gcp-observability-curl.toml).

For each `airlock exec` of a proxy tool, the daemon:

1. Starts a proxy on a random loopback port.
2. Points the tool at the proxy with `HTTPS_PROXY`. Points it at the Airlock CA with `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS`.
3. Limits the tool's network access to that one port with Seatbelt (macOS) or Landlock (Linux).
4. Stops the proxy when the tool exits.

For each request, the proxy:

1. Checks the host against the routes. A host with no route is unreachable (deny by default).
2. Checks the method and path against the route's allow/deny rules, in the order above.
3. Attaches the credential.
4. Sends the request over a verified TLS connection. The host must resolve to a public address.

The proxy redacts the response before the tool sees it, both header values and body. So an API that echoes the credential cannot pass it to the agent, not even through `curl -o file`. The proxy refuses compressed and partial responses instead of forwarding bytes it cannot redact. See [SECURITY.md](SECURITY.md#response-redaction).

Limits to know before you start:

- HTTP/1.1 only. gRPC and HTTP/2-only endpoints do not work.
- Clients that pin certificates fail, because the proxy intercepts TLS.
- The agent gets the full API permissions of the credential on the routed hosts. Give the service account the smallest scope that works.

Threat model and remaining risks: [SECURITY.md](SECURITY.md#proxy-tools). Design notes: [docs/proxy-tools-design.md](docs/proxy-tools-design.md).

### `[agent]` — for `airlock run`

| Field             | Description |
|-------------------|-------------|
| `timeout`         | Session limit in seconds. Absent or `0` = no limit. |
| `passthrough_env` | Host env var names forwarded to the agent (skipped if unset). |
| `env`             | `NAME = value` map, same syntax as tool `env`. |
| `filesystem`      | `read = [...]` / `write = [...]` paths beyond the sandbox root. |

`[agent.env]` may reference secrets. This is the one deliberate exception to "the agent never sees secrets": it is for credentials the agent itself must hold — its own LLM API key, typically — not for tool credentials, which belong in `[tools.<name>.env]`.

### Paths and templating

- `~/foo` → `$HOME/foo`; relative paths resolve against the sandbox root (an error in the global layer, since it applies to every project); absolute paths are used as-is.
- Static `env` strings may use `{sandbox_root}` (the canonicalized project directory), or `{tool_state}` (a per-project, per-tool directory under `$XDG_CACHE_HOME/airlock`, created on first use, writable only by that one tool — nothing else, not even another tool or the agent, can reach it). Use `{tool_state}` for a tool's own config directory (`GH_CONFIG_DIR`, `CLOUDSDK_CONFIG`); use `{sandbox_root}` only when two tools genuinely need to share a path, as `KUBECONFIG` does above. Escape literal braces as `\{` `\}`. No other placeholders exist; this is not shell interpolation.
- **Filesystem baseline:** the sandbox root is read-write; system paths needed to run at all are read-only (`/usr/lib`, `/usr/share`, `/etc`, `/dev/null`, `/dev/random`, `/dev/urandom`, plus `/System` and `/Library` on macOS, `/usr/bin`, `/bin`, `/lib*` on Linux) — except `/dev/null`, which is also writable, so `2>/dev/null` works. Nothing else — `/tmp`, `~/.config/<tool>`, caches — is reachable unless declared.

## Kits

Kits are a separate, composable layer on top of `airlock run`'s agent sandbox: what a *kind of work* needs (a language toolchain and its package caches), independent of whatever harness profile you use (`--profile claude`). They apply only to the agent sandbox — never to tools, and never to `session start`, which an external harness owns.

```toml
[agent]
kits = ["rust", "node"]     # any config layer; unioned across them

[kits.rust]                 # a built-in kit's own option: global or local layer only
mode = "isolated"           # the default; or "shared"
```

Built-in kits: `rust`, `node`, `python`, `go`, `elixir`. Each has two modes:

- **isolated** (the default). Airlock creates a directory private to this project (`$XDG_CACHE_HOME/airlock/kits/<id>/<kit>`) and points the toolchain's cache env vars (`CARGO_HOME`, `GOPATH`, ...) at it. The agent can read/write that directory and nothing else of the toolchain's; your real `~/.cargo`, `~/go`, etc. are untouched.
- **shared**. No env override — the agent gets write access to your real cache locations instead (honoring `CARGO_HOME`/`GOPATH`/etc. if you've already set them). **This lets the agent poison a cache an unsandboxed build later trusts without re-verifying** — e.g. `~/.cargo/registry/src` is extracted once and not re-checked per build. Prefer isolated; reach for shared only when you understand that tradeoff. See [SECURITY.md](SECURITY.md#kits).

`--kit <name>` on `airlock run` adds a kit for that invocation, additive to `agent.kits`. `airlock run -v` and `airlock config` both show the active kits, their mode, and the exact paths/env each one resolved to.

A kit never grants write to binaries or config files, or read of credential files — not `~/.cargo/bin`, not `~/.cargo/credentials.toml`, not `~/.hex/hex.config`. Shared `rust` does read `~/.cargo/config.toml`, so your cargo settings apply to the agent too. You can also define your own kit instead of (or alongside) the built-ins — same idea, your own paths:

```toml
[kits.bazel]                # global or local layer only; no mode (always these paths)
read  = ["~/.bazelrc"]
write = ["~/.cache/bazel"]
env   = { BAZEL_OUTPUT_USER_ROOT = "{kit_state}/out" }
```

`{kit_state}` expands to that kit's own directory under `$XDG_CACHE_HOME/airlock/kits` — the same idea as `{tool_state}` above, but for a kit instead of a tool. A kit's `[kits.<name>]` table sits in the same restricted slot as `allow_home_root`: your global config or `airlock.local.toml` only, never a project's own `airlock.toml` — a teammate's checked-in file must not decide what the agent may write in your home. `agent.kits` itself has no such restriction.

## Command reference

```bash
# Start an agent
airlock run [--profile NAME] [-- CMD...]     # start an agent with a session, sandboxed
airlock init [--local | --global]            # write a starter config
airlock trust [-y]                           # review and approve project config
airlock config                               # merged config, with the layer each part comes from
airlock status                               # daemon, project config and sessions

# Use tools
airlock exec -- TOOL [ARGS...]               # run a declared tool through the session
airlock tools list [--session ID]            # tools a session serves

# For the agent and its harness
airlock agent check                          # verify the session, self-test the sandbox
airlock agent hook claude-code               # SessionStart hook

# Manage
airlock session start | renew | list | reload | revoke
airlock daemon start [--foreground] | stop | restart | logs | install | uninstall
```

`airlock run` and `session start` always sandbox the agent, or hand it a session for its own; there is no flag that runs an agent with neither. `--config <path>` works only on commands that discover config (`run`, `trust`, `config`, `status`, `session start`/`reload`) — `exec` and `tools list` use their session and ignore it.

Inside the agent's own sandbox, `--help` lists only the commands that work there (`exec`, `tools`, `agent`, `init`, `config`) and names the ones it hides; `run`, `trust`, `status`, `session` and `daemon` refuse there even if called directly, since approval and registration need your own terminal.

## Troubleshooting

Start with:

```bash
airlock status        # is the daemon up, is this project's config approved, what sessions exist
airlock agent check    # from inside the agent: is this session healthy, does its sandbox pass self-test
airlock daemon logs    # recent daemon activity, optionally --session <ID>
```

`exec`, `tools list` and `agent check` use the exit codes 125 (Airlock itself couldn't run the request — no session, daemon unreachable, stale secret, …), 126 (the tool is declared but its binary can't be used — install it outside the project) and 127 (no such tool in this session). Airlock's own messages on stderr start with `airlock:`, which is how you tell them from a tool that happens to exit in that range itself.

If a sandboxed tool or agent misbehaves — "Operation not permitted", garbled interactive output, TLS failing silently — the cause is usually a sandbox rule that's too narrow. On macOS, Seatbelt logs every denial:

```bash
/usr/bin/log stream --predicate 'sender == "Sandbox" OR subsystem == "com.apple.sandbox"' --info --style compact
```

Use the full path: zsh has a `log` builtin that shadows `/usr/bin/log` and fails with "too many arguments".

Each line names the operation and the path or Mach service it hit — that's what to add to `[filesystem]`, `extra_read`/`extra_write`, or `[agent.filesystem]`.

With the default `access = "default"`, Nix and Homebrew tools work out of the box — their toolchain roots (`/nix/store`, `/opt/homebrew`, `/usr/local`, `/opt/local`, `/home/linuxbrew/.linuxbrew`) are already in the baseline. A `dyld: Library not loaded: … (blocked by sandbox)` error now means either that tool (or the top-level default) is set to `access = "none"` or `"system"`, or the library lives outside those roots — add its directory to that tool's `extra_read`. Statically linked tools such as `gh` never hit this.

## Building

```bash
cargo build --release
cargo test
```

Requires Rust 2024 edition. macOS uses Apple Seatbelt; Linux needs [Landlock](https://landlock.io/) (kernel 5.13+). A `nix develop` shell provides the toolchain if you use Nix. Release tarballs for Linux amd64 and macOS arm64 are attached to each GitHub release.

## Further reading

- [SKILL.md](SKILL.md) — the agent-facing guide: what to run, what to expect, what not to try.
- [ARCHITECTURE.md](ARCHITECTURE.md) — daemon/session model, config layering, wire protocol, redaction pipeline.
- [SECURITY.md](SECURITY.md) — threat model, trust boundaries, tool selection rules.

## How Airlock compares

Most tools in this space are **HTTP proxies**: the agent sends a placeholder token, the proxy swaps in the real one on the wire. That works for API calls but can't broker a credential a CLI reads from its environment (`gh`, `gcloud`, `kubectl`, `tofu`, `git` signing). Airlock works at the **process layer** instead: it spawns the tool itself, sandboxed, with the secret injected, and redacts the output.

| | Airlock | [claw-wrap](https://github.com/dedene/claw-wrap) | [fnox MCP](https://fnox.jdx.dev/guide/mcp.html) | [Infisical Agent Vault](https://github.com/Infisical/agent-vault) | [nono](https://github.com/nolabs-ai/nono) |
|---|---|---|---|---|---|
| Model | Local CLI exec broker | Local CLI exec broker | MCP `exec` tool in a secrets manager | HTTPS MITM proxy | Kernel sandbox + HTTP credential proxy |
| Brokers local CLIs (env-var creds) | ✅ | ✅ | ✅ | ❌ | ❌ (network only) |
| Brokers HTTP API calls | via the CLI | via the CLI, or MITM proxy mode | via the CLI | ✅ | ✅ |
| OS sandbox for the tool | ✅ Seatbelt / Landlock | ❌ (tool runs with daemon privileges) | ❌ | ❌ | ✅ Seatbelt / Landlock |
| Redacts tool stdout/stderr (incl. base64/hex/URL-encoded) | ✅ | user-supplied regex only | raw value only (docs: encoded forms leak) | ❌ | ❌ |
| Per-tool allowlist | ✅ | ✅ + blocked-arg patterns | ❌ (global secret allowlist) | egress filter | policy-as-code |
| Scoped / short-lived creds | ✅ | ✅ | ❌ | ❌ | ❌ |
| Runs offline, no account | ✅ | ✅ | ✅ | ✅ | ✅ |
| License | Open source | MIT | MIT | Open source | Open source |

[claw-wrap](https://github.com/dedene/claw-wrap) is the nearest relative — same daemon/socket/exec shape — but leaves sandboxing to an external tool and redacts only what you write regexes for. Airlock complements the proxy tools rather than replacing them: use a proxy for pure-API agents, Airlock for the tools the agent *runs*.

Commercial identity gateways such as [Aembit](https://aembit.io/) and [1Password Unified Access](https://1password.com/blog/introducing-1password-unified-access) solve the same problem as a central, cloud-hosted service that vends short-lived credentials to workloads; hosted integration layers like [Arcade](https://www.arcade.dev/), [Composio](https://composio.dev/) and [Nango](https://nango.dev/) do it for SaaS APIs via OAuth. Neither brokers local CLI tools.

## License

See [LICENSE](LICENSE).
