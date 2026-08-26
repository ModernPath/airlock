# airlock

Credential broker for AI agents — tools get your secrets, the agent never does.

An AI coding agent needs `gh`, `tofu`, `gcloud`, `kubectl` to do real work, and those tools need credentials. Hand the agent a token and it sits in the agent's environment, its shell history, and every line of output it reads. Airlock takes the token out of the agent's reach: a trusted daemon holds secrets in memory and injects them only into the specific tool processes that need them, runs each tool in an OS sandbox, and redacts its output before the agent sees it.

Airlock brokers credentials for the tools your agent *runs*, not just the APIs it *calls*. The CLI authenticates exactly as it always has — the agent simply never holds the key.

## Contents

- [What you get](#what-you-get)
- [How it works](#how-it-works)
- [Where Airlock fits](#where-airlock-fits)
- [Security model](#security-model)
- [Quick start](#quick-start)
- [Supplying secrets](#supplying-secrets)
- [Minting scoped credentials](#minting-scoped-credentials)
- [Configuration](#configuration)
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
- **Sandboxed tools.** Every tool runs with deny-by-default filesystem access (macOS Seatbelt, Linux Landlock) and a minimal environment.
- **Any secret source.** 1Password, Vault, cloud secret managers, plain env vars, or any command that prints a token.

What Airlock does *not* do: stop the agent from doing destructive things *through* a tool. If the token can delete repos, `gh repo delete` works. Airlock keeps the token from leaking; the token's scope decides what it can do — which is why minting narrow tokens matters. Full threat model in [SECURITY.md](SECURITY.md).

## How it works

```
┌──────────────────────────────┐    ┌──────────────────────────────────┐
│  env vars at daemon start    │    │  command sources                 │
│  op run · secretspec · vault │    │  op read · gcloud auth           │
│  · plain exports             │    │  print-access-token · …          │
└──────────────┬───────────────┘    └────────────────┬─────────────────┘
               │ read once, then                     │ spawned by the daemon;
               │ cleared from the process            │ re-run every `refresh` seconds
               ▼                                     ▼
          ┌──────────────────────────────────────────────────┐
          │                  airlock daemon                  │  ← secrets live here (in memory)
          │                 Unix socket API                  │
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
2. The daemon collects secrets at startup: `env` sources are read from its environment and **immediately cleared** from the process; `command` sources are spawned and their stdout captured, re-run on a schedule if `refresh` is set.
3. The agent runs `airlock exec -- gh pr list`. The daemon injects the secrets into a minimal child environment, spawns `gh` inside the sandbox, and streams back redacted output.

Only tools that need credentials go through Airlock. `grep`, `cargo`, `npm`, `make` and the rest run directly through the agent's own sandbox. `git` goes either way: run it directly for reads and local commits; declare it as a tool when signed commits or HTTPS pushes need a GPG key or credential-helper token.

## Where Airlock fits

Airlock is one layer of a defense-in-depth stack:

1. **Secret storage** — 1Password, Vault, a cloud secret manager. Never `.env` files or shell history.
2. **Scoped tokens** — fine-grained PATs, least-privilege service accounts. **This is the layer that limits damage.** Airlock can mint these for you ([below](#minting-scoped-credentials)).
3. **Airlock** — credential isolation at runtime: secrets in memory, injected per tool, output redacted.
4. **Agent harness sandbox** — `airlock run`, Claude Code's `--sandbox`, Docker, nsjail, bubblewrap. Without it, the agent could read the daemon's memory or connect to the socket directly.

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

- **The daemon is trusted and runs unsandboxed, as you.** That is deliberate: it needs your real `gcloud` login or `op` session to mint scoped tokens, and it is the one place raw secrets live. The agent can reach it only over the Unix socket.
- **The agent gets a sandbox shaped for an agent.** Read/write to the project and its own state directory, nothing else — no `~/.ssh`, no keychain, no daemon memory. `airlock run` provides this; Claude Code's own `--sandbox` or a container works too.
- **Each tool gets its own sandbox, shaped for that tool.** This is the part most setups skip. `gh` sees the repo and its own config dir but not `~/.config/gcloud`; `gcloud` gets the reverse. A compromised or misbehaving tool can expose at most the one secret it was handed — and even that is redacted before the agent reads it.

Two sandboxes because the agent and the tools have different jobs: the agent needs wide read access to reason about code but no credentials; a tool usually needs one credential plus its own config files. Even the config files can be kept out of your real home directory — point `CLOUDSDK_CONFIG` or `KUBECONFIG` at a project-local path (as in [Minting scoped credentials](#minting-scoped-credentials)) and `gcloud` or `kubectl` runs with only the minted token, never your privileged global login.

Under the hood, the daemon clears secret env vars from its own process after reading them, keeps values in memory that is zeroed on drop, disables core dumps, hands each tool a minimal environment with a timeout, and refuses to start if the OS sandbox is unavailable rather than run without it. Redaction is streaming and covers raw, base64, URL-encoded, and hex forms.

Known limits: redaction is best-effort (a tool can transform a secret in ways the redactor doesn't recognize), tools have unrestricted network access, and a local root user can read daemon memory. See [SECURITY.md](SECURITY.md) for the full threat model and mitigations.

## Quick start

```bash
cargo build --release          # or download a release binary (Linux amd64, macOS arm64)
airlock init                   # writes a starter airlock.toml in the current directory
```

A minimal `airlock.toml`:

```toml
[secrets.GH_TOKEN]
source = "env"                 # read GH_TOKEN from the daemon's environment at start

[tools.gh]
description = "GitHub CLI"

[tools.gh.env]
GH_TOKEN      = { secret = "GH_TOKEN" }
GH_CONFIG_DIR = "{sandbox_root}/.config/gh"   # project-local gh state, not ~/.config/gh
```

Start the daemon with the secret from wherever you keep it, then use the tool:

```bash
$ GH_TOKEN="op://Employee/GH_TOKEN/credential" op run -- airlock daemon start

$ airlock exec -- gh auth status
github.com
  ✓ Logged in to github.com account acme (GH_TOKEN)
  - Token: [REDACTED:GH_TOKEN]
```

To run the agent itself inside Airlock's sandbox with an embedded daemon:

```bash
airlock run --profile claude
```

More configs in [`examples/`](examples/).

## Supplying secrets

Each `[secrets.<label>]` entry is either read from the daemon's environment at startup (`source = "env"`) or produced by a command the daemon runs (`source = "command"`). Either way, the daemon clears secret variables from its own process right after reading them.

```bash
# 1Password CLI
GH_TOKEN="op://Employee/GH_TOKEN/credential" op run -- airlock daemon start

# secretspec
secretspec run -- airlock daemon start

# Hashicorp Vault, or any shell
GH_TOKEN=$(vault kv get -field=token secret/github) airlock daemon start
```

Or skip the environment entirely and let the daemon fetch the value:

```toml
[secrets.GH_TOKEN]
source  = "command"
command = ["op", "read", "op://Employee/GH_TOKEN/credential"]   # argv list, no shell
```

Add `refresh` and the same mechanism mints short-lived tokens.

## Minting scoped credentials

You are logged into your cloud provider with broad permissions. You want an agent to inspect deployed systems — pods, rollouts, load balancers — but not modify them, and certainly not as *you*. The usual fix is a long-lived key for a read-only service account: now you have a key to store, rotate, and worry about.

With Airlock you skip the key. The daemon uses your session to mint a token *as* the read-only account, hands only that token to the sandboxed tools, and re-mints it before it expires:

```toml
# Runs at daemon start, then every 50 min. Executes on the trusted side with the
# daemon's environment, so it can read ~/.config/gcloud — the sandboxed tools cannot.
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
CLOUDSDK_CONFIG = "{sandbox_root}/.config/gcloud"   # sandboxed gcloud never sees ~/.config/gcloud

[tools.kubectl.env]                                    # GKE auth plugin resolves the same env
CLOUDSDK_AUTH_ACCESS_TOKEN = { secret = "CLOUDSDK_AUTH_ACCESS_TOKEN" }
CLOUDSDK_CONFIG = "{sandbox_root}/.config/gcloud"
KUBECONFIG      = "{sandbox_root}/.config/kubeconfig"
```

| | Your admin credentials | The minted read-only token |
|---|---|---|
| Airlock daemon | ambient, via `~/.config/gcloud` — never copied into the secret store | in memory, zeroized on drop |
| `gcloud` / `kubectl` in the sandbox | **no** — path is outside their filesystem policy | injected as an env var at spawn |
| The agent | **no** | **no** — sees `[REDACTED:CLOUDSDK_AUTH_ACCESS_TOKEN]` |

The permission boundary is the service account's IAM bindings. Airlock doesn't enforce it; it makes sure nothing *broader* ever reaches the sandbox.

**Minting failures fail closed.** If your gcloud session expires overnight, the next re-mint fails, the secret is marked stale, and `airlock exec -- gcloud …` returns an error naming the stale secret instead of running with a dead token. The daemon retries with exponential backoff (5 s, 10 s, 20 s … capped at `refresh_max_backoff`) and recovers on its own once you `gcloud auth login` again.

The pattern fits any CLI that prints one short-lived token to stdout — GitHub App installation tokens, Vault dynamic secrets, most OAuth access tokens. **AWS is the exception:** `aws sts assume-role` returns three coupled values and a `command` source yields one. Until multi-value sources land ([TODO.md](TODO.md)), use scoped static keys as in [`examples/cloud-providers.toml`](examples/cloud-providers.toml). The full GCP walkthrough with IAM setup is in [`examples/gcp-impersonation.toml`](examples/gcp-impersonation.toml).

## Configuration

Airlock looks for `airlock.toml` by walking up from the current directory toward `$HOME`, using the first file owned by the current user. Its directory becomes the **sandbox root**: always read-write for tools, and home to the Unix socket and PID file.

> Don't put `airlock.toml` directly in `$HOME` — that makes your entire home directory the sandbox root. Airlock refuses to start unless the config sets `allow_home_root = true`.

```toml
timeout = 120                  # global tool timeout in seconds (default: 300)

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

### `[secrets.<label>]`

| Field                 | Applies to | Description |
|-----------------------|------------|-------------|
| `source`              | all        | `"env"` or `"command"`. |
| `from`                | `env`      | Daemon env var to read. Defaults to the label. |
| `command`             | `command`  | Argv list to spawn; trimmed stdout becomes the value. No shell. |
| `timeout`             | `command`  | Seconds to wait for the command. Default 10. |
| `refresh`             | `command`  | Seconds between background re-runs. Omit to fetch once at startup. |
| `refresh_max_backoff` | `command`  | Cap on backoff between failed refreshes. Defaults to `refresh`. |
| `env`                 | `command`  | `NAME = "value"` map applied when spawning the command. |
| `env_clear`           | `command`  | `true` gives the command a completely empty environment — no `PATH`, no `HOME`. Add back what it needs via `env`. |

> **Command sources run unsandboxed, on the trusted side**, with the daemon's environment and filesystem. That is what lets them derive narrow credentials from broad ones. Only configure commands you would run yourself at the shell.

### `[tools.<name>]`

| Field         | Description |
|---------------|-------------|
| `env`         | `NAME = value` map. A bare string is static; `{ secret = "label" }` resolves a secret. |
| `description` | Shown by `airlock list`. |
| `extra_read`  | Additional read-only paths. |
| `extra_write` | Additional read-write paths. |
| `timeout`     | Per-tool timeout in seconds; overrides the global value. |

> **Only declare purpose-built CLIs as tools** — never shells (`bash`), interpreters (`python`, `node`), or tools where the agent controls the request (`curl`). If the agent can script the tool, it can transform secrets past the redactor or upload `/proc/self/environ`. See [SECURITY.md](SECURITY.md#tool-selection-what-should-and-should-not-be-an-airlock-tool).

### `[agent]` — for `airlock run`

| Field             | Description |
|-------------------|-------------|
| `timeout`         | Session limit in seconds. Absent or `0` = no limit. |
| `passthrough_env` | Host env var names forwarded to the agent (skipped if unset). |
| `env`             | `NAME = value` map, same syntax as tool `env`. |
| `filesystem`      | `read = [...]` / `write = [...]` paths beyond the sandbox root. |

### Paths and templating

- `~/foo` → `$HOME/foo`; relative paths resolve against the sandbox root; absolute paths are used as-is.
- Static `env` strings may use `{sandbox_root}`, the canonicalized config directory — handy for keeping tool state project-local (`GH_CONFIG_DIR = "{sandbox_root}/.config/gh"`). Escape literal braces as `\{` `\}`. No other placeholders exist; this is not shell interpolation.
- **Filesystem baseline:** the sandbox root is read-write; system paths needed to run at all are read-only (`/usr/lib`, `/usr/share`, `/etc`, `/dev/null`, `/dev/random`, `/dev/urandom`, plus `/System` and `/Library` on macOS, `/usr/bin`, `/bin`, `/lib*` on Linux). Nothing else — `/tmp`, `~/.config/<tool>`, caches — is reachable unless declared.

## Command reference

```bash
airlock init                       # create a starter airlock.toml
airlock daemon start               # background daemon; returns once it accepts connections
airlock daemon run                 # foreground, for debugging
airlock daemon stop | restart
airlock exec -- <tool> [args...]   # run a declared tool; everything after -- is passed unchanged
airlock status                     # is a daemon serving on the socket?
airlock list                       # declared tools and their env bindings (no daemon needed)
airlock logs                       # recent daemon log entries
airlock run [flags] -- <cmd>       # run an agent in the sandbox, with an embedded daemon
```

`--config <path>` on any command bypasses discovery.

### `airlock run`

```bash
airlock run --profile claude                       # default command: claude --dangerously-skip-permissions
airlock run --profile claude-relaxed               # wider sandbox for interactive use
airlock run -- <agent-command> [args...]           # any command
airlock run --no-daemon -- claude                  # sandbox only; airlock exec will fail inside
```

`airlock run` launches the agent inside an OS-level sandbox (Seatbelt / Landlock), starts an embedded daemon so `airlock exec` works without a separate `daemon start`, and tears the daemon down when the agent exits. `--allow-read`, `--allow-write`, and `--passthrough-env` extend the `[agent]` config from the command line; `--no-config` runs without an `airlock.toml` at all (set `AIRLOCK_SANDBOX_ROOT`).

`[agent.env]` may reference secrets. This is the one deliberate exception to "the agent never sees secrets": it is for credentials the agent itself must hold — its own LLM API key, typically — not for tool credentials, which belong in `[tools.<name>.env]`.

Profiles bundle sandbox rules for a known agent:

- **`claude`** — read/write to `~/.claude/`, `~/.claude.json`, `~/.local/share/claude/`. The macOS keychain is unreachable, so Claude Code stores its OAuth token in `~/.claude/.credentials.json` (mode `0600`). Also disables Claude Code's own `sandbox-exec` wrapper, which cannot nest inside Airlock's profile.
- **`claude-relaxed`** — `claude` plus keychain access, clipboard, `open <url>`, and read access to shell dotfiles. Each widens the data-leak surface; see [SECURITY.md](SECURITY.md#built-in-agent-profiles).

## Troubleshooting

If a sandboxed tool or agent misbehaves — "Operation not permitted", garbled interactive output, TLS failing silently — the cause is usually a sandbox rule that's too narrow. On macOS, Seatbelt logs every denial:

```bash
log stream --predicate 'sender == "Sandbox" OR subsystem == "com.apple.sandbox"' --info --style compact
```

Each line names the operation and the path or Mach service it hit — that's what to add to `[filesystem]`, `extra_read`/`extra_write`, or `[agent.filesystem]`.

## Building

```bash
cargo build --release
cargo test
```

Requires Rust 2024 edition. macOS uses Apple Seatbelt; Linux needs [Landlock](https://landlock.io/) (kernel 5.13+). Release tarballs for Linux amd64 and macOS arm64 are attached to each GitHub release.

## Further reading

- [SKILL.md](SKILL.md) — the agent-facing guide: what to run, what to expect, what not to try.
- [ARCHITECTURE.md](ARCHITECTURE.md) — daemon/client split, fork sequence, wire protocol, redaction pipeline.
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
