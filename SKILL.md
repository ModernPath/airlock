---
name: airlock
description: Execute external tools (eg. GitHub CLI, Terraform, cloud CLIs) via the Airlock credential broker, which injects secrets into tool processes without exposing raw values to the agent. Use when a task requires a tool declared in airlock.toml — run `airlock list` to discover available tools.
---

# Airlock — Credential Broker for AI Agents

Airlock is a credential broker that lets you execute external tools (GitHub CLI,
Terraform, cloud CLIs) without exposing their credentials to the AI agent. The
daemon holds secrets in memory and injects them only into declared tool
processes. Output is redacted so the agent never sees raw credential values.
The only secrets in the agent's own environment are ones deliberately given to
it via `[agent.env]` — typically its own API key — never tool credentials.

## Commands You Need

### List available tools

```
airlock list
```

Shows every tool declared in `airlock.toml`, its description, and the
environment variables it will run with. Static entries are shown as literal
strings; secret-backed entries appear as `<secret "label">`. Use this to
discover which tools are available before attempting to execute them.
The daemon does NOT need to be running for this command — it reads the config
file directly.

Example output:

```
gh
  GitHub CLI
  GH_TOKEN = <secret "gh_token">
  GH_HOST = "github.com"
tofu
  OpenTofu
  CLOUDFLARE_API_TOKEN = <secret "cf_token">
  TF_INPUT = "0"
```

### Execute a tool

```
airlock exec -- <tool> [args...]
```

Everything after `--` is passed to the tool unchanged. The first argument is the
tool name (must match a `[tools.<name>]` section in `airlock.toml`), and the rest
are arguments forwarded to that tool.

Examples:

```
airlock exec -- gh repo list
airlock exec -- gh pr create --title "fix: update deps" --body "Automated update"
airlock exec -- gh issue list --label bug
airlock exec -- tofu plan
airlock exec -- kubectl get pods
```

The daemon must be running for `exec` to work. If it is not running, the command
will fail with a connection error.

Secret values in stdout/stderr are replaced with `[REDACTED:NAME]`, e.g.
`[REDACTED:GH_TOKEN]`. This is normal and expected — it means the redaction is
working.

### Check daemon status

```
airlock status
```

Returns whether a daemon is serving on the socket. A standalone daemon
(`airlock daemon start`) also reports its PID; an embedded daemon started by
`airlock run` is reported as running but without one, since it writes no PID
file.

## Important Limitations

### No shell expansion

Airlock executes tool binaries directly — it does NOT use a shell. This means:

- Environment variable references like `$HOME` or `$GH_TOKEN` in arguments are
  passed as literal strings, not expanded.
- Glob patterns like `*.tf` are not expanded.
- Pipes (`|`), redirects (`>`), command substitution (`$(...)`) do not work.
- Quoting rules are those of your calling shell, not of airlock itself.

This is a security feature: if shell expansion worked, an agent could extract
secrets from the environment via argument interpolation.

If you need to pass the output of one tool to another, capture it in the calling
environment and pass it as an argument.

### Stdin: piped data only, no interactive tty

You can pipe fixed data into a tool:

```
echo "some_data" | airlock exec -- <tool> [args...]
cat payload.json | airlock exec -- gh api /repos/foo/bar/issues --input -
```

Interactive tty is not supported — tools that try to read from a terminal
(prompts for passwords, editor invocations, `less`-style pagers, etc.) will
fail. Use non-interactive flags where available (e.g. `--yes`, `--no-pager`).

### No binary output

Airlock's redaction engine operates on UTF-8 text. Binary output (images,
compressed data, protocol buffers, etc.) is not supported and will be corrupted
by the lossy UTF-8 conversion in the redaction pipeline. Only use airlock for
tools that produce text output.

### Only declared tools work

A tool must be declared in `airlock.toml` to be executable through `airlock exec`.
Running `airlock exec -- sometool` for an undeclared tool will fail.

### Tools that do NOT need airlock

General-purpose tools that don't require secrets should be run directly, not
through airlock. This includes: `grep`, `find`, `cargo`, `npm`, `make`,
`ls`, `cat`, and similar. Airlock is only for tools that need credential
injection.

`git` is a judgement call: reads, local commits, and SSH-based pushes don't
need airlock, but signed commits (GPG key) and HTTPS pushes using a credential
helper (GitHub token, etc.) are legitimate airlock-brokered use cases and
should be declared as tools in `airlock.toml` when needed.

## Workflow for AI Agents

1. Run `airlock list` to discover available tools.
2. Run `airlock exec -- <tool> [args...]` to invoke a tool.
3. If you see `[REDACTED:NAME]` in output, that is expected — do not try to
   recover or work around redacted values.
4. If `airlock exec` fails with a connection error, the daemon is not running.
   Report this to the user rather than trying to start it yourself (starting the
   daemon requires secrets that you should not have access to).
5. For tools not listed by `airlock list`, run them directly without airlock.
6. If `airlock exec` returns an error like `secret "X" is stale (last refresh failed)`, a background secret refresh is failing. Report the error message verbatim to the user — they need to fix the upstream credential source (e.g. re-authenticate with `gcloud auth login`). The daemon will retry automatically and recover once the upstream is healthy.
