---
name: airlock
description: Execute external tools (eg. GitHub CLI, Terraform, cloud CLIs) via the Airlock credential broker, which injects secrets into tool processes without exposing raw values to the agent. Use when a task requires a tool declared in the project's Airlock config — run `airlock tools list` to discover available tools.
---

# Airlock — Credential Broker for AI Agents

Airlock lets you execute external tools (GitHub CLI, Terraform, cloud CLIs)
without exposing their credentials to you. A daemon holds secrets in memory
and injects them only into declared tool processes. Output is redacted so you
never see raw credential values. The only secrets in your own environment are
ones deliberately given to you via `[agent.env]` — typically your own API
key, never tool credentials.

You reach Airlock through a **session**: `AIRLOCK_ADDR` and `AIRLOCK_SESSION`
are already set in your environment if the user started you with
`airlock run` or `airlock session start`. If they are not set, or the daemon
does not answer, you have no session — see [No session](#no-session) below.

## Commands you need

### List available tools

```
airlock tools list
```

Shows every tool your session serves, its description, and the environment
variables it runs with. Static entries are shown as literal strings;
secret-backed entries appear as `<secret "label">`. This needs your session —
it asks the daemon, not a config file — so it fails with the same message as
`exec` when you have no session.

If a tool shows `proxy tool; reachable hosts:`, it is a proxy tool. See
[Proxy tools](#proxy-tools) for how to use one.

Example output:

```
gh
  GitHub CLI
  GH_CONFIG_DIR = "/home/me/.cache/airlock/3f9a1c2b7d4e8a60/gh"
  GH_TOKEN = <secret "GH_TOKEN">
```

### Execute a tool

```
airlock exec -- <tool> [args...]
```

Everything after `--` is passed to the tool unchanged. The first argument is
the tool name (must match a tool your session serves), and the rest are
arguments forwarded to that tool.

Examples:

```
airlock exec -- gh repo list
airlock exec -- gh pr create --title "fix: update deps" --body "Automated update"
airlock exec -- gh issue list --label bug
airlock exec -- tofu plan
airlock exec -- kubectl get pods
```

Secret values in stdout/stderr are replaced with `[REDACTED:NAME]`, e.g.
`[REDACTED:GH_TOKEN]`. This is normal and expected — it means the redaction is
working.

### Check your session

```
airlock agent check
```

Verifies your session and self-tests the sandbox you are running in: that
`admin.token` cannot be read, that the runtime directory, trust store and
global config cannot be written, that no tool secret is already sitting in
your environment, and that your tools' own credential stores
(`~/.config/gh`, `~/.config/gcloud`, `~/.aws`, `~/.kube`, …) cannot be read.
Run it once if a harness hook told you to, or any time something seems off.
It exits 0 if every check passes, 1 if one fails (it names the check and what
the user has to fix), 125 if you have no session. A failure does not mean you
did anything wrong — report it to the user; your sandbox is misconfigured,
not your request.

### Proxy tools

A proxy tool is an HTTP client (usually `curl`) that does not hold a
credential. Airlock adds the credential to each request after the request
leaves the tool. Use a proxy tool like any other tool, with normal `https://`
URLs from the API docs:

```
airlock exec -- curl -s https://run.googleapis.com/v2/projects/my-project/locations/-/services
airlock exec -- curl -s 'https://storage.googleapis.com/storage/v1/b?project=my-project'
```

`airlock tools list` shows the hosts a proxy tool can reach:

```
curl
  HTTP client for Google Cloud REST APIs (authenticated automatically)
  (no environment)
  proxy tool; reachable hosts:
    *.googleapis.com (authorization injected from <secret "gcp_token">)
```

Rules:

- **Do not pass authentication headers.** Airlock adds the credential. If you
  pass the same header yourself (for example `-H 'Authorization: ...'`), the
  proxy removes it. You also have no token to put there.
- **Only the hosts that `airlock tools list` shows are reachable.** Requests
  to any other host fail.
- **Set the method with `-X`.** The proxy refuses any request with an
  `X-HTTP-Method-Override`, `X-HTTP-Method` or `X-Method-Override` header.
- **`403` from the proxy means the host, port, method or path is not
  allowed.** The response body says why. This is a policy decision, not a
  temporary error. Do **not** retry with `--noproxy`, `--insecure`/`-k`, a
  different port, or a changed URL. The sandbox blocks direct connections, so
  these retries also fail. Tell the user about the refusal.
- **Responses are redacted, also when saved to a file.** The daemon redacts
  header values and body before the tool gets them. So `-o file` and
  `-D`/`--dump-header` write `[REDACTED:NAME]` in place of any credential. If
  you see this in a downloaded file, the API sent back a secret and Airlock
  replaced it. This is expected.
- **Compression is not available.** The proxy always asks the API for an
  uncompressed response, so `--compressed` gets plain bytes. If an API
  compresses the response anyway, the proxy returns
  `502 ... content-encoded`. You do not need to work around this.
- **Range requests and resumed downloads do not work.** The proxy removes the
  `Range` header that `--range`/`-r` and `-C -` send, so the API returns the
  whole resource. A resumed download fails or starts again from the
  beginning. Download each file in one request.

## Exit codes

`exec`, `tools list` and `agent check` use these exit codes instead of the
usual "1 means something failed": Airlock needs its own range because the
tool itself can legitimately exit 1.

| Exit | Meaning | What to do |
|---|---|---|
| **125** | Airlock itself could not run the request: no session, the session ended or expired, the daemon is unreachable, a secret is stale, or the working directory is outside the project. The message on stderr starts with `airlock:` and says what the user needs to do. | Relay the message to the user verbatim. Do not retry, and do not try to fix it yourself — you cannot start a daemon, approve config, or refresh a secret. |
| **126** | The tool is declared, but its binary cannot be used: not on the session's filtered `PATH`, or it resolves inside the project. | Tell the user; they install the tool outside the project (Homebrew, mise, Nix). There is no override — this is not a permission you can grant yourself. |
| **127** | No tool by that name in this session. | If you just added the tool to `airlock.toml` or `airlock.local.toml`, this is expected — see [After editing the config](#after-editing-the-config) below. Otherwise the tool genuinely is not declared; run it directly if it needs no secret, or tell the user to add it. |

A tool itself can also exit 125, 126 or 127 for its own reasons. Airlock's own
errors are the ones printed on stderr starting with `airlock:`.

## After editing the config

You can edit `airlock.toml` or `airlock.local.toml` — adding a tool, say —
but your own session keeps serving the config it started with until the user
approves and reloads it. Never run `airlock trust`, `airlock session reload`,
or any other launcher command yourself: those commands refuse to run inside
your sandbox, because approval has to happen in the user's own terminal.

So after an edit, tell the user what you changed and ask them to run:

```
airlock trust             # reviews the diff and approves it
airlock session reload    # applies it to your running session
```

Until they do, `airlock exec` on the new tool exits 127 and names the file
that changed. Do not try `airlock trust` or `airlock session reload`
yourself — they will refuse, and even if they did not, the point of
approval is that the user reviews the diff.

## No session

If `airlock agent check` or any `exec` says you have no session (exit 125,
message `no Airlock session...`), you were not started with `airlock run` or
`airlock session start`. Tell the user — do not try to start a daemon,
register a session, or find credentials another way. Starting a session
needs the user's terminal and `admin.token`, which your sandbox cannot read
by design.

## Important limitations

### No shell expansion

Airlock executes tool binaries directly — it does NOT use a shell. This means:

- Environment variable references like `$HOME` or `$GH_TOKEN` in arguments are
  passed as literal strings, not expanded.
- Glob patterns like `*.tf` are not expanded.
- Pipes (`|`), redirects (`>`), command substitution (`$(...)`) do not work.
- Quoting rules are those of your calling shell, not of airlock itself.

This is a security feature: if shell expansion worked, you could extract
secrets from the environment via argument interpolation.

If you need to pass the output of one tool to another, capture it in the
calling environment and pass it as an argument.

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

A tool must be declared in the project's merged config to be executable
through `airlock exec`. Running `airlock exec -- sometool` for an undeclared
tool exits 127.

### Tools that do NOT need airlock

General-purpose tools that don't require secrets should be run directly, not
through airlock. This includes: `grep`, `find`, `cargo`, `npm`, `make`,
`ls`, `cat`, and similar. Airlock is only for tools that need credential
injection.

`git` is a judgement call: reads, local commits, and SSH-based pushes don't
need airlock, but signed commits (GPG key) and HTTPS pushes using a credential
helper (GitHub token, etc.) are legitimate airlock-brokered use cases, and
your session serves them if the project declares them.

## Workflow

1. Run `airlock tools list` to discover available tools in this session.
2. Run `airlock exec -- <tool> [args...]` to invoke a tool.
3. If you see `[REDACTED:NAME]` in output, that is expected — do not try to
   recover or work around redacted values.
4. On exit 125, 126 or 127, read the `airlock:` message and follow
   [Exit codes](#exit-codes) above. Report what it says to the user rather
   than working around it — you cannot start daemons, approve config, or
   grant yourself a tool.
5. For tools not listed by `airlock tools list`, run them directly without
   airlock.
6. If `airlock exec` returns an error like `secret "X" is stale (last refresh
   failed)`, a background secret refresh is failing. Report the error message
   verbatim to the user — they need to fix the upstream credential source
   (e.g. re-authenticate with `gcloud auth login`). The daemon retries
   automatically and recovers once the upstream is healthy.
