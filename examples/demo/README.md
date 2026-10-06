# Airlock v2, end to end

`demo.sh` walks the real `airlock` CLI through a full v2 session in a
throwaway project: three config layers, approval, a redacted `exec`, the
agent editing config under the session's feet, `agent check`'s self-test,
the Claude Code hook, the sandboxed `airlock run` path, and shutdown. It's
the fastest way to see what v2 actually does, beyond reading the docs.

## Running it

```bash
cargo build && examples/demo/demo.sh
```

Run it from a plain terminal, not from inside another sandbox — some
steps spawn a sandboxed child process (a real `exec`, and `airlock run`
itself), and a sandbox can't nest one. It takes `$AIRLOCK` from the
environment if set, otherwise `target/debug/airlock`, building it first if
missing.

The script is idempotent: every run creates its own `mktemp -d` workspace
and removes it on exit (success or failure).

## What it doesn't touch

The script exports a throwaway `XDG_STATE_HOME`, `XDG_CONFIG_HOME` and
`XDG_CACHE_HOME` for its own duration, so your real global config, trust
store and tool-state cache are untouched — this demo's "global config"
and trust approvals disappear with the workspace.

It does *not* sandbox itself away from the real per-user daemon and
runtime directory (socket, PID file, admin token): those are never read
from the environment, by design, so there's nothing to override. If a
daemon from your own, real use of Airlock is already running, the demo
warns about that and uses it, but won't stop it when it's done — only a
daemon it started itself.

## Highlights to watch for

- **Unbound secret labels.** The repo config declares `DEMO_TOKEN` with no
  source; `airlock config` refuses until `airlock init --local` binds it
  (here, to a global binding via `from = "global"`).
- **Approval, by exact bytes.** `airlock trust --yes` approves both the
  repo and local files; the merged `airlock config` shows which layer each
  secret and tool came from.
- **Redaction.** `airlock exec -- printenv DEMO_TOKEN` prints
  `[REDACTED:DEMO_TOKEN]` — the `printenv` process itself gets the real
  value, decrypted only in the daemon's memory and the tool's own
  environment; the client never sees it.
- **Exit codes.** `airlock exec -- nosuch` exits 127 (no such tool); after
  the session ends, `exec` exits 125 (session ended); `airlock status`
  exits 3 when the daemon isn't running.
- **Config changes don't apply themselves.** The agent can edit
  `airlock.toml` mid-session, but its new tool stays unusable — and the
  session's next `exec` says why — until the user runs `airlock trust` and
  `airlock session reload`.
- **`airlock agent check` outside a sandbox fails on purpose.** Run from
  an ordinary shell with no Airlock sandbox around it, several checks FAIL
  (the runtime dir and trust store *can* be written, `admin.token` *can*
  be read). That's the self-test proving the probes are real, not a bug —
  under `airlock run`, the agent's own sandbox denies exactly those things
  and the same checks pass.
- **`airlock run` registers and cleans up its own session.** Once the
  sandboxed agent it started exits, `airlock session list` no longer shows
  it.

## `DEMO_SKIP_SANDBOXED=1`

Skips the steps that spawn a sandboxed child process: the real `exec` in
step e, the final `exec` in step g (after the new tool is trusted and
reloaded), and the whole `airlock run` step i. Useful for a quick check of
everything *except* sandboxed execution — e.g. inside a CI job, or inside
another sandbox that can't nest one (this is how the demo was verified
while being written, inside Airlock v1's own Seatbelt sandbox).
