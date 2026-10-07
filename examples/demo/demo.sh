#!/usr/bin/env bash
# Airlock v2, end to end, in a throwaway project of its own.
#
# Run it from a plain macOS terminal, outside any sandbox:
#
#   cargo build && examples/demo/demo.sh
#
# It never touches your real global config, trust store or tool-state
# cache: XDG_STATE_HOME / XDG_CONFIG_HOME / XDG_CACHE_HOME are pointed at a
# throwaway directory for the duration of the script. It does use the real
# per-user runtime directory (socket, PID file, admin token) and the real
# per-user daemon, because that's what "end to end" means — see the README
# in this directory.
#
# DEMO_SKIP_SANDBOXED=1 skips the steps that spawn a sandboxed child process
# (a real `exec` of a tool, or `airlock run` of an agent). Those fail with
# "Operation not permitted" inside another sandbox that can't nest one —
# e.g. inside Airlock v1's own Seatbelt, or in CI. Leave it unset in your
# own terminal to see the whole thing.

set -euo pipefail

# ─── Setup ──────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

AIRLOCK="${AIRLOCK:-$REPO_ROOT/target/debug/airlock}"
if [[ ! -x "$AIRLOCK" ]]; then
  echo "+ cargo build"
  (cd "$REPO_ROOT" && cargo build)
  AIRLOCK="$REPO_ROOT/target/debug/airlock"
fi

# Step i's `airlock run` sandboxes an agent that itself calls `airlock`
# (step i's whole point). That inner call resolves "airlock" through PATH
# like any other command, so a dev build — not installed anywhere —
# needs its directory on PATH, not just $AIRLOCK, for that to work. The
# agent's sandbox must also be able to read that directory; step i grants
# it with --allow-read. An installed airlock (Nix, Homebrew, ~/.cargo/bin)
# is already readable there.
AIRLOCK_DIR="$(cd "$(dirname "$AIRLOCK")" && pwd)"
export PATH="$AIRLOCK_DIR:$PATH"

heading() { printf '\n\033[1m── %s ──\033[0m\n' "$1"; }
note()    { printf 'note: %s\n' "$1"; }

# Echoes the command the way a user would type it, then runs it. $AIRLOCK
# may be an absolute path (when $AIRLOCK was set in the environment); the
# echo always shows the plain "airlock" users will actually type.
run() {
  printf '+ airlock %s\n' "$*"
  "$AIRLOCK" "$@"
}

# Same, but for a command this demo expects to fail (set -e would otherwise
# kill the script). Prints the exit code the way the walkthrough calls for.
run_expect_fail() {
  printf '+ airlock %s\n' "$*"
  set +e
  "$AIRLOCK" "$@"
  local code=$?
  set -e
  printf '+ echo $?\n%s\n' "$code"
}

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/airlock-demo.XXXXXX")"
PROJECT_DIR="$WORKDIR/project"
mkdir -p "$PROJECT_DIR"

# Keep this user's real trust store, global config and tool-state cache out
# of the way. These are the only three state locations Airlock reads from
# the environment (anchors.rs); the runtime directory (socket, PID file,
# admin.token) is never one of them, by design — see decision 1 in
# .git/v2-plan.md and RuntimeDir::locate(). That's why this demo can't
# sandbox itself away from the real daemon, and why it's careful about
# which daemon it stops.
export XDG_STATE_HOME="$WORKDIR/xdg-state"
export XDG_CONFIG_HOME="$WORKDIR/xdg-config"
export XDG_CACHE_HOME="$WORKDIR/xdg-cache"
mkdir -p "$XDG_STATE_HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"

# The daemon is one per user, shared by every project. If one is already
# serving real sessions, this demo must not stop it out from under them.
DAEMON_PRE_EXISTING=0
set +e
"$AIRLOCK" status >/dev/null 2>&1
precheck_code=$?
set -e
if [[ "$precheck_code" != 3 ]]; then
  DAEMON_PRE_EXISTING=1
  echo "warning: an airlock daemon is already running for this user."
  echo "         This demo will use it, but won't stop it at the end —"
  echo "         that daemon likely serves other projects of yours."
fi

cleanup() {
  if [[ "$DAEMON_PRE_EXISTING" == 0 ]]; then
    set +e
    "$AIRLOCK" status >/dev/null 2>&1
    if [[ $? != 3 ]]; then
      "$AIRLOCK" daemon stop --yes >/dev/null 2>&1
    fi
    set -e
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

DEMO_SKIP_SANDBOXED="${DEMO_SKIP_SANDBOXED:-0}"

cd "$PROJECT_DIR"

# ─── a. Config layers ───────────────────────────────────────────────────────

heading "a. Three config layers: global, repo, local"

note "writing \$XDG_CONFIG_HOME/airlock/airlock.toml (global — this user's own, every project)"
mkdir -p "$XDG_CONFIG_HOME/airlock"
cat > "$XDG_CONFIG_HOME/airlock/airlock.toml" <<'EOF'
# ~/.config/airlock/airlock.toml, in real life. This demo points
# XDG_CONFIG_HOME at a throwaway directory instead, so your real global
# config is untouched.

[secrets.DEMO_TOKEN]
source  = "command"
command = ["printf", "ghp_demo_0123456789abcdef"]
EOF
cat "$XDG_CONFIG_HOME/airlock/airlock.toml"

note "writing airlock.toml (repo — checked in, in real life)"
cat > "$PROJECT_DIR/airlock.toml" <<'EOF'
# airlock.toml — the team's config. Declares the DEMO_TOKEN label and the
# printenv tool, but leaves DEMO_TOKEN's source to each teammate (see
# README.md#team-and-personal-config).

[secrets.DEMO_TOKEN]
description = "Demo token standing in for a real credential"

[tools.printenv]
description = "prints environment variables — stands in here for a real credentialed CLI like gh or gcloud"

[tools.printenv.env]
DEMO_TOKEN      = { secret = "DEMO_TOKEN" }
DEMO_CONFIG_DIR = "{tool_state}"
EOF
cat "$PROJECT_DIR/airlock.toml"

# ─── b. Discovery, the unbound-label error, and init --local ───────────────

heading "b. airlock config before DEMO_TOKEN is bound"
run_expect_fail config

heading "airlock init --local"
run init --local

note "the generated airlock.local.toml"
cat "$PROJECT_DIR/airlock.local.toml"

heading "airlock config, merged, with layer provenance"
run config

# ─── c. Trust and paths ─────────────────────────────────────────────────────

heading "c. airlock trust --yes"
run trust --yes

heading "airlock config --paths"
run config --paths

# ─── d. Start a session ─────────────────────────────────────────────────────

heading "d. Start a session in this shell"
printf '+ eval "$(airlock session start --name demo -q)"\n'
eval "$("$AIRLOCK" session start --name demo -q)"

run status
run session list
run tools list

# ─── e. A redacted exec ─────────────────────────────────────────────────────

heading "e. exec printenv DEMO_TOKEN — the tool gets the real value, the client sees [REDACTED:DEMO_TOKEN]"
if [[ "$DEMO_SKIP_SANDBOXED" == 1 ]]; then
  note "DEMO_SKIP_SANDBOXED=1: skipping the real exec (it spawns a sandboxed"
  note "child, which can't nest inside another sandbox). In your own"
  note "terminal this prints '[REDACTED:DEMO_TOKEN]' and exits 0."
else
  printf '+ airlock exec -- printenv DEMO_TOKEN\n'
  set +e
  "$AIRLOCK" exec -- printenv DEMO_TOKEN
  code=$?
  set -e
  printf '+ echo $?\n%s\n' "$code"
fi

# ─── f. Exit codes ───────────────────────────────────────────────────────────

heading "f. Exit codes: an undeclared tool"
run_expect_fail exec -- nosuch

# ─── g. The agent edits the config ──────────────────────────────────────────

heading "g. The agent adds a tool; it needs trust + reload before it works"

note "appending [tools.date] to airlock.toml"
cat >> "$PROJECT_DIR/airlock.toml" <<'EOF'

[tools.date]
description = "prints the current date — added after the session already started"
EOF

run_expect_fail exec -- date

run trust --yes

run session reload

if [[ "$DEMO_SKIP_SANDBOXED" == 1 ]]; then
  note "DEMO_SKIP_SANDBOXED=1: skipping the real exec of 'date' now that it's"
  note "trusted and reloaded (same nested-sandbox limit as step e)."
else
  run exec -- date
fi

# ─── h. agent check and agent hook ──────────────────────────────────────────

heading "h. airlock agent check, run from an ordinary (unsandboxed) shell"
note "this shell has no Airlock sandbox around it, so several checks below"
note "are expected to FAIL — that's the self-test proving the probes are"
note "real, not that anything is broken. Under 'airlock run', the agent's"
note "sandbox denies exactly these things and the same checks pass."
set +e
run agent check
code=$?
set -e
printf '+ echo $?\n%s\n' "$code"

heading "airlock agent hook claude-code < /dev/null"
if command -v python3 >/dev/null 2>&1; then
  "$AIRLOCK" agent hook claude-code < /dev/null | python3 -m json.tool
else
  "$AIRLOCK" agent hook claude-code < /dev/null
fi

# ─── i. The sandboxed agent path ────────────────────────────────────────────

heading "i. airlock run — the full launcher + sandboxed agent path"
if [[ "$DEMO_SKIP_SANDBOXED" == 1 ]]; then
  note "DEMO_SKIP_SANDBOXED=1: skipping 'airlock run' (it sandboxes the agent"
  note "itself, which can't nest inside another sandbox here)."
else
  note "--allow-read lets the sandboxed agent run this dev build of airlock"
  printf "+ airlock run --allow-read %s -- sh -c 'airlock tools list && airlock exec -- printenv DEMO_TOKEN'\n" "$AIRLOCK_DIR"
  "$AIRLOCK" run --allow-read "$AIRLOCK_DIR" -- sh -c 'airlock tools list && airlock exec -- printenv DEMO_TOKEN'

  heading "the session airlock run registered is gone now that the agent exited"
  run session list
fi

# ─── j. Ending things ───────────────────────────────────────────────────────

heading "j. Revoking the session, then stopping the daemon"
run session revoke demo

run_expect_fail exec -- printenv DEMO_TOKEN

if [[ "$DAEMON_PRE_EXISTING" == 0 ]]; then
  run daemon stop --yes
  run_expect_fail status
else
  note "skipping 'airlock daemon stop': a daemon from outside this demo is"
  note "still running, serving your other projects."
fi

heading "done"
echo "cleaning up $WORKDIR"
