//! Several `airlock session start`s racing against an empty runtime dir
//! must all succeed against a single daemon, never corrupt each other's
//! startup, and never leave more than one daemon running.
//!
//! This is the scenario `src/runtime_dir.rs`'s `airlock.lock` and
//! `src/launcher.rs`'s `ensure_daemon` retry exist for: before the lock,
//! two launchers starting the automatic daemon at the same moment could
//! have one of them delete the winner's socket/admin.token as "stale", or
//! fail outright on a raw bind error.
//!
//! No tool is executed here — `session start` only registers a session and
//! prints its exports — so, unlike `run_integration.rs`'s tests, nothing
//! here needs a nestable sandbox.

#![allow(
    clippy::disallowed_methods,
    reason = "test harness drives the real binary via its own process env, not daemon request-path code"
)]

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use airlock::admin;
use airlock::launcher;
use airlock::protocol::{AdminRequest, DaemonMessage};
use airlock::runtime_dir::RuntimeDir;

fn airlock_bin() -> &'static str {
    env!("CARGO_BIN_EXE_airlock")
}

/// Everything `session start` needs: a `$HOME`, XDG dirs under it, a
/// pre-created, correctly-moded runtime dir, and a project directory —
/// same shape as `agent_integration.rs`'s `Fixture`.
struct Fixture {
    home: tempfile::TempDir,
    xdg_state: tempfile::TempDir,
    xdg_config: tempfile::TempDir,
    xdg_cache: tempfile::TempDir,
    runtime: tempfile::TempDir,
    project: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let runtime = tempfile::tempdir().unwrap();
        // The daemon refuses a runtime dir others can read, and tempdir()
        // follows the umask.
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Fixture {
            home: tempfile::tempdir().unwrap(),
            xdg_state: tempfile::tempdir().unwrap(),
            xdg_config: tempfile::tempdir().unwrap(),
            xdg_cache: tempfile::tempdir().unwrap(),
            runtime,
            project: tempfile::tempdir().unwrap(),
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new(airlock_bin());
        cmd.env_clear();
        if let Ok(path) = std::env::var("PATH") {
            cmd.env("PATH", path);
        }
        cmd.env("HOME", self.home.path());
        cmd.env("XDG_STATE_HOME", self.xdg_state.path());
        cmd.env("XDG_CONFIG_HOME", self.xdg_config.path());
        cmd.env("XDG_CACHE_HOME", self.xdg_cache.path());
        cmd.env("AIRLOCK_TEST_RUNTIME_DIR", self.runtime.path());
        // This suite may itself run under Airlock; the sessions it starts
        // stand in for ones started from the user's own terminal.
        cmd.env_remove("AIRLOCK_SANDBOX");
        cmd.current_dir(self.project.path());
        cmd.stdin(std::process::Stdio::null());
        cmd
    }

    fn runtime_dir(&self) -> RuntimeDir {
        RuntimeDir::at(self.runtime.path().to_path_buf())
    }
}

#[test]
fn concurrent_session_starts_all_succeed_against_one_daemon() {
    let fx = Fixture::new();
    std::fs::write(fx.project.path().join("airlock.toml"), "[tools.echo]\n").unwrap();

    let trust = fx.cmd().args(["trust", "--yes"]).output().unwrap();
    assert!(trust.status.success(), "{trust:?}");

    const N: usize = 4;
    let children: Vec<_> = (0..N)
        .map(|_| {
            fx.cmd()
                .args(["session", "start", "--format", "json", "--ttl", "1h"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn session start")
        })
        .collect();

    let outputs: Vec<_> = children
        .into_iter()
        .map(|c| c.wait_with_output().expect("wait for session start"))
        .collect();

    for (i, out) in outputs.iter().enumerate() {
        assert!(
            out.status.success(),
            "session start #{i} failed: status={:?} stdout={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Every session token in each child's JSON export is distinct — no
    // launcher mistakenly reused or collided with another's registration.
    let session_ids: HashSet<String> = outputs
        .iter()
        .map(|out| {
            let value: serde_json::Value = serde_json::from_slice(&out.stdout)
                .unwrap_or_else(|e| panic!("session start did not print JSON: {e}\n{out:?}"));
            value["session"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(session_ids.len(), N, "expected {N} distinct session tokens");

    // Exactly one daemon is up, and it knows about all N sessions — the
    // decisive check: if the lock had failed to serialize the races, a
    // losing launcher could have deleted the winner's socket/admin.token
    // as "stale", or a second daemon could have bound a second socket.
    let runtime = fx.runtime_dir();
    let mut conn = admin::Connection::connect(&runtime.socket_path()).expect("connect to daemon");
    let token = launcher::read_admin_token(&runtime).expect("read admin token");
    match conn
        .admin_request(&token, AdminRequest::ListSessions)
        .expect("ListSessions")
    {
        DaemonMessage::Sessions { sessions } => {
            assert_eq!(
                sessions.len(),
                N,
                "expected {N} live sessions: {sessions:?}"
            );
        }
        other => panic!("expected Sessions, got {other:?}"),
    }

    let _ = fx.cmd().args(["daemon", "stop", "--yes"]).output();
}
