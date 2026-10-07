//! `airlock session revoke`/`session reload` must resolve a ref exactly
//! like the daemon's own `Sessions::resolve_ref` — an ambiguous ref is a
//! refusal naming every candidate, never a silent "act on everything it
//! matches".
//!
//! Nothing here execs a tool, so — unlike `run_integration.rs`'s tests —
//! nothing needs a nestable sandbox.

#![allow(
    clippy::disallowed_methods,
    reason = "test harness drives the real binary via its own process env, not daemon request-path code"
)]

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
        cmd.env_remove("AIRLOCK_SANDBOX");
        cmd.current_dir(self.project.path());
        cmd.stdin(std::process::Stdio::null());
        cmd
    }

    fn runtime_dir(&self) -> RuntimeDir {
        RuntimeDir::at(self.runtime.path().to_path_buf())
    }

    fn session_count(&self) -> usize {
        let runtime = self.runtime_dir();
        let mut conn = admin::Connection::connect(&runtime.socket_path()).expect("connect");
        let token = launcher::read_admin_token(&runtime).expect("read admin token");
        match conn
            .admin_request(&token, AdminRequest::ListSessions)
            .expect("ListSessions")
        {
            DaemonMessage::Sessions { sessions } => sessions.len(),
            other => panic!("expected Sessions, got {other:?}"),
        }
    }
}

/// Starts a session named `name` and returns its session id (parsed out of
/// `airlock_<id>_<token>`).
fn start_named_session(fx: &Fixture, name: &str) -> String {
    let output = fx
        .cmd()
        .args([
            "session", "start", "--name", name, "--format", "json", "--ttl", "1h",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let session_token = value["session"].as_str().unwrap();
    session_token
        .strip_prefix("airlock_")
        .and_then(|rest| rest.split('_').next())
        .unwrap()
        .to_string()
}

#[test]
fn revoke_with_an_ambiguous_name_refuses_and_ends_neither() {
    let fx = Fixture::new();
    std::fs::write(fx.project.path().join("airlock.toml"), "[tools.echo]\n").unwrap();
    let trust = fx.cmd().args(["trust", "--yes"]).output().unwrap();
    assert!(trust.status.success(), "{trust:?}");

    let id_a = start_named_session(&fx, "dup");
    let id_b = start_named_session(&fx, "dup");
    assert_ne!(id_a, id_b);
    assert_eq!(fx.session_count(), 2);

    let revoke = fx
        .cmd()
        .args(["session", "revoke", "dup"])
        .output()
        .unwrap();
    assert_eq!(revoke.status.code(), Some(125), "{revoke:?}");
    let stderr = String::from_utf8_lossy(&revoke.stderr);
    assert!(stderr.contains("more than one session"), "{stderr}");
    assert!(stderr.contains(&id_a), "{stderr}");
    assert!(stderr.contains(&id_b), "{stderr}");

    // Neither session was ended by the ambiguous ref.
    assert_eq!(fx.session_count(), 2);

    // A unique id prefix ends exactly that session, reported by id and name.
    let revoke = fx
        .cmd()
        .args(["session", "revoke", &id_a[..5]])
        .output()
        .unwrap();
    assert!(revoke.status.success(), "{revoke:?}");
    assert_eq!(
        String::from_utf8_lossy(&revoke.stdout).trim(),
        format!("ended {id_a} \"dup\"")
    );
    assert_eq!(fx.session_count(), 1);

    let _ = fx.cmd().args(["daemon", "stop", "--yes"]).output();
}

#[test]
fn reload_with_an_ambiguous_name_refuses_and_reloads_neither() {
    let fx = Fixture::new();
    std::fs::write(fx.project.path().join("airlock.toml"), "[tools.echo]\n").unwrap();
    let trust = fx.cmd().args(["trust", "--yes"]).output().unwrap();
    assert!(trust.status.success(), "{trust:?}");

    let _id_a = start_named_session(&fx, "dup");
    let _id_b = start_named_session(&fx, "dup");
    assert_eq!(fx.session_count(), 2);

    let reload = fx
        .cmd()
        .args(["session", "reload", "dup"])
        .output()
        .unwrap();
    assert_eq!(reload.status.code(), Some(125), "{reload:?}");
    let stderr = String::from_utf8_lossy(&reload.stderr);
    assert!(stderr.contains("more than one session"), "{stderr}");

    let _ = fx.cmd().args(["daemon", "stop", "--yes"]).output();
}
