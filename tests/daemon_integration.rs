//! `airlock daemon` integration tests.
//!
//! `daemon start` calls into `daemon::start`, which in this worktree is
//! P2-G's temporary `unimplemented!()` shim (the real v2 daemon lands at
//! the phase-2 merge) — so every test that needs a daemon to actually come
//! up is `#[ignore = "needs the v2 daemon (phase 2 merge)"]`. What's left
//! is the CLI behavior that holds with no daemon running at all.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn airlock_bin() -> &'static str {
    env!("CARGO_BIN_EXE_airlock")
}

struct Fixture {
    home: tempfile::TempDir,
    runtime: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let runtime = tempfile::tempdir().unwrap();
        // The daemon refuses a runtime dir others can read, and tempdir()
        // follows the umask.
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Fixture {
            home: tempfile::tempdir().unwrap(),
            runtime,
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new(airlock_bin());
        cmd.env_clear();
        if let Ok(path) = std::env::var("PATH") {
            cmd.env("PATH", path);
        }
        cmd.env("HOME", self.home.path());
        cmd.env("AIRLOCK_TEST_RUNTIME_DIR", self.runtime.path());
        cmd.stdin(std::process::Stdio::null());
        cmd
    }
}

#[test]
fn stop_when_not_running_is_a_success_no_op() {
    let fx = Fixture::new();
    let output = fx.cmd().args(["daemon", "stop"]).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("not running"));
}

#[test]
fn logs_when_not_running_is_an_error() {
    let fx = Fixture::new();
    let output = fx.cmd().args(["daemon", "logs"]).output().unwrap();
    assert_eq!(output.status.code(), Some(125));
}

#[test]
fn install_and_uninstall_are_phase_three_stubs() {
    let fx = Fixture::new();
    for sub in ["install", "uninstall"] {
        let output = fx.cmd().args(["daemon", sub]).output().unwrap();
        assert_eq!(output.status.code(), Some(125), "daemon {sub}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("not implemented yet"));
    }
}

#[test]
fn start_foreground_then_stop_is_a_full_lifecycle() {
    let fx = Fixture::new();
    let mut child = fx
        .cmd()
        .args(["daemon", "start", "--foreground"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let socket_path: PathBuf = fx.runtime.path().join("airlock.sock");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !socket_path.exists() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("daemon did not create its socket in time");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // `daemon stop` polls the PID until it is gone. The daemon is this test's
    // own child, so reap it as soon as it exits; an unreaped zombie still
    // answers kill(pid, 0).
    let reaper = std::thread::spawn(move || child.wait());
    let stop = fx.cmd().args(["daemon", "stop", "--yes"]).output().unwrap();
    assert!(stop.status.success(), "{stop:?}");
    reaper.join().unwrap().unwrap();
}

#[test]
fn restart_replaces_a_running_daemon() {
    let fx = Fixture::new();
    let start = fx
        .cmd()
        .args(["daemon", "start", "--automatic"])
        .output()
        .unwrap();
    assert!(start.status.success(), "{start:?}");

    let restart = fx
        .cmd()
        .args(["daemon", "restart", "--yes"])
        .output()
        .unwrap();
    assert!(restart.status.success(), "{restart:?}");

    let _ = fx.cmd().args(["daemon", "stop", "--yes"]).output();
}
