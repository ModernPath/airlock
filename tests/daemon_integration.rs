//! `airlock daemon` integration tests: `start`/`stop`/`logs`/`uninstall`
//! against the real v2 daemon and a throwaway runtime dir. `install` is
//! deliberately not exercised here; see the note on
//! `uninstall_when_nothing_installed_is_a_success_no_op`.

#![allow(
    clippy::disallowed_methods,
    reason = "test harness drives the real binary via its own process env, not daemon request-path code"
)]

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

// `daemon install` is deliberately not exercised here: on a fresh `HOME`
// it always calls through to the real `launchctl bootstrap`/`systemctl
// enable` (`service::install`'s `RealCommandRunner`, which this binary
// always uses — there is no test seam at the CLI layer), which would
// register a `RunAtLoad`+`KeepAlive` service against the *developer's*
// real session pointing at this test run's throwaway `target/debug`
// binary. `service::macos::tests`/`service::linux::tests` already cover
// `install`'s logic in full with a `RecordingRunner`; this suite only
// checks the one path that can never touch the real service manager.
#[test]
fn uninstall_when_nothing_installed_is_a_success_no_op() {
    let fx = Fixture::new();
    let output = fx.cmd().args(["daemon", "uninstall"]).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("not installed"));
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
