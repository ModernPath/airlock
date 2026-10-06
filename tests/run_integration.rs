//! `airlock run` integration tests.
//!
//! Most of what `run` does before spawning the agent — discovery, merge
//! validation, trust — needs neither a daemon nor a sandbox, so it is
//! tested here against the real binary. Anything past that point needs
//! either a real v2 daemon (not in this worktree — P2-G's rewrite lands at
//! the phase-2 merge) or a nestable sandbox (this session already runs
//! inside Airlock's own Seatbelt profile, and nested Seatbelt/Landlock is
//! rejected by the kernel) — those are written but `#[ignore]`d per the v2
//! implementation contract's environment rules.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn airlock_bin() -> &'static str {
    env!("CARGO_BIN_EXE_airlock")
}

/// Everything a discovery-and-trust test needs: a `$HOME`, XDG dirs under
/// it, a pre-created, correctly-moded runtime dir (so `anchors::validate`'s
/// ownership/mode checks pass without a daemon ever having run), and a
/// project directory.
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
        cmd.current_dir(self.project.path());
        cmd.stdin(std::process::Stdio::null());
        cmd
    }

    fn write_config(&self, content: &str) -> PathBuf {
        let path = self.project.path().join("airlock.toml");
        std::fs::write(&path, content).unwrap();
        path
    }
}

fn minimal_config() -> &'static str {
    "[tools.echo]\n"
}

// ─── No project config ────────────────────────────────────────────────────────

#[test]
fn run_without_project_config_names_init_and_no_project_config() {
    let fx = Fixture::new();
    let output = fx.cmd().args(["run", "--", "echo", "hi"]).output().unwrap();
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no airlock.toml"), "{stderr}");
    assert!(stderr.contains("airlock init"), "{stderr}");
    assert!(stderr.contains("--no-project-config"), "{stderr}");
}

// ─── Untrusted config, non-interactive ───────────────────────────────────────

#[test]
fn run_with_unapproved_config_noninteractive_refuses_and_points_to_trust() {
    let fx = Fixture::new();
    fx.write_config(minimal_config());
    let output = fx.cmd().args(["run", "--", "echo", "hi"]).output().unwrap();
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("is not trusted yet"), "{stderr}");
    assert!(
        stderr.contains("run `airlock trust` in a terminal to approve it"),
        "{stderr}"
    );
}

#[test]
fn run_no_command_and_no_profile_errors() {
    let fx = Fixture::new();
    fx.write_config(minimal_config());
    let output = fx.cmd().args(["run"]).output().unwrap();
    assert_eq!(output.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no command specified"));
}

// ─── Trust, then run (reaches the sandbox — needs a nestable sandbox) ───────

#[test]
#[ignore = "needs a nestable sandbox; run outside Airlock with: cargo test -- --ignored"]
fn run_no_session_after_trust_runs_the_command() {
    let fx = Fixture::new();
    fx.write_config(minimal_config());

    let trust_output = fx.cmd().args(["trust", "--yes"]).output().unwrap();
    assert!(trust_output.status.success(), "{trust_output:?}");

    let output = fx
        .cmd()
        .args(["run", "--no-session", "--", "/bin/echo", "hello"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
}

#[test]
#[ignore = "needs the v2 daemon (phase 2 merge)"]
fn run_with_session_registers_and_execs_through_the_daemon() {
    let fx = Fixture::new();
    fx.write_config(minimal_config());
    let trust_output = fx.cmd().args(["trust", "--yes"]).output().unwrap();
    assert!(trust_output.status.success());

    let output = fx
        .cmd()
        .args(["run", "--", "/bin/echo", "hello"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

// Sanity check that the fixture's runtime dir is actually usable by
// `anchors::validate` the way the other tests assume (mode 0700, owned by
// us) — catches a fixture regression before it masquerades as a product
// bug in the tests above.
#[test]
fn fixture_runtime_dir_has_expected_mode() {
    let fx = Fixture::new();
    let mode = std::fs::metadata(fx.runtime.path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
    let _ = Path::new(".");
}
