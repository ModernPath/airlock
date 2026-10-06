//! Top-level CLI surface tests: things that are true regardless of whether
//! a daemon exists — help/version, `init`, the sandbox refusal table
//! (docs/airlock-v2-ux.md, "Commands refused inside the sandbox"), and the
//! agent-facing "no session" messages for `exec`/`tools list`.
//!
//! Tests that need a real v2 daemon are in `run_integration.rs` and
//! `daemon_integration.rs`, marked `#[ignore = "needs the v2 daemon (phase 2
//! merge)"]` per the v2 implementation contract.

use std::path::Path;
use std::process::Command;

fn airlock_bin() -> &'static str {
    env!("CARGO_BIN_EXE_airlock")
}

/// A bare `Command` with no inherited environment, a temp `$HOME`, and
/// `stdin` closed — `cargo test < /dev/null` per CLAUDE.md, but tests also
/// close it explicitly so they don't depend on how they're invoked.
fn base_cmd(home: &Path) -> Command {
    let mut cmd = Command::new(airlock_bin());
    cmd.env_clear();
    cmd.env("HOME", home);
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    cmd.stdin(std::process::Stdio::null());
    cmd
}

// ─── Version / help ───────────────────────────────────────────────────────────

#[test]
fn version_flag_prints_something() {
    let home = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path()).arg("--version").output().unwrap();
    assert!(output.status.success());
    assert!(!output.stdout.is_empty());
}

#[test]
fn help_lists_every_top_level_command() {
    let home = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path()).arg("--help").output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    for name in [
        "run", "init", "trust", "config", "status", "exec", "tools", "agent", "session", "daemon",
    ] {
        assert!(text.contains(name), "help text missing {name:?}:\n{text}");
    }
}

// ─── init ─────────────────────────────────────────────────────────────────────

#[test]
fn init_creates_airlock_toml() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path())
        .current_dir(project.path())
        .arg("init")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(project.path().join("airlock.toml").exists());
}

#[test]
fn init_fails_if_file_exists() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("airlock.toml"), "").unwrap();
    let output = base_cmd(home.path())
        .current_dir(project.path())
        .arg("init")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already exists"), "{stderr}");
}

#[test]
fn init_local_and_global_are_phase_three_stubs() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path())
        .current_dir(project.path())
        .args(["init", "--local"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not implemented yet"));
}

// ─── Phase-3 stubs ────────────────────────────────────────────────────────────

#[test]
fn status_is_a_phase_three_stub() {
    let home = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path()).arg("status").output().unwrap();
    assert_eq!(output.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not implemented yet"));
}

#[test]
fn config_is_a_phase_three_stub() {
    let home = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path()).arg("config").output().unwrap();
    assert_eq!(output.status.code(), Some(125));
}

#[test]
fn agent_check_is_a_phase_three_stub() {
    let home = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path())
        .args(["agent", "check"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
}

#[test]
fn agent_hook_is_a_phase_three_stub() {
    let home = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path())
        .args(["agent", "hook", "claude-code"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
}

// ─── Agent-facing "no session" messages ──────────────────────────────────────

#[test]
fn exec_without_session_env_reports_no_session() {
    let home = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path())
        .args(["exec", "--", "echo", "hi"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("airlock: "), "{stderr}");
    assert!(stderr.contains("no Airlock session"), "{stderr}");
}

#[test]
fn tools_list_without_session_env_reports_no_session() {
    let home = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path())
        .args(["tools", "list"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("airlock: "), "{stderr}");
    assert!(stderr.contains("no Airlock session"), "{stderr}");
}

#[test]
fn bare_tools_is_an_alias_for_tools_list() {
    let home = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path()).args(["tools"]).output().unwrap();
    assert_eq!(output.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no Airlock session"));
}

// ─── Sandbox refusal (U16, docs/airlock-v2-ux.md "Commands refused inside
//     the sandbox") ──────────────────────────────────────────────────────────

fn sandboxed_cmd(home: &Path) -> Command {
    let mut cmd = base_cmd(home);
    cmd.env("AIRLOCK_SANDBOX", "1");
    cmd
}

#[test]
fn run_refuses_inside_the_sandbox() {
    let home = tempfile::tempdir().unwrap();
    let output = sandboxed_cmd(home.path())
        .args(["run", "--", "echo", "hi"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot run inside an Airlock sandbox"),
        "{stderr}"
    );
}

#[test]
fn trust_refuses_inside_the_sandbox() {
    let home = tempfile::tempdir().unwrap();
    let output = sandboxed_cmd(home.path()).arg("trust").output().unwrap();
    assert_eq!(output.status.code(), Some(125));
}

#[test]
fn status_refuses_inside_the_sandbox_with_agent_check_hint() {
    let home = tempfile::tempdir().unwrap();
    let output = sandboxed_cmd(home.path()).arg("status").output().unwrap();
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("agent check"), "{stderr}");
}

#[test]
fn session_refuses_inside_the_sandbox() {
    let home = tempfile::tempdir().unwrap();
    let output = sandboxed_cmd(home.path())
        .args(["session", "list"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
}

#[test]
fn daemon_refuses_inside_the_sandbox() {
    let home = tempfile::tempdir().unwrap();
    let output = sandboxed_cmd(home.path())
        .args(["daemon", "logs"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
}

#[test]
fn init_global_refuses_inside_the_sandbox() {
    let home = tempfile::tempdir().unwrap();
    let output = sandboxed_cmd(home.path())
        .args(["init", "--global"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot run inside an Airlock sandbox"),
        "{stderr}"
    );
}

#[test]
fn init_plain_is_allowed_inside_the_sandbox() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let output = sandboxed_cmd(home.path())
        .current_dir(project.path())
        .arg("init")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn tools_list_with_session_flag_refuses_inside_the_sandbox() {
    let home = tempfile::tempdir().unwrap();
    let output = sandboxed_cmd(home.path())
        .args(["tools", "list", "--session", "abc123"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
}

#[test]
fn exec_is_allowed_inside_the_sandbox() {
    // Allowed by the table, but still has no session in this test, so it
    // fails for that reason instead — proving it is not the sandbox check
    // that stopped it.
    let home = tempfile::tempdir().unwrap();
    let output = sandboxed_cmd(home.path())
        .args(["exec", "--", "echo", "hi"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no Airlock session"), "{stderr}");
}
