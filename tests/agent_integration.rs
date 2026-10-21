//! `airlock agent check` and `airlock agent hook` against a real daemon
//! and a real `airlock session start` registration.
//!
//! Unlike `run_integration.rs`'s sandboxed tests, nothing here spawns an
//! OS sandbox — `session start` just registers a session and prints
//! exports — so these tests need no nested sandbox.
//!
//! The session's token is bound to the process tree of whatever called
//! `admin::Register` (docs/airlock-v2-design.md, "Token binding"): for a
//! `session start` (`SessionEnds::Ttl`), that's the *parent* of the
//! `airlock session start` process, i.e. this test binary. Spawning
//! `airlock agent check` as a second, sibling child of this same test
//! binary keeps it inside that tree, so the daemon's `OutsideProcessTree`
//! check never fires.
//!
//! The probes run unsandboxed here (this test binary, not a real harness
//! sandbox), so the runtime-dir/trust-store/global-config/admin.token
//! probes are all expected to FAIL — that FAILure is exactly what proves
//! the probes are doing real `open`s rather than always reporting "ok".

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

/// Everything `session start` needs: a `$HOME`, XDG dirs under it, a
/// pre-created, correctly-moded runtime dir, and a project directory —
/// same shape as `run_integration.rs`'s `Fixture`.
struct Fixture {
    home: tempfile::TempDir,
    xdg_state: tempfile::TempDir,
    xdg_config: tempfile::TempDir,
    xdg_cache: tempfile::TempDir,
    runtime: tempfile::TempDir,
    project: tempfile::TempDir,
}

// A session this fixture started (or an automatic daemon still in its idle
// grace period) would otherwise keep the daemon running long after the
// test and its runtime dir are gone.
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.runtime.path().join("airlock.sock").exists() {
            let _ = self.cmd().args(["daemon", "stop", "--yes"]).output();
        }
    }
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
        // This suite may itself run under Airlock; the session it starts
        // stands in for one started from the user's own terminal.
        cmd.env_remove("AIRLOCK_SANDBOX");
        cmd.current_dir(self.project.path());
        cmd.stdin(std::process::Stdio::null());
        cmd
    }

    fn write_config(&self, content: &str) {
        std::fs::write(self.project.path().join("airlock.toml"), content).unwrap();
    }

    /// Trusts the project's config non-interactively, then starts a
    /// session and parses its exports.
    fn start_session(&self) -> (String, String) {
        let trust = self.cmd().args(["trust", "--yes"]).output().unwrap();
        assert!(trust.status.success(), "{trust:?}");

        let output = self
            .cmd()
            .args(["session", "start", "--format", "json", "--ttl", "1h"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|e| panic!("session start did not print JSON: {e}\n{output:?}"));
        let addr = value["addr"].as_str().unwrap().to_string();
        let session = value["session"].as_str().unwrap().to_string();
        (addr, session)
    }

    /// Runs `airlock agent <args>` as a direct child of this test
    /// process, with the given session env vars (or none).
    fn agent_cmd(&self, args: &[&str], session: Option<(&str, &str)>) -> std::process::Output {
        let mut cmd = self.cmd();
        cmd.args(args);
        if let Some((addr, token)) = session {
            cmd.env("AIRLOCK_ADDR", addr);
            cmd.env("AIRLOCK_SESSION", token);
        }
        cmd.output().unwrap()
    }
}

fn minimal_config() -> &'static str {
    "[tools.echo]\n"
}

// ─── agent check: probes actually run (and FAIL unsandboxed) ────────────────

#[test]
fn agent_check_fails_runtime_dir_and_trust_store_probes_when_unsandboxed() {
    let fx = Fixture::new();
    fx.write_config(minimal_config());
    let (addr, session) = fx.start_session();

    let output = fx.agent_cmd(&["agent", "check"], Some((&addr, &session)));
    let stdout = String::from_utf8_lossy(&output.stdout);

    // This test process can read and write everywhere it owns — none of
    // Airlock's own paths are actually sandboxed here — so every probe
    // that depends on a real OS sandbox must FAIL, and the command must
    // report that with exit 1 (docs/airlock-v2-ux.md, "`airlock agent
    // check`": "Exit status: ... 1 if a check fails").
    assert_eq!(output.status.code(), Some(1), "{stdout}\n{output:?}");
    assert!(stdout.contains("FAIL"), "{stdout}");
    assert!(stdout.contains("runtime dir"), "{stdout}");
    assert!(stdout.contains("trust store"), "{stdout}");
    assert!(stdout.contains("session   "), "{stdout}");
    assert!(stdout.contains("tools     echo"), "{stdout}");
}

#[test]
fn agent_check_quiet_prints_only_fail_and_warn_lines() {
    let fx = Fixture::new();
    fx.write_config(minimal_config());
    let (addr, session) = fx.start_session();

    let output = fx.agent_cmd(&["agent", "check", "-q"], Some((&addr, &session)));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(1), "{stdout}\n{output:?}");
    assert!(stdout.contains("FAIL"), "{stdout}");
    // `-q` drops every header line and every "ok" line.
    assert!(!stdout.contains("session   "), "{stdout}");
    assert!(!stdout.contains("tools     "), "{stdout}");
    assert!(
        !stdout.lines().any(|l| l.trim_start().starts_with("ok ")),
        "{stdout}"
    );
}

#[test]
fn agent_check_without_session_env_reports_no_session() {
    let fx = Fixture::new();
    let output = fx.agent_cmd(&["agent", "check"], None);
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("airlock: "), "{stderr}");
    assert!(stderr.contains("no Airlock session"), "{stderr}");
}

// ─── agent hook: no config in the project prints nothing ────────────────────

#[test]
fn agent_hook_prints_nothing_without_config_or_session() {
    let fx = Fixture::new();
    // No airlock.toml written: this project has no Airlock config at all.
    let output = fx.agent_cmd(&["agent", "hook", "claude-code"], None);
    assert!(output.status.success(), "{output:?}");
    assert!(
        output.stdout.is_empty(),
        "expected no output, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn agent_hook_without_session_but_with_config_reports_no_session() {
    let fx = Fixture::new();
    fx.write_config(minimal_config());
    let output = fx.agent_cmd(&["agent", "hook", "claude-code"], None);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("hook did not print JSON: {e}\n{stdout}"));
    assert!(
        value["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap()
            .contains("was not started with `airlock run`")
    );
    assert_eq!(
        value["systemMessage"],
        serde_json::Value::String(
            "Airlock: this agent has no session. Start it with `airlock run`.".to_string()
        )
    );
}

#[test]
fn agent_hook_print_settings_matches_the_installed_hook_command() {
    let fx = Fixture::new();
    let output = fx.agent_cmd(&["agent", "hook", "claude-code", "--print-settings"], None);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("airlock agent hook claude-code"),
        "{stdout}"
    );
    assert!(stdout.contains("SessionStart"), "{stdout}");
}

// Sanity check mirroring run_integration.rs's: the fixture's runtime dir
// is actually usable before any test above assumes it.
#[test]
fn fixture_runtime_dir_has_expected_mode() {
    let fx = Fixture::new();
    let mode = std::fs::metadata(fx.runtime.path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
    let _ = PathBuf::from(".");
}
