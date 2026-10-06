//! Top-level CLI surface tests: help/version, `init`, `config`, `status`,
//! the sandbox refusal table and help restriction (docs/airlock-v2-ux.md,
//! "Commands refused inside the sandbox" and U16), and the agent-facing "no
//! session" messages for `exec`/`tools list`. A few `status` tests start a
//! real daemon (via `e2e_helpers`) to see a session reported; none of them
//! exec a tool, so — unlike `run_integration.rs`/`exec_integration.rs` —
//! nothing here needs a nestable sandbox.

#![allow(
    clippy::disallowed_methods,
    reason = "test harness drives the real binary via its own process env, not daemon request-path code"
)]

use std::path::Path;
use std::process::Command;

mod e2e_helpers;

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
    // `inspect::init_cmd` writes everything — success lines and errors
    // alike — to the single `out` writer main.rs maps to stdout; the exit
    // code is what distinguishes them.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("already exists"), "{stdout}");
}

#[test]
fn init_local_lists_unbound_repo_labels() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("airlock.toml"),
        "[secrets.GH_TOKEN]\ndescription = \"GitHub token with read access\"\n",
    )
    .unwrap();

    let output = base_cmd(home.path())
        .current_dir(project.path())
        .args(["init", "--local"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(project.path().join("airlock.local.toml").exists());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("GH_TOKEN"), "{text}");
    assert!(text.contains("not bound"), "{text}");
}

#[test]
fn init_global_creates_the_user_config() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path())
        .current_dir(project.path())
        .args(["init", "--global"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(home.path().join(".config/airlock/airlock.toml").exists());
}

// ─── config ───────────────────────────────────────────────────────────────────

#[test]
fn config_shows_layers_and_tools_for_a_two_layer_project() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("airlock.toml"),
        "[tools.gh]\ndescription = \"GitHub CLI\"\n",
    )
    .unwrap();
    std::fs::write(project.path().join("airlock.local.toml"), "").unwrap();

    let output = base_cmd(home.path())
        .env("AIRLOCK_TEST_RUNTIME_DIR", runtime.path().join("rt"))
        .current_dir(project.path())
        .arg("config")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.starts_with("layers\n"), "{text}");
    assert!(
        text.contains("repo") && text.contains("airlock.toml"),
        "{text}"
    );
    assert!(
        text.contains("local") && text.contains("airlock.local.toml"),
        "{text}"
    );
    assert!(text.contains("tools\n"), "{text}");
    assert!(text.contains("gh"), "{text}");
    assert!(text.contains("GitHub CLI"), "{text}");
}

#[test]
fn config_paths_lists_the_well_known_locations() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("airlock.toml"), "[tools.sh]\n").unwrap();

    let output = base_cmd(home.path())
        .env("AIRLOCK_TEST_RUNTIME_DIR", runtime.path().join("rt"))
        .current_dir(project.path())
        .args(["config", "--paths"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    for label in [
        "global config",
        "repo config",
        "trust store",
        "runtime dir",
        "socket",
        "tool state",
    ] {
        assert!(text.contains(label), "missing {label:?}\n{text}");
    }
}

// ─── status ───────────────────────────────────────────────────────────────────

#[test]
fn status_exit_3_when_daemon_not_running() {
    let home = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path())
        .env("AIRLOCK_TEST_RUNTIME_DIR", runtime.path().join("rt"))
        .arg("status")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "daemon not running\n"
    );
}

#[test]
fn status_exit_0_and_shows_the_session_when_the_daemon_runs() {
    let project = tempfile::tempdir().unwrap();
    let root = project.path().canonicalize().unwrap();
    e2e_helpers::write_config(&root, "allow_home_root = true\n\n[tools.sh]\n");
    let daemon = e2e_helpers::start_daemon(&root);
    let runtime_dir = daemon.socket_path.parent().unwrap().to_path_buf();

    let home = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path())
        .env("AIRLOCK_TEST_RUNTIME_DIR", &runtime_dir)
        .current_dir(&root)
        .arg("status")
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("running, PID"), "{text}");
    assert!(text.contains(daemon.session_id.as_str()), "{text}");
    assert!(text.contains("1 here, 1 in total"), "{text}");

    daemon.shutdown();
}

// ─── session reload ──────────────────────────────────────────────────────────

#[test]
fn session_reload_notes_agent_settings_changed() {
    // e2e_helpers registers over the raw protocol with a fake `agent_hash`
    // ("deadbeef") rather than the real launcher's, so any real reload's
    // freshly computed hash is guaranteed to differ — exactly the case
    // `[agent]` settings changed; restart the agent to apply them exists
    // for (docs/airlock-v2-design.md, "The agent changes the config").
    let project = tempfile::tempdir().unwrap();
    let root = project.path().canonicalize().unwrap();
    e2e_helpers::write_config(&root, "[tools.sh]\n\n[agent]\ntimeout = 30\n");

    let home = tempfile::tempdir().unwrap();
    let trust_runtime = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        trust_runtime.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let trust = base_cmd(home.path())
        .env("AIRLOCK_TEST_RUNTIME_DIR", trust_runtime.path())
        .current_dir(&root)
        .args(["trust", "--yes"])
        .output()
        .unwrap();
    assert!(trust.status.success(), "{trust:?}");

    let daemon = e2e_helpers::start_daemon(&root);
    let runtime_dir = daemon.socket_path.parent().unwrap().to_path_buf();

    let output = base_cmd(home.path())
        .env("AIRLOCK_TEST_RUNTIME_DIR", &runtime_dir)
        .current_dir(&root)
        .args(["session", "reload"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("note: agent settings changed; restart the agent to apply them"),
        "{text}"
    );

    daemon.shutdown();
}

// ─── --help grouping (U5) and the sandboxed help restriction (U16) ──────────

#[test]
fn help_groups_commands_by_audience_and_points_to_init_then_run() {
    let home = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path()).arg("--help").output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    for header in [
        "Start an agent",
        "Use tools",
        "Manage",
        "For the agent and its harness",
    ] {
        assert!(text.contains(header), "missing {header:?}\n{text}");
    }
    for name in [
        "run", "init", "trust", "config", "status", "exec", "tools", "session", "daemon", "agent",
    ] {
        assert!(text.contains(name), "missing {name:?}\n{text}");
    }
    assert!(text.contains("airlock init"), "{text}");
    assert!(text.contains("airlock run --profile claude"), "{text}");
}

#[test]
fn sandboxed_help_lists_only_five_commands_and_names_the_hidden_ones() {
    let home = tempfile::tempdir().unwrap();
    let output = sandboxed_cmd(home.path()).arg("--help").output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("sandbox"), "{text}");
    for name in ["exec", "tools", "agent", "init", "config"] {
        assert!(text.contains(name), "missing {name:?}\n{text}");
    }
    for hidden in ["run", "trust", "status", "session", "daemon"] {
        assert!(
            text.contains(hidden),
            "missing mention of {hidden:?}\n{text}"
        );
    }
    assert!(!text.contains("Manage the Airlock daemon"), "{text}");
}

#[test]
fn sandboxed_no_args_shows_the_same_restricted_listing() {
    let home = tempfile::tempdir().unwrap();
    let output = sandboxed_cmd(home.path()).output().unwrap();
    // `arg_required_else_help` renders through clap's usage-error path
    // (exit code 2, text on stderr), unlike an explicit `--help` (exit 0,
    // stdout) — both must show the same restricted listing (U16).
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("sandbox"), "{text}");
    assert!(text.contains("exec"), "{text}");
}

#[test]
fn sandboxed_hidden_commands_own_help_still_works_and_says_so_first() {
    let home = tempfile::tempdir().unwrap();
    let output = sandboxed_cmd(home.path())
        .args(["run", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.starts_with("`airlock run` needs your own terminal"),
        "{text}"
    );
}

#[test]
fn daemon_help_notes_the_automatic_daemon_lifecycle() {
    let home = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path())
        .args(["daemon", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("session start"), "{text}");
    assert!(text.contains("5 minutes"), "{text}");
}

// ─── Phase-3 stubs (still unimplemented: another agent owns src/agent.rs) ────

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
fn agent_hook_outside_an_airlock_project_prints_nothing() {
    let home = tempfile::tempdir().unwrap();
    let output = base_cmd(home.path())
        .args(["agent", "hook", "claude-code"])
        .current_dir(home.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty(), "{output:?}");
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
