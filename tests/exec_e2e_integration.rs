//! End-to-end tool execution tests.
//!
//! Tests the complete exec flow from client request through daemon spawn to
//! output and exit code.

#![cfg(any(target_os = "macos", target_os = "linux"))]

mod e2e_helpers;

use e2e_helpers::*;

// ─── Stdout from a tool is received correctly by the client ─────────────────

#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
#[test]
fn exec_tool_stdout_received_correctly() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let result = exec_tool(
        &daemon,
        "sh",
        &["-c", "echo hello world"],
        cwd.to_str().unwrap(),
    );

    assert_eq!(result.exit_code, Some(0), "tool should exit with code 0");
    assert!(
        result.stdout.contains("hello world"),
        "stdout should contain 'hello world', got: {:?}",
        result.stdout
    );

    daemon.shutdown();
}

// ─── Stderr from a tool is received separately from stdout ──────────────────

#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
#[test]
fn exec_tool_stderr_separate_from_stdout() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let result = exec_tool(
        &daemon,
        "sh",
        &["-c", "echo stdout_data && echo stderr_data >&2"],
        cwd.to_str().unwrap(),
    );

    assert_eq!(result.exit_code, Some(0));
    assert!(
        result.stdout.contains("stdout_data"),
        "stdout should contain 'stdout_data', got: {:?}",
        result.stdout
    );
    assert!(
        result.stderr.contains("stderr_data"),
        "stderr should contain 'stderr_data', got: {:?}",
        result.stderr
    );
    // Verify no cross-contamination.
    assert!(
        !result.stdout.contains("stderr_data"),
        "stdout should NOT contain stderr data"
    );
    assert!(
        !result.stderr.contains("stdout_data"),
        "stderr should NOT contain stdout data"
    );

    daemon.shutdown();
}

// ─── Non-zero exit codes are propagated faithfully ──────────────────────────

#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
#[test]
fn exec_tool_nonzero_exit_code_propagated() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let result = exec_tool(&daemon, "sh", &["-c", "exit 42"], cwd.to_str().unwrap());

    assert_eq!(
        result.exit_code,
        Some(42),
        "exit code should be 42, got: {:?}",
        result.exit_code
    );

    daemon.shutdown();
}

// ─── Unknown tool name produces an error ────────────────────────────────────

#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
#[test]
fn exec_unknown_tool_produces_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let result = exec_tool(&daemon, "nonexistent_tool_xyz", &[], cwd.to_str().unwrap());

    assert!(
        result.error.is_some(),
        "should receive an error for unknown tool"
    );
    let error = result.error.unwrap();
    assert!(
        error.contains("unknown tool") || error.contains("nonexistent_tool_xyz"),
        "error should mention unknown tool or tool name, got: {error}"
    );

    daemon.shutdown();
}

// ─── CWD outside sandbox root produces an error ─────────────────────────────

#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
#[test]
fn exec_cwd_outside_sandbox_root_produces_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let result = exec_tool(&daemon, "sh", &["-c", "echo hi"], "/tmp");

    assert!(
        result.error.is_some(),
        "should receive an error for CWD outside sandbox"
    );
    let error = result.error.unwrap();
    assert!(
        error.contains("is outside this session's project"),
        "error should say the working directory is outside the project, got: {error}"
    );

    daemon.shutdown();
}

// ─── Missing binary produces a clear error ──────────────────────────────────

#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
#[test]
fn exec_missing_binary_produces_error() {
    let tmp = tempfile::tempdir().unwrap();
    // Configure a tool named 'nonexistent_binary_xyz' that won't exist on disk.
    let config = config_with_tools(
        r#"
[tools.nonexistent_binary_xyz]
"#,
    );
    write_config(tmp.path(), &config);

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let result = exec_tool(
        &daemon,
        "nonexistent_binary_xyz",
        &[],
        cwd.to_str().unwrap(),
    );

    assert!(
        result.error.is_some(),
        "should receive an error for missing binary"
    );
    let error = result.error.unwrap();
    assert!(
        error.contains("binary") || error.contains("not found") || error.contains("resolution"),
        "error should mention binary resolution failure, got: {error}"
    );

    daemon.shutdown();
}

// ─── The real client with no stdin keeps the connection open ────────────────

// An agent's tool calls usually have stdin at EOF (`/dev/null`, an empty
// pipe). The client must still keep its write half open until the tool
// exits: the daemon reads EOF on the connection as "the client went away"
// and kills the tool. The tool sleeps so it is still running when the
// client's stdin EOF arrives; the raw-protocol tests above never close
// their write half, so only the real binary exercises this.
#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
#[test]
fn real_client_with_stdin_at_eof_waits_for_the_tool() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_airlock"))
        .env_remove("AIRLOCK_SANDBOX")
        .env(
            "AIRLOCK_ADDR",
            format!("unix://{}", daemon.socket_path.display()),
        )
        .env("AIRLOCK_SESSION", daemon.token.expose_secret())
        .current_dir(&cwd)
        .args(["exec", "--", "sh", "-c", "sleep 1; echo done"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "done\n");

    daemon.shutdown();
}
