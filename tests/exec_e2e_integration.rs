//! End-to-end tool execution tests.
//!
//! Tests the complete exec flow from client request through daemon spawn to
//! output and exit code.

#![cfg(any(target_os = "macos", target_os = "linux"))]

mod e2e_helpers;

use e2e_helpers::*;

// ─── Stdout from a tool is received correctly by the client ─────────────────

#[test]
fn exec_tool_stdout_received_correctly() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let result = exec_tool(
        &daemon.socket_path,
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

#[test]
fn exec_tool_stderr_separate_from_stdout() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let result = exec_tool(
        &daemon.socket_path,
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

#[test]
fn exec_tool_nonzero_exit_code_propagated() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let result = exec_tool(
        &daemon.socket_path,
        "sh",
        &["-c", "exit 42"],
        cwd.to_str().unwrap(),
    );

    assert_eq!(
        result.exit_code,
        Some(42),
        "exit code should be 42, got: {:?}",
        result.exit_code
    );

    daemon.shutdown();
}

// ─── Unknown tool name produces an error ────────────────────────────────────

#[test]
fn exec_unknown_tool_produces_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let result = exec_tool(
        &daemon.socket_path,
        "nonexistent_tool_xyz",
        &[],
        cwd.to_str().unwrap(),
    );

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

#[test]
fn exec_cwd_outside_sandbox_root_produces_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let result = exec_tool(&daemon.socket_path, "sh", &["-c", "echo hi"], "/tmp");

    assert!(
        result.error.is_some(),
        "should receive an error for CWD outside sandbox"
    );
    let error = result.error.unwrap();
    assert!(
        error.contains("CWD") || error.contains("cwd") || error.contains("sandbox"),
        "error should mention CWD validation failure, got: {error}"
    );

    daemon.shutdown();
}

// ─── Missing binary produces a clear error ──────────────────────────────────

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
        &daemon.socket_path,
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
