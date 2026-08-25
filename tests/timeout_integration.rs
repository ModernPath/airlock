//! Timeout enforcement integration tests.
//!
//! Tests that timeout enforcement kills the tool and reports the timeout.

#![cfg(any(target_os = "macos", target_os = "linux"))]

mod e2e_helpers;

use std::time::Duration;

use airlock::protocol::{ClientMessage, DaemonMessage};
use e2e_helpers::*;

// ─── Timed-out tool is killed and client receives timeout error ─────────────

#[test]
fn timed_out_tool_killed_and_client_gets_timeout_error() {
    let tmp = tempfile::tempdir().unwrap();

    // Configure a very short global timeout (2 seconds).
    let config = config_with_tools(
        r#"
timeout = 2

[tools.sh]
"#,
    );
    write_config(tmp.path(), &config);

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();

    // Run a long-running command that will be killed by the timeout.
    // Use `sh -c 'echo $$; exec sleep 600'` to get the PID for later checks.
    let mut stream = connect_to_daemon(&daemon.socket_path, 30);

    let exec_msg = ClientMessage::Exec {
        tool: "sh".to_string(),
        args: vec!["-c".to_string(), "echo $$; exec sleep 600".to_string()],
        cwd: cwd.to_str().unwrap().to_string(),
    };
    send_message(&mut stream, &exec_msg);

    // Collect responses.
    let mut stdout = String::new();
    let mut error_msg = None;

    let mut reader = std::io::BufReader::new(&mut stream);
    loop {
        match try_read_response(&mut reader) {
            Some(DaemonMessage::Stdout { data }) => stdout.push_str(&data),
            Some(DaemonMessage::Stderr { .. }) => {}
            Some(DaemonMessage::Error { message }) => {
                error_msg = Some(message);
                break;
            }
            Some(DaemonMessage::Exit { .. }) => {
                // Shouldn't happen for timeout, but break anyway.
                break;
            }
            _ => break,
        }
    }

    assert!(
        error_msg.is_some(),
        "should receive a timeout error message"
    );
    let error = error_msg.unwrap();
    assert!(
        error.contains("timed out") || error.contains("timeout"),
        "error should mention timeout, got: {error}"
    );

    // Verify the tool's process group is terminated.
    // Extract the PID from stdout (the tool printed its PID before exec sleep).
    if let Ok(child_pid) = stdout.trim().parse::<u32>() {
        // Brief wait for cleanup.
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            !is_process_alive(child_pid),
            "timed-out tool's process (PID {child_pid}) should be terminated"
        );
    }

    daemon.shutdown();
}

// ─── A tool finishing before timeout completes normally ──────────────────────

#[test]
fn tool_finishing_before_timeout_completes_normally() {
    let tmp = tempfile::tempdir().unwrap();

    // 60-second timeout — plenty of time for a quick command.
    let config = config_with_tools(
        r#"
timeout = 60

[tools.sh]
"#,
    );
    write_config(tmp.path(), &config);

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let result = exec_tool(
        &daemon.socket_path,
        "sh",
        &["-c", "echo done quickly"],
        cwd.to_str().unwrap(),
    );

    assert_eq!(
        result.exit_code,
        Some(0),
        "should exit normally with code 0"
    );
    assert!(
        result.stdout.contains("done quickly"),
        "should contain normal output"
    );
    assert!(
        result.error.is_none(),
        "should not have any error (no timeout)"
    );

    daemon.shutdown();
}

// ─── Per-tool timeout override is respected over the global timeout ─────────

#[test]
fn per_tool_timeout_override_respected() {
    let tmp = tempfile::tempdir().unwrap();

    // Global timeout is very long (300s), but per-tool timeout is 2s.
    let config = config_with_tools(
        r#"
timeout = 300

[tools.sh]
timeout = 2
"#,
    );
    write_config(tmp.path(), &config);

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();

    let start = std::time::Instant::now();

    let mut stream = connect_to_daemon(&daemon.socket_path, 30);

    let exec_msg = ClientMessage::Exec {
        tool: "sh".to_string(),
        args: vec!["-c".to_string(), "sleep 600".to_string()],
        cwd: cwd.to_str().unwrap().to_string(),
    };
    send_message(&mut stream, &exec_msg);

    let mut error_msg = None;

    let mut reader = std::io::BufReader::new(&mut stream);
    loop {
        match try_read_response(&mut reader) {
            Some(DaemonMessage::Stdout { .. }) => {}
            Some(DaemonMessage::Stderr { .. }) => {}
            Some(DaemonMessage::Error { message }) => {
                error_msg = Some(message);
                break;
            }
            Some(DaemonMessage::Exit { .. }) => break,
            _ => break,
        }
    }

    let elapsed = start.elapsed();

    assert!(
        error_msg.is_some(),
        "should receive a timeout error from per-tool timeout"
    );
    let error = error_msg.unwrap();
    assert!(
        error.contains("timed out") || error.contains("timeout"),
        "error should mention timeout, got: {error}"
    );

    // The timeout should trigger around 2s, not 300s.
    assert!(
        elapsed < Duration::from_secs(30),
        "per-tool timeout of 2s should trigger well before 300s global timeout; elapsed: {:?}",
        elapsed
    );

    daemon.shutdown();
}
