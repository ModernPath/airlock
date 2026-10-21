//! Logs integration tests.
//!
//! Tests that the ring buffer logs are accessible and contain expected events.

#![cfg(any(target_os = "macos", target_os = "linux"))]

mod e2e_helpers;

use airlock::protocol::{AdminRequest, Auth, DaemonMessage, LogEntry, Request, RequestBody};
use e2e_helpers::*;

/// Helper: send an admin `Logs` request and return the entries.
fn fetch_logs(daemon: &DaemonHandle) -> Vec<LogEntry> {
    let mut stream = connect_to_daemon(&daemon.socket_path, 10);
    let req = Request {
        auth: Auth::Admin {
            token: daemon.admin_token.clone(),
        },
        body: RequestBody::Admin(AdminRequest::Logs { session: None }),
    };
    send_message(&mut stream, &req);

    let mut reader = std::io::BufReader::new(&mut stream);
    match read_response(&mut reader) {
        DaemonMessage::LogsResponse { entries } => entries,
        other => panic!("expected LogsResponse, got: {other:?}"),
    }
}

// ─── Logs contain tool spawn events after execution ──────────────────────────

#[test]
#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
fn logs_contain_tool_spawn_events() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();

    let result = exec_tool(
        &daemon,
        "sh",
        &["-c", "echo log_test_output"],
        cwd.to_str().unwrap(),
    );
    assert_eq!(result.exit_code, Some(0));

    let entries = fetch_logs(&daemon);

    let has_spawn = entries
        .iter()
        .any(|e| e.message.contains("spawned") && e.message.contains("sh"));
    assert!(
        has_spawn,
        "logs should contain a spawn entry for 'sh', got entries: {entries:?}"
    );

    let spawn_entry = entries
        .iter()
        .find(|e| e.message.contains("spawned"))
        .unwrap();
    assert!(
        spawn_entry.message.contains("PID"),
        "spawn entry should mention PID, got: {:?}",
        spawn_entry.message
    );
    assert_eq!(
        spawn_entry.session.as_deref(),
        Some(daemon.session_id.as_str()),
        "spawn entry should be tagged with the session"
    );

    daemon.shutdown();
}

// ─── Log entries have timestamps and messages ───────────────────────────────

#[test]
fn log_entries_have_timestamps_and_messages() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let entries = fetch_logs(&daemon);

    assert!(
        !entries.is_empty(),
        "logs should not be empty after daemon starts"
    );

    for entry in &entries {
        assert!(
            !entry.timestamp.is_empty(),
            "every log entry should have a non-empty timestamp"
        );
        assert!(
            !entry.message.is_empty(),
            "every log entry should have a non-empty message"
        );
    }

    daemon.shutdown();
}

// ─── Logs work before any tool has been executed ────────────────────────────

#[test]
fn logs_before_any_execution() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let entries = fetch_logs(&daemon);

    assert!(
        !entries.is_empty(),
        "logs should have startup entries even before any tool execution"
    );

    let has_startup = entries.iter().any(|e| e.message.contains("daemon started"));
    assert!(
        has_startup,
        "logs should contain 'daemon started' entry, got: {entries:?}"
    );

    daemon.shutdown();
}

// ─── Logs filtered by session omit another session's entries ───────────────

#[test]
#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
fn logs_filtered_by_session_omit_other_sessions() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let result = exec_tool(&daemon, "sh", &["-c", "echo hi"], cwd.to_str().unwrap());
    assert_eq!(result.exit_code, Some(0));

    let mut stream = connect_to_daemon(&daemon.socket_path, 10);
    let req = Request {
        auth: Auth::Admin {
            token: daemon.admin_token.clone(),
        },
        body: RequestBody::Admin(AdminRequest::Logs {
            session: Some(daemon.session_id.to_string()),
        }),
    };
    send_message(&mut stream, &req);
    let mut reader = std::io::BufReader::new(&mut stream);
    let entries = match read_response(&mut reader) {
        DaemonMessage::LogsResponse { entries } => entries,
        other => panic!("expected LogsResponse, got: {other:?}"),
    };
    assert!(!entries.is_empty());
    assert!(
        entries
            .iter()
            .all(|e| e.session.as_deref() == Some(daemon.session_id.as_str()))
    );

    daemon.shutdown();
}
