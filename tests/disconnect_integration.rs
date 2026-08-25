//! Client disconnect integration tests.
//!
//! Tests that the daemon kills the tool when the client disconnects.

#![cfg(any(target_os = "macos", target_os = "linux"))]

mod e2e_helpers;

use std::time::Duration;

use airlock::protocol::{ClientMessage, DaemonMessage};
use e2e_helpers::*;

// ─── Tool's process group is killed when client disconnects ─────────────────

#[test]
fn tool_killed_when_client_disconnects() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();

    // Start a long-running tool that prints its PID.
    let mut stream = connect_to_daemon(&daemon.socket_path, 30);

    let exec_msg = ClientMessage::Exec {
        tool: "sh".to_string(),
        args: vec!["-c".to_string(), "echo $$; exec sleep 600".to_string()],
        cwd: cwd.to_str().unwrap().to_string(),
    };
    send_message(&mut stream, &exec_msg);

    // Read the PID from stdout.
    let mut child_pid: Option<u32> = None;

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut reader = std::io::BufReader::new(&mut stream);

    // Read until we get the PID from stdout.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if std::time::Instant::now() > deadline {
            break;
        }
        match try_read_response(&mut reader) {
            Some(DaemonMessage::Stdout { data }) => {
                if let Ok(pid) = data.trim().parse::<u32>() {
                    child_pid = Some(pid);
                    break;
                }
            }
            Some(DaemonMessage::Stderr { .. }) => {}
            _ => break,
        }
    }

    let child_pid = child_pid.expect("should have received child PID");

    // Verify the child is alive.
    assert!(
        is_process_alive(child_pid),
        "child process should be alive before disconnect"
    );

    // Disconnect by dropping the stream.
    drop(reader);
    drop(stream);

    // Wait for the daemon to detect the disconnect and kill the child.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        std::thread::sleep(Duration::from_millis(200));
        if !is_process_alive(child_pid) {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "child PID {child_pid} should be killed after client disconnect, but is still alive"
            );
        }
    }

    // Verify the child PID is no longer alive.
    assert!(
        !is_process_alive(child_pid),
        "child PID {child_pid} should not be alive after disconnect cleanup"
    );

    daemon.shutdown();
}
