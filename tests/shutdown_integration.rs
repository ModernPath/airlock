//! Graceful shutdown with active children tests.
//!
//! Tests that the daemon cleans up active children during shutdown.

#![cfg(any(target_os = "macos", target_os = "linux"))]

mod e2e_helpers;

use std::os::unix::net::UnixStream;
use std::time::Duration;

use airlock::protocol::{ClientMessage, DaemonMessage};
use e2e_helpers::*;

// ─── SIGTERM during active tool execution kills tool and exits cleanly ───────

#[test]
fn sigterm_during_active_tool_kills_tool_and_exits_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let socket_path = daemon.socket_path.clone();
    let pid_path = daemon.pid_path.clone();
    let daemon_pid = daemon.daemon_pid;

    // Start a long-running tool that prints its PID.
    let mut stream = connect_to_daemon(&socket_path, 30);
    let exec_msg = ClientMessage::Exec {
        tool: "sh".to_string(),
        args: vec!["-c".to_string(), "echo $$; exec sleep 600".to_string()],
        cwd: cwd.to_str().unwrap().to_string(),
    };
    send_message(&mut stream, &exec_msg);

    // Read the child PID from stdout.
    let mut child_pid: Option<u32> = None;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    {
        let mut reader = std::io::BufReader::new(&mut stream);
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
    }

    let child_pid = child_pid.expect("should have received child PID");
    assert!(is_process_alive(child_pid), "child should be alive");

    // Send SIGTERM to the daemon.
    unsafe {
        libc::kill(daemon_pid as i32, libc::SIGTERM);
    }

    // Wait for the daemon to shut down.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if daemon.join_handle.is_finished() {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("daemon thread did not finish after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    daemon.join_handle.join().expect("daemon thread clean exit");

    // Verify the child process is killed.
    // Give a brief moment for process cleanup.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !is_process_alive(child_pid),
        "child PID {child_pid} should be terminated after daemon shutdown"
    );

    // Verify socket and PID files are removed.
    assert!(
        !socket_path.exists(),
        "socket file should be removed after shutdown"
    );
    assert!(
        !pid_path.exists(),
        "PID file should be removed after shutdown"
    );
}

// ─── Multiple active tools are all terminated during shutdown ────────────────

#[test]
fn multiple_active_tools_terminated_during_shutdown() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let socket_path = daemon.socket_path.clone();
    let pid_path = daemon.pid_path.clone();
    let daemon_pid = daemon.daemon_pid;

    // Start two long-running tools on separate connections.
    let collect_pid = |conn: &mut UnixStream| -> u32 {
        conn.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut reader = std::io::BufReader::new(conn);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if std::time::Instant::now() > deadline {
                panic!("did not receive child PID within timeout");
            }
            match try_read_response(&mut reader) {
                Some(DaemonMessage::Stdout { data }) => {
                    if let Ok(pid) = data.trim().parse::<u32>() {
                        return pid;
                    }
                }
                Some(DaemonMessage::Stderr { .. }) => {}
                _ => {}
            }
        }
    };

    let mut stream1 = connect_to_daemon(&socket_path, 30);
    send_message(
        &mut stream1,
        &ClientMessage::Exec {
            tool: "sh".to_string(),
            args: vec!["-c".to_string(), "echo $$; exec sleep 600".to_string()],
            cwd: cwd.to_str().unwrap().to_string(),
        },
    );
    let child1_pid = collect_pid(&mut stream1);

    let mut stream2 = connect_to_daemon(&socket_path, 30);
    send_message(
        &mut stream2,
        &ClientMessage::Exec {
            tool: "sh".to_string(),
            args: vec!["-c".to_string(), "echo $$; exec sleep 600".to_string()],
            cwd: cwd.to_str().unwrap().to_string(),
        },
    );
    let child2_pid = collect_pid(&mut stream2);

    assert!(is_process_alive(child1_pid), "child 1 should be alive");
    assert!(is_process_alive(child2_pid), "child 2 should be alive");

    // Send SIGTERM to the daemon.
    unsafe {
        libc::kill(daemon_pid as i32, libc::SIGTERM);
    }

    // Wait for daemon shutdown.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if daemon.join_handle.is_finished() {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("daemon thread did not finish after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    daemon.join_handle.join().expect("daemon thread clean exit");

    // Verify both children are killed.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !is_process_alive(child1_pid),
        "child 1 PID {child1_pid} should be terminated"
    );
    assert!(
        !is_process_alive(child2_pid),
        "child 2 PID {child2_pid} should be terminated"
    );

    // Verify cleanup files.
    assert!(
        !socket_path.exists(),
        "socket file should be removed after shutdown"
    );
    assert!(
        !pid_path.exists(),
        "PID file should be removed after shutdown"
    );
}
