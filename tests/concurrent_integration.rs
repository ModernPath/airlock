//! Concurrent execution integration tests.
//!
//! Tests that multiple simultaneous tool executions do not interfere.

#![cfg(any(target_os = "macos", target_os = "linux"))]

mod e2e_helpers;

use std::time::Duration;

use airlock::protocol::{ClientMessage, DaemonMessage};
use e2e_helpers::*;

// ─── Two concurrent tools produce isolated output ───────────────────────────

#[test]
fn concurrent_tools_isolated_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let cwd_str = cwd.to_str().unwrap().to_string();

    let socket_path = daemon.socket_path.clone();

    // Start two tools simultaneously with unique identifiers.
    let sp1 = socket_path.clone();
    let cwd1 = cwd_str.clone();
    let t1 = std::thread::spawn(move || {
        exec_tool(&sp1, "sh", &["-c", "echo UNIQUE_ID_ALPHA_12345"], &cwd1)
    });

    let sp2 = socket_path.clone();
    let cwd2 = cwd_str.clone();
    let t2 = std::thread::spawn(move || {
        exec_tool(&sp2, "sh", &["-c", "echo UNIQUE_ID_BETA_67890"], &cwd2)
    });

    let result1 = t1.join().expect("thread 1 should finish");
    let result2 = t2.join().expect("thread 2 should finish");

    assert_eq!(result1.exit_code, Some(0));
    assert_eq!(result2.exit_code, Some(0));

    // Each client should only see its own tool's output.
    assert!(
        result1.stdout.contains("UNIQUE_ID_ALPHA_12345"),
        "client 1 should see its own output, got: {:?}",
        result1.stdout
    );
    assert!(
        !result1.stdout.contains("UNIQUE_ID_BETA_67890"),
        "client 1 should NOT see client 2's output"
    );

    assert!(
        result2.stdout.contains("UNIQUE_ID_BETA_67890"),
        "client 2 should see its own output, got: {:?}",
        result2.stdout
    );
    assert!(
        !result2.stdout.contains("UNIQUE_ID_ALPHA_12345"),
        "client 2 should NOT see client 1's output"
    );

    daemon.shutdown();
}

// ─── Killing one tool does not affect the other ─────────────────────────────

#[test]
fn killing_one_tool_does_not_affect_other() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let cwd_str = cwd.to_str().unwrap().to_string();

    // Start tool 1: a long-running tool that we'll disconnect from.
    let mut stream1 = connect_to_daemon(&daemon.socket_path, 30);
    let exec_msg1 = ClientMessage::Exec {
        tool: "sh".to_string(),
        args: vec!["-c".to_string(), "echo $$; exec sleep 600".to_string()],
        cwd: cwd_str.clone(),
    };
    send_message(&mut stream1, &exec_msg1);

    // Read the PID from stream1.
    let mut tool1_pid: Option<u32> = None;
    stream1
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    {
        let mut reader1 = std::io::BufReader::new(&mut stream1);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if std::time::Instant::now() > deadline {
                break;
            }
            match try_read_response(&mut reader1) {
                Some(DaemonMessage::Stdout { data }) => {
                    if let Ok(pid) = data.trim().parse::<u32>() {
                        tool1_pid = Some(pid);
                        break;
                    }
                }
                Some(DaemonMessage::Stderr { .. }) => {}
                _ => break,
            }
        }
    }
    let _tool1_pid = tool1_pid.expect("should receive tool1 PID");

    // Start tool 2: a quick tool on a separate connection.
    let socket_path = daemon.socket_path.clone();
    let cwd2 = cwd_str.clone();
    let t2 = std::thread::spawn(move || {
        // Give tool 1 a moment to be fully running.
        std::thread::sleep(Duration::from_millis(200));

        exec_tool(
            &socket_path,
            "sh",
            &["-c", "sleep 1 && echo surviving_tool_output"],
            &cwd2,
        )
    });

    // Disconnect tool 1 (kill its connection).
    std::thread::sleep(Duration::from_millis(100));
    drop(stream1);

    // Tool 2 should still complete normally.
    let result2 = t2.join().expect("thread 2 should finish");

    assert_eq!(
        result2.exit_code,
        Some(0),
        "tool 2 should complete normally after tool 1 is disconnected"
    );
    assert!(
        result2.stdout.contains("surviving_tool_output"),
        "tool 2 should produce its output, got: {:?}",
        result2.stdout
    );

    daemon.shutdown();
}
