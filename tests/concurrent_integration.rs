//! Concurrent execution integration tests.
//!
//! Tests that multiple simultaneous tool executions do not interfere.

#![cfg(any(target_os = "macos", target_os = "linux"))]

mod e2e_helpers;

use std::time::Duration;

use airlock::protocol::{Auth, DaemonMessage, Request, RequestBody, SessionRequest};
use e2e_helpers::*;

// ─── Two concurrent tools produce isolated output ───────────────────────────

#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
#[test]
fn concurrent_tools_isolated_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let cwd_str = cwd.to_str().unwrap().to_string();

    let socket_path = daemon.socket_path.clone();
    let token = daemon.token.clone();

    // Start two tools simultaneously with unique identifiers.
    let sp1 = socket_path.clone();
    let token1 = token.clone();
    let cwd1 = cwd_str.clone();
    let t1 = std::thread::spawn(move || {
        exec_tool_as(
            &sp1,
            &token1,
            "sh",
            &["-c", "echo UNIQUE_ID_ALPHA_12345"],
            &cwd1,
        )
    });

    let sp2 = socket_path.clone();
    let token2 = token.clone();
    let cwd2 = cwd_str.clone();
    let t2 = std::thread::spawn(move || {
        exec_tool_as(
            &sp2,
            &token2,
            "sh",
            &["-c", "echo UNIQUE_ID_BETA_67890"],
            &cwd2,
        )
    });

    let result1 = t1.join().expect("thread 1 should finish");
    let result2 = t2.join().expect("thread 2 should finish");

    assert_eq!(result1.exit_code, Some(0));
    assert_eq!(result2.exit_code, Some(0));

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

#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
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
    let req1 = Request {
        auth: Auth::Session {
            token: daemon.token.clone(),
        },
        body: RequestBody::Session(SessionRequest::Exec {
            tool: "sh".to_string(),
            args: vec!["-c".to_string(), "echo $$; exec sleep 600".to_string()],
            cwd: cwd.clone(),
        }),
    };
    send_message(&mut stream1, &req1);

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
    let token2 = daemon.token.clone();
    let cwd2 = cwd_str.clone();
    let t2 = std::thread::spawn(move || {
        // Give tool 1 a moment to be fully running.
        std::thread::sleep(Duration::from_millis(200));
        exec_tool_as(
            &socket_path,
            &token2,
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

// ─── A session's exec cap refuses its 17th concurrent exec ─────────────────

#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
#[test]
fn seventeenth_concurrent_exec_is_refused_busy() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let cwd_str = cwd.to_str().unwrap().to_string();

    // Hold 16 slow execs open, then try a 17th and expect Busy.
    let mut streams = Vec::new();
    for _ in 0..16 {
        let mut stream = connect_to_daemon(&daemon.socket_path, 30);
        let req = Request {
            auth: Auth::Session {
                token: daemon.token.clone(),
            },
            body: RequestBody::Session(SessionRequest::Exec {
                tool: "sh".to_string(),
                args: vec!["-c".to_string(), "sleep 5".to_string()],
                cwd: cwd.clone(),
            }),
        };
        send_message(&mut stream, &req);
        streams.push(stream);
    }

    // Give the daemon a moment to have actually spawned all 16.
    std::thread::sleep(Duration::from_millis(500));

    let result = exec_tool(&daemon, "sh", &["-c", "echo should-not-run"], &cwd_str);
    assert!(
        result.error.is_some(),
        "the 17th concurrent exec should be refused; stdout={:?} exit_code={:?}",
        result.stdout,
        result.exit_code
    );

    drop(streams);
    daemon.shutdown();
}
