//! Stdin forwarding integration tests.
//!
//! Tests that stdin data flows from the client through the daemon to the tool.

#![cfg(any(target_os = "macos", target_os = "linux"))]

mod e2e_helpers;

use airlock::protocol::{ClientMessage, DaemonMessage};
use e2e_helpers::*;

// ─── Piped stdin data flows through the daemon to the tool ──────────────────

#[test]
fn stdin_data_flows_through_daemon_to_tool() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();

    // Connect and send exec request for `cat` (reads stdin, echoes to stdout).
    let mut stream = connect_to_daemon(&daemon.socket_path, 30);

    let exec_msg = ClientMessage::Exec {
        tool: "sh".to_string(),
        args: vec!["-c".to_string(), "cat".to_string()],
        cwd: cwd.to_str().unwrap().to_string(),
    };
    send_message(&mut stream, &exec_msg);

    // Send stdin data.
    let stdin_msg = ClientMessage::Stdin {
        data: "hello from stdin\n".to_string(),
    };
    send_message(&mut stream, &stdin_msg);

    // Send stdin EOF to close the pipe.
    let eof_msg = ClientMessage::StdinEof;
    send_message(&mut stream, &eof_msg);

    // Collect responses.
    let mut stdout = String::new();
    let mut exit_code = None;

    let mut reader = std::io::BufReader::new(&mut stream);
    loop {
        match try_read_response(&mut reader) {
            Some(DaemonMessage::Stdout { data }) => stdout.push_str(&data),
            Some(DaemonMessage::Stderr { .. }) => {}
            Some(DaemonMessage::Exit { code }) => {
                exit_code = Some(code);
                break;
            }
            Some(DaemonMessage::Error { message }) => {
                panic!("unexpected error: {message}");
            }
            _ => break,
        }
    }

    assert_eq!(exit_code, Some(0), "cat should exit 0");
    assert!(
        stdout.contains("hello from stdin"),
        "stdout should contain the piped stdin data, got: {:?}",
        stdout
    );

    daemon.shutdown();
}

// ─── EOF on client stdin causes EOF on tool stdin ───────────────────────────

#[test]
fn stdin_eof_causes_tool_stdin_eof() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();

    // `wc -l` reads all of stdin then prints the line count.
    let mut stream = connect_to_daemon(&daemon.socket_path, 30);

    let exec_msg = ClientMessage::Exec {
        tool: "sh".to_string(),
        args: vec!["-c".to_string(), "wc -l".to_string()],
        cwd: cwd.to_str().unwrap().to_string(),
    };
    send_message(&mut stream, &exec_msg);

    // Send two lines, then EOF.
    send_message(
        &mut stream,
        &ClientMessage::Stdin {
            data: "line1\nline2\nline3\n".to_string(),
        },
    );
    send_message(&mut stream, &ClientMessage::StdinEof);

    // Collect responses.
    let mut stdout = String::new();
    let mut exit_code = None;

    let mut reader = std::io::BufReader::new(&mut stream);
    loop {
        match try_read_response(&mut reader) {
            Some(DaemonMessage::Stdout { data }) => stdout.push_str(&data),
            Some(DaemonMessage::Stderr { .. }) => {}
            Some(DaemonMessage::Exit { code }) => {
                exit_code = Some(code);
                break;
            }
            Some(DaemonMessage::Error { message }) => {
                panic!("unexpected error: {message}");
            }
            _ => break,
        }
    }

    assert_eq!(exit_code, Some(0), "wc -l should exit 0");
    assert!(
        stdout.trim().contains('3'),
        "wc -l should count 3 lines, got: {:?}",
        stdout
    );

    daemon.shutdown();
}

// ─── No stdin from client causes the tool's stdin to close ──────────────────

#[test]
fn no_stdin_causes_tool_stdin_to_close() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);
    let daemon = start_daemon(tmp.path());

    let cwd = std::fs::canonicalize(tmp.path()).unwrap();

    // `echo hello` does not read stdin, so it should exit normally
    // even if no stdin messages are sent. The daemon's stdin auto-close
    // timer will close the pipe after 2 seconds.
    let result = exec_tool(
        &daemon.socket_path,
        "sh",
        &["-c", "echo hello"],
        cwd.to_str().unwrap(),
    );

    assert_eq!(result.exit_code, Some(0), "tool should exit 0");
    assert!(
        result.stdout.contains("hello"),
        "stdout should contain 'hello', got: {:?}",
        result.stdout
    );

    daemon.shutdown();
}
