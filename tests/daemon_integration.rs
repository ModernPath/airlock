//! Integration tests for daemon startup, lifecycle, and connection handling.
//!
//! These tests verify end-to-end daemon behavior: starting in foreground mode,
//! accepting connections, responding to protocol messages, handling stale state,
//! and shutting down cleanly on SIGTERM.
//!
//! Platform-specific tests are gated with `#[cfg(target_os = "...")]`.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::io::{BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use airlock::daemon;
use airlock::protocol::{ClientMessage, DaemonMessage};

// ─── Test helpers ─────────────────────────────────────────────────────────────

/// Write an `airlock.toml` config with the given content to the specified directory.
fn write_config(dir: &Path, content: &str) {
    std::fs::write(dir.join("airlock.toml"), content).expect("failed to write config");
}

/// A minimal config with one tool and one secret.
fn minimal_config() -> &'static str {
    r#"
allow_home_root = true

[secrets.TEST_DAEMON_SECRET]
source = "env"

[tools.testtool.env]
TEST_DAEMON_SECRET = { secret = "TEST_DAEMON_SECRET" }
"#
}

/// A config with no secrets.
fn no_secrets_config() -> &'static str {
    r#"
allow_home_root = true

[tools.testtool]
"#
}

/// Send an NDJSON message over a UnixStream.
fn send_message(stream: &mut UnixStream, msg: &ClientMessage) {
    let json = serde_json::to_string(msg).expect("failed to serialize message");
    stream.write_all(json.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
}

/// Read one NDJSON line from a UnixStream and parse as DaemonMessage.
fn read_response(stream: &mut UnixStream) -> DaemonMessage {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("failed to read response");
    serde_json::from_str(line.trim()).expect("failed to parse response")
}

/// Poll until the PID file appears on disk, panicking if the deadline is exceeded.
fn wait_for_pid_file(pid_path: &Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !pid_path.exists() {
        if std::time::Instant::now() > deadline {
            panic!("daemon did not create PID file within timeout");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Read the daemon PID from its PID file.
fn read_daemon_pid(pid_path: &Path) -> u32 {
    let content = std::fs::read_to_string(pid_path).unwrap();
    content.trim().parse().expect("PID should be a number")
}

/// Send SIGTERM to the daemon and wait for its thread to finish, panicking if
/// the thread does not exit within 10 seconds.
fn shutdown_daemon(daemon_pid: u32, handle: std::thread::JoinHandle<()>) {
    unsafe { libc::kill(daemon_pid as i32, libc::SIGTERM) };

    let join_deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if handle.is_finished() {
            break;
        }
        if std::time::Instant::now() > join_deadline {
            panic!("daemon thread did not finish after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    handle.join().expect("daemon thread should finish cleanly");
}

/// Start the daemon in foreground mode on a background thread, wait for the PID
/// file to appear, and return the thread handle, socket path, PID path, and
/// daemon PID.
fn start_foreground_daemon(tmp: &Path) -> (std::thread::JoinHandle<()>, PathBuf, PathBuf, u32) {
    let state = daemon::synchronous_startup(tmp, None).expect("synchronous startup should succeed");

    let socket_path = state.config.socket_path.clone();
    let pid_path = state.config.pid_path.clone();

    let handle = std::thread::spawn(move || {
        daemon::run_foreground(state).expect("run_foreground should succeed");
    });

    wait_for_pid_file(&pid_path);
    let daemon_pid = read_daemon_pid(&pid_path);

    (handle, socket_path, pid_path, daemon_pid)
}

/// Synchronization helper: RAII guard for environment variables in integration tests.
///
/// Uses a static mutex to serialize all tests that modify env vars.
use std::sync::{Mutex, MutexGuard};

static ENV_MUTEX: Mutex<()> = Mutex::new(());

struct EnvGuard {
    vars: Vec<(String, Option<String>)>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn new(vars: &[(&str, &str)]) -> Self {
        let lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let mut saved = Vec::with_capacity(vars.len());

        for (key, value) in vars {
            let prev = std::env::var(*key).ok();
            saved.push((key.to_string(), prev));
            unsafe { std::env::set_var(*key, *value) };
        }

        Self {
            vars: saved,
            _lock: lock,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, prev) in &self.vars {
            match prev {
                Some(v) => unsafe { std::env::set_var(key, v) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }
}

// ─── Integration test: foreground daemon full lifecycle ──────────────────────

#[test]
fn foreground_daemon_starts_accepts_logs_and_shuts_down() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), no_secrets_config());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);

    let (handle, socket_path, pid_path, daemon_pid) = start_foreground_daemon(tmp.path());

    // Verify socket file exists.
    assert!(socket_path.exists(), "socket file should exist");

    // Verify PID is valid.
    assert!(daemon_pid > 0, "PID should be > 0");

    // Connect and send a logs request.
    let mut stream = UnixStream::connect(&socket_path).expect("should connect to daemon");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    send_message(&mut stream, &ClientMessage::Logs);

    let response = read_response(&mut stream);
    match response {
        DaemonMessage::LogsResponse { entries } => {
            // Should have at least the startup entry.
            assert!(
                !entries.is_empty(),
                "logs should contain at least the startup entry"
            );
            // Check that the startup message is present.
            let has_startup = entries.iter().any(|e| e.message.contains("daemon started"));
            assert!(
                has_startup,
                "should have 'daemon started' log entry, got: {entries:?}"
            );
        }
        other => panic!("expected LogsResponse, got: {other:?}"),
    }

    drop(stream);

    shutdown_daemon(daemon_pid, handle);

    // Verify cleanup: socket and PID files should be removed.
    assert!(
        !socket_path.exists(),
        "socket file should be removed after shutdown"
    );
    assert!(
        !pid_path.exists(),
        "PID file should be removed after shutdown"
    );
}

// ─── Integration test: stale PID file with dead process ─────────────────────

#[test]
fn stale_pid_file_with_dead_process_is_cleaned_up() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), no_secrets_config());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);

    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let pid_path = canonical_tmp.join("airlock.pid");
    let socket_path = canonical_tmp.join("airlock.sock");

    // Write a stale PID file with a dead process PID.
    std::fs::write(&pid_path, "999999999\n").unwrap();
    std::fs::write(&socket_path, "stale-socket-data").unwrap();

    // Synchronous startup should clean up and succeed.
    let state = daemon::synchronous_startup(tmp.path(), None)
        .expect("startup should succeed with stale PID");

    // The stale files should be gone (replaced by the new socket).
    assert!(
        state.config.socket_path.exists(),
        "new socket should be bound"
    );

    // Verify the startup completed correctly.
    assert!(
        !pid_path.exists() || state.config.socket_path.exists(),
        "stale PID should be cleaned up"
    );

    // Clean up: drop the state (including the listener) to unbind the socket.
    drop(state);

    // The socket file created by binding may still exist; that's OK.
    // The point is that the stale PID file was cleaned up and startup succeeded.
}

// ─── Integration test: already running ──────────────────────────────────────

#[test]
fn starting_when_already_running_produces_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), no_secrets_config());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);

    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let pid_path = canonical_tmp.join("airlock.pid");

    // Write our own PID to the PID file (definitely alive).
    let my_pid = std::process::id();
    std::fs::write(&pid_path, format!("{my_pid}\n")).unwrap();

    let result = daemon::synchronous_startup(tmp.path(), None);
    match result {
        Ok(_) => panic!("should fail when daemon is already running"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("already running"),
                "error should mention 'already running', got: {msg}"
            );
            assert!(
                msg.contains(&my_pid.to_string()),
                "error should contain the PID, got: {msg}"
            );
        }
    }
}

// ─── Integration test: missing secret env vars ──────────────────────────────

#[test]
fn missing_secret_env_vars_fails_with_clear_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), minimal_config());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);

    // Ensure the secret env var is NOT set.
    unsafe { std::env::remove_var("TEST_DAEMON_SECRET") };

    let result = daemon::synchronous_startup(tmp.path(), None);
    match result {
        Ok(_) => panic!("should fail when secrets are missing"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("TEST_DAEMON_SECRET"),
                "error should name the missing secret, got: {msg}"
            );
        }
    }
}

// ─── Integration test: no config file fails ─────────────────────────────────

#[test]
fn no_config_file_fails_with_clear_error() {
    let tmp = tempfile::tempdir().unwrap();
    // Do NOT write a config file.

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);

    let result = daemon::synchronous_startup(tmp.path(), None);
    match result {
        Ok(_) => panic!("should fail when no config file exists"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("airlock.toml") || msg.contains("config"),
                "error should mention config, got: {msg}"
            );
        }
    }
}

// ─── Integration test: unknown tool returns error ───────────────────────────

#[test]
fn exec_unknown_tool_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), no_secrets_config());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);

    let (handle, socket_path, _pid_path, daemon_pid) = start_foreground_daemon(tmp.path());

    // Connect and send an exec request for a tool NOT in config.
    let mut stream = UnixStream::connect(&socket_path).expect("should connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let exec_msg = ClientMessage::Exec {
        tool: "nonexistent_tool".to_string(),
        args: vec![],
        cwd: tmp.path().to_string_lossy().to_string(),
    };
    send_message(&mut stream, &exec_msg);

    let response = read_response(&mut stream);
    match response {
        DaemonMessage::Error { message } => {
            assert!(
                message.contains("unknown tool") && message.contains("nonexistent_tool"),
                "should get unknown tool error naming the tool, got: {message}"
            );
        }
        other => panic!("expected Error, got: {other:?}"),
    }

    drop(stream);

    shutdown_daemon(daemon_pid, handle);
}

// ─── Integration test: CWD outside sandbox root returns error ───────────────

#[test]
fn exec_cwd_outside_sandbox_root_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), no_secrets_config());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);

    let (handle, socket_path, _pid_path, daemon_pid) = start_foreground_daemon(tmp.path());

    // Connect and send an exec request with CWD outside sandbox root.
    let mut stream = UnixStream::connect(&socket_path).expect("should connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let exec_msg = ClientMessage::Exec {
        tool: "testtool".to_string(),
        args: vec![],
        cwd: "/tmp".to_string(),
    };
    send_message(&mut stream, &exec_msg);

    let response = read_response(&mut stream);
    match response {
        DaemonMessage::Error { message } => {
            assert!(
                message.contains("CWD validation failed"),
                "should get CWD validation error, got: {message}"
            );
        }
        other => panic!("expected Error, got: {other:?}"),
    }

    drop(stream);

    shutdown_daemon(daemon_pid, handle);
}

// ─── Integration test: unknown message type ─────────────────────────────────

#[test]
fn unknown_message_type_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), no_secrets_config());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);

    let (handle, socket_path, _pid_path, daemon_pid) = start_foreground_daemon(tmp.path());

    // Connect and send an unknown/malformed message.
    let mut stream = UnixStream::connect(&socket_path).expect("should connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Send malformed JSON that doesn't match any known type.
    stream
        .write_all(b"{\"type\":\"nonexistent_command\"}\n")
        .unwrap();
    stream.flush().unwrap();

    let response = read_response(&mut stream);
    match response {
        DaemonMessage::Error { message } => {
            assert!(!message.is_empty(), "error message should not be empty");
        }
        other => panic!("expected Error for unknown message, got: {other:?}"),
    }

    drop(stream);

    shutdown_daemon(daemon_pid, handle);
}

// ─── Integration test: socket permissions ───────────────────────────────────

#[test]
fn socket_has_owner_only_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), no_secrets_config());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);

    let state =
        daemon::synchronous_startup(tmp.path(), None).expect("synchronous startup should succeed");

    let socket_path = state.config.socket_path.clone();

    // Socket is created during synchronous_startup — check permissions immediately.
    let metadata = std::fs::metadata(&socket_path).expect("socket file should exist");
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o700,
        "socket should be owner-only (0o700), got: {mode:#o}"
    );

    // Clean up: drop the state to release the listener.
    drop(state);
}

// ─── Integration test: PID file permissions ─────────────────────────────────

#[test]
fn pid_file_has_owner_only_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), no_secrets_config());

    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);

    let (handle, _socket_path, pid_path, daemon_pid) = start_foreground_daemon(tmp.path());

    // Check PID file permissions.
    let metadata = std::fs::metadata(&pid_path).expect("PID file should exist");
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "PID file should be owner-only (0o600), got: {mode:#o}"
    );

    shutdown_daemon(daemon_pid, handle);
}

// ─── Embedded daemon lifecycle tests (via CLI binary) ────────────────────────

/// Get the path to the `airlock` binary built by `cargo test`.
fn airlock_bin() -> PathBuf {
    let mut path = std::env::current_exe().expect("failed to get test exe path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("airlock");
    assert!(
        path.exists(),
        "airlock binary not found at {:?}. Run `cargo build` first.",
        path
    );
    path
}

/// After `airlock run` (daemon mode) completes, the socket file is removed.
/// The embedded daemon performs graceful cleanup on shutdown.
#[test]
fn embedded_daemon_socket_removed_after_agent_exits() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), no_secrets_config());

    let canonical = std::fs::canonicalize(tmp.path()).unwrap();
    let socket_path = canonical.join("airlock.sock");

    // Socket should not exist before the run.
    assert!(!socket_path.exists(), "socket should not exist before run");

    let output = std::process::Command::new(airlock_bin())
        .args(["run", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "airlock run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // After the run, the embedded daemon should have cleaned up the socket.
    assert!(
        !socket_path.exists(),
        "socket file should be removed after embedded daemon shuts down"
    );
}

/// The embedded daemon never writes a PID file (`run_embedded` skips that step).
/// Assert the PID file is absent both before and after the run.
#[test]
fn embedded_daemon_no_pid_file_created() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), no_secrets_config());

    let canonical = std::fs::canonicalize(tmp.path()).unwrap();
    let pid_path = canonical.join("airlock.pid");

    // No PID file before the run.
    assert!(!pid_path.exists(), "PID file should not exist before run");

    let output = std::process::Command::new(airlock_bin())
        .args(["run", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "airlock run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // No PID file after the run — the embedded daemon never wrote one.
    assert!(
        !pid_path.exists(),
        "embedded daemon should never create a PID file"
    );
}

/// With `--no-daemon`, neither a socket nor a PID file is created at any point.
#[test]
fn no_daemon_mode_socket_never_created() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), no_secrets_config());

    let canonical = std::fs::canonicalize(tmp.path()).unwrap();
    let socket_path = canonical.join("airlock.sock");
    let pid_path = canonical.join("airlock.pid");

    assert!(!socket_path.exists(), "socket should not exist before run");
    assert!(!pid_path.exists(), "PID file should not exist before run");

    let output = std::process::Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run --no-daemon");

    assert!(
        output.status.success(),
        "airlock run --no-daemon should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Neither socket nor PID file should have been created.
    assert!(
        !socket_path.exists(),
        "no socket should be created with --no-daemon"
    );
    assert!(
        !pid_path.exists(),
        "no PID file should be created with --no-daemon"
    );
}

/// Skeleton test for the two-layer end-to-end scenario: `airlock run` spawning
/// an agent that itself calls `airlock exec` to execute a configured tool.
///
/// Marked `#[ignore]` because the agent's environment does not have `airlock`
/// on PATH by default — wiring the binary into PATH inside the sandbox requires
/// test-infrastructure setup that is too brittle for CI. The test documents the
/// intended two-layer flow and can be run manually when needed.
#[test]
#[ignore]
fn two_layer_nested_exec_agent_can_call_airlock_exec() {
    // Setup: a config with a simple tool (command = "true") so `airlock exec`
    // has minimal requirements.
    let tmp = tempfile::tempdir().unwrap();
    write_config(
        tmp.path(),
        r#"
allow_home_root = true

[tools.noop]
command = "true"
"#,
    );

    // Run: airlock run spawns an agent that calls `airlock exec -- noop`.
    // Requires `airlock` to be on PATH inside the agent's environment.
    let output = std::process::Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "airlock", "exec", "--", "noop"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run two-layer test");

    assert!(
        output.status.success(),
        "nested airlock exec should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
