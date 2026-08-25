//! Client-side logic for communicating with the Airlock daemon.
//!
//! This module provides the programmatic interface that the CLI (`airlock exec`,
//! `airlock logs`) uses to talk to a running daemon over a Unix domain socket.
//!
//! The client is intentionally thin. It performs no tool resolution, no
//! sandboxing, no secret handling, and no redaction — all of that happens in the
//! daemon. The client's responsibilities are:
//!
//! 1. Discover the socket path via [`config::discover_paths`]
//! 2. Connect to the daemon's Unix socket
//! 3. Send an NDJSON request (`exec` or `logs`)
//! 4. Forward the daemon's responses to the caller's stdout/stderr
//! 5. Exit with the tool's exit code
//!
//! This design keeps the trust boundary at the daemon process and makes the
//! client simple to audit.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::config::{self, ConfigError};
use crate::protocol::{ClientMessage, DaemonMessage};

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors that can occur in the client.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Config discovery failed (no `airlock.toml` found).
    #[error(
        "failed to discover airlock config: {source}\n\nHint: create an airlock.toml in your project directory, or check that you are running from within a project that has one."
    )]
    ConfigDiscovery {
        /// The underlying config error.
        source: ConfigError,
    },

    /// The socket file does not exist.
    #[error(
        "socket file not found at {path}\n\nHint: the daemon is not running. Start it with: airlock daemon start"
    )]
    SocketNotFound {
        /// The path where the socket was expected.
        path: PathBuf,
    },

    /// Connection to the daemon socket was refused.
    #[error(
        "connection refused at {path}\n\nHint: the daemon may not be running or the socket file may be stale. Try: airlock daemon start"
    )]
    ConnectionRefused {
        /// The socket path.
        path: PathBuf,
    },

    /// Permission denied when connecting to the daemon socket.
    #[error(
        "permission denied connecting to {path}\n\nHint: check filesystem permissions on the socket file."
    )]
    PermissionDenied {
        /// The socket path.
        path: PathBuf,
    },

    /// Other socket connection error.
    #[error("failed to connect to daemon at {path}: {source}")]
    ConnectionFailed {
        /// The socket path.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// I/O error during socket communication.
    #[error("socket communication error: {0}")]
    SocketIo(#[from] std::io::Error),

    /// NDJSON serialization or deserialization error.
    #[error("protocol error: {0}")]
    Protocol(#[from] serde_json::Error),

    /// Unexpected socket closure (daemon crash or shutdown).
    #[error("daemon connection closed unexpectedly (daemon may have crashed or shut down)")]
    UnexpectedEof,

    /// CWD canonicalization failure.
    #[error("failed to canonicalize working directory {path}: {source}")]
    CwdCanonicalization {
        /// The path that could not be canonicalized.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
}

// ─── Socket connection helper ────────────────────────────────────────────────

/// Discover the socket path and connect to the daemon.
///
/// When `config_path` is provided, socket discovery uses
/// [`config::discover_paths_from_file`] instead of walking up from
/// `start_dir`.
///
/// Returns the connected `UnixStream` and the socket path used.
async fn connect_to_daemon(
    start_dir: &Path,
    config_path: Option<&Path>,
) -> Result<(tokio::net::UnixStream, PathBuf), ClientError> {
    let paths = match config_path {
        Some(p) => config::discover_paths_from_file(p),
        None => config::discover_paths(start_dir),
    }
    .map_err(|e| ClientError::ConfigDiscovery { source: e })?;

    let socket_path = &paths.socket_path;

    // Check if the socket file exists before attempting connection.
    if !socket_path.exists() {
        return Err(ClientError::SocketNotFound {
            path: socket_path.clone(),
        });
    }

    let stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::ConnectionRefused => ClientError::ConnectionRefused {
                path: socket_path.clone(),
            },
            std::io::ErrorKind::PermissionDenied => ClientError::PermissionDenied {
                path: socket_path.clone(),
            },
            _ => ClientError::ConnectionFailed {
                path: socket_path.clone(),
                source: e,
            },
        })?;

    Ok((stream, socket_path.clone()))
}

// ─── NDJSON helpers ──────────────────────────────────────────────────────────

/// Write an NDJSON message to the given writer.
async fn write_client_message<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &ClientMessage,
) -> Result<(), ClientError> {
    let json = serde_json::to_string(msg)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

// ─── Exec client function ───────────────────────────────────────────────────

/// Execute a tool through the daemon and proxy its I/O.
///
/// This function:
/// 1. Discovers the daemon socket path via config
/// 2. Connects to the daemon
/// 3. Sends an NDJSON `exec` request with the tool name, args, and canonicalized CWD
/// 4. Forwards stdin (if piped) as NDJSON `stdin` / `stdin_eof` messages
/// 5. Dispatches daemon responses to stdout/stderr
/// 6. Returns the exit code from the daemon (or 1 on error)
///
/// SIGINT (Ctrl+C) is handled by closing the socket connection. The daemon
/// detects the disconnection and kills the child process group.
///
/// # Arguments
///
/// * `tool` — The tool name to execute.
/// * `args` — Arguments to pass to the tool.
/// * `cwd` — The working directory for the tool.
/// * `config_path` — Optional explicit config file path; bypasses directory-walk discovery.
///
/// # Returns
///
/// The process exit code: 0 on success, the tool's exit code on normal
/// completion, or 1 on error.
pub async fn exec(
    tool: String,
    args: Vec<String>,
    cwd: &Path,
    config_path: Option<&Path>,
) -> Result<i32, ClientError> {
    use tokio::io::BufReader;

    // Canonicalize the working directory.
    let canonical_cwd =
        std::fs::canonicalize(cwd).map_err(|e| ClientError::CwdCanonicalization {
            path: cwd.to_path_buf(),
            source: e,
        })?;

    // Connect to daemon.
    let (stream, _socket_path) = connect_to_daemon(cwd, config_path).await?;
    let (reader, mut writer) = stream.into_split();

    // Send the exec request.
    let exec_msg = ClientMessage::Exec {
        tool,
        args,
        cwd: canonical_cwd.to_string_lossy().into_owned(),
    };
    write_client_message(&mut writer, &exec_msg).await?;

    // Determine if stdin is a pipe (not a TTY).
    let stdin_is_pipe = !is_stdin_tty();

    // Spawn stdin forwarding task if stdin is a pipe.
    let stdin_handle = if stdin_is_pipe {
        let mut stdin_writer = writer;
        Some(tokio::spawn(async move {
            forward_stdin(&mut stdin_writer).await;
            stdin_writer
        }))
    } else {
        None
    };

    // Install SIGINT handler.
    // When Ctrl+C is received, we drop the socket connection (by returning).
    // The daemon detects the disconnection and kills the child process group.
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("failed to install SIGINT handler");

    // Read daemon responses, racing against SIGINT.
    let mut buf_reader = BufReader::new(reader);
    let exit_code = tokio::select! {
        result = read_daemon_responses(&mut buf_reader) => {
            result?
        }
        _ = sigint.recv() => {
            // SIGINT received — drop the reader (closes our side of the socket).
            // The daemon will detect the disconnect and kill the child.
            drop(buf_reader);

            // Abort stdin forwarding if running.
            if let Some(handle) = stdin_handle {
                handle.abort();
            }

            // Exit with code 130 (128 + SIGINT signal number 2), the conventional
            // exit code for SIGINT-terminated processes.
            return Ok(130);
        }
    };

    // If stdin forwarding is running, abort it.
    if let Some(handle) = stdin_handle {
        handle.abort();
    }

    Ok(exit_code)
}

/// Check whether stdin is a TTY (not a pipe).
fn is_stdin_tty() -> bool {
    // SAFETY: isatty is always safe to call with a valid file descriptor.
    // stdin is fd 0, which is always valid for the lifetime of the process.
    unsafe { libc::isatty(libc::STDIN_FILENO) != 0 }
}

/// Forward stdin data from the client to the daemon as NDJSON messages.
///
/// Reads chunks from the real stdin and sends them as `stdin` messages.
/// When stdin reaches EOF, sends an `stdin_eof` message.
///
/// `tokio::io::stdin()` schedules `read(2)` on a blocking thread that
/// `JoinHandle::abort` cannot wake — see tokio docs for `stdin()` and
/// tokio-rs/tokio#589. If stdin is a pipe whose writer never closes, the
/// thread parks forever. The caller (`cmd_exec` in `main.rs`) detaches the
/// runtime via `shutdown_background` so process exit is not held up.
async fn forward_stdin<W: tokio::io::AsyncWriteExt + Unpin>(writer: &mut W) {
    use tokio::io::AsyncReadExt;

    let mut stdin = tokio::io::stdin();
    let mut buf = vec![0u8; 8192];

    loop {
        let n = match stdin.read(&mut buf).await {
            Ok(0) => {
                // EOF reached — send stdin_eof.
                let eof_msg = ClientMessage::StdinEof;
                let _ = write_client_message(writer, &eof_msg).await;
                break;
            }
            Ok(n) => n,
            Err(_) => {
                // Read error — send EOF and stop.
                let eof_msg = ClientMessage::StdinEof;
                let _ = write_client_message(writer, &eof_msg).await;
                break;
            }
        };

        // Convert bytes to string (lossy) and send as stdin message.
        let data = String::from_utf8_lossy(&buf[..n]).into_owned();
        let stdin_msg = ClientMessage::Stdin { data };
        if write_client_message(writer, &stdin_msg).await.is_err() {
            // Socket closed — daemon is gone.
            break;
        }
    }
}

/// Read and dispatch daemon response messages.
///
/// Returns the exit code from an `exit` message, or 1 on error.
async fn read_daemon_responses<R: tokio::io::AsyncBufReadExt + Unpin>(
    reader: &mut R,
) -> Result<i32, ClientError> {
    use std::io::Write;

    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            // Unexpected EOF — daemon closed connection.
            return Err(ClientError::UnexpectedEof);
        }

        let msg: DaemonMessage = serde_json::from_str(line.trim())?;

        match msg {
            DaemonMessage::Stdout { data } => {
                let stdout = std::io::stdout();
                let mut handle = stdout.lock();
                let _ = handle.write_all(data.as_bytes());
                let _ = handle.flush();
            }
            DaemonMessage::Stderr { data } => {
                let stderr = std::io::stderr();
                let mut handle = stderr.lock();
                let _ = handle.write_all(data.as_bytes());
                let _ = handle.flush();
            }
            DaemonMessage::Exit { code } => {
                return Ok(code);
            }
            DaemonMessage::Error { message } => {
                eprintln!("airlock: {message}");
                return Ok(1);
            }
            DaemonMessage::LogsResponse { .. } => {
                // Unexpected message type during exec flow — ignore.
            }
        }
    }
}

// ─── Logs client function ───────────────────────────────────────────────────

/// Retrieve and print log entries from the daemon.
///
/// Connects to the daemon, sends a `logs` request, prints each log entry's
/// timestamp and message to stdout, and exits.
///
/// # Arguments
///
/// * `cwd` — The working directory to start config discovery from.
/// * `config_path` — Optional explicit config file path; bypasses directory-walk discovery.
///
/// # Returns
///
/// Exit code 0 on success, or an error.
pub async fn logs(cwd: &Path, config_path: Option<&Path>) -> Result<i32, ClientError> {
    use tokio::io::AsyncBufReadExt;

    let (stream, _socket_path) = connect_to_daemon(cwd, config_path).await?;
    let (reader, mut writer) = stream.into_split();

    // Send the logs request.
    let logs_msg = ClientMessage::Logs;
    write_client_message(&mut writer, &logs_msg).await?;

    // Read the response.
    let mut buf_reader = tokio::io::BufReader::new(reader);
    let mut line = String::new();
    let bytes_read = buf_reader.read_line(&mut line).await?;

    if bytes_read == 0 {
        return Err(ClientError::UnexpectedEof);
    }

    let msg: DaemonMessage = serde_json::from_str(line.trim())?;

    match msg {
        DaemonMessage::LogsResponse { entries } => {
            for entry in &entries {
                println!("{} {}", entry.timestamp, entry.message);
            }
            Ok(0)
        }
        DaemonMessage::Error { message } => {
            eprintln!("airlock: {message}");
            Ok(1)
        }
        other => {
            eprintln!(
                "airlock: unexpected response from daemon: {:?}",
                std::mem::discriminant(&other)
            );
            Ok(1)
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    // ── Helpers ──────────────────────────────────────────────────────────

    use std::sync::{Mutex, MutexGuard};

    /// Global mutex serializing tests that modify env vars.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// RAII guard for temporary environment variable overrides.
    struct TempEnvVar {
        key: String,
        prev: Option<String>,
        _lock: MutexGuard<'static, ()>,
    }

    impl TempEnvVar {
        fn new(key: &str, value: &str) -> Self {
            let lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
            let prev = std::env::var(key).ok();
            unsafe { std::env::set_var(key, value) };
            Self {
                key: key.to_string(),
                prev,
                _lock: lock,
            }
        }
    }

    impl Drop for TempEnvVar {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(&self.key, v) },
                None => unsafe { std::env::remove_var(&self.key) },
            }
        }
    }

    /// Create an `airlock.toml` with minimal content.
    fn write_config(dir: &Path, content: &str) {
        fs::write(dir.join("airlock.toml"), content).expect("failed to write config");
    }

    fn minimal_config() -> &'static str {
        r#"
[tools.echo]
"#
    }

    /// Spawn a mock daemon that listens on the given socket path and runs the
    /// provided handler for the first accepted connection.
    async fn mock_daemon<F, Fut>(socket_path: &Path, handler: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(tokio::net::UnixStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = tokio::net::UnixListener::bind(socket_path).unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handler(stream).await;
        })
    }

    /// Write an NDJSON daemon message to a writer.
    async fn write_daemon_msg<W: AsyncWriteExt + Unpin>(writer: &mut W, msg: &DaemonMessage) {
        let json = serde_json::to_string(msg).unwrap();
        writer.write_all(json.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();
    }

    // ── Error type tests ─────────────────────────────────────────────────

    #[test]
    fn client_error_is_std_error() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<ClientError>();
    }

    #[test]
    fn client_error_display_messages_are_actionable() {
        let err = ClientError::SocketNotFound {
            path: PathBuf::from("/tmp/airlock.sock"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("daemon"),
            "socket not found error should mention daemon: {msg}"
        );
        assert!(
            msg.contains("airlock daemon start"),
            "socket not found error should suggest starting daemon: {msg}"
        );

        let err = ClientError::ConnectionRefused {
            path: PathBuf::from("/tmp/airlock.sock"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("not running") || msg.contains("stale"),
            "connection refused error should mention daemon not running: {msg}"
        );

        let err = ClientError::PermissionDenied {
            path: PathBuf::from("/tmp/airlock.sock"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("permission"),
            "permission denied error should mention permissions: {msg}"
        );
    }

    #[test]
    fn client_error_config_discovery_includes_hint() {
        let err = ClientError::ConfigDiscovery {
            source: ConfigError::NotFound {
                start_dir: PathBuf::from("/tmp/test"),
                home_dir: PathBuf::from("/home/user"),
            },
        };
        let msg = err.to_string();
        assert!(
            msg.contains("airlock.toml"),
            "config discovery error should mention airlock.toml: {msg}"
        );
    }

    // ── Config discovery error (no config file) ──────────────────────────

    #[tokio::test]
    async fn exec_fails_with_no_config() {
        let tmp = tempdir().unwrap();
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let result = exec(
            "echo".to_string(),
            vec!["hello".to_string()],
            tmp.path(),
            None,
        )
        .await;
        assert!(result.is_err());
        assert!(
            matches!(
                result.as_ref().unwrap_err(),
                ClientError::ConfigDiscovery { .. }
            ),
            "expected ConfigDiscovery error, got: {:?}",
            result.unwrap_err()
        );
    }

    // ── Socket not found ─────────────────────────────────────────────────

    #[tokio::test]
    async fn exec_fails_when_socket_not_found() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        // No daemon is running, so no socket file exists.
        let result = exec(
            "echo".to_string(),
            vec!["hello".to_string()],
            tmp.path(),
            None,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ClientError::SocketNotFound { .. }),
            "expected SocketNotFound, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("airlock daemon start"),
            "error should suggest starting daemon: {msg}"
        );
    }

    // ── Permission denied error ──────────────────────────────────────────

    #[test]
    fn permission_denied_error_mentions_permissions() {
        let err = ClientError::PermissionDenied {
            path: PathBuf::from("/tmp/airlock.sock"),
        };
        let msg = err.to_string();
        assert!(msg.contains("permission"));
    }

    // ── Exec: sends correct NDJSON message ───────────────────────────────

    #[tokio::test]
    async fn exec_sends_correct_ndjson_exec_message() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let socket_path = canonical_tmp.join("airlock.sock");

        // Mock daemon that reads the exec message, validates, then sends an exit.
        let daemon = mock_daemon(&socket_path, move |stream| {
            let canonical_tmp = canonical_tmp.clone();
            async move {
                let (reader, mut writer) = stream.into_split();
                let mut buf_reader = BufReader::new(reader);
                let mut line = String::new();
                buf_reader.read_line(&mut line).await.unwrap();

                let msg: ClientMessage = serde_json::from_str(line.trim()).unwrap();
                match msg {
                    ClientMessage::Exec { tool, args, cwd } => {
                        assert_eq!(tool, "echo");
                        assert_eq!(args, vec!["hello", "world"]);
                        // CWD should be canonicalized.
                        assert_eq!(cwd, canonical_tmp.to_string_lossy().as_ref());
                    }
                    other => panic!("expected Exec message, got: {other:?}"),
                }

                // Send exit code 0.
                write_daemon_msg(&mut writer, &DaemonMessage::Exit { code: 0 }).await;
            }
        })
        .await;

        let code = exec(
            "echo".to_string(),
            vec!["hello".to_string(), "world".to_string()],
            tmp.path(),
            None,
        )
        .await
        .unwrap();

        assert_eq!(code, 0);
        daemon.await.unwrap();
    }

    // ── Exec: CWD is canonicalized (absolute, symlink-resolved) ──────────

    #[tokio::test]
    async fn exec_cwd_is_canonicalized() {
        let tmp = tempdir().unwrap();
        // Create a subdirectory and a symlink to it.
        let real_dir = tmp.path().join("real");
        fs::create_dir(&real_dir).unwrap();

        // Put config in the real directory.
        write_config(&real_dir, minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_real = std::fs::canonicalize(&real_dir).unwrap();
        let socket_path = canonical_real.join("airlock.sock");

        let daemon = mock_daemon(&socket_path, move |stream| {
            let canonical_real = canonical_real.clone();
            async move {
                let (reader, mut writer) = stream.into_split();
                let mut buf_reader = BufReader::new(reader);
                let mut line = String::new();
                buf_reader.read_line(&mut line).await.unwrap();

                let msg: ClientMessage = serde_json::from_str(line.trim()).unwrap();
                if let ClientMessage::Exec { cwd, .. } = msg {
                    // Must be an absolute path (starts with /).
                    assert!(cwd.starts_with('/'), "CWD should be absolute, got: {cwd}");
                    // Must match the canonicalized path.
                    assert_eq!(
                        cwd,
                        canonical_real.to_string_lossy().as_ref(),
                        "CWD should be canonicalized"
                    );
                }

                write_daemon_msg(&mut writer, &DaemonMessage::Exit { code: 0 }).await;
            }
        })
        .await;

        let code = exec("echo".to_string(), vec![], &real_dir, None)
            .await
            .unwrap();
        assert_eq!(code, 0);
        daemon.await.unwrap();
    }

    // ── Exec: stdout messages go to stdout ───────────────────────────────

    #[tokio::test]
    async fn exec_stdout_messages_received() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let socket_path = canonical_tmp.join("airlock.sock");

        let daemon = mock_daemon(&socket_path, |stream| async move {
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();
            buf_reader.read_line(&mut line).await.unwrap();

            // Send stdout, stderr, then exit.
            write_daemon_msg(
                &mut writer,
                &DaemonMessage::Stdout {
                    data: "hello stdout\n".to_string(),
                },
            )
            .await;
            write_daemon_msg(
                &mut writer,
                &DaemonMessage::Stderr {
                    data: "hello stderr\n".to_string(),
                },
            )
            .await;
            write_daemon_msg(&mut writer, &DaemonMessage::Exit { code: 0 }).await;
        })
        .await;

        // The exec function writes to real stdout/stderr, which we can't easily
        // capture in process. But we can verify it completes successfully.
        let code = exec("echo".to_string(), vec![], tmp.path(), None)
            .await
            .unwrap();
        assert_eq!(code, 0);
        daemon.await.unwrap();
    }

    // ── Exec: exit code 0 ────────────────────────────────────────────────

    #[tokio::test]
    async fn exec_exit_code_zero() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let socket_path = canonical_tmp.join("airlock.sock");

        let daemon = mock_daemon(&socket_path, |stream| async move {
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();
            buf_reader.read_line(&mut line).await.unwrap();

            write_daemon_msg(&mut writer, &DaemonMessage::Exit { code: 0 }).await;
        })
        .await;

        let code = exec("echo".to_string(), vec![], tmp.path(), None)
            .await
            .unwrap();
        assert_eq!(code, 0);
        daemon.await.unwrap();
    }

    // ── Exec: non-zero exit code is faithfully propagated ────────────────

    #[tokio::test]
    async fn exec_nonzero_exit_code_propagated() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let socket_path = canonical_tmp.join("airlock.sock");

        let daemon = mock_daemon(&socket_path, |stream| async move {
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();
            buf_reader.read_line(&mut line).await.unwrap();

            write_daemon_msg(&mut writer, &DaemonMessage::Exit { code: 42 }).await;
        })
        .await;

        let code = exec("echo".to_string(), vec![], tmp.path(), None)
            .await
            .unwrap();
        assert_eq!(code, 42);
        daemon.await.unwrap();
    }

    // ── Exec: error message from daemon ──────────────────────────────────

    #[tokio::test]
    async fn exec_error_message_returns_code_1() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let socket_path = canonical_tmp.join("airlock.sock");

        let daemon = mock_daemon(&socket_path, |stream| async move {
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();
            buf_reader.read_line(&mut line).await.unwrap();

            write_daemon_msg(
                &mut writer,
                &DaemonMessage::Error {
                    message: "unknown tool: foobar".to_string(),
                },
            )
            .await;
        })
        .await;

        let code = exec("foobar".to_string(), vec![], tmp.path(), None)
            .await
            .unwrap();
        assert_eq!(code, 1);
        daemon.await.unwrap();
    }

    // ── Exec: unexpected socket closure ──────────────────────────────────

    #[tokio::test]
    async fn exec_unexpected_eof_produces_error() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let socket_path = canonical_tmp.join("airlock.sock");

        // Mock daemon that closes connection immediately after reading request.
        let daemon = mock_daemon(&socket_path, |stream| async move {
            let (reader, _writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();
            buf_reader.read_line(&mut line).await.unwrap();
            // Drop writer — closes connection.
        })
        .await;

        let result = exec("echo".to_string(), vec![], tmp.path(), None).await;
        assert!(result.is_err());
        assert!(
            matches!(result.as_ref().unwrap_err(), ClientError::UnexpectedEof),
            "expected UnexpectedEof, got: {:?}",
            result.unwrap_err()
        );
        daemon.await.unwrap();
    }

    // ── Exec: stdin forwarding with pipe ─────────────────────────────────

    // Note: stdin forwarding when stdin is a pipe cannot be tested directly
    // in unit tests because test processes have their stdin connected to
    // /dev/null or a TTY, not a pipe. The stdin forwarding logic is exercised
    // in the CLI integration tests. However, we test the is_stdin_tty function
    // and the stdin message protocol.

    #[test]
    fn is_stdin_tty_returns_bool() {
        // In test context, stdin is typically not a TTY (connected to /dev/null
        // or a pipe from the test runner). We just verify the function doesn't
        // crash and returns a bool.
        let _result = is_stdin_tty();
    }

    // ── Logs: successful retrieval ───────────────────────────────────────

    #[tokio::test]
    async fn logs_retrieves_entries() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let socket_path = canonical_tmp.join("airlock.sock");

        let daemon = mock_daemon(&socket_path, |stream| async move {
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();
            buf_reader.read_line(&mut line).await.unwrap();

            let msg: ClientMessage = serde_json::from_str(line.trim()).unwrap();
            assert!(
                matches!(msg, ClientMessage::Logs),
                "expected Logs message, got: {msg:?}"
            );

            let response = DaemonMessage::LogsResponse {
                entries: vec![
                    crate::protocol::LogEntry {
                        timestamp: "2025-01-15T10:30:00Z".to_string(),
                        message: "daemon started".to_string(),
                    },
                    crate::protocol::LogEntry {
                        timestamp: "2025-01-15T10:30:05Z".to_string(),
                        message: "connection accepted".to_string(),
                    },
                ],
            };
            write_daemon_msg(&mut writer, &response).await;
        })
        .await;

        let code = logs(tmp.path(), None).await.unwrap();
        assert_eq!(code, 0);
        daemon.await.unwrap();
    }

    // ── Logs: daemon returns error ───────────────────────────────────────

    #[tokio::test]
    async fn logs_error_from_daemon_returns_code_1() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let socket_path = canonical_tmp.join("airlock.sock");

        let daemon = mock_daemon(&socket_path, |stream| async move {
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();
            buf_reader.read_line(&mut line).await.unwrap();

            write_daemon_msg(
                &mut writer,
                &DaemonMessage::Error {
                    message: "internal error".to_string(),
                },
            )
            .await;
        })
        .await;

        let code = logs(tmp.path(), None).await.unwrap();
        assert_eq!(code, 1);
        daemon.await.unwrap();
    }

    // ── Logs: empty entries ──────────────────────────────────────────────

    #[tokio::test]
    async fn logs_empty_entries() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let socket_path = canonical_tmp.join("airlock.sock");

        let daemon = mock_daemon(&socket_path, |stream| async move {
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();
            buf_reader.read_line(&mut line).await.unwrap();

            let response = DaemonMessage::LogsResponse { entries: vec![] };
            write_daemon_msg(&mut writer, &response).await;
        })
        .await;

        let code = logs(tmp.path(), None).await.unwrap();
        assert_eq!(code, 0);
        daemon.await.unwrap();
    }

    // ── Logs: socket not found ───────────────────────────────────────────

    #[tokio::test]
    async fn logs_fails_when_socket_not_found() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let result = logs(tmp.path(), None).await;
        assert!(result.is_err());
        assert!(
            matches!(
                result.as_ref().unwrap_err(),
                ClientError::SocketNotFound { .. }
            ),
            "expected SocketNotFound, got: {:?}",
            result.unwrap_err()
        );
    }

    // ── Logs: unexpected EOF ─────────────────────────────────────────────

    #[tokio::test]
    async fn logs_unexpected_eof() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let socket_path = canonical_tmp.join("airlock.sock");

        let daemon = mock_daemon(&socket_path, |stream| async move {
            let (reader, _writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();
            buf_reader.read_line(&mut line).await.unwrap();
            // Close connection without responding.
        })
        .await;

        let result = logs(tmp.path(), None).await;
        assert!(result.is_err());
        assert!(
            matches!(result.as_ref().unwrap_err(), ClientError::UnexpectedEof),
            "expected UnexpectedEof, got: {:?}",
            result.unwrap_err()
        );
        daemon.await.unwrap();
    }

    // ── Exec: connection refused (stale socket file) ─────────────────────

    #[tokio::test]
    async fn exec_connection_refused_with_stale_socket() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let socket_path = canonical_tmp.join("airlock.sock");

        // Create a regular file at the socket path to simulate a stale socket.
        fs::write(&socket_path, "stale").unwrap();

        let result = exec("echo".to_string(), vec![], tmp.path(), None).await;
        assert!(result.is_err());
        // The exact error depends on OS — could be ConnectionRefused or
        // ConnectionFailed. What matters is it's not SocketNotFound.
        let err = result.unwrap_err();
        assert!(
            !matches!(err, ClientError::SocketNotFound { .. }),
            "should not be SocketNotFound since the file exists: {err:?}"
        );
    }

    // ── SIGINT handling (structural test) ────────────────────────────────

    // Full SIGINT integration test requires a real daemon. Here we verify the
    // structural aspect: that dropping the socket connection terminates
    // the read loop with an appropriate error.
    #[tokio::test]
    async fn dropping_socket_causes_read_to_terminate() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let socket_path = canonical_tmp.join("airlock.sock");

        // Start a mock daemon that sends stdout then closes.
        let daemon = mock_daemon(&socket_path, |stream| async move {
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();
            buf_reader.read_line(&mut line).await.unwrap();

            write_daemon_msg(
                &mut writer,
                &DaemonMessage::Stdout {
                    data: "partial output\n".to_string(),
                },
            )
            .await;

            // Drop the writer to close our side.
            drop(writer);
        })
        .await;

        let result = exec("echo".to_string(), vec![], tmp.path(), None).await;
        // Should get UnexpectedEof since daemon closed without sending exit.
        assert!(result.is_err());
        assert!(
            matches!(result.as_ref().unwrap_err(), ClientError::UnexpectedEof),
            "expected UnexpectedEof after partial output, got: {:?}",
            result.unwrap_err()
        );
        daemon.await.unwrap();
    }

    // ── Exec: multiple stdout/stderr messages interleaved ────────────────

    #[tokio::test]
    async fn exec_handles_interleaved_stdout_stderr() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let socket_path = canonical_tmp.join("airlock.sock");

        let daemon = mock_daemon(&socket_path, |stream| async move {
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();
            buf_reader.read_line(&mut line).await.unwrap();

            // Interleave stdout and stderr.
            write_daemon_msg(
                &mut writer,
                &DaemonMessage::Stdout {
                    data: "out1\n".to_string(),
                },
            )
            .await;
            write_daemon_msg(
                &mut writer,
                &DaemonMessage::Stderr {
                    data: "err1\n".to_string(),
                },
            )
            .await;
            write_daemon_msg(
                &mut writer,
                &DaemonMessage::Stdout {
                    data: "out2\n".to_string(),
                },
            )
            .await;
            write_daemon_msg(
                &mut writer,
                &DaemonMessage::Stderr {
                    data: "err2\n".to_string(),
                },
            )
            .await;
            write_daemon_msg(&mut writer, &DaemonMessage::Exit { code: 0 }).await;
        })
        .await;

        let code = exec("echo".to_string(), vec![], tmp.path(), None)
            .await
            .unwrap();
        assert_eq!(code, 0);
        daemon.await.unwrap();
    }

    // ── read_daemon_responses: unit test with mock reader ────────────────

    #[tokio::test]
    async fn read_daemon_responses_handles_exit() {
        let data = format!(
            "{}\n",
            serde_json::to_string(&DaemonMessage::Exit { code: 7 }).unwrap()
        );
        let cursor = std::io::Cursor::new(data.into_bytes());
        let mut reader = tokio::io::BufReader::new(cursor);

        let code = read_daemon_responses(&mut reader).await.unwrap();
        assert_eq!(code, 7);
    }

    #[tokio::test]
    async fn read_daemon_responses_handles_error() {
        let data = format!(
            "{}\n",
            serde_json::to_string(&DaemonMessage::Error {
                message: "test error".to_string()
            })
            .unwrap()
        );
        let cursor = std::io::Cursor::new(data.into_bytes());
        let mut reader = tokio::io::BufReader::new(cursor);

        let code = read_daemon_responses(&mut reader).await.unwrap();
        assert_eq!(code, 1);
    }

    #[tokio::test]
    async fn read_daemon_responses_handles_stdout_then_exit() {
        let mut data = String::new();
        data.push_str(
            &serde_json::to_string(&DaemonMessage::Stdout {
                data: "hello\n".to_string(),
            })
            .unwrap(),
        );
        data.push('\n');
        data.push_str(&serde_json::to_string(&DaemonMessage::Exit { code: 0 }).unwrap());
        data.push('\n');

        let cursor = std::io::Cursor::new(data.into_bytes());
        let mut reader = tokio::io::BufReader::new(cursor);

        let code = read_daemon_responses(&mut reader).await.unwrap();
        assert_eq!(code, 0);
    }

    #[tokio::test]
    async fn read_daemon_responses_unexpected_eof() {
        // Empty input — no messages at all.
        let cursor = std::io::Cursor::new(Vec::<u8>::new());
        let mut reader = tokio::io::BufReader::new(cursor);

        let result = read_daemon_responses(&mut reader).await;
        assert!(matches!(result, Err(ClientError::UnexpectedEof)));
    }
}
