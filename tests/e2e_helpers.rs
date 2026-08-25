//! Shared test helpers for end-to-end integration tests.
//!
//! Provides reusable infrastructure for daemon-level testing:
//! - Config file creation in temp directories
//! - Daemon startup and shutdown
//! - Secret environment variable setup
//! - Client connection via NDJSON over Unix sockets

#![allow(dead_code)]

use std::io::{BufRead, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use airlock::daemon;
use airlock::protocol::{ClientMessage, DaemonMessage};

// ─── Environment variable guard ──────────────────────────────────────────────

/// Global mutex that serializes all E2E tests that modify environment variables.
///
/// Environment variables are process-global state. Without serialization,
/// concurrent tests that modify `HOME` (or other vars) race against each
/// other, producing flaky failures.
static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// RAII guard that sets environment variables for the duration of a test
/// and restores them when dropped. Holds the [`ENV_MUTEX`] lock to prevent
/// concurrent tests from interfering.
pub struct EnvGuard {
    vars: Vec<(String, Option<String>)>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvGuard {
    /// Set multiple environment variables, saving their previous values.
    pub fn new(vars: &[(&str, &str)]) -> Self {
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

// ─── Config file helpers ─────────────────────────────────────────────────────

/// Write an `airlock.toml` config with the given content to the specified directory.
pub fn write_config(dir: &Path, content: &str) {
    std::fs::write(dir.join("airlock.toml"), content).expect("failed to write config");
}

/// Config with `sh` tool and one secret (TEST_E2E_SECRET).
pub fn config_with_sh_secret() -> String {
    let mut read_paths = vec!["/usr/lib", "/usr/bin", "/bin", "/dev", "/etc"];

    #[cfg(target_os = "macos")]
    {
        read_paths.extend(&[
            "/System",
            "/Library",
            "/private/var",
            "/var",
            "/private/etc",
            "/Applications",
            "/usr/share",
            "/sbin",
            "/usr/local",
        ]);
    }

    #[cfg(target_os = "linux")]
    {
        for p in ["/lib", "/lib64", "/proc", "/sbin"] {
            if Path::new(p).exists() {
                read_paths.push(p);
            }
        }
    }

    // Support Nix and Homebrew paths.
    for p in ["/nix", "/opt"] {
        if Path::new(p).exists() {
            read_paths.push(p);
        }
    }

    let read_str = read_paths
        .iter()
        .map(|p| format!("\"{}\"", p))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        r#"
allow_home_root = true

[filesystem]
read = [{read_str}]
write = ["/tmp"]

[secrets.TEST_E2E_SECRET]
source = "env"

[tools.sh.env]
TEST_E2E_SECRET = {{ secret = "TEST_E2E_SECRET" }}
"#
    )
}

/// Config with `sh` tool and no secrets.
pub fn config_with_sh_no_secrets() -> String {
    let mut read_paths = vec!["/usr/lib", "/usr/bin", "/bin", "/dev", "/etc"];

    #[cfg(target_os = "macos")]
    {
        read_paths.extend(&[
            "/System",
            "/Library",
            "/private/var",
            "/var",
            "/private/etc",
            "/Applications",
            "/usr/share",
            "/sbin",
            "/usr/local",
        ]);
    }

    #[cfg(target_os = "linux")]
    {
        for p in ["/lib", "/lib64", "/proc", "/sbin"] {
            if Path::new(p).exists() {
                read_paths.push(p);
            }
        }
    }

    for p in ["/nix", "/opt"] {
        if Path::new(p).exists() {
            read_paths.push(p);
        }
    }

    let read_str = read_paths
        .iter()
        .map(|p| format!("\"{}\"", p))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        r#"
allow_home_root = true

[filesystem]
read = [{read_str}]
write = ["/tmp"]

[tools.sh]
"#
    )
}

/// Build a config string with custom tool definitions.
///
/// `tools_toml` may contain top-level keys (like `timeout = 2`) and
/// `[tools.X]` sections. Top-level keys are extracted and placed before
/// `[filesystem]`; everything else goes after.
pub fn config_with_tools(tools_toml: &str) -> String {
    let mut read_paths = vec!["/usr/lib", "/usr/bin", "/bin", "/dev", "/etc"];

    #[cfg(target_os = "macos")]
    {
        read_paths.extend(&[
            "/System",
            "/Library",
            "/private/var",
            "/var",
            "/private/etc",
            "/Applications",
            "/usr/share",
            "/sbin",
            "/usr/local",
        ]);
    }

    #[cfg(target_os = "linux")]
    {
        for p in ["/lib", "/lib64", "/proc", "/sbin"] {
            if Path::new(p).exists() {
                read_paths.push(p);
            }
        }
    }

    for p in ["/nix", "/opt"] {
        if Path::new(p).exists() {
            read_paths.push(p);
        }
    }

    let read_str = read_paths
        .iter()
        .map(|p| format!("\"{}\"", p))
        .collect::<Vec<_>>()
        .join(", ");

    // Separate top-level keys from section entries. Top-level keys are lines
    // that contain `=` and are not inside a `[section]`.
    let mut top_level = String::new();
    let mut sections = String::new();
    let mut in_section = false;

    for line in tools_toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_section = true;
        }
        if in_section || trimmed.is_empty() && !top_level.is_empty() {
            sections.push_str(line);
            sections.push('\n');
        } else if trimmed.contains('=') && !in_section {
            top_level.push_str(line);
            top_level.push('\n');
        } else if !trimmed.is_empty() {
            sections.push_str(line);
            sections.push('\n');
        }
    }

    format!(
        r#"allow_home_root = true
{top_level}
[filesystem]
read = [{read_str}]
write = ["/tmp"]

{sections}
"#
    )
}

// ─── Daemon lifecycle helpers ────────────────────────────────────────────────

/// A handle to a running foreground daemon for test purposes.
pub struct DaemonHandle {
    pub socket_path: PathBuf,
    pub pid_path: PathBuf,
    pub daemon_pid: u32,
    pub join_handle: std::thread::JoinHandle<()>,
}

impl DaemonHandle {
    /// Shut down the daemon by sending SIGTERM and waiting for the thread to finish.
    pub fn shutdown(self) {
        unsafe {
            libc::kill(self.daemon_pid as i32, libc::SIGTERM);
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            if self.join_handle.is_finished() {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("daemon thread did not finish after SIGTERM within 15s");
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        self.join_handle
            .join()
            .expect("daemon thread should finish cleanly");
    }
}

/// Start a foreground daemon in a background thread.
///
/// The daemon uses the config in the given temp directory.
/// Returns a `DaemonHandle` for lifecycle management.
pub fn start_daemon(tmp_dir: &Path) -> DaemonHandle {
    let state =
        daemon::synchronous_startup(tmp_dir, None).expect("synchronous startup should succeed");

    let socket_path = state.config.socket_path.clone();
    let pid_path = state.config.pid_path.clone();

    let handle = std::thread::spawn(move || {
        daemon::run_foreground(state).expect("run_foreground should succeed");
    });

    // Wait for the daemon to be ready (PID file appears).
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !pid_path.exists() {
        if std::time::Instant::now() > deadline {
            panic!("daemon did not create PID file within timeout");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let pid_content = std::fs::read_to_string(&pid_path).unwrap();
    let daemon_pid: u32 = pid_content.trim().parse().expect("PID should be a number");

    DaemonHandle {
        socket_path,
        pid_path,
        daemon_pid,
        join_handle: handle,
    }
}

// ─── NDJSON client helpers ───────────────────────────────────────────────────

/// Send an NDJSON message over a UnixStream.
pub fn send_message(stream: &mut UnixStream, msg: &ClientMessage) {
    let json = serde_json::to_string(msg).expect("failed to serialize message");
    stream.write_all(json.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
}

/// Read one NDJSON line from a UnixStream and parse as DaemonMessage.
pub fn read_response(reader: &mut std::io::BufReader<&mut UnixStream>) -> DaemonMessage {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("failed to read response");
    assert!(
        !line.is_empty(),
        "expected NDJSON response but got empty read (connection closed)"
    );
    serde_json::from_str(line.trim())
        .unwrap_or_else(|e| panic!("failed to parse response: {e}\nRaw line: {line:?}"))
}

/// Read one NDJSON line, returning None if the connection closes.
pub fn try_read_response(
    reader: &mut std::io::BufReader<&mut UnixStream>,
) -> Option<DaemonMessage> {
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => None, // Connection closed.
        Ok(_) => Some(
            serde_json::from_str(line.trim())
                .unwrap_or_else(|e| panic!("failed to parse response: {e}\nRaw line: {line:?}")),
        ),
        Err(_) => None,
    }
}

/// Connect to the daemon and set a read timeout.
pub fn connect_to_daemon(socket_path: &Path, timeout_secs: u64) -> UnixStream {
    let stream = UnixStream::connect(socket_path)
        .unwrap_or_else(|e| panic!("failed to connect to daemon at {:?}: {e}", socket_path));
    stream
        .set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .unwrap();
    stream
}

/// Collect all daemon messages for an exec request until an Exit or Error is received.
/// Returns (stdout_data, stderr_data, exit_or_error_message).
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
}

/// Run a tool through the daemon and collect all output.
pub fn exec_tool(socket_path: &Path, tool: &str, args: &[&str], cwd: &str) -> ExecResult {
    let mut stream = connect_to_daemon(socket_path, 30);

    let exec_msg = ClientMessage::Exec {
        tool: tool.to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
        cwd: cwd.to_string(),
    };
    send_message(&mut stream, &exec_msg);

    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code = None;
    let mut error = None;

    let mut reader = std::io::BufReader::new(&mut stream);

    loop {
        match try_read_response(&mut reader) {
            Some(DaemonMessage::Stdout { data }) => stdout.push_str(&data),
            Some(DaemonMessage::Stderr { data }) => stderr.push_str(&data),
            Some(DaemonMessage::Exit { code }) => {
                exit_code = Some(code);
                break;
            }
            Some(DaemonMessage::Error { message }) => {
                error = Some(message);
                break;
            }
            Some(DaemonMessage::LogsResponse { .. }) => {
                // Unexpected, ignore.
            }
            None => break, // Connection closed.
        }
    }

    ExecResult {
        stdout,
        stderr,
        exit_code,
        error,
    }
}

/// Check if a process is alive using signal-zero.
pub fn is_process_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}
