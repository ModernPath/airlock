//! Shared test helpers for end-to-end integration tests.
//!
//! Drives the real compiled `airlock` binary (`airlock daemon start
//! --foreground`, under `AIRLOCK_TEST_RUNTIME_DIR`) rather than calling
//! daemon internals directly, and registers a session over the real
//! protocol — so these tests exercise the actual v2 wire format end to end
//! and do not depend on the launcher (`src/launcher.rs`, P2-H's), which does
//! not exist yet in this worktree.

#![allow(dead_code)]
#![allow(
    clippy::disallowed_methods,
    reason = "test harness drives the real binary via its own process env (AIRLOCK_TEST_RUNTIME_DIR, etc.), not daemon request-path code"
)]

use std::io::{BufRead, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use airlock::protocol::{
    self, AdminRequest, AdminToken, Auth, ClientHello, DaemonMessage, RegisterPayload,
    RegisterRequest, Request, RequestBody, SandboxKind, SessionEnds, SessionId, SessionToken,
    WireAnchors, WireMode,
};

// ─── Environment variable guard ──────────────────────────────────────────────

/// Global mutex that serializes all E2E tests that modify environment variables.
static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// RAII guard that sets environment variables for the duration of a test
/// and restores them when dropped. Holds the [`ENV_MUTEX`] lock to prevent
/// concurrent tests from interfering.
pub struct EnvGuard {
    vars: Vec<(String, Option<String>)>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvGuard {
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

// ─── Config file helpers (unchanged shape: still plain airlock.toml text) ───

pub fn write_config(dir: &Path, content: &str) {
    std::fs::write(dir.join("airlock.toml"), content).expect("failed to write config");
}

fn standard_read_paths() -> Vec<&'static str> {
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

    read_paths
}

fn read_str() -> String {
    standard_read_paths()
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Config with `sh` tool and one secret (`TEST_E2E_SECRET`).
pub fn config_with_sh_secret() -> String {
    format!(
        r#"
allow_home_root = true

[filesystem]
read = [{}]
write = ["/tmp"]

[secrets.TEST_E2E_SECRET]
source = "env"

[tools.sh.env]
TEST_E2E_SECRET = {{ secret = "TEST_E2E_SECRET" }}
"#,
        read_str()
    )
}

/// Config with `sh` tool and no secrets.
pub fn config_with_sh_no_secrets() -> String {
    format!(
        r#"
allow_home_root = true

[filesystem]
read = [{}]
write = ["/tmp"]

[tools.sh]
"#,
        read_str()
    )
}

/// Build a config string with custom tool definitions.
pub fn config_with_tools(tools_toml: &str) -> String {
    let mut top_level = String::new();
    let mut sections = String::new();
    let mut in_section = false;

    for line in tools_toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_section = true;
        }
        if in_section || (trimmed.is_empty() && !top_level.is_empty()) {
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
        "allow_home_root = true\n{top_level}\n[filesystem]\nread = [{}]\nwrite = [\"/tmp\"]\n\n{sections}\n",
        read_str()
    )
}

// ─── Daemon lifecycle helpers ────────────────────────────────────────────────

/// A handle to a real `airlock daemon start --foreground` process, plus a
/// registered session for the project it was started for.
pub struct DaemonHandle {
    pub socket_path: PathBuf,
    pub pid_path: PathBuf,
    pub admin_token_path: PathBuf,
    pub daemon_pid: u32,
    pub admin_token: AdminToken,
    pub session_id: SessionId,
    pub token: SessionToken,
    /// This session's proxy CA certificate path, if its config declares a
    /// proxy tool (`<runtime base>/ca/<session id>.pem`; never a path in
    /// the project directory — v1's per-project `airlock-ca.pem` is gone).
    pub ca_path: Option<PathBuf>,
    process: Child,
    _runtime_tmp: tempfile::TempDir,
}

impl DaemonHandle {
    /// Non-blocking check of whether the daemon process has exited, for
    /// tests that signal it directly (SIGTERM) rather than through
    /// [`DaemonHandle::shutdown`].
    pub fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.process.try_wait().ok().flatten()
    }

    /// Block until the daemon process exits.
    pub fn wait(&mut self) -> std::process::ExitStatus {
        self.process.wait().expect("wait on daemon process")
    }

    /// Stop the daemon over the real admin protocol, then wait for the
    /// process to exit (falling back to SIGTERM/SIGKILL if it doesn't).
    pub fn shutdown(mut self) {
        if let Ok(mut stream) = UnixStream::connect(&self.socket_path) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
            handshake(&mut stream);
            let req = Request {
                auth: Auth::Admin {
                    token: self.admin_token.clone(),
                },
                body: RequestBody::Admin(AdminRequest::Stop),
            };
            send_message(&mut stream, &req);
            let mut reader = std::io::BufReader::new(&stream);
            let _ = try_read_response(&mut reader);
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            match self.process.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(_) => break,
            }
            if std::time::Instant::now() > deadline {
                unsafe { libc::kill(self.daemon_pid as i32, libc::SIGKILL) };
                let _ = self.process.wait();
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Start a real `airlock daemon start --foreground` process in a fresh,
/// isolated runtime dir, then register a session for `project_dir` built
/// from the `airlock.toml` already written there (see [`write_config`]).
pub fn start_daemon(project_dir: &Path) -> DaemonHandle {
    let toml_src = std::fs::read_to_string(project_dir.join("airlock.toml")).unwrap_or_default();
    start_daemon_with_config(project_dir, &toml_src)
}

/// Like [`start_daemon`], but takes the config text directly instead of
/// reading it back off disk.
pub fn start_daemon_with_config(project_dir: &Path, toml_src: &str) -> DaemonHandle {
    let runtime_tmp = tempfile::tempdir().expect("runtime tmpdir");
    let runtime_base = runtime_tmp.path().join("rt");

    let binary = env!("CARGO_BIN_EXE_airlock");
    let mut process = Command::new(binary)
        .args(["daemon", "start", "--foreground"])
        .env("AIRLOCK_TEST_RUNTIME_DIR", &runtime_base)
        // The suite may itself run under Airlock; the daemon it starts stands
        // in for one started from the user's terminal.
        .env_remove("AIRLOCK_SANDBOX")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn `airlock daemon start --foreground`");

    let socket_path = runtime_base.join("airlock.sock");
    let pid_path = runtime_base.join("airlock.pid");
    let admin_token_path = runtime_base.join("admin.token");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !(admin_token_path.exists() && socket_path.exists()) {
        if let Ok(Some(status)) = process.try_wait() {
            panic!("airlock daemon exited early with {status:?}");
        }
        if std::time::Instant::now() > deadline {
            let _ = process.kill();
            panic!("daemon did not become ready within 10s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let daemon_pid: u32 = std::fs::read_to_string(&pid_path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let admin_token = read_admin_token(&admin_token_path).expect("admin token should be readable");

    let (session_id, token, ca_path) =
        register_session(&socket_path, &admin_token, project_dir, toml_src);

    DaemonHandle {
        socket_path,
        pid_path,
        admin_token_path,
        daemon_pid,
        admin_token,
        session_id,
        token,
        ca_path,
        process,
        _runtime_tmp: runtime_tmp,
    }
}

fn read_admin_token(path: &Path) -> Option<AdminToken> {
    let contents = std::fs::read_to_string(path).ok()?;
    AdminToken::parse(contents.trim()).ok()
}

/// Act as a minimal stand-in for the real launcher: resolve the `env`
/// secrets a test's config declares from this process's own environment
/// (which the test set via [`EnvGuard`]), and run any `command` secrets
/// directly. Real secret resolution with its full error handling lives in
/// `src/secrets.rs`; this is test-only plumbing.
fn collect_test_secrets(raw: &airlock::config::RawConfig) -> Vec<protocol::WireSecret> {
    let mut out = Vec::new();
    let Some(secrets) = &raw.secrets else {
        return out;
    };

    for (label, spec) in secrets {
        match spec.source.as_deref() {
            Some("env") => {
                let var = spec.from.clone().unwrap_or_else(|| label.clone());
                if let Ok(value) = std::env::var(&var) {
                    out.push(protocol::WireSecret {
                        label: label.clone(),
                        value: zeroize::Zeroizing::new(value),
                    });
                }
            }
            Some("command") => {
                if let Some(argv) = &spec.command
                    && let Ok(output) = Command::new(&argv[0]).args(&argv[1..]).output()
                    && output.status.success()
                {
                    let mut value = String::from_utf8_lossy(&output.stdout).into_owned();
                    while matches!(value.chars().last(), Some('\n') | Some('\r')) {
                        value.pop();
                    }
                    out.push(protocol::WireSecret {
                        label: label.clone(),
                        value: zeroize::Zeroizing::new(value),
                    });
                }
            }
            _ => {}
        }
    }
    out
}

fn register_session(
    socket_path: &Path,
    admin_token: &AdminToken,
    root: &Path,
    toml_src: &str,
) -> (SessionId, SessionToken, Option<PathBuf>) {
    let raw: airlock::config::RawConfig = toml::from_str(toml_src)
        .unwrap_or_else(|e| panic!("test config does not parse: {e}\n{toml_src}"));
    let secrets = collect_test_secrets(&raw);

    let path = std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .map(PathBuf::from)
        .collect();

    let payload = RegisterPayload {
        root: root.to_path_buf(),
        mode: WireMode::Default,
        layers: Vec::new(),
        config: raw,
        secrets,
        env_snapshot: Default::default(),
        path,
        dropped_path: Vec::new(),
        write_grants: Vec::new(),
        anchors: WireAnchors {
            runtime_base: PathBuf::from("/tmp/airlock-e2e-rt"),
            trust_store: PathBuf::from("/tmp/airlock-e2e-trust"),
            global_config: PathBuf::from("/tmp/airlock-e2e-global.toml"),
        },
        agent_hash: "deadbeef".to_string(),
    };

    let mut stream = UnixStream::connect(socket_path)
        .unwrap_or_else(|e| panic!("connect to {socket_path:?}: {e}"));
    handshake(&mut stream);
    let req = Request {
        auth: Auth::Admin {
            token: admin_token.clone(),
        },
        body: RequestBody::Admin(AdminRequest::Register(Box::new(RegisterRequest {
            payload,
            name: "e2e".to_string(),
            sandbox: SandboxKind::External,
            ends: SessionEnds::Ttl { secs: 3600 },
        }))),
    };
    send_message(&mut stream, &req);
    let mut reader = std::io::BufReader::new(&stream);
    match read_response(&mut reader) {
        DaemonMessage::Registered { id, token, ca_path } => (id, token, ca_path),
        other => panic!("expected Registered, got {other:?}"),
    }
}

// ─── NDJSON client helpers ───────────────────────────────────────────────────

/// Send the client hello and discard the daemon's `Hello` reply. Every
/// connection must do this before sending its one `Request`.
pub fn handshake(stream: &mut UnixStream) {
    let hello = ClientHello {
        protocol: protocol::PROTOCOL_VERSION,
        version: "e2e-test".to_string(),
    };
    send_message(stream, &hello);
    let mut reader = std::io::BufReader::new(&*stream);
    let _: DaemonMessage = read_response(&mut reader);
}

/// Send an NDJSON message over a `UnixStream`.
pub fn send_message<T: serde::Serialize>(stream: &mut UnixStream, msg: &T) {
    let json = serde_json::to_string(msg).expect("failed to serialize message");
    stream.write_all(json.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
}

/// Read one NDJSON line from a UnixStream and parse as `DaemonMessage`.
pub fn read_response<R: std::io::Read>(reader: &mut std::io::BufReader<R>) -> DaemonMessage {
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

/// Read one NDJSON line, returning `None` if the connection closes.
pub fn try_read_response<R: std::io::Read>(
    reader: &mut std::io::BufReader<R>,
) -> Option<DaemonMessage> {
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => None,
        Ok(_) => Some(
            serde_json::from_str(line.trim())
                .unwrap_or_else(|e| panic!("failed to parse response: {e}\nRaw line: {line:?}")),
        ),
        Err(_) => None,
    }
}

/// Connect to the daemon, handshake, and set a read timeout — ready for the
/// caller to send its one `Request`.
pub fn connect_to_daemon(socket_path: &Path, timeout_secs: u64) -> UnixStream {
    let mut stream = UnixStream::connect(socket_path)
        .unwrap_or_else(|e| panic!("failed to connect to daemon at {socket_path:?}: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .unwrap();
    handshake(&mut stream);
    stream
}

/// Collect all daemon messages for an exec request until an `Exit` or
/// `Error` is received.
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
}

/// Run a tool through the daemon (using the handle's registered session)
/// and collect all output.
pub fn exec_tool(daemon: &DaemonHandle, tool: &str, args: &[&str], cwd: &str) -> ExecResult {
    exec_tool_as(&daemon.socket_path, &daemon.token, tool, args, cwd)
}

/// Like [`exec_tool`], but takes the socket path and session token
/// separately — for tests that run several execs from separate threads and
/// only want to clone the (small, `Clone`) token across them, not the whole
/// [`DaemonHandle`] (which owns the child process and isn't `Send`-shareable
/// that way).
pub fn exec_tool_as(
    socket_path: &Path,
    token: &SessionToken,
    tool: &str,
    args: &[&str],
    cwd: &str,
) -> ExecResult {
    let mut stream = connect_to_daemon(socket_path, 30);

    let req = Request {
        auth: Auth::Session {
            token: token.clone(),
        },
        body: RequestBody::Session(airlock::protocol::SessionRequest::Exec {
            tool: tool.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            cwd: PathBuf::from(cwd),
        }),
    };
    send_message(&mut stream, &req);

    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code = None;
    let mut error = None;

    let mut reader = std::io::BufReader::new(&stream);

    loop {
        match try_read_response(&mut reader) {
            Some(DaemonMessage::Stdout { data }) => stdout.push_str(&data),
            Some(DaemonMessage::Stderr { data }) => stderr.push_str(&data),
            Some(DaemonMessage::Exit { code }) => {
                exit_code = Some(code);
                break;
            }
            Some(DaemonMessage::Error { message, .. }) => {
                error = Some(message);
                break;
            }
            Some(_) => {}
            None => break,
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
