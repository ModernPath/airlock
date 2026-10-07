//! Agent-side client: `airlock exec` and `airlock tools list`.
//!
//! Reads only `AIRLOCK_ADDR` and `AIRLOCK_SESSION` — never discovers or
//! trusts config, never starts a daemon. Every message an agent sees on
//! stderr starts with `airlock: ` (docs/airlock-v2-ux.md, "Messages →
//! Agent"); the daemon already formats `Error.message` to match that table
//! verbatim, so most of this module's job is to relay it and map
//! `ErrorKind` to the right exit code.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::admin::{self, AdminError};
use crate::config;
use crate::protocol::{
    Auth, ClientHello, DaemonMessage, ErrorKind, Request, RequestBody, SessionRequest,
    SessionToken, StdinFrame, WireLayer,
};
use crate::runtime_dir;
use crate::trust::escape_for_terminal as esc;

/// No `AIRLOCK_SESSION` (or `AIRLOCK_ADDR`) is set — this process was not
/// started under a session. `pub(crate)`: `agent.rs`'s `check`/`hook`
/// reuse the exact wording.
pub(crate) const NO_SESSION_MESSAGE: &str = "no Airlock session. The user starts one with `airlock run`; this process was not started that way.";

/// Reads `AIRLOCK_ADDR` and `AIRLOCK_SESSION`, returning the socket path and
/// parsed token, or `None` if either is missing or malformed — both cases
/// collapse to the same "no session" message (docs/airlock-v2-ux.md,
/// "Messages → Agent"). `pub(crate)`: shared with `agent.rs`'s `check`/
/// `hook`, which read the same two variables and nothing else.
#[allow(
    clippy::disallowed_methods,
    reason = "client-side: reads the two session-handoff variables from its own process environment, not daemon request-path code"
)]
pub(crate) fn session_from_env() -> Option<(PathBuf, SessionToken)> {
    let addr = std::env::var("AIRLOCK_ADDR").ok()?;
    let session = std::env::var("AIRLOCK_SESSION").ok()?;
    let socket_path = runtime_dir::parse_addr(&addr).ok()?;
    let token = SessionToken::parse(&session).ok()?;
    Some((socket_path, token))
}

/// Connects to the daemon and performs the handshake. Returns the
/// `Hello` protocol it reports so callers that care about an incompatible
/// protocol can decide; this module just surfaces the daemon's own `Error`
/// reply either way.
async fn connect(socket_path: &Path) -> Result<UnixStream, String> {
    UnixStream::connect(socket_path).await.map_err(|_| {
        format!(
            "the daemon at unix://{} does not answer. Ask the user to check `airlock status`.",
            socket_path.display()
        )
    })
}

async fn handshake(stream: &mut UnixStream) -> Result<(), String> {
    let bytes = crate::protocol::encode_line(&ClientHello::current());
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| format!("socket write failed: {e}"))?;
    Ok(())
}

/// Reads one NDJSON `DaemonMessage` line from `reader`.
async fn read_one<R: tokio::io::AsyncBufReadExt + Unpin>(
    reader: &mut R,
) -> Result<DaemonMessage, String> {
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("socket read failed: {e}"))?;
    if n == 0 {
        return Err("the daemon closed the connection unexpectedly".to_string());
    }
    serde_json::from_str(line.trim_end())
        .map_err(|_| "malformed response from the daemon".to_string())
}

async fn write_frame<T: serde::Serialize, W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    value: &T,
) -> std::io::Result<()> {
    writer.write_all(&crate::protocol::encode_line(value)).await
}

/// Opens a fresh connection, handshakes, and sends `request` authorized
/// with `token`, returning the first [`DaemonMessage`] the daemon sends
/// back (which may itself be an `Error` — callers decide how to handle
/// that). A connection carries exactly one request (docs/airlock-v2-
/// technical-guidance.md), so every one-shot session request —
/// `tools list`'s own `List`, and `agent check`'s `Check`/`List` probes —
/// goes through this one connection-handling path and sees the same
/// connection-level failures (`connect`/`handshake`/`read_one`'s messages,
/// already matching docs/airlock-v2-ux.md, "Messages → Agent").
pub(crate) async fn session_request(
    socket_path: &Path,
    token: &SessionToken,
    request: SessionRequest,
) -> Result<DaemonMessage, String> {
    let mut stream = connect(socket_path).await?;
    handshake(&mut stream).await?;
    let (reader_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    read_one(&mut reader).await?; // Hello
    let req = Request {
        auth: Auth::Session {
            token: token.clone(),
        },
        body: RequestBody::Session(request),
    };
    write_frame(&mut writer, &req)
        .await
        .map_err(|e| format!("socket write failed: {e}"))?;
    read_one(&mut reader).await
}

// ─── exec ─────────────────────────────────────────────────────────────────────

/// Runs `airlock exec -- <tool> [args...]`. Returns the process exit code:
/// the tool's own code on success, or 125/126/127 per
/// [`ErrorKind::exit_code`] on an Airlock-level failure. Every failure is
/// printed to stderr (prefixed `airlock: `) before returning, so the caller
/// only needs to map the return value to a process exit status.
pub async fn exec(tool: String, args: Vec<String>, cwd: &Path) -> i32 {
    let Some((socket_path, token)) = session_from_env() else {
        eprintln!("airlock: {NO_SESSION_MESSAGE}");
        return 125;
    };

    let mut stream = match connect(&socket_path).await {
        Ok(s) => s,
        Err(message) => {
            eprintln!("airlock: {message}");
            return 125;
        }
    };
    if let Err(message) = handshake(&mut stream).await {
        eprintln!("airlock: {message}");
        return 125;
    }

    let (reader_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader_half);

    // Consume the Hello line; its contents don't change what we do next —
    // an incompatible protocol surfaces as the daemon's own Error reply,
    // handled uniformly below.
    if let Err(message) = read_one(&mut reader).await {
        eprintln!("airlock: {message}");
        return 125;
    }

    let request = Request {
        auth: Auth::Session {
            token: token.clone(),
        },
        body: RequestBody::Session(SessionRequest::Exec {
            tool: tool.clone(),
            args,
            cwd: cwd.to_path_buf(),
        }),
    };
    if let Err(e) = write_frame(&mut writer, &request).await {
        eprintln!("airlock: socket write failed: {e}");
        return 125;
    }

    let stdin_is_pipe = !is_stdin_tty();
    let stdin_handle = if stdin_is_pipe {
        Some(tokio::spawn(forward_stdin(writer)))
    } else {
        None
    };

    let mut sigint = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("airlock: failed to install SIGINT handler: {e}");
            return 125;
        }
    };

    let outcome = tokio::select! {
        result = read_responses(&mut reader, &token, &socket_path) => result,
        _ = sigint.recv() => {
            drop(reader);
            if let Some(handle) = stdin_handle {
                handle.abort();
            }
            return 130;
        }
    };

    if let Some(handle) = stdin_handle {
        handle.abort();
    }

    match outcome {
        Ok(code) => code,
        Err(message) => {
            eprintln!("airlock: {message}");
            125
        }
    }
}

fn is_stdin_tty() -> bool {
    // SAFETY: isatty is always safe to call with a valid file descriptor;
    // stdin (fd 0) is valid for the life of the process.
    unsafe { libc::isatty(libc::STDIN_FILENO) != 0 }
}

async fn forward_stdin<W: tokio::io::AsyncWriteExt + Unpin>(mut writer: W) {
    use tokio::io::AsyncReadExt;

    let mut stdin = tokio::io::stdin();
    let mut buf = vec![0u8; 8192];

    loop {
        let n = match stdin.read(&mut buf).await {
            Ok(0) | Err(_) => {
                let _ = write_frame(&mut writer, &StdinFrame::StdinEof).await;
                break;
            }
            Ok(n) => n,
        };
        let data = String::from_utf8_lossy(&buf[..n]).into_owned();
        if write_frame(&mut writer, &StdinFrame::Stdin { data })
            .await
            .is_err()
        {
            break;
        }
    }
    // Returning would drop `writer`, and dropping an `OwnedWriteHalf` shuts
    // down the socket's write side. The daemon reads that EOF as "the client
    // went away" and kills the tool, so hold the writer until `exec` aborts
    // this task.
    std::future::pending::<()>().await;
}

/// Reads daemon responses until `Exit` or `Error`, printing `Stdout`/
/// `Stderr` as they arrive. On `Error`, applies the `UnknownTool` ==>
/// config-changed-hint special case (docs/airlock-v2-ux.md, "The agent
/// changes the config") before returning the mapped exit code.
async fn read_responses<R: tokio::io::AsyncBufReadExt + Unpin>(
    reader: &mut R,
    token: &SessionToken,
    socket_path: &Path,
) -> Result<i32, String> {
    use std::io::Write;

    loop {
        match read_one(reader).await? {
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
            DaemonMessage::Exit { code } => return Ok(code),
            DaemonMessage::Error { kind, message } => {
                eprintln!("airlock: {message}");
                if kind == ErrorKind::UnknownTool {
                    print_config_changed_hint_if_any(socket_path, token).await;
                }
                return Ok(kind.exit_code() as i32);
            }
            _ => continue,
        }
    }
}

/// `UnknownTool`'s follow-up: ask the daemon (on a fresh connection) for
/// this session's layers via `List`, and if any registered layer's hash no
/// longer matches the file on disk, print the config-changed hint. Best
/// effort: any failure here is silently skipped — the primary error has
/// already been reported.
async fn print_config_changed_hint_if_any(socket_path: &Path, token: &SessionToken) {
    let Ok(mut stream) = connect(socket_path).await else {
        return;
    };
    if handshake(&mut stream).await.is_err() {
        return;
    }
    let (reader_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    if read_one(&mut reader).await.is_err() {
        return;
    }
    let request = Request {
        auth: Auth::Session {
            token: token.clone(),
        },
        body: RequestBody::Session(SessionRequest::List),
    };
    if write_frame(&mut writer, &request).await.is_err() {
        return;
    }
    if let Ok(DaemonMessage::Tools { session, .. }) = read_one(&mut reader).await
        && layers_changed(&session.layers)
    {
        eprintln!(
            "airlock: airlock.toml changed after this session started. Changes apply\n\
             \u{20}        once the user approves them (`airlock trust`) and reloads the\n\
             \u{20}        session (`airlock session reload`)."
        );
    }
}

/// `pub(crate)`: shared with `agent.rs`'s config-changed note in both
/// `agent check`'s report and `agent hook`'s outcomes.
pub fn layers_changed(layers: &[WireLayer]) -> bool {
    layers.iter().any(|layer| match std::fs::read(&layer.path) {
        Ok(bytes) => config::sha256_hex(&bytes) != layer.sha256,
        Err(_) => false,
    })
}

// ─── tools list ───────────────────────────────────────────────────────────────

/// Runs `airlock tools list` (session) or `airlock tools list --session
/// <ID>` (admin, from the user's terminal). Returns the process exit code.
pub async fn tools_list(session_override: Option<String>) -> i32 {
    match session_override {
        None => tools_list_own_session().await,
        Some(id) => tools_list_by_id(id).await,
    }
}

async fn tools_list_own_session() -> i32 {
    let Some((socket_path, token)) = session_from_env() else {
        eprintln!("airlock: {NO_SESSION_MESSAGE}");
        return 125;
    };
    match session_request(&socket_path, &token, SessionRequest::List).await {
        Ok(DaemonMessage::Tools { tools, .. }) => {
            print_tools(&tools);
            0
        }
        Ok(DaemonMessage::Error { kind, message }) => {
            eprintln!("airlock: {message}");
            kind.exit_code() as i32
        }
        Ok(_) => {
            eprintln!("airlock: unexpected response from the daemon");
            125
        }
        Err(message) => {
            eprintln!("airlock: {message}");
            125
        }
    }
}

/// `tools list --session <ID>`: an admin request from the user's terminal,
/// not a session one. `id` is an id, a unique id prefix or a unique name —
/// the daemon resolves it.
async fn tools_list_by_id(id: String) -> i32 {
    let runtime = match runtime_dir::RuntimeDir::locate() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return 125;
        }
    };
    let (mut conn, token) = match admin::connect_with_token(&runtime) {
        Ok(v) => v,
        Err(AdminError::Unreachable { path }) => {
            eprintln!(
                "error: the daemon at unix://{} does not answer",
                path.display()
            );
            return 125;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return 125;
        }
    };
    match conn.admin_request(&token, crate::protocol::AdminRequest::Tools { session: id }) {
        Ok(DaemonMessage::Tools { session, tools }) => {
            println!(
                "session {} {:?} for {}",
                session.id,
                session.name,
                session.root.display()
            );
            print_tools(&tools);
            0
        }
        Ok(_) => {
            eprintln!("error: unexpected response from the daemon");
            125
        }
        Err(AdminError::Daemon { kind, message }) => {
            eprintln!("error: {message}");
            kind.exit_code() as i32
        }
        Err(e) => {
            eprintln!("error: {e}");
            125
        }
    }
}

/// Renders `airlock tools list`'s output — every piece of text here comes
/// from the daemon's merged config, which may include an unapproved file,
/// so it goes through [`esc`] before it ever reaches the terminal.
fn format_tools(tools: &[crate::protocol::ToolInfo]) -> String {
    let mut sorted: Vec<&crate::protocol::ToolInfo> = tools.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));

    let mut out = String::new();
    for tool in sorted {
        out.push_str(&esc(&tool.name));
        out.push('\n');
        if let Some(desc) = &tool.description {
            out.push_str(&format!("  {}\n", esc(desc)));
        }
        if tool.env.is_empty() {
            out.push_str("  (no environment)\n");
        } else {
            for (var, value) in &tool.env {
                match value {
                    crate::protocol::EnvDisplay::Static(s) => {
                        out.push_str(&format!("  {} = {:?}\n", esc(var), esc(s)))
                    }
                    crate::protocol::EnvDisplay::Secret(label) => {
                        out.push_str(&format!("  {} = <secret {:?}>\n", esc(var), esc(label)))
                    }
                }
            }
        }
        if tool.proxy {
            out.push_str("  proxy tool\n");
        }
    }
    out
}

fn print_tools(tools: &[crate::protocol::ToolInfo]) {
    print!("{}", format_tools(tools));
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "tests may read/set the process environment freely; only request-path code is bound by the session isolation rule"
)]
mod tests {
    use super::*;
    use crate::protocol::PROTOCOL_VERSION;
    use std::sync::MutexGuard;
    use tokio::io::AsyncBufReadExt;

    #[test]
    fn format_tools_escapes_untrusted_control_characters() {
        // A tool description comes from the daemon's merged config, which
        // may include an unapproved file — a bidi override or an ESC byte
        // must not reach the terminal raw.
        let tools = vec![crate::protocol::ToolInfo {
            name: "gh".to_string(),
            description: Some("evil\u{202e}desc\x1b[31m".to_string()),
            env: Vec::new(),
            proxy: false,
        }];
        let out = format_tools(&tools);
        assert!(!out.contains('\u{202e}'));
        assert!(!out.contains('\x1b'));
        assert!(out.contains("\\u{202e}"));
        assert!(out.contains("\\u{1b}"));
    }

    /// RAII guard for a batch of temporary environment variable overrides,
    /// serialized against every other test in the crate that touches the
    /// process environment (`crate::test_support::ENV_MUTEX`).
    ///
    /// Takes every variable in one call rather than one guard per variable:
    /// `ENV_MUTEX` is a plain `std::sync::Mutex`, not reentrant, so two
    /// overlapping guards *on the same thread* (e.g. one each for
    /// `AIRLOCK_ADDR` and `AIRLOCK_SESSION`, both live for a test's
    /// duration) would self-deadlock on the second lock.
    struct TempEnv {
        prev: Vec<(String, Option<String>)>,
        _lock: MutexGuard<'static, ()>,
    }

    impl TempEnv {
        /// `Some(value)` sets the variable; `None` removes it. The previous
        /// value (or absence) of every key is restored on drop.
        fn new(vars: &[(&str, Option<&str>)]) -> Self {
            let lock = crate::test_support::ENV_MUTEX
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut prev = Vec::with_capacity(vars.len());
            for (key, value) in vars {
                prev.push((key.to_string(), std::env::var(key).ok()));
                // SAFETY: serialized by ENV_MUTEX above.
                match value {
                    Some(v) => unsafe { std::env::set_var(key, v) },
                    None => unsafe { std::env::remove_var(key) },
                }
            }
            Self { prev, _lock: lock }
        }
    }

    impl Drop for TempEnv {
        fn drop(&mut self) {
            for (key, value) in &self.prev {
                // SAFETY: serialized by ENV_MUTEX held for the guard's life.
                match value {
                    Some(v) => unsafe { std::env::set_var(key, v) },
                    None => unsafe { std::env::remove_var(key) },
                }
            }
        }
    }

    fn fixed_token() -> String {
        format!("airlock_abc123_{}", "A".repeat(43))
    }

    #[test]
    fn session_from_env_none_when_vars_absent() {
        let _env = TempEnv::new(&[("AIRLOCK_ADDR", None), ("AIRLOCK_SESSION", None)]);
        assert!(session_from_env().is_none());
    }

    #[test]
    fn session_from_env_none_when_token_malformed() {
        let _env = TempEnv::new(&[
            ("AIRLOCK_ADDR", Some("unix:///tmp/airlock.sock")),
            ("AIRLOCK_SESSION", Some("not-a-token")),
        ]);
        assert!(session_from_env().is_none());
    }

    #[test]
    fn session_from_env_parses_valid_pair() {
        let token = fixed_token();
        let _env = TempEnv::new(&[
            ("AIRLOCK_ADDR", Some("unix:///tmp/airlock.sock")),
            ("AIRLOCK_SESSION", Some(&token)),
        ]);
        let (path, parsed) = session_from_env().expect("should parse");
        assert_eq!(path, PathBuf::from("/tmp/airlock.sock"));
        assert_eq!(parsed.expose_secret(), token);
    }

    #[tokio::test]
    async fn exec_without_session_prints_no_session_message() {
        let _env = TempEnv::new(&[("AIRLOCK_ADDR", None), ("AIRLOCK_SESSION", None)]);
        let code = exec("echo".to_string(), vec![], Path::new("/tmp")).await;
        assert_eq!(code, 125);
    }

    #[test]
    fn layers_changed_false_for_matching_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("airlock.toml");
        std::fs::write(&path, b"hello").unwrap();
        let sha = config::sha256_hex(b"hello");
        let layers = vec![WireLayer {
            kind: crate::protocol::LayerKind::Repo,
            path,
            sha256: sha,
        }];
        assert!(!layers_changed(&layers));
    }

    #[test]
    fn layers_changed_true_for_mismatched_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("airlock.toml");
        std::fs::write(&path, b"hello").unwrap();
        let layers = vec![WireLayer {
            kind: crate::protocol::LayerKind::Repo,
            path,
            sha256: config::sha256_hex(b"something else"),
        }];
        assert!(layers_changed(&layers));
    }

    #[test]
    fn layers_changed_false_for_unreadable_file() {
        let layers = vec![WireLayer {
            kind: crate::protocol::LayerKind::Repo,
            path: PathBuf::from("/nonexistent/airlock.toml"),
            sha256: "deadbeef".to_string(),
        }];
        assert!(!layers_changed(&layers));
    }

    // ── Fake-daemon integration tests ──────────────────────────────────

    async fn write_daemon_msg<W: AsyncWriteExt + Unpin>(writer: &mut W, msg: &DaemonMessage) {
        writer
            .write_all(&crate::protocol::encode_line(msg))
            .await
            .unwrap();
    }

    fn ok_hello() -> DaemonMessage {
        DaemonMessage::Hello {
            protocol: PROTOCOL_VERSION,
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid: 1,
            mode: crate::protocol::DaemonMode::Automatic,
            sessions: 1,
        }
    }

    #[tokio::test]
    async fn exec_reports_exit_code_from_daemon() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_path = tmp.path().join("airlock.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader_half, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader_half);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            write_daemon_msg(&mut writer, &ok_hello()).await;

            let mut req_line = String::new();
            reader.read_line(&mut req_line).await.unwrap();
            write_daemon_msg(&mut writer, &DaemonMessage::Exit { code: 7 }).await;
        });

        let addr = format!("unix://{}", socket_path.display());
        let token = fixed_token();
        let _env = TempEnv::new(&[
            ("AIRLOCK_ADDR", Some(addr.as_str())),
            ("AIRLOCK_SESSION", Some(token.as_str())),
        ]);

        let code = exec("echo".to_string(), vec![], tmp.path()).await;
        assert_eq!(code, 7);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn exec_unknown_tool_maps_to_127_and_checks_config_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let socket_path = tmp.path().join("airlock.sock");
        let config_path = tmp.path().join("airlock.toml");
        std::fs::write(&config_path, "changed contents").unwrap();
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        let server = tokio::spawn(async move {
            // First connection: the Exec request.
            let (stream, _) = listener.accept().await.unwrap();
            let (reader_half, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader_half);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            write_daemon_msg(&mut writer, &ok_hello()).await;
            let mut req_line = String::new();
            reader.read_line(&mut req_line).await.unwrap();
            write_daemon_msg(
                &mut writer,
                &DaemonMessage::Error {
                    kind: ErrorKind::UnknownTool,
                    message: "no tool named \"psql\" in this session".to_string(),
                },
            )
            .await;

            // Second connection: the follow-up List.
            let (stream2, _) = listener.accept().await.unwrap();
            let (reader_half2, mut writer2) = stream2.into_split();
            let mut reader2 = BufReader::new(reader_half2);
            let mut line2 = String::new();
            reader2.read_line(&mut line2).await.unwrap();
            write_daemon_msg(&mut writer2, &ok_hello()).await;
            let mut req_line2 = String::new();
            reader2.read_line(&mut req_line2).await.unwrap();
            let session_info = crate::protocol::SessionInfo {
                id: crate::protocol::SessionId::parse("abc123").unwrap(),
                name: "claude".to_string(),
                root: root.clone(),
                started_unix: 0,
                execs: 0,
                ends: crate::protocol::EndsInfo::Never,
                sandbox: crate::protocol::SandboxKind::Airlock,
                layers: vec![WireLayer {
                    kind: crate::protocol::LayerKind::Repo,
                    path: config_path.clone(),
                    sha256: config::sha256_hex(b"original contents"),
                }],
                mode: crate::protocol::WireMode::Default,
                write_grants: Vec::new(),
            };
            write_daemon_msg(
                &mut writer2,
                &DaemonMessage::Tools {
                    session: session_info,
                    tools: vec![],
                },
            )
            .await;
        });

        let addr = format!("unix://{}", socket_path.display());
        let token = fixed_token();
        let _env = TempEnv::new(&[
            ("AIRLOCK_ADDR", Some(addr.as_str())),
            ("AIRLOCK_SESSION", Some(token.as_str())),
        ]);

        let code = exec("psql".to_string(), vec![], tmp.path()).await;
        assert_eq!(code, 127);
        server.await.unwrap();
    }
}
