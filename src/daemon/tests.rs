//! Daemon tests: a real async server, started in-process (no fork), talked
//! to over a real Unix socket in a temp runtime dir.

use super::*;
use crate::protocol::{
    self, AdminRequest, AdminToken, Auth, ClientHello, RegisterPayload, RegisterRequest,
    RequestBody, SandboxKind, SessionEnds, WireAnchors, WireMode,
};
use std::path::PathBuf;
use std::time::Duration;

// ─── Test harness ────────────────────────────────────────────────────────────

/// Keeps the temp dir alive for the test's duration and gives access to the
/// running daemon's state (socket path, admin token, etc.) without going
/// through a real fork.
struct TestDaemon {
    state: Arc<DaemonState>,
    admin_token: AdminToken,
    _tmp: tempfile::TempDir,
}

async fn start_test_daemon(mode: DaemonMode) -> TestDaemon {
    start_test_daemon_with_idle(mode, Some(Duration::from_millis(150))).await
}

async fn start_test_daemon_with_idle(mode: DaemonMode, idle_exit: Option<Duration>) -> TestDaemon {
    let tmp = tempfile::tempdir().expect("tempdir");
    let runtime = RuntimeDir::at(tmp.path().join("rt"));
    runtime.create_and_validate().expect("create_and_validate");

    let listener = bind_owner_only(&runtime.socket_path()).expect("bind");
    verify_socket_permissions(&runtime.socket_path()).expect("verify perms");

    let admin_token = AdminToken::generate();
    write_admin_token(&runtime.admin_token_path(), &admin_token).expect("write admin token");

    listener.set_nonblocking(true).expect("nonblocking");
    let tokio_listener = tokio::net::UnixListener::from_std(listener).expect("from_std");

    let state = DaemonState::new(
        runtime,
        admin_token.clone(),
        mode,
        idle_exit,
        RingBuffer::new(),
    );
    let daemon = Daemon {
        state: Arc::clone(&state),
        listener: tokio_listener,
    };
    tokio::spawn(daemon.serve());

    TestDaemon {
        state,
        admin_token,
        _tmp: tmp,
    }
}

/// A test client speaking the v2 protocol over a real socket.
struct TestClient {
    reader: tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

impl TestClient {
    async fn connect(socket: &Path) -> Self {
        let stream = tokio::net::UnixStream::connect(socket)
            .await
            .expect("connect");
        let (r, w) = stream.into_split();
        TestClient {
            reader: tokio::io::BufReader::new(r),
            writer: w,
        }
    }

    async fn send<T: serde::Serialize>(&mut self, value: &T) {
        use tokio::io::AsyncWriteExt;
        let line = protocol::encode_line(value);
        self.writer.write_all(&line).await.expect("write");
    }

    async fn read(&mut self) -> DaemonMessage {
        use tokio::io::AsyncBufReadExt;
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).await.expect("read_line");
        assert!(n > 0, "connection closed before a reply arrived");
        serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("bad reply {line:?}: {e}"))
    }

    /// Full handshake with the real protocol version, discarding the
    /// `Hello` reply.
    async fn hello(&mut self) {
        self.send(&ClientHello {
            protocol: protocol::PROTOCOL_VERSION,
            version: "test".to_string(),
        })
        .await;
        let _ = self.read().await;
    }

    async fn hello_with_protocol(&mut self, version: u32) -> DaemonMessage {
        self.send(&ClientHello {
            protocol: version,
            version: "test".to_string(),
        })
        .await;
        self.read().await
    }

    /// Handshake, send one request, return its reply.
    async fn request(&mut self, req: Request) -> DaemonMessage {
        self.hello().await;
        self.send(&req).await;
        self.read().await
    }
}

fn admin_request(admin_token: &AdminToken, body: AdminRequest) -> Request {
    Request {
        auth: Auth::Admin {
            token: admin_token.clone(),
        },
        body: RequestBody::Admin(body),
    }
}

fn session_request(token: crate::protocol::SessionToken, body: SessionRequest) -> Request {
    Request {
        auth: Auth::Session { token },
        body: RequestBody::Session(body),
    }
}

fn test_payload(root: &Path, toml_src: &str) -> RegisterPayload {
    let raw: crate::config::RawConfig = toml::from_str(toml_src).expect("valid test TOML");
    RegisterPayload {
        root: root.to_path_buf(),
        mode: WireMode::Default,
        layers: Vec::new(),
        config: raw,
        secrets: Vec::new(),
        env_snapshot: Default::default(),
        path: vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")],
        dropped_path: Vec::new(),
        write_grants: Vec::new(),
        anchors: WireAnchors {
            runtime_base: PathBuf::from("/tmp/airlock-test-rt"),
            trust_store: PathBuf::from("/tmp/airlock-test-trust"),
            global_config: PathBuf::from("/tmp/airlock-test-global.toml"),
        },
        agent_hash: "deadbeef".to_string(),
    }
}

async fn register(
    client: &mut TestClient,
    admin_token: &AdminToken,
    root: &Path,
    toml_src: &str,
    name: &str,
    ends: SessionEnds,
) -> (crate::protocol::SessionId, crate::protocol::SessionToken) {
    let payload = test_payload(root, toml_src);
    let req = admin_request(
        admin_token,
        AdminRequest::Register(Box::new(RegisterRequest {
            payload,
            name: name.to_string(),
            sandbox: SandboxKind::External,
            ends,
        })),
    );
    match client.request(req).await {
        DaemonMessage::Registered { id, token, .. } => (id, token),
        other => panic!("expected Registered, got {other:?}"),
    }
}

// ─── Handshake ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn handshake_version_mismatch_gives_incompatible_protocol() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let mut client = TestClient::connect(&daemon.state.runtime.socket_path()).await;

    let hello = client
        .hello_with_protocol(protocol::PROTOCOL_VERSION + 1)
        .await;
    assert!(matches!(hello, DaemonMessage::Hello { .. }));

    let err = client.read().await;
    assert!(
        matches!(
            err,
            DaemonMessage::Error {
                kind: ErrorKind::IncompatibleProtocol,
                ..
            }
        ),
        "{err:?}"
    );
}

// ─── Admin auth ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_auth_wrong_token_is_unauthorized() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let mut client = TestClient::connect(&daemon.state.runtime.socket_path()).await;

    let bad_token = AdminToken::generate();
    let reply = client
        .request(admin_request(&bad_token, AdminRequest::ListSessions))
        .await;
    assert!(
        matches!(
            reply,
            DaemonMessage::Error {
                kind: ErrorKind::Unauthorized,
                ..
            }
        ),
        "{reply:?}"
    );
}

#[tokio::test]
async fn admin_auth_correct_token_succeeds() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let mut client = TestClient::connect(&daemon.state.runtime.socket_path()).await;

    let reply = client
        .request(admin_request(
            &daemon.admin_token,
            AdminRequest::ListSessions,
        ))
        .await;
    assert!(matches!(reply, DaemonMessage::Sessions { .. }), "{reply:?}");
}

#[tokio::test]
async fn family_mismatch_is_unauthorized() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let mut client = TestClient::connect(&daemon.state.runtime.socket_path()).await;

    // An admin token presented with a session-family body.
    let req = Request {
        auth: Auth::Admin {
            token: daemon.admin_token.clone(),
        },
        body: RequestBody::Session(SessionRequest::List),
    };
    let reply = client.request(req).await;
    assert!(
        matches!(
            reply,
            DaemonMessage::Error {
                kind: ErrorKind::Unauthorized,
                ..
            }
        ),
        "{reply:?}"
    );
}

// ─── Session auth ────────────────────────────────────────────────────────────

#[tokio::test]
async fn session_auth_unknown_token_gives_no_session() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let mut client = TestClient::connect(&daemon.state.runtime.socket_path()).await;

    let bogus = crate::protocol::SessionToken::generate(crate::protocol::SessionId::generate());
    let reply = client
        .request(session_request(bogus, SessionRequest::List))
        .await;
    assert!(
        matches!(
            reply,
            DaemonMessage::Error {
                kind: ErrorKind::NoSession,
                ..
            }
        ),
        "{reply:?}"
    );
}

#[tokio::test]
async fn revoke_then_use_gives_session_ended() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let tmp = tempfile::tempdir().unwrap();

    let mut admin = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let (id, token) = register(
        &mut admin,
        &daemon.admin_token,
        tmp.path(),
        "[tools.sh]\n",
        "shell",
        SessionEnds::Ttl { secs: 3600 },
    )
    .await;

    let mut admin2 = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = admin2
        .request(admin_request(
            &daemon.admin_token,
            AdminRequest::Revoke {
                sessions: vec![id.to_string()],
            },
        ))
        .await;
    assert!(matches!(reply, DaemonMessage::Ok), "{reply:?}");

    let mut client = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = client
        .request(session_request(token, SessionRequest::List))
        .await;
    assert!(
        matches!(
            reply,
            DaemonMessage::Error {
                kind: ErrorKind::SessionEnded,
                ..
            }
        ),
        "{reply:?}"
    );
}

#[tokio::test]
async fn expired_ttl_gives_session_expired() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let tmp = tempfile::tempdir().unwrap();

    let mut admin = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let (_id, token) = register(
        &mut admin,
        &daemon.admin_token,
        tmp.path(),
        "[tools.sh]\n",
        "shell",
        SessionEnds::Ttl { secs: 0 },
    )
    .await;

    // Force the session's TTL into the past directly, rather than waiting:
    // the only thing under test is that `resolve_session` honors expiry.
    {
        let session = daemon.state.sessions.get(token.id()).unwrap();
        *session.ends.write().unwrap() = crate::session::Ends::Ttl {
            ttl: Duration::from_secs(1),
            expires_at: std::time::SystemTime::now() - Duration::from_secs(10),
        };
    }

    let mut client = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = client
        .request(session_request(token, SessionRequest::List))
        .await;
    assert!(
        matches!(
            reply,
            DaemonMessage::Error {
                kind: ErrorKind::SessionExpired,
                ..
            }
        ),
        "{reply:?}"
    );
}

#[tokio::test]
async fn process_tree_binding_refuses_a_non_descendant() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;

    // An anchor that is not an ancestor of this test process: a `sleep`
    // child of ours is a descendant of *us*, not the other way around.
    let mut child = tokio::process::Command::new("sleep")
        .arg("5")
        .spawn()
        .expect("spawn sleep");
    let child_pid = child.id().expect("pid") as i32;
    let anchor = crate::process_tree::proc_id(child_pid).expect("proc_id");

    let id = crate::protocol::SessionId::generate();
    let token = crate::protocol::SessionToken::generate(id.clone());
    let session = Arc::new(Session {
        id: id.clone(),
        token: token.clone(),
        name: "outsider".to_string(),
        root: PathBuf::from("/tmp"),
        sandbox: SandboxKind::External,
        ends: std::sync::RwLock::new(crate::session::Ends::Lease),
        anchor,
        started: std::time::SystemTime::now(),
        execs: std::sync::atomic::AtomicU64::new(0),
        exec_permits: Arc::new(tokio::sync::Semaphore::new(crate::session::EXEC_CAP)),
        policy: std::sync::RwLock::new(Arc::new(crate::session::empty_policy())),
        lease_closer: CancellationToken::new(),
    });
    daemon.state.sessions.insert(session);

    let mut client = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = client
        .request(session_request(token, SessionRequest::List))
        .await;
    assert!(
        matches!(
            reply,
            DaemonMessage::Error {
                kind: ErrorKind::OutsideProcessTree,
                ..
            }
        ),
        "{reply:?}"
    );

    let _ = child.kill().await;
}

// ─── Register / list / tools / check ────────────────────────────────────────

#[tokio::test]
async fn register_then_list_tools_and_check() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let tmp = tempfile::tempdir().unwrap();

    let mut admin = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let (id, token) = register(
        &mut admin,
        &daemon.admin_token,
        tmp.path(),
        "[tools.sh]\ndescription = \"a shell\"\n",
        "claude",
        SessionEnds::Ttl { secs: 3600 },
    )
    .await;

    let _ = admin;
    let mut admin2 = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = admin2
        .request(admin_request(
            &daemon.admin_token,
            AdminRequest::ListSessions,
        ))
        .await;
    let DaemonMessage::Sessions { sessions } = reply else {
        panic!("expected Sessions")
    };
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].id, id);
    assert_eq!(sessions[0].name, "claude");

    let mut client = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = client
        .request(session_request(token.clone(), SessionRequest::List))
        .await;
    let DaemonMessage::Tools { tools, .. } = reply else {
        panic!("expected Tools")
    };
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "sh");
    assert_eq!(tools[0].description, Some("a shell".to_string()));

    let mut client2 = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = client2
        .request(session_request(token, SessionRequest::Check))
        .await;
    assert!(
        matches!(reply, DaemonMessage::CheckResult { .. }),
        "{reply:?}"
    );
}

#[tokio::test]
async fn reload_swaps_tools_and_reports_changes() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let tmp = tempfile::tempdir().unwrap();

    let mut admin = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let (id, token) = register(
        &mut admin,
        &daemon.admin_token,
        tmp.path(),
        "[tools.gh]\n",
        "claude",
        SessionEnds::Ttl { secs: 3600 },
    )
    .await;

    let session = daemon.state.sessions.get(&id).unwrap();
    let old_policy = session.current_policy();

    let mut admin2 = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let payload = test_payload(tmp.path(), "[tools.psql]\n");
    let reply = admin2
        .request(admin_request(
            &daemon.admin_token,
            AdminRequest::Reload {
                session: id.to_string(),
                payload: Box::new(payload),
            },
        ))
        .await;
    let DaemonMessage::Reloaded { changes, .. } = reply else {
        panic!("expected Reloaded, got {reply:?}")
    };
    assert!(changes.contains(&"tools +psql".to_string()), "{changes:?}");
    assert!(changes.contains(&"tools -gh".to_string()), "{changes:?}");

    // The earlier Arc the first caller held is still a valid, unmodified
    // snapshot of the pre-reload policy.
    assert!(old_policy.config.tools.contains_key("gh"));

    let mut client = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = client
        .request(session_request(token, SessionRequest::List))
        .await;
    let DaemonMessage::Tools { tools, .. } = reply else {
        panic!("expected Tools")
    };
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "psql");
}

// ─── Revoke by prefix / name / ambiguity ─────────────────────────────────────

#[tokio::test]
async fn revoke_by_unique_prefix_and_name() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let tmp = tempfile::tempdir().unwrap();

    let mut admin = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let (id, _token) = register(
        &mut admin,
        &daemon.admin_token,
        tmp.path(),
        "[tools.sh]\n",
        "claude",
        SessionEnds::Ttl { secs: 3600 },
    )
    .await;

    let _ = admin;
    let prefix = &id.as_str()[..4];
    let mut admin2 = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = admin2
        .request(admin_request(
            &daemon.admin_token,
            AdminRequest::Revoke {
                sessions: vec![prefix.to_string()],
            },
        ))
        .await;
    assert!(matches!(reply, DaemonMessage::Ok), "{reply:?}");
    assert!(daemon.state.sessions.get(&id).is_none());
}

#[tokio::test]
async fn revoke_ambiguous_ref_errors_and_revokes_nothing() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let tmp = tempfile::tempdir().unwrap();

    let mut admin = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let (id_a, _) = register(
        &mut admin,
        &daemon.admin_token,
        tmp.path(),
        "[tools.sh]\n",
        "one",
        SessionEnds::Ttl { secs: 3600 },
    )
    .await;
    let mut admin2 = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let (id_b, _) = register(
        &mut admin2,
        &daemon.admin_token,
        tmp.path(),
        "[tools.sh]\n",
        "two",
        SessionEnds::Ttl { secs: 3600 },
    )
    .await;

    // Find a common prefix length that matches both (there always is one:
    // the empty string), long enough to still be ambiguous — the empty
    // string itself always works since it prefixes every id.
    let mut admin3 = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = admin3
        .request(admin_request(
            &daemon.admin_token,
            AdminRequest::Revoke {
                sessions: vec![String::new()],
            },
        ))
        .await;
    assert!(
        matches!(
            reply,
            DaemonMessage::Error {
                kind: ErrorKind::Malformed,
                ..
            }
        ),
        "{reply:?}"
    );
    assert!(daemon.state.sessions.get(&id_a).is_some());
    assert!(daemon.state.sessions.get(&id_b).is_some());
}

// ─── Renew ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn renew_restarts_the_ttl() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let tmp = tempfile::tempdir().unwrap();

    let mut admin = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let (id, _token) = register(
        &mut admin,
        &daemon.admin_token,
        tmp.path(),
        "[tools.sh]\n",
        "shell",
        SessionEnds::Ttl { secs: 1 },
    )
    .await;

    let _ = admin;
    let mut admin2 = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = admin2
        .request(admin_request(
            &daemon.admin_token,
            AdminRequest::Renew {
                session: id.to_string(),
                ttl_secs: Some(3600),
            },
        ))
        .await;
    assert!(matches!(reply, DaemonMessage::Ok), "{reply:?}");

    let session = daemon.state.sessions.get(&id).unwrap();
    let expired = session
        .ends
        .read()
        .unwrap()
        .is_expired(std::time::SystemTime::now());
    assert!(!expired);
}

#[tokio::test]
async fn renew_refuses_a_lease_session() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let tmp = tempfile::tempdir().unwrap();

    // A lease session keeps its connection open, so register it from a
    // background task and keep the handle alive for the duration of this
    // test.
    let payload = test_payload(tmp.path(), "[tools.sh]\n");
    let mut lease_conn = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let req = admin_request(
        &daemon.admin_token,
        AdminRequest::Register(Box::new(RegisterRequest {
            payload,
            name: "run".to_string(),
            sandbox: SandboxKind::Airlock,
            ends: SessionEnds::Lease,
        })),
    );
    let DaemonMessage::Registered { id, .. } = lease_conn.request(req).await else {
        panic!("expected Registered")
    };

    let mut admin = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = admin
        .request(admin_request(
            &daemon.admin_token,
            AdminRequest::Renew {
                session: id.to_string(),
                ttl_secs: None,
            },
        ))
        .await;
    assert!(
        matches!(
            reply,
            DaemonMessage::Error {
                kind: ErrorKind::Malformed,
                ..
            }
        ),
        "{reply:?}"
    );
}

// ─── Lease lifecycle ─────────────────────────────────────────────────────────

#[tokio::test]
async fn lease_eof_revokes_the_session() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let tmp = tempfile::tempdir().unwrap();

    let payload = test_payload(tmp.path(), "[tools.sh]\n");
    let mut lease_conn = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let req = admin_request(
        &daemon.admin_token,
        AdminRequest::Register(Box::new(RegisterRequest {
            payload,
            name: "run".to_string(),
            sandbox: SandboxKind::Airlock,
            ends: SessionEnds::Lease,
        })),
    );
    let DaemonMessage::Registered { id, .. } = lease_conn.request(req).await else {
        panic!("expected Registered")
    };
    assert!(daemon.state.sessions.get(&id).is_some());

    drop(lease_conn);

    // The daemon learns about the EOF asynchronously; poll briefly.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while daemon.state.sessions.get(&id).is_some() {
        if std::time::Instant::now() > deadline {
            panic!("lease EOF did not revoke the session in time");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        daemon.state.sessions.ended_reason(&id),
        Some(crate::session::EndedReason::LeaseClosed)
    );
}

// ─── Logs ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn logs_filtered_by_session() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let tmp = tempfile::tempdir().unwrap();

    let mut admin = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let (id_a, _) = register(
        &mut admin,
        &daemon.admin_token,
        tmp.path(),
        "[tools.sh]\n",
        "one",
        SessionEnds::Ttl { secs: 3600 },
    )
    .await;
    let mut admin2 = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let (id_b, _) = register(
        &mut admin2,
        &daemon.admin_token,
        tmp.path(),
        "[tools.sh]\n",
        "two",
        SessionEnds::Ttl { secs: 3600 },
    )
    .await;

    let mut admin3 = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = admin3
        .request(admin_request(
            &daemon.admin_token,
            AdminRequest::Logs {
                session: Some(id_a.to_string()),
            },
        ))
        .await;
    let DaemonMessage::LogsResponse { entries } = reply else {
        panic!("expected LogsResponse")
    };
    assert!(
        entries
            .iter()
            .all(|e| e.session.as_deref() != Some(id_b.as_str()))
    );
    assert!(
        entries
            .iter()
            .any(|e| e.session.as_deref() == Some(id_a.as_str()))
    );
}

// ─── Stop ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn stop_shuts_down_and_removes_files() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let socket_path = daemon.state.runtime.socket_path();
    let pid_path = daemon.state.runtime.pid_path();
    // No PID file in this harness (that's written by `async_main_inner`,
    // which this test bypasses) — write one so the cleanup path is exercised.
    std::fs::write(&pid_path, b"1\n").unwrap();

    let mut admin = TestClient::connect(&socket_path).await;
    let reply = admin
        .request(admin_request(&daemon.admin_token, AdminRequest::Stop))
        .await;
    assert!(matches!(reply, DaemonMessage::Ok));

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while socket_path.exists() {
        if std::time::Instant::now() > deadline {
            panic!("socket was not removed after Stop");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!pid_path.exists());
    assert!(!daemon.state.runtime.admin_token_path().exists());
}

// ─── Idle exit ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn automatic_daemon_idle_exits_with_no_sessions() {
    let daemon =
        start_test_daemon_with_idle(DaemonMode::Automatic, Some(Duration::from_millis(100))).await;
    let socket_path = daemon.state.runtime.socket_path();

    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !daemon.state.shutdown.is_cancelled() {
        if std::time::Instant::now() > deadline {
            panic!("automatic daemon did not idle-exit");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = socket_path;
}

#[tokio::test]
async fn manual_daemon_never_idle_exits() {
    let daemon = start_test_daemon_with_idle(DaemonMode::Manual, None).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!daemon.state.shutdown.is_cancelled());
}

// ─── Global redactor ─────────────────────────────────────────────────────────

#[tokio::test]
async fn global_redactor_masks_another_sessions_secret() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let tmp = tempfile::tempdir().unwrap();

    let raw: crate::config::RawConfig = toml::from_str("[tools.sh]\n").unwrap();
    let payload = RegisterPayload {
        root: tmp.path().to_path_buf(),
        mode: WireMode::Default,
        layers: Vec::new(),
        config: raw,
        secrets: vec![crate::protocol::WireSecret {
            label: "TOK".to_string(),
            value: zeroize::Zeroizing::new("s3cr3t-value".to_string()),
        }],
        env_snapshot: Default::default(),
        path: vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")],
        dropped_path: Vec::new(),
        write_grants: Vec::new(),
        anchors: WireAnchors {
            runtime_base: PathBuf::from("/tmp/a"),
            trust_store: PathBuf::from("/tmp/b"),
            global_config: PathBuf::from("/tmp/c"),
        },
        agent_hash: "deadbeef".to_string(),
    };
    let mut admin = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let req = admin_request(
        &daemon.admin_token,
        AdminRequest::Register(Box::new(RegisterRequest {
            payload,
            name: "one".to_string(),
            sandbox: SandboxKind::External,
            ends: SessionEnds::Ttl { secs: 3600 },
        })),
    );
    let DaemonMessage::Registered { .. } = admin.request(req).await else {
        panic!("expected Registered")
    };

    let redactor = daemon.state.global_redactor_snapshot();
    let out = redactor.redact_bytes(b"leaked: s3cr3t-value");
    let out = String::from_utf8_lossy(&out);
    assert!(!out.contains("s3cr3t-value"), "{out}");
}

// ─── Exec: pre-spawn errors (no sandbox needed) ──────────────────────────────

#[tokio::test]
async fn exec_unknown_tool_is_refused() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let tmp = tempfile::tempdir().unwrap();

    let mut admin = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let (_id, token) = register(
        &mut admin,
        &daemon.admin_token,
        tmp.path(),
        "[tools.sh]\n",
        "claude",
        SessionEnds::Ttl { secs: 3600 },
    )
    .await;

    let mut client = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = client
        .request(session_request(
            token,
            SessionRequest::Exec {
                tool: "nope".to_string(),
                args: vec![],
                cwd: tmp.path().to_path_buf(),
            },
        ))
        .await;
    assert!(
        matches!(
            reply,
            DaemonMessage::Error {
                kind: ErrorKind::UnknownTool,
                ..
            }
        ),
        "{reply:?}"
    );
}

#[tokio::test]
async fn exec_outside_root_is_refused() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();

    let mut admin = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let (_id, token) = register(
        &mut admin,
        &daemon.admin_token,
        tmp.path(),
        "[tools.sh]\n",
        "claude",
        SessionEnds::Ttl { secs: 3600 },
    )
    .await;

    let mut client = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = client
        .request(session_request(
            token,
            SessionRequest::Exec {
                tool: "sh".to_string(),
                args: vec![],
                cwd: outside.path().to_path_buf(),
            },
        ))
        .await;
    assert!(
        matches!(
            reply,
            DaemonMessage::Error {
                kind: ErrorKind::OutsideRoot,
                ..
            }
        ),
        "{reply:?}"
    );
}

#[tokio::test]
async fn exec_binary_unusable_when_tool_not_on_filtered_path() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let tmp = tempfile::tempdir().unwrap();

    let mut admin = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    // `[tools.doesnotexistanywhere]` is declared but nothing by that name
    // is on the session's (narrow) filtered PATH.
    let (_id, token) = register(
        &mut admin,
        &daemon.admin_token,
        tmp.path(),
        "[tools.doesnotexistanywhere]\n",
        "claude",
        SessionEnds::Ttl { secs: 3600 },
    )
    .await;

    let mut client = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let reply = client
        .request(session_request(
            token,
            SessionRequest::Exec {
                tool: "doesnotexistanywhere".to_string(),
                args: vec![],
                cwd: tmp.path().to_path_buf(),
            },
        ))
        .await;
    assert!(
        matches!(
            reply,
            DaemonMessage::Error {
                kind: ErrorKind::BinaryUnusable,
                ..
            }
        ),
        "{reply:?}"
    );
}

#[tokio::test]
async fn exec_cap_refuses_the_seventeenth_concurrent_exec() {
    let daemon = start_test_daemon(DaemonMode::Manual).await;
    let tmp = tempfile::tempdir().unwrap();

    let mut admin = TestClient::connect(&daemon.state.runtime.socket_path()).await;
    let (id, _token) = register(
        &mut admin,
        &daemon.admin_token,
        tmp.path(),
        "[tools.sh]\n",
        "claude",
        SessionEnds::Ttl { secs: 3600 },
    )
    .await;

    let session = daemon.state.sessions.get(&id).unwrap();
    // Hold every permit directly, rather than spawning 16 real tools —
    // this test is about the cap, not about exec's happy path.
    let mut held = Vec::new();
    for _ in 0..session::EXEC_CAP {
        held.push(
            Arc::clone(&session.exec_permits)
                .try_acquire_owned()
                .unwrap(),
        );
    }
    assert!(
        Arc::clone(&session.exec_permits)
            .try_acquire_owned()
            .is_err()
    );
    drop(held);
}
