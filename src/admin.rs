//! Synchronous admin client: the launcher's and the CLI's connection to the
//! daemon's admin family (`Register`, `Reload`, session management, `Tools`,
//! `Logs`, `Stop`).
//!
//! Deliberately blocking `std` sockets, not tokio: every caller (the
//! launcher, `airlock session ...`, `airlock daemon ...`) runs before any
//! tokio runtime exists (`main()` is synchronous — see CLAUDE.md), and a
//! short-lived admin round trip has no need for async I/O.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;

use crate::protocol::{
    AdminRequest, AdminToken, Auth, ClientHello, DaemonMessage, DaemonMode, ErrorKind,
    MAX_ADMIN_LINE_BYTES, PROTOCOL_VERSION, Request, RequestBody, SessionInfo,
};

/// Errors talking to the daemon's admin family.
#[derive(Debug, Error)]
pub enum AdminError {
    /// The socket does not exist, or nothing answers on it.
    #[error("the daemon at unix://{} does not answer", path.display())]
    Unreachable { path: std::path::PathBuf },

    /// An I/O error after the connection was established.
    #[error("admin connection error: {0}")]
    Io(#[from] std::io::Error),

    /// The daemon's response did not parse, or the connection closed before
    /// a full response arrived.
    #[error("malformed response from the daemon")]
    Malformed,

    /// The daemon's reply did not match the request's shape (e.g. a `Tools`
    /// reply to a `Stop`).
    #[error("unexpected response from the daemon")]
    UnexpectedResponse,

    /// The daemon answered with an [`ErrorKind`].
    #[error("{message}")]
    Daemon {
        /// Why.
        kind: ErrorKind,
        /// The daemon's message.
        message: String,
    },
}

/// What the daemon said in its handshake [`DaemonMessage::Hello`].
#[derive(Debug, Clone)]
pub struct Hello {
    pub protocol: u32,
    pub version: String,
    pub pid: u32,
    pub mode: DaemonMode,
    pub sessions: u32,
}

/// An open, handshaken connection to the daemon's admin family.
///
/// Holds the socket and the handshake it received. [`Connection::hello`]
/// never errors on a protocol mismatch — the daemon still answers it — so
/// callers can decide what to do about version skew (see `launcher.rs`'s
/// "Upgrading Airlock" handling) before sending anything further.
#[derive(Debug)]
pub struct Connection {
    reader: BufReader<UnixStream>,
    socket_path: PathBuf,
    /// The daemon serves one request per connection, so a second request
    /// reconnects first.
    used: bool,
    pub hello: Hello,
}

impl Connection {
    /// Connects to `socket_path`, sends [`ClientHello`], and reads the
    /// daemon's [`DaemonMessage::Hello`].
    pub fn connect(socket_path: &Path) -> Result<Self, AdminError> {
        let stream = UnixStream::connect(socket_path).map_err(|_| AdminError::Unreachable {
            path: socket_path.to_path_buf(),
        })?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let mut reader = BufReader::new(stream);

        write_line(
            &mut reader,
            &ClientHello {
                protocol: PROTOCOL_VERSION,
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        )?;

        let hello = match read_message(&mut reader)? {
            DaemonMessage::Hello {
                protocol,
                version,
                pid,
                mode,
                sessions,
            } => Hello {
                protocol,
                version,
                pid,
                mode,
                sessions,
            },
            _ => return Err(AdminError::Malformed),
        };

        Ok(Connection {
            reader,
            socket_path: socket_path.to_path_buf(),
            used: false,
            hello,
        })
    }

    /// Sends an admin-family request authenticated with `token`, and returns
    /// the daemon's single reply line.
    ///
    /// Does not check [`Hello::protocol`] against [`PROTOCOL_VERSION`] — a
    /// caller that already decided to proceed despite a mismatch (there is
    /// no such caller today; `launcher::ensure_daemon` refuses or restarts
    /// first) can still use this directly.
    pub fn admin_request(
        &mut self,
        token: &AdminToken,
        body: AdminRequest,
    ) -> Result<DaemonMessage, AdminError> {
        if self.used {
            *self = Connection::connect(&self.socket_path)?;
        }
        self.used = true;
        write_line(
            &mut self.reader,
            &Request {
                auth: Auth::Admin {
                    token: token.clone(),
                },
                body: RequestBody::Admin(body),
            },
        )?;
        read_message(&mut self.reader)
    }

    /// Sends `body` and expects a bare `Ok` back.
    pub fn request_ok(&mut self, token: &AdminToken, body: AdminRequest) -> Result<(), AdminError> {
        match self.admin_request(token, body)? {
            DaemonMessage::Ok => Ok(()),
            _ => Err(AdminError::UnexpectedResponse),
        }
    }

    /// Every live session.
    pub fn list_sessions(&mut self, token: &AdminToken) -> Result<Vec<SessionInfo>, AdminError> {
        match self.admin_request(token, AdminRequest::ListSessions)? {
            DaemonMessage::Sessions { sessions } => Ok(sessions),
            _ => Err(AdminError::UnexpectedResponse),
        }
    }

    /// Unwraps the connection into its raw socket, for a `Register { ends:
    /// Lease }` session: the launcher keeps this connection open for the
    /// lifetime of the agent, and a watcher thread blocks on it for EOF
    /// (the daemon closing it means the session ended).
    ///
    /// Clears the request timeouts set by [`Connection::connect`]: the
    /// watcher's read must block for as long as the agent runs, and a
    /// timed-out read would end the lease.
    pub fn into_raw(self) -> Result<UnixStream, AdminError> {
        let stream = self.reader.into_inner();
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(None)?;
        Ok(stream)
    }
}

/// Reads one NDJSON line and parses it as a [`DaemonMessage`], mapping a
/// [`DaemonMessage::Error`] straight to [`AdminError::Daemon`] so callers
/// handle the happy path without re-checking for it every time.
fn read_message(reader: &mut BufReader<UnixStream>) -> Result<DaemonMessage, AdminError> {
    let mut line = String::new();
    // The daemon is the trusted peer here (we dialed it, and it is the one
    // that minted our admin token), so this is a sanity bound against a
    // runaway reply, not a defense against a hostile one.
    let read = reader.read_line(&mut line)?;
    if read == 0 {
        return Err(AdminError::Malformed);
    }
    if line.len() > MAX_ADMIN_LINE_BYTES {
        return Err(AdminError::Malformed);
    }
    let msg: DaemonMessage =
        serde_json::from_str(line.trim_end()).map_err(|_| AdminError::Malformed)?;
    match msg {
        DaemonMessage::Error { kind, message } => Err(AdminError::Daemon { kind, message }),
        other => Ok(other),
    }
}

fn write_line<T: serde::Serialize>(
    reader: &mut BufReader<UnixStream>,
    value: &T,
) -> Result<(), AdminError> {
    let bytes = crate::protocol::encode_line(value);
    reader.get_mut().write_all(&bytes)?;
    reader.get_mut().flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// A single-shot fake daemon: accepts one connection, sends `hello`,
    /// reads one request, sends `reply`, then closes.
    fn fake_daemon(
        socket_path: std::path::PathBuf,
        hello: DaemonMessage,
        reply: DaemonMessage,
    ) -> std::thread::JoinHandle<Request> {
        let listener = UnixListener::bind(&socket_path).unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let _client_hello: ClientHello = serde_json::from_str(line.trim_end()).unwrap();

            write_line(&mut reader, &hello).unwrap();

            let mut req_line = String::new();
            reader.read_line(&mut req_line).unwrap();
            let request: Request = serde_json::from_str(req_line.trim_end()).unwrap();

            write_line(&mut reader, &reply).unwrap();
            request
        })
    }

    fn ok_hello() -> DaemonMessage {
        DaemonMessage::Hello {
            protocol: PROTOCOL_VERSION,
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid: 4242,
            mode: DaemonMode::Automatic,
            sessions: 1,
        }
    }

    #[test]
    fn connect_reads_hello() {
        let dir = tempdir();
        let socket_path = dir.path().join("airlock.sock");
        let handle = fake_daemon(socket_path.clone(), ok_hello(), DaemonMessage::Ok);

        let conn = Connection::connect(&socket_path).unwrap();
        assert_eq!(conn.hello.protocol, PROTOCOL_VERSION);
        assert_eq!(conn.hello.pid, 4242);
        assert_eq!(conn.hello.sessions, 1);

        drop(conn);
        let _ = handle.join();
    }

    #[test]
    fn into_raw_clears_the_request_timeouts() {
        let dir = tempdir();
        let socket_path = dir.path().join("airlock.sock");
        let handle = fake_daemon(socket_path.clone(), ok_hello(), DaemonMessage::Ok);

        let conn = Connection::connect(&socket_path).unwrap();
        let stream = conn.into_raw().unwrap();
        assert_eq!(stream.read_timeout().unwrap(), None);
        assert_eq!(stream.write_timeout().unwrap(), None);

        drop(stream);
        let _ = handle.join();
    }

    #[test]
    fn connect_to_nothing_is_unreachable() {
        let dir = tempdir();
        let socket_path = dir.path().join("airlock.sock");
        let err = Connection::connect(&socket_path).unwrap_err();
        assert!(matches!(err, AdminError::Unreachable { .. }));
    }

    #[test]
    fn admin_request_round_trips() {
        let dir = tempdir();
        let socket_path = dir.path().join("airlock.sock");
        let handle = fake_daemon(
            socket_path.clone(),
            ok_hello(),
            DaemonMessage::Sessions { sessions: vec![] },
        );

        let mut conn = Connection::connect(&socket_path).unwrap();
        let token = AdminToken::parse(&"a".repeat(64)).unwrap();
        let reply = conn
            .admin_request(&token, AdminRequest::ListSessions)
            .unwrap();
        assert!(matches!(reply, DaemonMessage::Sessions { sessions } if sessions.is_empty()));

        let sent = handle.join().unwrap();
        assert!(matches!(sent.auth, Auth::Admin { .. }));
        assert!(matches!(
            sent.body,
            RequestBody::Admin(AdminRequest::ListSessions)
        ));
    }

    #[test]
    fn typed_requests_refuse_a_reply_of_the_wrong_shape() {
        let dir = tempdir();
        let socket_path = dir.path().join("airlock.sock");
        let token = AdminToken::parse(&"a".repeat(64)).unwrap();

        let handle = fake_daemon(socket_path.clone(), ok_hello(), DaemonMessage::Ok);
        let mut conn = Connection::connect(&socket_path).unwrap();
        let err = conn.list_sessions(&token).unwrap_err();
        assert!(matches!(err, AdminError::UnexpectedResponse), "{err:?}");
        let _ = handle.join();

        let socket_path = dir.path().join("airlock2.sock");
        let handle = fake_daemon(
            socket_path.clone(),
            ok_hello(),
            DaemonMessage::Sessions { sessions: vec![] },
        );
        let mut conn = Connection::connect(&socket_path).unwrap();
        let err = conn.request_ok(&token, AdminRequest::Stop).unwrap_err();
        assert!(matches!(err, AdminError::UnexpectedResponse), "{err:?}");
        let _ = handle.join();
    }

    #[test]
    fn admin_request_surfaces_daemon_error() {
        let dir = tempdir();
        let socket_path = dir.path().join("airlock.sock");
        let _handle = fake_daemon(
            socket_path.clone(),
            ok_hello(),
            DaemonMessage::Error {
                kind: ErrorKind::Busy,
                message: "too many sessions".to_string(),
            },
        );

        let mut conn = Connection::connect(&socket_path).unwrap();
        let token = AdminToken::parse(&"a".repeat(64)).unwrap();
        let err = conn
            .admin_request(&token, AdminRequest::ListSessions)
            .unwrap_err();
        assert!(matches!(
            err,
            AdminError::Daemon {
                kind: ErrorKind::Busy,
                ..
            }
        ));
    }
}
