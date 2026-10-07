//! Daemon startup, lifecycle management, and connection handling.
//!
//! One daemon serves every project through sessions
//! (docs/airlock-v2-design.md, "Sessions"). This module implements:
//! - Synchronous startup (runtime dir, admin token, socket binding)
//! - Stale PID/socket detection and cleanup
//! - Double-fork daemonization with readiness pipe
//! - Foreground mode (no forking)
//! - The async accept loop, handshake, auth and request dispatch
//! - Ring buffer logging (1000 entries, each tagged with its session if any)
//! - Active child process registry (across every session's tools)
//! - SIGTERM / admin `Stop` / idle-exit graceful shutdown
//! - PID file and admin-token management
//!
//! # Fork safety
//!
//! The entire synchronous startup sequence completes before any fork or tokio
//! runtime creation. This is critical because tokio's multi-threaded runtime
//! spawns background threads; forking after the runtime starts leaves those
//! threads in an undefined state in the child.

use std::collections::{HashSet, VecDeque};
use std::os::unix::io::FromRawFd;
use std::os::unix::net as unix_net;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::exec;
use crate::policy;
use crate::process_tree;
pub use crate::protocol::DaemonMode;
use crate::protocol::{
    self, AdminRequest, Auth, ClientHello, DaemonMessage, ErrorKind, LogEntry, Request,
    RequestBody, SessionEnds, SessionRequest, SessionToken,
};
use crate::proxy::server::ProxySession;
use crate::redact::{self, Redactor, RedactorSwap, StreamRedactor};
use crate::runtime_dir::{RuntimeDir, RuntimeDirError};
use crate::session::{self, EndedReason, Ends, Session, SessionPolicy, Sessions};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of log entries retained in the ring buffer.
const RING_BUFFER_CAPACITY: usize = 1000;

/// Grace period for children to exit after receiving SIGTERM during shutdown.
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(5);

/// Grace period after SIGTERM before sending SIGKILL (timeout/disconnect).
const KILL_GRACE_PERIOD: Duration = Duration::from_secs(5);

/// Duration to wait for initial stdin before auto-closing the child's stdin pipe.
const STDIN_TIMEOUT: Duration = Duration::from_secs(2);

/// How often the serve loop sweeps expired TTL sessions.
const TTL_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// How often the serve loop checks the idle-exit grace period. Independent
/// of, and much shorter than, [`TTL_SWEEP_INTERVAL`]: idle-exit has no
/// request to piggyback an eager check on (nothing is happening at all),
/// and a sub-second `AIRLOCK_TEST_IDLE_EXIT_SECS` override needs this tick
/// to be short enough to observe it promptly. The check itself is cheap
/// (an `Instant` comparison) and a no-op for a `Manual`/`Service` daemon.
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Default idle-exit grace period for an automatic daemon with no sessions
/// and no open connections.
const DEFAULT_IDLE_EXIT: Duration = Duration::from_secs(300);

/// Debug-only escape hatch so integration tests do not have to wait five
/// real minutes for an idle exit.
#[cfg(debug_assertions)]
const IDLE_EXIT_OVERRIDE_VAR: &str = "AIRLOCK_TEST_IDLE_EXIT_SECS";

/// `airlock daemon start`'s exit code for [`DaemonError::StartInProgress`],
/// distinct from the generic 125 other startup failures use. `main.rs`'s
/// `cmd_daemon` emits it; `launcher::spawn_automatic_daemon` matches on it
/// to tell "another process already has this" apart from a real failure
/// and retry connecting instead of aborting.
pub const START_IN_PROGRESS_EXIT_CODE: u8 = 75;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors that can occur during daemon startup and lifecycle management.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// The runtime directory could not be located, created or validated.
    #[error("{0}")]
    RuntimeDir(#[from] RuntimeDirError),

    /// Failed to bind the Unix domain socket.
    #[error("failed to bind socket at {path}: {source}")]
    SocketBind {
        /// The path that could not be bound.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// Socket was created with permissions that are too open.
    #[error(
        "socket {path} has insecure permissions {actual:#o} (expected {expected:#o})\n\n\
         Hint: the filesystem may not support Unix permissions, or something \
         overrode the umask. Airlock refuses to start with a world-accessible socket."
    )]
    SocketPermissions {
        /// The socket path.
        path: PathBuf,
        /// The actual mode bits observed.
        actual: u32,
        /// The expected mode bits.
        expected: u32,
    },

    /// Failed to read the PID file.
    #[error("failed to read PID file {path}: {source}")]
    PidFileRead {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to write the PID file.
    #[error("failed to write PID file {path}: {source}")]
    PidFileWrite {
        /// The path that could not be written.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to write the admin token file.
    #[error("failed to write admin token {path}: {source}")]
    AdminTokenWrite {
        /// The path that could not be written.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// A daemon is already running with the given PID.
    #[error("daemon already running (PID: {pid})")]
    AlreadyRunning {
        /// The PID of the existing daemon.
        pid: u32,
    },

    /// Another process already holds the startup lock: it is either
    /// starting a daemon right now or already running one. The caller
    /// should not treat this as a hard failure — `ensure_daemon` retries
    /// connecting instead of propagating it.
    #[error("another process is already starting or running the daemon")]
    StartInProgress,

    /// Failed to open or lock `airlock.lock`.
    #[error("failed to acquire the startup lock {path}: {source}")]
    LockFailed {
        /// The lock file's path.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to clean up stale state files.
    #[error("failed to clean up stale state: {0}")]
    StaleCleanup(std::io::Error),

    /// A fork() call failed during daemonization.
    #[error("fork failed: {0}")]
    ForkFailed(std::io::Error),

    /// Failed to create the readiness pipe.
    #[error("failed to create readiness pipe: {0}")]
    PipeFailed(std::io::Error),

    /// Failed to create the tokio runtime.
    #[error("failed to create tokio runtime: {0}")]
    RuntimeCreation(std::io::Error),

    /// Failed to install the SIGTERM handler.
    #[error("failed to install SIGTERM handler: {0}")]
    SignalHandler(std::io::Error),
}

// ─── Ring buffer logging ──────────────────────────────────────────────────────

/// A thread-safe ring buffer for log entries with a fixed capacity.
///
/// When the buffer is at capacity and a new entry is added, the oldest entry
/// is evicted. Entries are retrievable in chronological order (oldest first).
///
/// When `echo` is `true`, entries are additionally written to stderr so a
/// foreground invocation surfaces the log in the operator's terminal.
/// Daemonized processes keep `echo = false` because stdio is redirected to
/// `/dev/null`.
#[derive(Clone)]
pub struct RingBuffer {
    inner: Arc<Mutex<VecDeque<LogEntry>>>,
    echo: bool,
}

impl Default for RingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl RingBuffer {
    /// Create a new empty ring buffer that only stores entries in memory.
    pub fn new() -> Self {
        Self::with_echo(false)
    }

    /// Create a new empty ring buffer that also mirrors each entry to stderr.
    pub fn new_echoing() -> Self {
        Self::with_echo(true)
    }

    fn with_echo(echo: bool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(RING_BUFFER_CAPACITY))),
            echo,
        }
    }

    /// Add a log entry with no session (daemon-level: startup, shutdown,
    /// accept errors, ...).
    pub fn log(&self, message: impl Into<String>) {
        self.push(None, message.into());
    }

    /// Add a log entry tagged with the session it concerns — every `exec`
    /// start/exit, registration, reload and end.
    pub fn log_session(&self, session: &str, message: impl Into<String>) {
        self.push(Some(session.to_string()), message.into());
    }

    fn push(&self, session: Option<String>, message: String) {
        let entry = LogEntry {
            timestamp: now_timestamp(),
            message,
            session,
        };
        if self.echo {
            eprintln!("[{}] {}", entry.timestamp, entry.message);
        }
        let mut buf = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if buf.len() >= RING_BUFFER_CAPACITY {
            buf.pop_front();
        }
        buf.push_back(entry);
    }

    /// Retrieve all entries in chronological order (oldest first).
    pub fn entries(&self) -> Vec<LogEntry> {
        let buf = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        buf.iter().cloned().collect()
    }
}

/// Produce a human-readable timestamp string for the current system time.
fn now_timestamp() -> String {
    use std::time::SystemTime;

    let now = SystemTime::now();
    let duration = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_date(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_date(days: u64) -> (u64, u64, u64) {
    // Civil calendar algorithm from Howard Hinnant.
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ─── Active child registry ──────────────────────────────────────────────────

/// A thread-safe set of PIDs for currently-running child processes, across
/// every session.
#[derive(Default)]
pub struct ChildRegistry {
    inner: Mutex<HashSet<u32>>,
}

impl ChildRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, pid: u32) {
        let mut set = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        set.insert(pid);
    }

    pub fn remove(&self, pid: u32) {
        let mut set = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        set.remove(&pid);
    }

    pub fn all(&self) -> Vec<u32> {
        let set = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        set.iter().copied().collect()
    }
}

// ─── Daemon entry point ─────────────────────────────────────────────────────

/// `airlock daemon start [--foreground] [--automatic] [--service]`.
///
/// Synchronous: locates and creates/validates the runtime dir, checks for
/// stale state, binds the socket (0700, verified), writes `admin.token`
/// (0600) — all before daemonizing (double fork + readiness pipe, unchanged
/// mechanism) or running in the foreground. Returns after readiness
/// (background) or at shutdown (foreground).
pub fn start(mode: DaemonMode, foreground: bool) -> Result<(), DaemonError> {
    let handles = synchronous_startup()?;
    let idle_exit = idle_exit_duration(mode);

    if foreground {
        run_foreground(handles, mode, idle_exit)
    } else {
        daemonize(handles, mode, idle_exit)
    }
}

/// `Some` idle-exit grace period for an [`DaemonMode::Automatic`] daemon;
/// `None` for a `Manual` or `Service` daemon, which never idle-exits.
///
/// The debug-only override is read here, in `start`, and nowhere else on the
/// request path.
#[allow(
    clippy::disallowed_methods,
    reason = "debug-only test override, read once in `start` before the runtime (and any session) exists"
)]
fn idle_exit_duration(mode: DaemonMode) -> Option<Duration> {
    if mode != DaemonMode::Automatic {
        return None;
    }
    #[cfg(debug_assertions)]
    if let Ok(v) = std::env::var(IDLE_EXIT_OVERRIDE_VAR)
        && let Ok(secs) = v.parse::<u64>()
    {
        return Some(Duration::from_secs(secs));
    }
    Some(DEFAULT_IDLE_EXIT)
}

// ─── Synchronous startup sequence ───────────────────────────────────────────

/// The resources [`synchronous_startup`] hands to [`daemonize`] or
/// [`run_foreground`], bundled into one value so the fork/async entry
/// points downstream of it don't each carry four separate parameters.
pub(crate) struct StartupHandles {
    runtime: RuntimeDir,
    listener: unix_net::UnixListener,
    admin_token: protocol::AdminToken,
    /// The startup `flock` ([`acquire_startup_lock`]); see
    /// [`DaemonState::_lock`] for why it is held for the daemon's life.
    lock: std::fs::File,
}

/// Locate, create and validate the runtime dir; take the startup lock; clean
/// up stale state; bind and verify the socket; write a fresh admin token.
/// Completes entirely without creating a tokio runtime or spawning any
/// thread.
fn synchronous_startup() -> Result<StartupHandles, DaemonError> {
    harden_process();

    let runtime = RuntimeDir::locate()?;
    runtime.create_and_validate()?;

    // Held from here through the rest of this process's life (the fd
    // survives both forks in `daemonize`, inherited like `listener` and
    // `admin_token`): no other `daemon start` can run its own stale-state
    // check, bind or admin-token write while this one is in flight, so a
    // second launcher starting the daemon at the same moment can never see
    // this one's socket/PID file mid-write and "clean up" it as stale.
    let lock = acquire_startup_lock(&runtime.lock_path())?;

    check_and_cleanup_stale_state(&runtime)?;

    let listener =
        bind_owner_only(&runtime.socket_path()).map_err(|e| DaemonError::SocketBind {
            path: runtime.socket_path(),
            source: e,
        })?;
    verify_socket_permissions(&runtime.socket_path())?;

    let admin_token = protocol::AdminToken::generate();
    write_admin_token(&runtime.admin_token_path(), &admin_token)?;

    Ok(StartupHandles {
        runtime,
        listener,
        admin_token,
        lock,
    })
}

/// Take a non-blocking exclusive `flock` on `path` (created with mode
/// `0600` if it doesn't exist). A busy lock means another process is
/// already starting or running the daemon — [`DaemonError::StartInProgress`],
/// not a hard failure: `ensure_daemon` in `launcher.rs` treats it as "someone
/// else has this" and retries connecting instead of propagating it.
fn acquire_startup_lock(path: &Path) -> Result<std::fs::File, DaemonError> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|source| DaemonError::LockFailed {
            path: path.to_path_buf(),
            source,
        })?;

    // SAFETY: flock(2) on a valid, owned fd; no memory is touched besides
    // the syscall's own arguments.
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(DaemonError::StartInProgress);
        }
        return Err(DaemonError::LockFailed {
            path: path.to_path_buf(),
            source: err,
        });
    }
    Ok(file)
}

/// Check for a stale PID/socket left by a crashed daemon.
///
/// - A PID file with a live process means a daemon is already running.
/// - A PID file with a dead process is stale: remove it and the socket.
/// - No PID file but a socket present is also treated as stale leftovers —
///   every v2 daemon writes a PID file before it starts serving, so a
///   socket without one cannot be a live daemon.
fn check_and_cleanup_stale_state(runtime: &RuntimeDir) -> Result<(), DaemonError> {
    let pid_path = runtime.pid_path();
    let socket_path = runtime.socket_path();

    if pid_path.exists() {
        let contents =
            std::fs::read_to_string(&pid_path).map_err(|e| DaemonError::PidFileRead {
                path: pid_path.clone(),
                source: e,
            })?;

        let pid: u32 = contents.trim().parse().map_err(|_| {
            DaemonError::StaleCleanup(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid PID in file: {:?}", contents.trim()),
            ))
        })?;

        let alive = rustix::process::Pid::from_raw(pid as i32)
            .is_some_and(|p| rustix::process::test_kill_process(p).is_ok());
        if alive {
            return Err(DaemonError::AlreadyRunning { pid });
        }

        remove_runtime_files([
            pid_path.as_path(),
            socket_path.as_path(),
            runtime.admin_token_path().as_path(),
        ]);
    } else if socket_path.exists() {
        remove_runtime_files([socket_path.as_path(), runtime.admin_token_path().as_path()]);
    }

    Ok(())
}

/// Remove the daemon's runtime files. Returns the ones that exist but could
/// not be removed; a file that is already gone is not an error.
pub fn remove_runtime_files<'a>(
    files: impl IntoIterator<Item = &'a Path>,
) -> Vec<(&'a Path, std::io::Error)> {
    files
        .into_iter()
        .filter_map(|path| match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Some((path, e)),
            _ => None,
        })
        .collect()
}

/// Serializes the umask swap in [`bind_owner_only`].
static UMASK_LOCK: Mutex<()> = Mutex::new(());

/// Bind a Unix socket at `path` with mode `0700`.
fn bind_owner_only(path: &Path) -> std::io::Result<unix_net::UnixListener> {
    let _guard = UMASK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let old_umask = rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);
    let result = unix_net::UnixListener::bind(path);
    rustix::process::umask(old_umask);
    result
}

/// Verify the socket file has owner-only permissions. Refuses to proceed if
/// other users have any access — the filesystem not honoring Unix
/// permissions, or an external umask override, are the only ways this can
/// happen, and the only safe response is to bail out.
fn verify_socket_permissions(socket_path: &Path) -> Result<(), DaemonError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(socket_path).map_err(|e| DaemonError::SocketBind {
        path: socket_path.to_path_buf(),
        source: e,
    })?;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(DaemonError::SocketPermissions {
            path: socket_path.to_path_buf(),
            actual: mode,
            expected: 0o700,
        });
    }

    Ok(())
}

// ─── Process hardening ──────────────────────────────────────────────────────

/// Apply best-effort process hardening to reduce the blast radius of secrets
/// living in the daemon's address space. All calls are best-effort: failures
/// are printed to stderr but do not abort startup.
///
/// Safe to call exactly once, early in startup, before any thread is spawned.
pub(crate) fn harden_process() {
    let rlim = rustix::process::Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    if let Err(err) = rustix::process::setrlimit(rustix::process::Resource::Core, rlim) {
        eprintln!("airlock: warning: setrlimit(RLIMIT_CORE, 0) failed: {err}");
    }

    #[cfg(target_os = "linux")]
    {
        if let Err(err) =
            rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        {
            eprintln!("airlock: warning: prctl(PR_SET_DUMPABLE, 0) failed: {err}");
        }

        if let Err(err) = rustix::process::set_ptracer(rustix::process::PTracer::None) {
            eprintln!("airlock: note: prctl(PR_SET_PTRACER, 0) returned: {err}");
        }
    }
}

// ─── Double-fork daemonization ──────────────────────────────────────────────

/// Daemonize using double-fork and then run the async runtime.
pub(crate) fn daemonize(
    handles: StartupHandles,
    mode: DaemonMode,
    idle_exit: Option<Duration>,
) -> Result<(), DaemonError> {
    let mut pipe_fds: [libc::c_int; 2] = [0; 2];
    let ret = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(DaemonError::PipeFailed(std::io::Error::last_os_error()));
    }
    let read_end = pipe_fds[0];
    let write_end = pipe_fds[1];

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(read_end);
            libc::close(write_end);
        }
        return Err(DaemonError::ForkFailed(std::io::Error::last_os_error()));
    }

    if pid > 0 {
        // ── Original parent ──
        unsafe { libc::close(write_end) };
        let read_end = unsafe { std::fs::File::from_raw_fd(read_end) };

        let status = match await_readiness(read_end) {
            Ok(()) => 0,
            Err(reason) => {
                eprintln!("error: daemon failed to start: {reason}");
                1
            }
        };

        unsafe { libc::_exit(status) };
    }

    // ── First child ──
    unsafe { libc::close(read_end) };

    if unsafe { libc::setsid() } < 0 {
        unsafe { libc::_exit(1) };
    }

    let pid2 = unsafe { libc::fork() };
    if pid2 < 0 {
        unsafe { libc::_exit(1) };
    }
    if pid2 > 0 {
        unsafe { libc::_exit(0) };
    }

    // ── Grandchild (final daemon process) ──
    redirect_stdio_to_devnull();
    unsafe {
        libc::chdir(c"/".as_ptr());
    }

    run_async_runtime(
        handles,
        mode,
        idle_exit,
        Some(ReadinessPipe(write_end)),
        false,
    )
}

/// Read the grandchild's verdict from the readiness pipe.
fn await_readiness(mut read_end: std::fs::File) -> Result<(), String> {
    use std::io::Read;

    let mut buf = Vec::new();
    if let Err(e) = read_end.read_to_end(&mut buf) {
        return Err(format!("readiness pipe read failed: {e}"));
    }
    match buf.split_first() {
        Some((&READY, _)) => Ok(()),
        Some((&FAILED, msg)) => Err(String::from_utf8_lossy(msg).into_owned()),
        _ => Err("daemon exited before signalling readiness".to_string()),
    }
}

const READY: u8 = 1;
const FAILED: u8 = 0;

/// Write end of the readiness pipe, owned by the grandchild.
pub(crate) struct ReadinessPipe(libc::c_int);

impl ReadinessPipe {
    fn ready(self) {
        self.write_all(&[READY]);
    }

    fn fail(self, err: &DaemonError) {
        let mut msg = vec![FAILED];
        msg.extend_from_slice(err.to_string().as_bytes());
        self.write_all(&msg);
    }

    fn write_all(self, bytes: &[u8]) {
        use std::io::Write;
        let mut file = unsafe { std::fs::File::from_raw_fd(self.0) };
        let _ = file.write_all(bytes);
    }
}

/// Redirect stdin, stdout, and stderr to /dev/null.
fn redirect_stdio_to_devnull() {
    unsafe {
        let devnull_fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull_fd >= 0 {
            libc::dup2(devnull_fd, 0);
            libc::dup2(devnull_fd, 1);
            libc::dup2(devnull_fd, 2);
            if devnull_fd > 2 {
                libc::close(devnull_fd);
            }
        }
    }
}

// ─── Foreground mode entry point ────────────────────────────────────────────

/// Run the daemon in the foreground (no forking).
pub(crate) fn run_foreground(
    handles: StartupHandles,
    mode: DaemonMode,
    idle_exit: Option<Duration>,
) -> Result<(), DaemonError> {
    run_async_runtime(handles, mode, idle_exit, None, true)
}

// ─── Admin-token file ────────────────────────────────────────────────────────

/// Write the admin token to `path` with mode 0600, created fresh.
fn write_admin_token(path: &Path, token: &protocol::AdminToken) -> Result<(), DaemonError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let write = || -> std::io::Result<()> {
        let _ = std::fs::remove_file(path);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(token.expose_secret().as_bytes())?;
        // `mode` on open is subject to the umask; fchmod via set_permissions
        // is not, so this is what actually fixes the mode.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.sync_all()
    };
    write().map_err(|source| DaemonError::AdminTokenWrite {
        path: path.to_path_buf(),
        source,
    })
}

// ─── Running daemon state ───────────────────────────────────────────────────

/// Everything the daemon holds across every session and every connection.
pub struct DaemonState {
    pub runtime: RuntimeDir,
    pub admin_token: protocol::AdminToken,
    pub mode: DaemonMode,
    pub sessions: Sessions,
    /// The last-pass redactor built from every live session's secrets
    /// (docs/airlock-v2-design.md, "Session isolation"). Output passes a
    /// session's own redactor first, then this one.
    pub global_redactor: RedactorSwap,
    pub ring_buffer: RingBuffer,
    pub child_registry: ChildRegistry,
    /// `None` for a `Manual` or `Service` daemon, which never idle-exits.
    idle_exit: Option<Duration>,
    /// Number of `Register` admin requests currently being handled — for a
    /// lease session, that spans the whole time its connection stays open.
    /// Idle-exit is based on the session count alone (merely connecting,
    /// e.g. a polling `airlock status`, must never reset the grace period),
    /// but a registration in flight is the one case where the session count
    /// can read 0 while the daemon is plainly not idle.
    registrations_in_flight: AtomicUsize,
    /// `Some(when it became idle)` while there are no sessions and no
    /// registration in flight; `None` while busy.
    idle_since: Mutex<Option<Instant>>,
    pub shutdown: CancellationToken,
    /// The startup `flock` ([`acquire_startup_lock`]), held for the
    /// daemon's entire life so a concurrent `daemon start` can never see
    /// this one's files mid-write. Never read; only its `Drop` (releasing
    /// the lock when this process exits) matters.
    _lock: std::fs::File,
}

impl DaemonState {
    fn new(
        runtime: RuntimeDir,
        admin_token: protocol::AdminToken,
        lock: std::fs::File,
        mode: DaemonMode,
        idle_exit: Option<Duration>,
        ring_buffer: RingBuffer,
    ) -> Arc<Self> {
        Arc::new(DaemonState {
            runtime,
            admin_token,
            mode,
            sessions: Sessions::new(),
            global_redactor: Arc::new(RwLock::new(Arc::new(
                Redactor::new(std::iter::empty()).expect("empty redactor always builds"),
            ))),
            ring_buffer,
            child_registry: ChildRegistry::new(),
            idle_exit,
            registrations_in_flight: AtomicUsize::new(0),
            idle_since: Mutex::new(Some(Instant::now())),
            shutdown: CancellationToken::new(),
            _lock: lock,
        })
    }

    /// Builds a session's policy from a `Register`/`Reload` payload, its
    /// refresh tasks wired to rebuild the global redactor after each
    /// successful refresh. Holds only a weak reference, so a session's
    /// refresh tasks never keep the daemon state alive.
    fn build_policy(
        self: &Arc<Self>,
        payload: &protocol::RegisterPayload,
        id: &protocol::SessionId,
        existing: Option<&SessionPolicy>,
    ) -> Result<SessionPolicy, String> {
        let weak = Arc::downgrade(self);
        let on_refresh: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            if let Some(state) = weak.upgrade() {
                state.rebuild_global_redactor();
            }
        });
        session::build_session_policy(
            payload,
            id,
            &self.runtime,
            &self.ring_buffer,
            on_refresh,
            existing,
        )
    }

    /// Snapshot of the current global redactor, taken once per exec.
    pub fn global_redactor_snapshot(&self) -> Arc<Redactor> {
        Arc::clone(
            &self
                .global_redactor
                .read()
                .unwrap_or_else(|e| e.into_inner()),
        )
    }

    /// Rebuild the global redactor from every live session's secrets: each
    /// one's current value, and its value before its latest refresh — the
    /// same generations the session's own redactor covers, so the backstop
    /// doesn't lose a just-rotated value either. Called after register,
    /// reload, revoke/end, and from a session's own refresh callback.
    pub fn rebuild_global_redactor(&self) {
        let mut builder = redact::RedactorBuilder::default();
        for live_session in self.sessions.list() {
            let policy = live_session.current_policy();
            let previous = policy
                .previous_secrets
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for (label, slot) in policy.secrets.iter() {
                builder.add(label, &slot.read().unwrap_or_else(|e| e.into_inner()).value);
                if let Some(old) = previous.get(label) {
                    builder.add(label, old);
                }
            }
        }
        if let Ok(new_redactor) = builder.build() {
            let mut g = self
                .global_redactor
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *g = Arc::new(new_redactor);
        }
    }

    /// End a session (if still live) and clean up everything that follows
    /// from that: wake its lease if it has one, stop its refresh tasks,
    /// remove its proxy CA file, and rebuild the global redactor.
    pub fn end_session(&self, id: &crate::protocol::SessionId, reason: EndedReason) {
        let Some(session) = self.sessions.end(id, reason) else {
            return;
        };
        self.release_session(&session);
        let policy = session.current_policy();
        tokio::spawn(async move {
            policy.shutdown_refresh().await;
        });
        self.rebuild_global_redactor();
        self.note_activity();
        self.ring_buffer
            .log_session(id.as_str(), format!("session ended ({reason:?})"));
    }

    /// Releases what an ended session holds outside its policy: wakes a
    /// lease holder blocked on it, and removes its CA file.
    fn release_session(&self, session: &Session) {
        session.lease_closer.cancel();
        self.remove_session_ca(&session.id);
    }

    /// Removes a session's proxy CA file. Unconditional, ignoring the
    /// common "never had one"/"already gone" case: a reload can drop the
    /// session's last proxy tool after writing the file, so the *current*
    /// policy no longer says whether one is on disk.
    fn remove_session_ca(&self, id: &protocol::SessionId) {
        let _ = std::fs::remove_file(self.runtime.ca_path(id.as_str()));
    }

    /// Recompute the idle marker. Called whenever the session count or the
    /// in-flight-registration count might have changed.
    fn note_activity(&self) {
        if self.idle_exit.is_none() {
            return;
        }
        let idle_now =
            self.sessions.count() == 0 && self.registrations_in_flight.load(Ordering::SeqCst) == 0;
        let mut marker = self.idle_since.lock().unwrap_or_else(|e| e.into_inner());
        if idle_now {
            if marker.is_none() {
                *marker = Some(Instant::now());
            }
        } else {
            *marker = None;
        }
    }

    /// Whether the idle grace period has elapsed. Always `false` for a
    /// `Manual`/`Service` daemon.
    fn should_idle_exit(&self) -> bool {
        let Some(grace) = self.idle_exit else {
            return false;
        };
        let marker = self.idle_since.lock().unwrap_or_else(|e| e.into_inner());
        marker.is_some_and(|since| since.elapsed() >= grace)
    }

    /// End every TTL session whose expiry has passed.
    fn sweep_expired_sessions(&self) {
        let now = SystemTime::now();
        for session in self.sessions.list() {
            if session.is_expired(now) {
                self.end_session(&session.id, EndedReason::Expired);
            }
        }
    }
}

/// A daemon that is bound and ready to accept.
struct Daemon {
    state: Arc<DaemonState>,
    listener: tokio::net::UnixListener,
}

impl Daemon {
    /// Accept connections, sweep expired sessions and check for idle exit,
    /// until `state.shutdown` fires, then shut down gracefully.
    async fn serve(self) {
        let Daemon { state, listener } = self;
        let mut ttl_sweep = tokio::time::interval(TTL_SWEEP_INTERVAL);
        ttl_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut idle_check = tokio::time::interval(IDLE_CHECK_INTERVAL);
        idle_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            let state = Arc::clone(&state);
                            tokio::spawn(async move {
                                handle_connection(stream, &state).await;
                            });
                        }
                        Err(e) => {
                            state.ring_buffer.log(format!("accept error: {e}"));
                        }
                    }
                }
                _ = ttl_sweep.tick() => {
                    state.sweep_expired_sessions();
                }
                _ = idle_check.tick() => {
                    if state.should_idle_exit() {
                        state.ring_buffer.log("idle with no sessions for the grace period; exiting");
                        state.shutdown.cancel();
                    }
                }
                () = state.shutdown.cancelled() => {
                    break;
                }
            }
        }

        graceful_shutdown(&state).await;
    }
}

/// Signal children, stop every session's refresh tasks, remove the daemon's
/// own files.
async fn graceful_shutdown(state: &Arc<DaemonState>) {
    let sessions = state.sessions.list();
    for session in &sessions {
        state.sessions.end(&session.id, EndedReason::Stopped);
        state.release_session(session);
    }
    for session in &sessions {
        session.current_policy().shutdown_refresh().await;
    }

    let pids = state.child_registry.all();
    if !pids.is_empty() {
        state.ring_buffer.log(format!(
            "sending SIGTERM to {} active child process group(s)",
            pids.len()
        ));
        for &pid in &pids {
            let _ = exec::kill_process_group(pid, libc::SIGTERM);
        }
        tokio::time::sleep(SHUTDOWN_GRACE_PERIOD).await;
        let remaining = state.child_registry.all();
        if !remaining.is_empty() {
            state.ring_buffer.log(format!(
                "sending SIGKILL to {} remaining child process group(s)",
                remaining.len()
            ));
            for &pid in &remaining {
                let _ = exec::kill_process_group(pid, libc::SIGKILL);
            }
        }
    }

    for (path, e) in remove_runtime_files(
        [
            state.runtime.pid_path(),
            state.runtime.socket_path(),
            state.runtime.admin_token_path(),
        ]
        .iter()
        .map(PathBuf::as_path),
    ) {
        state
            .ring_buffer
            .log(format!("failed to remove {}: {e}", path.display()));
    }

    state.ring_buffer.log("shutdown complete");
}

// ─── Async runtime entry point ──────────────────────────────────────────────

fn run_async_runtime(
    handles: StartupHandles,
    mode: DaemonMode,
    idle_exit: Option<Duration>,
    readiness: Option<ReadinessPipe>,
    foreground: bool,
) -> Result<(), DaemonError> {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            let err = DaemonError::RuntimeCreation(e);
            if let Some(pipe) = readiness {
                pipe.fail(&err);
            }
            return Err(err);
        }
    };

    rt.block_on(async_main(handles, mode, idle_exit, readiness, foreground))
}

async fn async_main(
    handles: StartupHandles,
    mode: DaemonMode,
    idle_exit: Option<Duration>,
    mut readiness: Option<ReadinessPipe>,
    foreground: bool,
) -> Result<(), DaemonError> {
    let result = async_main_inner(handles, mode, idle_exit, &mut readiness, foreground).await;
    if let (Err(err), Some(pipe)) = (&result, readiness.take()) {
        pipe.fail(err);
    }
    result
}

async fn async_main_inner(
    handles: StartupHandles,
    mode: DaemonMode,
    idle_exit: Option<Duration>,
    readiness: &mut Option<ReadinessPipe>,
    foreground: bool,
) -> Result<(), DaemonError> {
    let StartupHandles {
        runtime,
        listener,
        admin_token,
        lock,
    } = handles;

    let ring_buffer = if foreground {
        RingBuffer::new_echoing()
    } else {
        RingBuffer::new()
    };

    // Before the readiness signal, so a failure reaches `daemon start`, and
    // so a SIGTERM sent as soon as it returns gets a graceful shutdown.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(DaemonError::SignalHandler)?;

    listener
        .set_nonblocking(true)
        .map_err(|e| DaemonError::SocketBind {
            path: runtime.socket_path(),
            source: e,
        })?;
    let tokio_listener =
        tokio::net::UnixListener::from_std(listener).map_err(|e| DaemonError::SocketBind {
            path: runtime.socket_path(),
            source: e,
        })?;

    let pid = std::process::id();
    write_pid_file(&runtime.pid_path(), pid)?;

    ring_buffer.log(format!("daemon started (PID: {pid}, mode: {mode:?})"));
    ring_buffer.log(format!(
        "listening on {} — ready to accept connections",
        runtime.socket_path().display()
    ));

    let state = DaemonState::new(runtime, admin_token, lock, mode, idle_exit, ring_buffer);

    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            sigterm.recv().await;
            state.ring_buffer.log("SIGTERM received");
            state.shutdown.cancel();
        });
    }

    if let Some(pipe) = readiness.take() {
        pipe.ready();
    }

    Daemon {
        state,
        listener: tokio_listener,
    }
    .serve()
    .await;

    Ok(())
}

// ─── PID file management ────────────────────────────────────────────────────

fn write_pid_file(pid_path: &Path, pid: u32) -> Result<(), DaemonError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(pid_path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(DaemonError::AlreadyRunning { pid: 0 });
        }
        Err(e) => {
            return Err(DaemonError::PidFileWrite {
                path: pid_path.to_path_buf(),
                source: e,
            });
        }
    };

    file.write_all(format!("{pid}\n").as_bytes())
        .map_err(|e| DaemonError::PidFileWrite {
            path: pid_path.to_path_buf(),
            source: e,
        })?;

    Ok(())
}

// ─── Connection handling ────────────────────────────────────────────────────

type Reader =
    tokio_util::codec::FramedRead<tokio::net::unix::OwnedReadHalf, tokio_util::codec::LinesCodec>;
type Writer = tokio::net::unix::OwnedWriteHalf;

/// The one way a connection's replies leave the daemon. Every message goes
/// through [`write_ndjson_message`] with the daemon-wide redactor and, once
/// a session is in scope, that session's own — so no handler can send an
/// `Error` that skips redaction by passing the wrong arguments.
struct Responder {
    writer: Writer,
    global: Arc<Redactor>,
    session: Option<Arc<Redactor>>,
}

impl Responder {
    fn new(writer: Writer, global: Arc<Redactor>) -> Self {
        Responder {
            writer,
            global,
            session: None,
        }
    }

    async fn send(&mut self, msg: &DaemonMessage) -> std::io::Result<()> {
        write_ndjson_message(&mut self.writer, msg, &self.global, self.session.as_deref()).await
    }

    /// Sends an `Error`. A failed write is ignored: the caller is about to
    /// stop serving this connection either way.
    async fn error(&mut self, kind: ErrorKind, message: impl Into<String>) {
        let _ = self
            .send(&DaemonMessage::Error {
                kind,
                message: message.into(),
            })
            .await;
    }
}

/// Handle a single client connection: peer-uid check, handshake, one
/// request, dispatch.
async fn handle_connection(stream: tokio::net::UnixStream, state: &Arc<DaemonState>) {
    use tokio_stream::StreamExt;
    use tokio_util::codec::{FramedRead, LinesCodec};

    let (peer_pid, peer_uid) = match process_tree::peer_pid_uid(&stream) {
        Ok(v) => v,
        Err(_) => return,
    };
    let my_uid = unsafe { libc::geteuid() };
    if peer_uid != my_uid {
        state.ring_buffer.log(format!(
            "refused a connection from uid {peer_uid} (daemon runs as {my_uid})"
        ));
        return;
    }

    let (reader, writer) = stream.into_split();
    let mut framed: Reader = FramedRead::new(
        reader,
        LinesCodec::new_with_max_length(protocol::MAX_ADMIN_LINE_BYTES),
    );
    // No session is resolved yet on this path, so only the daemon-wide
    // redactor applies to any `Error` sent before one is.
    let mut responder = Responder::new(writer, state.global_redactor_snapshot());

    let hello_line = match framed.next().await {
        Some(Ok(line)) => line,
        _ => return,
    };
    let hello: ClientHello = match serde_json::from_str(hello_line.trim()) {
        Ok(h) => h,
        Err(_) => return,
    };

    let our_hello = DaemonMessage::Hello {
        protocol: protocol::PROTOCOL_VERSION,
        version: env!("CARGO_PKG_VERSION").to_string(),
        pid: std::process::id(),
        mode: state.mode,
        sessions: state.sessions.count() as u32,
    };
    if responder.send(&our_hello).await.is_err() {
        return;
    }

    if hello.protocol != protocol::PROTOCOL_VERSION {
        responder
            .error(
                ErrorKind::IncompatibleProtocol,
                format!(
                    "daemon speaks protocol {}, client speaks {}",
                    protocol::PROTOCOL_VERSION,
                    hello.protocol
                ),
            )
            .await;
        return;
    }

    let line = match framed.next().await {
        Some(Ok(line)) => line,
        _ => return,
    };
    let request: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            responder
                .error(ErrorKind::Malformed, format!("malformed request: {e}"))
                .await;
            return;
        }
    };

    let family_ok = matches!(
        (&request.auth, &request.body),
        (Auth::Admin { .. }, RequestBody::Admin(_))
            | (Auth::Session { .. }, RequestBody::Session(_))
    );
    if !family_ok {
        responder
            .error(
                ErrorKind::Unauthorized,
                "request family does not match the presented credential".to_string(),
            )
            .await;
        return;
    }
    if matches!(request.auth, Auth::Session { .. }) && line.len() > protocol::MAX_SESSION_LINE_BYTES
    {
        responder
            .error(
                ErrorKind::Malformed,
                "request exceeds the session family's maximum size".to_string(),
            )
            .await;
        return;
    }

    match request.auth {
        Auth::Admin { token } => {
            if !token.ct_eq(&state.admin_token) {
                responder
                    .error(ErrorKind::Unauthorized, "invalid admin token".to_string())
                    .await;
                return;
            }
            let RequestBody::Admin(req) = request.body else {
                unreachable!("family checked above")
            };
            handle_admin_request(req, state, peer_pid, framed, responder).await;
        }
        Auth::Session { token } => {
            let session = match resolve_session(state, &token, peer_pid) {
                Ok(s) => s,
                Err(kind) => {
                    responder.error(kind, session_error_message(kind)).await;
                    return;
                }
            };
            let RequestBody::Session(req) = request.body else {
                unreachable!("family checked above")
            };
            handle_session_request(req, state, session, framed, responder).await;
        }
    }
}

fn session_error_message(kind: ErrorKind) -> String {
    match kind {
        ErrorKind::NoSession | ErrorKind::SessionEnded => {
            "this session has ended (revoked by the user, or the daemon stopped). \
             Ask the user to start a new session."
                .to_string()
        }
        ErrorKind::SessionExpired => "this session expired. Ask the user to start a new one, \
             or to renew sessions before they expire with `airlock session renew`."
            .to_string(),
        ErrorKind::OutsideProcessTree => "this process was not started from the session's \
             agent or shell, so it cannot use the session."
            .to_string(),
        other => format!("{other:?}"),
    }
}

/// Resolve a presented session token to its live session, applying every
/// check: existence, token match, TTL expiry, process-tree binding.
fn resolve_session(
    state: &Arc<DaemonState>,
    token: &SessionToken,
    peer_pid: i32,
) -> Result<Arc<Session>, ErrorKind> {
    let id = token.id();
    let session = match state.sessions.get(id) {
        Some(s) => s,
        None => {
            return Err(state
                .sessions
                .ended_reason(id)
                .map(EndedReason::error_kind)
                .unwrap_or(ErrorKind::NoSession));
        }
    };
    if session.token != *token {
        return Err(ErrorKind::NoSession);
    }
    if session.is_expired(SystemTime::now()) {
        state.end_session(id, EndedReason::Expired);
        return Err(ErrorKind::SessionExpired);
    }
    if !process_tree::is_descendant_of(peer_pid, &session.anchor) {
        return Err(ErrorKind::OutsideProcessTree);
    }
    Ok(session)
}

// ─── Admin-family dispatch ───────────────────────────────────────────────────

async fn handle_admin_request(
    req: AdminRequest,
    state: &Arc<DaemonState>,
    peer_pid: i32,
    framed: Reader,
    mut responder: Responder,
) {
    match req {
        AdminRequest::Register(reg) => {
            handle_register(*reg, state, peer_pid, framed, responder).await
        }
        AdminRequest::Reload { session, payload } => {
            let reply = handle_reload(&session, *payload, state).await;
            let _ = responder.send(&reply).await;
        }
        AdminRequest::ListSessions => {
            let sessions = state.sessions.list().iter().map(|s| s.info()).collect();
            let _ = responder.send(&DaemonMessage::Sessions { sessions }).await;
        }
        AdminRequest::Revoke { sessions } => {
            let reply = handle_revoke(&sessions, state);
            let _ = responder.send(&reply).await;
        }
        AdminRequest::Renew { session, ttl_secs } => {
            let reply = handle_renew(&session, ttl_secs, state);
            let _ = responder.send(&reply).await;
        }
        AdminRequest::Tools { session } => {
            let reply = match state.sessions.resolve_ref(&session) {
                Ok(s) => {
                    let policy = s.current_policy();
                    DaemonMessage::Tools {
                        session: s.info(),
                        tools: session::tools_info(&policy.config),
                    }
                }
                Err(msg) => DaemonMessage::Error {
                    kind: ErrorKind::Malformed,
                    message: msg,
                },
            };
            let _ = responder.send(&reply).await;
        }
        AdminRequest::Logs { session } => {
            let entries = state.ring_buffer.entries();
            let entries = match session {
                Some(id) => entries
                    .into_iter()
                    .filter(|e| e.session.as_deref() == Some(id.as_str()))
                    .collect(),
                None => entries,
            };
            let _ = responder
                .send(&DaemonMessage::LogsResponse { entries })
                .await;
        }
        AdminRequest::Stop => {
            let _ = responder.send(&DaemonMessage::Ok).await;
            state
                .ring_buffer
                .log("stop requested over the admin connection");
            state.shutdown.cancel();
        }
    }
}

/// Marks a `Register` in flight for as long as it lives, so idle-exit
/// cannot fire in the gap between accepting the request and the new
/// session actually being inserted ([`DaemonState::registrations_in_flight`]).
/// Guard rather than manual decrements before each of `handle_register`'s
/// several early returns, so none of them can forget it.
struct RegistrationGuard<'a>(&'a DaemonState);

impl Drop for RegistrationGuard<'_> {
    fn drop(&mut self) {
        self.0
            .registrations_in_flight
            .fetch_sub(1, Ordering::SeqCst);
        self.0.note_activity();
    }
}

async fn handle_register(
    reg: protocol::RegisterRequest,
    state: &Arc<DaemonState>,
    peer_pid: i32,
    mut framed: Reader,
    mut responder: Responder,
) {
    use tokio_stream::StreamExt;

    // Idle-exit looks only at the session count, which can still be 0 here
    // — the new session isn't inserted until below, and for a lease this
    // call doesn't return until the lease ends. Held for this call's whole
    // duration so idle-exit can never fire in that gap.
    state.registrations_in_flight.fetch_add(1, Ordering::SeqCst);
    state.note_activity();
    let _registration_guard = RegistrationGuard(state);

    let protocol::RegisterRequest {
        payload,
        name,
        sandbox,
        ends,
    } = reg;

    let id = state.sessions.fresh_id();

    let anchor = match &ends {
        SessionEnds::Lease => process_tree::proc_id(peer_pid),
        SessionEnds::Ttl { .. } => {
            process_tree::parent_pid(peer_pid).and_then(process_tree::proc_id)
        }
    };
    let anchor = match anchor {
        Ok(a) => a,
        Err(e) => {
            responder
                .error(
                    ErrorKind::Internal,
                    format!("failed to resolve the session's anchor process: {e}"),
                )
                .await;
            return;
        }
    };

    let policy = match state.build_policy(&payload, &id, None) {
        Ok(p) => p,
        Err(e) => {
            responder.error(ErrorKind::Internal, e).await;
            return;
        }
    };

    let session_ends = match ends {
        SessionEnds::Lease => Ends::Lease,
        SessionEnds::Ttl { secs } => Ends::ttl_from_now(Duration::from_secs(secs)),
    };
    let is_lease = matches!(session_ends, Ends::Lease);

    let ca_path = if policy.proxy.is_some() {
        Some(state.runtime.ca_path(id.as_str()))
    } else {
        None
    };
    let session = Arc::new(Session::new(
        id.clone(),
        name,
        payload.root.clone(),
        sandbox,
        session_ends,
        anchor,
        policy,
    ));
    let token = session.token.clone();

    state.sessions.insert(Arc::clone(&session));
    state.rebuild_global_redactor();
    state.note_activity();
    state.ring_buffer.log_session(
        id.as_str(),
        format!(
            "session {id} {:?} registered for {}",
            session.name,
            session.root.display()
        ),
    );

    let reply = DaemonMessage::Registered {
        id: id.clone(),
        token,
        ca_path,
    };
    if responder.send(&reply).await.is_err() {
        // The launcher vanished before the reply landed; treat exactly like
        // a lease that closed immediately.
        state.end_session(&id, EndedReason::LeaseClosed);
        return;
    }

    // `responder` stays alive until this function returns: dropping its
    // `OwnedWriteHalf` shuts down the write side, and the launcher reads
    // that EOF as the lease ending.
    if is_lease {
        let lease_closer = session.lease_closer.clone();
        tokio::select! {
            () = lease_closer.cancelled() => {}
            _ = framed.next() => {
                state.end_session(&id, EndedReason::LeaseClosed);
            }
        }
    }
}

async fn handle_reload(
    session_ref: &str,
    payload: protocol::RegisterPayload,
    state: &Arc<DaemonState>,
) -> DaemonMessage {
    let session = match state.sessions.resolve_ref(session_ref) {
        Ok(s) => s,
        Err(msg) => {
            return DaemonMessage::Error {
                kind: ErrorKind::Malformed,
                message: msg,
            };
        }
    };

    let existing_policy = session.current_policy();

    let new_policy = match state.build_policy(&payload, &session.id, Some(&existing_policy)) {
        Ok(p) => p,
        Err(e) => {
            return DaemonMessage::Error {
                kind: ErrorKind::Internal,
                message: e,
            };
        }
    };

    // The CA file outlives any policy that still needs it (build_session_policy
    // keeps it across a reload whose routes are unchanged), but not a reload
    // that drops the session's last proxy tool.
    let proxy_removed = existing_policy.proxy.is_some() && new_policy.proxy.is_none();

    let (old_policy, changes, agent_changed) = {
        let mut guard = session.policy.write().unwrap_or_else(|e| e.into_inner());
        let changes = session::diff_tools(&guard.config, &new_policy.config);
        let agent_changed = guard.agent_hash != new_policy.agent_hash;
        let old = std::mem::replace(&mut *guard, Arc::new(new_policy));
        (old, changes, agent_changed)
    };
    tokio::spawn(async move {
        old_policy.shutdown_refresh().await;
    });

    if proxy_removed {
        state.remove_session_ca(&session.id);
    }

    state.rebuild_global_redactor();
    state
        .ring_buffer
        .log_session(session.id.as_str(), "session reloaded".to_string());

    DaemonMessage::Reloaded {
        id: session.id.clone(),
        changes,
        agent_changed,
    }
}

fn handle_revoke(refs: &[String], state: &Arc<DaemonState>) -> DaemonMessage {
    let mut resolved = Vec::with_capacity(refs.len());
    for r in refs {
        match state.sessions.resolve_ref(r) {
            Ok(session) => resolved.push(session),
            Err(msg) => {
                return DaemonMessage::Error {
                    kind: ErrorKind::Malformed,
                    message: msg,
                };
            }
        }
    }
    for session in resolved {
        state.end_session(&session.id, EndedReason::Revoked);
    }
    DaemonMessage::Ok
}

fn handle_renew(
    session_ref: &str,
    ttl_secs: Option<u64>,
    state: &Arc<DaemonState>,
) -> DaemonMessage {
    let session = match state.sessions.resolve_ref(session_ref) {
        Ok(s) => s,
        Err(msg) => {
            return DaemonMessage::Error {
                kind: ErrorKind::Malformed,
                message: msg,
            };
        }
    };
    let mut ends = session.ends.write().unwrap_or_else(|e| e.into_inner());
    match &*ends {
        Ends::Lease => DaemonMessage::Error {
            kind: ErrorKind::Malformed,
            message: format!(
                "session {} is held by a lease, not a TTL; it cannot be renewed",
                session.id
            ),
        },
        Ends::Ttl { ttl, .. } => {
            *ends = Ends::ttl_from_now(ttl_secs.map(Duration::from_secs).unwrap_or(*ttl));
            DaemonMessage::Ok
        }
    }
}

// ─── Session-family dispatch ─────────────────────────────────────────────────

async fn handle_session_request(
    req: SessionRequest,
    state: &Arc<DaemonState>,
    session: Arc<Session>,
    framed: Reader,
    mut responder: Responder,
) {
    match req {
        SessionRequest::List => {
            let policy = session.current_policy();
            let reply = DaemonMessage::Tools {
                session: session.info(),
                tools: session::tools_info(&policy.config),
            };
            let _ = responder.send(&reply).await;
        }
        SessionRequest::Check => {
            let policy = session.current_policy();
            let reply = DaemonMessage::CheckResult {
                session: session.info(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                anchors: Some(policy.anchors.clone()),
                secret_env_names: session::secret_env_names(&policy.config),
                credential_paths: session::credential_paths(&policy.config),
            };
            let _ = responder.send(&reply).await;
        }
        SessionRequest::Exec { tool, args, cwd } => {
            handle_exec_request(tool, args, cwd, state, session, framed, responder).await;
        }
    }
}

// ─── Exec request handling ──────────────────────────────────────────────────

/// The tool's `env` map with every secret reference resolved, in the map's
/// (alphabetical) order. A `Stale` slot — left behind by a failed background
/// refresh — is an error: the exec is refused rather than handing the tool a
/// value known to be expired.
fn resolve_tool_env(
    tool_config: &crate::config::ToolConfig,
    secrets: &crate::secrets::SecretStore,
) -> Result<Vec<(String, String)>, String> {
    use crate::config::EnvValue;
    use crate::secrets::Health;

    let mut env_pairs = Vec::with_capacity(tool_config.env.len());
    for (name, value) in &tool_config.env {
        match value {
            EnvValue::Static(s) => env_pairs.push((name.clone(), s.clone())),
            EnvValue::SecretRef(label) => {
                let Some(slot_lock) = secrets.get(label) else {
                    return Err(format!("secret {label:?} is not in the secret store"));
                };
                let slot = slot_lock.read().unwrap_or_else(|e| e.into_inner());
                match &slot.health {
                    Health::Healthy => {
                        env_pairs.push((name.clone(), slot.value.expose_secret().clone()))
                    }
                    Health::Stale { reason, .. } => {
                        return Err(format!(
                            "secret {label:?} is stale (last refresh failed): {reason}"
                        ));
                    }
                }
            }
        }
    }
    Ok(env_pairs)
}

/// An exec request rejected before the tool was spawned.
struct ExecStartError {
    kind: ErrorKind,
    message: String,
}

/// A tool that passed every check and was spawned.
struct StartedTool {
    spawned: exec::SpawnedChild,
    timeout: Duration,
    session_redactor: Arc<Redactor>,
    global_redactor: Arc<Redactor>,
    _proxy_session: Option<ProxySession>,
}

fn start_tool(
    tool: &str,
    args: Vec<String>,
    cwd: &Path,
    state: &DaemonState,
    session: &Session,
    policy: &SessionPolicy,
) -> Result<StartedTool, ExecStartError> {
    let tool_config = policy
        .config
        .tools
        .get(tool)
        .ok_or_else(|| ExecStartError {
            kind: ErrorKind::UnknownTool,
            message: format!("no tool named {tool:?} in this session"),
        })?;

    if !crate::anchors::is_inside(cwd, &session.root) {
        return Err(ExecStartError {
            kind: ErrorKind::OutsideRoot,
            message: format!(
                "{} is outside this session's project {}",
                cwd.display(),
                session.root.display()
            ),
        });
    }

    let binary = exec::resolve_binary_in(tool, &policy.path, &session.root, &policy.write_grants)
        .map_err(|e| ExecStartError {
        kind: ErrorKind::BinaryUnusable,
        message: e.to_string(),
    })?;

    let secret_pairs =
        resolve_tool_env(tool_config, &policy.secrets).map_err(|e| ExecStartError {
            kind: ErrorKind::StaleSecret,
            message: e,
        })?;
    let mut env = exec::build_env_from(&policy.snapshot, &policy.path, &secret_pairs);

    // Taken after the secrets are read, never earlier. A refresh swaps the
    // redactor before it publishes the new value, so a snapshot taken now
    // knows every value just put into `env`. One taken at accept time would
    // miss a refresh that lands before the client sends its request, and
    // the client chooses when that is.
    let session_redactor = Arc::clone(&policy.redactor.read().unwrap_or_else(|e| e.into_inner()));
    let global_redactor = state.global_redactor_snapshot();

    let proxy_session = match &tool_config.proxy {
        Some(proxy_policy) => {
            let shared = policy.proxy.as_ref().ok_or_else(|| ExecStartError {
                kind: ErrorKind::Internal,
                message: format!("tool {tool:?} is a proxy tool but the session holds no proxy CA"),
            })?;
            let proxy_session = ProxySession::start(tool.to_string(), proxy_policy.clone(), shared)
                .map_err(|e| ExecStartError {
                    kind: ErrorKind::Internal,
                    message: format!("failed to start the proxy for tool {tool:?}: {e}"),
                })?;
            proxy_session.apply_env(&mut env);
            Some(proxy_session)
        }
        None => None,
    };

    let timeout = tool_config.timeout.unwrap_or(policy.config.timeout);

    let proxy_port = proxy_session.as_ref().map(ProxySession::port);
    let mut tool_policy =
        policy::build_tool_policy(tool, &policy.config, proxy_port).map_err(|e| {
            ExecStartError {
                kind: ErrorKind::Internal,
                message: format!("policy construction failed for {tool:?}: {e}"),
            }
        })?;
    tool_policy.binary_path = Some(binary.clone());
    tool_policy.runtime_base = Some(state.runtime.base().to_path_buf());
    if tool_config.proxy.is_some() {
        tool_policy
            .read_paths
            .push(state.runtime.ca_path(session.id.as_str()));
    }

    let sandbox_profile =
        build_platform_sandbox_profile(&tool_policy).map_err(|e| ExecStartError {
            kind: ErrorKind::Internal,
            message: format!("sandbox profile construction failed for {tool:?}: {e}"),
        })?;

    let spawned = exec::spawn(exec::ExecRequest {
        binary,
        arg0: tool.to_string(),
        args,
        work_dir: cwd.to_path_buf(),
        env,
        sandbox_profile,
        timeout,
    })
    .map_err(|e| ExecStartError {
        kind: ErrorKind::Internal,
        message: format!("spawn failed for {tool:?}: {e}"),
    })?;

    Ok(StartedTool {
        spawned,
        timeout,
        session_redactor,
        global_redactor,
        _proxy_session: proxy_session,
    })
}

/// The reason the concurrent I/O loop terminated.
enum TermReason {
    ChildExited(std::process::ExitStatus),
    ChildWaitError(std::io::Error),
    Timeout,
    ClientDisconnect,
    ClientLineOverflow,
}

async fn handle_exec_request(
    tool: String,
    args: Vec<String>,
    cwd: PathBuf,
    state: &Arc<DaemonState>,
    session: Arc<Session>,
    mut framed: Reader,
    mut responder: Responder,
) {
    use tokio::io::AsyncWriteExt;
    use tokio_stream::StreamExt;
    use tokio_util::codec::LinesCodecError;

    // Set once, up front, so every `Error` this request can send — even one
    // refused before a tool is ever started, like a stale secret's
    // refresh-failure reason below — passes through this session's own
    // redactor too.
    let policy = session.current_policy();
    responder.session = Some(Arc::clone(
        &policy.redactor.read().unwrap_or_else(|e| e.into_inner()),
    ));

    let permit = match Arc::clone(&session.exec_permits).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            responder
                .error(
                    ErrorKind::Busy,
                    format!(
                        "session {} is already running {} concurrent execs",
                        session.id,
                        session::EXEC_CAP
                    ),
                )
                .await;
            return;
        }
    };

    let StartedTool {
        spawned,
        timeout,
        session_redactor,
        global_redactor,
        _proxy_session,
    } = match start_tool(&tool, args, &cwd, state, &session, &policy) {
        Ok(started) => started,
        Err(e) => {
            state.ring_buffer.log_session(
                session.id.as_str(),
                format!("exec {tool:?} refused: {}", e.message),
            );
            responder.error(e.kind, e.message).await;
            return;
        }
    };

    // The snapshot taken alongside the tool's secrets covers its output and
    // everything sent after it.
    responder.global = Arc::clone(&global_redactor);
    session.execs.fetch_add(1, Ordering::Relaxed);

    let pid = spawned.pid;
    let mut child = spawned.child;

    state.child_registry.insert(pid);
    state.ring_buffer.log_session(
        session.id.as_str(),
        format!("tool {tool:?} spawned (PID: {pid})"),
    );

    let (stdout_task, mut stdout_rx) = spawn_redaction_pipeline(
        Arc::clone(&session_redactor),
        Arc::clone(&global_redactor),
        spawned.stdout,
    );
    let (stderr_task, mut stderr_rx) = spawn_redaction_pipeline(
        session_redactor,
        Arc::clone(&global_redactor),
        spawned.stderr,
    );

    let mut child_stdin: Option<tokio::process::ChildStdin> = Some(spawned.stdin);
    let mut stdin_received = false;
    let mut stdout_done = false;
    let mut stderr_done = false;

    let timeout_timer = tokio::time::sleep(timeout);
    tokio::pin!(timeout_timer);
    let stdin_timer = tokio::time::sleep(STDIN_TIMEOUT);
    tokio::pin!(stdin_timer);

    let term_reason: TermReason;

    loop {
        tokio::select! {
            status = child.wait() => {
                term_reason = match status {
                    Ok(s) => TermReason::ChildExited(s),
                    Err(e) => TermReason::ChildWaitError(e),
                };
                break;
            }

            data = stdout_rx.recv(), if !stdout_done => {
                match data {
                    Some(bytes) => send_output(&mut responder, &bytes, stdout_message).await,
                    None => stdout_done = true,
                }
            }

            data = stderr_rx.recv(), if !stderr_done => {
                match data {
                    Some(bytes) => send_output(&mut responder, &bytes, stderr_message).await,
                    None => stderr_done = true,
                }
            }

            result = framed.next() => {
                match result {
                    None => {
                        term_reason = TermReason::ClientDisconnect;
                        break;
                    }
                    Some(Err(LinesCodecError::MaxLineLengthExceeded)) => {
                        term_reason = TermReason::ClientLineOverflow;
                        break;
                    }
                    Some(Err(LinesCodecError::Io(e))) => {
                        if e.kind() == std::io::ErrorKind::InvalidData {
                            continue;
                        }
                        term_reason = TermReason::ClientDisconnect;
                        break;
                    }
                    Some(Ok(line)) => {
                        if let Ok(frame) = serde_json::from_str::<protocol::StdinFrame>(line.trim()) {
                            match frame {
                                protocol::StdinFrame::Stdin { data } => {
                                    stdin_received = true;
                                    if let Some(ref mut stdin) = child_stdin {
                                        let _ = stdin.write_all(data.as_bytes()).await;
                                    }
                                }
                                protocol::StdinFrame::StdinEof => {
                                    stdin_received = true;
                                    child_stdin = None;
                                }
                            }
                        }
                    }
                }
            }

            _ = &mut stdin_timer, if !stdin_received && child_stdin.is_some() => {
                child_stdin = None;
            }

            _ = &mut timeout_timer => {
                term_reason = TermReason::Timeout;
                break;
            }
        }
    }

    drop(child_stdin);

    match term_reason {
        TermReason::ChildExited(status) => {
            let _ = stdout_task.await;
            let _ = stderr_task.await;

            drain_channel_to_client(&mut stdout_rx, &mut responder, stdout_message).await;
            drain_channel_to_client(&mut stderr_rx, &mut responder, stderr_message).await;

            let code = exit_code_from_status(status);
            let _ = responder.send(&DaemonMessage::Exit { code }).await;
            state.ring_buffer.log_session(
                session.id.as_str(),
                format!("tool {tool:?} exited (PID: {pid}, code: {code})"),
            );
        }
        TermReason::ChildWaitError(e) => {
            let _ = exec::kill_process_group(pid, libc::SIGKILL);
            let _ = responder.send(&DaemonMessage::Exit { code: -1 }).await;
            state.ring_buffer.log_session(
                session.id.as_str(),
                format!("tool {tool:?} wait error (PID: {pid}): {e}"),
            );
        }
        TermReason::Timeout => {
            state.ring_buffer.log_session(
                session.id.as_str(),
                format!("tool {tool:?} timed out after {timeout:?} (PID: {pid})"),
            );
            sigterm_then_sigkill(&mut child, pid).await;
            let msg = format!(
                "tool {tool:?} timed out after {} seconds",
                timeout.as_secs()
            );
            responder.error(ErrorKind::Internal, msg).await;
        }
        TermReason::ClientDisconnect => {
            state.ring_buffer.log_session(
                session.id.as_str(),
                format!("client disconnected during tool {tool:?} (PID: {pid})"),
            );
            sigterm_then_sigkill(&mut child, pid).await;
        }
        TermReason::ClientLineOverflow => {
            state.ring_buffer.log_session(session.id.as_str(), format!("client sent an oversized stdin line during tool {tool:?} (PID: {pid}); terminating"));
            sigterm_then_sigkill(&mut child, pid).await;
            responder
                .error(
                    ErrorKind::Malformed,
                    "stdin line exceeds maximum length".to_string(),
                )
                .await;
            let _ = responder.send(&DaemonMessage::Exit { code: -1 }).await;
        }
    }

    state.child_registry.remove(pid);
    drop(permit);
}

// ─── Child lifecycle helpers ─────────────────────────────────────────────────

async fn sigterm_then_sigkill(child: &mut tokio::process::Child, pid: u32) {
    let _ = exec::kill_process_group(pid, libc::SIGTERM);

    let grace = tokio::time::sleep(KILL_GRACE_PERIOD);
    tokio::pin!(grace);

    tokio::select! {
        _ = child.wait() => {}
        _ = &mut grace => {
            let _ = exec::kill_process_group(pid, libc::SIGKILL);
            let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
        }
    }
}

async fn drain_channel_to_client(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    responder: &mut Responder,
    message: fn(String) -> DaemonMessage,
) {
    while let Ok(bytes) = rx.try_recv() {
        send_output(responder, &bytes, message).await;
    }
}

/// Send one chunk of output that [`spawn_redaction_pipeline`] has already
/// redacted to the client.
async fn send_output(
    responder: &mut Responder,
    bytes: &[u8],
    message: fn(String) -> DaemonMessage,
) {
    let text = redact::bytes_to_lossy_utf8(bytes);
    if !text.is_empty() {
        let _ = responder.send(&message(text)).await;
    }
}

fn stdout_message(data: String) -> DaemonMessage {
    DaemonMessage::Stdout { data }
}

fn stderr_message(data: String) -> DaemonMessage {
    DaemonMessage::Stderr { data }
}

/// Read a tool's output to EOF, passing it through the session's own
/// redactor and then the daemon-wide global one (docs/airlock-v2-design.md,
/// "Session isolation"). Both passes are streams, so a secret split across
/// two reads — or across two chunks the first pass emits — is still caught.
/// The task ends once the held-back tail is flushed at EOF.
fn spawn_redaction_pipeline<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    session_redactor: Arc<Redactor>,
    global_redactor: Arc<Redactor>,
    mut reader: R,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    let task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut session_pass = StreamRedactor::new(session_redactor);
        let mut global_pass = StreamRedactor::new(global_redactor);
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let out = global_pass.push(&session_pass.push(&buf[..n]));
                    if !out.is_empty() && tx.send(out).is_err() {
                        return;
                    }
                }
            }
        }
        let mut tail = global_pass.push(&session_pass.finish());
        tail.extend(global_pass.finish());
        if !tail.is_empty() {
            let _ = tx.send(tail);
        }
    });

    (task, rx)
}

fn build_platform_sandbox_profile(
    policy: &crate::sandbox::ToolPolicy,
) -> Result<crate::sandbox::SandboxProfile, crate::sandbox::SandboxError> {
    use crate::sandbox::SandboxBackend;

    #[cfg(target_os = "macos")]
    {
        crate::sandbox::macos::MacOSSeatbelt.build(policy)
    }

    #[cfg(target_os = "linux")]
    {
        crate::sandbox::linux::LinuxLandlock.build(policy)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = policy;
        Err(crate::sandbox::SandboxError::ProfileBuildError(
            "sandbox not supported on this platform".to_string(),
        ))
    }
}

fn exit_code_from_status(status: std::process::ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| -(status.signal().unwrap_or(0)))
}

/// Send one message to the client. This is the only place a message is
/// serialized onto the wire, so it is the one place that can guarantee an
/// `Error` message's text — built at ~18 call sites, some from strings the
/// daemon did not choose (a secret refresh command's stderr, a config
/// error) — gets the same redaction pass stdout/stderr already get: the
/// session's own redactor first when one is in scope, then the daemon-wide
/// global redactor as the backstop. Every other variant passes through
/// unchanged.
async fn write_ndjson_message<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &DaemonMessage,
    global_redactor: &Redactor,
    session_redactor: Option<&Redactor>,
) -> Result<(), std::io::Error> {
    let json = match msg {
        DaemonMessage::Error { kind, message } => {
            let mut text = message.clone();
            if let Some(redactor) = session_redactor {
                text = redact::bytes_to_lossy_utf8(&redactor.redact_bytes(text.as_bytes()));
            }
            text = redact::bytes_to_lossy_utf8(&global_redactor.redact_bytes(text.as_bytes()));
            serde_json::to_string(&DaemonMessage::Error {
                kind: *kind,
                message: text,
            })
        }
        other => serde_json::to_string(other),
    }
    .map_err(std::io::Error::other)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
