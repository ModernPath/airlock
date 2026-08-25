//! Daemon startup, lifecycle management, and connection handling.
//!
//! This module implements:
//! - Synchronous startup sequence (config, secrets, redaction, socket binding)
//! - Stale PID/socket detection and cleanup
//! - Double-fork daemonization with readiness pipe
//! - Foreground mode (no forking)
//! - Async runtime creation and socket accept loop
//! - Ring buffer logging (1000 entries)
//! - Active child process registry
//! - SIGTERM graceful shutdown with child cleanup
//! - PID file management
//!
//! # Fork safety
//!
//! The entire synchronous startup sequence completes before any fork or tokio
//! runtime creation. This is critical because tokio's multi-threaded runtime
//! spawns background threads; forking after the runtime starts leaves those
//! threads in an undefined state in the child.

use std::collections::{HashSet, VecDeque};
use std::os::unix::net as unix_net;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use thiserror::Error;

use crate::config::{self, Config, ConfigError};
use crate::exec;
use crate::policy;
use crate::protocol::{ClientMessage, DaemonMessage, LogEntry};
use crate::redact::{self, RedactError, Redactor};
use crate::refresh;
use crate::sandbox;
use crate::secrets::{self, Health, SecretStore, SecretsError};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of log entries retained in the ring buffer.
const RING_BUFFER_CAPACITY: usize = 1000;

/// Grace period for children to exit after receiving SIGTERM during shutdown.
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(5);

/// Duration to wait for initial stdin before auto-closing the child's stdin pipe.
const STDIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Grace period after SIGTERM before sending SIGKILL (timeout/disconnect).
const KILL_GRACE_PERIOD: Duration = Duration::from_secs(5);

/// Maximum length (bytes, excluding the trailing newline) of a single NDJSON
/// line from a client — applies uniformly to the initial control frame and to
/// per-message stdin frames during an active exec.
///
/// A malicious or buggy client that never sends a newline would otherwise force
/// the daemon to grow its read buffer without bound. The cap is sized for
/// legitimate stdin chunks (which may carry binary-ish data) rather than the
/// much smaller control frames; an oversized control frame is still bounded
/// and would be rejected by JSON parsing after the fact. Only the socket owner
/// can connect (0o600), so a tighter control-frame cap would be pure
/// defense-in-depth.
const MAX_NDJSON_LINE_BYTES: usize = 1024 * 1024;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors that can occur during daemon startup and lifecycle management.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Config discovery or parsing failed.
    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    /// Secret collection failed (missing or invalid environment variables).
    #[error("secrets error: {0}")]
    Secrets(#[from] SecretsError),

    /// Redaction automaton construction failed.
    #[error("redaction error: {0}")]
    Redaction(#[from] RedactError),

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

    /// A daemon is already running with the given PID.
    #[error("daemon already running (PID: {pid})")]
    AlreadyRunning {
        /// The PID of the existing daemon.
        pid: u32,
    },

    /// A socket file is present and a daemon is actively serving on it, but no
    /// PID file accompanies it — the signature of an embedded `airlock run`
    /// daemon. Airlock will neither adopt nor replace such a daemon: its
    /// lifecycle belongs to the owning `run` session, distinct from the
    /// PID-file-backed standalone daemon reported by `AlreadyRunning`.
    #[error(
        "a daemon is already serving on socket {path}, but it has no PID file\n\n\
         This is an embedded daemon owned by an `airlock run` session. Airlock \
         will not adopt or replace it — its lifecycle is tied to that session. \
         Wait for the other `airlock run` to finish, or work from a separate \
         project directory."
    )]
    SocketInUse {
        /// The socket path that is already in use.
        path: PathBuf,
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
}

// ─── Ring buffer logging ──────────────────────────────────────────────────────

/// A thread-safe ring buffer for log entries with a fixed capacity.
///
/// When the buffer is at capacity and a new entry is added, the oldest entry
/// is evicted. Entries are retrievable in chronological order (oldest first).
///
/// When `echo` is `true`, entries are additionally written to stderr so a
/// foreground (`airlock daemon run`) invocation surfaces the log in the
/// operator's terminal. Daemonized processes keep `echo = false` because
/// stdio is redirected to `/dev/null`.
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

    /// Add a log entry with the current timestamp.
    pub fn log(&self, message: impl Into<String>) {
        let entry = LogEntry {
            timestamp: now_timestamp(),
            message: message.into(),
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

    // Simple UTC timestamp: YYYY-MM-DDTHH:MM:SSZ
    // Compute components from Unix timestamp.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch to date (simplified algorithm).
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

/// A thread-safe set of PIDs for currently-running child processes.
///
/// Supports insert, remove, and iterate-all operations. Safe to access from
/// multiple tokio tasks concurrently.
#[derive(Clone)]
pub struct ChildRegistry {
    inner: Arc<Mutex<HashSet<u32>>>,
}

impl Default for ChildRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ChildRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Register a child PID. Duplicate insertions are handled gracefully.
    pub fn insert(&self, pid: u32) {
        let mut set = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        set.insert(pid);
    }

    /// Remove a child PID.
    pub fn remove(&self, pid: u32) {
        let mut set = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        set.remove(&pid);
    }

    /// Return all currently-registered PIDs.
    pub fn all(&self) -> Vec<u32> {
        let set = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        set.iter().copied().collect()
    }
}

// ─── Startup state bundle ───────────────────────────────────────────────────

/// The state produced by the synchronous startup sequence.
///
/// This bundle is consumed by either the daemonization or foreground entry
/// point. It contains everything needed to run the async daemon loop.
pub struct StartupState {
    /// The fully parsed config.
    pub config: Config,
    /// Per-secret slots wrapped for shared, in-place mutation by refresh tasks.
    pub secrets: SecretStore,
    /// The shared, swappable redactor. Refresh tasks rebuild it on each
    /// successful refresh (covering current + previous generations); active
    /// connections snapshot the inner `Arc<Redactor>` at accept time.
    pub redactor: Arc<RwLock<Arc<Redactor>>>,
    /// The bound std UnixListener.
    pub listener: unix_net::UnixListener,
}

// ─── Synchronous startup sequence ───────────────────────────────────────────

/// Perform the synchronous startup sequence.
///
/// This function completes entirely without creating a tokio runtime or
/// spawning any threads. It:
///
/// 1. Discovers and parses the config file
/// 2. Detects and cleans up stale PID/socket files
/// 3. Collects secrets from environment variables
/// 4. Clears secret environment variables
/// 5. Builds the redaction automaton
/// 6. Binds a std UnixListener at the socket path (owner-only permissions)
/// 7. Verifies socket permissions are owner-only (refuses to start otherwise)
///
/// # Arguments
///
/// * `start_dir` — The directory to start config discovery from (used when
///   `config_path` is `None`).
/// * `config_path` — If `Some`, load config from this explicit file path
///   rather than performing the directory-walk discovery from `start_dir`.
///   `sandbox_root` is derived from the file's parent directory.
///
/// # Errors
///
/// Returns [`DaemonError`] if any step fails.
pub fn synchronous_startup(
    start_dir: &Path,
    config_path: Option<&Path>,
) -> Result<StartupState, DaemonError> {
    // 0. Process hardening. Disable core dumps and (on Linux) mark the process
    //    non-dumpable before any secret enters our address space. This is
    //    best-effort — failures are logged, not fatal.
    harden_process();

    // 1. Config discovery and parsing.
    //    When an explicit path is provided use it directly; otherwise walk up
    //    from `start_dir` to find the nearest `airlock.toml`.
    let config = match config_path {
        Some(p) => config::load_config_from_file(p)?,
        None => config::load_config(start_dir)?,
    };

    // 2. Stale state detection and cleanup.
    check_and_cleanup_stale_state(&config.pid_path, &config.socket_path)?;

    // 3. Secret collection. Wrapped per-slot so refresh tasks can later swap
    //    values in place; every slot starts `Healthy`.
    let secret_store = secrets::build_secret_store(&config)?;

    // 4. Environment variable clearing.
    secrets::clear_secret_env_vars(&config);

    // 5. Automaton building. Wrapped in `RwLock<Arc<_>>` so refresh tasks can
    //    rebuild and swap atomically while in-flight connections keep their
    //    snapshot.
    let initial_redactor = {
        let pairs: Vec<(String, std::sync::Arc<crate::secrets::Secret<String>>)> = secret_store
            .iter()
            .map(|(name, slot)| {
                let s = slot.read().unwrap();
                (name.clone(), std::sync::Arc::clone(&s.value))
            })
            .collect();
        let refs: Vec<(&str, &crate::secrets::Secret<String>)> = pairs
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_ref()))
            .collect();
        redact::Redactor::new(refs)?
    };
    let redactor = Arc::new(RwLock::new(Arc::new(initial_redactor)));

    // 6. Socket binding with restrictive permissions (owner-only).
    //    Set umask to 0o077 so the socket is created with mode 0o700.
    //    This prevents other local users from connecting to the daemon.
    let old_umask = rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);
    let bind_result =
        unix_net::UnixListener::bind(&config.socket_path).map_err(|e| DaemonError::SocketBind {
            path: config.socket_path.clone(),
            source: e,
        });
    // Restore the original umask immediately, even if bind failed.
    rustix::process::umask(old_umask);
    let listener = bind_result?;

    // 7. Verify socket permissions are owner-only.
    //    Bail out immediately if the filesystem didn't honor the umask — we
    //    refuse to run with a world-accessible socket.
    verify_socket_permissions(&config.socket_path)?;

    Ok(StartupState {
        config,
        secrets: secret_store,
        redactor,
        listener,
    })
}

/// Check for stale PID/socket files and clean them up.
///
/// - If a PID file exists with a live process, returns `AlreadyRunning`.
/// - If a PID file exists with a dead process, removes both PID and socket files.
/// - If no PID file exists but a socket file does, connects to it: a daemon
///   that answers (an embedded `airlock run` daemon, which writes no PID file)
///   yields `SocketInUse`; an unresponsive socket is removed as stale.
/// - If neither exists, proceeds normally.
fn check_and_cleanup_stale_state(pid_path: &Path, socket_path: &Path) -> Result<(), DaemonError> {
    if pid_path.exists() {
        // Read the PID from the file.
        let contents = std::fs::read_to_string(pid_path).map_err(|e| DaemonError::PidFileRead {
            path: pid_path.to_path_buf(),
            source: e,
        })?;

        let pid: u32 = contents.trim().parse().map_err(|_| {
            DaemonError::StaleCleanup(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid PID in file: {:?}", contents.trim()),
            ))
        })?;

        // Check if the process is alive using signal-zero.
        let alive = rustix::process::Pid::from_raw(pid as i32)
            .is_some_and(|p| rustix::process::test_kill_process(p).is_ok());
        if alive {
            // Process is alive — daemon already running.
            return Err(DaemonError::AlreadyRunning { pid });
        }

        // Process is dead (ESRCH) — stale state. Clean up.
        let _ = std::fs::remove_file(pid_path);
        let _ = std::fs::remove_file(socket_path);
    } else if socket_path.exists() {
        // No PID file, but a socket file is present. It is either a live
        // embedded daemon (an `airlock run` session writes no PID file) or a
        // socket left behind by a crash. Connecting is the only way to tell
        // them apart — removing a live daemon's socket would silently sever it
        // from its clients. If it answers, refuse; if the connection is
        // refused, nothing is listening and the socket is genuinely stale.
        if std::os::unix::net::UnixStream::connect(socket_path).is_ok() {
            return Err(DaemonError::SocketInUse {
                path: socket_path.to_path_buf(),
            });
        }
        let _ = std::fs::remove_file(socket_path);
    }

    Ok(())
}

/// Verify the socket file has owner-only permissions.
///
/// Refuses to proceed if other users have any access. This is not something
/// we attempt to fix — if the permissions are wrong, something unexpected
/// happened (filesystem doesn't support Unix permissions, external umask
/// override, etc.) and the only safe response is to bail out.
fn verify_socket_permissions(socket_path: &Path) -> Result<(), DaemonError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(socket_path).map_err(|e| DaemonError::SocketBind {
        path: socket_path.to_path_buf(),
        source: e,
    })?;

    let mode = metadata.permissions().mode() & 0o777;
    // Owner-only: no group or other bits may be set.
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
/// living in the daemon's address space:
///
/// - Set `RLIMIT_CORE` to 0 so a crash cannot produce a core dump containing
///   secrets.
/// - On Linux, set `PR_SET_DUMPABLE` to 0, which additionally makes the
///   `/proc/<pid>/mem` and `/proc/<pid>/maps` files owned by root and blocks
///   same-UID ptrace under yama.
/// - On Linux, set `PR_SET_PTRACER` to 0 as an extra yama hardening nudge.
///
/// All calls are best-effort: failures are printed to stderr but do not abort
/// startup. These are defense-in-depth and the daemon functions without them.
///
/// Safe to call exactly once, early in startup, before any thread is spawned.
pub(crate) fn harden_process() {
    // Disable core dumps on both Unix platforms.
    let rlim = rustix::process::Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    if let Err(err) = rustix::process::setrlimit(rustix::process::Resource::Core, rlim) {
        eprintln!("airlock: warning: setrlimit(RLIMIT_CORE, 0) failed: {err}");
    }

    #[cfg(target_os = "linux")]
    {
        // PR_SET_DUMPABLE = 0 prevents core dumps, makes /proc/<pid>/mem
        // inaccessible to same-UID processes (reverts to root ownership), and
        // blocks ptrace by non-privileged same-UID peers under yama.
        if let Err(err) =
            rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        {
            eprintln!("airlock: warning: prctl(PR_SET_DUMPABLE, 0) failed: {err}");
        }

        // PTracer::None clears any explicit ptracer allowance. Effectively
        // a no-op unless something earlier set a ptracer; included for
        // defense-in-depth.
        if let Err(err) = rustix::process::set_ptracer(rustix::process::PTracer::None) {
            // Non-fatal; yama may not be enabled.
            eprintln!("airlock: note: prctl(PR_SET_PTRACER, 0) returned: {err}");
        }
    }
}

// ─── Double-fork daemonization ──────────────────────────────────────────────

/// Daemonize using double-fork and then run the async runtime.
///
/// This function:
/// 1. Creates a readiness pipe
/// 2. First fork — parent waits for readiness, intermediate child calls setsid
/// 3. Second fork — intermediate child exits, grandchild is the daemon
/// 4. Redirects stdio to /dev/null
/// 5. Changes working directory to /
/// 6. Enters the async runtime
///
/// The original parent process calls `_exit(0)` after receiving the readiness
/// signal. This function does not return in the parent.
pub fn daemonize(state: StartupState) -> Result<(), DaemonError> {
    // Create readiness pipe.
    let mut pipe_fds: [libc::c_int; 2] = [0; 2];
    let ret = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(DaemonError::PipeFailed(std::io::Error::last_os_error()));
    }
    let read_end = pipe_fds[0];
    let write_end = pipe_fds[1];

    // First fork.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // Fork failed. Close pipe fds.
        unsafe {
            libc::close(read_end);
            libc::close(write_end);
        }
        return Err(DaemonError::ForkFailed(std::io::Error::last_os_error()));
    }

    if pid > 0 {
        // ── Original parent ──
        // Close write end; wait for readiness signal on read end.
        unsafe { libc::close(write_end) };

        let mut buf = [0u8; 1];
        // Blocking read — will return when child writes or pipe closes.
        unsafe { libc::read(read_end, buf.as_mut_ptr() as *mut libc::c_void, 1) };
        unsafe { libc::close(read_end) };

        // Exit without running Rust destructors.
        unsafe { libc::_exit(0) };
    }

    // ── First child ──
    // Close read end of pipe (parent has it).
    unsafe { libc::close(read_end) };

    // Become session leader.
    if unsafe { libc::setsid() } < 0 {
        unsafe { libc::_exit(1) };
    }

    // Second fork.
    let pid2 = unsafe { libc::fork() };
    if pid2 < 0 {
        unsafe { libc::_exit(1) };
    }
    if pid2 > 0 {
        // Intermediate child exits.
        unsafe { libc::_exit(0) };
    }

    // ── Grandchild (final daemon process) ──

    // Redirect stdio to /dev/null.
    redirect_stdio_to_devnull();

    // Change working directory to /.
    unsafe {
        libc::chdir(c"/".as_ptr());
    }

    // Enter the async runtime with the readiness pipe write end.
    run_async_runtime(state, Some(write_end), false)
}

/// Redirect stdin, stdout, and stderr to /dev/null.
fn redirect_stdio_to_devnull() {
    unsafe {
        let devnull_fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull_fd >= 0 {
            libc::dup2(devnull_fd, 0); // stdin
            libc::dup2(devnull_fd, 1); // stdout
            libc::dup2(devnull_fd, 2); // stderr
            if devnull_fd > 2 {
                libc::close(devnull_fd);
            }
        }
    }
}

// ─── Foreground mode entry point ────────────────────────────────────────────

/// Run the daemon in the foreground (no forking).
///
/// Performs the same async runtime entry as daemonized mode, but without
/// any fork/setsid/stdio-redirect steps.
pub fn run_foreground(state: StartupState) -> Result<(), DaemonError> {
    run_async_runtime(state, None, true)
}

// ─── Embedded mode entry point ───────────────────────────────────────────────

/// Run the daemon accept loop inside a caller-supplied tokio runtime.
///
/// Unlike [`run_foreground`] and [`daemonize`], this function does **not**
/// create its own runtime — it must be called from within an existing one
/// (e.g. via `tokio::spawn` or `block_on`). It is intended for the
/// `airlock run` path where the daemon shares a runtime with the agent child
/// process.
///
/// Shutdown is triggered only when the caller drops or fires the `cancel_rx`
/// oneshot — which `airlock run` does once the agent child has exited.
///
/// The embedded daemon deliberately installs **no** SIGTERM handler of its
/// own. It shares a process with the `airlock run` orchestrator, where
/// SIGTERM is handled by `run::signal_loop` and forwarded to the agent.
/// Reacting to SIGTERM here would let the daemon — and its Unix socket —
/// disappear while the agent is still running and trying to reach it, which
/// is exactly the failure this design avoids: the daemon must always outlive
/// the agent it serves.
///
/// No PID file is written and no readiness byte is sent — the caller already
/// knows the daemon is ready because the socket was bound during
/// [`synchronous_startup`].
pub(crate) async fn run_embedded(
    state: StartupState,
    cancel_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), DaemonError> {
    let StartupState {
        config,
        secrets,
        redactor,
        listener: std_listener,
    } = state;

    // Convert the std listener to a tokio listener (identical to async_main).
    std_listener
        .set_nonblocking(true)
        .map_err(|e| DaemonError::SocketBind {
            path: config.socket_path.clone(),
            source: e,
        })?;
    let listener =
        tokio::net::UnixListener::from_std(std_listener).map_err(|e| DaemonError::SocketBind {
            path: config.socket_path.clone(),
            source: e,
        })?;

    let config = Arc::new(config);

    // Embedded mode does not echo log lines to stderr — stderr belongs to the
    // agent process. Writes go to the ring buffer only.
    let ring_buffer = RingBuffer::new();
    let child_registry = ChildRegistry::new();

    // Spawn per-secret refresh tasks, identical to async_main.
    let (mut refresh_tasks, refresh_shutdown) = refresh::spawn_all(
        &config,
        Arc::clone(&secrets),
        Arc::clone(&redactor),
        ring_buffer.clone(),
    );
    let refresh_count = refresh_tasks.len();
    if refresh_count > 0 {
        ring_buffer.log(format!("spawned {refresh_count} secret refresh task(s)"));
    }

    // Capture paths before moving config into Arc.
    let socket_path = config.socket_path.clone();
    let pid_path = config.pid_path.clone();

    ring_buffer.log("embedded daemon started, accepting connections".to_string());

    // `oneshot::Receiver<T>` is `Unpin`, so borrowing via `&mut cancel_rx`
    // in each select! arm is sufficient — no pinning machinery needed.
    let mut cancel_rx = cancel_rx;

    // Accept loop. The cancel oneshot is the *only* shutdown trigger:
    // `airlock run` drops the sender once the agent child has exited. The
    // embedded daemon must not react to SIGTERM itself (see this function's
    // doc comment) so that it always outlives the agent it serves.
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, addr)) => {
                        let peer_info = format!("{:?}", addr);
                        ring_buffer.log(format!("connection accepted from {peer_info}"));

                        let rb = ring_buffer.clone();
                        let cr = child_registry.clone();
                        let cfg = config.clone();
                        let sec = Arc::clone(&secrets);
                        // Snapshot the redactor at accept time so in-flight
                        // connections are not affected by concurrent refreshes.
                        let red = redactor.read().unwrap_or_else(|e| e.into_inner()).clone();

                        tokio::spawn(async move {
                            handle_connection(stream, cfg, sec, red, rb.clone(), cr).await;
                            rb.log(format!("connection closed ({peer_info})"));
                        });
                    }
                    Err(e) => {
                        ring_buffer.log(format!("accept error: {e}"));
                    }
                }
            }
            _ = &mut cancel_rx => {
                ring_buffer.log("cancel signal received, initiating graceful shutdown".to_string());
                break;
            }
        }
    }

    // Stop refresh tasks before tearing down children/files (same bounded
    // 2-second wait as async_main).
    let _ = refresh_shutdown.send(true);
    let drain = async { while refresh_tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(2), drain)
        .await
        .is_err()
    {
        ring_buffer.log("refresh tasks did not stop within 2s; aborting".to_string());
        refresh_tasks.abort_all();
    }

    // Graceful shutdown: signal/wait for child processes and remove the socket
    // file. No PID file was written, so pid_path removal will fail silently
    // (the error is logged to the ring buffer only).
    graceful_shutdown(&child_registry, &ring_buffer, &socket_path, &pid_path).await;

    Ok(())
}

// ─── Async runtime entry point ──────────────────────────────────────────────

/// Create a fresh tokio runtime and run the daemon's async main loop.
///
/// # Arguments
///
/// * `state` — The startup state bundle from the synchronous phase.
/// * `readiness_fd` — If `Some`, the write end of the readiness pipe.
///   A single byte is written and the fd is closed after the daemon is
///   ready to accept connections. If `None` (foreground mode), this is a no-op.
fn run_async_runtime(
    state: StartupState,
    readiness_fd: Option<libc::c_int>,
    foreground: bool,
) -> Result<(), DaemonError> {
    let runtime = tokio::runtime::Runtime::new().map_err(DaemonError::RuntimeCreation)?;

    runtime.block_on(async_main(state, readiness_fd, foreground))
}

/// The async main loop of the daemon.
async fn async_main(
    state: StartupState,
    readiness_fd: Option<libc::c_int>,
    foreground: bool,
) -> Result<(), DaemonError> {
    let StartupState {
        config,
        secrets,
        redactor,
        listener: std_listener,
    } = state;

    // Convert the std listener to a tokio listener.
    std_listener
        .set_nonblocking(true)
        .map_err(|e| DaemonError::SocketBind {
            path: config.socket_path.clone(),
            source: e,
        })?;
    let listener =
        tokio::net::UnixListener::from_std(std_listener).map_err(|e| DaemonError::SocketBind {
            path: config.socket_path.clone(),
            source: e,
        })?;

    // Wrap shared state in Arcs for concurrent access across connections.
    // `secrets` is already `SecretStore` (Arc<HashMap<...>>); `redactor` is
    // already `Arc<RwLock<Arc<Redactor>>>`.
    let config = Arc::new(config);

    // Create shared state. Foreground mode echoes log lines to stderr so the
    // operator sees what the daemon is doing; daemonized mode writes to the
    // ring buffer only (stdio is /dev/null).
    let ring_buffer = if foreground {
        RingBuffer::new_echoing()
    } else {
        RingBuffer::new()
    };
    let child_registry = ChildRegistry::new();

    // Spawn one background task per refreshable secret. Tasks live until they
    // observe the shutdown signal or get aborted at SIGTERM.
    let (mut refresh_tasks, refresh_shutdown) = refresh::spawn_all(
        &config,
        Arc::clone(&secrets),
        Arc::clone(&redactor),
        ring_buffer.clone(),
    );
    let refresh_count = refresh_tasks.len();
    if refresh_count > 0 {
        ring_buffer.log(format!("spawned {refresh_count} secret refresh task(s)"));
    }

    // Write PID file.
    let pid = std::process::id();
    let pid_path = config.pid_path.clone();
    let socket_path = config.socket_path.clone();

    if let Err(e) = write_pid_file(&pid_path, pid) {
        ring_buffer.log(format!("failed to write PID file: {e}"));
        return Err(e);
    }

    ring_buffer.log(format!("daemon started (PID: {pid})"));
    ring_buffer.log(format!(
        "listening on {} — ready to accept connections",
        socket_path.display()
    ));

    // Signal readiness.
    if let Some(fd) = readiness_fd {
        unsafe {
            let byte: [u8; 1] = [1];
            libc::write(fd, byte.as_ptr() as *const libc::c_void, 1);
            libc::close(fd);
        }
    }

    // Install SIGTERM handler.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    // Accept loop with shutdown.
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, addr)) => {
                        let peer_info = format!("{:?}", addr);
                        ring_buffer.log(format!("connection accepted from {peer_info}"));

                        let rb = ring_buffer.clone();
                        let cr = child_registry.clone();
                        let cfg = config.clone();
                        let sec = Arc::clone(&secrets);
                        // Snapshot the redactor at accept time. Refresh tasks
                        // may swap the inner Arc later; this connection keeps
                        // its snapshot for its full lifetime.
                        let red = redactor.read().unwrap_or_else(|e| e.into_inner()).clone();

                        tokio::spawn(async move {
                            handle_connection(stream, cfg, sec, red, rb.clone(), cr).await;
                            rb.log(format!("connection closed ({peer_info})"));
                        });
                    }
                    Err(e) => {
                        ring_buffer.log(format!("accept error: {e}"));
                    }
                }
            }
            _ = sigterm.recv() => {
                ring_buffer.log("SIGTERM received, initiating graceful shutdown".to_string());
                break;
            }
        }
    }

    // Stop refresh tasks before tearing down children/files. Bound the wait
    // so a stuck task cannot wedge shutdown.
    let _ = refresh_shutdown.send(true);
    let drain = async { while refresh_tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(2), drain)
        .await
        .is_err()
    {
        ring_buffer.log("refresh tasks did not stop within 2s; aborting".to_string());
        refresh_tasks.abort_all();
    }

    // ── Graceful shutdown ──
    graceful_shutdown(&child_registry, &ring_buffer, &socket_path, &pid_path).await;

    Ok(())
}

// ─── Connection handling ────────────────────────────────────────────────────

/// Handle a single client connection.
///
/// Reads the first NDJSON line to determine the request type, dispatches to
/// the appropriate handler, and closes the connection.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    config: Arc<Config>,
    secrets: SecretStore,
    redactor: Arc<Redactor>,
    ring_buffer: RingBuffer,
    child_registry: ChildRegistry,
) {
    use tokio_stream::StreamExt;
    use tokio_util::codec::{FramedRead, LinesCodec, LinesCodecError};

    let (reader, mut writer) = stream.into_split();
    // LinesCodec frames by `\n` (stripping `\n` / `\r\n`), requires UTF-8, and
    // returns `MaxLineLengthExceeded` if the cap is hit before a newline.
    let mut framed = FramedRead::new(
        reader,
        LinesCodec::new_with_max_length(MAX_NDJSON_LINE_BYTES),
    );

    let line = match framed.next().await {
        None => {
            // Connection closed before sending any data, or closed mid-line.
            return;
        }
        Some(Ok(line)) => line,
        Some(Err(LinesCodecError::MaxLineLengthExceeded)) => {
            ring_buffer.log(format!(
                "connection sent request exceeding {} bytes; closing",
                MAX_NDJSON_LINE_BYTES
            ));
            let _ = write_ndjson_message(
                &mut writer,
                &DaemonMessage::Error {
                    message: "request exceeds maximum length".to_string(),
                },
            )
            .await;
            return;
        }
        Some(Err(LinesCodecError::Io(e))) => {
            // `InvalidData` from LinesCodec means non-UTF-8; anything else is
            // a genuine I/O failure. Treat both as a closed/malformed
            // connection — do not echo the parser error back to the client.
            if e.kind() == std::io::ErrorKind::InvalidData {
                ring_buffer.log("request line contained invalid UTF-8");
                let _ = write_ndjson_message(
                    &mut writer,
                    &DaemonMessage::Error {
                        message: "malformed request".to_string(),
                    },
                )
                .await;
            } else {
                ring_buffer.log(format!("error reading from connection: {e}"));
            }
            return;
        }
    };

    // Parse the message. Do not echo the raw parser error back to the client —
    // it can contain fragments of the offending input.
    let msg: ClientMessage = match serde_json::from_str(line.trim()) {
        Ok(msg) => msg,
        Err(e) => {
            ring_buffer.log(format!("failed to parse request JSON: {e}"));
            let error_response = DaemonMessage::Error {
                message: "malformed request".to_string(),
            };
            let _ = write_ndjson_message(&mut writer, &error_response).await;
            return;
        }
    };

    match msg {
        ClientMessage::Logs => {
            let entries = ring_buffer.entries();
            let response = DaemonMessage::LogsResponse { entries };
            let _ = write_ndjson_message(&mut writer, &response).await;
        }
        ClientMessage::Exec { tool, args, cwd } => {
            handle_exec_request(
                tool,
                args,
                cwd,
                framed,
                writer,
                config,
                secrets,
                redactor,
                ring_buffer,
                child_registry,
            )
            .await;
        }
        other => {
            // Unknown message type for initial request. Log only the variant
            // discriminator (never client-supplied payload bytes, which could
            // carry secrets or large blobs).
            let variant = match other {
                ClientMessage::Stdin { .. } => "stdin",
                ClientMessage::StdinEof => "stdin_eof",
                ClientMessage::Logs => "logs",
                ClientMessage::Exec { .. } => "exec",
            };
            ring_buffer.log(format!(
                "unexpected message type as initial request: {variant}"
            ));
            let error_response = DaemonMessage::Error {
                message: "unexpected initial message type".to_string(),
            };
            let _ = write_ndjson_message(&mut writer, &error_response).await;
        }
    }
}

// ─── Exec request handler ───────────────────────────────────────────────────

/// Log an error to the ring buffer and send it to the client as an NDJSON
/// error message, collapsing the repeated "build msg, log, send" pattern used
/// throughout exec request validation.
async fn log_and_send_error<W: tokio::io::AsyncWrite + Unpin>(
    msg: String,
    ring_buffer: &RingBuffer,
    writer: &mut W,
) {
    ring_buffer.log(&msg);
    let _ = write_ndjson_message(writer, &DaemonMessage::Error { message: msg }).await;
}

/// The reason the concurrent I/O loop terminated.
enum TermReason {
    /// The child process exited with the given status.
    ChildExited(std::process::ExitStatus),
    /// Waiting for the child's exit status failed.
    ChildWaitError(std::io::Error),
    /// The configured timeout was exceeded.
    Timeout,
    /// The client disconnected while the child was running.
    ClientDisconnect,
    /// The client sent a line exceeding [`MAX_NDJSON_LINE_BYTES`].
    ClientLineOverflow,
}

/// Handle an exec request: validate, spawn, and manage the child's lifecycle.
///
/// This function implements the full exec flow:
/// 1. Tool validation
/// 2. CWD validation
/// 3. Binary resolution
/// 4. Environment construction
/// 5. Timeout resolution
/// 6. Policy and sandbox profile construction
/// 7. ExecRequest assembly and spawn
/// 8. Child registration
/// 9. Concurrent I/O loop (output streaming, stdin forwarding, timeout, disconnect)
/// 10. Post-loop cleanup (drain output, send exit, kill if needed)
#[allow(clippy::too_many_arguments)]
async fn handle_exec_request(
    tool: String,
    args: Vec<String>,
    cwd: String,
    mut framed: tokio_util::codec::FramedRead<
        tokio::net::unix::OwnedReadHalf,
        tokio_util::codec::LinesCodec,
    >,
    mut writer: tokio::net::unix::OwnedWriteHalf,
    config: Arc<Config>,
    secrets: SecretStore,
    redactor: Arc<Redactor>,
    ring_buffer: RingBuffer,
    child_registry: ChildRegistry,
) {
    use tokio::io::AsyncWriteExt;
    use tokio_stream::StreamExt;
    use tokio_util::codec::LinesCodecError;

    // ── 1. Tool validation ──────────────────────────────────────────────────
    if let Err(e) = policy::validate_tool_exists(&tool, &config) {
        log_and_send_error(
            format!("unknown tool {:?}: {e}", tool),
            &ring_buffer,
            &mut writer,
        )
        .await;
        return;
    }

    // ── 2. CWD validation ───────────────────────────────────────────────────
    let cwd_path = PathBuf::from(&cwd);
    if let Err(e) = policy::validate_cwd(&cwd_path, &config.sandbox_root) {
        log_and_send_error(
            format!("CWD validation failed: {e}"),
            &ring_buffer,
            &mut writer,
        )
        .await;
        return;
    }

    // ── 3. Binary resolution ────────────────────────────────────────────────
    let binary = match exec::resolve_binary(&tool) {
        Ok(path) => path,
        Err(e) => {
            log_and_send_error(
                format!("binary resolution failed for {:?}: {e}", tool),
                &ring_buffer,
                &mut writer,
            )
            .await;
            return;
        }
    };

    // ── 4. Environment construction ─────────────────────────────────────────
    //
    // Walk the tool's env map in order (BTreeMap → alphabetical). Static
    // entries pass through; SecretRef entries take a short-lived read lock on
    // the slot. A `Stale` slot — left behind by a failed background refresh —
    // is a hard error: we refuse the exec rather than hand the tool a value
    // we know to be expired. Refs are validated at config load time, so a
    // missing label here is an internal invariant break.
    let tool_config = &config.tools[&tool];
    let env_build_result: Result<Vec<(String, String)>, (String, String)> = (|| {
        let mut env_pairs: Vec<(String, String)> = Vec::with_capacity(tool_config.env.len());
        for (name, value) in tool_config.env.iter() {
            match value {
                config::EnvValue::Static(s) => env_pairs.push((name.clone(), s.clone())),
                config::EnvValue::SecretRef(label) => {
                    let Some(slot_lock) = secrets.get(label) else {
                        continue;
                    };
                    let slot = slot_lock.read().unwrap_or_else(|e| e.into_inner());
                    match &slot.health {
                        Health::Healthy => {
                            env_pairs.push((name.clone(), slot.value.expose_secret().clone()));
                        }
                        Health::Stale { reason, .. } => {
                            return Err((label.clone(), reason.clone()));
                        }
                    }
                }
            }
        }
        Ok(env_pairs)
    })();
    let env_pairs = match env_build_result {
        Ok(p) => p,
        Err((label, reason)) => {
            log_and_send_error(
                format!("secret {label:?} is stale (last refresh failed): {reason}"),
                &ring_buffer,
                &mut writer,
            )
            .await;
            return;
        }
    };
    let env = exec::build_env(&env_pairs);

    // ── 5. Timeout resolution ───────────────────────────────────────────────
    let timeout = tool_config.timeout.unwrap_or(config.timeout);

    // ── 6. Policy and sandbox profile construction ──────────────────────────
    let mut tool_policy = match policy::build_tool_policy(&tool, &config) {
        Ok(p) => p,
        Err(e) => {
            log_and_send_error(
                format!("policy construction failed for {:?}: {e}", tool),
                &ring_buffer,
                &mut writer,
            )
            .await;
            return;
        }
    };
    tool_policy.binary_path = Some(binary.clone());

    let sandbox_profile = match build_platform_sandbox_profile(&tool_policy) {
        Ok(p) => p,
        Err(e) => {
            log_and_send_error(
                format!("sandbox profile construction failed for {:?}: {e}", tool),
                &ring_buffer,
                &mut writer,
            )
            .await;
            return;
        }
    };

    // ── 7. ExecRequest assembly and spawn ───────────────────────────────────
    let request = exec::ExecRequest {
        binary,
        args,
        work_dir: cwd_path,
        env,
        sandbox_profile,
        timeout,
    };

    let spawned = match exec::spawn(request) {
        Ok(s) => s,
        Err(e) => {
            log_and_send_error(
                format!("spawn failed for {:?}: {e}", tool),
                &ring_buffer,
                &mut writer,
            )
            .await;
            return;
        }
    };

    let pid = spawned.pid;
    let mut child = spawned.child;

    // ── 8. Child registration ───────────────────────────────────────────────
    child_registry.insert(pid);
    ring_buffer.log(format!("tool {:?} spawned (PID: {pid})", tool));

    // ── 9. Set up redaction pipelines ───────────────────────────────────────
    //
    // For each output stream (stdout/stderr), the pipeline is:
    //   async reader task → std sync channel → blocking redact task → tokio mpsc → select loop
    //
    // The async reader reads chunks from the child's pipe and sends them
    // through a std::sync::mpsc channel. A blocking task wraps that channel
    // in a ChannelReader (impl Read), feeds it through redact_stream, and
    // writes redacted output to a tokio mpsc channel. The select loop
    // receives redacted chunks and sends NDJSON messages to the client.

    let (stdout_task, mut stdout_rx) = spawn_redaction_pipeline(redactor.clone(), spawned.stdout);
    let (stderr_task, mut stderr_rx) = spawn_redaction_pipeline(redactor, spawned.stderr);

    // ── 10. Concurrent I/O loop ─────────────────────────────────────────────
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
            // Child exit — highest priority terminal event.
            status = child.wait() => {
                term_reason = match status {
                    Ok(s) => TermReason::ChildExited(s),
                    Err(e) => TermReason::ChildWaitError(e),
                };
                break;
            }

            // Stdout redacted output.
            data = stdout_rx.recv(), if !stdout_done => {
                match data {
                    Some(bytes) => {
                        let text = redact::bytes_to_lossy_utf8(&bytes);
                        if !text.is_empty() {
                            let _ = write_ndjson_message(
                                &mut writer,
                                &DaemonMessage::Stdout { data: text },
                            ).await;
                        }
                    }
                    None => {
                        stdout_done = true;
                    }
                }
            }

            // Stderr redacted output.
            data = stderr_rx.recv(), if !stderr_done => {
                match data {
                    Some(bytes) => {
                        let text = redact::bytes_to_lossy_utf8(&bytes);
                        if !text.is_empty() {
                            let _ = write_ndjson_message(
                                &mut writer,
                                &DaemonMessage::Stderr { data: text },
                            ).await;
                        }
                    }
                    None => {
                        stderr_done = true;
                    }
                }
            }

            // Client messages (stdin forwarding, disconnect detection).
            // LinesCodec caps each line at MAX_NDJSON_LINE_BYTES, preventing an
            // unbounded memory-growth DoS if the client never sends a newline.
            result = framed.next() => {
                match result {
                    None => {
                        // Stream ended (clean EOF, or truncated line without a
                        // trailing newline — LinesCodec yields the final partial
                        // line as Ok then None; both paths terminate the exec).
                        term_reason = TermReason::ClientDisconnect;
                        break;
                    }
                    Some(Err(LinesCodecError::MaxLineLengthExceeded)) => {
                        term_reason = TermReason::ClientLineOverflow;
                        break;
                    }
                    Some(Err(LinesCodecError::Io(e))) => {
                        if e.kind() == std::io::ErrorKind::InvalidData {
                            // Invalid UTF-8 on the control channel — ignore
                            // the frame (match prior behavior of tolerating a
                            // single malformed line rather than disconnecting).
                            continue;
                        }
                        term_reason = TermReason::ClientDisconnect;
                        break;
                    }
                    Some(Ok(line)) => {
                        if let Ok(msg) = serde_json::from_str::<ClientMessage>(line.trim()) {
                            match msg {
                                ClientMessage::Stdin { data } => {
                                    stdin_received = true;
                                    if let Some(ref mut stdin) = child_stdin {
                                        let _ = stdin.write_all(data.as_bytes()).await;
                                    }
                                }
                                ClientMessage::StdinEof => {
                                    stdin_received = true;
                                    child_stdin = None; // Drop closes pipe.
                                }
                                _ => {} // Ignore other messages during exec.
                            }
                        }
                    }
                }
            }

            // Stdin auto-close: if no stdin messages within 2s, close the pipe
            // to prevent the child from blocking on stdin.
            _ = &mut stdin_timer, if !stdin_received && child_stdin.is_some() => {
                child_stdin = None; // Drop closes pipe.
            }

            // Exec timeout.
            _ = &mut timeout_timer => {
                term_reason = TermReason::Timeout;
                break;
            }
        }
    }

    // Ensure child's stdin is closed.
    drop(child_stdin);

    // ── Post-loop handling ──────────────────────────────────────────────────
    match term_reason {
        TermReason::ChildExited(status) => {
            // Wait for redaction tasks to complete so all output is flushed
            // through the channels.
            let _ = stdout_task.await;
            let _ = stderr_task.await;

            // Drain remaining output from channels.
            drain_channel_to_client(&mut stdout_rx, &mut writer, true).await;
            drain_channel_to_client(&mut stderr_rx, &mut writer, false).await;

            // Send exit message.
            let code = exit_code_from_status(status);
            let _ = write_ndjson_message(&mut writer, &DaemonMessage::Exit { code }).await;

            // Clean up.
            child_registry.remove(pid);
            ring_buffer.log(format!("tool {:?} exited (PID: {pid}, code: {code})", tool));
        }

        TermReason::ChildWaitError(e) => {
            // Unusual: wait() itself failed. Kill and report.
            let _ = exec::kill_process_group(pid, libc::SIGKILL);
            let code = -1;
            let _ = write_ndjson_message(&mut writer, &DaemonMessage::Exit { code }).await;
            child_registry.remove(pid);
            ring_buffer.log(format!("tool {:?} wait error (PID: {pid}): {e}", tool));
        }

        TermReason::Timeout => {
            ring_buffer.log(format!(
                "tool {:?} timed out after {:?} (PID: {pid})",
                tool, timeout
            ));

            sigterm_then_sigkill(&mut child, pid).await;

            // Send error to client.
            let msg = format!(
                "tool {:?} timed out after {} seconds",
                tool,
                timeout.as_secs()
            );
            let _ = write_ndjson_message(&mut writer, &DaemonMessage::Error { message: msg }).await;

            child_registry.remove(pid);
        }

        TermReason::ClientDisconnect => {
            ring_buffer.log(format!(
                "client disconnected during tool {:?} (PID: {pid})",
                tool
            ));

            sigterm_then_sigkill(&mut child, pid).await;

            child_registry.remove(pid);
            // No message to client — already disconnected.
        }

        TermReason::ClientLineOverflow => {
            ring_buffer.log(format!(
                "client sent stdin line exceeding {} bytes during tool {:?} (PID: {pid}); terminating",
                MAX_NDJSON_LINE_BYTES, tool
            ));

            sigterm_then_sigkill(&mut child, pid).await;

            // The tool has consumed bytes it can't fully see; report a clean
            // termination to the client rather than a bogus exit code.
            let _ = write_ndjson_message(
                &mut writer,
                &DaemonMessage::Error {
                    message: "stdin line exceeds maximum length".to_string(),
                },
            )
            .await;
            let _ = write_ndjson_message(&mut writer, &DaemonMessage::Exit { code: -1 }).await;

            child_registry.remove(pid);
        }
    }
}

// ─── Child lifecycle helpers ─────────────────────────────────────────────────

/// Send SIGTERM to the child's process group, wait up to [`KILL_GRACE_PERIOD`],
/// then escalate to SIGKILL if the child has not exited.
///
/// Used by both the Timeout and ClientDisconnect post-loop branches.
async fn sigterm_then_sigkill(child: &mut tokio::process::Child, pid: u32) {
    let _ = exec::kill_process_group(pid, libc::SIGTERM);

    let grace = tokio::time::sleep(KILL_GRACE_PERIOD);
    tokio::pin!(grace);

    tokio::select! {
        _ = child.wait() => {}
        _ = &mut grace => {
            let _ = exec::kill_process_group(pid, libc::SIGKILL);
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                child.wait(),
            )
            .await;
        }
    }
}

/// Drain all remaining redacted output from a channel and send it to the client.
///
/// `is_stdout` selects whether to wrap each chunk as a `Stdout` or `Stderr`
/// NDJSON message.
async fn drain_channel_to_client<W: tokio::io::AsyncWriteExt + Unpin>(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    writer: &mut W,
    is_stdout: bool,
) {
    while let Ok(bytes) = rx.try_recv() {
        let text = redact::bytes_to_lossy_utf8(&bytes);
        if !text.is_empty() {
            let msg = if is_stdout {
                DaemonMessage::Stdout { data: text }
            } else {
                DaemonMessage::Stderr { data: text }
            };
            let _ = write_ndjson_message(writer, &msg).await;
        }
    }
}

/// Set up an async reader -> sync channel -> blocking redact -> tokio mpsc pipeline
/// for a single output stream (stdout or stderr).
///
/// Returns the blocking task's `JoinHandle` (for awaiting completion) and the
/// unbounded receiver that delivers redacted byte chunks to the select loop.
fn spawn_redaction_pipeline<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    redactor: Arc<Redactor>,
    mut async_reader: R,
) -> (
    tokio::task::JoinHandle<std::io::Result<()>>,
    tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let (input_tx, input_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let (output_tx, output_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    let blocking_task = tokio::task::spawn_blocking(move || {
        let reader = ChannelReader::new(input_rx);
        let writer = ChannelWriter { tx: output_tx };
        redactor.redact_stream(reader, writer)
    });

    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 8192];
        loop {
            match async_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if input_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    (blocking_task, output_rx)
}

// ─── Redaction pipeline helpers ─────────────────────────────────────────────

/// A [`std::io::Read`] adapter that receives byte chunks from a
/// [`std::sync::mpsc::Receiver`].
///
/// Used in blocking redaction tasks: the async reader task sends child output
/// chunks through the channel, and this adapter presents them as a synchronous
/// byte stream suitable for [`Redactor::redact_stream`].
///
/// Returns `Ok(0)` (EOF) when the channel is closed (sender dropped).
struct ChannelReader {
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
    buffer: Vec<u8>,
    pos: usize,
}

impl ChannelReader {
    fn new(rx: std::sync::mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            buffer: Vec::new(),
            pos: 0,
        }
    }
}

impl std::io::Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Return buffered data first.
        if self.pos < self.buffer.len() {
            let available = self.buffer.len() - self.pos;
            let n = std::cmp::min(buf.len(), available);
            buf[..n].copy_from_slice(&self.buffer[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }

        // Wait for new data from the channel.
        match self.rx.recv() {
            Ok(data) => {
                if data.is_empty() {
                    return Ok(0);
                }
                let n = std::cmp::min(buf.len(), data.len());
                buf[..n].copy_from_slice(&data[..n]);
                if n < data.len() {
                    self.buffer = data;
                    self.pos = n;
                } else {
                    self.buffer.clear();
                    self.pos = 0;
                }
                Ok(n)
            }
            Err(_) => Ok(0), // Channel closed = EOF
        }
    }
}

/// A [`std::io::Write`] adapter that sends byte chunks through a tokio mpsc
/// channel.
///
/// Used by the redaction pipeline to bridge the synchronous
/// [`Redactor::redact_stream`](crate::redact::Redactor::redact_stream) with
/// the async daemon I/O loop. Each `write()` call sends a new `Vec<u8>` into
/// the channel; the async receiver collects these chunks for NDJSON serialization.
struct ChannelWriter {
    tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

impl std::io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.tx
            .send(buf.to_vec())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "receiver dropped"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Build a sandbox profile using the platform-appropriate backend.
///
/// On macOS, uses `MacOSSeatbelt`. On Linux, uses `LinuxLandlock`.
fn build_platform_sandbox_profile(
    policy: &sandbox::ToolPolicy,
) -> Result<sandbox::SandboxProfile, sandbox::SandboxError> {
    use sandbox::SandboxBackend;

    #[cfg(target_os = "macos")]
    {
        sandbox::macos::MacOSSeatbelt.build(policy)
    }

    #[cfg(target_os = "linux")]
    {
        sandbox::linux::LinuxLandlock.build(policy)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = policy;
        Err(sandbox::SandboxError::ProfileBuildError(
            "sandbox not supported on this platform".to_string(),
        ))
    }
}

/// Extract an exit code from a process exit status.
///
/// If the process exited normally, returns the exit code.
/// If killed by a signal, returns the negated signal number (e.g., -9 for SIGKILL).
fn exit_code_from_status(status: std::process::ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| -(status.signal().unwrap_or(0)))
}

/// Write an NDJSON message (single JSON line + newline) to the writer.
async fn write_ndjson_message<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &DaemonMessage,
) -> Result<(), std::io::Error> {
    let json = serde_json::to_string(msg).map_err(std::io::Error::other)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

// ─── Graceful shutdown ──────────────────────────────────────────────────────

/// Perform graceful shutdown: signal children, wait, cleanup files.
async fn graceful_shutdown(
    child_registry: &ChildRegistry,
    ring_buffer: &RingBuffer,
    socket_path: &Path,
    pid_path: &Path,
) {
    // Signal all active children with SIGTERM.
    let pids = child_registry.all();
    if !pids.is_empty() {
        ring_buffer.log(format!(
            "sending SIGTERM to {} active child process group(s)",
            pids.len()
        ));
        for &pid in &pids {
            let _ = exec::kill_process_group(pid, libc::SIGTERM);
        }

        // Wait for children to exit (up to grace period).
        tokio::time::sleep(SHUTDOWN_GRACE_PERIOD).await;

        // Kill stragglers.
        let remaining = child_registry.all();
        if !remaining.is_empty() {
            ring_buffer.log(format!(
                "sending SIGKILL to {} remaining child process group(s)",
                remaining.len()
            ));
            for &pid in &remaining {
                let _ = exec::kill_process_group(pid, libc::SIGKILL);
            }
        }
    }

    // Remove socket file.
    if let Err(e) = std::fs::remove_file(socket_path) {
        ring_buffer.log(format!("failed to remove socket file: {e}"));
    }

    // Remove PID file.
    if let Err(e) = std::fs::remove_file(pid_path) {
        ring_buffer.log(format!("failed to remove PID file: {e}"));
    }

    ring_buffer.log("shutdown complete".to_string());
}

// ─── PID file management ────────────────────────────────────────────────────

/// Write the daemon's PID to the PID file.
///
/// Uses `O_CREAT | O_EXCL` with mode `0o600` in a single `open(2)` syscall so
/// that:
/// - Two daemons racing past the stale-cleanup check cannot both successfully
///   write the PID file; the second caller sees `ErrorKind::AlreadyExists` and
///   returns `DaemonError::AlreadyRunning`.
/// - The file is never visible on disk with a more permissive mode than
///   `0o600` (there is no "chmod after write" race window).
fn write_pid_file(pid_path: &Path, pid: u32) -> Result<(), DaemonError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true) // O_CREAT | O_EXCL
        .mode(0o600)
        .open(pid_path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another daemon raced past `check_and_cleanup_stale_state` and
            // created the PID file before we got here. Surface this as an
            // AlreadyRunning error; the PID is unknown at this point (reading
            // it would itself be TOCTOU-prone).
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

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Ring buffer tests ──────────────────────────────────────────────────

    #[test]
    fn ring_buffer_empty_returns_no_entries() {
        let buf = RingBuffer::new();
        assert!(buf.entries().is_empty());
    }

    #[test]
    fn ring_buffer_single_entry_retrievable() {
        let buf = RingBuffer::new();
        buf.log("test entry");
        let entries = buf.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "test entry");
        assert!(!entries[0].timestamp.is_empty());
    }

    #[test]
    fn ring_buffer_multiple_entries_in_order() {
        let buf = RingBuffer::new();
        buf.log("first");
        buf.log("second");
        buf.log("third");
        let entries = buf.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].message, "first");
        assert_eq!(entries[1].message, "second");
        assert_eq!(entries[2].message, "third");
    }

    #[test]
    fn ring_buffer_at_capacity_retains_all() {
        let buf = RingBuffer::new();
        for i in 0..RING_BUFFER_CAPACITY {
            buf.log(format!("entry-{i}"));
        }
        let entries = buf.entries();
        assert_eq!(entries.len(), RING_BUFFER_CAPACITY);
        assert_eq!(entries[0].message, "entry-0");
        assert_eq!(
            entries[RING_BUFFER_CAPACITY - 1].message,
            format!("entry-{}", RING_BUFFER_CAPACITY - 1)
        );
    }

    #[test]
    fn ring_buffer_beyond_capacity_evicts_oldest() {
        let buf = RingBuffer::new();
        for i in 0..=RING_BUFFER_CAPACITY {
            buf.log(format!("entry-{i}"));
        }
        let entries = buf.entries();
        assert_eq!(entries.len(), RING_BUFFER_CAPACITY);
        // The oldest ("entry-0") should have been evicted.
        assert_eq!(entries[0].message, "entry-1");
        assert_eq!(
            entries[RING_BUFFER_CAPACITY - 1].message,
            format!("entry-{RING_BUFFER_CAPACITY}")
        );
    }

    #[test]
    fn ring_buffer_chronological_order() {
        let buf = RingBuffer::new();
        for i in 0..50 {
            buf.log(format!("msg-{i}"));
        }
        let entries = buf.entries();
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry.message, format!("msg-{i}"));
        }
    }

    #[tokio::test]
    async fn ring_buffer_concurrent_access() {
        let buf = RingBuffer::new();
        let mut handles = Vec::new();

        for i in 0..10 {
            let buf_clone = buf.clone();
            handles.push(tokio::spawn(async move {
                for j in 0..100 {
                    buf_clone.log(format!("task-{i}-msg-{j}"));
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let entries = buf.entries();
        assert_eq!(entries.len(), 1000);
    }

    // ── Active child registry tests ────────────────────────────────────────

    #[test]
    fn registry_insert_and_iterate() {
        let reg = ChildRegistry::new();
        reg.insert(100);
        reg.insert(200);
        let pids = reg.all();
        assert!(pids.contains(&100));
        assert!(pids.contains(&200));
        assert_eq!(pids.len(), 2);
    }

    #[test]
    fn registry_remove() {
        let reg = ChildRegistry::new();
        reg.insert(100);
        reg.insert(200);
        reg.remove(100);
        let pids = reg.all();
        assert!(!pids.contains(&100));
        assert!(pids.contains(&200));
        assert_eq!(pids.len(), 1);
    }

    #[test]
    fn registry_duplicate_insert_is_idempotent() {
        let reg = ChildRegistry::new();
        reg.insert(100);
        reg.insert(100);
        reg.insert(100);
        let pids = reg.all();
        assert_eq!(pids.len(), 1);
        assert!(pids.contains(&100));
    }

    #[test]
    fn registry_remove_nonexistent_is_noop() {
        let reg = ChildRegistry::new();
        reg.insert(100);
        reg.remove(999); // Does not exist.
        let pids = reg.all();
        assert_eq!(pids.len(), 1);
    }

    #[tokio::test]
    async fn registry_concurrent_access() {
        let reg = ChildRegistry::new();
        let mut handles = Vec::new();

        for i in 0..10 {
            let reg_clone = reg.clone();
            handles.push(tokio::spawn(async move {
                for j in 0..100 {
                    let pid = (i * 1000 + j) as u32 + 2; // Ensure PIDs >= 2
                    reg_clone.insert(pid);
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let pids = reg.all();
        assert_eq!(pids.len(), 1000);
    }

    // ── Stale state detection tests ────────────────────────────────────────

    #[test]
    fn stale_detection_no_pid_file_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_path = tmp.path().join("airlock.pid");
        let socket_path = tmp.path().join("airlock.sock");

        let result = check_and_cleanup_stale_state(&pid_path, &socket_path);
        assert!(result.is_ok());
    }

    #[test]
    fn stale_detection_dead_process_cleans_up() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_path = tmp.path().join("airlock.pid");
        let socket_path = tmp.path().join("airlock.sock");

        // Write a PID that is (almost certainly) dead.
        // Use a very high PID that is unlikely to be running.
        std::fs::write(&pid_path, "999999999\n").unwrap();
        std::fs::write(&socket_path, "dummy").unwrap();

        let result = check_and_cleanup_stale_state(&pid_path, &socket_path);
        assert!(result.is_ok());
        assert!(!pid_path.exists(), "PID file should be cleaned up");
        assert!(!socket_path.exists(), "socket file should be cleaned up");
    }

    #[test]
    fn stale_detection_live_process_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_path = tmp.path().join("airlock.pid");
        let socket_path = tmp.path().join("airlock.sock");

        // Use our own PID (definitely alive).
        let my_pid = std::process::id();
        std::fs::write(&pid_path, format!("{my_pid}\n")).unwrap();

        let result = check_and_cleanup_stale_state(&pid_path, &socket_path);
        assert!(result.is_err());
        let err = result.unwrap_err();
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

    #[test]
    fn stale_detection_stale_socket_without_pid_file_cleaned_up() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_path = tmp.path().join("airlock.pid");
        let socket_path = tmp.path().join("airlock.sock");

        // No PID file, but socket exists.
        std::fs::write(&socket_path, "stale").unwrap();

        let result = check_and_cleanup_stale_state(&pid_path, &socket_path);
        assert!(result.is_ok());
        assert!(!socket_path.exists(), "stale socket should be cleaned up");
    }

    #[test]
    fn stale_detection_live_socket_without_pid_file_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_path = tmp.path().join("airlock.pid");
        let socket_path = tmp.path().join("airlock.sock");

        // A live listener with no PID file is the signature of an embedded
        // `airlock run` daemon. Cleanup must refuse with `SocketInUse` and
        // leave the socket in place rather than silently severing it.
        let _listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

        let result = check_and_cleanup_stale_state(&pid_path, &socket_path);
        assert!(
            matches!(result, Err(DaemonError::SocketInUse { .. })),
            "expected SocketInUse, got: {result:?}"
        );
        assert!(
            socket_path.exists(),
            "a live daemon's socket must not be removed"
        );
    }

    // ── PID file management tests ──────────────────────────────────────────

    #[test]
    fn write_pid_file_creates_correct_content() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_path = tmp.path().join("airlock.pid");

        write_pid_file(&pid_path, 12345).unwrap();

        let contents = std::fs::read_to_string(&pid_path).unwrap();
        assert_eq!(contents, "12345\n");
    }

    #[test]
    fn write_pid_file_contains_decimal_integer() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_path = tmp.path().join("airlock.pid");

        write_pid_file(&pid_path, 1).unwrap();

        let contents = std::fs::read_to_string(&pid_path).unwrap();
        let parsed: u32 = contents.trim().parse().unwrap();
        assert_eq!(parsed, 1);
    }

    #[test]
    fn write_pid_file_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let pid_path = tmp.path().join("airlock.pid");

        write_pid_file(&pid_path, 42).unwrap();

        let metadata = std::fs::metadata(&pid_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "PID file should be owner-only (0o600), got {mode:#o}"
        );
    }

    #[test]
    fn write_pid_file_refuses_when_file_exists() {
        // A second write to the same path must fail with AlreadyRunning —
        // verifying the O_CREAT|O_EXCL atomic-create semantics.
        let tmp = tempfile::tempdir().unwrap();
        let pid_path = tmp.path().join("airlock.pid");

        write_pid_file(&pid_path, 1).unwrap();

        let err = write_pid_file(&pid_path, 2).expect_err("second write should fail");
        assert!(
            matches!(err, DaemonError::AlreadyRunning { .. }),
            "expected AlreadyRunning, got {err:?}"
        );

        // First write's contents must be preserved — no truncation by the
        // failed second call.
        let contents = std::fs::read_to_string(&pid_path).unwrap();
        assert_eq!(contents, "1\n");
    }

    #[test]
    fn socket_created_with_restrictive_umask_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let socket_path = tmp.path().join("test.sock");

        // Reproduce the same umask pattern used in synchronous_startup().
        let old_umask = rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);
        let _listener = unix_net::UnixListener::bind(&socket_path).unwrap();
        rustix::process::umask(old_umask);

        let metadata = std::fs::symlink_metadata(&socket_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "socket should be owner-only (0o700), got {mode:#o}"
        );
    }

    // ── Socket permission verification tests ────────────────────────────────

    #[test]
    fn verify_socket_permissions_accepts_owner_only() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_path = tmp.path().join("good.sock");

        let old_umask = rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);
        let _listener = unix_net::UnixListener::bind(&socket_path).unwrap();
        rustix::process::umask(old_umask);

        let result = verify_socket_permissions(&socket_path);
        assert!(result.is_ok(), "owner-only socket should pass: {result:?}");
    }

    #[test]
    fn verify_socket_permissions_rejects_group_readable() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let socket_path = tmp.path().join("bad.sock");

        // Create socket then widen permissions to simulate a bad filesystem.
        let old_umask = rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);
        let _listener = unix_net::UnixListener::bind(&socket_path).unwrap();
        rustix::process::umask(old_umask);

        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o750)).unwrap();

        let result = verify_socket_permissions(&socket_path);
        assert!(result.is_err(), "group-readable socket should be rejected");

        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("insecure permissions"),
            "error should mention insecure permissions: {msg}"
        );
        // Socket should NOT be deleted — leave it for the user to inspect.
        assert!(
            socket_path.exists(),
            "insecure socket should be left for user to inspect"
        );
    }

    #[test]
    fn verify_socket_permissions_rejects_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let socket_path = tmp.path().join("bad.sock");

        let old_umask = rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);
        let _listener = unix_net::UnixListener::bind(&socket_path).unwrap();
        rustix::process::umask(old_umask);

        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let result = verify_socket_permissions(&socket_path);
        assert!(result.is_err(), "world-readable socket should be rejected");
        // Socket should NOT be deleted — leave it for the user to inspect.
        assert!(
            socket_path.exists(),
            "insecure socket should be left for user to inspect"
        );
    }

    // ── Timestamp format tests ─────────────────────────────────────────────

    #[test]
    fn timestamp_format_is_iso8601() {
        let ts = now_timestamp();
        // Should match YYYY-MM-DDTHH:MM:SSZ pattern.
        assert!(ts.len() >= 20, "timestamp too short: {ts}");
        assert!(ts.ends_with('Z'), "timestamp should end with Z: {ts}");
        assert!(ts.contains('T'), "timestamp should contain T: {ts}");
    }

    // ── DaemonError tests ──────────────────────────────────────────────────

    #[test]
    fn daemon_error_is_std_error() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<DaemonError>();
    }

    #[test]
    fn daemon_error_display_already_running() {
        let err = DaemonError::AlreadyRunning { pid: 42 };
        let msg = err.to_string();
        assert!(msg.contains("already running"));
        assert!(msg.contains("42"));
    }

    #[test]
    fn daemon_error_display_socket_bind() {
        let err = DaemonError::SocketBind {
            path: PathBuf::from("/tmp/test.sock"),
            source: std::io::Error::new(std::io::ErrorKind::AddrInUse, "in use"),
        };
        let msg = err.to_string();
        assert!(msg.contains("/tmp/test.sock"));
    }

    #[test]
    fn daemon_error_display_socket_permissions() {
        let err = DaemonError::SocketPermissions {
            path: PathBuf::from("/tmp/test.sock"),
            actual: 0o755,
            expected: 0o700,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("insecure permissions"),
            "should mention insecure permissions: {msg}"
        );
        assert!(
            msg.contains("/tmp/test.sock"),
            "should contain the path: {msg}"
        );
        assert!(msg.contains("0o755"), "should show actual mode: {msg}");
    }

    // ── run_embedded tests ─────────────────────────────────────────────────

    /// `run_embedded` must exit cleanly when the oneshot sender is dropped
    /// (the expected programmatic shutdown signal from `run.rs`).
    #[tokio::test]
    async fn run_embedded_exits_on_cancel() {
        let tmp = tempfile::tempdir().unwrap();

        // Minimal valid config: an empty airlock.toml in a fresh directory.
        std::fs::write(tmp.path().join("airlock.toml"), "").unwrap();

        let state = match synchronous_startup(tmp.path(), None) {
            Ok(s) => s,
            // AlreadyRunning cannot happen with a fresh tempdir (no PID file
            // exists). Guard defensively so the test skips rather than panics
            // if something unexpected occurs in a constrained CI environment.
            Err(DaemonError::AlreadyRunning { .. }) => return,
            Err(e) => panic!("synchronous_startup failed: {e}"),
        };

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        // Spawn the embedded daemon.
        let task = tokio::spawn(run_embedded(state, rx));

        // Drop the sender immediately — this signals cancel.
        drop(tx);

        // The task must complete without error within a short timeout.
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("run_embedded did not complete within 1 second")
            .expect("task panicked")
            .expect("run_embedded returned Err");
    }

    /// When an explicit config path is provided, `synchronous_startup` must
    /// derive `sandbox_root` (and therefore `socket_path` / `pid_path`) from
    /// the config file's parent directory, not from `start_dir`.
    #[test]
    fn synchronous_startup_explicit_path_uses_parent_as_sandbox_root() {
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("airlock.toml");
        std::fs::write(&config_path, "").unwrap();

        // `start_dir` is an unrelated directory — must not affect sandbox_root.
        let unrelated_dir = tempfile::tempdir().unwrap();

        let result = synchronous_startup(unrelated_dir.path(), Some(&config_path));

        match result {
            Ok(state) => {
                // Clean up the socket that synchronous_startup bound.
                let _ = std::fs::remove_file(&state.config.socket_path);

                let expected_root = config_dir.path().canonicalize().unwrap();
                assert_eq!(
                    state.config.sandbox_root, expected_root,
                    "sandbox_root should be the config file's parent, not start_dir"
                );
            }
            // AlreadyRunning cannot happen with a fresh tempdir; guard defensively.
            Err(DaemonError::AlreadyRunning { .. }) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
