//! Process execution, binary resolution, and environment construction.
//!
//! This module is responsible for:
//! - Resolving bare binary names to absolute executable paths via `PATH` walking
//! - Building a clean, minimal environment map for child processes
//! - Bundling pre-fork state into [`ExecRequest`] for consumption by [`spawn`]
//! - Spawning sandboxed child processes with [`spawn`]
//! - Sending signals to child process groups with [`kill_process_group`]
//!
//! All potentially-failing work (binary resolution, environment construction,
//! sandbox profile generation) must complete before the fork so that failures
//! surface as clean errors to the caller rather than as cryptic post-fork failures,
//! and to ensure no Rust allocation is required inside the `pre_exec` closure.
//!
//! # Why `Child::kill()` must never be used
//!
//! [`tokio::process::Child::kill()`] sends `SIGKILL` to the direct child PID
//! only. If the tool has spawned subprocesses (grandchildren), they remain alive
//! as orphans in the process group. The [`kill_process_group`] helper sends the
//! signal to the entire process group via `kill(-pgid, signal)`, ensuring all
//! processes in the group — including grandchildren — receive the signal.
//! All callers must use [`kill_process_group`] instead of `Child::kill()`.
//! `kill_on_drop` must also remain `false` for the same reason.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};

use crate::sandbox::SandboxProfile;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors that can occur during binary resolution, spawn preparation, or spawn.
#[derive(Debug, Error)]
pub enum ExecError {
    /// The tool name contains a `/` path separator.
    ///
    /// Only bare binary names (e.g., `"sh"`, `"python3"`) are accepted;
    /// absolute or relative paths (e.g., `"/usr/bin/sh"`, `"./script"`) are not.
    #[error(
        "tool name contains a path separator ('/'): only bare binary names are accepted, \
         not paths: {0:?}"
    )]
    PathSeparatorInName(String),

    /// The `PATH` environment variable is not set in the daemon's environment.
    #[error("PATH environment variable is not set in the daemon's environment")]
    PathNotSet,

    /// No executable with the given name was found in any directory in `PATH`.
    #[error("binary {0:?} not found in PATH")]
    BinaryNotFound(String),

    /// The child process could not be spawned.
    ///
    /// This includes errors from the `pre_exec` closure (e.g., `setpgid` failure,
    /// sandbox application failure) as well as OS-level fork/exec errors.
    #[error("failed to spawn child process: {0}")]
    SpawnFailed(#[source] std::io::Error),

    /// The child PID passed to [`kill_process_group`] is invalid.
    ///
    /// PID 0 would signal the calling process's own group; PID 1 would signal
    /// every process the caller can reach (`kill(-1, sig)`); PIDs larger than
    /// `i32::MAX` overflow on negation. All three are rejected to prevent
    /// catastrophic mis-signals.
    #[error(
        "invalid child PID {0} for kill_process_group: must be >= 2 and <= i32::MAX (2147483647)"
    )]
    InvalidKillPid(u32),
}

// ─── Constants ────────────────────────────────────────────────────────────────

/// Essential environment variables copied from the daemon's environment into
/// every child process's environment, regardless of declared secrets.
///
/// The set is deliberately small. It covers what almost every CLI needs to
/// behave correctly: process basics (`PATH`, `HOME`, `USER`), terminal
/// rendering (`TERM`), timezone (`TZ` — without it, tools that print
/// timestamps render in UTC or some surprising default), and the standard
/// locale family (`LANG` plus the `LC_*` overrides — without these, sort
/// orders, number/date formatting, and message translations vary in subtle
/// ways across hosts).
///
/// If any of these variables is absent from the daemon's environment, it is
/// silently omitted from the child's environment — this is not an error.
const ESSENTIAL_VARS: &[&str] = &[
    "PATH",
    "HOME",
    "TERM",
    "USER",
    "TZ",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_COLLATE",
    "LC_MONETARY",
    "LC_MESSAGES",
];

// ─── Binary resolution ────────────────────────────────────────────────────────

/// Check whether `path` is executable by the current process.
///
/// Uses the POSIX `access(2)` syscall with `X_OK` to probe execute permission.
fn is_executable(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    let bytes = path.as_os_str().as_bytes();
    let Ok(cstr) = std::ffi::CString::new(bytes) else {
        return false;
    };
    // SAFETY: access(2) with X_OK reads kernel file-permission state without
    // modifying memory. It returns -1 with EACCES/ENOENT when not accessible.
    unsafe { libc::access(cstr.as_ptr(), libc::X_OK) == 0 }
}

/// Walk a colon-separated `path_var` string to find an executable binary.
///
/// This inner function accepts an explicit `path_var` so that tests can drive
/// it without manipulating the process environment.
///
/// Non-existent directories are silently skipped; the search continues to the
/// next `PATH` entry. An empty `path_var` or a `path_var` that contains only
/// non-existent directories returns [`ExecError::BinaryNotFound`].
fn resolve_binary_in(tool_name: &str, path_var: &str) -> Result<PathBuf, ExecError> {
    for dir in path_var.split(':') {
        if dir.is_empty() {
            // Skip empty components produced by leading/trailing colons or
            // consecutive colons (e.g. "dir1::dir2", ":dir", "dir:").
            continue;
        }

        let candidate = Path::new(dir).join(tool_name);

        // `metadata()` follows symlinks and returns `Err` if the path does not
        // exist or is not accessible — we skip that directory silently.
        if let Ok(meta) = std::fs::metadata(&candidate)
            && meta.is_file()
            && is_executable(&candidate)
        {
            // Canonicalize to resolve symlinks and produce a clean absolute path.
            // If canonicalization fails (e.g., a race where the file was removed
            // between the metadata check and the canonicalize call), fall back to
            // the already-absolute candidate path.
            let resolved = std::fs::canonicalize(&candidate).unwrap_or(candidate);
            return Ok(resolved);
        }
        // Directory did not exist, or the binary was not found / not executable:
        // silently continue to the next PATH entry.
    }

    Err(ExecError::BinaryNotFound(tool_name.to_string()))
}

/// Resolve a bare binary name to its absolute canonical path by walking `PATH`.
///
/// Resolution happens at request time (not at daemon startup), so tools
/// installed after the daemon starts are found correctly.
///
/// # Errors
///
/// - [`ExecError::PathSeparatorInName`] — `tool_name` contains a `'/'`.
/// - [`ExecError::PathNotSet`] — the `PATH` environment variable is not set.
/// - [`ExecError::BinaryNotFound`] — no executable with `tool_name` was found
///   in any directory listed in `PATH`.
pub fn resolve_binary(tool_name: &str) -> Result<PathBuf, ExecError> {
    // Reject names that contain a path separator character.
    if tool_name.contains('/') {
        return Err(ExecError::PathSeparatorInName(tool_name.to_string()));
    }

    let path_var = std::env::var("PATH").map_err(|_| ExecError::PathNotSet)?;
    resolve_binary_in(tool_name, &path_var)
}

// ─── Environment construction ─────────────────────────────────────────────────

/// Build a clean, minimal environment map for a child process.
///
/// The returned map contains exactly:
/// - The tool's declared `secrets` (already unwrapped from `Secret<String>`
///   by the caller; this function does not interact with the `redact` crate).
/// - Essential pass-through variables (see [`ESSENTIAL_VARS`]) — process
///   basics, terminal, timezone, and the standard locale family — copied
///   from the daemon's environment. An essential variable absent from the
///   daemon's environment is silently omitted; this is not an error.
///
/// No other variables from the daemon's environment or any other source are
/// included. Isolation from the daemon's environment is intentional.
///
/// If a secret's name collides with an essential variable name (e.g. a secret
/// named `"PATH"`), the essential variable value from the daemon's environment
/// takes precedence, ensuring critical runtime variables are never replaced.
pub fn build_env(secrets: &[(String, String)]) -> HashMap<String, String> {
    let mut env = HashMap::new();

    // Insert declared secrets first.
    for (name, value) in secrets {
        env.insert(name.clone(), value.clone());
    }

    // Layer in essential pass-through variables. Written after secrets so that
    // essential variables take precedence if their name collides with a secret name.
    for var in ESSENTIAL_VARS {
        if let Ok(value) = std::env::var(var) {
            env.insert((*var).to_string(), value);
        }
    }

    env
}

// ─── ExecRequest ─────────────────────────────────────────────────────────────

/// All pre-fork state required by [`spawn`].
///
/// `ExecRequest` bundles the resolved binary path, argument list, working
/// directory, clean environment, pre-built sandbox profile, and effective
/// timeout into a single value that is consumed by `exec::spawn()`.
///
/// `ExecRequest` is intentionally **not** `Clone`: on Linux, `SandboxProfile`
/// owns an `OwnedFd` (the Landlock ruleset file descriptor) that must not be
/// duplicated, so cloning would be semantically incorrect.
pub struct ExecRequest {
    /// Absolute, canonical path to the executable binary (produced by
    /// [`resolve_binary`]).
    pub binary: PathBuf,

    /// Argument list — the full `argv` after the binary name (i.e., `argv[1..]`).
    pub args: Vec<String>,

    /// Working directory for the child process.
    ///
    /// Pre-validated by the policy layer as being within the sandbox root;
    /// this module does not re-validate it.
    pub work_dir: PathBuf,

    /// Clean environment map for the child process (produced by [`build_env`]).
    pub env: HashMap<String, String>,

    /// Pre-built, platform-specific sandbox profile produced by a
    /// `SandboxBackend`. Consumed by [`spawn`]'s `pre_exec` closure.
    pub sandbox_profile: SandboxProfile,

    /// Effective timeout for this invocation.
    ///
    /// Resolved by the caller from the per-tool timeout override or the
    /// global default; [`spawn`] enforces it via a watchdog.
    pub timeout: Duration,
}

// ─── SendSyncPtr (macOS only) ────────────────────────────────────────────────

/// Newtype wrapper around a raw `*const c_char` pointer that implements
/// `Send` and `Sync`.
///
/// Used exclusively to satisfy the `Send + Sync + 'static` bound on the
/// `pre_exec` closure on macOS, where we need to capture a raw pointer to
/// the pre-built SBPL profile bytes.
///
/// # Safety
///
/// This is safe because:
/// - The pointed-to data (a `CString` owned by `SandboxProfile`) lives for
///   the duration of the `spawn()` call — the `SandboxProfile` is not dropped
///   until after `tokio::process::Command::spawn()` returns.
/// - The `pre_exec` closure runs only in the single-threaded child context
///   after fork, so no concurrent access occurs.
#[cfg(target_os = "macos")]
struct SendSyncPtr(*const std::ffi::c_char);

#[cfg(target_os = "macos")]
unsafe impl Send for SendSyncPtr {}

#[cfg(target_os = "macos")]
unsafe impl Sync for SendSyncPtr {}

#[cfg(target_os = "macos")]
impl SendSyncPtr {
    /// Returns the wrapped raw pointer.
    ///
    /// Using a method rather than direct field access (`.0`) ensures the
    /// closure captures the entire `SendSyncPtr` wrapper — not just the inner
    /// `*const c_char` field, which would fail `Send + Sync` bounds under
    /// Rust 2021+ disjoint closure captures.
    fn as_ptr(&self) -> *const std::ffi::c_char {
        self.0
    }
}

// ─── SpawnedChild ────────────────────────────────────────────────────────────

/// The result of a successful [`spawn`] call.
///
/// Contains the child's direct PID, the `tokio::process::Child` handle (for
/// awaiting exit), and the three pipe handles for stdin/stdout/stderr.
///
/// All pipe handles are taken from the `Child` immediately upon spawn. The
/// caller must not re-take them from `Child` after receiving `SpawnedChild`.
#[derive(Debug)]
pub struct SpawnedChild {
    /// The direct child PID, used by [`kill_process_group`] and the daemon's
    /// active-child registry.
    pub pid: u32,

    /// The `tokio::process::Child` handle, used to await the child's exit
    /// status via `child.wait()`.
    pub child: Child,

    /// Async reader for the child's standard output pipe.
    pub stdout: ChildStdout,

    /// Async reader for the child's standard error pipe.
    pub stderr: ChildStderr,

    /// Async writer for the child's standard input pipe.
    pub stdin: ChildStdin,
}

// ─── spawn ───────────────────────────────────────────────────────────────────

/// Spawn a sandboxed child process according to the given [`ExecRequest`].
///
/// This function:
/// 1. Configures a `tokio::process::Command` with the resolved binary path,
///    arguments, working directory, and clean environment.
/// 2. Registers a `pre_exec` closure that places the child in its own process
///    group and applies the platform-specific sandbox.
/// 3. Forks the daemon process via `Command::spawn()`.
/// 4. On Linux, closes the parent's copy of the Landlock ruleset fd.
/// 5. Extracts and returns the child PID, `Child` handle, and pipe handles.
///
/// The `pre_exec` closure contains **no Rust allocation** — no `String`, `Vec`,
/// `Box`, `format!`, or any heap-allocating call. Only async-signal-safe
/// operations are performed.
///
/// `kill_on_drop` is intentionally **not** set to `true`. See the module-level
/// documentation for why `Child::kill()` must never be used.
///
/// # Errors
///
/// Returns [`ExecError::SpawnFailed`] if the child cannot be spawned, including
/// errors propagated from the `pre_exec` closure (e.g., `setpgid` failure or
/// sandbox application failure). When `pre_exec` fails, no child process
/// remains — Rust's `Command` infrastructure ensures the child exits.
// `mut` is needed on Linux for `close_ruleset_fd()` after spawn.
#[allow(unused_mut)]
pub fn spawn(mut request: ExecRequest) -> Result<SpawnedChild, ExecError> {
    let mut cmd = tokio::process::Command::new(&request.binary);
    cmd.args(&request.args);
    cmd.current_dir(&request.work_dir);

    // Clear the inherited environment entirely, then insert only the clean
    // environment map from ExecRequest.
    cmd.env_clear();
    for (key, value) in &request.env {
        cmd.env(key, value);
    }

    // Set all three stdio handles to piped mode.
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    // NOTE: kill_on_drop is NOT set to true. It remains at its default of false.
    // See the module-level documentation for why Child::kill() must never be used.

    // ── Register the pre_exec closure (platform-specific) ────────────────
    //
    // The closure runs in the child between fork and exec. It performs:
    // 1. setpgid(0, 0) — places the child in its own process group.
    // 2. Platform-specific sandbox application.
    //
    // The closure must NOT:
    // - Perform any Rust allocation (no String, Vec, Box, format!, etc.)
    // - Call any Tokio APIs
    // - Use buffered IO (no println!, eprintln!)
    //
    // Only async-signal-safe operations are permitted.

    #[cfg(target_os = "macos")]
    {
        // Capture the raw pointer to the pre-built SBPL bytes. The SendSyncPtr
        // wrapper satisfies the Send + Sync bound required by pre_exec.
        let sbpl_ptr = SendSyncPtr(request.sandbox_profile.as_ptr());

        // SAFETY: The pre_exec closure runs between fork and exec in the child.
        // All operations are async-signal-safe with no allocation. The SBPL
        // pointer is valid because the SandboxProfile (which owns the CString)
        // lives until after Command::spawn() returns. The closure captures
        // SendSyncPtr (which is Send + Sync) rather than the raw pointer.
        unsafe {
            cmd.pre_exec(move || {
                // 1. Place child in its own process group (pgid = child PID).
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // 2. Apply macOS Seatbelt sandbox. The sandbox_init() call is
                // irreversible — no cleanup is possible or needed on success.
                let mut errorbuf: *mut std::ffi::c_char = std::ptr::null_mut();
                let ret = crate::sandbox::macos::sandbox_init(sbpl_ptr.as_ptr(), 0, &mut errorbuf);
                if ret != 0 {
                    // Free the error string allocated by sandbox_init before
                    // returning the error to the parent.
                    if !errorbuf.is_null() {
                        crate::sandbox::macos::sandbox_free_error(errorbuf);
                    }
                    return Err(std::io::Error::last_os_error());
                }

                Ok(())
            });
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Capture the raw fd integer. i32 is Copy + Send + Sync + 'static,
        // so no wrapper is needed.
        let raw_fd = request.sandbox_profile.raw_fd();

        // SAFETY: The pre_exec closure runs between fork and exec in the child.
        // All operations are async-signal-safe with no allocation. The raw fd
        // is inherited across fork and valid in the child until exec replaces
        // the process image.
        unsafe {
            cmd.pre_exec(move || {
                // 1. Place child in its own process group (pgid = child PID).
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // 2. Prevent the child from gaining new privileges. This is
                // required before landlock_restrict_self can be called.
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // 3. Apply the Landlock sandbox via raw syscall. The landlock
                // crate's restrict_self() method is NOT used here because its
                // return type is incompatible with the pre_exec closure.
                if libc::syscall(libc::SYS_landlock_restrict_self, raw_fd, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(())
            });
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        // On unsupported platforms, only set the process group.
        // No sandbox is applied.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    // ── Spawn the child process ──────────────────────────────────────────
    //
    // Inherited fd hygiene: the child does not need any of the daemon's open
    // fds beyond stdin/stdout/stderr (set above via `Stdio::piped()`) and, on
    // Linux, the Landlock ruleset fd applied inside the pre-exec closure. We
    // do not run an explicit `close_range(3, ~0u32, CLOSE_RANGE_CLOEXEC)` call
    // because tokio's Unix sockets and pipes are all created with
    // `O_CLOEXEC`/`SOCK_CLOEXEC` atomically by mio — the ownership chain is:
    //   tokio → mio → `mio::sys::unix::net::new_socket` (uses `SOCK_CLOEXEC`)
    //         and `mio::sys::unix::pipe::new` (uses `O_CLOEXEC`).
    // See https://github.com/tokio-rs/mio/blob/master/src/sys/unix/net.rs
    //   and https://github.com/tokio-rs/mio/blob/master/src/sys/unix/pipe.rs
    // An explicit fd sweep here would also risk closing fds tokio is holding
    // for its own runtime, so we rely on `CLOEXEC` instead.
    let mut child = cmd.spawn().map_err(ExecError::SpawnFailed)?;

    // ── Post-spawn fd cleanup (Linux only) ───────────────────────────────
    // Close the parent's copy of the Landlock ruleset fd immediately. The
    // child has already inherited it across fork and applied it via
    // landlock_restrict_self. Leaving it open would leak one fd per
    // execution in the daemon process.
    #[cfg(target_os = "linux")]
    request.sandbox_profile.close_ruleset_fd();

    // ── Extract child PID and pipe handles ───────────────────────────────
    // The PID is available immediately after spawn. The pipe handles are
    // taken from the Child and stored in SpawnedChild so the caller does
    // not need to (and must not) re-take them.
    let pid = child
        .id()
        .expect("child PID should be available immediately after spawn");
    let stdout = child
        .stdout
        .take()
        .expect("stdout pipe should be available (set to piped)");
    let stderr = child
        .stderr
        .take()
        .expect("stderr pipe should be available (set to piped)");
    let stdin = child
        .stdin
        .take()
        .expect("stdin pipe should be available (set to piped)");

    Ok(SpawnedChild {
        pid,
        child,
        stdout,
        stderr,
        stdin,
    })
}

// ─── Process-group kill helper ───────────────────────────────────────────────

/// Send a signal to the entire process group of a child.
///
/// This is the **exclusive** kill mechanism used across all paths in the daemon.
/// [`tokio::process::Child::kill()`] and `kill_on_drop` are never used because
/// they only signal the direct child PID, leaving grandchildren alive as orphans.
///
/// The function negates the child PID to produce the process group ID argument
/// for `kill(2)`: `kill(-pgid, signal)` sends the signal to every process in
/// the group.
///
/// The caller is responsible for the grace-period logic: call with
/// `libc::SIGTERM` first, wait, then call with `libc::SIGKILL` if the child
/// has not yet exited.
///
/// # Arguments
///
/// * `child_pid` — The direct child's PID (as returned in [`SpawnedChild::pid`]).
///   Must be `>= 2` and `<= i32::MAX`.
/// * `signal` — The signal number to send (e.g., `libc::SIGTERM`, `libc::SIGKILL`).
///
/// # Errors
///
/// - [`ExecError::InvalidKillPid`] if `child_pid` is 0, 1, or `> i32::MAX`.
///   PID 0 would signal the calling process's own group; PID 1 would produce
///   `kill(-1, sig)` which targets every process the caller can reach; values
///   above `i32::MAX` overflow on cast to `i32`.
/// - [`std::io::Error`] if the underlying `kill(2)` syscall fails (e.g., the
///   process group no longer exists, or the signal number is invalid).
pub fn kill_process_group(child_pid: u32, signal: i32) -> Result<(), ExecError> {
    // Guard against catastrophic mis-signals:
    //  - PID 0: kill(0, sig) signals the calling process's own group.
    //  - PID 1: kill(-1, sig) signals every process the caller can reach.
    //  - PID > i32::MAX: truncation on cast to i32 produces a negative value,
    //    and negating that can yield a positive or zero pgid — both wrong.
    if child_pid < 2 || child_pid > i32::MAX as u32 {
        return Err(ExecError::InvalidKillPid(child_pid));
    }

    // Negate the child PID to target the entire process group.
    // Safe because child_pid is in [2, i32::MAX] — the negation stays in
    // [i32::MIN+1, -2], always a valid negative argument for kill(2).
    let pgid = -(child_pid as i32);

    // SAFETY: kill() with a negative first argument sends the signal to all
    // processes in the process group whose PGID equals the absolute value of
    // the argument. This is a standard POSIX operation.
    let ret = unsafe { libc::kill(pgid, signal) };
    if ret != 0 {
        return Err(ExecError::SpawnFailed(std::io::Error::last_os_error()));
    }
    Ok(())
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;

    // ── Binary resolution ────────────────────────────────────────────────────

    /// `sh` is universally present in PATH on both macOS and Linux.
    /// Verify that it resolves to an absolute path pointing to an executable file.
    #[test]
    fn resolve_sh_returns_absolute_executable_path() {
        let path = resolve_binary("sh").expect("sh should be found in PATH");

        assert!(
            path.is_absolute(),
            "resolved path must be absolute, got: {path:?}"
        );
        assert!(
            path.is_file(),
            "resolved path must point to a regular file, got: {path:?}"
        );
        assert!(
            is_executable(&path),
            "resolved path must be executable, got: {path:?}"
        );
    }

    /// A binary name that does not exist in PATH returns an error whose message
    /// identifies the binary name.
    #[test]
    fn resolve_nonexistent_binary_returns_error_with_name() {
        let name = "binary_that_definitely_does_not_exist_in_any_path_directory_xyzzy42";
        let err = resolve_binary(name).expect_err("nonexistent binary should not resolve");
        let msg = err.to_string();
        assert!(
            msg.contains(name),
            "error message should mention the binary name {name:?}, got: {msg:?}"
        );
    }

    /// A tool name containing a `'/'` character returns a `PathSeparatorInName`
    /// error without consulting PATH at all.
    #[test]
    fn resolve_with_slash_returns_path_separator_error() {
        // Absolute path — rejected.
        let result = resolve_binary("/usr/bin/sh");
        assert!(
            matches!(result, Err(ExecError::PathSeparatorInName(_))),
            "absolute path should return PathSeparatorInName, got: {result:?}"
        );

        // Relative path with directory component — also rejected.
        let result = resolve_binary("some/relative/path");
        assert!(
            matches!(result, Err(ExecError::PathSeparatorInName(_))),
            "relative path with '/' should return PathSeparatorInName, got: {result:?}"
        );

        // Bare name with a trailing slash — also rejected.
        let result = resolve_binary("sh/");
        assert!(
            matches!(result, Err(ExecError::PathSeparatorInName(_))),
            "name with trailing '/' should return PathSeparatorInName, got: {result:?}"
        );
    }

    /// An empty PATH string returns an error (no directories to search).
    #[test]
    fn empty_path_string_returns_error() {
        let result = resolve_binary_in("sh", "");
        assert!(
            result.is_err(),
            "empty PATH string should return an error, got: {result:?}"
        );
    }

    /// A PATH containing a non-existent directory does not panic; that directory
    /// is skipped and resolution continues to the next entry.
    #[test]
    fn nonexistent_dir_in_path_is_skipped_and_binary_found() {
        // Build a custom PATH that has a non-existent directory first, followed
        // by the real PATH (which contains sh).
        let real_path = std::env::var("PATH").unwrap_or_default();
        let custom_path = format!("/this/directory/does/absolutely/not/exist/xyzzy:{real_path}");

        // Must not panic, and should still find sh via the real PATH entries.
        let result = resolve_binary_in("sh", &custom_path);
        assert!(
            result.is_ok(),
            "should find sh despite a non-existent leading directory, got: {result:?}"
        );
        let path = result.unwrap();
        assert!(path.is_absolute(), "resolved path must be absolute");
    }

    // ── Environment construction ─────────────────────────────────────────────

    /// The output map contains the declared secrets with their correct values.
    #[test]
    fn build_env_contains_declared_secrets() {
        let secrets = vec![
            ("MY_API_KEY".to_string(), "secret_value_123".to_string()),
            ("DB_PASSWORD".to_string(), "hunter2".to_string()),
        ];
        let env = build_env(&secrets);

        assert_eq!(
            env.get("MY_API_KEY").map(String::as_str),
            Some("secret_value_123"),
            "MY_API_KEY should be present with its correct value"
        );
        assert_eq!(
            env.get("DB_PASSWORD").map(String::as_str),
            Some("hunter2"),
            "DB_PASSWORD should be present with its correct value"
        );
    }

    /// The output map contains `PATH` with the value from the daemon's environment.
    #[test]
    fn build_env_contains_path_from_daemon_env() {
        // PATH is almost certainly set in any test environment; guard anyway.
        let Ok(expected_path) = std::env::var("PATH") else {
            // PATH is not set — nothing to verify.
            return;
        };

        let env = build_env(&[]);
        assert_eq!(
            env.get("PATH").map(String::as_str),
            Some(expected_path.as_str()),
            "env PATH should match the daemon's PATH"
        );
    }

    /// The output map contains HOME, TERM, LANG, and USER when they are present
    /// in the daemon's environment.
    #[test]
    fn build_env_contains_essential_vars_when_present_in_daemon_env() {
        let env = build_env(&[]);

        for var in &["HOME", "TERM", "LANG", "USER"] {
            match std::env::var(var) {
                Ok(expected) => {
                    assert_eq!(
                        env.get(*var).map(String::as_str),
                        Some(expected.as_str()),
                        "env should contain {var} = {expected:?} when set in daemon env"
                    );
                }
                Err(_) => {
                    // Variable absent from daemon env — must also be absent from child env.
                    assert!(
                        !env.contains_key(*var),
                        "env should NOT contain {var} when absent from daemon env"
                    );
                }
            }
        }
    }

    /// The output map contains exactly the declared secrets plus the essential
    /// variables that are present in the daemon's environment — no more, no less.
    ///
    /// Verified by checking:
    /// 1. The key count equals the expected count.
    /// 2. Every key is either a declared secret or an essential variable.
    #[test]
    fn build_env_has_exactly_secrets_plus_present_essential_vars() {
        let secrets = vec![
            ("SECRET_ALPHA".to_string(), "value_a".to_string()),
            ("SECRET_BETA".to_string(), "value_b".to_string()),
        ];
        let env = build_env(&secrets);

        let secret_names: HashSet<&str> = secrets.iter().map(|(n, _)| n.as_str()).collect();
        let essential_names: HashSet<&str> = ESSENTIAL_VARS.iter().copied().collect();

        // Count present essential vars (those not already named by a secret).
        let present_essential_count = ESSENTIAL_VARS
            .iter()
            .filter(|var| !secret_names.contains(*var) && std::env::var(*var).is_ok())
            .count();

        let expected_count = secrets.len() + present_essential_count;

        assert_eq!(
            env.len(),
            expected_count,
            "env should contain exactly {} secret(s) + {} present essential var(s) = {} entries, \
             but got {} entries: {:?}",
            secrets.len(),
            present_essential_count,
            expected_count,
            env.len(),
            env.keys().collect::<Vec<_>>()
        );

        // Verify every key is either a declared secret or an essential variable.
        for key in env.keys() {
            assert!(
                secret_names.contains(key.as_str()) || essential_names.contains(key.as_str()),
                "unexpected key in env: {key:?} — \
                 only declared secrets and essential variables are permitted"
            );
        }
    }

    /// The output map does not contain any variable from the daemon's environment
    /// beyond the declared secrets and the essential set.
    #[test]
    fn build_env_does_not_leak_daemon_environment() {
        let env = build_env(&[]);

        // A sample of well-known environment variables that are commonly set in
        // daemon/CI/developer environments but must not appear in the child env.
        let forbidden = [
            "SHELL",
            "EDITOR",
            "VISUAL",
            "DISPLAY",
            "DBUS_SESSION_BUS_ADDRESS",
            "XDG_RUNTIME_DIR",
            "XDG_SESSION_TYPE",
            "TMPDIR",
            "PWD",
            "OLDPWD",
            "SHLVL",
            "LOGNAME",
            "MANPATH",
            "LESS",
            "PAGER",
            "COLORTERM",
            "TERM_PROGRAM",
            "TERM_PROGRAM_VERSION",
        ];

        for var in &forbidden {
            assert!(
                !env.contains_key(*var),
                "env must not contain daemon variable {var:?}"
            );
        }
    }

    /// If the daemon's environment is missing `TERM`, the output map omits `TERM`
    /// without returning an error.
    ///
    /// Because we cannot safely remove `TERM` from the process environment in
    /// parallel tests, this test validates the invariant by inspecting the
    /// current state: if TERM is set, it must be present; if absent, it must
    /// not appear.
    #[test]
    fn build_env_omits_absent_essential_vars_without_error() {
        let env = build_env(&[]);

        match std::env::var("TERM") {
            Ok(val) => {
                assert_eq!(
                    env.get("TERM").map(String::as_str),
                    Some(val.as_str()),
                    "TERM should be present when set in daemon env"
                );
            }
            Err(_) => {
                assert!(
                    !env.contains_key("TERM"),
                    "TERM should be absent when not set in daemon env"
                );
            }
        }
    }

    /// A tool declared with no secrets produces an env map containing only the
    /// essential variables that are present in the daemon's environment.
    #[test]
    fn build_env_no_secrets_produces_only_essential_vars() {
        let env = build_env(&[]);

        let essential_names: HashSet<&str> = ESSENTIAL_VARS.iter().copied().collect();

        for key in env.keys() {
            assert!(
                essential_names.contains(key.as_str()),
                "with no secrets, env should only contain essential vars; found unexpected key: {key:?}"
            );
        }
    }

    // ── ExecRequest construction (compile-time verification) ─────────────────

    /// Verify that `ExecRequest` can be constructed with all required fields and
    /// that the resulting value is accepted by `exec::spawn()`.
    ///
    /// This test is a compile-time check: if `ExecRequest` is missing fields or
    /// has the wrong types, or if `spawn()` does not accept it, this test will
    /// fail to compile. Restricted to macOS and Linux where a `SandboxBackend`
    /// is available.
    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn exec_request_can_be_constructed_and_accepted_by_spawn() {
        use crate::sandbox::{SandboxBackend, ToolPolicy};

        let policy = ToolPolicy {
            read_paths: vec![PathBuf::from("/tmp")],
            read_write_paths: vec![],
            requires_network: false,
            binary_path: None,
        };

        // Build a sandbox profile using the platform-specific backend.
        #[cfg(target_os = "macos")]
        let sandbox_profile = crate::sandbox::macos::MacOSSeatbelt
            .build(&policy)
            .expect("sandbox profile should build on macOS");

        #[cfg(target_os = "linux")]
        let sandbox_profile = crate::sandbox::linux::LinuxLandlock
            .build(&policy)
            .expect("sandbox profile should build on Linux");

        let secrets = vec![("API_KEY".to_string(), "test_secret".to_string())];

        let _request = ExecRequest {
            binary: PathBuf::from("/bin/sh"),
            args: vec!["-c".to_string(), "true".to_string()],
            work_dir: PathBuf::from("/tmp"),
            env: build_env(&secrets),
            sandbox_profile,
            timeout: Duration::from_secs(30),
        };

        // Compile-time verification: assert that `spawn` has the expected signature.
        // If `ExecRequest` or `SpawnedChild` had the wrong type, this line would
        // fail to compile.
        let _: fn(ExecRequest) -> Result<SpawnedChild, ExecError> = spawn;
    }

    // ── Process-group kill helper ─────────────────────────────────────────────

    /// Verify that `kill_process_group` sends a signal to the negated PID
    /// (i.e., to the entire process group).
    ///
    /// The test spawns a real child process in its own process group, sends
    /// `SIGCONT` via the kill helper (a no-op signal for running processes),
    /// and confirms:
    /// 1. The kill helper returns `Ok(())` — the signal was delivered.
    /// 2. The child is still alive — `SIGCONT` does not terminate a process.
    #[test]
    fn kill_process_group_sends_signal_to_process_group() {
        use std::os::unix::process::CommandExt;

        // Spawn a child process that sleeps, placing it in its own process group
        // via the pre_exec closure (the same mechanism used by exec::spawn).
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("60");
        // SAFETY: setpgid(0, 0) is async-signal-safe and valid in a newly
        // forked child. No allocation occurs.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().expect("failed to spawn sleep process");
        let pid = child.id();

        // Also set the process group from the parent side to avoid a race
        // with the child's pre_exec. Both set the same value, so the call
        // is idempotent.
        let _ = unsafe { libc::setpgid(pid as i32, pid as i32) };

        // Brief wait to ensure the process group is fully established.
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Send SIGCONT to the entire process group via the kill helper.
        // SIGCONT is a no-op for a running process — it only resumes a
        // stopped process. This makes it safe for testing: the child
        // remains alive and the signal delivery can be verified.
        let result = kill_process_group(pid, libc::SIGCONT);
        assert!(
            result.is_ok(),
            "kill_process_group(SIGCONT) should succeed, got: {:?}",
            result.err()
        );

        // Verify the child is still alive after receiving SIGCONT.
        // kill(pid, 0) probes whether the process exists without sending
        // a signal.
        let alive = unsafe { libc::kill(pid as i32, 0) };
        assert_eq!(
            alive, 0,
            "child should still be alive after receiving SIGCONT"
        );

        // Clean up: terminate the child using the kill helper (not Child::kill).
        kill_process_group(pid, libc::SIGKILL)
            .expect("failed to send SIGKILL to child process group");
        child.wait().expect("failed to wait for child");
    }

    // ── pre_exec failure propagation (Linux only) ─────────────────────────────

    /// On Linux, constructing a `SandboxProfile` with an already-closed fd and
    /// attempting `spawn()` returns an error because `landlock_restrict_self`
    /// fails in the `pre_exec` closure. No child process survives.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pre_exec_failure_with_invalid_fd_returns_error() {
        use crate::sandbox::SandboxProfile;

        // Get a valid fd by opening /dev/null, then close it to make it invalid.
        let devnull = std::ffi::CString::new("/dev/null").unwrap();
        let fd = unsafe { libc::open(devnull.as_ptr(), libc::O_RDONLY) };
        assert!(fd > 0, "open /dev/null should succeed, got {fd}");
        unsafe { libc::close(fd) };

        let profile = SandboxProfile::new_for_test(fd);

        let request = ExecRequest {
            binary: resolve_binary("true").expect("true should be in PATH"),
            args: vec![],
            work_dir: PathBuf::from("/tmp"),
            env: build_env(&[]),
            sandbox_profile: profile,
            timeout: Duration::from_secs(10),
        };

        let result = spawn(request);
        assert!(
            result.is_err(),
            "spawn with invalid fd should return an error"
        );

        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.is_empty(),
            "error message should be non-empty, got: {msg:?}"
        );
        // No child process should be alive — spawn returned Err, so no PID
        // was returned. The pre_exec closure's error caused the child to
        // exit before exec.
    }

    // ── Landlock fd cleanup after spawn (Linux only) ──────────────────────────

    /// After a successful `spawn()`, the Landlock ruleset fd is no longer valid
    /// in the parent process — confirming `close_ruleset_fd()` was called.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn landlock_fd_closed_in_parent_after_spawn() {
        use crate::sandbox::linux::{FdClosedProbe, LinuxLandlock};
        use crate::sandbox::{SandboxBackend, ToolPolicy};

        let mut read_paths: Vec<PathBuf> = vec![
            PathBuf::from("/usr/lib"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
            PathBuf::from("/dev"),
            PathBuf::from("/etc"),
            PathBuf::from("/tmp"),
        ];
        for p in ["/lib", "/lib64"] {
            if std::path::Path::new(p).exists() {
                read_paths.push(PathBuf::from(p));
            }
        }

        let policy = ToolPolicy {
            read_paths,
            read_write_paths: vec![PathBuf::from("/tmp")],
            requires_network: false,
            binary_path: None,
        };

        let profile = LinuxLandlock
            .build(&policy)
            .expect("build profile should succeed");

        // Capture the raw fd before spawning (the profile is moved into ExecRequest).
        let raw_fd = profile.raw_fd();
        assert!(raw_fd > 2, "raw fd should be valid before spawn");
        let probe = FdClosedProbe::arm(raw_fd);

        let request = ExecRequest {
            binary: resolve_binary("true").expect("true should be in PATH"),
            args: vec![],
            work_dir: PathBuf::from("/tmp"),
            env: build_env(&[]),
            sandbox_profile: profile,
            timeout: Duration::from_secs(10),
        };

        // spawn() closes the parent's copy of the fd before it returns, so the
        // check belongs here rather than after the child exits — and must be
        // here, so the probe's serialising lock is released before the await.
        let mut spawned = spawn(request).expect("spawn should succeed");
        probe.assert_closed();

        spawned.child.wait().await.unwrap();
    }
}
