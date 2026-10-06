//! Secret value management for Airlock.
//!
//! This module provides:
//! - [`Secret<T>`] — a newtype wrapper that prevents accidental exposure of
//!   secret values via logging or debug output
//! - [`collect_secrets`] — resolves each `[secrets.<label>]` entry in the
//!   config into a live value. `source = "env"` reads a daemon env var;
//!   `source = "command"` spawns a process and captures its stdout. Errors
//!   are batched: the operator sees every missing env var or failed command
//!   in one message.
//! - [`clear_secret_env_vars`] — removes the source env vars from the daemon
//!   process after collection, preventing exposure via `/proc/<pid>/environ`
//!
//! # Security properties
//!
//! 1. Secret values never appear in debug output — [`Secret<T>`]'s `Debug` impl
//!    always prints `[REDACTED]`.
//! 2. Secret environment variables are cleared from the daemon process after
//!    reading, preventing exposure via `/proc/<pid>/environ`.
//! 3. Secret values are only exposed at two controlled points: building the
//!    child environment (`exec::build_env`) and building the redaction automaton.
//!    Both points require an explicit `expose_secret()` call.
//! 4. `source = "command"` runs with the daemon's environment and is **not**
//!    sandboxed. `airlock.toml` is already trusted, so the command line is
//!    too — but the operator should treat it with the same care.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;
use zeroize::Zeroize;

use crate::config::{CommandEnv, Config, SecretSource};
use crate::exec::FilteredPath;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors that can occur during secret collection.
#[derive(Debug, Error)]
pub enum SecretsError {
    /// One or more `source = "env"` secrets point at daemon env vars that
    /// are not set.
    ///
    /// The error message lists all missing names so the operator can fix them
    /// in a single pass rather than discovering them one at a time.
    #[error("missing secret environment variables: {}", missing.join(", "))]
    MissingSecrets {
        /// The names of the missing environment variables.
        missing: Vec<String>,
    },

    /// An environment variable's value is not valid UTF-8.
    #[error("secret environment variable {name:?} contains invalid UTF-8")]
    InvalidUtf8 {
        /// The name of the environment variable with the invalid value.
        name: String,
    },

    /// One or more `source = "command"` secrets failed to produce a value.
    ///
    /// Reports all failures in a single error, each annotated with the label
    /// and a short explanation of what went wrong.
    #[error(
        "{} secret command(s) failed: {}",
        failures.len(),
        failures.iter()
            .map(|(label, reason)| format!("[secrets.{label}]: {reason}"))
            .collect::<Vec<_>>()
            .join("; ")
    )]
    CommandFailures {
        /// Pairs of (secret label, failure reason).
        failures: Vec<(String, String)>,
    },

    /// Under [`collect_secrets_with`]: a `source = "command"` secret's
    /// `argv[0]` is not on the session's filtered `PATH`, or resolves inside
    /// the project root or a write grant (B2 in the design doc — approving
    /// `airlock.toml` does not approve a binary the agent can rewrite).
    /// Returned eagerly, like [`SecretsError::InvalidUtf8`], rather than
    /// batched: it is a config problem, not a one-off command failure.
    #[error("{0}")]
    CommandUnusable(String),

    /// Under [`collect_secrets_with`]: one or more `source = "command"`
    /// secrets ran but failed (non-zero exit, spawn error, or timeout).
    /// Each message is pre-formatted per the UX table: the command
    /// backticked, its stderr indented beneath it.
    #[error("{}", messages.join("\n\n"))]
    CommandRunFailures {
        /// One formatted message per failed secret.
        messages: Vec<String>,
    },
}

// ─── Secret<T> wrapper ────────────────────────────────────────────────────────

/// A wrapper that holds a secret value and prevents accidental exposure.
///
/// Guarantees:
/// - The `Debug` implementation always prints `[REDACTED]`, regardless of the
///   inner value.
/// - The only way to read the inner value is [`expose_secret()`](Secret::expose_secret),
///   making exposure explicit and easy to audit (grep for `expose_secret`).
/// - On drop, the inner value is zeroed (when `T: Zeroize`). For `String`,
///   this overwrites the backing byte buffer with zeros before deallocation.
///   Note: if the string was grown (e.g. via `push_str`) the *old* backing
///   buffer — since realloc'd — may still contain secret bytes. In practice,
///   secret values are written exactly once at construction from an env var
///   and never mutated, so realloc growth does not apply here.
///
/// `Secret<T>` intentionally does not implement `Clone` or `Copy` to prevent
/// casual proliferation of secret values in memory.
pub struct Secret<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> Secret<T> {
    /// Wrap a value as a secret.
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Access the wrapped secret value.
    ///
    /// This is the only way to read the inner value. The method name makes
    /// exposure explicit at call sites, so reviewers can easily grep for all
    /// points where secret values are accessed.
    pub fn expose_secret(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

// ─── Refresh-aware secret store ──────────────────────────────────────────────

/// Health of a refreshable secret. A secret transitions to [`Health::Stale`]
/// when its background refresh command fails; the previous value is kept in
/// memory but the exec path refuses to inject it.
#[derive(Debug, Clone)]
pub enum Health {
    /// The slot's `value` reflects the last successful fetch (initial collect
    /// or most recent refresh).
    Healthy,
    /// The most recent refresh failed. The slot's `value` is the last good
    /// fetch and is presumed expired; exec must reject.
    Stale {
        /// Operator-facing reason (never the secret value).
        reason: String,
        /// Wall-clock time the failure was recorded.
        since: Instant,
    },
}

/// One entry in the [`SecretStore`]: the resolved value plus its health.
///
/// The `value` is wrapped in `Arc<Secret<String>>` so that the redactor and
/// the exec path can hold their own references — the refresh task can swap
/// the slot's value while live readers retain the previous `Arc` for the
/// lifetime of their borrow (zeroize fires when the last `Arc` drops).
#[derive(Debug)]
pub struct SecretSlot {
    /// The currently-injected value.
    pub value: Arc<Secret<String>>,
    /// Slot health. See [`Health`].
    pub health: Health,
}

/// Per-secret slots keyed by label. The outer `HashMap` is fixed at config
/// load; only the contents of each `RwLock<SecretSlot>` change at runtime.
pub type SecretStore = Arc<HashMap<String, RwLock<SecretSlot>>>;

/// Build a [`SecretStore`] by running [`collect_secrets`] and wrapping each
/// value in a [`SecretSlot`] (initially [`Health::Healthy`]).
pub fn build_secret_store(config: &Config) -> Result<SecretStore, SecretsError> {
    let resolved = collect_secrets(config)?;
    let mut map: HashMap<String, RwLock<SecretSlot>> = HashMap::with_capacity(resolved.len());
    for (label, secret) in resolved {
        map.insert(
            label,
            RwLock::new(SecretSlot {
                value: Arc::new(secret),
                health: Health::Healthy,
            }),
        );
    }
    Ok(Arc::new(map))
}

// ─── Secret collection ───────────────────────────────────────────────────────

/// Resolve every `[secrets.<label>]` entry in the config into a live value
/// wrapped in [`Secret<String>`], keyed by label.
///
/// For `source = "env"` entries, reads the named daemon env var. For
/// `source = "command"` entries, spawns the command, waits up to the
/// configured timeout, and captures its stdout (trailing newlines trimmed).
///
/// Errors are batched: if any `env` sources are missing or any `command`
/// sources fail, the function returns a single error describing every
/// problem so the operator can fix them in one pass.
///
/// # Errors
///
/// - [`SecretsError::MissingSecrets`] — one or more `env` sources point at
///   unset daemon env vars.
/// - [`SecretsError::InvalidUtf8`] — an `env` source's value is not valid UTF-8.
///   Returned eagerly, not batched (very rare and hard to recover from).
/// - [`SecretsError::CommandFailures`] — one or more `command` sources failed
///   (spawn error, non-zero exit, or timeout).
pub fn collect_secrets(config: &Config) -> Result<HashMap<String, Secret<String>>, SecretsError> {
    let mut labels: Vec<&String> = config.secrets.keys().collect();
    labels.sort();

    let mut secrets: HashMap<String, Secret<String>> = HashMap::with_capacity(labels.len());
    let mut missing: Vec<String> = Vec::new();
    let mut command_failures: Vec<(String, String)> = Vec::new();

    for label in labels {
        let spec = &config.secrets[label];
        match &spec.source {
            SecretSource::Env { from } => match std::env::var(from) {
                Ok(value) => {
                    secrets.insert(label.clone(), Secret::new(value));
                }
                Err(std::env::VarError::NotPresent) => {
                    missing.push(from.clone());
                }
                Err(std::env::VarError::NotUnicode(_)) => {
                    return Err(SecretsError::InvalidUtf8 { name: from.clone() });
                }
            },
            SecretSource::Command {
                argv, timeout, env, ..
            } => {
                // Initial fetches are synchronous and can take seconds
                // (1Password, vault, AWS STS, etc.). Log before and after so
                // the operator knows why startup is pausing.
                let program = argv.first().map(String::as_str).unwrap_or("");
                eprintln!("airlock: fetching secret {label:?} via {program}...");
                let started = Instant::now();
                match run_command_secret(argv, *timeout, env) {
                    Ok(value) => {
                        eprintln!(
                            "airlock: fetched secret {label:?} in {}ms",
                            started.elapsed().as_millis()
                        );
                        secrets.insert(label.clone(), Secret::new(value));
                    }
                    Err(reason) => {
                        eprintln!("airlock: failed to fetch secret {label:?}: {reason}");
                        command_failures.push((label.clone(), reason));
                    }
                }
            }
        }
    }

    if !missing.is_empty() {
        return Err(SecretsError::MissingSecrets { missing });
    }
    if !command_failures.is_empty() {
        return Err(SecretsError::CommandFailures {
            failures: command_failures,
        });
    }

    Ok(secrets)
}

/// The outcome of spawning a secret command and waiting for it, before any
/// label- or UX-specific formatting is applied. Shared by the legacy
/// (process-env) and [`CommandContext`]-based run paths.
pub(crate) enum CommandRunError {
    /// `Command::spawn` itself failed.
    Spawn(String),
    /// The child exited (successfully or not); stdout could not be read.
    ReadStdout(String),
    /// The child exited non-zero. `stderr` is already trimmed and may be
    /// empty.
    Exited { status: String, stderr: String },
    /// The child did not exit within its timeout and was killed.
    Timeout(u64),
    /// `try_wait` itself failed.
    Wait(String),
}

impl CommandRunError {
    /// Render as the single-line reason string the legacy (process-env)
    /// callers have always returned.
    pub(crate) fn to_flat(&self) -> String {
        match self {
            CommandRunError::Spawn(e) => format!("spawn failed: {e}"),
            CommandRunError::ReadStdout(e) => format!("failed to read stdout: {e}"),
            CommandRunError::Exited { status, stderr } => {
                if stderr.is_empty() {
                    format!("exited with {status}")
                } else {
                    format!("exited with {status}: {stderr}")
                }
            }
            CommandRunError::Timeout(secs) => format!("timed out after {secs}s"),
            CommandRunError::Wait(e) => format!("wait failed: {e}"),
        }
    }
}

/// Spawn an already-configured `cmd` and wait for it, with a wall-clock
/// timeout.
///
/// Stdin must already be `/dev/null`, and stdout/stderr piped — this
/// function only drives the wait loop and reads the pipes; it does not
/// configure the command. Stdout is the value; stderr is captured only to
/// enrich failure messages. Trailing `\n`/`\r` are trimmed from stdout for
/// convenience (most CLIs emit a newline).
///
/// Timeout is enforced by polling `try_wait` with a 50 ms tick. If stdout is
/// very large (>64 KiB) it may block the child before it exits; for secret
/// fetching this is an acceptable constraint.
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<String, CommandRunError> {
    let mut child = cmd
        .spawn()
        .map_err(|e| CommandRunError::Spawn(e.to_string()))?;

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                if let Some(mut pipe) = child.stdout.take() {
                    pipe.read_to_string(&mut stdout)
                        .map_err(|e| CommandRunError::ReadStdout(e.to_string()))?;
                }
                if !status.success() {
                    let mut stderr = String::new();
                    if let Some(mut pipe) = child.stderr.take() {
                        let _ = pipe.read_to_string(&mut stderr);
                    }
                    return Err(CommandRunError::Exited {
                        status: status.to_string(),
                        stderr: stderr.trim().to_string(),
                    });
                }
                while stdout.ends_with('\n') || stdout.ends_with('\r') {
                    stdout.pop();
                }
                return Ok(stdout);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CommandRunError::Timeout(timeout.as_secs()));
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(CommandRunError::Wait(e.to_string())),
        }
    }
}

/// Spawn `argv` and capture its stdout as a secret value, inheriting the
/// daemon's own environment (so tools like `op` and `vault` can read
/// `OP_SERVICE_ACCOUNT_TOKEN` / `VAULT_ADDR`).
///
/// This is the v1 daemon's path: `argv[0]` is resolved by `exec(3)` against
/// the daemon's own `PATH`, with no location check. [`CommandContext`] and
/// [`collect_secrets_with`] replace it for v2 sessions, which run with an
/// explicit snapshot and filtered `PATH` instead.
pub(crate) fn run_command_secret(
    argv: &[String],
    timeout: Duration,
    env: &CommandEnv,
) -> Result<String, String> {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if env.clear {
        cmd.env_clear();
    }
    for (name, value) in &env.set {
        cmd.env(name, value);
    }

    run_with_timeout(cmd, timeout).map_err(|e| e.to_flat())
}

// ─── Session-scoped secret collection ────────────────────────────────────────

/// Everything a session's secret commands need, in place of the daemon's
/// own environment and `PATH`: the launcher's environment snapshot (taken
/// once, at `Register` time), the session's filtered `PATH`, and the
/// anchors a resolved `argv[0]` must land outside of.
///
/// Held by the session so `refresh.rs` can re-run `source = "command"`
/// secrets later without ever touching the daemon's process environment.
pub struct CommandContext {
    /// The launcher's own environment at registration time, minus the
    /// variables consumed by `source = "env"` secrets.
    pub snapshot: BTreeMap<String, String>,
    /// The session's filtered `PATH`. Always wins over `snapshot`'s own
    /// `PATH`, and over an unresolved `argv[0]`'s search — see
    /// [`run_command_with_ctx`].
    pub path: FilteredPath,
    /// Working directory for secret commands (the session's root, or a
    /// subdirectory of it if the launcher started there).
    pub cwd: PathBuf,
    /// The project root. An `argv[0]` resolving here is refused.
    pub root: PathBuf,
    /// Write grants. An `argv[0]` resolving into one of these is refused,
    /// same as the root.
    pub write_grants: Vec<PathBuf>,
}

/// The result of [`collect_secrets_with`]: resolved values, plus which
/// `source = "env"` variable names were actually read, so the launcher can
/// drop them from the snapshot it hands the daemon (B2: the daemon's
/// session state should not carry a secret value twice).
#[derive(Debug)]
pub struct Collected {
    /// Resolved values, keyed by label.
    pub values: HashMap<String, Secret<String>>,
    /// Names of the daemon/launcher env vars consumed by `source = "env"`
    /// secrets.
    pub consumed_env: Vec<String>,
}

/// The outcome of resolving and running a `source = "command"` secret under
/// a [`CommandContext`], before label-specific formatting.
pub(crate) enum CommandCtxError {
    /// `argv[0]` (a bare name) was not found on `ctx.path`'s surviving
    /// entries.
    NotOnPath {
        argv0: String,
        dropped: Vec<(String, String)>,
    },
    /// `argv[0]` resolved inside the project root.
    InsideRoot { argv0: String, path: PathBuf },
    /// `argv[0]` resolved inside a write grant (but not the root).
    InsideWriteGrant { argv0: String, path: PathBuf },
    /// `argv[0]` resolved and passed its location check, but running it
    /// failed.
    Run(CommandRunError),
}

impl CommandCtxError {
    /// Render the full, label-prefixed message. Structural failures
    /// (`NotOnPath`, `Inside*`) are formatted per the UX table's secret
    /// command messages; a run failure defers to [`CommandRunError::to_flat`].
    pub(crate) fn to_flat(&self, label: &str) -> String {
        match self {
            CommandCtxError::NotOnPath { argv0, dropped } => format!(
                "secret {label}: command {argv0:?} is not on the session's PATH{}",
                crate::exec::format_dropped_suffix(dropped)
            ),
            CommandCtxError::InsideRoot { argv0, path } => format!(
                "secret {label}: command {argv0:?} resolves to {}, inside the project; \
                 refusing to run it. Install it outside the project (Homebrew, mise, Nix).",
                path.display()
            ),
            CommandCtxError::InsideWriteGrant { argv0, path } => format!(
                "secret {label}: command {argv0:?} resolves to {}, inside a write grant; \
                 refusing to run it. Install it outside the project (Homebrew, mise, Nix).",
                path.display()
            ),
            CommandCtxError::Run(e) => e.to_flat(),
        }
    }
}

/// Resolve `argv[0]` against the session's filtered `PATH`, applying the
/// same location check as tool binaries ([`crate::exec::resolve_binary_in`]):
/// an `argv0` containing `/` is canonicalized and checked directly (relative
/// to `ctx.cwd`, matching shell semantics), exactly like a bare name found
/// on `PATH` — so `command = ["./scripts/token.sh"]` is refused the same
/// way a planted `gh` would be.
fn resolve_command_argv0(argv0: &str, ctx: &CommandContext) -> Result<PathBuf, CommandCtxError> {
    let canon = if argv0.contains('/') {
        let candidate = Path::new(argv0);
        let candidate = if candidate.is_relative() {
            ctx.cwd.join(candidate)
        } else {
            candidate.to_path_buf()
        };
        std::fs::canonicalize(&candidate).unwrap_or(candidate)
    } else {
        match crate::exec::search_path_entries(argv0, &ctx.path.entries) {
            Some(p) => p,
            None => {
                return Err(CommandCtxError::NotOnPath {
                    argv0: argv0.to_string(),
                    dropped: ctx.path.dropped.clone(),
                });
            }
        }
    };

    match crate::exec::classify_location(&canon, &ctx.root, &ctx.write_grants) {
        crate::exec::Location::Outside => Ok(canon),
        crate::exec::Location::InsideRoot => Err(CommandCtxError::InsideRoot {
            argv0: argv0.to_string(),
            path: canon,
        }),
        crate::exec::Location::InsideWriteGrant => Err(CommandCtxError::InsideWriteGrant {
            argv0: argv0.to_string(),
            path: canon,
        }),
    }
}

/// Run a `source = "command"` secret under a [`CommandContext`]: `argv[0]`
/// resolved and location-checked against the session's filtered `PATH`,
/// spawned with `cwd = ctx.cwd` and an environment built as
/// `(env.clear ? {} : ctx.snapshot) + PATH=<filtered> + env.set` — in that
/// order, so the filtered `PATH` always overrides the snapshot's own, and
/// an explicit `env.set["PATH"]` (the user's approved choice in
/// `airlock.toml`) overrides the filtered one in turn.
pub(crate) fn run_command_with_ctx(
    argv: &[String],
    timeout: Duration,
    env: &CommandEnv,
    ctx: &CommandContext,
) -> Result<String, CommandCtxError> {
    let argv0 = argv.first().map(String::as_str).unwrap_or("");
    let binary = resolve_command_argv0(argv0, ctx)?;

    let mut cmd = Command::new(&binary);
    cmd.args(&argv[1..])
        .current_dir(&ctx.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    cmd.env_clear();
    if !env.clear {
        for (name, value) in &ctx.snapshot {
            cmd.env(name, value);
        }
    }
    let filtered_path = ctx
        .path
        .entries
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(":");
    cmd.env("PATH", filtered_path);
    for (name, value) in &env.set {
        cmd.env(name, value);
    }

    run_with_timeout(cmd, timeout).map_err(CommandCtxError::Run)
}

/// Resolve every `[secrets.<label>]` entry into a live value, the
/// [`CommandContext`]-based counterpart to [`collect_secrets`].
///
/// `source = "env"` reads `env_lookup` — the launcher's own environment —
/// instead of the daemon's. `source = "command"` runs under `ctx`: its
/// `argv[0]` resolved and location-checked against the session's filtered
/// `PATH`, spawned with `ctx`'s snapshot and `PATH`, never the daemon's own
/// environment (see [`run_command_with_ctx`]).
///
/// # Errors
///
/// - [`SecretsError::MissingSecrets`] — one or more `env` sources are absent
///   from `env_lookup`, batched together.
/// - [`SecretsError::CommandUnusable`] — a `command` secret's `argv[0]` is
///   not on the filtered `PATH`, or resolves inside the root or a write
///   grant. Returned eagerly (it is a config problem, not a one-off
///   failure), so a later label's missing `env` var may go unreported in
///   the same call.
/// - [`SecretsError::CommandRunFailures`] — one or more `command` secrets
///   resolved but failed to run, batched.
pub fn collect_secrets_with(
    config: &Config,
    env_lookup: &dyn Fn(&str) -> Option<String>,
    ctx: &CommandContext,
) -> Result<Collected, SecretsError> {
    let mut labels: Vec<&String> = config.secrets.keys().collect();
    labels.sort();

    let mut values: HashMap<String, Secret<String>> = HashMap::with_capacity(labels.len());
    let mut consumed_env: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    let mut run_failures: Vec<String> = Vec::new();

    for label in labels {
        let spec = &config.secrets[label];
        match &spec.source {
            SecretSource::Env { from } => match env_lookup(from) {
                Some(value) => {
                    values.insert(label.clone(), Secret::new(value));
                    consumed_env.push(from.clone());
                }
                None => missing.push(from.clone()),
            },
            SecretSource::Command {
                argv, timeout, env, ..
            } => match run_command_with_ctx(argv, *timeout, env, ctx) {
                Ok(value) => {
                    values.insert(label.clone(), Secret::new(value));
                }
                Err(CommandCtxError::Run(run_err)) => {
                    let cmd_display = argv.join(" ");
                    let mut msg = match &run_err {
                        CommandRunError::Exited { status, .. } => {
                            format!("secret {label}: `{cmd_display}` exited with {status}:")
                        }
                        other => format!("secret {label}: `{cmd_display}` {}", other.to_flat()),
                    };
                    if let CommandRunError::Exited { stderr, .. } = &run_err {
                        for line in stderr.lines() {
                            msg.push('\n');
                            msg.push_str("  ");
                            msg.push_str(line);
                        }
                    }
                    run_failures.push(msg);
                }
                Err(other) => return Err(SecretsError::CommandUnusable(other.to_flat(label))),
            },
        }
    }

    if !missing.is_empty() {
        return Err(SecretsError::MissingSecrets { missing });
    }
    if !run_failures.is_empty() {
        return Err(SecretsError::CommandRunFailures {
            messages: run_failures,
        });
    }

    Ok(Collected {
        values,
        consumed_env,
    })
}

// ─── Environment clearing ────────────────────────────────────────────────────

/// Remove the daemon env vars referenced by `source = "env"` secrets from the
/// daemon's process environment.
///
/// Leaves `PATH`, `HOME`, `TERM`, `LANG`, `USER`, and any vars not referenced
/// by an `env` source alone. `source = "command"` entries have nothing to
/// clear.
///
/// # Safety note on `std::env::remove_var`
///
/// In Rust 2024 edition, `std::env::remove_var` is `unsafe` because modifying
/// the environment is not thread-safe. The caller must ensure no other thread
/// is reading or writing environment variables concurrently. This function is
/// intended to be called early in daemon startup, before any concurrent tasks
/// are spawned.
pub fn clear_secret_env_vars(config: &Config) {
    let mut names: Vec<&str> = config
        .secrets
        .values()
        .filter_map(|spec| match &spec.source {
            SecretSource::Env { from } => Some(from.as_str()),
            SecretSource::Command { .. } => None,
        })
        .collect();
    names.sort();
    names.dedup();

    for name in names {
        // SAFETY: Called early in daemon startup before any concurrent tasks
        // are spawned. No other thread is reading or writing env vars.
        unsafe {
            std::env::remove_var(name);
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::MutexGuard;
    use std::time::Duration;

    use tempfile::tempdir;

    use crate::config::{Config, SecretSpec};

    // ── Helpers ──────────────────────────────────────────────────────────

    /// RAII guard that sets environment variables for the duration of a test
    /// and restores them when dropped. Holds
    /// [`crate::test_support::ENV_MUTEX`] — the crate-wide lock — so these
    /// tests serialize against every other test that touches the process
    /// environment, not just the ones in this module.
    struct EnvGuard {
        vars: Vec<(String, Option<String>)>,
        _lock: MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        /// Set the given environment variables, saving their previous values
        /// for restoration on drop.
        fn new(vars: &[(&str, &str)]) -> Self {
            let lock = crate::test_support::ENV_MUTEX
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut saved = Vec::with_capacity(vars.len());

            for (key, value) in vars {
                let prev = std::env::var(*key).ok();
                saved.push((key.to_string(), prev));
                // SAFETY: we hold the crate-wide ENV_MUTEX, so no other test
                // thread anywhere in the suite is reading or writing env vars
                // concurrently.
                unsafe { std::env::set_var(*key, *value) };
            }

            Self {
                vars: saved,
                _lock: lock,
            }
        }

        /// Acquire the env mutex without setting any variables. Useful when
        /// we need to set and clear in a specific order within the test body.
        fn lock_only() -> Self {
            let lock = crate::test_support::ENV_MUTEX
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            Self {
                vars: Vec::new(),
                _lock: lock,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, prev) in &self.vars {
                match prev {
                    // SAFETY: We still hold ENV_MUTEX (dropped after this).
                    Some(v) => unsafe { std::env::set_var(key, v) },
                    None => unsafe { std::env::remove_var(key) },
                }
            }
        }
    }

    /// Build a test `Config` containing only `[secrets]` entries with
    /// `source = "env"`. Each `(label, env_var_name)` pair becomes a
    /// `SecretSpec` that reads `env_var_name` at collection time.
    fn make_config_env(secrets: Vec<(&str, &str)>) -> Config {
        let mut secret_map = HashMap::new();
        for (label, from) in secrets {
            secret_map.insert(
                label.to_string(),
                SecretSpec {
                    label: label.to_string(),
                    source: SecretSource::Env {
                        from: from.to_string(),
                    },
                },
            );
        }
        Config {
            sandbox_root: PathBuf::from("/tmp/test-sandbox"),
            socket_path: PathBuf::from("/tmp/test-sandbox/airlock.sock"),
            pid_path: PathBuf::from("/tmp/test-sandbox/airlock.pid"),
            ca_path: PathBuf::from("/tmp/test-sandbox/airlock-ca.pem"),
            timeout: Duration::from_secs(300),
            filesystem_read: Vec::new(),
            filesystem_write: Vec::new(),
            secrets: secret_map,
            tools: HashMap::new(),
            agent: None,
        }
    }

    /// Build a test `Config` with `source = "command"` entries. Each tuple is
    /// `(label, argv, timeout_secs)`.
    fn make_config_command(secrets: Vec<(&str, Vec<&str>, u64)>) -> Config {
        let mut secret_map = HashMap::new();
        for (label, argv, timeout_secs) in secrets {
            secret_map.insert(
                label.to_string(),
                SecretSpec {
                    label: label.to_string(),
                    source: SecretSource::Command {
                        argv: argv.into_iter().map(String::from).collect(),
                        timeout: Duration::from_secs(timeout_secs),
                        refresh: None,
                        env: crate::config::CommandEnv::default(),
                    },
                },
            );
        }
        Config {
            sandbox_root: PathBuf::from("/tmp/test-sandbox"),
            socket_path: PathBuf::from("/tmp/test-sandbox/airlock.sock"),
            pid_path: PathBuf::from("/tmp/test-sandbox/airlock.pid"),
            ca_path: PathBuf::from("/tmp/test-sandbox/airlock-ca.pem"),
            timeout: Duration::from_secs(300),
            filesystem_read: Vec::new(),
            filesystem_write: Vec::new(),
            secrets: secret_map,
            tools: HashMap::new(),
            agent: None,
        }
    }

    // ── Secret<T> wrapper tests ──────────────────────────────────────────

    #[test]
    fn secret_debug_is_redacted() {
        let secret = Secret::new("super-secret-value".to_string());
        let debug_output = format!("{:?}", secret);
        assert_eq!(debug_output, "[REDACTED]");
        assert!(
            !debug_output.contains("super-secret-value"),
            "debug output must not contain the secret value"
        );
    }

    #[test]
    fn secret_expose_returns_original_value() {
        let secret = Secret::new("my-secret-123".to_string());
        assert_eq!(secret.expose_secret(), "my-secret-123");
    }

    #[test]
    fn secret_empty_string_debug_is_redacted() {
        let secret = Secret::new(String::new());
        let debug_output = format!("{:?}", secret);
        assert_eq!(debug_output, "[REDACTED]");
    }

    #[test]
    fn secret_generic_wraps_vec_u8() {
        let data: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let secret = Secret::new(data.clone());

        // Debug should be redacted.
        let debug_output = format!("{:?}", secret);
        assert_eq!(debug_output, "[REDACTED]");

        // Value should be accessible.
        assert_eq!(secret.expose_secret(), &data);
    }

    #[test]
    fn secret_generic_wraps_i32() {
        let secret = Secret::new(42i32);
        let debug_output = format!("{:?}", secret);
        assert_eq!(debug_output, "[REDACTED]");
        assert_eq!(*secret.expose_secret(), 42);
    }

    #[test]
    fn secret_value_with_special_characters_preserved() {
        // Newlines.
        let secret = Secret::new("line1\nline2\nline3".to_string());
        assert_eq!(secret.expose_secret(), "line1\nline2\nline3");

        // Null bytes.
        let secret = Secret::new("before\0after".to_string());
        assert_eq!(secret.expose_secret(), "before\0after");

        // Unicode.
        let secret = Secret::new("Hello \u{1F600} World \u{00E9}".to_string());
        assert_eq!(secret.expose_secret(), "Hello \u{1F600} World \u{00E9}");
    }

    #[test]
    fn secret_debug_in_struct() {
        // When a struct containing a Secret is debug-formatted, the secret
        // should still appear as [REDACTED].
        #[derive(Debug)]
        #[allow(dead_code)]
        struct AppState {
            name: String,
            api_key: Secret<String>,
        }

        let state = AppState {
            name: "my-app".to_string(),
            api_key: Secret::new("sk-1234567890".to_string()),
        };

        let debug_output = format!("{:?}", state);
        assert!(
            debug_output.contains("[REDACTED]"),
            "struct debug should contain [REDACTED]"
        );
        assert!(
            !debug_output.contains("sk-1234567890"),
            "struct debug must not contain the secret value"
        );
    }

    // ── Secret collection tests ──────────────────────────────────────────

    #[test]
    fn collect_secrets_env_source_reads_from_daemon_env() {
        let _guard = EnvGuard::new(&[("TEST_SECRET_A", "value_a"), ("TEST_SECRET_B", "value_b")]);

        // Labels differ from the source env var names to confirm resolution
        // goes through `from`.
        let config = make_config_env(vec![("alpha", "TEST_SECRET_A"), ("beta", "TEST_SECRET_B")]);

        let secrets = collect_secrets(&config).expect("should succeed");
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets["alpha"].expose_secret(), "value_a");
        assert_eq!(secrets["beta"].expose_secret(), "value_b");
    }

    #[test]
    fn collect_secrets_fails_one_missing() {
        let _guard = EnvGuard::new(&[("TEST_COLL_PRESENT", "value")]);
        unsafe { std::env::remove_var("TEST_COLL_MISSING") };

        let config = make_config_env(vec![
            ("present", "TEST_COLL_PRESENT"),
            ("missing", "TEST_COLL_MISSING"),
        ]);

        let err = collect_secrets(&config).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("TEST_COLL_MISSING"),
            "error should name the missing env var, got: {msg}"
        );
    }

    #[test]
    fn collect_secrets_fails_all_missing_listed() {
        let _guard = EnvGuard::lock_only();
        unsafe {
            std::env::remove_var("TEST_MULTI_MISS_A");
            std::env::remove_var("TEST_MULTI_MISS_B");
            std::env::remove_var("TEST_MULTI_MISS_C");
        }

        let config = make_config_env(vec![
            ("a", "TEST_MULTI_MISS_A"),
            ("b", "TEST_MULTI_MISS_B"),
            ("c", "TEST_MULTI_MISS_C"),
        ]);

        let err = collect_secrets(&config).unwrap_err();
        match &err {
            SecretsError::MissingSecrets { missing } => {
                assert_eq!(missing.len(), 3, "should list all 3, got: {missing:?}");
                for name in [
                    "TEST_MULTI_MISS_A",
                    "TEST_MULTI_MISS_B",
                    "TEST_MULTI_MISS_C",
                ] {
                    assert!(
                        missing.iter().any(|m| m == name),
                        "should list {name}, got: {missing:?}"
                    );
                }
            }
            other => panic!("expected MissingSecrets, got: {other:?}"),
        }
    }

    #[test]
    fn collect_secrets_empty_set_succeeds() {
        let _guard = EnvGuard::lock_only();
        let config = make_config_env(vec![]);
        let secrets = collect_secrets(&config).expect("should succeed with empty set");
        assert!(secrets.is_empty());
    }

    #[test]
    fn collect_secrets_preserves_special_characters() {
        let _guard = EnvGuard::new(&[
            ("TEST_SPECIAL_NEWLINE", "line1\nline2"),
            ("TEST_SPECIAL_UNICODE", "caf\u{00E9} \u{1F600}"),
        ]);

        let config = make_config_env(vec![
            ("nl", "TEST_SPECIAL_NEWLINE"),
            ("uni", "TEST_SPECIAL_UNICODE"),
        ]);

        let secrets = collect_secrets(&config).expect("should succeed");
        assert_eq!(secrets["nl"].expose_secret(), "line1\nline2");
        assert_eq!(secrets["uni"].expose_secret(), "caf\u{00E9} \u{1F600}");
    }

    // ── Command-source collection ────────────────────────────────────────

    #[test]
    fn collect_secrets_command_source_captures_stdout() {
        // `printf` is portable across macOS and Linux; emits no trailing newline.
        let _guard = EnvGuard::lock_only();
        let config = make_config_command(vec![("pw", vec!["printf", "%s", "s3cret-value"], 5)]);

        let secrets = collect_secrets(&config).expect("should succeed");
        assert_eq!(secrets["pw"].expose_secret(), "s3cret-value");
    }

    #[test]
    fn collect_secrets_command_trims_trailing_newline() {
        // `echo` emits a trailing newline — the collector must strip it.
        let _guard = EnvGuard::lock_only();
        let config = make_config_command(vec![("pw", vec!["echo", "token-xyz"], 5)]);

        let secrets = collect_secrets(&config).expect("should succeed");
        assert_eq!(secrets["pw"].expose_secret(), "token-xyz");
    }

    #[test]
    fn collect_secrets_command_nonzero_exit_reports_failure() {
        let _guard = EnvGuard::lock_only();
        let config = make_config_command(vec![("pw", vec!["false"], 5)]);

        let err = collect_secrets(&config).unwrap_err();
        match err {
            SecretsError::CommandFailures { failures } => {
                assert_eq!(failures.len(), 1);
                assert_eq!(failures[0].0, "pw");
                assert!(
                    failures[0].1.contains("exited with"),
                    "reason should mention exit status, got: {:?}",
                    failures[0].1
                );
            }
            other => panic!("expected CommandFailures, got: {other:?}"),
        }
    }

    #[test]
    fn collect_secrets_command_spawn_failure_reports() {
        let _guard = EnvGuard::lock_only();
        let config = make_config_command(vec![("pw", vec!["/nonexistent/airlock/test/binary"], 5)]);

        let err = collect_secrets(&config).unwrap_err();
        matches!(err, SecretsError::CommandFailures { .. });
    }

    #[test]
    fn collect_secrets_command_timeout_kills_child() {
        let _guard = EnvGuard::lock_only();
        let config = make_config_command(vec![("pw", vec!["sleep", "10"], 1)]);

        let start = Instant::now();
        let err = collect_secrets(&config).unwrap_err();
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(5),
            "timeout should fire well before the child completes, took {elapsed:?}"
        );
        match err {
            SecretsError::CommandFailures { failures } => {
                assert!(
                    failures[0].1.contains("timed out"),
                    "reason should mention timeout, got: {:?}",
                    failures[0].1
                );
            }
            other => panic!("expected CommandFailures, got: {other:?}"),
        }
    }

    // ── run_command_secret env override tests ────────────────────────────

    #[test]
    fn run_command_secret_sets_env_for_child() {
        let _guard = EnvGuard::lock_only();
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf %s \"$AIRLOCK_TEST_OVERRIDE\"".to_string(),
        ];
        let env = crate::config::CommandEnv {
            clear: false,
            set: [(
                "AIRLOCK_TEST_OVERRIDE".to_string(),
                "child-saw-this".to_string(),
            )]
            .into_iter()
            .collect(),
        };
        let out = run_command_secret(&argv, Duration::from_secs(5), &env).unwrap();
        assert_eq!(out, "child-saw-this");
    }

    #[test]
    fn run_command_secret_env_clear_drops_inherited_env() {
        let _guard = EnvGuard::new(&[("AIRLOCK_TEST_CLEARED", "parent-value")]);
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf %s \"${AIRLOCK_TEST_CLEARED-MISSING}\"".to_string(),
        ];
        let env = crate::config::CommandEnv {
            clear: true,
            set: std::collections::BTreeMap::new(),
        };
        let out = run_command_secret(&argv, Duration::from_secs(5), &env).unwrap();
        assert_eq!(out, "MISSING");
    }

    #[test]
    fn run_command_secret_env_clear_plus_set_only_exposes_set_var() {
        let _guard = EnvGuard::new(&[("AIRLOCK_TEST_PARENT", "leaked")]);
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf %s=%s/%s \"EXPLICIT\" \"${AIRLOCK_EXPLICIT}\" \"${AIRLOCK_TEST_PARENT-MISSING}\""
                .to_string(),
        ];
        let env = crate::config::CommandEnv {
            clear: true,
            set: [("AIRLOCK_EXPLICIT".to_string(), "seen".to_string())]
                .into_iter()
                .collect(),
        };
        let out = run_command_secret(&argv, Duration::from_secs(5), &env).unwrap();
        assert_eq!(out, "EXPLICIT=seen/MISSING");
    }

    // ── collect_secrets_with / CommandContext ─────────────────────────────

    /// Build a `CommandContext` whose filtered `PATH` is `/bin:/usr/bin` —
    /// real system directories outside any test tempdir, so `sh` and other
    /// POSIX utilities actually resolve through it — plus the given
    /// snapshot, cwd, root and write grants.
    fn test_ctx(
        snapshot: std::collections::BTreeMap<String, String>,
        cwd: PathBuf,
        root: PathBuf,
        write_grants: Vec<PathBuf>,
    ) -> CommandContext {
        let path = crate::exec::filter_path("/bin:/usr/bin", &root, &write_grants);
        CommandContext {
            snapshot,
            path,
            cwd,
            root,
            write_grants,
        }
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    /// `source = "command"` under `collect_secrets_with` runs with `ctx`'s
    /// snapshot, not the process environment — proven with a snapshot value
    /// absent from the real process env — and `argv[0]` ("sh", a bare name)
    /// resolves through `ctx`'s filtered `PATH`.
    #[test]
    fn collect_secrets_with_command_uses_snapshot_and_filtered_path() {
        let root = tempdir().unwrap();
        let mut snapshot = std::collections::BTreeMap::new();
        snapshot.insert(
            "AIRLOCK_TEST_CTX_ONLY".to_string(),
            "from-the-snapshot".to_string(),
        );
        let ctx = test_ctx(
            snapshot,
            root.path().to_path_buf(),
            root.path().to_path_buf(),
            vec![],
        );

        let config = make_config_command(vec![(
            "pw",
            vec!["sh", "-c", "printf %s \"$AIRLOCK_TEST_CTX_ONLY\""],
            5,
        )]);

        let collected = collect_secrets_with(&config, &no_env, &ctx).expect("should succeed");
        assert_eq!(collected.values["pw"].expose_secret(), "from-the-snapshot");
    }

    /// `source = "env"` under `collect_secrets_with` reads `env_lookup`, and
    /// every variable it actually reads is reported in `consumed_env`.
    #[test]
    fn collect_secrets_with_reports_consumed_env() {
        let root = tempdir().unwrap();
        let ctx = test_ctx(
            std::collections::BTreeMap::new(),
            root.path().to_path_buf(),
            root.path().to_path_buf(),
            vec![],
        );
        let config = make_config_env(vec![
            ("alpha", "TEST_CTX_ENV_A"),
            ("beta", "TEST_CTX_ENV_B"),
        ]);

        let lookup = |name: &str| match name {
            "TEST_CTX_ENV_A" => Some("value-a".to_string()),
            "TEST_CTX_ENV_B" => Some("value-b".to_string()),
            _ => None,
        };

        let collected = collect_secrets_with(&config, &lookup, &ctx).expect("should succeed");
        assert_eq!(collected.values["alpha"].expose_secret(), "value-a");
        assert_eq!(collected.values["beta"].expose_secret(), "value-b");

        let mut consumed = collected.consumed_env.clone();
        consumed.sort();
        assert_eq!(consumed, vec!["TEST_CTX_ENV_A", "TEST_CTX_ENV_B"]);
    }

    /// `source = "env"` under `collect_secrets_with` never falls back to the
    /// process environment, even when `env_lookup` returns nothing and the
    /// process happens to have the variable set.
    #[test]
    fn collect_secrets_with_env_source_ignores_process_env() {
        let _guard = EnvGuard::new(&[("TEST_CTX_PROCESS_ONLY", "should-not-be-seen")]);
        let root = tempdir().unwrap();
        let ctx = test_ctx(
            std::collections::BTreeMap::new(),
            root.path().to_path_buf(),
            root.path().to_path_buf(),
            vec![],
        );
        let config = make_config_env(vec![("x", "TEST_CTX_PROCESS_ONLY")]);

        let err = collect_secrets_with(&config, &no_env, &ctx).unwrap_err();
        match err {
            SecretsError::MissingSecrets { missing } => {
                assert_eq!(missing, vec!["TEST_CTX_PROCESS_ONLY".to_string()]);
            }
            other => panic!("expected MissingSecrets, got: {other:?}"),
        }
    }

    /// An `argv[0]` containing `/` is resolved relative to `ctx.cwd` and
    /// refused when it lands inside the project root — `command =
    /// ["./scripts/token.sh"]` is a config error, not a one-off failure.
    #[test]
    fn collect_secrets_with_argv0_with_slash_inside_root_refused() {
        let root = tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("scripts")).unwrap();
        let script = root.path().join("scripts/token.sh");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();

        let ctx = test_ctx(
            std::collections::BTreeMap::new(),
            root.path().to_path_buf(),
            root.path().to_path_buf(),
            vec![],
        );
        let config = make_config_command(vec![("pw", vec!["./scripts/token.sh"], 5)]);

        let err = collect_secrets_with(&config, &no_env, &ctx).unwrap_err();
        match err {
            SecretsError::CommandUnusable(msg) => {
                assert!(msg.contains("secret pw"));
                assert!(msg.contains("./scripts/token.sh"));
                assert!(msg.contains("inside the project"));
            }
            other => panic!("expected CommandUnusable, got: {other:?}"),
        }
    }

    /// Same check, but the offending path is inside a write grant rather
    /// than the root.
    #[test]
    fn collect_secrets_with_argv0_with_slash_inside_write_grant_refused() {
        let root = tempdir().unwrap();
        let grant_dir = tempdir().unwrap();
        let script = grant_dir.path().join("token.sh");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();

        let ctx = test_ctx(
            std::collections::BTreeMap::new(),
            root.path().to_path_buf(),
            root.path().to_path_buf(),
            vec![grant_dir.path().to_path_buf()],
        );
        let argv0 = script.to_string_lossy().into_owned();
        let config = make_config_command(vec![("pw", vec![argv0.as_str()], 5)]);

        let err = collect_secrets_with(&config, &no_env, &ctx).unwrap_err();
        match err {
            SecretsError::CommandUnusable(msg) => {
                assert!(msg.contains("secret pw"));
                assert!(msg.contains("inside a write grant"));
            }
            other => panic!("expected CommandUnusable, got: {other:?}"),
        }
    }

    /// A bare `argv[0]` not found on the filtered `PATH` reports the
    /// dropped entries and why, like the tool "binary not found" message.
    #[test]
    fn collect_secrets_with_command_not_on_path_lists_dropped() {
        let root = tempdir().unwrap();
        let mut ctx = test_ctx(
            std::collections::BTreeMap::new(),
            root.path().to_path_buf(),
            root.path().to_path_buf(),
            vec![],
        );
        // Force a known drop so the message has something concrete to name.
        ctx.path
            .dropped
            .push(("relative/bin".to_string(), "relative".to_string()));
        let config = make_config_command(vec![("pw", vec!["totally_missing_tool_xyzzy"], 5)]);

        let err = collect_secrets_with(&config, &no_env, &ctx).unwrap_err();
        match err {
            SecretsError::CommandUnusable(msg) => {
                assert!(msg.contains("secret pw"));
                assert!(msg.contains("totally_missing_tool_xyzzy"));
                assert!(msg.contains("session's PATH"));
                assert!(msg.contains("relative/bin"));
            }
            other => panic!("expected CommandUnusable, got: {other:?}"),
        }
    }

    /// A command that resolves and runs, but exits non-zero, is reported
    /// per the UX table: the command backticked, its stderr indented
    /// beneath it, batched under `CommandRunFailures`.
    #[test]
    fn collect_secrets_with_run_failure_is_formatted_and_batched() {
        let root = tempdir().unwrap();
        let ctx = test_ctx(
            std::collections::BTreeMap::new(),
            root.path().to_path_buf(),
            root.path().to_path_buf(),
            vec![],
        );
        let config =
            make_config_command(vec![("pw", vec!["sh", "-c", "echo boom >&2; exit 3"], 5)]);

        let err = collect_secrets_with(&config, &no_env, &ctx).unwrap_err();
        match err {
            SecretsError::CommandRunFailures { messages } => {
                assert_eq!(messages.len(), 1);
                assert!(messages[0].contains("secret pw"));
                assert!(messages[0].contains('`'));
                assert!(messages[0].contains("exited with"));
                assert!(messages[0].contains("\n  boom"));
            }
            other => panic!("expected CommandRunFailures, got: {other:?}"),
        }
    }

    // ── Environment clearing tests ───────────────────────────────────────

    #[test]
    fn clear_removes_env_source_vars() {
        let _guard = EnvGuard::new(&[
            ("TEST_CLEAR_SEC_A", "secret_a"),
            ("TEST_CLEAR_SEC_B", "secret_b"),
        ]);

        let config = make_config_env(vec![("a", "TEST_CLEAR_SEC_A"), ("b", "TEST_CLEAR_SEC_B")]);

        assert!(std::env::var("TEST_CLEAR_SEC_A").is_ok());
        clear_secret_env_vars(&config);
        assert!(std::env::var("TEST_CLEAR_SEC_A").is_err());
        assert!(std::env::var("TEST_CLEAR_SEC_B").is_err());
    }

    #[test]
    fn clear_does_not_remove_unrelated_vars() {
        let _guard = EnvGuard::new(&[
            ("TEST_CLEAR_KEEP", "keep_this"),
            ("TEST_CLEAR_REMOVE", "remove_this"),
        ]);

        let config = make_config_env(vec![("r", "TEST_CLEAR_REMOVE")]);
        clear_secret_env_vars(&config);

        assert_eq!(std::env::var("TEST_CLEAR_KEEP").unwrap(), "keep_this");
        assert!(std::env::var("TEST_CLEAR_REMOVE").is_err());
    }

    #[test]
    fn clear_ignores_command_source_secrets() {
        let _guard = EnvGuard::lock_only();

        // A command-source secret has no env var to clear; the function must
        // simply skip it without panicking.
        let config = make_config_command(vec![("pw", vec!["echo", "x"], 5)]);
        clear_secret_env_vars(&config);
    }

    #[test]
    fn clear_deduplicates_when_two_labels_share_a_source() {
        let _guard = EnvGuard::new(&[("TEST_CLEAR_DUP", "dup_value")]);

        // Two different labels pointing at the same `from` — clearing must
        // not panic on the duplicate `remove_var` attempt.
        let config = make_config_env(vec![("one", "TEST_CLEAR_DUP"), ("two", "TEST_CLEAR_DUP")]);
        clear_secret_env_vars(&config);

        assert!(std::env::var("TEST_CLEAR_DUP").is_err());
    }

    // ── Error type tests ─────────────────────────────────────────────────

    #[test]
    fn secrets_error_is_std_error() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<SecretsError>();
    }

    #[test]
    fn secrets_error_missing_display_lists_names() {
        let err = SecretsError::MissingSecrets {
            missing: vec!["API_KEY".to_string(), "DB_PASS".to_string()],
        };
        let msg = err.to_string();
        assert!(msg.contains("API_KEY"));
        assert!(msg.contains("DB_PASS"));
        assert!(msg.contains("missing secret environment variables"));
    }

    #[test]
    fn secrets_error_command_failures_display() {
        let err = SecretsError::CommandFailures {
            failures: vec![
                ("alpha".to_string(), "exited with status 1".to_string()),
                ("beta".to_string(), "timed out after 5s".to_string()),
            ],
        };
        let msg = err.to_string();
        assert!(msg.contains("[secrets.alpha]"));
        assert!(msg.contains("[secrets.beta]"));
        assert!(msg.contains("timed out"));
    }

    #[test]
    fn secrets_error_invalid_utf8_display() {
        let err = SecretsError::InvalidUtf8 {
            name: "BAD_VAR".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("BAD_VAR"));
        assert!(msg.contains("invalid UTF-8"));
    }
}
