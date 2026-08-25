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

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;
use zeroize::Zeroize;

use crate::config::{Config, SecretSource};

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

/// Spawn `argv` and capture its stdout as a secret value, with a wall-clock
/// timeout.
///
/// The command inherits the daemon's environment (so tools like `op` and
/// `vault` can read `OP_SERVICE_ACCOUNT_TOKEN` / `VAULT_ADDR`). Stdin is
/// connected to `/dev/null`. Stdout is the value; stderr is captured only to
/// enrich failure messages. Trailing `\n`/`\r` are trimmed from stdout for
/// convenience (most CLIs emit a newline).
///
/// Timeout is enforced by polling `try_wait` with a 50 ms tick. If stdout is
/// very large (>64 KiB) it may block the child before it exits; for secret
/// fetching this is an acceptable constraint.
pub(crate) fn run_command_secret(
    argv: &[String],
    timeout: Duration,
    env: &crate::config::CommandEnv,
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

    let mut child = cmd.spawn().map_err(|e| format!("spawn failed: {e}"))?;

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                if let Some(mut pipe) = child.stdout.take() {
                    pipe.read_to_string(&mut stdout)
                        .map_err(|e| format!("failed to read stdout: {e}"))?;
                }
                if !status.success() {
                    let mut stderr = String::new();
                    if let Some(mut pipe) = child.stderr.take() {
                        let _ = pipe.read_to_string(&mut stderr);
                    }
                    let trimmed = stderr.trim();
                    return Err(if trimmed.is_empty() {
                        format!("exited with {status}")
                    } else {
                        format!("exited with {status}: {trimmed}")
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
                    return Err(format!("timed out after {}s", timeout.as_secs()));
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("wait failed: {e}")),
        }
    }
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
    use std::sync::{Mutex, MutexGuard};
    use std::time::Duration;

    use crate::config::{Config, SecretSpec};

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Global mutex that serializes all tests that modify environment variables.
    ///
    /// Environment variables are process-global state. Without serialization,
    /// concurrent tests that modify env vars race against each other, producing
    /// flaky failures.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// RAII guard that sets environment variables for the duration of a test
    /// and restores them when dropped. Also holds the [`ENV_MUTEX`] lock.
    struct EnvGuard {
        vars: Vec<(String, Option<String>)>,
        _lock: MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        /// Set the given environment variables, saving their previous values
        /// for restoration on drop.
        fn new(vars: &[(&str, &str)]) -> Self {
            let lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
            let mut saved = Vec::with_capacity(vars.len());

            for (key, value) in vars {
                let prev = std::env::var(*key).ok();
                saved.push((key.to_string(), prev));
                // SAFETY: We hold ENV_MUTEX, so no other test thread is reading
                // or writing env vars concurrently within this test module.
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
            let lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
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
