//! Background refresh of `source = "command"` secrets.
//!
//! For each secret whose config carries a [`RefreshSpec`], the daemon spawns
//! a long-lived tokio task that periodically re-runs the command — under the
//! owning session's [`CommandContext`], never the daemon's own environment —
//! and swaps the in-memory value. On failure the slot's [`Health`] flips to
//! [`Health::Stale`] — the previous value is kept in memory, but the exec
//! path refuses it. Refresh keeps trying with exponential backoff capped at
//! `refresh_max_backoff`; the slot returns to `Healthy` on the next success.
//!
//! # Concurrency model
//!
//! - Per-secret state lives in `RwLock<SecretSlot>` keyed inside a fixed
//!   `Arc<HashMap<...>>` ([`SecretStore`]). The lock is held only for the
//!   microseconds it takes to swap an `Arc` or read/clone health.
//! - The redactor is shared as [`RedactorSwap`]. An exec snapshots the
//!   inner `Arc<Redactor>` once, right after it reads the tool's secrets, and
//!   keeps that snapshot for the child's lifetime.
//! - On every successful refresh the redactor is rebuilt with two generations
//!   per refreshed secret (current + previous) and swapped in *before* the
//!   new value is published to the slot, so no reader can ever hand a secret
//!   upstream that the live redactor doesn't know. The retired previous value
//!   drops one cycle later — this is a deliberate trade-off against
//!   `Secret<T>`'s eager-zeroize guarantee, in exchange for closing the
//!   redaction gap during a swap.
//! - Rebuild, swap and publish run under one mutex in `RefreshShared`,
//!   shared by all refresh tasks of one session. The rebuild reads every
//!   slot, so two overlapping refreshes could otherwise swap in a redactor
//!   built before the other one published, and it would miss a value the
//!   proxy is already injecting.
//! - `on_refresh` runs after every successful refresh, so the daemon can
//!   rebuild its cross-session global redactor (docs/airlock-v2-design.md,
//!   "Session isolation") without this module knowing anything about other
//!   sessions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::config::{CommandEnv, Config, RefreshSpec, SecretSource};
use crate::daemon::RingBuffer;
use crate::redact::{Redactor, RedactorSwap};
use crate::secrets::{CommandContext, Health, Secret, SecretStore};

/// Initial sleep before the first retry after a refresh failure.
const INITIAL_BACKOFF: Duration = Duration::from_secs(5);

/// The value each refreshed secret held before its latest refresh, keyed by
/// label. Shared with the daemon so its global redactor covers these too.
pub type PreviousValues = Arc<Mutex<HashMap<String, Arc<Secret<String>>>>>;

/// What all of one session's refresh tasks share.
pub(crate) struct RefreshShared {
    store: SecretStore,
    redactor_swap: RedactorSwap,
    /// The value each refreshed secret held before its latest refresh, keyed
    /// by label. Every redactor rebuild includes these, and the mutex
    /// serializes refreshes (see the module docs).
    previous: PreviousValues,
    ring: RingBuffer,
    on_refresh: Arc<dyn Fn() + Send + Sync>,
}

impl RefreshShared {
    pub(crate) fn new(
        store: SecretStore,
        redactor_swap: RedactorSwap,
        ring: RingBuffer,
        on_refresh: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        RefreshShared {
            store,
            redactor_swap,
            previous: PreviousValues::default(),
            ring,
            on_refresh,
        }
    }
}

/// Spawn one refresh task per `[secrets.<label>]` entry that declares
/// `refresh = N`, running each command under `ctx` — the session's own
/// environment snapshot and filtered `PATH`. Returns the task set, a
/// shutdown sender — set the channel to `true` to ask all tasks to stop,
/// then `await` the [`JoinSet`] — and the session's previous values.
pub fn spawn_all_ctx(
    config: &Config,
    store: SecretStore,
    redactor_swap: RedactorSwap,
    ring: RingBuffer,
    ctx: Arc<CommandContext>,
    on_refresh: Arc<dyn Fn() + Send + Sync>,
) -> (JoinSet<()>, watch::Sender<bool>, PreviousValues) {
    let (tx, rx) = watch::channel(false);
    let mut set = JoinSet::new();
    let shared = Arc::new(RefreshShared::new(store, redactor_swap, ring, on_refresh));
    let previous = Arc::clone(&shared.previous);

    for (label, spec) in &config.secrets {
        let SecretSource::Command {
            argv,
            timeout,
            refresh: Some(refresh),
            env,
        } = &spec.source
        else {
            continue;
        };
        let task = RefreshTask {
            label: label.clone(),
            argv: argv.clone(),
            timeout: *timeout,
            refresh: refresh.clone(),
            env: env.clone(),
            shared: Arc::clone(&shared),
            ctx: Arc::clone(&ctx),
            shutdown: rx.clone(),
        };
        set.spawn(task.run());
    }

    (set, tx, previous)
}

/// Compute the next sleep after `consecutive_failures` consecutive refresh
/// failures: `INITIAL_BACKOFF * 2^(consecutive_failures - 1)`, capped at
/// `max`. Saturating arithmetic so high failure counts don't panic.
pub(crate) fn next_backoff(consecutive_failures: u32, max: Duration) -> Duration {
    if consecutive_failures == 0 {
        return INITIAL_BACKOFF.min(max);
    }
    let shift = consecutive_failures.saturating_sub(1);
    let multiplier: u64 = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let secs = INITIAL_BACKOFF
        .as_secs()
        .saturating_mul(multiplier)
        .min(max.as_secs());
    Duration::from_secs(secs)
}

/// State carried by a per-secret refresh task.
struct RefreshTask {
    label: String,
    argv: Vec<String>,
    timeout: Duration,
    refresh: RefreshSpec,
    env: CommandEnv,
    shared: Arc<RefreshShared>,
    ctx: Arc<CommandContext>,
    shutdown: watch::Receiver<bool>,
}

impl RefreshTask {
    async fn run(mut self) {
        let mut consecutive_failures: u32 = 0;
        let mut next_sleep = self.refresh.interval;

        loop {
            let sleep = tokio::time::sleep(next_sleep);
            tokio::select! {
                _ = sleep => {}
                _ = self.shutdown.changed() => {
                    if *self.shutdown.borrow() {
                        return;
                    }
                }
            }

            let label = self.label.clone();
            let argv = self.argv.clone();
            let timeout = self.timeout;
            let env = self.env.clone();
            let ctx = Arc::clone(&self.ctx);
            let shared = Arc::clone(&self.shared);

            let res = tokio::task::spawn_blocking(move || {
                refresh_once_ctx(&label, &argv, timeout, &env, &ctx, &shared)
            })
            .await
            .unwrap_or_else(|join_err| Err(format!("refresh task panicked: {join_err}")));

            match res {
                Ok(()) => {
                    consecutive_failures = 0;
                    next_sleep = self.refresh.interval;
                }
                Err(_) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    next_sleep = next_backoff(consecutive_failures, self.refresh.max_backoff);
                }
            }
        }
    }
}

/// Run one refresh attempt synchronously under a session's
/// [`CommandContext`] — its own environment snapshot and filtered `PATH`,
/// never the daemon's own environment.
///
/// See [`apply_refresh_result`] for what happens to the slot and redactor.
pub(crate) fn refresh_once_ctx(
    label: &str,
    argv: &[String],
    timeout: Duration,
    env: &CommandEnv,
    ctx: &CommandContext,
    shared: &RefreshShared,
) -> Result<(), String> {
    let result =
        crate::secrets::run_command_with_ctx(argv, timeout, env, ctx).map_err(|e| e.to_flat(label));
    apply_refresh_result(label, result, shared)
}

/// On success, rebuild the redactor with two generations for this secret and
/// swap it in, then publish the freshly-fetched value to the slot and mark
/// it `Healthy`, then call `shared.on_refresh` so the caller can rebuild any
/// redactor that spans more than this session. On failure, mark the slot
/// `Stale`, leave the value alone (so its bytes still feed the redactor), and
/// log to the ring buffer.
///
/// The redactor must be swapped *before* the slot is published: anything
/// that reads the slot (the proxy's credential injection, exec's env
/// building) may send the new value upstream immediately, and the redactor
/// snapshot taken for that response has to already know it. Publishing
/// first would open a window where an echoing upstream returns the new
/// secret to the tool in plaintext.
fn apply_refresh_result(
    label: &str,
    result: Result<String, String>,
    shared: &RefreshShared,
) -> Result<(), String> {
    let RefreshShared {
        store,
        redactor_swap,
        previous,
        ring,
        on_refresh,
    } = shared;
    match result {
        Ok(value) => {
            let new_value = Arc::new(Secret::new(value));
            let slot_lock = store
                .get(label)
                .ok_or_else(|| format!("secret label {label:?} missing from store"))?;

            // Held until the new value is published; see the module docs.
            let mut previous = previous.lock().unwrap_or_else(|e| e.into_inner());
            let previous_value = {
                let slot = slot_lock.read().unwrap_or_else(|e| e.into_inner());
                Arc::clone(&slot.value)
            };
            previous.insert(label.to_string(), previous_value);

            rebuild_redactor(store, &previous, label, &new_value, redactor_swap)?;

            let was_stale = {
                let mut slot = slot_lock.write().unwrap_or_else(|e| e.into_inner());
                let was_stale = matches!(slot.health, Health::Stale { .. });
                slot.value = new_value;
                slot.health = Health::Healthy;
                was_stale
            };
            if was_stale {
                ring.log(format!(
                    "secret refresh recovered for {label} (now healthy)"
                ));
            } else {
                ring.log(format!("secret refresh succeeded for {label}"));
            }
            // Released first: `on_refresh` rebuilds the global redactor,
            // which reads `previous` too.
            drop(previous);
            on_refresh();
            Ok(())
        }
        Err(reason) => {
            ring.log(format!("secret refresh failed for {label}: {reason}"));
            let slot_lock = store
                .get(label)
                .ok_or_else(|| format!("secret label {label:?} missing from store"))?;
            let mut slot = slot_lock.write().unwrap_or_else(|e| e.into_inner());
            slot.health = Health::Stale {
                reason: reason.clone(),
                since: Instant::now(),
            };
            Err(reason)
        }
    }
}

/// Rebuild the shared [`Redactor`] from the current store and the previous
/// generation of every refreshed secret, with `refreshed_current` standing
/// in for the not-yet-published value of `refreshed_label`.
fn rebuild_redactor(
    store: &SecretStore,
    previous: &HashMap<String, Arc<Secret<String>>>,
    refreshed_label: &str,
    refreshed_current: &Arc<Secret<String>>,
    redactor_swap: &RedactorSwap,
) -> Result<(), String> {
    let mut owned: HashMap<String, Vec<Arc<Secret<String>>>> = HashMap::with_capacity(store.len());
    for (label, slot_lock) in store.iter() {
        let current = if label == refreshed_label {
            Arc::clone(refreshed_current)
        } else {
            let slot = slot_lock.read().unwrap_or_else(|e| e.into_inner());
            Arc::clone(&slot.value)
        };
        let mut gens = vec![current];
        gens.extend(previous.get(label).cloned());
        owned.insert(label.clone(), gens);
    }

    let refs: Vec<(&str, &[Arc<Secret<String>>])> = owned
        .iter()
        .map(|(name, gens)| (name.as_str(), gens.as_slice()))
        .collect();
    let new_redactor = Redactor::build_from_generations(refs)
        .map_err(|e| format!("failed to rebuild redactor: {e}"))?;

    let mut slot = redactor_swap.write().unwrap_or_else(|e| e.into_inner());
    *slot = Arc::new(new_redactor);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{Health, SecretSlot};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::RwLock;

    fn empty_redactor_swap() -> RedactorSwap {
        let r = Redactor::new(std::iter::empty()).unwrap();
        Arc::new(RwLock::new(Arc::new(r)))
    }

    fn noop_callback() -> Arc<dyn Fn() + Send + Sync> {
        Arc::new(|| {})
    }

    fn store_with(label: &str, value: &str) -> SecretStore {
        let mut map = HashMap::new();
        map.insert(
            label.to_string(),
            RwLock::new(SecretSlot {
                value: Arc::new(Secret::new(value.to_string())),
                health: Health::Healthy,
            }),
        );
        Arc::new(map)
    }

    fn read_value(store: &SecretStore, label: &str) -> String {
        let slot = store[label].read().unwrap();
        slot.value.expose_secret().clone()
    }

    fn read_health(store: &SecretStore, label: &str) -> Health {
        let slot = store[label].read().unwrap();
        slot.health.clone()
    }

    fn echo_argv(s: &str) -> Vec<String> {
        vec!["/bin/echo".to_string(), s.to_string()]
    }

    fn nonexistent_argv() -> Vec<String> {
        vec![
            PathBuf::from("/var/empty/airlock-no-such-binary")
                .to_string_lossy()
                .to_string(),
        ]
    }

    /// Build a `CommandContext` with a filtered `PATH` of real system
    /// directories (`/bin:/usr/bin`) — so `sh`/`echo` actually resolve — and
    /// a snapshot of the caller's choosing, rooted at `root` with no write
    /// grants.
    fn test_ctx(
        root: &std::path::Path,
        snapshot: std::collections::BTreeMap<String, String>,
    ) -> CommandContext {
        let path = crate::exec::filter_path("/bin:/usr/bin", root, &[]);
        CommandContext {
            snapshot,
            path,
            cwd: root.to_path_buf(),
            root: root.to_path_buf(),
            write_grants: Vec::new(),
        }
    }

    #[test]
    fn next_backoff_doubles_until_capped() {
        let max = Duration::from_secs(60);
        assert_eq!(next_backoff(1, max), Duration::from_secs(5));
        assert_eq!(next_backoff(2, max), Duration::from_secs(10));
        assert_eq!(next_backoff(3, max), Duration::from_secs(20));
        assert_eq!(next_backoff(4, max), Duration::from_secs(40));
        assert_eq!(next_backoff(5, max), Duration::from_secs(60));
        assert_eq!(next_backoff(20, max), Duration::from_secs(60));
    }

    #[test]
    fn next_backoff_saturates_safely_at_high_counts() {
        let max = Duration::from_secs(1_800);
        assert_eq!(next_backoff(u32::MAX, max), max);
    }

    #[test]
    fn next_backoff_zero_failures_returns_initial() {
        assert_eq!(
            next_backoff(0, Duration::from_secs(60)),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn refresh_once_ctx_uses_context_snapshot_and_marks_healthy() {
        let tmp = tempfile::tempdir().unwrap();
        let mut snapshot = std::collections::BTreeMap::new();
        snapshot.insert(
            "AIRLOCK_REFRESH_CTX_TEST".to_string(),
            "ctx-value".to_string(),
        );
        let ctx = test_ctx(tmp.path(), snapshot);

        let shared = &RefreshShared::new(
            store_with("TOK", "old"),
            empty_redactor_swap(),
            RingBuffer::new(),
            noop_callback(),
        );

        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            "printf %s \"$AIRLOCK_REFRESH_CTX_TEST\"".to_string(),
        ];
        let res = refresh_once_ctx(
            "TOK",
            &argv,
            Duration::from_secs(5),
            &CommandEnv::default(),
            &ctx,
            shared,
        );
        assert!(res.is_ok(), "{res:?}");
        assert_eq!(read_value(&shared.store, "TOK"), "ctx-value");
        assert!(matches!(read_health(&shared.store, "TOK"), Health::Healthy));
    }

    #[test]
    fn refresh_once_ctx_calls_on_refresh_on_success() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path(), std::collections::BTreeMap::new());
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called_clone = Arc::clone(&called);
        let shared = &RefreshShared::new(
            store_with("TOK", "old"),
            empty_redactor_swap(),
            RingBuffer::new(),
            Arc::new(move || called_clone.store(true, std::sync::atomic::Ordering::SeqCst)),
        );

        refresh_once_ctx(
            "TOK",
            &echo_argv("new-value"),
            Duration::from_secs(2),
            &CommandEnv::default(),
            &ctx,
            shared,
        )
        .unwrap();
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn refresh_once_ctx_does_not_call_on_refresh_on_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path(), std::collections::BTreeMap::new());
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called_clone = Arc::clone(&called);
        let shared = &RefreshShared::new(
            store_with("TOK", "still-good"),
            empty_redactor_swap(),
            RingBuffer::new(),
            Arc::new(move || called_clone.store(true, std::sync::atomic::Ordering::SeqCst)),
        );

        let _ = refresh_once_ctx(
            "TOK",
            &nonexistent_argv(),
            Duration::from_secs(1),
            &CommandEnv::default(),
            &ctx,
            shared,
        );
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn refresh_once_ctx_refuses_command_inside_root_and_marks_stale() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("scripts")).unwrap();
        let script = tmp.path().join("scripts/token.sh");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();

        let ctx = test_ctx(tmp.path(), std::collections::BTreeMap::new());
        let shared = &RefreshShared::new(
            store_with("TOK", "still-good"),
            empty_redactor_swap(),
            RingBuffer::new(),
            noop_callback(),
        );

        let res = refresh_once_ctx(
            "TOK",
            &["./scripts/token.sh".to_string()],
            Duration::from_secs(5),
            &CommandEnv::default(),
            &ctx,
            shared,
        );
        assert!(res.is_err());
        let msg = res.unwrap_err();
        assert!(msg.contains("secret TOK"));
        assert!(msg.contains("inside the project"));
        assert_eq!(read_value(&shared.store, "TOK"), "still-good");
        assert!(matches!(
            read_health(&shared.store, "TOK"),
            Health::Stale { .. }
        ));
    }

    #[test]
    fn refresh_once_ctx_rebuilds_redactor_with_both_generations() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path(), std::collections::BTreeMap::new());
        let shared = &RefreshShared::new(
            store_with("TOK", "old-value"),
            empty_redactor_swap(),
            RingBuffer::new(),
            noop_callback(),
        );

        refresh_once_ctx(
            "TOK",
            &echo_argv("new-value"),
            Duration::from_secs(2),
            &CommandEnv::default(),
            &ctx,
            shared,
        )
        .unwrap();

        let redactor = shared.redactor_swap.read().unwrap().clone();
        let out = redactor.redact_bytes(b"saw old-value and new-value here");
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("old-value"), "old generation not redacted: {s}");
        assert!(!s.contains("new-value"), "new generation not redacted: {s}");
    }

    #[test]
    fn refresh_once_ctx_failure_marks_stale_and_keeps_value() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path(), std::collections::BTreeMap::new());
        let shared = &RefreshShared::new(
            store_with("TOK", "still-good-for-now"),
            empty_redactor_swap(),
            RingBuffer::new(),
            noop_callback(),
        );

        let res = refresh_once_ctx(
            "TOK",
            &nonexistent_argv(),
            Duration::from_secs(1),
            &CommandEnv::default(),
            &ctx,
            shared,
        );
        assert!(res.is_err());
        assert_eq!(read_value(&shared.store, "TOK"), "still-good-for-now");
        assert!(matches!(
            read_health(&shared.store, "TOK"),
            Health::Stale { .. }
        ));
        let log = shared
            .ring
            .entries()
            .iter()
            .map(|e| e.message.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            log.contains("secret refresh failed for TOK"),
            "missing log line, got: {log}"
        );
    }

    #[test]
    fn refresh_once_ctx_success_after_failure_restores_healthy() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path(), std::collections::BTreeMap::new());
        let shared = &RefreshShared::new(
            store_with("TOK", "old"),
            empty_redactor_swap(),
            RingBuffer::new(),
            noop_callback(),
        );

        let _ = refresh_once_ctx(
            "TOK",
            &nonexistent_argv(),
            Duration::from_secs(1),
            &CommandEnv::default(),
            &ctx,
            shared,
        );
        assert!(matches!(
            read_health(&shared.store, "TOK"),
            Health::Stale { .. }
        ));

        refresh_once_ctx(
            "TOK",
            &echo_argv("recovered"),
            Duration::from_secs(2),
            &CommandEnv::default(),
            &ctx,
            shared,
        )
        .unwrap();
        assert_eq!(read_value(&shared.store, "TOK"), "recovered");
        assert!(matches!(read_health(&shared.store, "TOK"), Health::Healthy));
    }

    #[tokio::test]
    async fn spawn_all_ctx_spawns_one_task_per_refreshable_secret() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.secrets.insert(
            "TOK".to_string(),
            crate::config::SecretSpec {
                label: "TOK".to_string(),
                source: SecretSource::Command {
                    argv: echo_argv("v"),
                    timeout: Duration::from_secs(2),
                    refresh: Some(RefreshSpec {
                        interval: Duration::from_secs(3600),
                        max_backoff: Duration::from_secs(3600),
                    }),
                    env: CommandEnv::default(),
                },
            },
        );
        let store = store_with("TOK", "old");
        let ctx = Arc::new(test_ctx(tmp.path(), std::collections::BTreeMap::new()));

        let (mut tasks, tx, _previous) = spawn_all_ctx(
            &config,
            store,
            empty_redactor_swap(),
            RingBuffer::new(),
            ctx,
            noop_callback(),
        );
        assert_eq!(tasks.len(), 1);
        let _ = tx.send(true);
        let drain = async { while tasks.join_next().await.is_some() {} };
        tokio::time::timeout(Duration::from_secs(2), drain)
            .await
            .unwrap();
    }

    fn test_config() -> Config {
        Config {
            sandbox_root: PathBuf::from("/tmp"),
            timeout: Duration::from_secs(300),
            access: crate::sandbox::ToolAccess::default(),
            filesystem_read: Vec::new(),
            filesystem_write: Vec::new(),
            secrets: HashMap::new(),
            tools: HashMap::new(),
            agent: None,
            tool_state_dirs: Vec::new(),
        }
    }
}
