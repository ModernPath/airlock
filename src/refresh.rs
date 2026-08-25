//! Background refresh of `source = "command"` secrets.
//!
//! For each secret whose config carries a [`RefreshSpec`], the daemon spawns
//! a long-lived tokio task that periodically re-runs the command and swaps
//! the in-memory value. On failure the slot's [`Health`] flips to
//! [`Health::Stale`] — the previous value is kept in memory, but the exec
//! path refuses it. Refresh keeps trying with exponential backoff capped at
//! `refresh_max_backoff`; the slot returns to `Healthy` on the next success.
//!
//! # Concurrency model
//!
//! - Per-secret state lives in `RwLock<SecretSlot>` keyed inside a fixed
//!   `Arc<HashMap<...>>` ([`SecretStore`]). The lock is held only for the
//!   microseconds it takes to swap an `Arc` or read/clone health.
//! - The redactor is shared as `Arc<RwLock<Arc<Redactor>>>`. Connection
//!   handlers snapshot the inner `Arc<Redactor>` once at accept time, so
//!   in-flight streams keep their old redactor for their lifetime.
//! - On every successful refresh the redactor is rebuilt with two generations
//!   per refreshable secret (current + previous). The retired previous value
//!   drops one cycle later — this is a deliberate trade-off against
//!   `Secret<T>`'s eager-zeroize guarantee, in exchange for closing the
//!   redaction gap during a swap.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::config::{CommandEnv, Config, RefreshSpec, SecretSource};
use crate::daemon::RingBuffer;
use crate::redact::Redactor;
use crate::secrets::{Health, Secret, SecretStore, run_command_secret};

/// Initial sleep before the first retry after a refresh failure.
const INITIAL_BACKOFF: Duration = Duration::from_secs(5);

/// Spawn one refresh task per `[secrets.<label>]` entry that declares
/// `refresh = N`. Returns the task set and a shutdown sender — set the
/// channel to `true` to ask all tasks to stop, then `await` the [`JoinSet`].
pub fn spawn_all(
    config: &Config,
    store: SecretStore,
    redactor_swap: Arc<RwLock<Arc<Redactor>>>,
    ring: RingBuffer,
) -> (JoinSet<()>, watch::Sender<bool>) {
    let (tx, rx) = watch::channel(false);
    let mut set = JoinSet::new();

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
            store: Arc::clone(&store),
            redactor_swap: Arc::clone(&redactor_swap),
            ring: ring.clone(),
            shutdown: rx.clone(),
        };
        set.spawn(task.run());
    }

    (set, tx)
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
    store: SecretStore,
    redactor_swap: Arc<RwLock<Arc<Redactor>>>,
    ring: RingBuffer,
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
            let store = Arc::clone(&self.store);
            let redactor_swap = Arc::clone(&self.redactor_swap);
            let ring = self.ring.clone();

            let res = tokio::task::spawn_blocking(move || {
                refresh_once(&label, &argv, timeout, &env, &store, &redactor_swap, &ring)
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

/// Run one refresh attempt synchronously. On success, swap the slot's value
/// to the freshly-fetched one, mark `Healthy`, and rebuild the redactor with
/// two generations per refreshable secret. On failure, mark the slot
/// `Stale`, leave the value alone (so its bytes still feed the redactor),
/// and log to the ring buffer.
pub(crate) fn refresh_once(
    label: &str,
    argv: &[String],
    timeout: Duration,
    env: &CommandEnv,
    store: &SecretStore,
    redactor_swap: &RwLock<Arc<Redactor>>,
    ring: &RingBuffer,
) -> Result<(), String> {
    match run_command_secret(argv, timeout, env) {
        Ok(value) => {
            let new_value = Arc::new(Secret::new(value));
            let (previous_value, was_stale) = {
                let slot_lock = store
                    .get(label)
                    .ok_or_else(|| format!("secret label {label:?} missing from store"))?;
                let mut slot = slot_lock.write().unwrap_or_else(|e| e.into_inner());
                let prev = Arc::clone(&slot.value);
                let was_stale = matches!(slot.health, Health::Stale { .. });
                slot.value = Arc::clone(&new_value);
                slot.health = Health::Healthy;
                (prev, was_stale)
            };

            rebuild_redactor(
                store,
                label,
                &new_value,
                Some(&previous_value),
                redactor_swap,
            )?;
            if was_stale {
                ring.log(format!(
                    "secret refresh recovered for {label} (now healthy)"
                ));
            } else {
                ring.log(format!("secret refresh succeeded for {label}"));
            }
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

/// Rebuild the shared [`Redactor`] from the current store, plus an extra
/// "previous" generation for the secret that just got refreshed.
fn rebuild_redactor(
    store: &SecretStore,
    refreshed_label: &str,
    refreshed_current: &Arc<Secret<String>>,
    refreshed_previous: Option<&Arc<Secret<String>>>,
    redactor_swap: &RwLock<Arc<Redactor>>,
) -> Result<(), String> {
    let mut owned: HashMap<String, Vec<Arc<Secret<String>>>> = HashMap::with_capacity(store.len());
    for (label, slot_lock) in store.iter() {
        let slot = slot_lock.read().unwrap_or_else(|e| e.into_inner());
        owned.insert(label.clone(), vec![Arc::clone(&slot.value)]);
    }
    if let Some(prev) = refreshed_previous
        && let Some(gens) = owned.get_mut(refreshed_label)
    {
        gens.clear();
        gens.push(Arc::clone(refreshed_current));
        gens.push(Arc::clone(prev));
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

    fn empty_redactor_swap() -> Arc<RwLock<Arc<Redactor>>> {
        let r = Redactor::new(std::iter::empty()).unwrap();
        Arc::new(RwLock::new(Arc::new(r)))
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
        // Path that should never resolve on macOS or Linux.
        vec![
            PathBuf::from("/var/empty/airlock-no-such-binary")
                .to_string_lossy()
                .to_string(),
        ]
    }

    #[test]
    fn next_backoff_doubles_until_capped() {
        let max = Duration::from_secs(60);
        assert_eq!(next_backoff(1, max), Duration::from_secs(5));
        assert_eq!(next_backoff(2, max), Duration::from_secs(10));
        assert_eq!(next_backoff(3, max), Duration::from_secs(20));
        assert_eq!(next_backoff(4, max), Duration::from_secs(40));
        // 5 → 80 capped to 60
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
    fn refresh_once_replaces_value_and_marks_healthy() {
        let store = store_with("TOK", "old");
        let swap = empty_redactor_swap();
        let ring = RingBuffer::new();

        let res = refresh_once(
            "TOK",
            &echo_argv("new-value"),
            Duration::from_secs(2),
            &CommandEnv::default(),
            &store,
            &swap,
            &ring,
        );
        assert!(res.is_ok(), "{res:?}");
        assert_eq!(read_value(&store, "TOK"), "new-value");
        assert!(matches!(read_health(&store, "TOK"), Health::Healthy));
    }

    #[test]
    fn refresh_once_rebuilds_redactor_with_both_generations() {
        let store = store_with("TOK", "old-value");
        let swap = empty_redactor_swap();
        let ring = RingBuffer::new();

        refresh_once(
            "TOK",
            &echo_argv("new-value"),
            Duration::from_secs(2),
            &CommandEnv::default(),
            &store,
            &swap,
            &ring,
        )
        .unwrap();

        let redactor = swap.read().unwrap().clone();
        let out = redactor.redact_bytes(b"saw old-value and new-value here");
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("old-value"), "old generation not redacted: {s}");
        assert!(!s.contains("new-value"), "new generation not redacted: {s}");
    }

    #[test]
    fn refresh_once_failure_marks_stale_and_keeps_value() {
        let store = store_with("TOK", "still-good-for-now");
        let swap = empty_redactor_swap();
        let ring = RingBuffer::new();

        let res = refresh_once(
            "TOK",
            &nonexistent_argv(),
            Duration::from_secs(1),
            &CommandEnv::default(),
            &store,
            &swap,
            &ring,
        );
        assert!(res.is_err());
        // Value preserved.
        assert_eq!(read_value(&store, "TOK"), "still-good-for-now");
        // Health flipped.
        assert!(matches!(read_health(&store, "TOK"), Health::Stale { .. }));
        // Failure logged.
        let log = ring
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
    fn refresh_once_success_after_failure_restores_healthy() {
        let store = store_with("TOK", "old");
        let swap = empty_redactor_swap();
        let ring = RingBuffer::new();

        // Force into Stale.
        let _ = refresh_once(
            "TOK",
            &nonexistent_argv(),
            Duration::from_secs(1),
            &CommandEnv::default(),
            &store,
            &swap,
            &ring,
        );
        assert!(matches!(read_health(&store, "TOK"), Health::Stale { .. }));

        // Successful refresh restores Healthy.
        refresh_once(
            "TOK",
            &echo_argv("recovered"),
            Duration::from_secs(2),
            &CommandEnv::default(),
            &store,
            &swap,
            &ring,
        )
        .unwrap();
        assert_eq!(read_value(&store, "TOK"), "recovered");
        assert!(matches!(read_health(&store, "TOK"), Health::Healthy));
    }
}
