//! Session state: the daemon's multi-tenant registry.
//!
//! A session binds a client to one project: its root, its approved config
//! and the secrets resolved for it (docs/airlock-v2-design.md, "Sessions").
//! Everything sensitive — secrets, the redactor, the proxy, the environment
//! snapshot and filtered `PATH` — lives behind [`Session::policy`], an
//! `Arc` that `Reload` swaps in one step. Request handlers receive an
//! `Arc<Session>` (resolved from the presented token) and never look
//! anything up in a global map keyed by label.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, EnvValue};
use crate::daemon::RingBuffer;
use crate::exec::FilteredPath;
use crate::process_tree::ProcId;
use crate::protocol::{
    EndsInfo, EnvDisplay, ErrorKind, RegisterPayload, SandboxKind, SessionId, SessionInfo,
    SessionToken, ToolInfo, WireAnchors, WireLayer, WireMode,
};
use crate::proxy::ca::ProxyCa;
use crate::proxy::server::ProxyShared;
use crate::redact::{Redactor, RedactorSwap};
use crate::refresh;
use crate::runtime_dir::RuntimeDir;
use crate::secrets::{CommandContext, Health, Secret, SecretSlot, SecretStore};

/// Concurrent `exec`s a single session may run at once (decision 6).
pub const EXEC_CAP: usize = 16;

/// How long [`SessionPolicy::shutdown_refresh`] waits for refresh tasks to
/// stop before aborting them — mirrors the old daemon's shutdown grace.
const REFRESH_STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// Bounded history of ended sessions, so a late request against a session
/// that just ended gets the right [`ErrorKind`] (expired vs. revoked) rather
/// than a generic "no such session".
const ENDED_CAPACITY: usize = 256;

// ─── SessionPolicy: everything `Reload` swaps in one step ──────────────────

/// The compiled, per-session state that `Register` builds and `Reload`
/// replaces wholesale. An in-flight `exec` clones the `Arc<SessionPolicy>`
/// it started with, so a `Reload` racing a running tool never changes what
/// that tool sees.
pub struct SessionPolicy {
    /// The resolved config this session serves.
    pub config: Config,
    /// This session's own secret values. Never looked up anywhere but here.
    pub secrets: SecretStore,
    /// This session's own redactor (secrets this session knows about).
    /// Output passes this, then the daemon-wide global redactor.
    pub redactor: RedactorSwap,
    /// Shared state for this session's proxy tools, if it has any.
    pub proxy: Option<Arc<ProxyShared>>,
    /// Context `source = "command"` secrets run under when refreshed.
    pub command_ctx: Arc<CommandContext>,
    /// The launcher's environment snapshot, for building tool environments
    /// (`exec::build_env_from`).
    pub snapshot: std::collections::BTreeMap<String, String>,
    /// The session's filtered `PATH`.
    pub path: FilteredPath,
    /// Every path a sandboxed tool or the agent may write to, for
    /// `resolve_binary_in`'s project/grant refusal. Only ever grows across
    /// reloads (see [`build_session_policy`]).
    pub write_grants: Vec<PathBuf>,
    /// The anchor paths the launcher validated, echoed back by `Check`.
    pub anchors: WireAnchors,
    /// SHA-256 of the normalized `[agent]` section, for `Reload`'s
    /// "agent settings changed" note.
    pub agent_hash: String,
    /// The config layers this session was built from.
    pub layers: Vec<WireLayer>,
    /// How the session's root was discovered.
    pub mode: WireMode,
    /// The value each refreshed secret held before its latest refresh; the
    /// session's own redactor covers these, and so must the global one.
    pub previous_secrets: refresh::PreviousValues,
    pub(crate) refresh_tasks: tokio::sync::Mutex<JoinSet<()>>,
    pub(crate) refresh_shutdown: watch::Sender<bool>,
}

impl SessionPolicy {
    /// Stop this policy's refresh tasks, waiting briefly before aborting
    /// stragglers. Called when a `Reload` retires this policy, and when a
    /// session ends.
    pub async fn shutdown_refresh(&self) {
        let _ = self.refresh_shutdown.send(true);
        let mut tasks = self.refresh_tasks.lock().await;
        let drain = async { while tasks.join_next().await.is_some() {} };
        if tokio::time::timeout(REFRESH_STOP_TIMEOUT, drain)
            .await
            .is_err()
        {
            tasks.abort_all();
        }
    }
}

/// Build a [`SecretStore`] directly from a `Register`/`Reload` payload's
/// already-resolved secrets. The daemon never runs a secret command itself
/// — the launcher did that with the user's terminal and environment.
fn secret_store_from_wire(secrets: &[crate::protocol::WireSecret]) -> SecretStore {
    let mut map = HashMap::with_capacity(secrets.len());
    for s in secrets {
        map.insert(
            s.label.clone(),
            RwLock::new(SecretSlot {
                value: Arc::new(Secret::new((*s.value).clone())),
                health: Health::Healthy,
            }),
        );
    }
    Arc::new(map)
}

/// Build a [`Redactor`] from every value currently in `store`.
pub fn build_redactor(store: &SecretStore) -> Result<Redactor, crate::redact::RedactError> {
    let pairs: Vec<(String, Arc<Secret<String>>)> = store
        .iter()
        .map(|(name, slot)| {
            let s = slot.read().unwrap_or_else(|e| e.into_inner());
            (name.clone(), Arc::clone(&s.value))
        })
        .collect();
    let refs: Vec<(&str, &Secret<String>)> = pairs
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_ref()))
        .collect();
    Redactor::new(refs)
}

/// Build the [`SessionPolicy`] a `Register` or `Reload` request describes.
///
/// `on_refresh` is called after every successful background secret refresh,
/// so the caller can rebuild the daemon-wide global redactor
/// (docs/airlock-v2-design.md, "Session isolation").
pub fn build_session_policy(
    payload: &RegisterPayload,
    session_id: &SessionId,
    runtime: &RuntimeDir,
    ring_buffer: &RingBuffer,
    on_refresh: Arc<dyn Fn() + Send + Sync>,
    existing: Option<&SessionPolicy>,
) -> Result<SessionPolicy, String> {
    let config = crate::config::resolve_wire_config(payload.config.clone(), &payload.root)
        .map_err(|e| format!("config error: {e}"))?;

    let secrets = secret_store_from_wire(&payload.secrets);
    let initial_redactor = build_redactor(&secrets).map_err(|e| e.to_string())?;
    let redactor: RedactorSwap = Arc::new(RwLock::new(Arc::new(initial_redactor)));

    // An agent's sandbox is fixed when it launches, so a reload can take a
    // write grant away from the config but never from the agent. Keep every
    // grant the session has ever had, and re-filter `PATH` against them, so
    // `resolve_binary_in` and tools' `PATH` keep refusing what the agent can
    // still write — whatever the reloading launcher sent.
    let mut write_grants = existing.map(|p| p.write_grants.clone()).unwrap_or_default();
    for grant in &payload.write_grants {
        if !write_grants.contains(grant) {
            write_grants.push(grant.clone());
        }
    }

    let path = FilteredPath {
        entries: payload.path.clone(),
        dropped: payload
            .dropped_path
            .iter()
            .map(|d| (d.entry.clone(), d.reason.clone()))
            .collect(),
    }
    .refiltered(&payload.root, &write_grants);

    let proxy = if config.tools.values().any(|t| t.proxy.is_some()) {
        let ca_path = runtime.ca_path(session_id.as_str());
        let proxy_policies = || config.tools.values().filter_map(|t| t.proxy.as_ref());

        // A reload whose routes are unchanged keeps the same CA — same key,
        // same cert, same file on disk, no rewrite under whatever is
        // mid-`exec` and already trusts it. One whose routes changed (or a
        // fresh `Register`, which has no `existing` at all) cannot: the old
        // CA's name constraints would no longer match what this config
        // needs.
        let reused_ca = existing
            .and_then(|p| p.proxy.as_ref())
            .filter(|shared| shared.ca().covers(proxy_policies()))
            .map(|shared| Arc::clone(shared.ca()));

        let ca = match reused_ca {
            Some(ca) => ca,
            None => {
                let ca = ProxyCa::generate(proxy_policies())
                    .map_err(|e| format!("proxy CA error: {e}"))?
                    .ok_or_else(|| {
                        "internal: a proxy tool is configured but no CA was generated".to_string()
                    })?;
                ca.write_cert_pem(&ca_path)
                    .map_err(|e| format!("failed to write the session's proxy CA: {e}"))?;
                // The runtime base is 0700, so this is belt-and-suspenders: a
                // session's CA is readable only by its own tools' sandbox
                // grants, never by another session or an unsandboxed
                // process of the user.
                if let Err(e) = std::fs::set_permissions(
                    &ca_path,
                    std::os::unix::fs::PermissionsExt::from_mode(0o600),
                ) {
                    ring_buffer.log(format!(
                        "failed to tighten permissions on {}: {e}",
                        ca_path.display()
                    ));
                }
                Arc::new(ca)
            }
        };
        Some(Arc::new(ProxyShared::new(
            ca,
            ca_path,
            Arc::clone(&secrets),
            Arc::clone(&redactor),
            ring_buffer.clone(),
        )))
    } else {
        None
    };

    let command_ctx = Arc::new(CommandContext {
        snapshot: payload.env_snapshot.clone(),
        path: path.clone(),
        cwd: payload.root.clone(),
        root: payload.root.clone(),
        write_grants: write_grants.clone(),
    });

    let (refresh_tasks, refresh_shutdown, previous_secrets) = refresh::spawn_all_ctx(
        &config,
        Arc::clone(&secrets),
        Arc::clone(&redactor),
        ring_buffer.clone(),
        Arc::clone(&command_ctx),
        on_refresh,
    );

    Ok(SessionPolicy {
        config,
        secrets,
        redactor,
        proxy,
        command_ctx,
        snapshot: payload.env_snapshot.clone(),
        path,
        write_grants,
        anchors: payload.anchors.clone(),
        agent_hash: payload.agent_hash.clone(),
        layers: payload.layers.clone(),
        mode: payload.mode.clone(),
        previous_secrets,
        refresh_tasks: tokio::sync::Mutex::new(refresh_tasks),
        refresh_shutdown,
    })
}

/// Tools this session's config declares, in display form (never the secret
/// values themselves).
pub fn tools_info(config: &Config) -> Vec<ToolInfo> {
    let mut names: Vec<&String> = config.tools.keys().collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let t = &config.tools[name];
            let env = t
                .env
                .iter()
                .map(|(k, v)| {
                    let display = match v {
                        EnvValue::Static(s) => EnvDisplay::Static(s.clone()),
                        EnvValue::SecretRef(label) => EnvDisplay::Secret(label.clone()),
                    };
                    (k.clone(), display)
                })
                .collect();
            ToolInfo {
                name: name.clone(),
                description: t.description.clone(),
                env,
                proxy: t.proxy.is_some(),
            }
        })
        .collect()
}

/// Names (never values) of every tool env var that resolves to a secret —
/// `Check`'s `secret_env_names`.
pub fn secret_env_names(config: &Config) -> Vec<String> {
    let mut names: Vec<String> = config
        .tools
        .values()
        .flat_map(|t| t.env.iter())
        .filter_map(|(name, v)| match v {
            EnvValue::SecretRef(_) => Some(name.clone()),
            EnvValue::Static(_) => None,
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Union of every tool's `extra_read` paths — `Check`'s `credential_paths`.
pub fn credential_paths(config: &Config) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = config
        .tools
        .values()
        .flat_map(|t| t.extra_read.iter().cloned())
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

/// Human-readable tool-set changes between two configs, for `Reloaded`:
/// `"tools +psql"`, `"tools -gh"`. Empty when nothing changed.
pub fn diff_tools(old: &Config, new: &Config) -> Vec<String> {
    let old_names: std::collections::BTreeSet<&String> = old.tools.keys().collect();
    let new_names: std::collections::BTreeSet<&String> = new.tools.keys().collect();
    let mut changes = Vec::new();
    for added in new_names.difference(&old_names) {
        changes.push(format!("tools +{added}"));
    }
    for removed in old_names.difference(&new_names) {
        changes.push(format!("tools -{removed}"));
    }
    changes
}

// ─── Session ─────────────────────────────────────────────────────────────────

/// What ends a session (docs/airlock-v2-design.md, "Lifetime").
#[derive(Debug, Clone, Copy)]
pub enum Ends {
    /// Ends when the `Register` connection closes.
    Lease,
    /// Ends `ttl` after `expires_at` was last set; `ttl == Duration::ZERO`
    /// means never.
    Ttl {
        /// The duration a renewal without an explicit `--ttl` repeats.
        ttl: Duration,
        /// When this expiry was last computed.
        expires_at: SystemTime,
    },
}

impl Ends {
    /// Whether `now` is past this session's expiry. Always `false` for a
    /// lease or a never-expiring (`ttl == 0`) TTL.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        match self {
            Ends::Lease => false,
            Ends::Ttl { ttl, expires_at } => *ttl != Duration::ZERO && now >= *expires_at,
        }
    }

    /// Render for [`SessionInfo::ends`]. `anchor_pid` is the session's own
    /// anchor PID, which for a lease is the launcher holding it open.
    pub fn to_info(&self, anchor_pid: i32) -> EndsInfo {
        match self {
            Ends::Lease => EndsInfo::Lease { pid: anchor_pid },
            Ends::Ttl { ttl, .. } if *ttl == Duration::ZERO => EndsInfo::Never,
            Ends::Ttl { expires_at, .. } => EndsInfo::Ttl {
                expires_unix: expires_at
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            },
        }
    }
}

/// A live session: a client's binding to one project.
///
/// Everything sensitive lives behind [`Session::policy`]; this struct itself
/// carries only identity, lifecycle and the exec concurrency cap.
pub struct Session {
    pub id: SessionId,
    pub token: SessionToken,
    pub name: String,
    pub root: PathBuf,
    pub sandbox: SandboxKind,
    pub ends: RwLock<Ends>,
    /// The process this session is bound to (docs/airlock-v2-design.md,
    /// "Token binding"). Fixed at registration; never changes.
    pub anchor: ProcId,
    pub started: SystemTime,
    pub execs: AtomicU64,
    pub exec_permits: Arc<Semaphore>,
    pub policy: RwLock<Arc<SessionPolicy>>,
    /// Cancelled to wake a blocked lease-holding connection — used when an
    /// admin `Revoke` or `Stop` ends a session out from under its lease.
    pub lease_closer: CancellationToken,
}

impl std::fmt::Debug for Session {
    /// Deliberately shallow: never descends into `policy`, which holds this
    /// session's secrets.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Snapshot for `session list`, `tools list` and `agent check`.
    pub fn info(&self) -> SessionInfo {
        let policy = self
            .policy
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        SessionInfo {
            id: self.id.clone(),
            name: self.name.clone(),
            root: self.root.clone(),
            started_unix: self
                .started
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            execs: self.execs.load(Ordering::Relaxed),
            ends: self
                .ends
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .to_info(self.anchor.pid),
            sandbox: self.sandbox,
            layers: policy.layers.clone(),
            mode: policy.mode.clone(),
            write_grants: policy.write_grants.clone(),
        }
    }

    /// The policy this session serves right now. Clone the returned `Arc`
    /// once per request — a `Reload` racing the request must not change
    /// what it sees mid-flight.
    pub fn current_policy(&self) -> Arc<SessionPolicy> {
        Arc::clone(&self.policy.read().unwrap_or_else(|e| e.into_inner()))
    }
}

// ─── Sessions registry ───────────────────────────────────────────────────────

/// Why a session is no longer live, kept for a bounded time so a request
/// that arrives just after can be told the right story.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndedReason {
    Revoked,
    Expired,
    LeaseClosed,
    Stopped,
}

impl EndedReason {
    pub fn error_kind(self) -> ErrorKind {
        match self {
            EndedReason::Expired => ErrorKind::SessionExpired,
            EndedReason::Revoked | EndedReason::LeaseClosed | EndedReason::Stopped => {
                ErrorKind::SessionEnded
            }
        }
    }
}

/// The daemon's session table: every live session, plus a bounded history
/// of recently-ended ones.
#[derive(Default)]
pub struct Sessions {
    live: RwLock<HashMap<SessionId, Arc<Session>>>,
    ended: Mutex<VecDeque<(SessionId, EndedReason)>>,
}

impl Sessions {
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh id not already in use by a live session.
    pub fn fresh_id(&self) -> SessionId {
        loop {
            let id = SessionId::generate();
            if !self
                .live
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&id)
            {
                return id;
            }
        }
    }

    pub fn insert(&self, session: Arc<Session>) {
        self.live
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session.id.clone(), session);
    }

    pub fn get(&self, id: &SessionId) -> Option<Arc<Session>> {
        self.live
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
    }

    pub fn ended_reason(&self, id: &SessionId) -> Option<EndedReason> {
        self.ended
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .rev()
            .find(|(i, _)| i == id)
            .map(|(_, r)| *r)
    }

    /// Remove a session and record why, if it was still live. Idempotent:
    /// ending an already-gone session is a no-op (returns `None`), so a
    /// lease-close race against an explicit revoke never double-records.
    pub fn end(&self, id: &SessionId, reason: EndedReason) -> Option<Arc<Session>> {
        let removed = self
            .live
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        if removed.is_some() {
            let mut ended = self.ended.lock().unwrap_or_else(|e| e.into_inner());
            if ended.len() >= ENDED_CAPACITY {
                ended.pop_front();
            }
            ended.push_back((id.clone(), reason));
        }
        removed
    }

    pub fn list(&self) -> Vec<Arc<Session>> {
        self.live
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }

    pub fn count(&self) -> usize {
        self.live.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Resolve `s` as a session id, a unique id prefix, or a unique name.
    ///
    /// Keep this in sync with [`resolve_session_ref`] below, which applies
    /// the identical rule client-side, over the `SessionInfo` list `session
    /// list` already returns, for a CLI command that must resolve a ref
    /// itself before it can act (`session reload`, `session revoke`) rather
    /// than hand the raw ref to an admin request that resolves it here.
    pub fn resolve_ref(&self, s: &str) -> Result<Arc<Session>, String> {
        let live = self.live.read().unwrap_or_else(|e| e.into_inner());

        if let Ok(id) = SessionId::parse(s)
            && let Some(session) = live.get(&id)
        {
            return Ok(Arc::clone(session));
        }

        let mut matches: Vec<&Arc<Session>> = live
            .values()
            .filter(|session| session.id.as_str().starts_with(s) || session.name == s)
            .collect();
        matches.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        matches.dedup_by(|a, b| a.id == b.id);

        match matches.len() {
            0 => Err(format!("no session matches {s:?}")),
            1 => Ok(Arc::clone(matches[0])),
            _ => {
                let ids: Vec<&str> = matches.iter().map(|s| s.id.as_str()).collect();
                Err(format!(
                    "{s:?} matches more than one session: {}",
                    ids.join(", ")
                ))
            }
        }
    }
}

/// Resolves `s` against `sessions` by the same rule as
/// [`Sessions::resolve_ref`] (exact id, unique id prefix, or unique name) —
/// for a client that only has the `SessionInfo` list `session list`/`Tools`
/// already return, not the daemon's live registry. `session reload` uses
/// this: it must know which session(s) it's reloading, each with its own
/// project root, before it can even build that session's `Reload` payload,
/// so it cannot simply hand the raw ref to an admin request and let the
/// daemon resolve it the way `session revoke` does.
///
/// Never silently acts on more than one match: ambiguity is an error naming
/// every candidate.
pub fn resolve_session_ref<'a>(
    s: &str,
    sessions: &'a [SessionInfo],
) -> Result<&'a SessionInfo, String> {
    if let Some(exact) = sessions.iter().find(|session| session.id.as_str() == s) {
        return Ok(exact);
    }

    let mut matches: Vec<&SessionInfo> = sessions
        .iter()
        .filter(|session| session.id.as_str().starts_with(s) || session.name == s)
        .collect();
    matches.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    matches.dedup_by(|a, b| a.id == b.id);

    match matches.len() {
        0 => Err(format!("no session matches {s:?}")),
        1 => Ok(matches[0]),
        _ => {
            let ids: Vec<&str> = matches.iter().map(|session| session.id.as_str()).collect();
            Err(format!(
                "{s:?} matches more than one session: {}",
                ids.join(", ")
            ))
        }
    }
}

/// A session anchored to this test process itself (always a descendant of
/// its own anchor) — for tests that don't care about process-tree binding.
/// Reused by `daemon`'s own tests via `crate::session::test_session`.
#[cfg(test)]
pub(crate) fn test_session(id: SessionId, name: &str) -> Arc<Session> {
    let token = SessionToken::generate(id.clone());
    Arc::new(Session {
        id,
        token,
        name: name.to_string(),
        root: PathBuf::from("/tmp"),
        sandbox: SandboxKind::External,
        ends: RwLock::new(Ends::Lease),
        anchor: crate::process_tree::proc_id(std::process::id() as i32).unwrap(),
        started: SystemTime::now(),
        execs: AtomicU64::new(0),
        exec_permits: Arc::new(Semaphore::new(EXEC_CAP)),
        policy: RwLock::new(Arc::new(empty_policy())),
        lease_closer: CancellationToken::new(),
    })
}

/// A minimal, inert [`SessionPolicy`] with no tools and no secrets, for
/// tests that only exercise session lifecycle/auth, not `exec`.
#[cfg(test)]
pub(crate) fn empty_policy() -> SessionPolicy {
    let secrets: SecretStore = Arc::new(HashMap::new());
    let redactor: RedactorSwap = Arc::new(RwLock::new(Arc::new(
        Redactor::new(std::iter::empty()).unwrap(),
    )));
    let (tx, _rx) = watch::channel(false);
    SessionPolicy {
        config: Config {
            sandbox_root: PathBuf::from("/tmp"),
            timeout: Duration::from_secs(300),
            access: crate::sandbox::ToolAccess::default(),
            filesystem_read: Vec::new(),
            filesystem_write: Vec::new(),
            secrets: HashMap::new(),
            tools: HashMap::new(),
            agent: None,
            tool_state_dirs: Vec::new(),
        },
        secrets,
        redactor,
        proxy: None,
        command_ctx: Arc::new(CommandContext {
            snapshot: std::collections::BTreeMap::new(),
            path: FilteredPath::default(),
            cwd: PathBuf::from("/tmp"),
            root: PathBuf::from("/tmp"),
            write_grants: Vec::new(),
        }),
        snapshot: std::collections::BTreeMap::new(),
        path: FilteredPath::default(),
        write_grants: Vec::new(),
        anchors: WireAnchors {
            runtime_base: PathBuf::from("/tmp/airlock"),
            trust_store: PathBuf::from("/tmp/trust"),
            global_config: PathBuf::from("/tmp/airlock.toml"),
        },
        agent_hash: String::new(),
        layers: Vec::new(),
        mode: WireMode::NoProjectConfig,
        previous_secrets: Default::default(),
        refresh_tasks: tokio::sync::Mutex::new(JoinSet::new()),
        refresh_shutdown: tx,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_id_is_not_already_live() {
        let sessions = Sessions::new();
        let id = sessions.fresh_id();
        assert!(sessions.get(&id).is_none());
    }

    #[test]
    fn resolve_ref_by_exact_id() {
        let sessions = Sessions::new();
        let session = test_session(SessionId::parse("abc123").unwrap(), "claude");
        sessions.insert(Arc::clone(&session));

        let found = sessions.resolve_ref("abc123").unwrap();
        assert_eq!(found.id, session.id);
    }

    #[test]
    fn resolve_ref_by_unique_prefix() {
        let sessions = Sessions::new();
        let session = test_session(SessionId::parse("abc123").unwrap(), "claude");
        sessions.insert(Arc::clone(&session));

        let found = sessions.resolve_ref("abc1").unwrap();
        assert_eq!(found.id, session.id);
    }

    #[test]
    fn resolve_ref_by_unique_name() {
        let sessions = Sessions::new();
        let session = test_session(SessionId::parse("abc123").unwrap(), "claude");
        sessions.insert(Arc::clone(&session));

        let found = sessions.resolve_ref("claude").unwrap();
        assert_eq!(found.id, session.id);
    }

    #[test]
    fn resolve_ref_ambiguous_prefix_errors() {
        let sessions = Sessions::new();
        sessions.insert(test_session(SessionId::parse("abc123").unwrap(), "claude"));
        sessions.insert(test_session(SessionId::parse("abc456").unwrap(), "codex"));

        let err = sessions.resolve_ref("abc").unwrap_err();
        assert!(err.contains("more than one session"), "{err}");
    }

    #[test]
    fn resolve_ref_unknown_errors() {
        let sessions = Sessions::new();
        let err = sessions.resolve_ref("nope").unwrap_err();
        assert!(err.contains("no session matches"), "{err}");
    }

    // ── resolve_session_ref: the client-side mirror of resolve_ref, over
    //    SessionInfo rather than the live registry (main.rs's `session
    //    reload`/`session revoke`) ────────────────────────────────────────

    #[test]
    fn resolve_session_ref_by_exact_id() {
        let infos = vec![test_session(SessionId::parse("abc123").unwrap(), "claude").info()];
        let found = resolve_session_ref("abc123", &infos).unwrap();
        assert_eq!(found.id.as_str(), "abc123");
    }

    #[test]
    fn resolve_session_ref_by_unique_prefix() {
        let infos = vec![test_session(SessionId::parse("abc123").unwrap(), "claude").info()];
        let found = resolve_session_ref("abc1", &infos).unwrap();
        assert_eq!(found.id.as_str(), "abc123");
    }

    #[test]
    fn resolve_session_ref_by_unique_name() {
        let infos = vec![test_session(SessionId::parse("abc123").unwrap(), "claude").info()];
        let found = resolve_session_ref("claude", &infos).unwrap();
        assert_eq!(found.id.as_str(), "abc123");
    }

    #[test]
    fn resolve_session_ref_ambiguous_prefix_names_every_candidate() {
        let infos = vec![
            test_session(SessionId::parse("abc123").unwrap(), "claude").info(),
            test_session(SessionId::parse("abc456").unwrap(), "codex").info(),
        ];
        let err = resolve_session_ref("abc", &infos).unwrap_err();
        assert!(err.contains("more than one session"), "{err}");
        assert!(err.contains("abc123"), "{err}");
        assert!(err.contains("abc456"), "{err}");
    }

    #[test]
    fn resolve_session_ref_unknown_errors() {
        let err = resolve_session_ref("nope", &[]).unwrap_err();
        assert!(err.contains("no session matches"), "{err}");
    }

    #[test]
    fn end_is_idempotent_and_records_reason() {
        let sessions = Sessions::new();
        let session = test_session(SessionId::parse("abc123").unwrap(), "claude");
        let id = session.id.clone();
        sessions.insert(session);

        assert!(sessions.end(&id, EndedReason::Revoked).is_some());
        assert!(sessions.end(&id, EndedReason::Expired).is_none());
        assert_eq!(sessions.ended_reason(&id), Some(EndedReason::Revoked));
    }

    #[test]
    fn ends_ttl_zero_never_expires() {
        let ends = Ends::Ttl {
            ttl: Duration::ZERO,
            expires_at: SystemTime::now() - Duration::from_secs(10),
        };
        assert!(!ends.is_expired(SystemTime::now()));
        assert!(matches!(ends.to_info(1), EndsInfo::Never));
    }

    #[test]
    fn ends_ttl_expires_after_deadline() {
        let now = SystemTime::now();
        let ends = Ends::Ttl {
            ttl: Duration::from_secs(10),
            expires_at: now - Duration::from_secs(1),
        };
        assert!(ends.is_expired(now));
    }

    #[test]
    fn ends_lease_never_expires() {
        assert!(!Ends::Lease.is_expired(SystemTime::now()));
        assert!(matches!(
            Ends::Lease.to_info(42),
            EndsInfo::Lease { pid: 42 }
        ));
    }

    #[test]
    fn diff_tools_reports_additions_and_removals() {
        let mut old = empty_policy().config;
        old.tools.insert("gh".to_string(), test_tool());
        let mut new = empty_policy().config;
        new.tools.insert("psql".to_string(), test_tool());

        let changes = diff_tools(&old, &new);
        assert_eq!(
            changes,
            vec!["tools +psql".to_string(), "tools -gh".to_string()]
        );
    }

    fn test_tool() -> crate::config::ToolConfig {
        crate::config::ToolConfig {
            env: std::collections::BTreeMap::new(),
            extra_read: Vec::new(),
            extra_write: Vec::new(),
            timeout: None,
            access: None,
            description: None,
            proxy: None,
        }
    }
}
