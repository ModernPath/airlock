//! Launcher: the synchronous pipeline shared by `airlock run`, `airlock
//! session start` and `airlock session reload` — discovery, trust, secret
//! resolution, daemon startup and session registration.
//!
//! Everything here runs before any tokio runtime exists (`main()` is
//! synchronous — see CLAUDE.md): discovery, trust prompts and secret
//! resolution are synchronous, and the automatic daemon is started by
//! spawning this binary again as `airlock daemon start --automatic`, not by
//! an in-process fork.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;

use crate::admin::{self, AdminError};
use crate::anchors::{self, AnchorError, Anchors};
use crate::config::{self, ConfigError, RawConfig};
use crate::exec::{self, FilteredPath};
use crate::layers::{self, DiscoveryMode, LoadedLayers, MergeContext, Provenance};
use crate::protocol::{
    AdminRequest, AdminToken, DaemonMessage, DroppedPath, RegisterPayload, RegisterRequest,
    SandboxKind, SessionEnds, SessionId, SessionToken, WireAnchors, WireLayer, WireSecret,
};
use crate::runtime_dir::{RuntimeDir, RuntimeDirError};
use crate::secrets::{self, CommandContext, SecretsError};
use crate::trust::{self, Approval, PromptKind, TrustError, TrustStore};

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the launcher pipeline.
///
/// `Aborted` means the launcher already printed everything the user needs to
/// see (a trust decline, a non-interactive refusal) — the caller just maps
/// it to exit code 125 without printing anything more, matching the UX
/// transcripts, which have no `error:` prefix for those cases.
#[derive(Debug, Error)]
pub enum LauncherError {
    #[error("already reported")]
    Aborted,
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("{0}")]
    Anchor(#[from] AnchorError),
    #[error("{0}")]
    RuntimeDir(#[from] RuntimeDirError),
    #[error("{0}")]
    Trust(#[from] TrustError),
    #[error("{0}")]
    Secrets(#[from] SecretsError),
    #[error("{0}")]
    Admin(#[from] AdminError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Message(String),
}

// ─── Discovery options ────────────────────────────────────────────────────────

/// How to discover the project config, set from `--config` /
/// `--no-project-config`.
#[derive(Debug, Clone, Default)]
pub struct DiscoverOpts {
    pub config: Option<PathBuf>,
    pub no_project_config: bool,
}

impl DiscoverOpts {
    fn mode(&self) -> DiscoveryMode {
        if let Some(path) = &self.config {
            DiscoveryMode::ConfigFile(path.clone())
        } else if self.no_project_config {
            DiscoveryMode::NoProjectConfig
        } else {
            DiscoveryMode::Default
        }
    }
}

/// Options that steer `prepare`'s behaviour but not its discovery mode.
pub struct PrepareOptions {
    pub discover: DiscoverOpts,
    pub verbose: bool,
    pub quiet: bool,
    /// `--allow-write` (run only); resolved to absolute paths by the caller.
    pub extra_write_grants: Vec<PathBuf>,
}

// ─── Prepared state ───────────────────────────────────────────────────────────

/// Everything resolved by [`prepare`], ready to become a `Register` payload.
pub struct Prepared {
    pub root: PathBuf,
    pub mode: crate::protocol::WireMode,
    pub layers: Vec<WireLayer>,
    pub raw_config: RawConfig,
    pub config: config::Config,
    pub secret_values: std::collections::HashMap<String, secrets::Secret<String>>,
    pub path: FilteredPath,
    pub dropped_path: Vec<DroppedPath>,
    pub env_snapshot: BTreeMap<String, String>,
    pub write_grants: Vec<PathBuf>,
    pub anchors: Anchors,
    pub agent_hash: String,
    pub runtime: RuntimeDir,
}

impl Prepared {
    /// Builds the `Register`/`Reload` payload from this prepared state.
    pub fn to_wire_payload(&self) -> RegisterPayload {
        let secrets = self
            .secret_values
            .iter()
            .map(|(label, secret)| WireSecret {
                label: label.clone(),
                value: zeroize::Zeroizing::new(secret.expose_secret().clone()),
            })
            .collect();

        RegisterPayload {
            root: self.root.clone(),
            mode: self.mode.clone(),
            layers: self.layers.clone(),
            config: self.raw_config.clone(),
            secrets,
            env_snapshot: self.env_snapshot.clone(),
            path: self.path.entries.clone(),
            dropped_path: self.dropped_path.clone(),
            write_grants: self.write_grants.clone(),
            anchors: WireAnchors {
                runtime_base: self.anchors.runtime_base.clone(),
                trust_store: self.anchors.trust_store.clone(),
                global_config: self.anchors.global_config.clone(),
            },
            agent_hash: self.agent_hash.clone(),
        }
    }
}

// ─── prepare: discovery, trust, secrets ──────────────────────────────────────

/// Runs discovery, cross-layer merge validation, anchor validation, trust
/// review/approval and secret resolution — steps 1 through 5 of the
/// launcher pipeline in the phase-2 contract. `cwd` is the directory the
/// command was invoked from (not necessarily the project root).
#[allow(
    clippy::disallowed_methods,
    reason = "launcher-side: runs once in the user's terminal before Register, building the snapshot the daemon will use instead of its own environment"
)]
pub fn prepare(cwd: &Path, opts: &PrepareOptions) -> Result<Prepared, LauncherError> {
    let home = home_dir()?;
    let runtime = RuntimeDir::locate()?;
    let anchors = anchors::resolve(&|k| std::env::var(k).ok(), &home, &runtime);

    let mode = opts.discover.mode();
    let loaded = layers::load_layers(&mode, cwd, &home, &anchors.global_config)?;
    let root = loaded.root.clone();

    let merge_ctx = MergeContext {
        root: root.clone(),
        home: home.clone(),
        tool_state_base: anchors.tool_state_base.clone(),
    };
    let merged = layers::merge(&loaded, &merge_ctx)?;

    let raw_config = merged.to_wire();
    let config = config::resolve_wire_config(raw_config.clone(), &root)?;

    let mut write_grants = config::write_grants(&config);
    write_grants.extend(opts.extra_write_grants.iter().cloned());

    anchors::validate(&anchors, Some(&root), &write_grants)?;

    review_and_trust(&anchors, &loaded, &root, &raw_config, &merged)?;

    for dir in merged.tool_state_dirs() {
        anchors::validate_tool_state_dir(&anchors, &root, dir)?;
        create_dir_0700(dir)?;
    }

    let host_path = std::env::var("PATH").unwrap_or_default();
    let path = exec::filter_path(&host_path, &root, &write_grants);
    let dropped_path = path
        .dropped
        .iter()
        .map(|(entry, reason)| DroppedPath {
            entry: entry.clone(),
            reason: reason.clone(),
        })
        .collect();

    let full_snapshot: BTreeMap<String, String> = std::env::vars().collect();
    let cmd_ctx = CommandContext {
        snapshot: full_snapshot.clone(),
        path: path.clone(),
        cwd: cwd.to_path_buf(),
        root: root.clone(),
        write_grants: write_grants.clone(),
    };

    let collected = resolve_secrets(&config, &cmd_ctx, opts)?;

    let mut env_snapshot = full_snapshot;
    for name in &collected.consumed_env {
        env_snapshot.remove(name);
    }

    let layer_wire = wire_layers(&loaded);
    let agent_bytes =
        serde_json::to_vec(&raw_config.agent).expect("RawAgentConfig always serializes");
    let agent_hash = config::sha256_hex(&agent_bytes);

    Ok(Prepared {
        root,
        mode: wire_mode(&mode),
        layers: layer_wire,
        raw_config,
        config,
        secret_values: collected.values,
        path,
        dropped_path,
        env_snapshot,
        write_grants,
        anchors,
        agent_hash,
        runtime,
    })
}

#[allow(
    clippy::disallowed_methods,
    reason = "launcher-side: runs in the user's terminal before Register"
)]
fn home_dir() -> Result<PathBuf, LauncherError> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| LauncherError::Config(ConfigError::HomeNotSet))
}

fn create_dir_0700(dir: &Path) -> Result<(), LauncherError> {
    use std::os::unix::fs::DirBuilderExt;
    // `{tool_state}` nests under `$XDG_CACHE_HOME/airlock/<project-id>/`, which
    // doesn't exist yet on a project's first session — recursive(true) creates
    // those parents too, not just the tool's own leaf directory.
    match std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
    {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(LauncherError::Io(e)),
    }
}

fn wire_mode(mode: &DiscoveryMode) -> crate::protocol::WireMode {
    match mode {
        DiscoveryMode::Default => crate::protocol::WireMode::Default,
        DiscoveryMode::ConfigFile(path) => {
            crate::protocol::WireMode::ConfigFile { path: path.clone() }
        }
        DiscoveryMode::NoProjectConfig => crate::protocol::WireMode::NoProjectConfig,
    }
}

fn wire_layers(loaded: &LoadedLayers) -> Vec<WireLayer> {
    [&loaded.global, &loaded.repo, &loaded.local]
        .into_iter()
        .filter_map(|f| f.as_ref())
        .map(|f| WireLayer {
            kind: f.kind,
            path: f.path.clone(),
            sha256: f.sha256.clone(),
        })
        .collect()
}

/// Secrets resolved by spawning a command get a progress line (UX "First
/// run": `airlock: resolving GH_TOKEN (gh)… done`) — with `-v`, or
/// unconditionally once the whole batch takes more than a second, since
/// `collect_secrets_with` runs labels sequentially and we only learn a
/// single command was slow after the fact.
#[allow(
    clippy::disallowed_methods,
    reason = "launcher-side: `source = \"env\"` secrets read the launcher's own environment, before Register, never the daemon's"
)]
fn resolve_secrets(
    config: &config::Config,
    ctx: &CommandContext,
    opts: &PrepareOptions,
) -> Result<secrets::Collected, LauncherError> {
    if config.secrets.is_empty() {
        return Ok(secrets::Collected {
            values: std::collections::HashMap::new(),
            consumed_env: Vec::new(),
        });
    }

    let mut command_secrets: Vec<(&String, &str)> = config
        .secrets
        .iter()
        .filter_map(|(label, spec)| match &spec.source {
            config::SecretSource::Command { argv, .. } => {
                Some((label, argv.first().map(String::as_str).unwrap_or("")))
            }
            config::SecretSource::Env { .. } => None,
        })
        .collect();
    command_secrets.sort();

    if opts.verbose {
        for (label, argv0) in &command_secrets {
            eprint!("airlock: resolving {label} ({argv0})… ");
            std::io::stderr().flush().ok();
        }
    }

    let start = std::time::Instant::now();
    let result = secrets::collect_secrets_with(config, &|k| std::env::var(k).ok(), ctx);
    let elapsed = start.elapsed();

    if opts.verbose {
        for _ in &command_secrets {
            eprintln!("done");
        }
    } else if elapsed > Duration::from_secs(1) {
        for (label, argv0) in &command_secrets {
            eprintln!("airlock: resolving {label} ({argv0})… done");
        }
    }
    result.map_err(LauncherError::Secrets)
}

// ─── Trust review ─────────────────────────────────────────────────────────────

fn trust_file_name(kind: crate::protocol::LayerKind, path: &Path) -> String {
    match kind {
        crate::protocol::LayerKind::Repo => config::config_filename().to_string(),
        crate::protocol::LayerKind::Local => config::local_config_filename().to_string(),
        crate::protocol::LayerKind::ConfigFile => path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "config".to_string()),
        crate::protocol::LayerKind::Global => unreachable!("the global layer is never approved"),
    }
}

/// Reviews and, on a terminal, prompts for approval of every repo/local/
/// config-file layer that isn't already approved (U1). The global layer is
/// never reviewed — it is the user's own file, protected by the anchor
/// checks instead.
fn review_and_trust(
    anchors: &Anchors,
    loaded: &LoadedLayers,
    root: &Path,
    raw_config: &RawConfig,
    merged: &layers::MergedConfig,
) -> Result<(), LauncherError> {
    let store = TrustStore::open(&anchors.trust_store)?;
    let interactive = trust::is_interactive();

    for file in [&loaded.repo, &loaded.local].into_iter().flatten() {
        let file_name = trust_file_name(file.kind, &file.path);
        let approval = store.state(root, &file_name, &file.bytes)?;
        if matches!(approval, Approval::Approved) {
            continue;
        }

        let path_display = file.path.display().to_string();
        let annotate = global_link_annotator(merged.provenance(), raw_config);
        let review = trust::render_review(&path_display, &approval, &file.bytes, &annotate);
        eprint!("{review}");
        eprintln!();

        if interactive {
            let question = trust::prompt_question(PromptKind::Launcher, &approval);
            let approved = trust::prompt_yes_no(question).unwrap_or(false);
            if approved {
                store.approve(root, &file_name, &file.bytes)?;
                eprintln!("trusted {path_display}");
            } else {
                eprintln!("not trusted; nothing started");
                return Err(LauncherError::Aborted);
            }
        } else {
            eprintln!("run `airlock trust` in a terminal to approve it");
            return Err(LauncherError::Aborted);
        }
    }
    Ok(())
}

/// Builds the `annotate` closure `render_review` calls per line: for a
/// `from = "global"` line inside a `[secrets.<label>]` block, shows what it
/// resolves to right now. Display only — not part of the approved bytes.
fn global_link_annotator<'a>(
    provenance: &'a Provenance,
    raw_config: &'a RawConfig,
) -> impl Fn(&str) -> Option<String> + 'a {
    let current_label = std::cell::RefCell::new(None::<String>);
    move |line: &str| {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("[secrets.") {
            if let Some(label) = rest.strip_suffix(']') {
                *current_label.borrow_mut() = Some(label.to_string());
            }
            return None;
        }
        if trimmed != "from = \"global\"" {
            return None;
        }
        let label = current_label.borrow().clone()?;
        if !matches!(
            provenance.secrets.get(&label).copied(),
            Some(layers::SecretProvenance::GlobalLink)
        ) {
            return None;
        }
        let spec = raw_config.secrets.as_ref()?.get(&label)?;
        describe_secret_source(spec)
    }
}

fn describe_secret_source(spec: &config::RawSecretSpec) -> Option<String> {
    match spec.source.as_deref() {
        Some("command") => {
            let argv = spec.command.as_ref()?;
            Some(format!("global: command {}", argv.join(" ")))
        }
        Some("env") => {
            let var = spec.from.as_deref().unwrap_or_default();
            Some(format!("global: env {var}"))
        }
        _ => None,
    }
}

// ─── Daemon startup and version skew ─────────────────────────────────────────

/// Timeout waiting for a daemon we told to stop to actually go away.
const DAEMON_STOP_TIMEOUT: Duration = Duration::from_secs(10);
const DAEMON_STOP_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Ensures a daemon is reachable at `runtime`'s socket: connects to an
/// existing one, handling version skew per "Upgrading Airlock" in the UX
/// doc, or starts an automatic one by re-executing this binary.
///
/// The returned `bool` is `true` when this call started a fresh automatic
/// daemon (so the caller can print `airlock: started daemon, PID …` under
/// `-v`), `false` when it reused one already running.
pub fn ensure_daemon(
    runtime: &RuntimeDir,
    verbose: bool,
    quiet: bool,
) -> Result<(admin::Connection, bool), LauncherError> {
    let mut conn = match admin::Connection::connect(&runtime.socket_path()) {
        Ok(c) => Some(c),
        Err(AdminError::Unreachable { .. }) => None,
        Err(e) => return Err(LauncherError::Admin(e)),
    };

    if let Some(c) = &conn {
        let skewed_protocol = c.hello.protocol != crate::protocol::PROTOCOL_VERSION;
        let skewed_version = c.hello.version != env!("CARGO_PKG_VERSION");

        if skewed_protocol && c.hello.sessions > 0 {
            return Err(LauncherError::Message(format!(
                "the running daemon (airlock {}) cannot serve this airlock ({}); \
                 `airlock daemon restart` replaces it and ends its {} sessions",
                c.hello.version,
                env!("CARGO_PKG_VERSION"),
                c.hello.sessions
            )));
        }

        if (skewed_protocol || skewed_version) && c.hello.sessions == 0 {
            let token = read_admin_token(runtime)?;
            let mut stale = conn.take().expect("checked Some above");
            let _ = stale.admin_request(&token, AdminRequest::Stop);
            drop(stale);
            wait_for_daemon_gone(runtime);
        } else if skewed_version && !quiet {
            eprintln!(
                "note: the daemon runs airlock {} and this is {}. It keeps serving its {} \
                 sessions; it is replaced when it is idle, or now with `airlock daemon restart`.",
                c.hello.version,
                env!("CARGO_PKG_VERSION"),
                c.hello.sessions
            );
        }
    }

    let started_new = conn.is_none();
    if started_new {
        spawn_automatic_daemon(verbose)?;
        conn = Some(admin::Connection::connect(&runtime.socket_path())?);
    }

    Ok((conn.expect("filled above"), started_new))
}

fn wait_for_daemon_gone(runtime: &RuntimeDir) {
    let deadline = std::time::Instant::now() + DAEMON_STOP_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(runtime.socket_path()).is_err() {
            return;
        }
        std::thread::sleep(DAEMON_STOP_POLL_INTERVAL);
    }
}

fn spawn_automatic_daemon(verbose: bool) -> Result<(), LauncherError> {
    let exe = std::env::current_exe()?;
    if verbose {
        eprintln!("airlock: starting daemon…");
    }
    let status = std::process::Command::new(exe)
        .args(["daemon", "start", "--automatic"])
        .status()?;
    if !status.success() {
        return Err(LauncherError::Aborted);
    }
    Ok(())
}

/// Reads and parses `admin.token` from the runtime directory.
pub fn read_admin_token(runtime: &RuntimeDir) -> Result<AdminToken, LauncherError> {
    let raw = std::fs::read_to_string(runtime.admin_token_path())?;
    AdminToken::parse(raw.trim())
        .map_err(|_| LauncherError::Message("admin.token is malformed".to_string()))
}

/// Registers a new session for `prepared` with the daemon over `conn`.
pub fn register(
    conn: &mut admin::Connection,
    token: &AdminToken,
    prepared: &Prepared,
    name: String,
    sandbox: SandboxKind,
    ends: SessionEnds,
) -> Result<(SessionId, SessionToken, Option<PathBuf>), LauncherError> {
    let payload = prepared.to_wire_payload();
    let request = AdminRequest::Register(Box::new(RegisterRequest {
        payload,
        name,
        sandbox,
        ends,
    }));
    match conn.admin_request(token, request)? {
        DaemonMessage::Registered { id, token, ca_path } => Ok((id, token, ca_path)),
        _ => Err(LauncherError::Message(
            "unexpected response from the daemon".to_string(),
        )),
    }
}

/// Reloads an existing session's config in place.
pub fn reload(
    conn: &mut admin::Connection,
    token: &AdminToken,
    session: &str,
    prepared: &Prepared,
) -> Result<(SessionId, Vec<String>, bool), LauncherError> {
    let payload = prepared.to_wire_payload();
    let request = AdminRequest::Reload {
        session: session.to_string(),
        payload: Box::new(payload),
    };
    match conn.admin_request(token, request)? {
        DaemonMessage::Reloaded {
            id,
            changes,
            agent_changed,
        } => Ok((id, changes, agent_changed)),
        _ => Err(LauncherError::Message(
            "unexpected response from the daemon".to_string(),
        )),
    }
}

// ─── `airlock trust` ──────────────────────────────────────────────────────────

/// One file awaiting a decision, with everything [`run_trust`] needs to
/// review and (maybe) approve it.
struct PendingFile<'a> {
    file: &'a layers::LayerFile,
    file_name: String,
    approval: Approval,
}

/// Runs `airlock trust`: discovers the project exactly like `session
/// start`, validates and merges (refusing before anything is shown, same as
/// the launcher), then reviews and approves every repo/local/config-file
/// layer that isn't already approved.
#[allow(
    clippy::disallowed_methods,
    reason = "launcher-side: `airlock trust` runs in the user's terminal, resolving anchors from its own environment"
)]
pub fn run_trust(
    cwd: &Path,
    config_path: Option<PathBuf>,
    yes: bool,
    expect_sha256: &[String],
) -> Result<(), LauncherError> {
    let home = home_dir()?;
    let runtime = RuntimeDir::locate()?;
    let anchors = anchors::resolve(&|k| std::env::var(k).ok(), &home, &runtime);

    let mode = match &config_path {
        Some(path) => DiscoveryMode::ConfigFile(path.clone()),
        None => DiscoveryMode::Default,
    };
    let loaded = layers::load_layers(&mode, cwd, &home, &anchors.global_config)?;
    let root = loaded.root.clone();

    let merge_ctx = MergeContext {
        root: root.clone(),
        home: home.clone(),
        tool_state_base: anchors.tool_state_base.clone(),
    };
    let merged = layers::merge(&loaded, &merge_ctx)?;
    let raw_config = merged.to_wire();
    let resolved = config::resolve_wire_config(raw_config.clone(), &root)?;
    let write_grants = config::write_grants(&resolved);
    anchors::validate(&anchors, Some(&root), &write_grants)?;

    let store = TrustStore::open(&anchors.trust_store)?;
    let interactive = trust::is_interactive();

    let mut pending = Vec::new();
    for file in [&loaded.repo, &loaded.local].into_iter().flatten() {
        let file_name = trust_file_name(file.kind, &file.path);
        let approval = store.state(&root, &file_name, &file.bytes)?;
        if !matches!(approval, Approval::Approved) {
            pending.push(PendingFile {
                file,
                file_name,
                approval,
            });
        }
    }

    if pending.is_empty() {
        println!("nothing to trust; every config file is already approved");
        return Ok(());
    }

    let unapproved: Vec<trust::UnapprovedFile> = pending
        .iter()
        .map(|p| trust::UnapprovedFile {
            path_display: p.file.path.display().to_string(),
            sha256_current: p.file.sha256.clone(),
        })
        .collect();
    let annotate = global_link_annotator(merged.provenance(), &raw_config);

    let mut any_approved = false;
    match trust::decide(&unapproved, interactive, yes, expect_sha256) {
        trust::Decision::Approve => {
            for p in &pending {
                print_review(&p.file.path, &p.approval, &p.file.bytes, &annotate);
                store.approve(&root, &p.file_name, &p.file.bytes)?;
                println!("trusted {}", p.file.path.display());
                any_approved = true;
            }
        }
        trust::Decision::Prompt => {
            for p in &pending {
                print_review(&p.file.path, &p.approval, &p.file.bytes, &annotate);
                let question = trust::prompt_question(PromptKind::TrustCommand, &p.approval);
                if trust::prompt_yes_no(question).unwrap_or(false) {
                    store.approve(&root, &p.file_name, &p.file.bytes)?;
                    println!("trusted {}", p.file.path.display());
                    any_approved = true;
                } else {
                    println!("not trusted: {}", p.file.path.display());
                }
            }
        }
        trust::Decision::Refuse { .. } => {
            for p in &pending {
                print_review(&p.file.path, &p.approval, &p.file.bytes, &annotate);
            }
            println!("run `airlock trust -y` or `--expect-sha256` on a non-terminal to approve");
            return Err(LauncherError::Aborted);
        }
    }

    if any_approved {
        notify_sessions_using_previous_config(&root);
    }

    Ok(())
}

fn print_review(
    path: &Path,
    approval: &Approval,
    bytes: &[u8],
    annotate: &dyn Fn(&str) -> Option<String>,
) {
    let path_display = path.display().to_string();
    let review = trust::render_review(&path_display, approval, bytes, annotate);
    print!("{review}");
    println!();
}

/// Best-effort: if the daemon is running and already has sessions for
/// `root`, tells the user to `airlock session reload` them.
fn notify_sessions_using_previous_config(root: &Path) {
    let Ok(runtime) = RuntimeDir::locate() else {
        return;
    };
    let Ok(mut conn) = admin::Connection::connect(&runtime.socket_path()) else {
        return;
    };
    let Ok(token) = read_admin_token(&runtime) else {
        return;
    };
    let Ok(DaemonMessage::Sessions { sessions }) =
        conn.admin_request(&token, AdminRequest::ListSessions)
    else {
        return;
    };
    let matching: Vec<_> = sessions.iter().filter(|s| s.root == root).collect();
    if matching.is_empty() {
        return;
    }
    let names: Vec<String> = matching
        .iter()
        .map(|s| format!("{} {:?}", s.id, s.name))
        .collect();
    println!(
        "{} session{} for {} use the previous config: {}",
        matching.len(),
        if matching.len() == 1 { "" } else { "s" },
        root.display(),
        names.join(", ")
    );
    println!("run `airlock session reload` to apply it to them");
}

// ─── Name defaults ────────────────────────────────────────────────────────────

/// The default `--name` for `run`: the harness command's base name.
pub fn default_name_from_command(command: &str) -> String {
    Path::new(command)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| command.to_string())
}

/// The default `--name` for `session start`: `"shell"`.
pub fn default_session_start_name() -> String {
    "shell".to_string()
}

// ─── Duration parsing (`--ttl`) ───────────────────────────────────────────────

/// Errors parsing a `--ttl` duration like `30m`, `12h`, `2d`, or `0`.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid duration {0:?}: expected a number followed by m, h, or d, or 0")]
pub struct DurationParseError(String);

/// Parses a `--ttl` value into seconds. `0` means never; `30m`/`12h`/`2d`
/// parse as minutes/hours/days.
pub fn parse_ttl(s: &str) -> Result<u64, DurationParseError> {
    if s == "0" {
        return Ok(0);
    }
    let (digits, unit) = s.split_at(s.len().saturating_sub(1));
    let multiplier = match unit {
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return Err(DurationParseError(s.to_string())),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| DurationParseError(s.to_string()))?;
    Ok(n * multiplier)
}

/// Formats a session duration for display (`"12h"`, `"90m"`, ...), the
/// inverse of [`parse_ttl`] for the common cases `session list`/`session
/// start` print.
pub fn format_duration_short(secs: u64) -> String {
    if secs == 0 {
        return "never".to_string();
    }
    if secs.is_multiple_of(24 * 60 * 60) {
        return format!("{}d", secs / (24 * 60 * 60));
    }
    if secs.is_multiple_of(60 * 60) {
        return format!("{}h", secs / (60 * 60));
    }
    if secs.is_multiple_of(60) {
        return format!("{}m", secs / 60);
    }
    format!("{secs}s")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ttl_zero_means_never() {
        assert_eq!(parse_ttl("0"), Ok(0));
    }

    #[test]
    fn parse_ttl_minutes_hours_days() {
        assert_eq!(parse_ttl("30m"), Ok(30 * 60));
        assert_eq!(parse_ttl("12h"), Ok(12 * 60 * 60));
        assert_eq!(parse_ttl("2d"), Ok(2 * 24 * 60 * 60));
    }

    #[test]
    fn parse_ttl_rejects_garbage() {
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("abc").is_err());
        assert!(parse_ttl("5x").is_err());
        assert!(parse_ttl("-5m").is_err());
    }

    #[test]
    fn format_duration_short_round_trips_common_values() {
        assert_eq!(format_duration_short(0), "never");
        assert_eq!(format_duration_short(12 * 60 * 60), "12h");
        assert_eq!(format_duration_short(90 * 60), "90m");
        assert_eq!(format_duration_short(2 * 24 * 60 * 60), "2d");
    }

    #[test]
    fn default_name_from_command_uses_basename() {
        assert_eq!(default_name_from_command("/usr/bin/claude"), "claude");
        assert_eq!(default_name_from_command("codex"), "codex");
    }

    #[test]
    fn default_session_start_name_is_shell() {
        assert_eq!(default_session_start_name(), "shell");
    }
}
