//! Agent process orchestrator for `airlock run`.
//!
//! Drives the launcher pipeline ([`crate::launcher`]) to get a sandboxed
//! agent a credential-bearing session, then:
//!
//! - Builds a clean, sandboxed environment for the agent child process.
//! - Spawns the agent with platform-specific OS sandboxing (Seatbelt on
//!   macOS, Landlock on Linux).
//! - Forwards SIGHUP, SIGINT and SIGTERM to the agent.
//! - Watches the session's lease connection and tells the user if it closes
//!   out from under a running agent.
//! - Ends the lease (if any) when the agent exits.
//!
//! `run_agent` itself stays synchronous until every step that can fail
//! outside a sandboxed child has run; the tokio runtime used to drive the
//! agent and the lease watcher is created only at the very end.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::ValueEnum;
use thiserror::Error;
use tokio::process::{Child, Command};

use crate::config::{AgentConfig, EnvValue};
use crate::launcher::{self, DiscoverOpts, LauncherError, PrepareOptions, Prepared};
use crate::policy::build_agent_policy;
use crate::protocol::{SandboxKind, SessionEnds};
use crate::sandbox::{self, SandboxError, SandboxProfile};
use crate::secrets::Secret;

// ─── SendSyncPtr (macOS only) ─────────────────────────────────────────────────
//
// Redeclared from `src/exec.rs` — the duplication is intentional so both
// spawn sites remain independently readable. See `exec.rs` for the original
// and its safety documentation.

#[cfg(target_os = "macos")]
struct SendSyncPtr(*const std::ffi::c_char);

// SAFETY: The pointer is used only in the single-threaded post-fork child
// context, before exec replaces the process image. See exec.rs for the full
// safety argument.
#[cfg(target_os = "macos")]
unsafe impl Send for SendSyncPtr {}

#[cfg(target_os = "macos")]
unsafe impl Sync for SendSyncPtr {}

#[cfg(target_os = "macos")]
impl SendSyncPtr {
    fn as_ptr(&self) -> *const std::ffi::c_char {
        self.0
    }
}

// ─── RunError ─────────────────────────────────────────────────────────────────

/// Errors that can occur during `airlock run`.
#[derive(Debug, Error)]
pub enum RunError {
    /// The launcher already printed everything the user needs to see
    /// (a trust decline, a non-interactive refusal); the caller just maps
    /// this to exit 125.
    #[error("already reported")]
    Aborted,

    /// Any other launcher failure (discovery, trust, secrets, daemon).
    #[error("{0}")]
    Launcher(String),

    /// The sandbox profile could not be built.
    #[error("sandbox error: {0}")]
    Sandbox(#[from] SandboxError),

    /// The tokio runtime could not be created.
    #[error("failed to create tokio runtime: {0}")]
    RuntimeCreation(#[source] std::io::Error),

    /// The agent child process could not be spawned.
    #[error("failed to spawn agent process: {0}")]
    SpawnFailed(#[source] std::io::Error),
}

impl From<LauncherError> for RunError {
    fn from(e: LauncherError) -> Self {
        match e {
            LauncherError::Aborted => RunError::Aborted,
            other => RunError::Launcher(other.to_string()),
        }
    }
}

// ─── Built-in profiles ────────────────────────────────────────────────────────

/// Built-in filesystem profiles that pre-populate the agent's sandbox
/// read/write paths for well-known tools.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Claude Code: grants read/write access to `~/.claude/`, `~/.claude.json`,
    /// and `~/.local/share/claude/`, and installs the SessionStart hook
    /// (`airlock agent hook claude-code`).
    Claude,
    /// Claude Code with interactive-ergonomics relaxations: everything in
    /// [`Profile::Claude`] plus clipboard, `open <url>` via Launch Services,
    /// default-browser lookup, shell init dotfile reads, and read/write to
    /// `~/Library/Keychains/`. See SECURITY.md for the tradeoffs.
    ClaudeRelaxed,
}

/// The settings blob a `--profile claude`/`claude-relaxed` default command
/// passes to `claude --settings`: it disables Claude Code's own inner
/// `sandbox-exec` wrapper (nesting Seatbelt profiles is rejected by the
/// kernel — airlock's outer profile already confines the agent) and
/// installs the SessionStart hook described in
/// `docs/airlock-v2-ux.md`, "Installing the hook". The `hooks` portion
/// comes from [`crate::agent::claude_code_hooks_value`] — the same object
/// `agent hook claude-code --print-settings` prints — so the hook actually
/// installed and the one the docs show can never drift apart.
pub fn claude_hook_settings_json() -> String {
    let mut value = crate::agent::claude_code_hooks_value();
    value["sandbox"] = serde_json::json!({ "enabled": false });
    serde_json::to_string(&value).expect("hook settings JSON always serializes")
}

impl Profile {
    /// Default command and arguments to invoke when `airlock run --profile <P>`
    /// is called without a trailing command.
    pub fn default_command(self) -> Vec<String> {
        match self {
            Profile::Claude | Profile::ClaudeRelaxed => vec![
                "claude".to_string(),
                "--dangerously-skip-permissions".to_string(),
                "--settings".to_string(),
                claude_hook_settings_json(),
            ],
        }
    }

    fn sandbox_kind(self) -> crate::sandbox::AgentProfileKind {
        match self {
            Profile::Claude => crate::sandbox::AgentProfileKind::Claude,
            Profile::ClaudeRelaxed => crate::sandbox::AgentProfileKind::ClaudeRelaxed,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Profile::Claude => "claude",
            Profile::ClaudeRelaxed => "claude-relaxed",
        }
    }
}

/// Resolve the read/write filesystem paths that a profile contributes to the
/// agent policy. `$HOME` comes from the launcher's environment snapshot, not
/// the live process environment.
pub(crate) fn profile_read_write_paths(profile: Profile, home: Option<&str>) -> Vec<PathBuf> {
    let Some(home) = home else {
        return Vec::new();
    };

    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from(home).join(".claude"),
        PathBuf::from(home).join(".claude.json"),
        PathBuf::from(home).join(".cache/claude"),
        PathBuf::from(home).join(".local/share/claude"),
        PathBuf::from(home).join(".local/state/claude"),
    ];

    if matches!(profile, Profile::ClaudeRelaxed) {
        candidates.push(PathBuf::from(home).join("Library/Keychains"));
    }

    candidates.into_iter().filter(|p| p.exists()).collect()
}

// ─── Toolchain auto-detection ─────────────────────────────────────────────────

/// Probe common toolchain installation directories and return those that exist.
pub(crate) fn detect_toolchain_paths(home: Option<&str>) -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from("/usr/local"),
        PathBuf::from("/opt/homebrew"),
        PathBuf::from("/nix/store"),
    ];

    const TILDE_CANDIDATES: &[&str] = &[
        "~/.local/bin",
        "~/.cargo/bin",
        "~/.rustup",
        "~/.pyenv",
        "~/.nvm",
    ];

    for tilde_path in TILDE_CANDIDATES {
        if let Some(home_dir) = home {
            candidates.push(PathBuf::from(tilde_path.replacen('~', home_dir, 1)));
        }
    }

    candidates.into_iter().filter(|p| p.exists()).collect()
}

// ─── Agent environment builder ────────────────────────────────────────────────

/// Build the clean environment map for the agent child process from the
/// launcher's resolved state — never the live process environment.
///
/// Layers (applied in order): essential variables from `snapshot`, the
/// `AIRLOCK_SANDBOX` marker, `passthrough_env` from `[agent]`, `[agent.env]`
/// entries (secrets resolved from `secret_values`), then CLI
/// `--passthrough-env` names. See the v1 docstring this replaces for the
/// rationale behind each layer; unchanged here except that every lookup
/// goes through `snapshot` instead of `std::env`.
pub(crate) fn build_agent_env(
    agent_config: Option<&AgentConfig>,
    secret_values: &HashMap<String, Secret<String>>,
    cli_passthrough_env: &[String],
    snapshot: &std::collections::BTreeMap<String, String>,
) -> HashMap<String, String> {
    let mut env: HashMap<String, String> = HashMap::new();

    const NAMED_ESSENTIAL: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "SHELL",
        "TERM",
        "TERMINFO",
        "TERMINFO_DIRS",
        "LANG",
        "TZ",
        "TMPDIR",
    ];
    for &var in NAMED_ESSENTIAL {
        if let Some(value) = snapshot.get(var) {
            env.insert(var.to_string(), value.clone());
        }
    }
    for (key, value) in snapshot {
        if key.starts_with("LC_") {
            env.insert(key.clone(), value.clone());
        }
    }

    env.insert("AIRLOCK_SANDBOX".to_string(), "1".to_string());

    if let Some(agent) = agent_config {
        for var in &agent.passthrough_env {
            if let Some(value) = snapshot.get(var) {
                env.insert(var.clone(), value.clone());
            }
        }

        for (name, entry) in &agent.env {
            match entry {
                EnvValue::Static(s) => {
                    env.insert(name.clone(), s.clone());
                }
                EnvValue::SecretRef(label) => {
                    if let Some(secret) = secret_values.get(label) {
                        env.insert(name.clone(), secret.expose_secret().clone());
                    }
                }
            }
        }
    }

    for var in cli_passthrough_env {
        if let Some(value) = snapshot.get(var) {
            env.insert(var.clone(), value.clone());
        }
    }

    env
}

/// Applies a kit's resolved env on top of an already-built agent env
/// (passthrough + `[agent.env]`), overriding any colliding key — the
/// isolation guarantee an isolated kit depends on: a `CARGO_HOME` the user
/// passes through must not defeat it.
pub(crate) fn apply_kit_env(
    mut env: HashMap<String, String>,
    kit_env: &std::collections::BTreeMap<String, String>,
) -> HashMap<String, String> {
    for (k, v) in kit_env {
        env.insert(k.clone(), v.clone());
    }
    env
}

// ─── RunOptions ───────────────────────────────────────────────────────────────

/// CLI options forwarded from `Commands::Run` to [`run_agent`].
pub struct RunOptions {
    pub profile: Option<Profile>,
    pub allow_read: Vec<PathBuf>,
    pub allow_write: Vec<PathBuf>,
    pub passthrough_env: Vec<String>,
    pub name: Option<String>,
    pub no_session: bool,
    pub discover: DiscoverOpts,
    pub verbose: bool,
    pub quiet: bool,
    /// `--kit` (repeatable), additive to `agent.kits` — see "Kits" in
    /// `docs/airlock-v2-design.md`.
    pub kits: Vec<String>,
}

// ─── run_agent ────────────────────────────────────────────────────────────────

/// Run an agent process inside an OS-level sandbox, registering a leased
/// session with the daemon unless `opts.no_session` is set.
///
/// Deliberately **not** `async` — consistent with the project invariant
/// that `main()` is synchronous (CLAUDE.md). A tokio runtime is created
/// internally once every fallible, pre-sandbox step has completed.
pub fn run_agent(
    cwd: &Path,
    command: &str,
    args: &[String],
    opts: RunOptions,
) -> Result<ExitCode, RunError> {
    let extra_write_grants = resolve_paths(&opts.allow_write, cwd);

    let prepared = launcher::prepare(
        cwd,
        &PrepareOptions {
            discover: opts.discover.clone(),
            verbose: opts.verbose,
            quiet: opts.quiet,
            extra_write_grants,
            cli_kits: opts.kits.clone(),
        },
    )?;

    let name = opts
        .name
        .clone()
        .unwrap_or_else(|| launcher::default_name_from_command(command));

    let session = if opts.no_session {
        None
    } else {
        Some(start_session(
            &prepared,
            name.clone(),
            opts.verbose,
            opts.quiet,
        )?)
    };

    let home = prepared.env_snapshot.get("HOME").map(String::as_str);
    let toolchain_paths = detect_toolchain_paths(home);
    let mut policy = build_agent_policy(&prepared.config, &toolchain_paths);
    policy.runtime_base = Some(prepared.anchors.runtime_base.clone());
    policy.tmpdir = prepared.env_snapshot.get("TMPDIR").map(PathBuf::from);
    policy.home = home.map(PathBuf::from);
    if let Some(p) = opts.profile {
        policy
            .read_write_paths
            .extend(profile_read_write_paths(p, home));
    }
    policy
        .read_paths
        .extend(resolve_paths(&opts.allow_read, cwd));
    policy
        .read_write_paths
        .extend(resolve_paths(&opts.allow_write, cwd));
    // Kit read paths may not exist (e.g. no ~/.rustup on this machine) —
    // filtered here, same as detect_toolchain_paths/profile_read_write_paths.
    // Kit write dirs/files were already created by launcher::prepare, so no
    // filter is needed (and none would be correct: a missing shared dir
    // the launcher just created for a kit must still be granted).
    policy
        .read_paths
        .extend(prepared.kits.read.iter().filter(|p| p.exists()).cloned());
    policy
        .read_write_paths
        .extend(prepared.kits.write.iter().cloned());
    policy
        .read_write_paths
        .extend(prepared.kits.write_files.iter().cloned());

    let sandbox_profile_kind = opts.profile.map(Profile::sandbox_kind);
    let mut sandbox_profile =
        sandbox::build_platform_agent_sandbox_profile(&policy, sandbox_profile_kind)?;

    let mut env = build_agent_env(
        prepared.config.agent.as_ref(),
        &prepared.secret_values,
        &opts.passthrough_env,
        &prepared.env_snapshot,
    );
    // Applied after the env snapshot and the passthrough env above, so a
    // CARGO_HOME (etc.) the user passes through cannot defeat an isolated
    // kit's whole point.
    env = apply_kit_env(env, &prepared.kits.env);
    if let Some(session) = &session {
        env.insert("AIRLOCK_ADDR".to_string(), prepared.runtime.addr());
        env.insert("AIRLOCK_SESSION".to_string(), session.token.expose_secret());
    }

    if opts.verbose {
        let profile_desc = opts
            .profile
            .map(|p| format!("{} profile, ", p.label()))
            .unwrap_or_default();
        eprintln!(
            "airlock: sandbox: {profile_desc}root {}",
            prepared.root.display()
        );
        if !prepared.kits.active.is_empty() {
            let desc: Vec<String> = prepared
                .kits
                .active
                .iter()
                .map(|(name, mode)| match mode {
                    Some(m) => format!("{name} ({})", m.as_str()),
                    None => name.clone(),
                })
                .collect();
            eprintln!("airlock: kits: {}", desc.join(", "));
        }
    }

    let timeout = prepared
        .config
        .agent
        .as_ref()
        .map(|a| a.timeout)
        .unwrap_or(Duration::ZERO);

    let command = command.to_string();
    let args = args.to_vec();

    let runtime = tokio::runtime::Runtime::new().map_err(RunError::RuntimeCreation)?;
    runtime.block_on(async move {
        let sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler should be installable");

        let (child, child_pid) = spawn_agent(&mut sandbox_profile, &command, &args, env)
            .map_err(RunError::SpawnFailed)?;

        let lease_ended = match session {
            Some(s) => watch_lease(s.lease),
            // No session to watch: a receiver whose sender we deliberately
            // never drop (leaking the sender half, scoped to this process's
            // lifetime) so it never resolves and the `lease_ended` branch in
            // `signal_loop`'s select! never fires.
            None => {
                let (tx, rx) = tokio::sync::oneshot::channel();
                std::mem::forget(tx);
                rx
            }
        };

        let exit_code = signal_loop(child, child_pid, timeout, sigterm, lease_ended).await;
        Ok::<ExitCode, RunError>(exit_code)
    })
}

fn resolve_paths(paths: &[PathBuf], cwd: &Path) -> Vec<PathBuf> {
    paths
        .iter()
        .map(|p| {
            if p.is_absolute() {
                p.clone()
            } else {
                cwd.join(p)
            }
        })
        .collect()
}

/// The session a leased `airlock run` registered: its token (for
/// `AIRLOCK_SESSION`) and the still-open admin connection, which the daemon
/// treats as the lease — closing it (dropping `lease`) ends the session.
struct Session {
    token: crate::protocol::SessionToken,
    lease: std::os::unix::net::UnixStream,
}

fn start_session(
    prepared: &Prepared,
    name: String,
    verbose: bool,
    quiet: bool,
) -> Result<Session, RunError> {
    let (mut conn, started_new) = launcher::ensure_daemon(&prepared.runtime, verbose, quiet)?;
    if verbose && started_new {
        eprintln!(
            "airlock: started daemon, PID {}, exits when idle",
            conn.hello.pid
        );
    }
    let admin_token = launcher::read_admin_token(&prepared.runtime)?;
    let (id, token, _ca_path) = launcher::register(
        &mut conn,
        &admin_token,
        prepared,
        name.clone(),
        SandboxKind::Airlock,
        SessionEnds::Lease,
    )?;
    if verbose {
        let n = prepared.config.tools.len();
        eprintln!(
            "airlock: session {id} {name:?} registered, {n} tool{}",
            if n == 1 { "" } else { "s" }
        );
    }
    let lease = conn.into_raw().map_err(LauncherError::from)?;
    Ok(Session { token, lease })
}

/// Spawns a blocking watcher on the lease connection's raw socket. Resolves
/// (sends on the oneshot) when the daemon closes it — which means the
/// session ended (revoked, or the daemon stopped) — so `signal_loop` can
/// tell the user while the agent keeps running.
fn watch_lease(mut stream: std::os::unix::net::UnixStream) -> tokio::sync::oneshot::Receiver<()> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1];
        // Any read outcome (EOF, data, or error) means the connection is no
        // longer a quiet, open lease; either is a reason to notify.
        let _ = std::io::Read::read(&mut stream, &mut buf);
        let _ = tx.send(());
    });
    rx
}

/// Spawn the agent child process with the platform sandbox applied via
/// `pre_exec`.
#[allow(unused_mut)]
fn spawn_agent(
    sandbox_profile: &mut SandboxProfile,
    command: &str,
    args: &[String],
    env: HashMap<String, String>,
) -> Result<(Child, u32), std::io::Error> {
    let mut cmd = Command::new(command);
    cmd.args(args);
    cmd.env_clear();
    cmd.envs(env);

    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    #[cfg(target_os = "macos")]
    {
        let sbpl_ptr = SendSyncPtr(sandbox_profile.as_ptr());

        // SAFETY: see exec.rs's pre_exec safety argument; the same applies
        // here. No setpgid(0, 0): the agent stays in the parent's process
        // group so Ctrl+C reaches it directly.
        unsafe {
            cmd.pre_exec(move || {
                let mut errorbuf: *mut std::ffi::c_char = std::ptr::null_mut();
                let ret = crate::sandbox::macos::sandbox_init(sbpl_ptr.as_ptr(), 0, &mut errorbuf);
                if ret != 0 {
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
        let raw_fd = sandbox_profile.raw_fd();

        // SAFETY: see exec.rs's pre_exec safety argument.
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::syscall(libc::SYS_landlock_restrict_self, raw_fd, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = sandbox_profile;
    }

    let mut child = cmd.spawn()?;

    #[cfg(target_os = "linux")]
    sandbox_profile.close_ruleset_fd();

    let child_pid = child
        .id()
        .expect("child PID should be available immediately after spawn");

    Ok((child, child_pid))
}

/// Wait for the agent child to exit, forwarding SIGTERM/SIGHUP, enforcing an
/// optional session timeout, and reporting a lease that closed out from
/// under the agent.
async fn signal_loop(
    mut child: Child,
    child_pid: u32,
    timeout: Duration,
    mut sigterm: tokio::signal::unix::Signal,
    lease_ended: tokio::sync::oneshot::Receiver<()>,
) -> ExitCode {
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("SIGHUP handler should be installable");
    // The agent shares this process's group, so a terminal Ctrl-C already
    // delivers SIGINT to it directly; forwarding it again here is harmless
    // (same as SIGTERM below) and covers a SIGINT sent to the launcher
    // alone, e.g. via `kill -INT`.
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("SIGINT handler should be installable");

    let use_timeout = !timeout.is_zero();
    let timeout_sleep = tokio::time::sleep(if use_timeout {
        timeout
    } else {
        Duration::from_secs(365 * 24 * 3600)
    });
    tokio::pin!(timeout_sleep);
    tokio::pin!(lease_ended);
    let mut lease_notified = false;

    loop {
        tokio::select! {
            result = child.wait() => {
                return match result {
                    Ok(status) => exit_status_to_code(status),
                    Err(_) => ExitCode::FAILURE,
                };
            }
            _ = sigterm.recv() => {
                // SAFETY: kill() is a standard POSIX syscall; child_pid is a
                // valid PID freshly returned by Child::id().
                unsafe { libc::kill(child_pid as i32, libc::SIGTERM); }
            }
            _ = sighup.recv() => {
                unsafe { libc::kill(child_pid as i32, libc::SIGHUP); }
            }
            _ = sigint.recv() => {
                unsafe { libc::kill(child_pid as i32, libc::SIGINT); }
            }
            _ = &mut lease_ended, if !lease_notified => {
                lease_notified = true;
                eprintln!(
                    "airlock: the agent's session has ended (the daemon stopped or the \
                     session was revoked)"
                );
            }
            _ = &mut timeout_sleep, if use_timeout => {
                unsafe { libc::kill(child_pid as i32, libc::SIGTERM); }
                return tokio::select! {
                    result = child.wait() => {
                        match result {
                            Ok(status) => exit_status_to_code(status),
                            Err(_) => ExitCode::FAILURE,
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {
                        unsafe { libc::kill(child_pid as i32, libc::SIGKILL); }
                        match child.wait().await {
                            Ok(status) => exit_status_to_code(status),
                            Err(_) => ExitCode::FAILURE,
                        }
                    }
                };
            }
        }
    }
}

/// Map a process exit status to an [`ExitCode`].
fn exit_status_to_code(status: std::process::ExitStatus) -> ExitCode {
    match status.code() {
        Some(code) => ExitCode::from((code as u32 & 0xFF) as u8),
        None => ExitCode::FAILURE,
    }
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::secrets::Secret;

    fn agent_config_with_passthrough(vars: &[&str]) -> AgentConfig {
        AgentConfig {
            timeout: Duration::ZERO,
            passthrough_env: vars.iter().map(|s| s.to_string()).collect(),
            env: BTreeMap::new(),
            filesystem_read: Vec::new(),
            filesystem_write: Vec::new(),
        }
    }

    fn agent_config_with_env(entries: Vec<(&str, EnvValue)>) -> AgentConfig {
        AgentConfig {
            timeout: Duration::ZERO,
            passthrough_env: Vec::new(),
            env: entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            filesystem_read: Vec::new(),
            filesystem_write: Vec::new(),
        }
    }

    fn snapshot(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn agent_env_always_sets_airlock_sandbox() {
        let env = build_agent_env(None, &HashMap::new(), &[], &BTreeMap::new());
        assert_eq!(env.get("AIRLOCK_SANDBOX").map(String::as_str), Some("1"));
    }

    #[test]
    fn agent_env_pulls_essentials_from_snapshot_not_process_env() {
        // SHELL is set in the snapshot but deliberately absent from the
        // process's own env, proving the lookup goes through `snapshot`.
        let snap = snapshot(&[("SHELL", "/bin/zsh")]);
        let env = build_agent_env(None, &HashMap::new(), &[], &snap);
        assert_eq!(env.get("SHELL").map(String::as_str), Some("/bin/zsh"));
    }

    #[test]
    fn agent_env_excludes_vars_not_in_snapshot_or_passthrough() {
        let snap = snapshot(&[("SOME_OTHER_SECRET", "nope")]);
        let env = build_agent_env(None, &HashMap::new(), &[], &snap);
        assert!(!env.contains_key("SOME_OTHER_SECRET"));
    }

    #[test]
    fn agent_env_passthrough_from_config() {
        let agent = agent_config_with_passthrough(&["COLORTERM"]);
        let snap = snapshot(&[("COLORTERM", "truecolor")]);
        let env = build_agent_env(Some(&agent), &HashMap::new(), &[], &snap);
        assert_eq!(env.get("COLORTERM").map(String::as_str), Some("truecolor"));
    }

    #[test]
    fn agent_env_passthrough_skips_absent_var() {
        let agent = agent_config_with_passthrough(&["NOT_SET"]);
        let env = build_agent_env(Some(&agent), &HashMap::new(), &[], &BTreeMap::new());
        assert!(!env.contains_key("NOT_SET"));
    }

    #[test]
    fn agent_env_static_and_secret_ref_entries() {
        let mut secrets = HashMap::new();
        secrets.insert("API_KEY".to_string(), Secret::new("s3cr3t".to_string()));
        let agent = agent_config_with_env(vec![
            ("STATIC_VAR", EnvValue::Static("hello".to_string())),
            ("SECRET_VAR", EnvValue::SecretRef("API_KEY".to_string())),
        ]);
        let env = build_agent_env(Some(&agent), &secrets, &[], &BTreeMap::new());
        assert_eq!(env.get("STATIC_VAR").map(String::as_str), Some("hello"));
        assert_eq!(env.get("SECRET_VAR").map(String::as_str), Some("s3cr3t"));
    }

    #[test]
    fn agent_env_cli_passthrough_is_additive() {
        let agent = agent_config_with_passthrough(&["CONFIG_VAR"]);
        let snap = snapshot(&[("CONFIG_VAR", "a"), ("CLI_VAR", "b")]);
        let env = build_agent_env(
            Some(&agent),
            &HashMap::new(),
            &["CLI_VAR".to_string()],
            &snap,
        );
        assert_eq!(env.get("CONFIG_VAR").map(String::as_str), Some("a"));
        assert_eq!(env.get("CLI_VAR").map(String::as_str), Some("b"));
    }

    #[test]
    fn apply_kit_env_overrides_passthrough_cargo_home() {
        // A user passing through their own CARGO_HOME must not defeat an
        // isolated rust kit — kit env wins.
        let snap = snapshot(&[("CARGO_HOME", "/home/u/.cargo")]);
        let env = build_agent_env(None, &HashMap::new(), &["CARGO_HOME".to_string()], &snap);
        assert_eq!(
            env.get("CARGO_HOME").map(String::as_str),
            Some("/home/u/.cargo")
        );

        let mut kit_env = BTreeMap::new();
        kit_env.insert(
            "CARGO_HOME".to_string(),
            "/kit-state/rust/cargo".to_string(),
        );
        let env = apply_kit_env(env, &kit_env);
        assert_eq!(
            env.get("CARGO_HOME").map(String::as_str),
            Some("/kit-state/rust/cargo")
        );
    }

    #[test]
    fn apply_kit_env_overrides_agent_env_too() {
        let agent = agent_config_with_env(vec![(
            "CARGO_HOME",
            EnvValue::Static("/wrong/cargo".to_string()),
        )]);
        let env = build_agent_env(Some(&agent), &HashMap::new(), &[], &BTreeMap::new());
        let mut kit_env = BTreeMap::new();
        kit_env.insert(
            "CARGO_HOME".to_string(),
            "/kit-state/rust/cargo".to_string(),
        );
        let env = apply_kit_env(env, &kit_env);
        assert_eq!(
            env.get("CARGO_HOME").map(String::as_str),
            Some("/kit-state/rust/cargo")
        );
    }

    #[test]
    fn apply_kit_env_leaves_unrelated_vars_alone() {
        let snap = snapshot(&[("SHELL", "/bin/zsh")]);
        let env = build_agent_env(None, &HashMap::new(), &[], &snap);
        let env = apply_kit_env(env, &BTreeMap::new());
        assert_eq!(env.get("SHELL").map(String::as_str), Some("/bin/zsh"));
    }

    #[test]
    fn profile_claude_default_command_has_hook_and_no_inner_sandbox() {
        let cmd = Profile::Claude.default_command();
        assert_eq!(cmd[0], "claude");
        assert!(cmd.contains(&"--dangerously-skip-permissions".to_string()));
        let settings = cmd.last().unwrap();
        assert!(settings.contains("airlock agent hook claude-code"));
        assert!(settings.contains(r#""sandbox":{"enabled":false}"#));
    }

    #[test]
    fn profile_claude_relaxed_shares_claude_default_command() {
        assert_eq!(
            Profile::Claude.default_command(),
            Profile::ClaudeRelaxed.default_command()
        );
    }

    #[test]
    fn profile_read_write_paths_empty_without_home() {
        assert!(profile_read_write_paths(Profile::Claude, None).is_empty());
    }

    #[test]
    fn profile_read_write_paths_only_existing_paths() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join(".claude")).unwrap();
        let home = tmp.path().to_str().unwrap();
        let paths = profile_read_write_paths(Profile::Claude, Some(home));
        assert!(paths.iter().all(|p| p.exists()));
        assert!(paths.iter().any(|p| p.ends_with(".claude")));
    }

    #[test]
    fn profile_relaxed_adds_keychains_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("Library/Keychains")).unwrap();
        let home = tmp.path().to_str().unwrap();
        let relaxed = profile_read_write_paths(Profile::ClaudeRelaxed, Some(home));
        let strict = profile_read_write_paths(Profile::Claude, Some(home));
        assert!(relaxed.iter().any(|p| p.ends_with("Library/Keychains")));
        assert!(!strict.iter().any(|p| p.ends_with("Library/Keychains")));
    }

    #[test]
    fn detect_toolchain_paths_only_existing_and_handles_no_home() {
        let paths = detect_toolchain_paths(None);
        for p in &paths {
            assert!(p.exists());
        }
    }

    #[test]
    fn resolve_paths_joins_relative_against_cwd() {
        let cwd = Path::new("/some/project");
        let resolved = resolve_paths(&[PathBuf::from("rel"), PathBuf::from("/abs")], cwd);
        assert_eq!(resolved[0], PathBuf::from("/some/project/rel"));
        assert_eq!(resolved[1], PathBuf::from("/abs"));
    }

    // `signal_loop` only needs an already-spawned `tokio::process::Child`,
    // not an OS sandbox, so its SIGINT wiring is testable here without
    // nesting one: a real SIGINT delivered to this test process (which
    // `signal_loop`'s own handler, installed inside it, intercepts instead
    // of the OS default) must reach the child.
    #[tokio::test]
    async fn signal_loop_forwards_sigint_to_the_child() {
        let child = tokio::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("spawn sleep");
        let child_pid = child.id().expect("child has a pid");

        let sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install sigterm");
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::mem::forget(tx);

        let handle = tokio::spawn(signal_loop(child, child_pid, Duration::ZERO, sigterm, rx));

        // Give the spawned task a chance to run and install signal_loop's
        // own SIGINT handler before this sends one.
        tokio::time::sleep(Duration::from_millis(100)).await;
        // SAFETY: sends to this test process's own pid, a standard libc call.
        unsafe { libc::kill(std::process::id() as i32, libc::SIGINT) };

        let exit_code = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("signal_loop should not hang")
            .expect("signal_loop should not panic");
        // `sleep` has no SIGINT handler of its own, so the forwarded signal
        // kills it; a signal-terminated child has no exit code.
        assert_eq!(exit_code, ExitCode::FAILURE);
    }
}
