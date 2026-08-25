//! Agent process orchestrator for `airlock run`.
//!
//! This module drives the `airlock run` command. It:
//!
//! - Starts (or reuses) an Airlock daemon via [`daemon::synchronous_startup`].
//! - Auto-detects common toolchain locations on the host filesystem.
//! - Builds a clean, sandboxed environment for the agent child process.
//! - Spawns the agent with platform-specific OS sandboxing (Seatbelt on
//!   macOS, Landlock on Linux).
//! - Forwards SIGTERM and SIGHUP to the agent and enforces an optional
//!   session timeout.
//! - Tears down the embedded daemon (if started) when the agent exits.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::ValueEnum;
use thiserror::Error;
use tokio::process::{Child, Command};

use crate::config::{AgentConfig, ConfigError, EnvValue};
use crate::daemon::{self, DaemonError};
use crate::policy::build_agent_policy;
use crate::sandbox::{self, SandboxError, SandboxProfile};
use crate::secrets::{self, SecretStore, SecretsError};

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
    /// Returns the wrapped raw pointer.
    ///
    /// Using a method rather than direct field access (`.0`) ensures the
    /// closure captures the entire `SendSyncPtr` wrapper — not just the raw
    /// pointer field — avoiding a `Send + Sync` failure under Rust 2021+
    /// disjoint capture rules.
    fn as_ptr(&self) -> *const std::ffi::c_char {
        self.0
    }
}

// ─── RunError ─────────────────────────────────────────────────────────────────

/// Errors that can occur during `airlock run`.
#[derive(Debug, Error)]
pub enum RunError {
    /// No `airlock.toml` was found between the starting directory and `$HOME`.
    ///
    /// Callers should present a user-friendly message suggesting `airlock init`.
    #[error("no airlock.toml found; run `airlock init` to create one")]
    ConfigNotFound,

    /// The config file could not be loaded or parsed.
    #[error("config error: {0}")]
    Config(ConfigError),

    /// `--no-config` was set but `AIRLOCK_SANDBOX_ROOT` is not set in the environment.
    ///
    /// The caller must set `AIRLOCK_SANDBOX_ROOT` to an existing directory before
    /// invoking `airlock run --no-config`.
    #[error(
        "AIRLOCK_SANDBOX_ROOT is not set; \
         set it to an existing directory when using --no-config"
    )]
    SandboxRootRequired,

    /// `--no-config` was set and `AIRLOCK_SANDBOX_ROOT` names a path that does not exist.
    ///
    /// The directory must be created before `airlock run --no-config` is invoked.
    #[error(
        "AIRLOCK_SANDBOX_ROOT={0}: directory does not exist; \
         create it before running airlock"
    )]
    SandboxRootNotFound(PathBuf),

    /// The daemon failed to start or errored during the agent session.
    #[error("daemon error: {0}")]
    Daemon(DaemonError),

    /// The sandbox profile could not be built.
    #[error("sandbox error: {0}")]
    Sandbox(SandboxError),

    /// Secrets could not be read from the environment.
    #[error("secrets error: {0}")]
    Secrets(SecretsError),

    /// The tokio runtime could not be created.
    #[error("failed to create tokio runtime: {0}")]
    RuntimeCreation(#[source] std::io::Error),

    /// The agent child process could not be spawned.
    #[error("failed to spawn agent process: {0}")]
    SpawnFailed(#[source] std::io::Error),
}

// ─── Built-in profiles ────────────────────────────────────────────────────────

/// Built-in filesystem profiles that pre-populate the agent's sandbox
/// read/write paths for well-known tools.
///
/// Profiles are merged into [`AgentPolicy::read_write_paths`] after the policy
/// is constructed from config, so anything declared in `[agent.filesystem]`
/// composes with the profile rather than being overridden.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Claude Code: grants read/write access to `~/.claude/`, `~/.claude.json`,
    /// and `~/.local/share/claude/` so the agent can read settings, write
    /// telemetry, and access managed Claude installations.
    Claude,
    /// Claude Code with interactive-ergonomics relaxations: everything in
    /// [`Profile::Claude`] plus clipboard, `open <url>` via Launch Services,
    /// default-browser lookup, shell init dotfile reads, and read/write to
    /// `~/Library/Keychains/` (so `security add-generic-password` — used by
    /// Claude Code's OAuth token-save path — does not fall back to a plaintext
    /// `~/.claude/.credentials.json` file). Each of these is a deliberate
    /// widening of the data-leak surface; see [`SECURITY.md`](SECURITY.md).
    ClaudeRelaxed,
}

impl Profile {
    /// Default command and arguments to invoke when `airlock run --profile <P>`
    /// is called without a trailing command.
    pub fn default_command(self) -> Vec<String> {
        match self {
            // `--settings '{"sandbox":{"enabled":false}}'` disables Claude
            // Code's own inner `sandbox-exec` wrapper for Bash. Nesting
            // Seatbelt profiles is rejected by the kernel
            // (`sandbox_apply: Operation not permitted`), and airlock's
            // outer profile already confines the agent — the inner one
            // adds nothing but breakage.
            Profile::Claude | Profile::ClaudeRelaxed => vec![
                "claude".to_string(),
                "--dangerously-skip-permissions".to_string(),
                "--settings".to_string(),
                r#"{"sandbox":{"enabled":false}}"#.to_string(),
            ],
        }
    }

    /// Map a run-time [`Profile`] to the sandbox-side [`AgentProfileKind`] so
    /// platform backends can emit any profile-specific rules that cannot be
    /// expressed as plain read/write paths.
    fn sandbox_kind(self) -> crate::sandbox::AgentProfileKind {
        match self {
            Profile::Claude => crate::sandbox::AgentProfileKind::Claude,
            Profile::ClaudeRelaxed => crate::sandbox::AgentProfileKind::ClaudeRelaxed,
        }
    }
}

/// Resolve the read/write filesystem paths that a profile contributes to the
/// agent policy.
///
/// `$HOME` is required; if unset, an empty vec is returned (mirroring
/// [`detect_toolchain_paths`]). Non-existent paths are filtered out so that
/// Landlock profile construction on Linux does not fail when a path cannot be
/// opened — this means a first-time Claude Code run may need to bootstrap
/// `~/.claude.json` outside the sandbox before the profile can protect it.
pub(crate) fn profile_read_write_paths(profile: Profile) -> Vec<PathBuf> {
    let Some(home) = std::env::var("HOME").ok() else {
        return Vec::new();
    };

    // Shared base for every Claude variant.
    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from(&home).join(".claude"),
        PathBuf::from(&home).join(".claude.json"),
        PathBuf::from(&home).join(".cache/claude"),
        PathBuf::from(&home).join(".local/share/claude"),
        PathBuf::from(&home).join(".local/state/claude"),
    ];

    if matches!(profile, Profile::ClaudeRelaxed) {
        // `security add-generic-password` (legacy `SecKeychainItem*` API) takes
        // a file lock and writes the keychain DB directly. Without write access
        // here Claude Code's OAuth save path errors with
        // `UNIX[Operation not permitted]` and silently falls back to writing
        // `~/.claude/.credentials.json` in plaintext, which then desyncs from
        // the keychain copy. The standard `Claude` profile keeps the narrower
        // posture and accepts the plaintext fallback.
        candidates.push(PathBuf::from(&home).join("Library/Keychains"));
    }

    candidates.into_iter().filter(|p| p.exists()).collect()
}

// ─── Toolchain auto-detection ─────────────────────────────────────────────────

/// Probe common toolchain installation directories and return those that exist.
///
/// The candidate list covers standard system and user-local toolchain locations:
/// `/usr/local`, `/opt/homebrew`, `/nix/store`, plus tilde-expanded variants of
/// `~/.local/bin`, `~/.cargo/bin`, `~/.rustup`, `~/.pyenv`, and `~/.nvm`.
///
/// Tilde expansion reads `$HOME`. If `HOME` is unset, tilde-prefixed candidates
/// are silently skipped without error.
///
/// Only filesystem existence is checked — no executables are invoked.
pub(crate) fn detect_toolchain_paths() -> Vec<PathBuf> {
    let home = std::env::var("HOME").ok();

    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from("/usr/local"),
        PathBuf::from("/opt/homebrew"),
        PathBuf::from("/nix/store"),
    ];

    // Tilde-prefixed candidates: expand with $HOME, skip silently if HOME is unset.
    const TILDE_CANDIDATES: &[&str] = &[
        "~/.local/bin",
        "~/.cargo/bin",
        "~/.rustup",
        "~/.pyenv",
        "~/.nvm",
    ];

    for tilde_path in TILDE_CANDIDATES {
        if let Some(ref home_dir) = home {
            candidates.push(PathBuf::from(tilde_path.replacen('~', home_dir, 1)));
        }
        // HOME unset: skip silently — no error.
    }

    // Retain only paths that actually exist on this host.
    candidates.into_iter().filter(|p| p.exists()).collect()
}

// ─── Agent environment builder ────────────────────────────────────────────────

/// Build the clean environment map for the agent child process.
///
/// The host environment is **not** inherited — only explicitly approved
/// variables are included. Build layers (applied in order):
///
/// 1. **Essential host variables**: `PATH`, `HOME`, `USER`, `SHELL`, `TERM`,
///    `TERMINFO`, `TERMINFO_DIRS`, `LANG`, all `LC_*` variables, and `TZ` —
///    read from the current process environment and included if present.
///    (`SHELL` is intentionally included here even though it is absent from
///    `ESSENTIAL_VARS` in `exec.rs` — the two lists are independent. `LANG`,
///    `LC_*`, and `TZ` are locale and timezone variables that affect correct
///    tool behaviour without posing a credential-leak risk. `TERMINFO` /
///    `TERMINFO_DIRS` let ncurses locate the terminfo database — iTerm.app
///    ships its own terminfo out of `/usr/share/terminfo`, so without these
///    nano/vim/less fall back to a stub entry and arrow keys misbehave.)
/// 2. **Sandbox marker**: `AIRLOCK_SANDBOX=1` is always set.
/// 3. **`passthrough_env`** from `[agent]`: host variables explicitly listed
///    by the config author are included if set; absent variables are silently
///    skipped (never inserted as empty strings).
/// 4. **`[agent.env]` entries**: static values are inserted as-is; `SecretRef`
///    values are resolved by looking up the label in the secret store.
/// 5. **CLI `--passthrough-env` names** (`cli_passthrough_env`): same
///    lookup-and-insert logic as layer 3. Applied after config-based layers so
///    that CLI-supplied names are additive — they do not replace or remove
///    any variables forwarded via the config. Variables absent from the host
///    are silently skipped; no error is emitted.
///
/// Variables not listed in layers 1–5 are excluded regardless of their
/// presence in the host environment.
pub(crate) fn build_agent_env(
    agent_config: Option<&AgentConfig>,
    secrets: &SecretStore,
    cli_passthrough_env: &[String],
) -> HashMap<String, String> {
    let mut env: HashMap<String, String> = HashMap::new();

    // Layer 1a: Named essential variables.
    // Note: SHELL is intentionally included here even though it is absent from
    // ESSENTIAL_VARS in exec.rs — the two lists are independent.
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
        if let Ok(value) = std::env::var(var) {
            env.insert(var.to_string(), value);
        }
    }

    // Layer 1b: All LC_* variables from the host environment.
    for (key, value) in std::env::vars() {
        if key.starts_with("LC_") {
            env.insert(key, value);
        }
    }

    // Layer 2: Sandbox marker — unconditionally present.
    env.insert("AIRLOCK_SANDBOX".to_string(), "1".to_string());

    if let Some(agent) = agent_config {
        // Layer 3: Passthrough variables declared in [agent].
        // Variables absent from the host environment are silently skipped.
        for var in &agent.passthrough_env {
            if let Ok(value) = std::env::var(var) {
                env.insert(var.clone(), value);
            }
        }

        // Layer 4: Declared env entries from [agent.env].
        for (name, entry) in &agent.env {
            match entry {
                EnvValue::Static(s) => {
                    env.insert(name.clone(), s.clone());
                }
                EnvValue::SecretRef(label) => {
                    // Resolve the label against the secret store. If the label
                    // is absent (should not happen after config validation),
                    // skip silently rather than panicking.
                    if let Some(slot_lock) = secrets.get(label) {
                        let slot = slot_lock.read().expect("secret slot lock not poisoned");
                        env.insert(name.clone(), slot.value.expose_secret().clone());
                    }
                }
            }
        }
    }

    // Layer 5: CLI-supplied passthrough env variable names (`--passthrough-env`).
    // Same lookup-and-insert logic as Layer 3. Additive w.r.t. config-based
    // passthrough vars — variables absent from the host are silently skipped.
    for var in cli_passthrough_env {
        if let Ok(value) = std::env::var(var) {
            env.insert(var.clone(), value);
        }
    }

    env
}

// ─── RunOptions ───────────────────────────────────────────────────────────────

/// CLI options forwarded from `Commands::Run` to [`run_agent`] and its helpers.
///
/// Grouping the boolean flags and profile into a struct avoids an ever-growing
/// argument list as new flags are added (steps 002, 003, …).
pub struct RunOptions {
    /// When `true`, skip starting an embedded daemon; call
    /// [`daemon::harden_process`] directly instead.
    pub no_daemon: bool,

    /// When `true`, skip `airlock.toml` discovery entirely and read the sandbox
    /// root from `AIRLOCK_SANDBOX_ROOT`. All other config fields default to
    /// empty.
    pub no_config: bool,

    /// Optional built-in filesystem profile that extends the agent's sandbox
    /// read/write paths for a well-known tool.
    pub profile: Option<Profile>,

    /// Additional paths granted read-only access from the CLI `--allow-read`
    /// flag. Applied on top of config-file and profile permissions.
    pub allow_read: Vec<PathBuf>,

    /// Additional paths granted read-write access from the CLI `--allow-write`
    /// flag. Applied on top of config-file and profile permissions.
    pub allow_write: Vec<PathBuf>,

    /// Environment variable names to forward from the host to the agent,
    /// supplied via the CLI `--passthrough-env` flag. Applied on top of
    /// any `passthrough_env` list declared in `[agent]` — the two sets
    /// are additive.
    pub passthrough_env: Vec<String>,
}

// ─── run_agent ────────────────────────────────────────────────────────────────

/// Run an agent process inside an OS-level sandbox.
///
/// This is the synchronous entry point for `airlock run`. `run_agent` is
/// deliberately **not** `async` — consistent with the project invariant that
/// `main()` is synchronous. A tokio runtime is created internally.
///
/// # Arguments
///
/// * `start_dir` — Directory from which config discovery begins (typically
///   the current working directory).
/// * `config_path` — If `Some`, use this explicit path instead of discovery.
/// * `command` — The agent binary to execute.
/// * `args` — Arguments passed to the agent binary (`argv[1..]`).
/// * `opts` — CLI flags (daemon mode, config bypass, profile, relaxed bundle).
///
/// # Errors
///
/// Returns [`RunError::ConfigNotFound`] when no `airlock.toml` is present so
/// that `main.rs` can emit a user-friendly "run `airlock init`" message.
/// Returns [`RunError::SandboxRootRequired`] when `--no-config` is set but
/// `AIRLOCK_SANDBOX_ROOT` is not set in the environment.
/// Returns [`RunError::SandboxRootNotFound`] when `AIRLOCK_SANDBOX_ROOT` names
/// a path that does not exist.
/// All other errors propagate as the appropriate [`RunError`] variant.
pub fn run_agent(
    start_dir: &Path,
    config_path: Option<&Path>,
    command: &str,
    args: &[String],
    opts: RunOptions,
) -> Result<ExitCode, RunError> {
    if opts.no_daemon {
        run_no_daemon(start_dir, config_path, command, args, &opts)
    } else {
        run_with_embedded_daemon(start_dir, config_path, command, args, &opts)
    }
}

// ─── Private helpers ──────────────────────────────────────────────────────────

/// Load config from an explicit path or by discovery, mapping `NotFound` to
/// [`RunError::ConfigNotFound`] and all other errors to [`RunError::Config`].
fn load_config_for_run(
    start_dir: &Path,
    config_path: Option<&Path>,
) -> Result<crate::config::Config, RunError> {
    let result = match config_path {
        Some(p) => crate::config::load_config_from_file(p),
        None => crate::config::load_config(start_dir),
    };
    result.map_err(|e| match e {
        ConfigError::NotFound { .. } => RunError::ConfigNotFound,
        other => RunError::Config(other),
    })
}

/// Resolve the [`Config`] to use for an `airlock run` invocation.
///
/// When `no_config` is `false`, delegates to [`load_config_for_run`] using the
/// normal discovery or explicit-path logic — `AIRLOCK_SANDBOX_ROOT` is ignored.
///
/// When `no_config` is `true`, skips `airlock.toml` discovery entirely and
/// constructs a minimal [`Config`] from `AIRLOCK_SANDBOX_ROOT`:
///
/// 1. Reads `AIRLOCK_SANDBOX_ROOT` from the environment. Returns
///    [`RunError::SandboxRootRequired`] if the variable is absent or empty.
/// 2. Validates that the path exists and is a directory. Returns
///    [`RunError::SandboxRootNotFound`] if the path does not exist.
/// 3. Constructs a minimal [`Config`] with `sandbox_root` set to the
///    canonicalized path, `socket_path` and `pid_path` derived from it, and
///    all collection fields (`secrets`, `tools`, `agent`, `filesystem_read`,
///    `filesystem_write`) at their zero/empty values.
fn resolve_config(
    start_dir: &Path,
    config_path: Option<&Path>,
    no_config: bool,
) -> Result<crate::config::Config, RunError> {
    if !no_config {
        return load_config_for_run(start_dir, config_path);
    }

    // --no-config path: read sandbox root from AIRLOCK_SANDBOX_ROOT.
    let root_str = std::env::var("AIRLOCK_SANDBOX_ROOT").unwrap_or_default();
    if root_str.is_empty() {
        return Err(RunError::SandboxRootRequired);
    }

    let root = PathBuf::from(&root_str);
    if !root.is_dir() {
        return Err(RunError::SandboxRootNotFound(root));
    }

    // Canonicalize so that the sandbox policy sees a stable, symlink-free path.
    let sandbox_root =
        std::fs::canonicalize(&root).map_err(|_| RunError::SandboxRootNotFound(root))?;

    let socket_path = sandbox_root.join("airlock.sock");
    let pid_path = sandbox_root.join("airlock.pid");

    Ok(crate::config::Config {
        sandbox_root,
        socket_path,
        pid_path,
        // 300 s matches the DEFAULT_TIMEOUT_SECS constant in config.rs.
        // This field governs daemon tool-execution timeouts; with --no-daemon
        // it is unused. Keep it at the standard default for consistency.
        timeout: Duration::from_secs(300),
        filesystem_read: Vec::new(),
        filesystem_write: Vec::new(),
        secrets: HashMap::new(),
        tools: HashMap::new(),
        agent: None,
    })
}

/// `--no-daemon` flow: harden the process, load config, run the agent without
/// an embedded daemon.
fn run_no_daemon(
    start_dir: &Path,
    config_path: Option<&Path>,
    command: &str,
    args: &[String],
    opts: &RunOptions,
) -> Result<ExitCode, RunError> {
    let config = resolve_config(start_dir, config_path, opts.no_config)?;

    // Apply process hardening (disable core dumps, etc.) — the step normally
    // performed by synchronous_startup is bypassed here.
    daemon::harden_process();

    let secrets = secrets::build_secret_store(&config).map_err(RunError::Secrets)?;
    secrets::clear_secret_env_vars(&config);

    run_with_config_and_secrets(config, secrets, command, args, opts)
}

/// Embedded daemon flow: start the daemon in-process, run the agent, then
/// shut down the daemon when the agent exits.
fn run_with_embedded_daemon(
    start_dir: &Path,
    config_path: Option<&Path>,
    command: &str,
    args: &[String],
    opts: &RunOptions,
) -> Result<ExitCode, RunError> {
    match daemon::synchronous_startup(start_dir, config_path) {
        Ok(state) => {
            // Extract the clone-able fields we need for policy and env building
            // before moving `state` into the async block (which consumes it for
            // `run_embedded`). Config does not implement Clone; we clone only
            // the individual fields we need.
            let agent_config = state.config.agent.clone();
            let secrets = state.secrets.clone();

            let toolchain_paths = detect_toolchain_paths();
            let mut policy = build_agent_policy(&state.config, &toolchain_paths);
            if let Some(p) = opts.profile {
                policy.read_write_paths.extend(profile_read_write_paths(p));
            }
            // Resolve and extend CLI-supplied allow_read / allow_write paths.
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            policy.read_paths.extend(opts.allow_read.iter().map(|p| {
                if p.is_absolute() {
                    p.clone()
                } else {
                    cwd.join(p)
                }
            }));
            policy
                .read_write_paths
                .extend(opts.allow_write.iter().map(|p| {
                    if p.is_absolute() {
                        p.clone()
                    } else {
                        cwd.join(p)
                    }
                }));
            let sandbox_profile_kind = opts.profile.map(|p| p.sandbox_kind());
            let mut sandbox_profile =
                sandbox::build_platform_agent_sandbox_profile(&policy, sandbox_profile_kind)
                    .map_err(RunError::Sandbox)?;
            let env = build_agent_env(agent_config.as_ref(), &secrets, &opts.passthrough_env);
            let timeout = agent_config
                .as_ref()
                .map(|a| a.timeout)
                .unwrap_or(Duration::ZERO);

            let command = command.to_string();
            let args = args.to_vec();

            let runtime = tokio::runtime::Runtime::new().map_err(RunError::RuntimeCreation)?;
            runtime.block_on(async move {
                // Register the SIGTERM handler before the daemon task or the
                // agent exists. SIGTERM is the orchestrator's concern, not the
                // embedded daemon's: signal_loop forwards it to the agent, and
                // the daemon shuts down only once the agent has exited (via the
                // dropped cancel sender). Installing the handler up front also
                // means a SIGTERM arriving during startup is forwarded rather
                // than killing the whole process and orphaning the agent.
                let sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("SIGTERM handler should be installable");

                // Start the embedded daemon. Dropping the oneshot sender triggers
                // graceful shutdown inside run_embedded.
                let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
                let daemon_task = tokio::spawn(daemon::run_embedded(state, cancel_rx));

                // Spawn the agent child process with sandbox applied via pre_exec.
                // spawn_agent closes the Landlock fd on Linux internally.
                let (child, child_pid) = spawn_agent(&mut sandbox_profile, &command, &args, env)
                    .map_err(RunError::SpawnFailed)?;

                // Forward signals and enforce the optional timeout.
                let exit_code = signal_loop(child, child_pid, timeout, sigterm).await;

                // Tear down the embedded daemon by dropping the sender, then
                // wait for the daemon task to finish.
                drop(cancel_tx);
                match daemon_task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => eprintln!("airlock: embedded daemon error: {e}"),
                    Err(e) => eprintln!("airlock: embedded daemon task panicked: {e}"),
                }

                Ok::<ExitCode, RunError>(exit_code)
            })
        }

        Err(DaemonError::AlreadyRunning { .. }) => {
            // A *standalone* daemon — one with a PID file, started via
            // `airlock daemon start` — is already running. Its lifecycle is
            // independent of this session, so sharing it is safe: connect to
            // it and leave it running when the agent exits. This arm only ever
            // sees standalone daemons; `check_and_cleanup_stale_state` reports
            // a peer `airlock run`'s embedded daemon (no PID file) as
            // `SocketInUse`, which the catch-all arm below refuses rather than
            // shares — an embedded daemon would be torn down under us when its
            // owning session exits.
            eprintln!(
                "airlock: warning: an Airlock daemon is already running; \
                 it will not be stopped when the agent exits"
            );
            // synchronous_startup returned early (before build_secret_store /
            // clear_secret_env_vars), so we perform those steps manually here —
            // the same sequence used by the --no-daemon path.
            let config = resolve_config(start_dir, config_path, opts.no_config)?;
            let secrets = secrets::build_secret_store(&config).map_err(RunError::Secrets)?;
            secrets::clear_secret_env_vars(&config);
            run_with_config_and_secrets(config, secrets, command, args, opts)
        }

        Err(DaemonError::Config(ConfigError::NotFound { .. })) => Err(RunError::ConfigNotFound),

        Err(e) => Err(RunError::Daemon(e)),
    }
}

/// Build sandbox and env, create a runtime, spawn the agent, and run the
/// signal loop — with no embedded daemon task.
///
/// Used by both the `AlreadyRunning` fall-through and the `--no-daemon` path.
fn run_with_config_and_secrets(
    config: crate::config::Config,
    secrets: SecretStore,
    command: &str,
    args: &[String],
    opts: &RunOptions,
) -> Result<ExitCode, RunError> {
    let agent_config = config.agent.clone();

    let toolchain_paths = detect_toolchain_paths();
    let mut policy = build_agent_policy(&config, &toolchain_paths);
    if let Some(p) = opts.profile {
        policy.read_write_paths.extend(profile_read_write_paths(p));
    }
    // Resolve and extend CLI-supplied allow_read / allow_write paths.
    // Relative paths are resolved against the process working directory;
    // non-existent paths are accepted without error.
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    policy.read_paths.extend(opts.allow_read.iter().map(|p| {
        if p.is_absolute() {
            p.clone()
        } else {
            cwd.join(p)
        }
    }));
    policy
        .read_write_paths
        .extend(opts.allow_write.iter().map(|p| {
            if p.is_absolute() {
                p.clone()
            } else {
                cwd.join(p)
            }
        }));
    let sandbox_profile_kind = opts.profile.map(|p| p.sandbox_kind());
    let mut sandbox_profile =
        sandbox::build_platform_agent_sandbox_profile(&policy, sandbox_profile_kind)
            .map_err(RunError::Sandbox)?;
    let env = build_agent_env(agent_config.as_ref(), &secrets, &opts.passthrough_env);
    let timeout = agent_config
        .as_ref()
        .map(|a| a.timeout)
        .unwrap_or(Duration::ZERO);

    let command = command.to_string();
    let args = args.to_vec();

    let runtime = tokio::runtime::Runtime::new().map_err(RunError::RuntimeCreation)?;
    runtime.block_on(async move {
        // Register the SIGTERM handler before the agent is spawned so a
        // SIGTERM during startup is forwarded to the agent rather than
        // terminating the process by default action.
        let sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler should be installable");

        // spawn_agent closes the Landlock fd on Linux internally.
        let (child, child_pid) = spawn_agent(&mut sandbox_profile, &command, &args, env)
            .map_err(RunError::SpawnFailed)?;

        let exit_code = signal_loop(child, child_pid, timeout, sigterm).await;
        Ok::<ExitCode, RunError>(exit_code)
    })
}

/// Spawn the agent child process with the platform sandbox applied via
/// `pre_exec`.
///
/// Key differences from `exec::spawn`:
/// - **No `setpgid(0, 0)`**: the agent remains in the parent's process group
///   so that Ctrl+C from the terminal (SIGINT) reaches the agent directly
///   without any forwarding needed.
/// - **Stdin/stdout/stderr inherited**: the agent writes directly to the
///   user's terminal rather than through pipes.
///
/// On Linux, closes the parent's copy of the Landlock ruleset fd inside this
/// function, after `spawn()` returns successfully.
///
/// # Pre-exec invariants
///
/// The closure registered via `pre_exec` is async-signal-safe and
/// zero-alloc — no `String`, `Vec`, `Box`, `format!`, or any heap-allocating
/// call. Only raw libc syscalls and `std::io::Error::last_os_error()` are used.
// `mut` is needed on Linux for close_ruleset_fd(). Suppress the warning on
// platforms where sandbox_profile is not mutated.
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

    // Inherit the user's terminal for interactive use.
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    // NOTE: kill_on_drop is intentionally NOT set to true. See exec.rs for
    // the rationale (Child::kill() only signals the direct child PID).

    // ── Register the pre_exec closure (platform-specific) ─────────────────
    //
    // Compared to exec.rs, the only intentional omission is `setpgid(0, 0)`.
    // The agent must stay in the parent's process group so that Ctrl+C from
    // the terminal reaches the agent directly without run.rs needing to
    // intercept and re-forward SIGINT.

    #[cfg(target_os = "macos")]
    {
        let sbpl_ptr = SendSyncPtr(sandbox_profile.as_ptr());

        // SAFETY: The pre_exec closure runs between fork and exec in the child.
        // All operations are async-signal-safe with no allocation. The SBPL
        // pointer is valid because the SandboxProfile (which owns the CString)
        // lives until after Command::spawn() returns. The closure captures
        // SendSyncPtr (which is Send + Sync) rather than the raw pointer.
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

        // SAFETY: The pre_exec closure runs between fork and exec in the child.
        // All operations are async-signal-safe with no allocation. The raw fd
        // is inherited across fork and valid in the child until exec replaces
        // the process image.
        unsafe {
            cmd.pre_exec(move || {
                // Prevent the child from gaining new privileges. Required
                // before landlock_restrict_self can be called.
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // Apply the Landlock sandbox via raw syscall.
                if libc::syscall(libc::SYS_landlock_restrict_self, raw_fd, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(())
            });
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        // On unsupported platforms no sandbox is applied.
        let _ = sandbox_profile;
    }

    let mut child = cmd.spawn()?;

    // Close the parent's copy of the Landlock ruleset fd immediately after
    // spawn (Linux only). The child has already inherited and applied it.
    #[cfg(target_os = "linux")]
    sandbox_profile.close_ruleset_fd();

    let child_pid = child
        .id()
        .expect("child PID should be available immediately after spawn");

    Ok((child, child_pid))
}

/// Wait for the agent child to exit, forwarding SIGTERM/SIGHUP and enforcing
/// an optional session timeout.
///
/// The SIGTERM `Signal` is supplied by the caller rather than installed here:
/// it must be registered *before* the embedded daemon task and the agent are
/// spawned, so that a SIGTERM arriving during startup is forwarded to the
/// agent instead of terminating the process by default action. The embedded
/// daemon installs no SIGTERM handler of its own (see `daemon::run_embedded`),
/// so this is the only consumer that drives shutdown on SIGTERM.
///
/// SIGINT is **not** intercepted here — the agent is in the same process group
/// as the terminal and receives Ctrl+C directly from the kernel without any
/// forwarding needed.
///
/// If `timeout` is non-zero, send SIGTERM to the agent when it elapses, then
/// SIGKILL after a 5-second grace period if the agent has not yet exited.
async fn signal_loop(
    mut child: Child,
    child_pid: u32,
    timeout: Duration,
    mut sigterm: tokio::signal::unix::Signal,
) -> ExitCode {
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("SIGHUP handler should be installable");

    // Arm a sleep for the timeout. When timeout is zero, use a long sleep
    // that the `if use_timeout` guard prevents from ever being polled.
    let use_timeout = !timeout.is_zero();
    let timeout_sleep = tokio::time::sleep(if use_timeout {
        timeout
    } else {
        // 1 year — never fires in practice; guard disables the arm anyway.
        Duration::from_secs(365 * 24 * 3600)
    });
    tokio::pin!(timeout_sleep);

    loop {
        tokio::select! {
            result = child.wait() => {
                return match result {
                    Ok(status) => exit_status_to_code(status),
                    Err(_) => ExitCode::FAILURE,
                };
            }
            _ = sigterm.recv() => {
                // Forward SIGTERM to the agent child.
                // SAFETY: kill() is a standard POSIX syscall; child_pid is a
                // valid PID freshly returned by Child::id().
                unsafe { libc::kill(child_pid as i32, libc::SIGTERM); }
            }
            _ = sighup.recv() => {
                // Forward SIGHUP to the agent child.
                unsafe { libc::kill(child_pid as i32, libc::SIGHUP); }
            }
            _ = &mut timeout_sleep, if use_timeout => {
                // Timeout elapsed: initiate a graceful shutdown sequence.
                unsafe { libc::kill(child_pid as i32, libc::SIGTERM); }

                // Allow up to 5 seconds for the agent to exit gracefully,
                // then force-kill.
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
///
/// Normal exits use the process exit code (lower 8 bits).
/// Signal-terminated processes produce [`ExitCode::FAILURE`].
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
    use std::sync::{Arc, RwLock};

    use crate::secrets::{Health, Secret, SecretSlot};

    // Serialize env mutations across tests — env is global process state.
    // Imported from the crate-wide test_support mutex so that sibling modules
    // reading HOME (sandbox tests, etc.) serialize against our writes.
    use crate::test_support::ENV_MUTEX;

    // ── Test helpers ──────────────────────────────────────────────────────

    fn empty_secret_store() -> SecretStore {
        Arc::new(HashMap::new())
    }

    fn secret_store_with(label: &str, value: &str) -> SecretStore {
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

    // ── profile_read_write_paths tests ────────────────────────────────────

    #[test]
    fn profile_claude_returns_only_existing_paths_under_home() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let old_home = std::env::var("HOME").ok();

        // SAFETY: test-only env mutation, serialized by ENV_MUTEX.
        unsafe {
            std::env::set_var("HOME", tmp.path());
        }

        // Create ~/.claude/ and ~/.claude.json but not ~/.local/share/claude.
        std::fs::create_dir(tmp.path().join(".claude")).unwrap();
        std::fs::write(tmp.path().join(".claude.json"), "{}").unwrap();

        let paths = profile_read_write_paths(Profile::Claude);

        // Restore HOME before asserting.
        unsafe {
            match old_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let expected_claude_dir = canonical_tmp.join(".claude");
        let expected_claude_json = canonical_tmp.join(".claude.json");
        let unexpected_local_share = canonical_tmp.join(".local/share/claude");

        let canonical_paths: Vec<PathBuf> = paths
            .iter()
            .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
            .collect();

        assert!(
            canonical_paths.contains(&expected_claude_dir),
            "existing ~/.claude should be included, got: {canonical_paths:?}"
        );
        assert!(
            canonical_paths.contains(&expected_claude_json),
            "existing ~/.claude.json should be included, got: {canonical_paths:?}"
        );
        assert!(
            !canonical_paths.contains(&unexpected_local_share),
            "non-existent ~/.local/share/claude should be excluded"
        );
    }

    #[test]
    fn profile_claude_default_command_is_claude_with_dangerous_skip() {
        assert_eq!(
            Profile::Claude.default_command(),
            vec![
                "claude".to_string(),
                "--dangerously-skip-permissions".to_string(),
                "--settings".to_string(),
                r#"{"sandbox":{"enabled":false}}"#.to_string(),
            ]
        );
    }

    #[test]
    fn profile_claude_relaxed_default_command_matches_plain_claude() {
        // The relaxed variant runs the same binary with the same flags —
        // the difference lives entirely in the sandbox-side rules.
        assert_eq!(
            Profile::ClaudeRelaxed.default_command(),
            Profile::Claude.default_command(),
        );
    }

    #[test]
    fn profile_claude_relaxed_includes_library_keychains_when_present() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let old_home = std::env::var("HOME").ok();

        // SAFETY: test-only env mutation, serialized by ENV_MUTEX.
        unsafe {
            std::env::set_var("HOME", tmp.path());
        }

        std::fs::create_dir_all(tmp.path().join("Library/Keychains")).unwrap();

        let relaxed_paths = profile_read_write_paths(Profile::ClaudeRelaxed);
        let strict_paths = profile_read_write_paths(Profile::Claude);

        unsafe {
            match old_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let kc_path = canonical_tmp.join("Library/Keychains");

        let canonicalize = |paths: &[PathBuf]| -> Vec<PathBuf> {
            paths
                .iter()
                .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
                .collect()
        };

        assert!(
            canonicalize(&relaxed_paths).contains(&kc_path),
            "ClaudeRelaxed should include ~/Library/Keychains when it exists, got: {relaxed_paths:?}"
        );
        assert!(
            !canonicalize(&strict_paths).contains(&kc_path),
            "plain Claude profile must NOT include ~/Library/Keychains, got: {strict_paths:?}"
        );
    }

    #[test]
    fn profile_claude_empty_when_home_unset() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let old_home = std::env::var("HOME").ok();

        // SAFETY: test-only env mutation, serialized by ENV_MUTEX.
        unsafe {
            std::env::remove_var("HOME");
        }

        let paths = profile_read_write_paths(Profile::Claude);

        unsafe {
            if let Some(h) = old_home {
                std::env::set_var("HOME", h);
            }
        }

        assert!(
            paths.is_empty(),
            "profile should yield no paths when HOME is unset, got: {paths:?}"
        );
    }

    // ── detect_toolchain_paths tests ──────────────────────────────────────

    #[test]
    fn toolchain_detector_returns_only_existing_paths() {
        let paths = detect_toolchain_paths();
        for path in &paths {
            assert!(
                path.exists(),
                "detect_toolchain_paths returned non-existent path: {path:?}"
            );
        }
    }

    #[test]
    fn toolchain_detector_excludes_nonexistent_paths() {
        // /nix/store typically does not exist on macOS or non-Nix Linux hosts.
        // Verify: if it does not exist on this host, it must not appear in results.
        let nix_store = PathBuf::from("/nix/store");
        let paths = detect_toolchain_paths();
        if !nix_store.exists() {
            assert!(
                !paths.contains(&nix_store),
                "/nix/store should not be returned when it does not exist on this host"
            );
        }
    }

    #[test]
    fn toolchain_detector_home_unset_does_not_panic() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let old_home = std::env::var("HOME").ok();

        // SAFETY: test-only env modification, serialized by ENV_MUTEX.
        unsafe {
            std::env::remove_var("HOME");
        }

        let paths = detect_toolchain_paths();

        // Restore HOME before asserting (so other tests see it).
        if let Some(h) = old_home {
            unsafe {
                std::env::set_var("HOME", &h);
            }
        }

        // All returned paths must exist — no tilde paths should have been added.
        for path in &paths {
            assert!(
                path.exists(),
                "path {path:?} should exist on the filesystem"
            );
        }
    }

    // ── build_agent_env tests ─────────────────────────────────────────────

    #[test]
    fn agent_env_always_sets_airlock_sandbox() {
        let store = empty_secret_store();
        let env = build_agent_env(None, &store, &[]);
        assert_eq!(
            env.get("AIRLOCK_SANDBOX").map(String::as_str),
            Some("1"),
            "AIRLOCK_SANDBOX should always be set to \"1\""
        );
    }

    #[test]
    fn agent_env_includes_lang_lc_and_tz_without_passthrough_env() {
        let _guard = ENV_MUTEX.lock().unwrap();

        // Set known locale and timezone variables.
        unsafe {
            std::env::set_var("LANG", "en_US.UTF-8");
            std::env::set_var("LC_ALL", "en_US.UTF-8");
            std::env::set_var("TZ", "UTC");
        }

        let store = empty_secret_store();
        // No agent config — no passthrough_env entries.
        let env = build_agent_env(None, &store, &[]);

        let result_lang = env.get("LANG").cloned();
        let result_lc_all = env.get("LC_ALL").cloned();
        let result_tz = env.get("TZ").cloned();

        // Cleanup before asserting.
        unsafe {
            std::env::remove_var("LANG");
            std::env::remove_var("LC_ALL");
            std::env::remove_var("TZ");
        }

        assert_eq!(
            result_lang.as_deref(),
            Some("en_US.UTF-8"),
            "LANG should be included as an essential variable"
        );
        assert_eq!(
            result_lc_all.as_deref(),
            Some("en_US.UTF-8"),
            "LC_ALL should be included via LC_* scan"
        );
        assert_eq!(
            result_tz.as_deref(),
            Some("UTC"),
            "TZ should be included as an essential variable"
        );
    }

    #[test]
    fn agent_env_shell_included_even_without_passthrough() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("SHELL", "/bin/sh");
        }

        let store = empty_secret_store();
        let env = build_agent_env(None, &store, &[]);
        let result = env.get("SHELL").cloned();

        unsafe {
            std::env::remove_var("SHELL");
        }

        assert_eq!(
            result.as_deref(),
            Some("/bin/sh"),
            "SHELL should be included in agent env (independent of exec.rs ESSENTIAL_VARS)"
        );
    }

    #[test]
    fn agent_env_includes_passthrough_var_when_set_in_host() {
        let _guard = ENV_MUTEX.lock().unwrap();
        const VAR: &str = "AIRLOCK_TEST_PASSTHROUGH_12345";
        unsafe {
            std::env::set_var(VAR, "passed_through");
        }

        let agent = agent_config_with_passthrough(&[VAR]);
        let store = empty_secret_store();
        let env = build_agent_env(Some(&agent), &store, &[]);
        let result = env.get(VAR).cloned();

        unsafe {
            std::env::remove_var(VAR);
        }

        assert_eq!(
            result.as_deref(),
            Some("passed_through"),
            "passthrough var set in host env should appear in agent env"
        );
    }

    #[test]
    fn agent_env_excludes_passthrough_var_absent_from_host() {
        let _guard = ENV_MUTEX.lock().unwrap();
        const VAR: &str = "AIRLOCK_TEST_ABSENT_VAR_67890";
        unsafe {
            std::env::remove_var(VAR);
        }

        let agent = agent_config_with_passthrough(&[VAR]);
        let store = empty_secret_store();
        let env = build_agent_env(Some(&agent), &store, &[]);

        assert!(
            !env.contains_key(VAR),
            "absent passthrough var should not appear — not even as empty string"
        );
    }

    #[test]
    fn agent_env_includes_static_agent_env_entries() {
        let agent = agent_config_with_env(vec![(
            "MY_STATIC_VAR",
            EnvValue::Static("hello_world".to_string()),
        )]);
        let store = empty_secret_store();
        let env = build_agent_env(Some(&agent), &store, &[]);

        assert_eq!(
            env.get("MY_STATIC_VAR").map(String::as_str),
            Some("hello_world"),
            "static [agent.env] entry should appear in agent env"
        );
    }

    #[test]
    fn agent_env_resolves_secret_ref_from_store() {
        let store = secret_store_with("my_api_key", "s3cr3t_v@lue_xyz");

        let agent = agent_config_with_env(vec![(
            "MY_API_KEY",
            EnvValue::SecretRef("my_api_key".to_string()),
        )]);
        let env = build_agent_env(Some(&agent), &store, &[]);

        assert_eq!(
            env.get("MY_API_KEY").map(String::as_str),
            Some("s3cr3t_v@lue_xyz"),
            "SecretRef should be resolved to its value from the store"
        );
    }

    #[test]
    fn agent_env_excludes_arbitrary_host_vars_not_explicitly_allowed() {
        let _guard = ENV_MUTEX.lock().unwrap();
        const SECRET_VAR: &str = "MY_PRIVATE_CREDENTIAL_ABCDEF";
        unsafe {
            std::env::set_var(SECRET_VAR, "should_never_appear");
        }

        let store = empty_secret_store();
        // No agent config — no passthrough_env entries that name this var.
        let env = build_agent_env(None, &store, &[]);
        let result = env.contains_key(SECRET_VAR);

        unsafe {
            std::env::remove_var(SECRET_VAR);
        }

        assert!(
            !result,
            "host env var not in essentials or passthrough_env must be excluded (credential isolation)"
        );
    }

    // ── CLI passthrough_env (Layer 5) tests ───────────────────────────────

    #[test]
    fn agent_env_cli_passthrough_forwards_set_var() {
        let _guard = ENV_MUTEX.lock().unwrap();
        const VAR: &str = "AIRLOCK_TEST_CLI_PASSTHROUGH_SET_12345";
        unsafe {
            std::env::set_var(VAR, "cli_forwarded_value");
        }

        let store = empty_secret_store();
        let cli_vars = vec![VAR.to_string()];
        let env = build_agent_env(None, &store, &cli_vars);
        let result = env.get(VAR).cloned();

        unsafe {
            std::env::remove_var(VAR);
        }

        assert_eq!(
            result.as_deref(),
            Some("cli_forwarded_value"),
            "CLI-supplied passthrough var set in host env should appear in agent env"
        );
    }

    #[test]
    fn agent_env_cli_passthrough_skips_absent_var() {
        let _guard = ENV_MUTEX.lock().unwrap();
        const VAR: &str = "AIRLOCK_TEST_CLI_PASSTHROUGH_ABSENT_99999";
        unsafe {
            std::env::remove_var(VAR);
        }

        let store = empty_secret_store();
        let cli_vars = vec![VAR.to_string()];
        let env = build_agent_env(None, &store, &cli_vars);

        assert!(
            !env.contains_key(VAR),
            "CLI-supplied passthrough var absent from host must be silently skipped"
        );
    }

    #[test]
    fn agent_env_cli_passthrough_additive_with_config_passthrough() {
        let _guard = ENV_MUTEX.lock().unwrap();
        const CONFIG_VAR: &str = "AIRLOCK_TEST_CONFIG_PASSTHROUGH_VAR";
        const CLI_VAR: &str = "AIRLOCK_TEST_CLI_PASSTHROUGH_VAR";
        unsafe {
            std::env::set_var(CONFIG_VAR, "config_value");
            std::env::set_var(CLI_VAR, "cli_value");
        }

        let agent = agent_config_with_passthrough(&[CONFIG_VAR]);
        let store = empty_secret_store();
        let cli_vars = vec![CLI_VAR.to_string()];
        let env = build_agent_env(Some(&agent), &store, &cli_vars);
        let config_result = env.get(CONFIG_VAR).cloned();
        let cli_result = env.get(CLI_VAR).cloned();

        unsafe {
            std::env::remove_var(CONFIG_VAR);
            std::env::remove_var(CLI_VAR);
        }

        assert_eq!(
            config_result.as_deref(),
            Some("config_value"),
            "config-declared passthrough var should still appear when CLI passthrough is also used"
        );
        assert_eq!(
            cli_result.as_deref(),
            Some("cli_value"),
            "CLI-supplied passthrough var should appear alongside config-declared one"
        );
    }

    #[test]
    fn agent_env_cli_passthrough_works_without_agent_config() {
        let _guard = ENV_MUTEX.lock().unwrap();
        const VAR: &str = "AIRLOCK_TEST_CLI_NO_AGENT_CONFIG";
        unsafe {
            std::env::set_var(VAR, "no_config_value");
        }

        let store = empty_secret_store();
        // None agent_config simulates --no-config mode (no [agent] section).
        let cli_vars = vec![VAR.to_string()];
        let env = build_agent_env(None, &store, &cli_vars);
        let result = env.get(VAR).cloned();

        unsafe {
            std::env::remove_var(VAR);
        }

        assert_eq!(
            result.as_deref(),
            Some("no_config_value"),
            "CLI passthrough should work even when agent_config is None (--no-config mode)"
        );
    }
}
