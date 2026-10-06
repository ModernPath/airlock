//! CLI entry point for Airlock v2.
//!
//! Parses CLI arguments using clap subcommands and dispatches to the
//! appropriate module. `main()` is synchronous — no `#[tokio::main]` — the
//! daemon's own startup (`airlock daemon start`) performs fork-unsafe
//! operations that must complete before any tokio runtime exists
//! (CLAUDE.md). Commands that need async I/O create their own tokio runtime
//! internally.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};

use airlock::admin::{self, AdminError};
use airlock::daemon;
use airlock::launcher::{self, DiscoverOpts, LauncherError, PrepareOptions};
use airlock::protocol::{
    AdminRequest, DaemonMessage, DaemonMode, SandboxKind, SessionEnds, WireMode,
};
use airlock::run::{self, RunOptions};
use airlock::runtime_dir::RuntimeDir;

// ─── Version string ──────────────────────────────────────────────────────────

fn long_version() -> &'static str {
    use std::sync::LazyLock;
    static VERSION: LazyLock<String> = LazyLock::new(|| {
        let ver = env!("CARGO_PKG_VERSION");
        let hash = env!("GIT_HASH");
        let dirty = env!("GIT_DIRTY");
        if dirty == "true" {
            format!("{ver} ({hash} dirty)")
        } else {
            format!("{ver} ({hash})")
        }
    });
    &VERSION
}

// ─── CLI argument structure ──────────────────────────────────────────────────

/// Airlock — sandboxed tool execution with secret injection and output redaction.
#[derive(Parser)]
#[command(name = "airlock", version = long_version(), about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start an agent with a session, sandboxed.
    Run {
        #[arg(long, value_enum, value_name = "NAME")]
        profile: Option<run::Profile>,
        #[arg(long, value_name = "PATH", action = clap::ArgAction::Append)]
        allow_read: Vec<PathBuf>,
        #[arg(long, value_name = "PATH", action = clap::ArgAction::Append)]
        allow_write: Vec<PathBuf>,
        #[arg(long = "passthrough-env", value_name = "VAR", action = clap::ArgAction::Append)]
        passthrough_env: Vec<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        no_session: bool,
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        #[arg(long)]
        no_project_config: bool,
        #[arg(short = 'v', long)]
        verbose: bool,
        #[arg(short = 'q', long)]
        quiet: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Write a starter config.
    Init {
        #[arg(long)]
        local: bool,
        #[arg(long)]
        global: bool,
    },

    /// Review and approve project config.
    Trust {
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        #[arg(short = 'y', long)]
        yes: bool,
        #[arg(long = "expect-sha256", value_name = "HASH", action = clap::ArgAction::Append)]
        expect_sha256: Vec<String>,
    },

    /// Merged config, with the layer each part comes from.
    Config {
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        #[arg(long)]
        no_project_config: bool,
        #[arg(long)]
        paths: bool,
    },

    /// Daemon, project config and sessions.
    Status {
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        #[arg(long)]
        no_project_config: bool,
    },

    /// Run a declared tool through the session.
    ///
    /// Everything after `--` is passed to the tool unchanged.
    Exec {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        args: Vec<String>,
    },

    /// Tools a session serves.
    Tools {
        #[command(subcommand)]
        action: Option<ToolsAction>,
    },

    /// Commands run by the agent and its harness, not the user.
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },

    /// Manage sessions.
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },

    /// Manage the Airlock daemon.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
}

#[derive(Subcommand)]
enum ToolsAction {
    /// Tools a session serves.
    List {
        /// A session id, a unique id prefix or a unique name. Needs the
        /// user's terminal.
        #[arg(long, value_name = "ID")]
        session: Option<String>,
    },
}

#[derive(Subcommand)]
enum AgentAction {
    /// (agent) verify the session, self-test the sandbox.
    Check {
        #[arg(short = 'q', long)]
        quiet: bool,
    },
    /// (harness) adapts `check` and `tools list` to one harness's hook
    /// protocol.
    Hook {
        #[arg(value_enum)]
        harness: HookHarness,
        #[arg(long)]
        print_settings: bool,
    },
}

#[derive(ValueEnum, Clone, Copy)]
enum HookHarness {
    ClaudeCode,
    Text,
}

#[derive(Subcommand)]
enum SessionAction {
    /// Start an unsandboxed session for a harness with its own sandbox.
    Start {
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_name = "DURATION", default_value = "12h")]
        ttl: String,
        #[arg(long, value_enum, default_value = "sh")]
        format: ExportFormat,
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        #[arg(long)]
        no_project_config: bool,
        #[arg(short = 'q', long)]
        quiet: bool,
    },
    /// Restart a session's TTL clock.
    Renew {
        id: String,
        #[arg(long, value_name = "DURATION")]
        ttl: Option<String>,
    },
    /// Sessions on the daemon.
    List {
        #[arg(long)]
        here: bool,
    },
    /// Apply approved config to running sessions.
    Reload {
        ids: Vec<String>,
        #[arg(long)]
        all: bool,
    },
    /// End sessions.
    Revoke {
        ids: Vec<String>,
        #[arg(long)]
        here: bool,
        #[arg(long)]
        all: bool,
    },
}

#[derive(ValueEnum, Clone, Copy)]
enum ExportFormat {
    Sh,
    Fish,
    Json,
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the daemon.
    Start {
        #[arg(long)]
        foreground: bool,
        /// Started on demand by a launcher. Hidden: not for interactive use.
        #[arg(long, hide = true)]
        automatic: bool,
        /// Started by `daemon install`'s service unit. Hidden: not for
        /// interactive use.
        #[arg(long, hide = true)]
        service: bool,
    },
    /// Stop the daemon.
    Stop {
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Stop then start the daemon.
    Restart {
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Recent daemon log entries.
    Logs {
        #[arg(long, value_name = "ID")]
        session: Option<String>,
    },
    /// Install an always-on daemon service.
    Install,
    /// Remove the always-on daemon service.
    Uninstall,
}

// ─── Sandbox refusal (U16 / "Commands refused inside the sandbox") ──────────

/// `true` when this process is itself running inside an Airlock sandbox.
fn in_sandbox() -> bool {
    std::env::var("AIRLOCK_SANDBOX").as_deref() == Ok("1")
}

/// If this command is refused inside the sandbox, prints the UX message and
/// returns the exit code to use. `None` means proceed.
fn sandbox_refusal(command: &Commands) -> Option<ExitCode> {
    if !in_sandbox() {
        return None;
    }
    let message = match command {
        Commands::Run { .. } => Some(
            "`airlock run` cannot run inside an Airlock sandbox; run it from your own terminal",
        ),
        Commands::Trust { .. } => Some(
            "`airlock trust` cannot run inside an Airlock sandbox; run it from your own terminal",
        ),
        Commands::Status { .. } => Some(
            "`airlock status` needs your own terminal. Inside a session, `airlock agent check` shows this session.",
        ),
        Commands::Session { .. } => Some(
            "`airlock session` cannot run inside an Airlock sandbox; run it from your own terminal",
        ),
        Commands::Daemon { .. } => Some(
            "`airlock daemon` cannot run inside an Airlock sandbox; run it from your own terminal",
        ),
        Commands::Init { global: true, .. } => Some(
            "`airlock init --global` cannot run inside an Airlock sandbox; run it from your own terminal",
        ),
        Commands::Tools {
            action: Some(ToolsAction::List { session: Some(_) }),
        } => Some(
            "`airlock tools list --session` needs the user's terminal; run it from your own terminal",
        ),
        _ => None,
    };
    message.map(|m| {
        eprintln!("error: {m}");
        ExitCode::from(125)
    })
}

// ─── Shared helpers ──────────────────────────────────────────────────────────

fn current_dir_or_fail() -> Result<PathBuf, ExitCode> {
    std::env::current_dir().map_err(|e| {
        eprintln!("error: failed to determine current directory: {e}");
        ExitCode::from(125)
    })
}

fn tokio_runtime_or_fail() -> Result<tokio::runtime::Runtime, ExitCode> {
    tokio::runtime::Runtime::new().map_err(|e| {
        eprintln!("error: failed to create async runtime: {e}");
        ExitCode::from(125)
    })
}

/// Prints a `LauncherError`'s message, unless it is `Aborted` (the launcher
/// already printed everything the user needs to see).
fn report_launcher_error(e: &LauncherError) {
    if !matches!(e, LauncherError::Aborted) {
        eprintln!("error: {e}");
    }
}

fn discover_opts(config: Option<PathBuf>, no_project_config: bool) -> DiscoverOpts {
    DiscoverOpts {
        config,
        no_project_config,
    }
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Some(code) = sandbox_refusal(&cli.command) {
        return code;
    }

    match cli.command {
        Commands::Run {
            profile,
            allow_read,
            allow_write,
            passthrough_env,
            name,
            no_session,
            config,
            no_project_config,
            verbose,
            quiet,
            args,
        } => cmd_run(
            args,
            RunOptions {
                profile,
                allow_read,
                allow_write,
                passthrough_env,
                name,
                no_session,
                discover: discover_opts(config, no_project_config),
                verbose,
                quiet,
            },
        ),
        Commands::Init { local, global } => cmd_init(local, global),
        Commands::Trust {
            config,
            yes,
            expect_sha256,
        } => cmd_trust(config, yes, expect_sha256),
        Commands::Config { .. } => not_implemented(),
        Commands::Status { .. } => not_implemented(),
        Commands::Exec { args } => cmd_exec(args),
        Commands::Tools { action } => cmd_tools(action),
        Commands::Agent { action } => cmd_agent(action),
        Commands::Session { action } => cmd_session(action),
        Commands::Daemon { action } => cmd_daemon(action),
    }
}

/// Phase-3 commands (`config`, `status`, `agent check`, `agent hook`, `init
/// --local`/`--global`, `daemon install`/`uninstall`) get their clap
/// definitions now; phase 3 fills in their behavior in `src/agent.rs`,
/// `src/inspect.rs` and `src/service.rs`.
fn not_implemented() -> ExitCode {
    eprintln!("airlock: not implemented yet");
    ExitCode::from(125)
}

// ─── Command: run ───────────────────────────────────────────────────────────

fn cmd_run(args: Vec<String>, opts: RunOptions) -> ExitCode {
    let resolved_args: Vec<String> = if args.is_empty() {
        match opts.profile {
            Some(p) => p.default_command(),
            None => {
                eprintln!(
                    "error: no command specified\n\n\
                     Usage: airlock run [--profile <NAME>] -- <command> [args...]"
                );
                return ExitCode::from(125);
            }
        }
    } else {
        args
    };

    let command = resolved_args[0].clone();
    let command_args = resolved_args[1..].to_vec();

    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };

    match run::run_agent(&cwd, &command, &command_args, opts) {
        Ok(code) => code,
        Err(run::RunError::Aborted) => ExitCode::from(125),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(125)
        }
    }
}

// ─── Command: init ───────────────────────────────────────────────────────────

fn cmd_init(local: bool, global: bool) -> ExitCode {
    if local || global {
        return not_implemented();
    }

    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let config_path = cwd.join(airlock::config::config_filename());

    if config_path.exists() {
        eprintln!(
            "error: {} already exists in {}",
            airlock::config::config_filename(),
            cwd.display()
        );
        return ExitCode::from(125);
    }

    match std::fs::write(&config_path, airlock::config::default_config_template()) {
        Ok(()) => {
            println!("created {}", config_path.display());
            println!("edit it to declare your tools, then run `airlock run --profile claude`");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: failed to write {}: {e}", config_path.display());
            ExitCode::from(125)
        }
    }
}

// ─── Command: trust ──────────────────────────────────────────────────────────

fn cmd_trust(config: Option<PathBuf>, yes: bool, expect_sha256: Vec<String>) -> ExitCode {
    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };

    match airlock::launcher::run_trust(&cwd, config, yes, &expect_sha256) {
        Ok(()) => ExitCode::SUCCESS,
        Err(LauncherError::Aborted) => ExitCode::from(125),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(125)
        }
    }
}

// ─── Command: exec ───────────────────────────────────────────────────────────

fn cmd_exec(args: Vec<String>) -> ExitCode {
    if args.is_empty() {
        eprintln!("error: no tool specified\n\nUsage: airlock exec -- <tool> [args...]");
        return ExitCode::from(125);
    }
    let tool = args[0].clone();
    let tool_args: Vec<String> = args[1..].to_vec();

    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let canonical_cwd = std::fs::canonicalize(&cwd).unwrap_or(cwd);

    let rt = match tokio_runtime_or_fail() {
        Ok(r) => r,
        Err(code) => return code,
    };

    let code = rt.block_on(airlock::client::exec(tool, tool_args, &canonical_cwd));
    // See the v1 rationale this replaces: `forward_stdin` may park a
    // blocking thread reading real stdin that `JoinHandle::abort` cannot
    // wake. Detach rather than let the default `Runtime` drop wait for it.
    rt.shutdown_background();
    ExitCode::from(code as u8)
}

// ─── Command: tools ──────────────────────────────────────────────────────────

fn cmd_tools(action: Option<ToolsAction>) -> ExitCode {
    let session = match action {
        None => None,
        Some(ToolsAction::List { session }) => session,
    };
    if session.is_some() && in_sandbox() {
        eprintln!(
            "error: `airlock tools list --session` needs the user's terminal; run it from your own terminal"
        );
        return ExitCode::from(125);
    }
    let rt = match tokio_runtime_or_fail() {
        Ok(r) => r,
        Err(code) => return code,
    };
    let code = rt.block_on(airlock::client::tools_list(session));
    ExitCode::from(code as u8)
}

// ─── Command: agent ──────────────────────────────────────────────────────────

fn cmd_agent(action: AgentAction) -> ExitCode {
    let _ = action;
    not_implemented()
}

// ─── Command: session ────────────────────────────────────────────────────────

fn cmd_session(action: SessionAction) -> ExitCode {
    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };
    match action {
        SessionAction::Start {
            name,
            ttl,
            format,
            config,
            no_project_config,
            quiet,
        } => cmd_session_start(&cwd, name, ttl, format, config, no_project_config, quiet),
        SessionAction::Renew { id, ttl } => cmd_session_renew(id, ttl),
        SessionAction::List { here } => cmd_session_list(&cwd, here),
        SessionAction::Reload { ids, all } => cmd_session_reload(&cwd, ids, all),
        SessionAction::Revoke { ids, here, all } => cmd_session_revoke(&cwd, ids, here, all),
    }
}

fn cmd_session_start(
    cwd: &std::path::Path,
    name: Option<String>,
    ttl: String,
    format: ExportFormat,
    config: Option<PathBuf>,
    no_project_config: bool,
    quiet: bool,
) -> ExitCode {
    let ttl_secs = match launcher::parse_ttl(&ttl) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(125);
        }
    };
    let name = name.unwrap_or_else(launcher::default_session_start_name);

    let prepared = match launcher::prepare(
        cwd,
        &PrepareOptions {
            discover: discover_opts(config, no_project_config),
            verbose: false,
            quiet,
            extra_write_grants: Vec::new(),
        },
    ) {
        Ok(p) => p,
        Err(e) => {
            report_launcher_error(&e);
            return ExitCode::from(125);
        }
    };

    let (mut conn, _started_new) = match launcher::ensure_daemon(&prepared.runtime, false, quiet) {
        Ok(c) => c,
        Err(e) => {
            report_launcher_error(&e);
            return ExitCode::from(125);
        }
    };
    let admin_token = match launcher::read_admin_token(&prepared.runtime) {
        Ok(t) => t,
        Err(e) => {
            report_launcher_error(&e);
            return ExitCode::from(125);
        }
    };
    let (id, token, _ca_path) = match launcher::register(
        &mut conn,
        &admin_token,
        &prepared,
        name.clone(),
        SandboxKind::External,
        SessionEnds::Ttl { secs: ttl_secs },
    ) {
        Ok(r) => r,
        Err(e) => {
            report_launcher_error(&e);
            return ExitCode::from(125);
        }
    };

    let addr = prepared.runtime.addr();
    let session = token.expose_secret();
    match format {
        ExportFormat::Sh => {
            println!("export AIRLOCK_ADDR='{addr}'");
            println!("export AIRLOCK_SESSION='{session}'");
        }
        ExportFormat::Fish => {
            println!("set -gx AIRLOCK_ADDR '{addr}'");
            println!("set -gx AIRLOCK_SESSION '{session}'");
        }
        ExportFormat::Json => {
            println!(
                "{}",
                serde_json::json!({ "addr": addr, "session": session })
            );
        }
    }

    if !quiet {
        let expiry = if ttl_secs == 0 {
            String::new()
        } else {
            format!(", expires in {}", launcher::format_duration_short(ttl_secs))
        };
        eprintln!(
            "session {id} {name:?} for {}{expiry}",
            prepared.root.display()
        );
        eprintln!(
            "note: this harness runs in its own sandbox, or none. It must deny reads of\n      \
             {} and keep the agent away from your credential stores; see\n      \
             https://github.com/ModernPath/airlock/blob/main/SECURITY.md#external-sandboxes",
            prepared.anchors.runtime_base.display()
        );
    }

    ExitCode::SUCCESS
}

fn cmd_session_renew(id: String, ttl: Option<String>) -> ExitCode {
    let ttl_secs = match &ttl {
        Some(s) => match launcher::parse_ttl(s) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(125);
            }
        },
        None => None,
    };

    let (mut conn, token, runtime) = match connect_admin() {
        Ok(v) => v,
        Err(code) => return code,
    };

    match conn.admin_request(
        &token,
        AdminRequest::Renew {
            session: id.clone(),
            ttl_secs,
        },
    ) {
        Ok(DaemonMessage::Ok) => {}
        Ok(_) => {
            eprintln!("error: unexpected response from the daemon");
            return ExitCode::from(125);
        }
        Err(AdminError::Daemon { message, .. }) => {
            eprintln!("error: {message}");
            return ExitCode::from(125);
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(125);
        }
    }

    let _ = runtime;
    match find_session(&mut conn, &token, &id) {
        Some(info) => {
            let expiry = match info.ends {
                airlock::protocol::EndsInfo::Ttl { expires_unix } => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let remaining = expires_unix.saturating_sub(now);
                    format!(
                        ", expires in {}",
                        launcher::format_duration_short(remaining)
                    )
                }
                _ => String::new(),
            };
            println!("renewed {} {:?}{expiry}", info.id, info.name);
        }
        None => println!("renewed {id}"),
    }
    ExitCode::SUCCESS
}

fn cmd_session_list(cwd: &std::path::Path, here: bool) -> ExitCode {
    let (mut conn, token, _runtime) = match connect_admin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    let sessions = match conn.admin_request(&token, AdminRequest::ListSessions) {
        Ok(DaemonMessage::Sessions { sessions }) => sessions,
        Ok(_) => {
            eprintln!("error: unexpected response from the daemon");
            return ExitCode::from(125);
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(125);
        }
    };

    let project_root = discover_root_quietly(cwd);
    for s in &sessions {
        if here && project_root.as_deref() != Some(s.root.as_path()) {
            continue;
        }
        let ends = match &s.ends {
            airlock::protocol::EndsInfo::Lease { pid } => format!("lease (pid {pid})"),
            airlock::protocol::EndsInfo::Ttl { expires_unix } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                format!(
                    "ttl ({} left)",
                    launcher::format_duration_short(expires_unix.saturating_sub(now))
                )
            }
            airlock::protocol::EndsInfo::Never => "never".to_string(),
        };
        let changed = if layers_changed_on_disk(&s.layers) {
            " (config changed)"
        } else {
            ""
        };
        println!(
            "{}  {:<10}  {}  {} execs  {ends}{changed}",
            s.id,
            s.name,
            s.root.display(),
            s.execs
        );
    }
    ExitCode::SUCCESS
}

fn cmd_session_reload(cwd: &std::path::Path, ids: Vec<String>, all: bool) -> ExitCode {
    let (mut conn, token, _runtime) = match connect_admin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    let sessions = match conn.admin_request(&token, AdminRequest::ListSessions) {
        Ok(DaemonMessage::Sessions { sessions }) => sessions,
        Ok(_) => {
            eprintln!("error: unexpected response from the daemon");
            return ExitCode::from(125);
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(125);
        }
    };

    let project_root = discover_root_quietly(cwd);
    let targets: Vec<_> = sessions
        .into_iter()
        .filter(|s| {
            if all {
                true
            } else if !ids.is_empty() {
                ids.iter()
                    .any(|id| s.id.as_str().starts_with(id.as_str()) || &s.name == id)
            } else {
                project_root.as_deref() == Some(s.root.as_path())
            }
        })
        .collect();

    let mut exit = ExitCode::SUCCESS;
    for session in targets {
        let discover = match &session.mode {
            WireMode::Default => DiscoverOpts::default(),
            WireMode::ConfigFile { path } => DiscoverOpts {
                config: Some(path.clone()),
                no_project_config: false,
            },
            WireMode::NoProjectConfig => DiscoverOpts {
                config: None,
                no_project_config: true,
            },
        };
        let prepared = match launcher::prepare(
            &session.root,
            &PrepareOptions {
                discover,
                verbose: false,
                quiet: true,
                extra_write_grants: Vec::new(),
            },
        ) {
            Ok(p) => p,
            Err(e) => {
                report_launcher_error(&e);
                exit = ExitCode::from(125);
                continue;
            }
        };
        match launcher::reload(&mut conn, &token, session.id.as_str(), &prepared) {
            Ok((id, changes, agent_changed)) => {
                let summary = if changes.is_empty() {
                    "no changes".to_string()
                } else {
                    changes.join(", ")
                };
                println!("reloaded {id} {:?}: {summary}", session.name);
                if agent_changed {
                    println!("note: [agent] settings changed; restart the session to apply them");
                }
            }
            Err(e) => {
                report_launcher_error(&e);
                exit = ExitCode::from(125);
            }
        }
    }
    exit
}

fn cmd_session_revoke(cwd: &std::path::Path, ids: Vec<String>, here: bool, all: bool) -> ExitCode {
    let (mut conn, token, _runtime) = match connect_admin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    let sessions = match conn.admin_request(&token, AdminRequest::ListSessions) {
        Ok(DaemonMessage::Sessions { sessions }) => sessions,
        Ok(_) => {
            eprintln!("error: unexpected response from the daemon");
            return ExitCode::from(125);
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(125);
        }
    };

    let project_root = discover_root_quietly(cwd);
    let targets: Vec<_> = sessions
        .into_iter()
        .filter(|s| {
            if all {
                true
            } else if here {
                project_root.as_deref() == Some(s.root.as_path())
            } else {
                ids.iter()
                    .any(|id| s.id.as_str().starts_with(id.as_str()) || &s.name == id)
            }
        })
        .collect();

    if targets.is_empty() {
        eprintln!("error: no matching session");
        return ExitCode::from(125);
    }

    let target_ids: Vec<String> = targets.iter().map(|s| s.id.to_string()).collect();
    match conn.admin_request(
        &token,
        AdminRequest::Revoke {
            sessions: target_ids,
        },
    ) {
        Ok(DaemonMessage::Ok) => {}
        Ok(_) => {
            eprintln!("error: unexpected response from the daemon");
            return ExitCode::from(125);
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(125);
        }
    }

    for s in &targets {
        println!("ended {} {:?}", s.id, s.name);
    }
    ExitCode::SUCCESS
}

// ─── Command: daemon ─────────────────────────────────────────────────────────

fn cmd_daemon(action: DaemonAction) -> ExitCode {
    match action {
        DaemonAction::Start {
            foreground,
            automatic,
            service,
        } => {
            let mode = if service {
                DaemonMode::Service
            } else if automatic {
                DaemonMode::Automatic
            } else {
                DaemonMode::Manual
            };
            match daemon::start(mode, foreground) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(125)
                }
            }
        }
        DaemonAction::Stop { yes } => cmd_daemon_stop(yes),
        DaemonAction::Restart { yes } => {
            let stop_code = cmd_daemon_stop(yes);
            if stop_code != ExitCode::SUCCESS {
                return stop_code;
            }
            match daemon::start(DaemonMode::Manual, false) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(125)
                }
            }
        }
        DaemonAction::Logs { session } => cmd_daemon_logs(session),
        DaemonAction::Install | DaemonAction::Uninstall => not_implemented(),
    }
}

const DAEMON_STOP_TIMEOUT: Duration = Duration::from_secs(10);
const DAEMON_STOP_POLL_INTERVAL: Duration = Duration::from_millis(100);

fn cmd_daemon_stop(yes: bool) -> ExitCode {
    let runtime = match RuntimeDir::locate() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(125);
        }
    };
    let mut conn = match admin::Connection::connect(&runtime.socket_path()) {
        Ok(c) => c,
        Err(AdminError::Unreachable { .. }) => {
            eprintln!("daemon is not running");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(125);
        }
    };
    let token = match launcher::read_admin_token(&runtime) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(125);
        }
    };

    if conn.hello.sessions > 0 {
        let interactive = airlock::trust::is_interactive();
        if interactive {
            if let Ok(DaemonMessage::Sessions { sessions }) =
                conn.admin_request(&token, AdminRequest::ListSessions)
            {
                let names: Vec<String> = sessions
                    .iter()
                    .map(|s| format!("{} {:?} ({})", s.id, s.name, s.root.display()))
                    .collect();
                eprintln!(
                    "this ends {} session{}: {}",
                    conn.hello.sessions,
                    if conn.hello.sessions == 1 { "" } else { "s" },
                    names.join(", ")
                );
            }
            let approved = airlock::trust::prompt_yes_no("Stop the daemon? [y/N]").unwrap_or(false);
            if !approved {
                eprintln!("not stopped");
                return ExitCode::from(125);
            }
        } else if !yes {
            eprintln!(
                "error: the daemon has {} active session(s); pass --yes to stop it anyway",
                conn.hello.sessions
            );
            return ExitCode::from(125);
        }
    }

    let pid = conn.hello.pid;
    match conn.admin_request(&token, AdminRequest::Stop) {
        Ok(DaemonMessage::Ok) => {}
        Ok(_) => {
            eprintln!("error: unexpected response from the daemon");
            return ExitCode::from(125);
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(125);
        }
    }
    drop(conn);

    let deadline = std::time::Instant::now() + DAEMON_STOP_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if unsafe { libc::kill(pid as i32, 0) } != 0 {
            eprintln!("daemon stopped");
            return ExitCode::SUCCESS;
        }
        std::thread::sleep(DAEMON_STOP_POLL_INTERVAL);
    }
    eprintln!("daemon did not stop; PID {pid} may require manual intervention");
    ExitCode::from(125)
}

fn cmd_daemon_logs(session: Option<String>) -> ExitCode {
    let (mut conn, token, _runtime) = match connect_admin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    match conn.admin_request(&token, AdminRequest::Logs { session }) {
        Ok(DaemonMessage::LogsResponse { entries }) => {
            for entry in &entries {
                println!("{} {}", entry.timestamp, entry.message);
            }
            ExitCode::SUCCESS
        }
        Ok(_) => {
            eprintln!("error: unexpected response from the daemon");
            ExitCode::from(125)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(125)
        }
    }
}

// ─── Shared admin helpers ─────────────────────────────────────────────────────

fn connect_admin()
-> Result<(admin::Connection, airlock::protocol::AdminToken, RuntimeDir), ExitCode> {
    let runtime = RuntimeDir::locate().map_err(|e| {
        eprintln!("error: {e}");
        ExitCode::from(125)
    })?;
    let conn = admin::Connection::connect(&runtime.socket_path()).map_err(|e| {
        eprintln!("error: {e}");
        ExitCode::from(125)
    })?;
    let token = launcher::read_admin_token(&runtime).map_err(|e| {
        eprintln!("error: {e}");
        ExitCode::from(125)
    })?;
    Ok((conn, token, runtime))
}

fn find_session(
    conn: &mut admin::Connection,
    token: &airlock::protocol::AdminToken,
    id: &str,
) -> Option<airlock::protocol::SessionInfo> {
    match conn.admin_request(token, AdminRequest::ListSessions) {
        Ok(DaemonMessage::Sessions { sessions }) => sessions
            .into_iter()
            .find(|s| s.id.as_str() == id || s.id.as_str().starts_with(id) || s.name == id),
        _ => None,
    }
}

/// Best-effort project root discovery for `--here` filtering: walks up from
/// `cwd` the same way `DiscoveryMode::Default` does, but never fails — a
/// project with no config simply matches no session.
fn discover_root_quietly(cwd: &std::path::Path) -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let runtime = RuntimeDir::locate().ok()?;
    let anchors =
        airlock::anchors::resolve(&|k| std::env::var(k).ok(), &PathBuf::from(&home), &runtime);
    let loaded = airlock::layers::load_layers(
        &airlock::layers::DiscoveryMode::Default,
        cwd,
        &PathBuf::from(&home),
        &anchors.global_config,
    )
    .ok()?;
    Some(loaded.root)
}

fn layers_changed_on_disk(layers: &[airlock::protocol::WireLayer]) -> bool {
    layers.iter().any(|l| match std::fs::read(&l.path) {
        Ok(bytes) => airlock::config::sha256_hex(&bytes) != l.sha256,
        Err(_) => false,
    })
}
