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

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};

use airlock::admin::{self, AdminError};
use airlock::daemon;
use airlock::inspect;
use airlock::launcher::{self, DiscoverOpts, LauncherError, PrepareOptions};
use airlock::protocol::{
    AdminRequest, DaemonMessage, DaemonMode, EndsInfo, SandboxKind, SessionEnds, SessionInfo,
    WireMode,
};
use airlock::run::{self, RunOptions};
use airlock::runtime_dir::RuntimeDir;
use airlock::session;

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
#[command(
    name = "airlock",
    version = long_version(),
    about,
    help_template = HELP_TEMPLATE,
    arg_required_else_help = true
)]
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
        harness: airlock::agent::Harness,
        #[arg(long)]
        print_settings: bool,
    },
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
#[allow(
    clippy::disallowed_methods,
    reason = "client-side: the CLI binary checking its own environment, not daemon request-path code"
)]
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

// ─── Help grouping (U5) and sandboxed help restriction (U16) ────────────────

/// Top-level command groups, by who runs them (U5), in the order shown in
/// `airlock --help`. Each name must be a subcommand of [`Commands`].
const HELP_GROUPS: &[(&str, &[&str])] = &[
    (
        "Start an agent",
        &["run", "init", "trust", "config", "status"],
    ),
    ("Use tools", &["exec", "tools"]),
    ("Manage", &["session", "daemon"]),
    ("For the agent and its harness", &["agent"]),
];

/// Visible with `AIRLOCK_SANDBOX=1` (U16): the commands that work from
/// inside an Airlock sandbox. Everything else is hidden from `--help` and a
/// bare `airlock`, though each hidden command's own `--help` still works.
const SANDBOX_VISIBLE: &[&str] = &["exec", "tools", "agent", "init", "config"];

/// Every top-level command name in [`HELP_GROUPS`] that is not in
/// [`SANDBOX_VISIBLE`] — hidden from help under `AIRLOCK_SANDBOX=1`.
fn hidden_in_sandbox() -> impl Iterator<Item = &'static str> {
    HELP_GROUPS
        .iter()
        .flat_map(|(_, names)| names.iter().copied())
        .filter(|n| !SANDBOX_VISIBLE.contains(n))
}

/// The line a hidden command's own `--help` starts with (U16): "a hidden
/// command's own `--help` still works and starts with a line saying it
/// needs the user's terminal."
fn hidden_command_notice(name: &str) -> String {
    let why = match name {
        "status" => {
            "needs your own terminal. Inside a session, `airlock agent check` shows this session."
        }
        _ => "needs your own terminal; it cannot run inside an Airlock sandbox.",
    };
    format!("`airlock {name}` {why}\n")
}

/// Leaves out `{subcommands}`/`{options}`: [`build_after_help`] renders both
/// itself, grouped (clap has no notion of subcommand headings), so the
/// listing can differ between a normal and a sandboxed invocation (U16).
const HELP_TEMPLATE: &str = "{about-with-newline}\n{usage-heading} {usage}{after-help}";

/// One line per name in `names`, padded to the widest, with the one-line
/// description read back off `cmd` (each variant's doc comment, which clap
/// already turned into its `about`) so this can never drift from the real
/// subcommand list.
fn render_command_list(cmd: &clap::Command, names: &[&str]) -> String {
    let width = names.iter().map(|n| n.len()).max().unwrap_or(0);
    let mut out = String::new();
    for name in names {
        let about = cmd
            .find_subcommand(name)
            .and_then(|c| c.get_about())
            .map(|s| s.to_string())
            .unwrap_or_default();
        out.push_str(&format!("  {name:<width$}  {about}\n"));
    }
    out
}

/// The body `--help` prints below the usage line: the command groups (or,
/// inside the sandbox, the restricted list and which commands are hidden),
/// a static `Options:` block (every top-level flag besides the subcommand
/// is `-h`/`-V`, which clap adds itself, so this can't drift), and the
/// footer pointing a new user at `init` then `run`.
fn build_after_help(cmd: &clap::Command, sandboxed: bool) -> String {
    let mut out = String::new();
    if sandboxed {
        let hidden: Vec<&str> = hidden_in_sandbox().collect();
        out.push_str("Running inside an Airlock sandbox: only the commands below work here.\n");
        out.push_str(&format!(
            "Hidden (run these from your own terminal): {}.\n\n",
            hidden.join(", ")
        ));
        out.push_str(&render_command_list(cmd, SANDBOX_VISIBLE));
        out.push('\n');
    } else {
        for (title, names) in HELP_GROUPS {
            out.push_str(title);
            out.push_str(":\n");
            out.push_str(&render_command_list(cmd, names));
            out.push('\n');
        }
    }
    out.push_str("Options:\n  -h, --help     Print help\n  -V, --version  Print version\n\n");
    out.push_str("Start with `airlock init`, then `airlock run --profile claude`.\n");
    out
}

/// Applies the help grouping (U5) and, with `AIRLOCK_SANDBOX=1`, the help
/// restriction (U16) to a freshly built [`Cli::command`]: hides the
/// commands that need the user's own terminal and gives each a
/// `before_help` line saying so, gives `daemon --help` its lifecycle note,
/// and replaces the flat subcommand listing with the grouped one.
fn customize_help(mut cmd: clap::Command, sandboxed: bool) -> clap::Command {
    if sandboxed {
        for name in hidden_in_sandbox() {
            let notice = hidden_command_notice(name);
            cmd = cmd.mut_subcommand(name, |c| c.hide(true).before_help(notice));
        }
        // `init` itself works inside the sandbox, but `--global` needs the
        // user's own terminal (sandbox_refusal refuses it) — hide the arg
        // so a sandboxed `init --help` doesn't list a flag it then refuses.
        cmd = cmd.mut_subcommand("init", |c| c.mut_arg("global", |a| a.hide(true)));
    }
    cmd = cmd.mut_subcommand("daemon", |c| {
        c.after_help(
            "`run` and `session start` start the daemon when it is not running; a daemon \
             started that way exits after 5 minutes with no sessions.\n",
        )
    });
    let after_help = build_after_help(&cmd, sandboxed);
    cmd.after_help(after_help)
}

// ─── Shared helpers ──────────────────────────────────────────────────────────

#[allow(
    clippy::disallowed_methods,
    reason = "client-side: the CLI binary resolving its own cwd before talking to the daemon"
)]
fn current_dir_or_fail() -> Result<PathBuf, ExitCode> {
    std::env::current_dir().map_err(|e| {
        eprintln!("error: failed to determine current directory: {e}");
        ExitCode::from(125)
    })
}

#[allow(
    clippy::disallowed_methods,
    reason = "client-side: the CLI binary resolving the user's home directory, not daemon request-path code"
)]
fn home_dir_or_fail() -> Result<PathBuf, ExitCode> {
    std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        eprintln!("error: HOME is not set");
        ExitCode::from(125)
    })
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn tokio_runtime_or_fail() -> Result<tokio::runtime::Runtime, ExitCode> {
    tokio::runtime::Runtime::new().map_err(|e| {
        eprintln!("error: failed to create async runtime: {e}");
        ExitCode::from(125)
    })
}

/// The line [`eprint_error`] prints, split out so the escaping itself is
/// testable without capturing real stderr.
fn format_error_line(message: impl std::fmt::Display) -> String {
    format!(
        "error: {}",
        airlock::trust::escape_for_terminal(&message.to_string())
    )
}

/// Prints an error whose text can carry content the user running this
/// command never chose — a tool name or secret label from a project config
/// not yet trusted, or a session name echoed back by the daemon. These
/// reach the terminal before (or instead of) the trust prompt that would
/// otherwise be the user's first look at that content, so they get the
/// same escaping `airlock trust`'s review already gives it
/// ([`airlock::trust::escape_for_terminal`]) rather than going out raw.
fn eprint_error(message: impl std::fmt::Display) {
    eprintln!("{}", format_error_line(message));
}

/// Prints a `LauncherError`'s message, unless it is `Aborted` (the launcher
/// already printed everything the user needs to see).
fn report_launcher_error(e: &LauncherError) {
    if !matches!(e, LauncherError::Aborted) {
        eprint_error(e);
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
    let sandboxed = in_sandbox();
    let cmd = customize_help(Cli::command(), sandboxed);
    let matches = cmd.get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    };

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
        Commands::Config {
            config,
            no_project_config,
            paths,
        } => cmd_config(config, no_project_config, paths),
        Commands::Status {
            config,
            no_project_config,
        } => cmd_status(config, no_project_config),
        Commands::Exec { args } => cmd_exec(args),
        Commands::Tools { action } => cmd_tools(action),
        Commands::Agent { action } => cmd_agent(action),
        Commands::Session { action } => cmd_session(action),
        Commands::Daemon { action } => cmd_daemon(action),
    }
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
            eprint_error(e);
            ExitCode::from(125)
        }
    }
}

// ─── Command: init ───────────────────────────────────────────────────────────

/// `main.rs`'s own inputs for [`inspect::init_cmd`]: `cwd`/`HOME` from the
/// process, `XDG_CONFIG_HOME` for `--global`'s directory, and the real
/// `git check-ignore` for `--local`'s ignore-file note. `--global` inside
/// the sandbox is already refused by `sandbox_refusal` before this runs.
#[allow(
    clippy::disallowed_methods,
    reason = "client-side inspect wrapper: gathers the CLI's own cwd/HOME/XDG_CONFIG_HOME to hand to inspect::init_cmd"
)]
fn cmd_init(local: bool, global: bool) -> ExitCode {
    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let home = match home_dir_or_fail() {
        Ok(h) => h,
        Err(code) => return code,
    };
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let kind = if global {
        inspect::InitKind::Global
    } else if local {
        inspect::InitKind::Local
    } else {
        inspect::InitKind::Plain
    };
    let mut stdout = std::io::stdout();
    inspect::init_cmd(
        kind,
        &cwd,
        &home,
        xdg_config_home.as_deref(),
        &inspect::RealGitRunner,
        &mut stdout,
    )
}

// ─── Command: config ─────────────────────────────────────────────────────────

/// `airlock config [--config] [--no-project-config] [--paths]`: gathers the
/// real `cwd`, `HOME`, anchors (`anchors::resolve` over the real
/// environment) and runtime dir, then hands them to [`inspect::config_cmd`],
/// which does the actual file reading and rendering.
#[allow(
    clippy::disallowed_methods,
    reason = "client-side inspect wrapper: resolves anchors from the CLI's own environment to hand to inspect::config_cmd"
)]
fn cmd_config(config: Option<PathBuf>, no_project_config: bool, paths: bool) -> ExitCode {
    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let home = match home_dir_or_fail() {
        Ok(h) => h,
        Err(code) => return code,
    };
    let runtime = match RuntimeDir::locate() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(125);
        }
    };
    let anchors = airlock::anchors::resolve(&|k| std::env::var(k).ok(), &home, &runtime);

    let opts = inspect::ConfigOptions {
        config,
        no_project_config,
        paths,
    };
    let paths_report = inspect::ConfigPaths {
        global_config: anchors.global_config.clone(),
        trust_store: anchors.trust_store.clone(),
        runtime_dir: runtime.base().to_path_buf(),
        socket: runtime.socket_path(),
        tool_state_base: anchors.tool_state_base.clone(),
    };

    let mut stdout = std::io::stdout();
    inspect::config_cmd(
        &opts,
        &cwd,
        &home,
        &anchors.global_config,
        &anchors.tool_state_base,
        &paths_report,
        in_sandbox(),
        &mut stdout,
    )
}

// ─── Command: status ─────────────────────────────────────────────────────────

/// Reads the daemon's admin family (`Hello`, then `ListSessions`) for
/// [`inspect::status_cmd`]'s [`inspect::DaemonProbe`]. The daemon's `Hello`
/// carries no start time, so an automatic daemon's age is read off the
/// runtime dir's PID file mtime instead — written once, at startup, by the
/// same process `Hello.pid` names.
struct AdminProbe {
    runtime: RuntimeDir,
    conn: Option<admin::Connection>,
    token: Option<airlock::protocol::AdminToken>,
}

impl AdminProbe {
    fn new(runtime: RuntimeDir) -> Self {
        Self {
            runtime,
            conn: None,
            token: None,
        }
    }
}

fn pid_file_started_unix(pid_path: &std::path::Path) -> Option<u64> {
    std::fs::metadata(pid_path)
        .and_then(|m| m.modified())
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

impl inspect::DaemonProbe for AdminProbe {
    fn hello(&mut self) -> Option<inspect::DaemonStatus> {
        let conn = admin::Connection::connect(&self.runtime.socket_path()).ok()?;
        let started_unix = (conn.hello.mode == DaemonMode::Automatic)
            .then(|| pid_file_started_unix(&self.runtime.pid_path()))
            .flatten();
        let status = inspect::DaemonStatus {
            pid: conn.hello.pid,
            version: conn.hello.version.clone(),
            mode: conn.hello.mode,
            started_unix,
            addr: self.runtime.addr(),
        };
        self.token = launcher::read_admin_token(&self.runtime).ok();
        self.conn = Some(conn);
        Some(status)
    }

    fn list_sessions(&mut self) -> Vec<SessionInfo> {
        let (Some(conn), Some(token)) = (self.conn.as_mut(), self.token.as_ref()) else {
            return Vec::new();
        };
        match conn.admin_request(token, AdminRequest::ListSessions) {
            Ok(DaemonMessage::Sessions { sessions }) => sessions,
            _ => Vec::new(),
        }
    }
}

/// `airlock status [--config] [--no-project-config]`. Refused inside the
/// sandbox before this runs (`sandbox_refusal`, with a hint to `agent
/// check`).
#[allow(
    clippy::disallowed_methods,
    reason = "client-side inspect wrapper: resolves anchors from the CLI's own environment to hand to inspect::status_cmd"
)]
fn cmd_status(config: Option<PathBuf>, no_project_config: bool) -> ExitCode {
    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let home = match home_dir_or_fail() {
        Ok(h) => h,
        Err(code) => return code,
    };
    let runtime = match RuntimeDir::locate() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(125);
        }
    };
    let anchors = airlock::anchors::resolve(&|k| std::env::var(k).ok(), &home, &runtime);

    let opts = inspect::StatusOptions {
        config,
        no_project_config,
    };
    let mut probe = AdminProbe::new(runtime);
    let mut stdout = std::io::stdout();
    inspect::status_cmd(
        &opts,
        &cwd,
        &home,
        &anchors.global_config,
        &anchors.trust_store,
        &mut probe,
        now_unix(),
        &mut stdout,
    )
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
            eprint_error(e);
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
    match action {
        AgentAction::Check { quiet } => airlock::agent::check_cmd(quiet),
        AgentAction::Hook {
            harness,
            print_settings,
        } => airlock::agent::hook_cmd(harness, print_settings),
    }
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
            eprint_error(message);
            return ExitCode::from(125);
        }
        Err(e) => {
            eprint_error(e);
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

/// What ends a session, per "Options" in `docs/airlock-v2-ux.md`
/// (`session list`'s "what ends it" column): `"held by airlock run, PID
/// 4821"`, `"expires in 6h"`, or `"never expires"`.
fn ends_text(ends: &EndsInfo, now: u64) -> String {
    match ends {
        EndsInfo::Lease { pid } => format!("held by airlock run, PID {pid}"),
        EndsInfo::Ttl { expires_unix } => format!(
            "expires in {}",
            launcher::format_duration_short(expires_unix.saturating_sub(now))
        ),
        EndsInfo::Never => "never expires".to_string(),
    }
}

fn cmd_session_list(cwd: &std::path::Path, here: bool) -> ExitCode {
    let home = match home_dir_or_fail() {
        Ok(h) => h,
        Err(code) => return code,
    };
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
            eprint_error(e);
            return ExitCode::from(125);
        }
    };

    let project_root = discover_root_quietly(cwd);
    let now = now_unix();
    let rows: Vec<Vec<String>> = sessions
        .iter()
        .filter(|s| !here || project_root.as_deref() == Some(s.root.as_path()))
        .map(|s| {
            vec![
                s.id.to_string(),
                s.name.clone(),
                inspect::display_path(&s.root, &home),
                inspect::format_hhmm_local(s.started_unix),
                format!("{} execs", s.execs),
                ends_text(&s.ends, now),
                if layers_changed_on_disk(&s.layers) {
                    "config changed".to_string()
                } else {
                    String::new()
                },
            ]
        })
        .collect();
    print!("{}", inspect::table(&rows));
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
            eprint_error(e);
            return ExitCode::from(125);
        }
    };

    let project_root = discover_root_quietly(cwd);
    let targets: Vec<SessionInfo> = if all {
        sessions
    } else if !ids.is_empty() {
        // Resolve each ref exactly once, by the same rule the daemon's own
        // handlers use (exact id, unique id prefix, or unique name) — never
        // silently reload every session an ambiguous ref happens to match.
        let mut resolved = Vec::with_capacity(ids.len());
        for id in &ids {
            match session::resolve_session_ref(id, &sessions) {
                Ok(info) => resolved.push(info.clone()),
                Err(msg) => {
                    eprint_error(msg);
                    return ExitCode::from(125);
                }
            }
        }
        resolved
    } else {
        sessions
            .into_iter()
            .filter(|s| project_root.as_deref() == Some(s.root.as_path()))
            .collect()
    };

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
                    println!("note: agent settings changed; restart the agent to apply them");
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
            eprint_error(e);
            return ExitCode::from(125);
        }
    };

    // Refs resolve by the daemon's rule (exact id, unique id prefix, unique
    // name), so an ambiguous ref is refused instead of ending every session
    // it matches. Resolving here also gives the id and name to report.
    let targets: Vec<&SessionInfo> = if all || here {
        let project_root = discover_root_quietly(cwd);
        sessions
            .iter()
            .filter(|s| all || project_root.as_deref() == Some(s.root.as_path()))
            .collect()
    } else {
        let mut resolved = Vec::new();
        for id in &ids {
            match airlock::session::resolve_session_ref(id, &sessions) {
                Ok(s) => resolved.push(s),
                Err(message) => {
                    eprint_error(message);
                    return ExitCode::from(125);
                }
            }
        }
        resolved
    };

    if targets.is_empty() {
        eprintln!("error: no matching session");
        return ExitCode::from(125);
    }

    match conn.admin_request(
        &token,
        AdminRequest::Revoke {
            sessions: targets.iter().map(|s| s.id.to_string()).collect(),
        },
    ) {
        Ok(DaemonMessage::Ok) => {}
        Ok(DaemonMessage::Error { kind, message }) => {
            eprint_error(message);
            return ExitCode::from(kind.exit_code());
        }
        Ok(_) => {
            eprintln!("error: unexpected response from the daemon");
            return ExitCode::from(125);
        }
        Err(e) => {
            eprint_error(e);
            return ExitCode::from(125);
        }
    }

    for s in &targets {
        println!("ended {} {:?}", s.id, s.name);
    }
    ExitCode::SUCCESS
}

// ─── Command: daemon ─────────────────────────────────────────────────────────

fn report_daemon_start_result(result: Result<(), daemon::DaemonError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(daemon::DaemonError::StartInProgress) => {
            eprintln!("note: another process is already starting or running the daemon");
            ExitCode::from(daemon::START_IN_PROGRESS_EXIT_CODE)
        }
        Err(e) => {
            eprint_error(e);
            ExitCode::from(125)
        }
    }
}

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
            report_daemon_start_result(daemon::start(mode, foreground))
        }
        DaemonAction::Stop { yes } => cmd_daemon_stop(yes),
        DaemonAction::Restart { yes } => {
            let stop_code = cmd_daemon_stop(yes);
            if stop_code != ExitCode::SUCCESS {
                return stop_code;
            }
            report_daemon_start_result(daemon::start(DaemonMode::Manual, false))
        }
        DaemonAction::Logs { session } => cmd_daemon_logs(session),
        DaemonAction::Install => cmd_daemon_install(),
        DaemonAction::Uninstall => airlock::service::uninstall_cmd(),
    }
}

/// Probes the socket (`docs/airlock-v2-design.md`'s "Commands refused..."
/// wording aside, this is the one place `daemon install` needs to know
/// whether a daemon is already up, per `install_cmd`'s doc comment) and
/// hands the result to [`airlock::service::install_cmd`].
fn cmd_daemon_install() -> ExitCode {
    let daemon_running = RuntimeDir::locate()
        .map(|runtime| admin::Connection::connect(&runtime.socket_path()).is_ok())
        .unwrap_or(false);
    airlock::service::install_cmd(daemon_running)
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
            eprint_error(e);
            return ExitCode::from(125);
        }
    };
    let token = match launcher::read_admin_token(&runtime) {
        Ok(t) => t,
        Err(e) => {
            eprint_error(e);
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
            eprint_error(e);
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
            eprint_error(e);
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
        eprint_error(e);
        ExitCode::from(125)
    })?;
    let token = launcher::read_admin_token(&runtime).map_err(|e| {
        eprint_error(e);
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
#[allow(
    clippy::disallowed_methods,
    reason = "client-side: the CLI binary resolving its own HOME/anchors for best-effort `--here` filtering"
)]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A `ConfigError`/`LauncherError`/`AdminError`'s text can echo a tool
    /// name, secret label or session name the user hasn't trusted yet; the
    /// terminal must not run it. `escape_for_terminal` keeps newlines (an
    /// error is allowed to span lines) but neutralizes a control sequence.
    #[test]
    fn format_error_line_escapes_terminal_hostile_text() {
        let line = format_error_line(format!(
            "invalid tool name {:?}: tool names may only contain ASCII letters, digits, '.', '_', '+' and '-'",
            "tool\u{1b}[31mname"
        ));
        assert!(!line.contains('\u{1b}'), "{line:?}");
        assert!(line.starts_with("error: "), "{line:?}");
    }

    #[test]
    fn format_error_line_keeps_newlines() {
        let line = format_error_line("first line\nsecond line");
        assert_eq!(line, "error: first line\nsecond line");
    }
}
