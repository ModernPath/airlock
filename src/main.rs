//! CLI entry point for Airlock.
//!
//! Parses CLI arguments using clap subcommands and dispatches to the
//! appropriate module functions. The `main()` function is synchronous —
//! no `#[tokio::main]` attribute — because the daemon module must perform
//! fork-unsafe operations before any tokio runtime is created. Commands
//! that need async I/O create their own tokio runtime internally.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use airlock::client;
use airlock::config;
use airlock::daemon;
use airlock::run;

// ─── Version string ──────────────────────────────────────────────────────────

/// Build a version string like "0.1.0 (a1b2c3d dirty)".
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
    /// Path to an explicit config file, bypassing directory-walk discovery.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

/// Top-level subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Manage the Airlock daemon.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Execute a tool through the daemon.
    ///
    /// Everything after `--` is passed to the tool unchanged.
    Exec {
        /// The tool name and its arguments (pass after `--`).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        args: Vec<String>,
    },

    /// Check whether the daemon is running.
    Status,

    /// List configured tools and their declared secrets.
    List,

    /// Show recent daemon log entries.
    Logs,

    /// Run an AI agent inside an OS-level sandbox.
    ///
    /// Everything after `--` is the agent command and its arguments.
    Run {
        /// Do not start an embedded daemon. When set, `airlock exec` calls
        /// from within the agent will fail.
        #[arg(long)]
        no_daemon: bool,

        /// Skip `airlock.toml` discovery entirely.
        ///
        /// When set, `AIRLOCK_SANDBOX_ROOT` must be set to the path of an
        /// existing directory to use as the sandbox root. All other config
        /// fields (filesystem paths, secrets, tools) are left at their empty
        /// defaults. Use this flag when running in an arbitrary project
        /// directory that has no `airlock.toml`.
        #[arg(long)]
        no_config: bool,

        /// Built-in filesystem profile to extend the sandbox with common
        /// paths for a well-known agent (e.g. `claude`, `claude-relaxed`).
        #[arg(long, value_enum, value_name = "NAME")]
        profile: Option<run::Profile>,

        /// Grant read-only access to PATH in addition to config/profile
        /// permissions. May be specified multiple times.
        #[arg(long, value_name = "PATH", action = clap::ArgAction::Append)]
        allow_read: Vec<PathBuf>,

        /// Grant read-write access to PATH in addition to config/profile
        /// permissions. May be specified multiple times.
        #[arg(long, value_name = "PATH", action = clap::ArgAction::Append)]
        allow_write: Vec<PathBuf>,

        /// Forward the named host environment variable to the sandboxed agent.
        /// The variable is silently skipped if it is not set on the host.
        /// May be supplied multiple times.
        #[arg(long = "passthrough-env", value_name = "VAR", action = clap::ArgAction::Append)]
        passthrough_env: Vec<String>,

        /// The agent command and its arguments (pass after `--`).
        ///
        /// Optional when `--profile <NAME>` supplies a default command
        /// (e.g. `--profile claude` runs `claude --dangerously-skip-permissions`).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Create a new airlock.toml in the current directory.
    Init,
}

/// Subcommands for `airlock daemon`.
#[derive(Subcommand)]
enum DaemonAction {
    /// Start the daemon in the background (daemonize).
    Start,
    /// Run the daemon in the foreground.
    Run,
    /// Stop a running daemon.
    Stop,
    /// Stop the daemon if running, then start a new one.
    Restart,
}

// ─── Shared helpers ──────────────────────────────────────────────────────────

/// Get the current working directory, printing an error and returning
/// `ExitCode::FAILURE` if it cannot be determined.
fn current_dir_or_fail() -> Result<std::path::PathBuf, ExitCode> {
    std::env::current_dir().map_err(|e| {
        eprintln!("error: failed to determine current directory: {e}");
        ExitCode::FAILURE
    })
}

/// Create a single-use tokio runtime, printing an error and returning
/// `ExitCode::FAILURE` if creation fails.
fn tokio_runtime_or_fail() -> Result<tokio::runtime::Runtime, ExitCode> {
    tokio::runtime::Runtime::new().map_err(|e| {
        eprintln!("error: failed to create async runtime: {e}");
        ExitCode::FAILURE
    })
}

/// The result of reading a PID file and checking whether the daemon is alive.
enum PidCheckResult {
    /// The process with the given PID is alive.
    Alive(i32),
    /// A PID file exists but the process is dead (stale state).
    Stale,
    /// No PID file exists.
    NoPidFile,
}

/// Read the PID file at `pid_path`, parse its contents, and check process
/// liveness via `kill(pid, 0)`. Returns `Err(ExitCode::FAILURE)` for
/// unrecoverable errors (unreadable file, unparseable PID).
fn read_pid_and_check_liveness(pid_path: &Path) -> Result<PidCheckResult, ExitCode> {
    let pid_contents = match std::fs::read_to_string(pid_path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PidCheckResult::NoPidFile);
        }
        Err(e) => {
            eprintln!("error: failed to read PID file {}: {e}", pid_path.display());
            return Err(ExitCode::FAILURE);
        }
    };

    let pid: i32 = match pid_contents.trim().parse() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: invalid PID in {}: {e}", pid_path.display());
            return Err(ExitCode::FAILURE);
        }
    };

    let alive = unsafe { libc::kill(pid, 0) } == 0;
    if alive {
        Ok(PidCheckResult::Alive(pid))
    } else {
        Ok(PidCheckResult::Stale)
    }
}

/// Remove stale PID and socket files, ignoring errors.
fn cleanup_stale_files(pid_path: &Path, socket_path: &Path) {
    let _ = std::fs::remove_file(pid_path);
    let _ = std::fs::remove_file(socket_path);
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let cli = Cli::parse();
    let config_path = cli.config.as_deref();

    match cli.command {
        Commands::Daemon { action } => match action {
            DaemonAction::Start => cmd_daemon_start(config_path),
            DaemonAction::Run => cmd_daemon_run(config_path),
            DaemonAction::Stop => cmd_daemon_stop(config_path),
            DaemonAction::Restart => cmd_daemon_restart(config_path),
        },
        Commands::Exec { args } => cmd_exec(args, config_path),
        Commands::Status => cmd_status(config_path),
        Commands::List => cmd_list(config_path),
        Commands::Logs => cmd_logs(config_path),
        Commands::Init => cmd_init(),
        Commands::Run {
            no_daemon,
            no_config,
            profile,
            allow_read,
            allow_write,
            passthrough_env,
            args,
        } => cmd_run(
            args,
            run::RunOptions {
                no_daemon,
                no_config,
                profile,
                allow_read,
                allow_write,
                passthrough_env,
            },
            config_path,
        ),
    }
}

// ─── Command: daemon start ──────────────────────────────────────────────────

fn cmd_daemon_start(config_path: Option<&Path>) -> ExitCode {
    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };

    let state = match daemon::synchronous_startup(&cwd, config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    match daemon::daemonize(state) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ─── Command: daemon run ────────────────────────────────────────────────────

fn cmd_daemon_run(config_path: Option<&Path>) -> ExitCode {
    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };

    let state = match daemon::synchronous_startup(&cwd, config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    match daemon::run_foreground(state) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ─── Command: daemon stop ───────────────────────────────────────────────────

/// Timeout for waiting for the daemon to exit after SIGTERM.
const STOP_TIMEOUT_SECS: u64 = 10;

/// Poll interval when waiting for the daemon process to exit.
const STOP_POLL_INTERVAL_MS: u64 = 100;

fn cmd_daemon_stop(config_path: Option<&Path>) -> ExitCode {
    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };

    match stop_daemon(&cwd, config_path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

/// Stop the daemon if it is running, cleaning up stale state. Prints
/// user-visible status to stderr. Returns `Ok(())` whether the daemon was
/// running or not — only unrecoverable errors produce `Err`.
fn stop_daemon(cwd: &Path, config_path: Option<&Path>) -> Result<(), ExitCode> {
    let paths = match config_path {
        Some(p) => config::discover_paths_from_file(p),
        None => config::discover_paths(cwd),
    }
    .map_err(|e| {
        eprintln!("error: failed to discover airlock config: {e}");
        ExitCode::FAILURE
    })?;

    let pid = match read_pid_and_check_liveness(&paths.pid_path)? {
        PidCheckResult::NoPidFile => {
            eprintln!("daemon is not running");
            return Ok(());
        }
        PidCheckResult::Stale => {
            cleanup_stale_files(&paths.pid_path, &paths.socket_path);
            eprintln!("cleaned up stale PID file");
            return Ok(());
        }
        PidCheckResult::Alive(pid) => pid,
    };

    // Process is alive — send SIGTERM.
    let kill_result = unsafe { libc::kill(pid, libc::SIGTERM) };
    if kill_result != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            // Race condition: process exited between liveness check and SIGTERM.
            cleanup_stale_files(&paths.pid_path, &paths.socket_path);
            eprintln!("daemon stopped");
            return Ok(());
        }
        eprintln!("error: failed to send SIGTERM to PID {pid}: {err}");
        return Err(ExitCode::FAILURE);
    }

    // Wait for the process to exit.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(STOP_TIMEOUT_SECS);

    loop {
        std::thread::sleep(std::time::Duration::from_millis(STOP_POLL_INTERVAL_MS));

        let still_alive = unsafe { libc::kill(pid, 0) } == 0;
        if !still_alive {
            eprintln!("daemon stopped");
            return Ok(());
        }

        if std::time::Instant::now() >= deadline {
            eprintln!("daemon did not stop; PID {pid} may require manual intervention");
            return Err(ExitCode::FAILURE);
        }
    }
}

// ─── Command: daemon restart ────────────────────────────────────────────────

fn cmd_daemon_restart(config_path: Option<&Path>) -> ExitCode {
    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };

    if let Err(code) = stop_daemon(&cwd, config_path) {
        return code;
    }

    let state = match daemon::synchronous_startup(&cwd, config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    match daemon::daemonize(state) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ─── Command: exec ──────────────────────────────────────────────────────────

fn cmd_exec(args: Vec<String>, config_path: Option<&Path>) -> ExitCode {
    if args.is_empty() {
        eprintln!("error: no tool specified\n\nUsage: airlock exec -- <tool> [args...]");
        return ExitCode::FAILURE;
    }

    let tool = args[0].clone();
    let tool_args: Vec<String> = args[1..].to_vec();

    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };

    let rt = match tokio_runtime_or_fail() {
        Ok(r) => r,
        Err(code) => return code,
    };

    let result = rt.block_on(client::exec(tool, tool_args, &cwd, config_path));

    // `client::exec` may have spawned `forward_stdin`, which reads stdin via
    // `tokio::io::stdin()` on a blocking thread that `JoinHandle::abort` cannot
    // wake. If our stdin is a pipe whose write end never closes (common when
    // invoked from a non-interactive harness), the thread parks forever in
    // `read(2)` and the default `Runtime` drop waits for it. Detach instead;
    // the kernel reaps the thread when this process exits.
    rt.shutdown_background();

    match result {
        Ok(exit_code) => {
            if exit_code == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(exit_code as u8)
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ─── Command: status ────────────────────────────────────────────────────────

fn cmd_status(config_path: Option<&Path>) -> ExitCode {
    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };

    let discover_result = match config_path {
        Some(p) => config::discover_paths_from_file(p),
        None => config::discover_paths(&cwd),
    };
    let paths = match discover_result {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: failed to discover airlock config: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The socket is the ground truth for liveness: a daemon is running if and
    // only if something accepts connections on it. The PID file is only a
    // kill-handle for a standalone daemon — an embedded `airlock run` daemon
    // writes none — so it is consulted purely to enrich the output, never to
    // decide whether the daemon is up.
    if std::os::unix::net::UnixStream::connect(&paths.socket_path).is_err() {
        eprintln!("daemon is not running");
        return ExitCode::FAILURE;
    }

    // Enrich with the standalone daemon's PID when the file is present and
    // parseable. Stay silent otherwise: an embedded daemon writes no PID file,
    // and a corrupt one must not turn a healthy `status` into an error.
    match std::fs::read_to_string(&paths.pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
    {
        Some(pid) => println!("daemon is running (PID: {pid})"),
        None => println!("daemon is running"),
    }
    ExitCode::SUCCESS
}

// ─── Command: list ──────────────────────────────────────────────────────────

fn cmd_list(config_path: Option<&Path>) -> ExitCode {
    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };

    let load_result = match config_path {
        Some(p) => config::load_config_from_file(p),
        None => config::load_config(&cwd),
    };
    let cfg = match load_result {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to load airlock config: {e}");
            return ExitCode::FAILURE;
        }
    };

    if cfg.tools.is_empty() {
        println!("No tools configured.");
        return ExitCode::SUCCESS;
    }

    // Sort tool names for deterministic output.
    let mut tool_names: Vec<&String> = cfg.tools.keys().collect();
    tool_names.sort();

    for name in tool_names {
        let tool = &cfg.tools[name];
        println!("{name}");

        if let Some(desc) = &tool.description {
            println!("  {desc}");
        }

        if tool.env.is_empty() {
            println!("  (no environment)");
        } else {
            for (var, value) in &tool.env {
                match value {
                    config::EnvValue::Static(s) => println!("  {var} = {s:?}"),
                    config::EnvValue::SecretRef(label) => {
                        println!("  {var} = <secret {label:?}>")
                    }
                }
            }
        }
    }

    ExitCode::SUCCESS
}

// ─── Command: run ───────────────────────────────────────────────────────────

fn cmd_run(args: Vec<String>, opts: run::RunOptions, config_path: Option<&Path>) -> ExitCode {
    // When no command was passed after `--`, fall back to the profile's
    // default command (if any). Without both, we have nothing to run.
    let resolved_args: Vec<String> = if args.is_empty() {
        match opts.profile {
            Some(p) => p.default_command(),
            None => {
                eprintln!(
                    "error: no command specified\n\n\
                     Usage: airlock run [--profile <NAME>] -- <command> [args...]"
                );
                return ExitCode::FAILURE;
            }
        }
    } else {
        args
    };

    let command = &resolved_args[0];
    let command_args = &resolved_args[1..];

    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };

    match run::run_agent(&cwd, config_path, command, command_args, opts) {
        Ok(exit_code) => exit_code,
        Err(run::RunError::ConfigNotFound) => {
            eprintln!(
                "error: no airlock.toml found\n\nHint: run `airlock init` to create one in the current directory"
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ─── Command: init ──────────────────────────────────────────────────────────

fn cmd_init() -> ExitCode {
    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };

    let config_path = cwd.join(config::config_filename());

    if config_path.exists() {
        eprintln!(
            "error: {} already exists in {}",
            config::config_filename(),
            cwd.display()
        );
        return ExitCode::FAILURE;
    }

    match std::fs::write(&config_path, config::default_config_template()) {
        Ok(()) => {
            println!("Created {}", config_path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: failed to write {}: {e}", config_path.display());
            ExitCode::FAILURE
        }
    }
}

// ─── Command: logs ──────────────────────────────────────────────────────────

fn cmd_logs(config_path: Option<&Path>) -> ExitCode {
    let cwd = match current_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };

    let rt = match tokio_runtime_or_fail() {
        Ok(r) => r,
        Err(code) => return code,
    };

    match rt.block_on(client::logs(&cwd, config_path)) {
        Ok(exit_code) => {
            if exit_code == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
