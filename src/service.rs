//! `airlock daemon install` / `airlock daemon uninstall`: registering the
//! always-on daemon with the platform's service manager (a launchd agent on
//! macOS, a systemd user unit on Linux).
//!
//! The daemon itself does not care which lifecycle started it — automatic,
//! service or manual all run the same binary with the same `Register`
//! protocol (see [Lifecycle](../docs/airlock-v2-design.md#lifecycle)). This
//! module only writes the service manager's definition file and tells it to
//! load or unload it.
//!
//! [`install`] and [`uninstall`] take every input explicitly (the exe path,
//! `HOME`, uid, `XDG_CONFIG_HOME`, whether a daemon currently answers) and a
//! [`CommandRunner`] to issue `launchctl`/`systemctl` through, so they run
//! hermetically under test: nothing here reads the process environment or
//! shells out except through the trait. Only [`install_cmd`] and
//! [`uninstall_cmd`] — the real entry points `main.rs` wires up — gather
//! those inputs from the process.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use thiserror::Error;

/// The launchd label / systemd unit name, shared by both platforms' file
/// names and `launchctl`/`systemctl` targets.
#[cfg(target_os = "macos")]
const SERVICE_NAME: &str = "ai.modernpath.airlock";
#[cfg(target_os = "linux")]
const SYSTEMD_UNIT: &str = "airlock.service";

// ─── Command runner ─────────────────────────────────────────────────────────

/// Abstracts shelling out to the platform's service manager, so tests never
/// touch the user's real `launchctl`/`systemctl` state.
pub trait CommandRunner {
    /// Runs `program` with `args` to completion. `Err` on a nonzero exit, a
    /// signal, or a failure to spawn.
    fn run(&self, program: &str, args: &[&str]) -> Result<(), ServiceError>;
}

/// The real runner, used by [`install_cmd`] / [`uninstall_cmd`].
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<(), ServiceError> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|source| ServiceError::Spawn {
                program: program.to_string(),
                source,
            })?;

        if output.status.success() {
            return Ok(());
        }
        Err(ServiceError::CommandFailed {
            program: program.to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr)
                .trim_end()
                .to_string(),
        })
    }
}

// ─── Errors ─────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },

    #[error("could not run {program}: {source}")]
    Spawn { program: String, source: io::Error },

    #[error(
        "{program} {} failed{}: {stderr}",
        args.join(" "),
        status.map(|c| format!(" (exit {c})")).unwrap_or_default()
    )]
    CommandFailed {
        program: String,
        args: Vec<String>,
        status: Option<i32>,
        stderr: String,
    },

    #[error("HOME is not set")]
    NoHome,

    #[error("could not determine the current executable: {0}")]
    CurrentExe(io::Error),

    #[error("`airlock daemon install`/`uninstall` is not supported on this platform")]
    UnsupportedPlatform,
}

fn io_err(path: &Path, source: io::Error) -> ServiceError {
    ServiceError::Io {
        path: path.to_path_buf(),
        source,
    }
}

// ─── Shared report types ───────────────────────────────────────────────────

/// What [`install`] actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// The definition file already matched; nothing was written or reloaded.
    AlreadyInstalled,
    /// No definition file existed yet; it was written and loaded.
    Fresh,
    /// A definition file existed with different content; it was rewritten
    /// and reloaded.
    Reinstalled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    /// The definition file that was written (or already matched).
    pub unit_path: PathBuf,
    pub outcome: InstallOutcome,
    /// Set when `exe` looks like a build or temp path that will not survive.
    pub exe_warning: Option<String>,
    /// Set when `daemon_running` was true: the install does not stop it.
    pub daemon_running_note: Option<String>,
    /// Linux only: the `loginctl enable-linger` reminder.
    pub linger_note: Option<String>,
}

/// What [`uninstall`] actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UninstallOutcome {
    /// No definition file existed; nothing to do.
    NotInstalled,
    /// The definition file was unloaded and removed.
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallReport {
    pub unit_path: PathBuf,
    pub outcome: UninstallOutcome,
}

/// Renders `path` with a leading `home` replaced by `~`, the way every UX
/// example in the docs shows it.
fn display_path(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) if !rest.as_os_str().is_empty() => format!("~/{}", rest.display()),
        _ => path.display().to_string(),
    }
}

/// True when `exe` sits somewhere that will not outlive this invocation: a
/// Cargo build directory, or a system temp directory. A service definition
/// written for such a path keeps pointing at it after the build is cleaned
/// or the temp directory is swept.
fn looks_unstable(exe: &Path) -> bool {
    let components: Vec<&str> = exe
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();

    let under_cargo_target = components
        .windows(2)
        .any(|w| w[0] == "target" && matches!(w[1], "debug" | "release"));

    // macOS temp dirs resolve under /private/var/folders/...; /tmp itself is
    // a symlink there, but the unresolved path is what a shell or build
    // script hands us, so both are checked.
    let under_tmp = exe.starts_with("/tmp")
        || exe.starts_with("/private/tmp")
        || exe.starts_with("/private/var/folders")
        || exe.starts_with("/var/folders");

    under_cargo_target || under_tmp
}

fn exe_warning(exe: &Path) -> Option<String> {
    if looks_unstable(exe) {
        Some(format!(
            "{} looks like a build or temporary path; the installed service will keep pointing at it",
            exe.display()
        ))
    } else {
        None
    }
}

fn daemon_running_note(daemon_running: bool) -> Option<String> {
    daemon_running.then(|| {
        "a daemon started on demand is running; `airlock daemon restart` replaces it with the service".to_string()
    })
}

// ─── Public entry points ───────────────────────────────────────────────────

/// Installs the service definition for `exe`, idempotently.
///
/// `xdg_config_home` is consulted on Linux only (`$XDG_CONFIG_HOME/systemd/user`),
/// and ignored on macOS. `daemon_running` is whatever the caller already
/// learned by probing the socket; this function never stops that daemon
/// itself (see the open question in `docs/airlock-v2-ux.md`, resolved as:
/// tell the user to run `airlock daemon restart`).
pub fn install(
    exe: &Path,
    home: &Path,
    uid: u32,
    xdg_config_home: Option<&Path>,
    daemon_running: bool,
    runner: &dyn CommandRunner,
) -> Result<InstallReport, ServiceError> {
    #[cfg(target_os = "macos")]
    {
        let _ = xdg_config_home;
        macos::install(exe, home, uid, daemon_running, runner)
    }
    #[cfg(target_os = "linux")]
    {
        linux::install(exe, home, uid, xdg_config_home, daemon_running, runner)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (exe, home, uid, xdg_config_home, daemon_running, runner);
        Err(ServiceError::UnsupportedPlatform)
    }
}

/// Removes the service definition, if any.
pub fn uninstall(
    home: &Path,
    uid: u32,
    xdg_config_home: Option<&Path>,
    runner: &dyn CommandRunner,
) -> Result<UninstallReport, ServiceError> {
    #[cfg(target_os = "macos")]
    {
        let _ = xdg_config_home;
        macos::uninstall(home, uid, runner)
    }
    #[cfg(target_os = "linux")]
    {
        let _ = uid;
        linux::uninstall(home, xdg_config_home, runner)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (home, uid, xdg_config_home, runner);
        Err(ServiceError::UnsupportedPlatform)
    }
}

/// Formats the lines [`install_cmd`] prints: the ones that always appear, in
/// order, then the ones that only appear as warnings/notes.
fn install_messages(report: &InstallReport, home: &Path) -> Vec<String> {
    let mut lines = Vec::new();
    match report.outcome {
        InstallOutcome::AlreadyInstalled => lines.push("already installed".to_string()),
        InstallOutcome::Fresh | InstallOutcome::Reinstalled => {
            lines.push(format!("wrote {}", display_path(&report.unit_path, home)));
            lines.extend(platform_load_messages(report.outcome));
        }
    }
    if let Some(note) = &report.linger_note {
        lines.push(note.clone());
    }
    if let Some(note) = &report.exe_warning {
        lines.push(format!("warning: {note}"));
    }
    if let Some(note) = &report.daemon_running_note {
        lines.push(note.clone());
    }
    lines
}

#[cfg(target_os = "macos")]
fn platform_load_messages(outcome: InstallOutcome) -> Vec<String> {
    let verb = match outcome {
        InstallOutcome::Reinstalled => "reloaded",
        _ => "loaded",
    };
    vec![format!(
        "{verb} it: the daemon now starts at login and keeps running without sessions"
    )]
}

#[cfg(target_os = "linux")]
fn platform_load_messages(outcome: InstallOutcome) -> Vec<String> {
    match outcome {
        InstallOutcome::Reinstalled => vec![format!("restarted {SYSTEMD_UNIT}")],
        _ => vec![format!("enabled and started {SYSTEMD_UNIT}")],
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn platform_load_messages(_outcome: InstallOutcome) -> Vec<String> {
    Vec::new()
}

fn uninstall_messages(report: &UninstallReport, home: &Path) -> Vec<String> {
    match report.outcome {
        UninstallOutcome::NotInstalled => vec!["not installed".to_string()],
        UninstallOutcome::Removed => {
            vec![format!("removed {}", display_path(&report.unit_path, home))]
        }
    }
}

/// Gathers the real inputs (current exe, `HOME`, euid, `XDG_CONFIG_HOME`) and
/// whether a daemon currently answers, installs the service, and prints the
/// UX messages. Returns the process exit code: 0 on success, 125 on failure.
#[allow(
    clippy::disallowed_methods,
    reason = "launcher-side: runs in the user's terminal"
)]
pub fn install_cmd(daemon_running: bool) -> ExitCode {
    let exe = match std::env::current_exe().and_then(|p| p.canonicalize()) {
        Ok(exe) => exe,
        Err(source) => {
            eprintln!("airlock: {}", ServiceError::CurrentExe(source));
            return ExitCode::from(125);
        }
    };
    let home = match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home),
        None => {
            eprintln!("airlock: {}", ServiceError::NoHome);
            return ExitCode::from(125);
        }
    };
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let uid = unsafe { libc::geteuid() };

    match install(
        &exe,
        &home,
        uid,
        xdg_config_home.as_deref(),
        daemon_running,
        &RealCommandRunner,
    ) {
        Ok(report) => {
            for line in install_messages(&report, &home) {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("airlock: {e}");
            ExitCode::from(125)
        }
    }
}

/// Gathers the real inputs and removes the service, printing the UX
/// messages. Returns 0 whether or not it was installed, 125 on failure.
#[allow(
    clippy::disallowed_methods,
    reason = "launcher-side: runs in the user's terminal"
)]
pub fn uninstall_cmd() -> ExitCode {
    let home = match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home),
        None => {
            eprintln!("airlock: {}", ServiceError::NoHome);
            return ExitCode::from(125);
        }
    };
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let uid = unsafe { libc::geteuid() };

    match uninstall(&home, uid, xdg_config_home.as_deref(), &RealCommandRunner) {
        Ok(report) => {
            for line in uninstall_messages(&report, &home) {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("airlock: {e}");
            ExitCode::from(125)
        }
    }
}

// ─── XML / systemd escaping ─────────────────────────────────────────────────

fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// systemd unit files treat `%` as the start of a specifier; a literal `%`
/// in a path must be doubled.
#[cfg(target_os = "linux")]
fn escape_systemd(s: &str) -> String {
    s.replace('%', "%%")
}

// ─── macOS: launchd ─────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    fn plist_path(home: &Path) -> PathBuf {
        home.join("Library/LaunchAgents")
            .join(format!("{SERVICE_NAME}.plist"))
    }

    fn log_path(home: &Path) -> PathBuf {
        home.join("Library/Logs/airlock/daemon.log")
    }

    fn render_plist(exe: &Path, home: &Path) -> String {
        let exe = escape_xml(&exe.display().to_string());
        let log = escape_xml(&log_path(home).display().to_string());
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
             \t<key>Label</key>\n\
             \t<string>{SERVICE_NAME}</string>\n\
             \t<key>ProgramArguments</key>\n\
             \t<array>\n\
             \t\t<string>{exe}</string>\n\
             \t\t<string>daemon</string>\n\
             \t\t<string>start</string>\n\
             \t\t<string>--foreground</string>\n\
             \t\t<string>--service</string>\n\
             \t</array>\n\
             \t<key>RunAtLoad</key>\n\
             \t<true/>\n\
             \t<key>KeepAlive</key>\n\
             \t<true/>\n\
             \t<key>StandardErrorPath</key>\n\
             \t<string>{log}</string>\n\
             \t<key>ProcessType</key>\n\
             \t<string>Background</string>\n\
             </dict>\n\
             </plist>\n"
        )
    }

    fn gui_target(uid: u32) -> String {
        format!("gui/{uid}")
    }

    fn gui_service_target(uid: u32) -> String {
        format!("gui/{uid}/{SERVICE_NAME}")
    }

    pub fn install(
        exe: &Path,
        home: &Path,
        uid: u32,
        daemon_running: bool,
        runner: &dyn CommandRunner,
    ) -> Result<InstallReport, ServiceError> {
        let path = plist_path(home);
        let content = render_plist(exe, home);
        let existing = read_existing(&path)?;

        let outcome = match existing {
            Some(current) if current == content => InstallOutcome::AlreadyInstalled,
            Some(_) => {
                write_file(&path, &content)?;
                // The label is already bootstrapped under the old
                // definition; bootstrap refuses a label that is already
                // loaded, so it must be unloaded first.
                runner.run("launchctl", &["bootout", &gui_service_target(uid)])?;
                runner.run(
                    "launchctl",
                    &["bootstrap", &gui_target(uid), path_str(&path)],
                )?;
                InstallOutcome::Reinstalled
            }
            None => {
                write_file(&path, &content)?;
                runner.run(
                    "launchctl",
                    &["bootstrap", &gui_target(uid), path_str(&path)],
                )?;
                InstallOutcome::Fresh
            }
        };

        Ok(InstallReport {
            unit_path: path,
            outcome,
            exe_warning: exe_warning(exe),
            daemon_running_note: daemon_running_note(daemon_running),
            linger_note: None,
        })
    }

    pub fn uninstall(
        home: &Path,
        uid: u32,
        runner: &dyn CommandRunner,
    ) -> Result<UninstallReport, ServiceError> {
        let path = plist_path(home);
        if read_existing(&path)?.is_none() {
            return Ok(UninstallReport {
                unit_path: path,
                outcome: UninstallOutcome::NotInstalled,
            });
        }

        runner.run("launchctl", &["bootout", &gui_service_target(uid)])?;
        remove_file(&path)?;

        Ok(UninstallReport {
            unit_path: path,
            outcome: UninstallOutcome::Removed,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::service::test_support::RecordingRunner;

        fn home() -> tempfile::TempDir {
            tempfile::tempdir().expect("tempdir")
        }

        #[test]
        fn plist_content_is_exact() {
            let home = home();
            let plist = render_plist(Path::new("/usr/local/bin/airlock"), home.path());
            let expected = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                 <plist version=\"1.0\">\n\
                 <dict>\n\
                 \t<key>Label</key>\n\
                 \t<string>ai.modernpath.airlock</string>\n\
                 \t<key>ProgramArguments</key>\n\
                 \t<array>\n\
                 \t\t<string>/usr/local/bin/airlock</string>\n\
                 \t\t<string>daemon</string>\n\
                 \t\t<string>start</string>\n\
                 \t\t<string>--foreground</string>\n\
                 \t\t<string>--service</string>\n\
                 \t</array>\n\
                 \t<key>RunAtLoad</key>\n\
                 \t<true/>\n\
                 \t<key>KeepAlive</key>\n\
                 \t<true/>\n\
                 \t<key>StandardErrorPath</key>\n\
                 \t<string>{}/Library/Logs/airlock/daemon.log</string>\n\
                 \t<key>ProcessType</key>\n\
                 \t<string>Background</string>\n\
                 </dict>\n\
                 </plist>\n",
                home.path().display()
            );
            assert_eq!(plist, expected);
        }

        #[test]
        fn plist_escapes_xml_special_characters_in_exe_path() {
            let home = home();
            let plist = render_plist(Path::new("/opt/a&b<c>d\"e'f"), home.path());
            assert!(plist.contains("<string>/opt/a&amp;b&lt;c&gt;d&quot;e&apos;f</string>"));
        }

        #[test]
        fn fresh_install_writes_file_and_bootstraps() {
            let home = home();
            let runner = RecordingRunner::default();
            let report = install(
                Path::new("/usr/local/bin/airlock"),
                home.path(),
                501,
                false,
                &runner,
            )
            .unwrap();

            assert_eq!(report.outcome, InstallOutcome::Fresh);
            assert!(report.unit_path.exists());
            assert_eq!(
                runner.calls(),
                vec![vec![
                    "launchctl".to_string(),
                    "bootstrap".to_string(),
                    "gui/501".to_string(),
                    report.unit_path.display().to_string(),
                ]]
            );
        }

        #[test]
        fn install_is_idempotent_for_identical_content() {
            let home = home();
            let runner = RecordingRunner::default();
            install(
                Path::new("/usr/local/bin/airlock"),
                home.path(),
                501,
                false,
                &runner,
            )
            .unwrap();
            runner.clear();

            let report = install(
                Path::new("/usr/local/bin/airlock"),
                home.path(),
                501,
                false,
                &runner,
            )
            .unwrap();

            assert_eq!(report.outcome, InstallOutcome::AlreadyInstalled);
            assert!(runner.calls().is_empty());
        }

        #[test]
        fn install_rewrites_and_reloads_when_content_differs() {
            let home = home();
            let runner = RecordingRunner::default();
            install(
                Path::new("/usr/local/bin/airlock"),
                home.path(),
                501,
                false,
                &runner,
            )
            .unwrap();
            runner.clear();

            let report = install(
                Path::new("/usr/local/bin/airlock-new"),
                home.path(),
                501,
                false,
                &runner,
            )
            .unwrap();

            assert_eq!(report.outcome, InstallOutcome::Reinstalled);
            assert_eq!(
                runner.calls(),
                vec![
                    vec![
                        "launchctl".to_string(),
                        "bootout".to_string(),
                        "gui/501/ai.modernpath.airlock".to_string(),
                    ],
                    vec![
                        "launchctl".to_string(),
                        "bootstrap".to_string(),
                        "gui/501".to_string(),
                        report.unit_path.display().to_string(),
                    ],
                ]
            );
            let written = std::fs::read_to_string(&report.unit_path).unwrap();
            assert!(written.contains("airlock-new"));
        }

        #[test]
        fn install_warns_about_build_or_temp_exe_paths() {
            let home = home();
            let runner = RecordingRunner::default();
            let report = install(
                Path::new("/Users/me/src/airlock/target/debug/airlock"),
                home.path(),
                501,
                false,
                &runner,
            )
            .unwrap();
            assert!(report.exe_warning.is_some());
        }

        #[test]
        fn install_does_not_warn_about_a_stable_exe_path() {
            let home = home();
            let runner = RecordingRunner::default();
            let report = install(
                Path::new("/opt/homebrew/bin/airlock"),
                home.path(),
                501,
                false,
                &runner,
            )
            .unwrap();
            assert!(report.exe_warning.is_none());
        }

        #[test]
        fn install_notes_an_already_running_daemon_without_stopping_it() {
            let home = home();
            let runner = RecordingRunner::default();
            let report = install(
                Path::new("/usr/local/bin/airlock"),
                home.path(),
                501,
                true,
                &runner,
            )
            .unwrap();
            assert!(report.daemon_running_note.is_some());
            assert!(
                report
                    .daemon_running_note
                    .unwrap()
                    .contains("airlock daemon restart")
            );
        }

        #[test]
        fn uninstall_when_not_installed_reports_not_installed() {
            let home = home();
            let runner = RecordingRunner::default();
            let report = uninstall(home.path(), 501, &runner).unwrap();
            assert_eq!(report.outcome, UninstallOutcome::NotInstalled);
            assert!(runner.calls().is_empty());
        }

        #[test]
        fn uninstall_boots_out_then_removes_the_file() {
            let home = home();
            let runner = RecordingRunner::default();
            install(
                Path::new("/usr/local/bin/airlock"),
                home.path(),
                501,
                false,
                &runner,
            )
            .unwrap();
            runner.clear();

            let report = uninstall(home.path(), 501, &runner).unwrap();

            assert_eq!(report.outcome, UninstallOutcome::Removed);
            assert!(!report.unit_path.exists());
            assert_eq!(
                runner.calls(),
                vec![vec![
                    "launchctl".to_string(),
                    "bootout".to_string(),
                    "gui/501/ai.modernpath.airlock".to_string(),
                ]]
            );
        }
    }
}

// ─── Linux: systemd --user ──────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    fn unit_dir(home: &Path, xdg_config_home: Option<&Path>) -> PathBuf {
        match xdg_config_home {
            Some(dir) => dir.join("systemd/user"),
            None => home.join(".config/systemd/user"),
        }
    }

    fn unit_path(home: &Path, xdg_config_home: Option<&Path>) -> PathBuf {
        unit_dir(home, xdg_config_home).join(SYSTEMD_UNIT)
    }

    fn render_unit(exe: &Path) -> String {
        let exe = escape_systemd(&exe.display().to_string());
        format!(
            "[Unit]\n\
             Description=Airlock credential broker\n\
             \n\
             [Service]\n\
             ExecStart={exe} daemon start --foreground --service\n\
             Restart=on-failure\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n"
        )
    }

    pub fn install(
        exe: &Path,
        home: &Path,
        _uid: u32,
        xdg_config_home: Option<&Path>,
        daemon_running: bool,
        runner: &dyn CommandRunner,
    ) -> Result<InstallReport, ServiceError> {
        let path = unit_path(home, xdg_config_home);
        let content = render_unit(exe);
        let existing = read_existing(&path)?;

        let outcome = match existing {
            Some(current) if current == content => InstallOutcome::AlreadyInstalled,
            Some(_) => {
                write_file(&path, &content)?;
                runner.run("systemctl", &["--user", "daemon-reload"])?;
                runner.run("systemctl", &["--user", "restart", SYSTEMD_UNIT])?;
                InstallOutcome::Reinstalled
            }
            None => {
                write_file(&path, &content)?;
                runner.run("systemctl", &["--user", "daemon-reload"])?;
                runner.run("systemctl", &["--user", "enable", "--now", SYSTEMD_UNIT])?;
                InstallOutcome::Fresh
            }
        };

        Ok(InstallReport {
            unit_path: path,
            outcome,
            exe_warning: exe_warning(exe),
            daemon_running_note: daemon_running_note(daemon_running),
            linger_note: Some(
                "systemd stops user services at logout. To keep the daemon running, run `loginctl enable-linger`."
                    .to_string(),
            ),
        })
    }

    pub fn uninstall(
        home: &Path,
        xdg_config_home: Option<&Path>,
        runner: &dyn CommandRunner,
    ) -> Result<UninstallReport, ServiceError> {
        let path = unit_path(home, xdg_config_home);
        if read_existing(&path)?.is_none() {
            return Ok(UninstallReport {
                unit_path: path,
                outcome: UninstallOutcome::NotInstalled,
            });
        }

        runner.run("systemctl", &["--user", "disable", "--now", SYSTEMD_UNIT])?;
        remove_file(&path)?;
        runner.run("systemctl", &["--user", "daemon-reload"])?;

        Ok(UninstallReport {
            unit_path: path,
            outcome: UninstallOutcome::Removed,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::service::test_support::RecordingRunner;

        fn home() -> tempfile::TempDir {
            tempfile::tempdir().expect("tempdir")
        }

        #[test]
        fn unit_content_is_exact() {
            let unit = render_unit(Path::new("/usr/local/bin/airlock"));
            let expected = "[Unit]\n\
                 Description=Airlock credential broker\n\
                 \n\
                 [Service]\n\
                 ExecStart=/usr/local/bin/airlock daemon start --foreground --service\n\
                 Restart=on-failure\n\
                 \n\
                 [Install]\n\
                 WantedBy=default.target\n";
            assert_eq!(unit, expected);
        }

        #[test]
        fn unit_escapes_percent_signs_in_exe_path() {
            let unit = render_unit(Path::new("/opt/100%/airlock"));
            assert!(
                unit.contains("ExecStart=/opt/100%%/airlock daemon start --foreground --service\n")
            );
        }

        #[test]
        fn fresh_install_writes_unit_and_enables_it() {
            let home = home();
            let runner = RecordingRunner::default();
            let report = install(
                Path::new("/usr/local/bin/airlock"),
                home.path(),
                1000,
                None,
                false,
                &runner,
            )
            .unwrap();

            assert_eq!(report.outcome, InstallOutcome::Fresh);
            assert!(report.unit_path.exists());
            assert_eq!(
                report.unit_path,
                home.path().join(".config/systemd/user/airlock.service")
            );
            assert_eq!(
                runner.calls(),
                vec![
                    vec![
                        "systemctl".to_string(),
                        "--user".to_string(),
                        "daemon-reload".to_string()
                    ],
                    vec![
                        "systemctl".to_string(),
                        "--user".to_string(),
                        "enable".to_string(),
                        "--now".to_string(),
                        "airlock.service".to_string(),
                    ],
                ]
            );
        }

        #[test]
        fn install_honors_xdg_config_home() {
            let home = home();
            let xdg = tempfile::tempdir().unwrap();
            let runner = RecordingRunner::default();
            let report = install(
                Path::new("/usr/local/bin/airlock"),
                home.path(),
                1000,
                Some(xdg.path()),
                false,
                &runner,
            )
            .unwrap();

            assert_eq!(
                report.unit_path,
                xdg.path().join("systemd/user/airlock.service")
            );
        }

        #[test]
        fn install_is_idempotent_for_identical_content() {
            let home = home();
            let runner = RecordingRunner::default();
            install(
                Path::new("/usr/local/bin/airlock"),
                home.path(),
                1000,
                None,
                false,
                &runner,
            )
            .unwrap();
            runner.clear();

            let report = install(
                Path::new("/usr/local/bin/airlock"),
                home.path(),
                1000,
                None,
                false,
                &runner,
            )
            .unwrap();

            assert_eq!(report.outcome, InstallOutcome::AlreadyInstalled);
            assert!(runner.calls().is_empty());
        }

        #[test]
        fn install_rewrites_and_restarts_when_content_differs() {
            let home = home();
            let runner = RecordingRunner::default();
            install(
                Path::new("/usr/local/bin/airlock"),
                home.path(),
                1000,
                None,
                false,
                &runner,
            )
            .unwrap();
            runner.clear();

            let report = install(
                Path::new("/usr/local/bin/airlock-new"),
                home.path(),
                1000,
                None,
                false,
                &runner,
            )
            .unwrap();

            assert_eq!(report.outcome, InstallOutcome::Reinstalled);
            assert_eq!(
                runner.calls(),
                vec![
                    vec![
                        "systemctl".to_string(),
                        "--user".to_string(),
                        "daemon-reload".to_string()
                    ],
                    vec![
                        "systemctl".to_string(),
                        "--user".to_string(),
                        "restart".to_string(),
                        "airlock.service".to_string(),
                    ],
                ]
            );
        }

        #[test]
        fn uninstall_when_not_installed_reports_not_installed() {
            let home = home();
            let runner = RecordingRunner::default();
            let report = uninstall(home.path(), None, &runner).unwrap();
            assert_eq!(report.outcome, UninstallOutcome::NotInstalled);
            assert!(runner.calls().is_empty());
        }

        #[test]
        fn uninstall_disables_removes_and_reloads() {
            let home = home();
            let runner = RecordingRunner::default();
            install(
                Path::new("/usr/local/bin/airlock"),
                home.path(),
                1000,
                None,
                false,
                &runner,
            )
            .unwrap();
            runner.clear();

            let report = uninstall(home.path(), None, &runner).unwrap();

            assert_eq!(report.outcome, UninstallOutcome::Removed);
            assert!(!report.unit_path.exists());
            assert_eq!(
                runner.calls(),
                vec![
                    vec![
                        "systemctl".to_string(),
                        "--user".to_string(),
                        "disable".to_string(),
                        "--now".to_string(),
                        "airlock.service".to_string(),
                    ],
                    vec![
                        "systemctl".to_string(),
                        "--user".to_string(),
                        "daemon-reload".to_string()
                    ],
                ]
            );
        }
    }
}

// ─── Shared file helpers ────────────────────────────────────────────────────

/// Reads the file at `path` if it exists. `Ok(None)` means it does not.
fn read_existing(path: &Path) -> Result<Option<String>, ServiceError> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_err(path, source)),
    }
}

fn write_file(path: &Path, content: &str) -> Result<(), ServiceError> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|source| io_err(dir, source))?;
    }
    std::fs::write(path, content).map_err(|source| io_err(path, source))
}

fn remove_file(path: &Path) -> Result<(), ServiceError> {
    std::fs::remove_file(path).map_err(|source| io_err(path, source))
}

#[cfg(target_os = "macos")]
fn path_str(path: &Path) -> &str {
    path.to_str()
        .expect("install paths are built from UTF-8 components")
}

// ─── Test support ───────────────────────────────────────────────────────────

#[cfg(test)]
mod test_support {
    use super::*;
    use std::cell::RefCell;

    /// Records every command issued, in order, instead of running it.
    #[derive(Default)]
    pub struct RecordingRunner {
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl RecordingRunner {
        pub fn calls(&self) -> Vec<Vec<String>> {
            self.calls.borrow().clone()
        }

        pub fn clear(&self) {
            self.calls.borrow_mut().clear();
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<(), ServiceError> {
            let mut call = vec![program.to_string()];
            call.extend(args.iter().map(|a| a.to_string()));
            self.calls.borrow_mut().push(call);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_path_replaces_home_prefix_with_tilde() {
        let home = Path::new("/Users/me");
        assert_eq!(
            display_path(&home.join("Library/LaunchAgents/x.plist"), home),
            "~/Library/LaunchAgents/x.plist"
        );
    }

    #[test]
    fn display_path_leaves_unrelated_paths_alone() {
        let home = Path::new("/Users/me");
        assert_eq!(display_path(Path::new("/etc/foo"), home), "/etc/foo");
    }

    #[test]
    fn looks_unstable_flags_cargo_target_debug_and_release() {
        assert!(looks_unstable(Path::new(
            "/src/airlock/target/debug/airlock"
        )));
        assert!(looks_unstable(Path::new(
            "/src/airlock/target/release/airlock"
        )));
    }

    #[test]
    fn looks_unstable_flags_tmp_paths() {
        assert!(looks_unstable(Path::new("/tmp/airlock")));
        assert!(looks_unstable(Path::new("/private/tmp/airlock")));
        assert!(looks_unstable(Path::new("/private/var/folders/xx/airlock")));
    }

    #[test]
    fn looks_unstable_accepts_installed_paths() {
        assert!(!looks_unstable(Path::new("/usr/local/bin/airlock")));
        assert!(!looks_unstable(Path::new("/opt/homebrew/bin/airlock")));
        assert!(!looks_unstable(Path::new("/home/me/.local/bin/airlock")));
    }

    #[test]
    fn escape_xml_escapes_all_five_special_characters() {
        assert_eq!(
            escape_xml("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }

    #[test]
    fn install_messages_already_installed_is_one_line() {
        let report = InstallReport {
            unit_path: PathBuf::from("/x"),
            outcome: InstallOutcome::AlreadyInstalled,
            exe_warning: None,
            daemon_running_note: None,
            linger_note: None,
        };
        assert_eq!(
            install_messages(&report, Path::new("/home/me")),
            vec!["already installed"]
        );
    }

    #[test]
    fn uninstall_messages_not_installed_is_one_line() {
        let report = UninstallReport {
            unit_path: PathBuf::from("/x"),
            outcome: UninstallOutcome::NotInstalled,
        };
        assert_eq!(
            uninstall_messages(&report, Path::new("/home/me")),
            vec!["not installed"]
        );
    }

    #[test]
    fn install_messages_uses_tilde_for_home_relative_paths() {
        let home = Path::new("/home/me");
        let report = InstallReport {
            unit_path: home.join(".config/systemd/user/airlock.service"),
            outcome: InstallOutcome::Fresh,
            exe_warning: None,
            daemon_running_note: None,
            linger_note: None,
        };
        let lines = install_messages(&report, home);
        assert_eq!(lines[0], "wrote ~/.config/systemd/user/airlock.service");
    }
}
