//! Commands run by the agent and its harness, not the user:
//! `airlock agent check` and `airlock agent hook <harness>`
//! (docs/airlock-v2-design.md, "Agent integration";
//! docs/airlock-v2-ux.md, "Harness hooks").
//!
//! `check_cmd` and `hook_cmd` are the two entry points `main.rs` calls.
//! Both build their own tokio runtime (like [`crate::run::run_agent`]) so
//! the rest of the crate never needs one just to call into this module.
//!
//! Every probe is a single filesystem `open`, expected to fail, run
//! against the paths the daemon echoes back on [`crate::protocol::DaemonMessage::CheckResult`]
//! (never computed locally — see "Agent integration" in the design doc:
//! "An agent environment that lacks the XDG variables cannot send the
//! probes to the wrong place"). The one exception is the four well-known
//! credential stores, which the design doc names by `~`; `~` there means
//! this process's own `$HOME`, used only for those four paths.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::ValueEnum;
use serde_json::Value;

use crate::client;
use crate::protocol::{
    DaemonMessage, SandboxKind, SessionInfo, SessionRequest, ToolInfo, WireAnchors,
};
use crate::trust::escape_for_terminal as esc;

/// Hanging indent for a probe or hook line's continuation text: 2 spaces
/// plus an 8-wide label field (docs/airlock-v2-ux.md, "`airlock agent
/// check`" transcripts — every continuation line lines up under the first
/// character after the label).
const CONT: &str = "          ";

// ─── Harness ────────────────────────────────────────────────────────────────

/// Which harness `airlock agent hook` adapts `check`/`tools list` to
/// (docs/airlock-v2-ux.md, "Harness hooks"). `clap::ValueEnum` so
/// `main.rs` can parse it straight off the command line.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[value(rename_all = "kebab-case")]
pub enum Harness {
    /// Claude Code's `SessionStart` hook: reads the event JSON from
    /// stdin, writes `hookSpecificOutput`/`systemMessage` JSON.
    ClaudeCode,
    /// Plain text, for any harness that shows a start command's output to
    /// the agent.
    Text,
}

// ─── The claude-code hook's command and settings block ──────────────────────
//
// Shared with `run.rs`'s `--profile claude`/`claude-relaxed` default
// command (`crate::run::claude_hook_settings_json`), so the hook string
// Claude Code actually runs and the one `--print-settings` documents can
// never drift apart (docs/airlock-v2-ux.md, "Installing the hook": "so the
// docs and the binary cannot drift").

/// The exact command Claude Code's `SessionStart` hook runs. Claude Code
/// dedupes hooks by command text (v2-plan.md, decision 8), so this string
/// must stay byte-identical everywhere it's installed.
pub const CLAUDE_CODE_HOOK_COMMAND: &str = "airlock agent hook claude-code";

/// The `hooks` block from docs/airlock-v2-ux.md, "Installing the hook".
pub fn claude_code_hooks_value() -> Value {
    serde_json::json!({
        "hooks": {
            "SessionStart": [
                { "hooks": [ { "type": "command", "command": CLAUDE_CODE_HOOK_COMMAND } ] }
            ]
        }
    })
}

/// `airlock agent hook claude-code --print-settings`.
fn print_settings() {
    let value = claude_code_hooks_value();
    println!(
        "{}",
        serde_json::to_string_pretty(&value).expect("hooks JSON always serializes")
    );
}

// ─── Connecting to the session (reuses client.rs) ────────────────────────────

/// Why a `Check`/`List` request never reached a `DaemonMessage` reply.
enum ConnectError {
    /// No `AIRLOCK_ADDR`/`AIRLOCK_SESSION`, or either was malformed.
    NoSession,
    /// A connection-level failure, already formatted per
    /// docs/airlock-v2-ux.md, "Messages → Agent" (client.rs's own
    /// `connect`/`handshake`/`read_one` messages).
    Message(String),
}

async fn fetch(request: SessionRequest) -> Result<DaemonMessage, ConnectError> {
    let Some((socket_path, token)) = client::session_from_env() else {
        return Err(ConnectError::NoSession);
    };
    client::session_request(&socket_path, &token, request)
        .await
        .map_err(ConnectError::Message)
}

// ─── Probes ───────────────────────────────────────────────────────────────────

/// One line of the sandbox self-test.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProbeStatus {
    Ok(String),
    Warn(String),
    Fail(String),
}

impl ProbeStatus {
    fn is_fail(&self) -> bool {
        matches!(self, ProbeStatus::Fail(_))
    }
}

/// Attempts to open `path` for reading. `None` when `path` doesn't exist —
/// there is nothing to probe, so the caller skips the line rather than
/// claim a pass. `Some(true)` means the open failed (good: unreadable);
/// `Some(false)` means it succeeded (bad: readable).
fn probe_cannot_open_for_read(path: &Path) -> Option<bool> {
    if !path.exists() {
        return None;
    }
    Some(std::fs::OpenOptions::new().read(true).open(path).is_err())
}

/// Attempts to create a uniquely named file in `dir` with `O_CREAT|O_EXCL`,
/// removing it at once on success. `None` when `dir` doesn't exist.
/// `Some(true)` means creation failed (good: not writable); `Some(false)`
/// means it succeeded (bad: writable).
fn probe_cannot_create(dir: &Path) -> Option<bool> {
    if !dir.exists() {
        return None;
    }
    let probe_path = dir.join(probe_file_name());
    let created = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe_path)
        .is_ok();
    if created {
        let _ = std::fs::remove_file(&probe_path);
    }
    Some(!created)
}

/// A random, collision-proof probe file name, so two concurrent `agent
/// check` runs against the same directory never race each other.
fn probe_file_name() -> String {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).expect("the system RNG must be available");
    let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    format!(".airlock-agent-check-{hex}")
}

fn probe_admin_token(runtime_base: &Path) -> Option<ProbeStatus> {
    let path = runtime_base.join("admin.token");
    let cannot_read = probe_cannot_open_for_read(&path)?;
    Some(if cannot_read {
        ProbeStatus::Ok("admin.token cannot be read".to_string())
    } else {
        ProbeStatus::Fail(format!(
            "{} can be read. The harness's sandbox must deny\n{CONT}reads of {}, or this agent can start sessions for any project.",
            path.display(),
            runtime_base.display()
        ))
    })
}

fn probe_write_dir(dir: &Path, label: &str, reason: &str) -> Option<ProbeStatus> {
    let cannot_write = probe_cannot_create(dir)?;
    Some(if cannot_write {
        ProbeStatus::Ok(format!("{label} cannot be written"))
    } else {
        ProbeStatus::Fail(format!(
            "{label} {} can be written. The harness's sandbox must deny\n{CONT}writes to it, or {reason}",
            dir.display()
        ))
    })
}

/// Names (never values) of tool secrets set in this process's own
/// environment — a leak means the secret reached the agent some other way
/// (`--passthrough-env`, a leaky harness).
fn probe_environment(
    names: &[String],
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Vec<ProbeStatus> {
    let mut leaked: Vec<&String> = names.iter().filter(|n| lookup(n).is_some()).collect();
    leaked.sort();
    leaked.dedup();
    if leaked.is_empty() {
        vec![ProbeStatus::Ok(
            "no tool secret in this environment".to_string(),
        )]
    } else {
        leaked
            .into_iter()
            .map(|n| {
                ProbeStatus::Fail(format!(
                    "{n} is set in this environment. It reached the agent some other way\n{CONT}(for example --passthrough-env); remove it from the harness's environment."
                ))
            })
            .collect()
    }
}

/// Every tool's `extra_read` paths, plus the four well-known credential
/// stores under this process's `$HOME`, paired with the warning text for
/// each. Deduplicated so a tool that happens to declare one of the
/// well-known paths doesn't warn twice.
fn credential_store_entries(credential_paths: &[PathBuf], home: &Path) -> Vec<(PathBuf, String)> {
    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    for path in credential_paths {
        if seen.insert(path.clone()) {
            entries.push((
                path.clone(),
                format!(
                    "The agent can read your credentials there\n{CONT}directly; deny it in the harness's sandbox."
                ),
            ));
        }
    }
    for (rel, what) in [
        (".config/gh", "gh login"),
        (".config/gcloud", "gcloud login"),
        (".aws", "aws credentials"),
        (".kube", "kube config"),
    ] {
        let path = home.join(rel);
        if seen.insert(path.clone()) {
            entries.push((
                path,
                format!(
                    "The agent can use your {what}\n{CONT}directly; deny it in the harness's sandbox."
                ),
            ));
        }
    }
    entries
}

/// A warning (never a failure — `claude-relaxed` opens some of these on
/// purpose) per readable store, or one aggregate "ok" line when every
/// existing store refused the read.
fn probe_credential_stores(entries: &[(PathBuf, String)]) -> Vec<ProbeStatus> {
    let warns: Vec<ProbeStatus> = entries
        .iter()
        .filter_map(|(path, reason)| {
            let cannot_read = probe_cannot_open_for_read(path)?;
            if cannot_read {
                None
            } else {
                Some(ProbeStatus::Warn(format!(
                    "{} can be read. {reason}",
                    path.display()
                )))
            }
        })
        .collect();
    if warns.is_empty() {
        vec![ProbeStatus::Ok(
            "credential stores cannot be read".to_string(),
        )]
    } else {
        warns
    }
}

/// Every sandbox self-test probe, in the order `agent check` prints them.
fn run_probes(
    anchors: &WireAnchors,
    secret_env_names: &[String],
    credential_paths: &[PathBuf],
    home: &Path,
    env_lookup: &dyn Fn(&str) -> Option<String>,
) -> Vec<ProbeStatus> {
    let mut out = Vec::new();
    out.extend(probe_admin_token(&anchors.runtime_base));
    out.extend(probe_write_dir(
        &anchors.runtime_base,
        "runtime dir",
        "this agent can replace the socket or CA.",
    ));
    out.extend(probe_write_dir(
        &anchors.trust_store,
        "trust store",
        "this agent can approve its own config.",
    ));
    let global_dir = anchors.global_config.parent().unwrap_or(Path::new("/"));
    out.extend(probe_write_dir(
        global_dir,
        "global config",
        "this agent can edit the unapproved global layer.",
    ));
    out.extend(probe_environment(secret_env_names, env_lookup));
    out.extend(probe_credential_stores(&credential_store_entries(
        credential_paths,
        home,
    )));
    out
}

// ─── Rendering (pure — no I/O, so these are unit-testable directly) ─────────

fn render_header(label: &str, text: &str) -> String {
    format!("{label:<10}{text}")
}

fn render_probe(status: &ProbeStatus) -> String {
    let (tag, msg) = match status {
        ProbeStatus::Ok(m) => ("ok", m.as_str()),
        ProbeStatus::Warn(m) => ("warn", m.as_str()),
        ProbeStatus::Fail(m) => ("FAIL", m.as_str()),
    };
    format!("  {tag:<8}{msg}")
}

fn sandbox_label(kind: SandboxKind) -> &'static str {
    match kind {
        SandboxKind::Airlock => "Airlock's",
        SandboxKind::External => "external",
    }
}

fn tool_names_csv(tools: &[ToolInfo]) -> String {
    let mut names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    names.sort_unstable();
    if names.is_empty() {
        "(none)".to_string()
    } else {
        names.join(", ")
    }
}

/// The aligned `  name  description` table used in the hook's
/// `additionalContext` (docs/airlock-v2-ux.md, "`airlock agent hook
/// claude-code`" JSON example).
fn tool_table(tools: &[ToolInfo]) -> String {
    let mut sorted: Vec<&ToolInfo> = tools.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let width = sorted.iter().map(|t| t.name.len()).max().unwrap_or(0);
    sorted
        .iter()
        .map(|t| {
            let name = esc(&t.name);
            let desc = t.description.as_deref().map(esc).unwrap_or_default();
            format!("  {name:<width$}  {desc}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

const CONFIG_CHANGED_NOTE: &str = "airlock.toml changed after this session started. Changes apply once the user approves them (`airlock trust`) and reloads the session (`airlock session reload`).";

/// Builds every line of `agent check`'s report and whether the run passes,
/// with no I/O of its own — `probes` and `tools` are already fetched, and
/// `layers_changed` is already evaluated. Returns `(line, keep_in_quiet)`
/// pairs: `-q` prints only the lines with `keep_in_quiet == true`
/// (docs/airlock-v2-ux.md, "Options": "`-q` prints only failures and
/// warnings").
fn build_report(
    session: &SessionInfo,
    version: &str,
    home: &Path,
    probes: Option<&[ProbeStatus]>,
    tools: &[ToolInfo],
    config_changed: bool,
) -> (Vec<(String, bool)>, bool) {
    let mut lines = Vec::new();
    lines.push((
        render_header(
            "session",
            &format!(
                "{} {:?} for {}",
                session.id,
                session.name,
                crate::inspect::display_path(&session.root, home)
            ),
        ),
        false,
    ));
    lines.push((
        render_header("daemon", &format!("answers, airlock {version}")),
        false,
    ));
    lines.push((
        render_header("sandbox", sandbox_label(session.sandbox)),
        false,
    ));
    let mut any_fail = false;
    if let Some(probes) = probes {
        for p in probes {
            any_fail |= p.is_fail();
            lines.push((render_probe(p), !matches!(p, ProbeStatus::Ok(_))));
        }
    }
    lines.push((render_header("tools", &tool_names_csv(tools)), false));
    if config_changed {
        lines.push((
            render_header(
                "config",
                "files changed since this session started; run `airlock trust` then `airlock session reload`",
            ),
            false,
        ));
    }
    (lines, any_fail)
}

fn render_report(lines: &[(String, bool)], quiet: bool) -> String {
    lines
        .iter()
        .filter(|(_, keep)| !quiet || *keep)
        .map(|(text, _)| text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

// ─── agent check ──────────────────────────────────────────────────────────────

/// `airlock agent check`.
pub fn check_cmd(quiet: bool) -> ExitCode {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("airlock: failed to create tokio runtime: {e}");
            return ExitCode::from(125);
        }
    };
    rt.block_on(check_cmd_async(quiet))
}

#[allow(
    clippy::disallowed_methods,
    reason = "client-side: `agent check` probes the current process's own HOME/env, not daemon request-path code"
)]
async fn check_cmd_async(quiet: bool) -> ExitCode {
    let home = std::env::var("HOME").map(PathBuf::from).unwrap_or_default();

    let (session, version, anchors, secret_env_names, credential_paths) =
        match fetch(SessionRequest::Check).await {
            Ok(DaemonMessage::CheckResult {
                session,
                version,
                anchors,
                secret_env_names,
                credential_paths,
            }) => (
                session,
                version,
                anchors,
                secret_env_names,
                credential_paths,
            ),
            Ok(DaemonMessage::Error { kind, message }) => {
                eprintln!("airlock: {message}");
                return ExitCode::from(kind.exit_code());
            }
            Ok(_) => {
                eprintln!("airlock: unexpected response from the daemon");
                return ExitCode::from(125);
            }
            Err(ConnectError::NoSession) => {
                eprintln!("airlock: {}", client::NO_SESSION_MESSAGE);
                return ExitCode::from(125);
            }
            Err(ConnectError::Message(message)) => {
                eprintln!("airlock: {message}");
                return ExitCode::from(125);
            }
        };

    let tools = match fetch(SessionRequest::List).await {
        Ok(DaemonMessage::Tools { tools, .. }) => tools,
        Ok(DaemonMessage::Error { kind, message }) => {
            eprintln!("airlock: {message}");
            return ExitCode::from(kind.exit_code());
        }
        _ => Vec::new(),
    };

    let probes = anchors.as_ref().map(|a| {
        run_probes(a, &secret_env_names, &credential_paths, &home, &|k| {
            std::env::var(k).ok()
        })
    });
    let config_changed = client::layers_changed(&session.layers);

    let (lines, any_fail) = build_report(
        &session,
        &version,
        &home,
        probes.as_deref(),
        &tools,
        config_changed,
    );
    let rendered = render_report(&lines, quiet);
    if !rendered.is_empty() {
        println!("{rendered}");
    }

    if any_fail {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

// ─── agent hook ───────────────────────────────────────────────────────────────

/// `airlock agent hook <claude-code|text>`.
pub fn hook_cmd(harness: Harness, print_settings_flag: bool) -> ExitCode {
    if print_settings_flag {
        print_settings();
        return ExitCode::SUCCESS;
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(_) => return ExitCode::SUCCESS, // always exits 0; nothing useful to report
    };
    rt.block_on(hook_cmd_async(harness));
    ExitCode::SUCCESS
}

fn no_session_output() -> (String, String) {
    (
        "This project uses Airlock, but this agent was not started with `airlock run`, so tools that need credentials are unavailable. Tell the user. Do not look for credentials yourself.".to_string(),
        "Airlock: this agent has no session. Start it with `airlock run`.".to_string(),
    )
}

fn ended_or_unreachable_output(message: &str) -> (String, String) {
    let text = format!("{message} Tell the user.");
    (text.clone(), text)
}

fn self_test_failed_output(check: &str) -> (String, String) {
    (
        format!(
            "Airlock's sandbox self-test failed: {check}. Do not use `airlock exec` until the user fixes it. Tell the user."
        ),
        format!("Airlock sandbox self-test failed: {check}"),
    )
}

fn external_output(tools: &[ToolInfo]) -> String {
    format!(
        "{}\n\nBefore your first `airlock exec`, run `airlock agent check` with your shell tool and report any FAIL to the user.",
        tool_table(tools)
    )
}

fn config_changed_output(tools: &[ToolInfo]) -> String {
    format!("{}\n\n{CONFIG_CHANGED_NOTE}", tool_table(tools))
}

fn success_output(session_id: &str, tools: &[ToolInfo]) -> String {
    format!(
        "Airlock is active for this project (session {session_id}, sandbox self-test passed).\n\n\
         These tools hold credentials. Run them only through Airlock, as `airlock exec -- <tool> [args...]`:\n\n\
         {}\n\n\
         Running them directly fails: their credentials are not in your environment. Secrets in their output appear as [REDACTED:NAME]; that is expected. `airlock tools list` shows details. Other commands run directly as usual.",
        tool_table(tools)
    )
}

/// The first line of a probe message — everything before the first
/// continuation line — for the hook's `<check>` placeholder.
fn first_line(s: &str) -> &str {
    s.split('\n').next().unwrap_or(s)
}

/// Renders `(context, system_message)` for the given harness, or an empty
/// string when nothing should be printed (no context at all — the "no
/// session, no config" case).
fn render_hook(harness: Harness, context: Option<&str>, system_message: Option<&str>) -> String {
    let Some(context) = context else {
        return String::new();
    };
    match harness {
        Harness::Text => context.to_string(),
        Harness::ClaudeCode => {
            let mut value = serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": context,
                }
            });
            if let Some(message) = system_message {
                value["systemMessage"] = Value::String(message.to_string());
            }
            value.to_string()
        }
    }
}

/// Discovers whether the project at `cwd` has an Airlock config at all
/// (`airlock.toml` or `airlock.local.toml` somewhere between `cwd` and
/// `home`), the same walk `prepare`/`session start` use
/// ([`crate::layers::load_layers`]). A malformed file still counts as
/// "has config" — it exists, it just doesn't parse.
#[allow(
    clippy::disallowed_methods,
    reason = "client-side: `agent hook` resolving the current process's own anchors, not daemon request-path code"
)]
fn project_has_config(cwd: &Path, home: &Path) -> bool {
    let Ok(runtime) = crate::runtime_dir::RuntimeDir::locate() else {
        return false;
    };
    let anchors = crate::anchors::resolve(&|k| std::env::var(k).ok(), home, &runtime);
    !matches!(
        crate::layers::load_layers(
            &crate::layers::DiscoveryMode::Default,
            cwd,
            home,
            &anchors.global_config,
        ),
        Err(crate::config::ConfigError::NoProjectConfig { .. })
    )
}

#[allow(
    clippy::disallowed_methods,
    reason = "client-side: `agent hook` probes the current process's own cwd/HOME/env, not daemon request-path code"
)]
async fn hook_cmd_async(harness: Harness) {
    if harness == Harness::ClaudeCode {
        // Drain stdin so the harness's write doesn't block on a full pipe;
        // the event JSON's fields don't change what this hook does (every
        // SessionStart trigger — start, resume, /clear, compaction — gets
        // the same treatment), so the content itself is discarded.
        let mut buf = String::new();
        let _ = std::io::stdin().read_to_string(&mut buf);
    }

    let Ok(cwd) = std::env::current_dir() else {
        return;
    };
    let home = std::env::var("HOME").map(PathBuf::from).ok();

    if client::session_from_env().is_none() {
        let has_config = home
            .as_deref()
            .map(|h| project_has_config(&cwd, h))
            .unwrap_or(false);
        if !has_config {
            return;
        }
        let (context, system_message) = no_session_output();
        print_rendered(harness, Some(&context), Some(&system_message));
        return;
    }

    let (session, tools) = match fetch(SessionRequest::List).await {
        Ok(DaemonMessage::Tools { session, tools }) => (session, tools),
        Ok(DaemonMessage::Error { message, .. }) => {
            let (context, system_message) = ended_or_unreachable_output(&message);
            print_rendered(harness, Some(&context), Some(&system_message));
            return;
        }
        Err(ConnectError::Message(message)) => {
            let (context, system_message) = ended_or_unreachable_output(&message);
            print_rendered(harness, Some(&context), Some(&system_message));
            return;
        }
        _ => return,
    };

    if session.sandbox == SandboxKind::External {
        print_rendered(harness, Some(&external_output(&tools)), None);
        return;
    }

    let (anchors, secret_env_names, credential_paths) = match fetch(SessionRequest::Check).await {
        Ok(DaemonMessage::CheckResult {
            anchors,
            secret_env_names,
            credential_paths,
            ..
        }) => (anchors, secret_env_names, credential_paths),
        Ok(DaemonMessage::Error { message, .. }) => {
            let (context, system_message) = ended_or_unreachable_output(&message);
            print_rendered(harness, Some(&context), Some(&system_message));
            return;
        }
        _ => (None, Vec::new(), Vec::new()),
    };

    let home_path = home.unwrap_or_default();
    let probes = anchors.as_ref().map(|a| {
        run_probes(a, &secret_env_names, &credential_paths, &home_path, &|k| {
            std::env::var(k).ok()
        })
    });

    if let Some(check) = probes.iter().flatten().find_map(|p| match p {
        ProbeStatus::Fail(m) => Some(first_line(m)),
        _ => None,
    }) {
        let (context, system_message) = self_test_failed_output(check);
        print_rendered(harness, Some(&context), Some(&system_message));
        return;
    }

    if client::layers_changed(&session.layers) {
        print_rendered(harness, Some(&config_changed_output(&tools)), None);
        return;
    }

    print_rendered(
        harness,
        Some(&success_output(&session.id.to_string(), &tools)),
        None,
    );
}

fn print_rendered(harness: Harness, context: Option<&str>, system_message: Option<&str>) {
    let rendered = render_hook(harness, context, system_message);
    if !rendered.is_empty() {
        println!("{rendered}");
    }
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "tests may read/set the process environment freely; only request-path code is bound by the session isolation rule"
)]
mod tests {
    use super::*;
    use crate::protocol::{EndsInfo, SessionId, WireMode};
    use std::os::unix::fs::PermissionsExt;

    fn fake_session(sandbox: SandboxKind) -> SessionInfo {
        SessionInfo {
            id: SessionId::parse("7f3a9c").unwrap(),
            name: "claude".to_string(),
            root: PathBuf::from("/home/user/src/app"),
            started_unix: 0,
            execs: 0,
            ends: EndsInfo::Never,
            sandbox,
            layers: Vec::new(),
            mode: WireMode::Default,
        }
    }

    fn fake_tool(name: &str, desc: &str) -> ToolInfo {
        ToolInfo {
            name: name.to_string(),
            description: Some(desc.to_string()),
            env: Vec::new(),
            proxy: false,
        }
    }

    fn sample_tools() -> Vec<ToolInfo> {
        vec![
            fake_tool("gh", "GitHub CLI"),
            fake_tool("psql", "Postgres shell"),
            fake_tool("tofu", "OpenTofu"),
        ]
    }

    // ── Probes: filesystem behavior ─────────────────────────────────────

    #[test]
    fn probe_cannot_create_fails_in_writable_dir() {
        let dir = tempfile::tempdir().unwrap();
        // A writable dir means the probe file creation *succeeds* —
        // that's the bad outcome (`Some(false)`).
        assert_eq!(probe_cannot_create(dir.path()), Some(false));
    }

    #[test]
    fn probe_cannot_create_ok_in_readonly_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = probe_cannot_create(dir.path());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result, Some(true));
    }

    #[test]
    fn probe_cannot_create_skips_missing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert_eq!(probe_cannot_create(&missing), None);
    }

    #[test]
    fn probe_cannot_open_for_read_skips_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(probe_cannot_open_for_read(&dir.path().join("nope")), None);
    }

    #[test]
    fn probe_cannot_open_for_read_fails_on_readable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        assert_eq!(probe_cannot_open_for_read(&path), Some(false));
    }

    #[test]
    fn probe_cannot_open_for_read_ok_on_unreadable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = probe_cannot_open_for_read(&path);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        if unsafe { libc::geteuid() } == 0 {
            // root bypasses permission bits; skip under a root test runner.
            return;
        }
        assert_eq!(result, Some(true));
    }

    #[test]
    fn probe_admin_token_ok_and_fail() {
        let dir = tempfile::tempdir().unwrap();
        // Missing admin.token: skipped.
        assert_eq!(probe_admin_token(dir.path()), None);
        // Present and readable: FAIL.
        std::fs::write(dir.path().join("admin.token"), b"secret").unwrap();
        assert!(matches!(
            probe_admin_token(dir.path()),
            Some(ProbeStatus::Fail(_))
        ));
    }

    #[test]
    fn probe_write_dir_reports_label_on_ok() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let status = probe_write_dir(dir.path(), "runtime dir", "reasons");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            status,
            Some(ProbeStatus::Ok("runtime dir cannot be written".to_string()))
        );
    }

    // ── Probes: environment / credential stores ─────────────────────────

    #[test]
    fn probe_environment_ok_when_nothing_set() {
        let names = vec!["GH_TOKEN".to_string()];
        let result = probe_environment(&names, &|_| None);
        assert_eq!(
            result,
            vec![ProbeStatus::Ok(
                "no tool secret in this environment".to_string()
            )]
        );
    }

    #[test]
    fn probe_environment_fails_per_leaked_var() {
        let names = vec!["B_TOKEN".to_string(), "A_TOKEN".to_string()];
        let result = probe_environment(&names, &|n| {
            if n == "A_TOKEN" {
                Some("leaked".to_string())
            } else {
                None
            }
        });
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], ProbeStatus::Fail(m) if m.starts_with("A_TOKEN is set")));
    }

    #[test]
    fn probe_credential_stores_ok_when_all_missing_or_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let entries = vec![(dir.path().join("nope"), "reason".to_string())];
        assert_eq!(
            probe_credential_stores(&entries),
            vec![ProbeStatus::Ok(
                "credential stores cannot be read".to_string()
            )]
        );
    }

    #[test]
    fn probe_credential_stores_warns_on_readable_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gh");
        std::fs::create_dir(&path).unwrap();
        let entries = vec![(path.clone(), "deny it".to_string())];
        let result = probe_credential_stores(&entries);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], ProbeStatus::Warn(m) if m.contains("deny it")));
    }

    // ── Rendering ─────────────────────────────────────────────────────────

    #[test]
    fn render_header_matches_ux_transcript() {
        assert_eq!(
            render_header("session", "7f3a9c \"claude\" for ~/src/app"),
            "session   7f3a9c \"claude\" for ~/src/app"
        );
        assert_eq!(
            render_header("daemon", "answers, airlock 0.6.0"),
            "daemon    answers, airlock 0.6.0"
        );
        assert_eq!(render_header("sandbox", "Airlock's"), "sandbox   Airlock's");
        assert_eq!(
            render_header("tools", "gh, psql, tofu"),
            "tools     gh, psql, tofu"
        );
    }

    #[test]
    fn render_probe_matches_ux_transcript() {
        assert_eq!(
            render_probe(&ProbeStatus::Ok("admin.token cannot be read".to_string())),
            "  ok      admin.token cannot be read"
        );
        let fail = render_probe(&ProbeStatus::Fail(
            "$RUNTIME/admin.token can be read. The harness's sandbox must deny\n          reads of $RUNTIME, or this agent can start sessions for any project.".to_string(),
        ));
        assert_eq!(
            fail,
            "  FAIL    $RUNTIME/admin.token can be read. The harness's sandbox must deny\n          reads of $RUNTIME, or this agent can start sessions for any project."
        );
        let warn = render_probe(&ProbeStatus::Warn(
            "~/.config/gcloud can be read. The agent can use your gcloud login\n          directly; deny it in the harness's sandbox.".to_string(),
        ));
        assert_eq!(
            warn,
            "  warn    ~/.config/gcloud can be read. The agent can use your gcloud login\n          directly; deny it in the harness's sandbox."
        );
    }

    #[test]
    fn tool_table_matches_ux_json_example() {
        assert_eq!(
            tool_table(&sample_tools()),
            "  gh    GitHub CLI\n  psql  Postgres shell\n  tofu  OpenTofu"
        );
    }

    #[test]
    fn tool_table_escapes_untrusted_control_characters() {
        // The description comes from the daemon's merged config, which may
        // include an unapproved file — a bidi override or an ESC byte must
        // not reach the agent's context (or the terminal, for `check`) raw.
        let tools = vec![fake_tool("gh", "evil\u{202e}desc\x1b[31m")];
        let out = tool_table(&tools);
        assert!(!out.contains('\u{202e}'));
        assert!(!out.contains('\x1b'));
        assert!(out.contains("\\u{202e}"));
        assert!(out.contains("\\u{1b}"));
    }

    #[test]
    fn tool_names_csv_sorted_and_empty() {
        assert_eq!(tool_names_csv(&sample_tools()), "gh, psql, tofu");
        assert_eq!(tool_names_csv(&[]), "(none)");
    }

    // ── build_report / render_report ─────────────────────────────────────

    #[test]
    fn build_report_all_ok_has_no_failures() {
        let session = fake_session(SandboxKind::Airlock);
        let probes = vec![ProbeStatus::Ok("x".to_string())];
        let (lines, any_fail) = build_report(
            &session,
            "1.0.0",
            Path::new("/home/user"),
            Some(&probes),
            &sample_tools(),
            false,
        );
        assert!(!any_fail);
        assert!(lines.iter().any(|(t, _)| t.starts_with("session   ")));
        assert!(lines.iter().any(|(t, _)| t.starts_with("tools     ")));
        assert!(!lines.iter().any(|(_, keep)| *keep));
    }

    #[test]
    fn build_report_fail_probe_sets_any_fail_and_keep() {
        let session = fake_session(SandboxKind::External);
        let probes = vec![ProbeStatus::Fail("bad".to_string())];
        let (lines, any_fail) = build_report(
            &session,
            "1.0.0",
            Path::new("/home/user"),
            Some(&probes),
            &[],
            false,
        );
        assert!(any_fail);
        assert!(lines.iter().any(|(t, keep)| *keep && t.contains("FAIL")));
    }

    #[test]
    fn render_report_quiet_drops_ok_and_header_lines() {
        let lines = vec![
            ("session   x".to_string(), false),
            ("  ok      y".to_string(), false),
            ("  FAIL    z".to_string(), true),
        ];
        assert_eq!(render_report(&lines, true), "  FAIL    z");
        assert_eq!(
            render_report(&lines, false),
            "session   x\n  ok      y\n  FAIL    z"
        );
    }

    #[test]
    fn render_report_quiet_empty_when_nothing_to_keep() {
        let lines = vec![("session   x".to_string(), false)];
        assert_eq!(render_report(&lines, true), "");
    }

    // ── Hook outcome builders ──────────────────────────────────────────────

    #[test]
    fn render_hook_none_context_prints_nothing() {
        assert_eq!(render_hook(Harness::ClaudeCode, None, None), "");
        assert_eq!(render_hook(Harness::Text, None, None), "");
    }

    #[test]
    fn render_hook_text_is_just_the_context() {
        assert_eq!(
            render_hook(Harness::Text, Some("hello"), Some("sys")),
            "hello"
        );
    }

    #[test]
    fn render_hook_claude_code_omits_absent_system_message() {
        let json = render_hook(Harness::ClaudeCode, Some("hello"), None);
        let value: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value["hookSpecificOutput"]["additionalContext"],
            Value::String("hello".to_string())
        );
        assert_eq!(
            value["hookSpecificOutput"]["hookEventName"],
            Value::String("SessionStart".to_string())
        );
        assert!(value.get("systemMessage").is_none());
    }

    #[test]
    fn render_hook_claude_code_includes_system_message_when_present() {
        let json = render_hook(Harness::ClaudeCode, Some("hello"), Some("sys"));
        let value: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["systemMessage"], Value::String("sys".to_string()));
    }

    #[test]
    fn no_session_output_matches_ux_table() {
        let (context, system_message) = no_session_output();
        assert!(context.starts_with("This project uses Airlock"));
        assert!(context.contains("Tell the user."));
        assert_eq!(
            system_message,
            "Airlock: this agent has no session. Start it with `airlock run`."
        );
    }

    #[test]
    fn ended_or_unreachable_output_appends_tell_the_user() {
        let (context, system_message) = ended_or_unreachable_output("this session has ended.");
        assert_eq!(context, "this session has ended. Tell the user.");
        assert_eq!(context, system_message);
    }

    #[test]
    fn self_test_failed_output_differs_between_context_and_message() {
        let (context, system_message) = self_test_failed_output("admin.token can be read");
        assert!(context.starts_with("Airlock's sandbox self-test failed"));
        assert!(context.contains("Tell the user."));
        assert_eq!(
            system_message,
            "Airlock sandbox self-test failed: admin.token can be read"
        );
    }

    #[test]
    fn external_output_lists_tools_and_asks_for_manual_check() {
        let out = external_output(&sample_tools());
        assert!(out.contains("gh    GitHub CLI"));
        assert!(out.contains("run `airlock agent check` with your shell tool"));
    }

    #[test]
    fn config_changed_output_lists_tools_and_note() {
        let out = config_changed_output(&sample_tools());
        assert!(out.contains("gh    GitHub CLI"));
        assert!(out.contains("airlock trust"));
        assert!(out.contains("airlock session reload"));
    }

    #[test]
    fn success_output_matches_ux_json_example() {
        let tools = sample_tools();
        let expected = format!(
            "Airlock is active for this project (session 7f3a9c, sandbox self-test passed).\n\nThese tools hold credentials. Run them only through Airlock, as `airlock exec -- <tool> [args...]`:\n\n{}\n\nRunning them directly fails: their credentials are not in your environment. Secrets in their output appear as [REDACTED:NAME]; that is expected. `airlock tools list` shows details. Other commands run directly as usual.",
            tool_table(&tools)
        );
        assert_eq!(success_output("7f3a9c", &tools), expected);
    }

    #[test]
    fn first_line_drops_continuation() {
        assert_eq!(first_line("one\n          two"), "one");
        assert_eq!(first_line("one"), "one");
    }

    // ── project_has_config ─────────────────────────────────────────────────

    #[test]
    fn project_has_config_false_in_empty_tree() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        assert!(!project_has_config(project.path(), home.path()));
    }

    #[test]
    fn project_has_config_true_when_airlock_toml_present() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("airlock.toml"), "[tools.echo]\n").unwrap();
        assert!(project_has_config(project.path(), home.path()));
    }

    // ── check_cmd / hook_cmd exit codes without a session ────────────────
    //
    // Serialized against every other test that touches the process
    // environment (`crate::test_support::ENV_MUTEX`), same convention as
    // `client.rs`'s own tests.

    struct TempEnv {
        prev: Vec<(String, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl TempEnv {
        fn new(vars: &[(&str, Option<&str>)]) -> Self {
            let lock = crate::test_support::ENV_MUTEX
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut prev = Vec::with_capacity(vars.len());
            for (key, value) in vars {
                prev.push((key.to_string(), std::env::var(key).ok()));
                match value {
                    // SAFETY: serialized by ENV_MUTEX above.
                    Some(v) => unsafe { std::env::set_var(key, v) },
                    None => unsafe { std::env::remove_var(key) },
                }
            }
            Self { prev, _lock: lock }
        }
    }

    impl Drop for TempEnv {
        fn drop(&mut self) {
            for (key, value) in &self.prev {
                // SAFETY: serialized by ENV_MUTEX held for the guard's life.
                match value {
                    Some(v) => unsafe { std::env::set_var(key, v) },
                    None => unsafe { std::env::remove_var(key) },
                }
            }
        }
    }

    #[test]
    fn check_cmd_without_session_exits_125() {
        let _env = TempEnv::new(&[("AIRLOCK_ADDR", None), ("AIRLOCK_SESSION", None)]);
        assert_eq!(check_cmd(false), ExitCode::from(125));
    }

    #[test]
    fn hook_cmd_without_session_or_config_exits_0_and_prints_nothing() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let _env = TempEnv::new(&[
            ("AIRLOCK_ADDR", None),
            ("AIRLOCK_SESSION", None),
            ("HOME", Some(home.path().to_str().unwrap())),
        ]);
        let prev_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(project.path()).unwrap();
        let code = hook_cmd(Harness::ClaudeCode, false);
        std::env::set_current_dir(prev_dir).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn hook_cmd_print_settings_exits_0() {
        assert_eq!(hook_cmd(Harness::ClaudeCode, true), ExitCode::SUCCESS);
    }

    #[test]
    fn claude_code_hooks_value_contains_the_exact_command() {
        let value = claude_code_hooks_value();
        let rendered = value.to_string();
        assert!(rendered.contains(CLAUDE_CODE_HOOK_COMMAND));
    }
}
