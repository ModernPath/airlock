//! `airlock config`, `airlock status` and `airlock init`: pure rendering of
//! what the config files and the daemon say, plus thin command functions
//! that take every environment-derived input explicitly (`cwd`, `home`,
//! where the global config and trust store live, ...) so `main.rs` can wire
//! them to the real process environment once it exists.
//!
//! See "Inspecting config and sessions" in `docs/airlock-v2-design.md` and
//! the "`config`"/"`status`"/"`init`" rows of "Options" plus the `airlock
//! config` output block in `docs/airlock-v2-ux.md` for the exact shapes
//! this module produces.

use std::collections::HashMap;
use std::io::{self, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::config::{self, RawEnvValue, RawSecretSpec};
use crate::kits;
use crate::layers::{
    self, AgentEnvProvenance, DiscoveryMode, LoadedLayers, MergeContext, MergedConfig,
    SecretProvenance,
};
use crate::protocol::{DaemonMode, LayerKind, SessionInfo};
use crate::trust::{Approval, TrustError, TrustStore, escape_for_terminal as esc};

// ─── Shared display helpers ─────────────────────────────────────────────────

/// Renders `path` relative to `home` with a leading `~`, or the path
/// unchanged when it is not under `home`. Used everywhere a path is shown to
/// the user, so a project under `$HOME` never scrolls off a terminal line.
pub fn display_path(path: &Path, home: &Path) -> String {
    if path == home {
        return "~".to_string();
    }
    match path.strip_prefix(home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

/// Renders rows of cells as a left-aligned table: each column is padded to
/// the widest cell in that column, with two spaces of gutter, and trailing
/// whitespace is trimmed from every line. An empty leading cell still gets
/// the column's indent, which is how a repeated label (`agent.passthrough_env`
/// shown once, blank on the rows after it) lines up under the first row.
pub fn table(rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![0usize; cols];
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in rows {
        let mut line = String::new();
        for (i, cell) in row.iter().enumerate() {
            line.push_str(cell);
            if i + 1 != row.len() {
                let pad = widths[i] - cell.chars().count() + 2;
                line.push_str(&" ".repeat(pad));
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

pub(crate) fn layer_label(kind: LayerKind) -> &'static str {
    match kind {
        LayerKind::Global => "global",
        LayerKind::Repo => "repo",
        LayerKind::Local => "local",
        LayerKind::ConfigFile => "config",
    }
}

/// The approval state of one config layer, as shown in the `layers` section
/// of `airlock config` and `airlock status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalState {
    /// The global layer: never approved, protected by the anchor checks
    /// instead.
    UserFile,
    /// Current bytes match the trust store's copy.
    Trusted,
    /// Current bytes differ from the trust store's copy.
    ChangedSinceTrusted,
    /// No copy has ever been approved.
    NotTrustedYet,
    /// The global layer, from inside the agent sandbox, which is never
    /// granted read access to it.
    NotReadable,
}

impl ApprovalState {
    fn text(self) -> &'static str {
        match self {
            ApprovalState::UserFile => "user file",
            ApprovalState::Trusted => "trusted",
            ApprovalState::ChangedSinceTrusted => "changed since trusted",
            ApprovalState::NotTrustedYet => "not trusted yet",
            ApprovalState::NotReadable => "not readable from this sandbox",
        }
    }

    /// Whether an item owned by a layer in this state may be shown without
    /// an `(unapproved)` marker.
    fn is_approved(self) -> bool {
        matches!(self, ApprovalState::UserFile | ApprovalState::Trusted)
    }
}

/// One row of the `layers` section: a config file (or the global layer) and
/// its approval state, with a path already formatted for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerRow {
    pub kind: LayerKind,
    pub path_display: String,
    pub state: ApprovalState,
}

fn layer_rows_table(layers: &[LayerRow]) -> String {
    let rows: Vec<Vec<String>> = layers
        .iter()
        .map(|l| {
            vec![
                format!("  {}", layer_label(l.kind)),
                esc(&l.path_display),
                l.state.text().to_string(),
            ]
        })
        .collect();
    table(&rows)
}

fn is_layer_approved(kind: LayerKind, approvals: &HashMap<LayerKind, ApprovalState>) -> bool {
    approvals.get(&kind).is_none_or(|s| s.is_approved())
}

/// Reads the approval state of the repo/local/config-file layers that were
/// actually loaded (the global layer is never checked: it is always
/// [`ApprovalState::UserFile`], or [`ApprovalState::NotReadable`] when
/// `in_sandbox` is set and no global file could be read).
fn build_layer_rows(
    loaded: &LoadedLayers,
    home: &Path,
    trust_store: &TrustStore,
    in_sandbox: bool,
    global_config_path: &Path,
) -> Result<Vec<LayerRow>, TrustError> {
    let mut rows = Vec::new();
    match &loaded.global {
        Some(file) => rows.push(LayerRow {
            kind: LayerKind::Global,
            path_display: display_path(&file.path, home),
            state: ApprovalState::UserFile,
        }),
        None if in_sandbox => rows.push(LayerRow {
            kind: LayerKind::Global,
            path_display: display_path(global_config_path, home),
            state: ApprovalState::NotReadable,
        }),
        None => {}
    }
    for file in [&loaded.repo, &loaded.local].into_iter().flatten() {
        let name = file.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let approval = trust_store.state(&loaded.root, name, &file.bytes)?;
        let state = match approval {
            Approval::Approved => ApprovalState::Trusted,
            Approval::Changed { .. } => ApprovalState::ChangedSinceTrusted,
            Approval::New => ApprovalState::NotTrustedYet,
        };
        rows.push(LayerRow {
            kind: file.kind,
            path_display: display_path(&file.path, home),
            state,
        });
    }
    Ok(rows)
}

fn file_name_only(path_display: &str) -> String {
    Path::new(path_display)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path_display)
        .to_string()
}

// ─── `airlock config` ───────────────────────────────────────────────────────

/// One `secrets` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRow {
    pub label: String,
    /// `"global"` / `"repo"` / `"local"` / `"local → global"`.
    pub layer_text: String,
    /// `"command: op read ..."` / `"env: GH_TOKEN"`.
    pub source_text: String,
    pub unapproved: bool,
}

/// One `tools` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRow {
    pub name: String,
    pub layer_text: String,
    pub description: String,
    /// `(VAR, LABEL)` for each `env` entry that references a secret —
    /// static values are not shown here.
    pub secret_env: Vec<(String, String)>,
    /// Effective `access` level plus provenance, e.g. `"default"` (built-in,
    /// nothing sets it), `"system (global)"` (inherited from the top-level
    /// default some layer set), or `"none (repo)"` (the tool's own
    /// override).
    pub access_text: String,
    pub replaces_global: bool,
    pub unapproved: bool,
}

/// One `settings` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingRow {
    Timeout {
        value: u64,
        layer_text: String,
    },
    Access {
        value: String,
        layer_text: String,
    },
    FilesystemPath {
        kind: &'static str,
        path: String,
        layer_text: String,
    },
    PassthroughEnv {
        name: String,
        layer_text: String,
    },
    AgentEnv {
        key: String,
        value_display: String,
        layer_text: String,
        overrides: Option<String>,
        unapproved: bool,
    },
}

/// One `kits` row: a single active kit (`agent.kits`, from any layer, plus
/// `--kit`, though `airlock config` only ever sees the config-declared
/// ones), fully expanded — the same expansion `airlock run` uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KitRow {
    pub name: String,
    /// Where `agent.kits` first named it, or where its `[kits.<name>]`
    /// table lives, whichever this kit has.
    pub layer_text: String,
    /// `"isolated"`/`"shared"` for a built-in kit, empty for a user-defined
    /// one (no mode concept).
    pub mode: String,
    pub read: Vec<String>,
    pub write: Vec<String>,
    /// `(VAR, VALUE)` pairs, in a stable order.
    pub env: Vec<(String, String)>,
}

/// Everything `render_config` needs. Built by [`config_cmd`] from a
/// [`LoadedLayers`], a [`MergedConfig`] and the layers' approval state —
/// kept as its own type so the renderer itself touches none of those types
/// and stays trivially testable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigReport {
    pub layers: Vec<LayerRow>,
    pub secrets: Vec<SecretRow>,
    pub tools: Vec<ToolRow>,
    pub settings: Vec<SettingRow>,
    pub kits: Vec<KitRow>,
    /// Trailing notes, one per unapproved repo/local file, e.g.
    /// `"airlock.local.toml changed since you trusted it; the next session
    /// start asks about it."`.
    pub notes: Vec<String>,
}

/// Renders the exact `airlock config` output described in
/// `docs/airlock-v2-ux.md` ("`airlock config` output"): `layers`, then
/// (when present) `secrets`, `tools`, `settings`, then any trailing notes.
pub fn render_config(report: &ConfigReport) -> String {
    let mut out = String::new();
    out.push_str("layers\n");
    out.push_str(&layer_rows_table(&report.layers));

    if !report.secrets.is_empty() {
        out.push('\n');
        out.push_str("secrets\n");
        let rows: Vec<Vec<String>> = report
            .secrets
            .iter()
            .map(|s| {
                vec![
                    format!("  {}", esc(&s.label)),
                    s.layer_text.clone(),
                    esc(&s.source_text),
                    if s.unapproved {
                        "(unapproved)".to_string()
                    } else {
                        String::new()
                    },
                ]
            })
            .collect();
        out.push_str(&table(&rows));
    }

    if !report.tools.is_empty() {
        out.push('\n');
        out.push_str("tools\n");
        let rows: Vec<Vec<String>> = report
            .tools
            .iter()
            .map(|t| {
                let secret_env = t
                    .secret_env
                    .iter()
                    .map(|(var, label)| format!("{} = <secret \"{}\">", esc(var), esc(label)))
                    .collect::<Vec<_>>()
                    .join(", ");
                let marker = match (t.replaces_global, t.unapproved) {
                    (true, true) => "(replaces global) (unapproved)".to_string(),
                    (true, false) => "(replaces global)".to_string(),
                    (false, true) => "(unapproved)".to_string(),
                    (false, false) => String::new(),
                };
                vec![
                    format!("  {}", esc(&t.name)),
                    t.layer_text.clone(),
                    esc(&t.description),
                    secret_env,
                    esc(&t.access_text),
                    marker,
                ]
            })
            .collect();
        out.push_str(&table(&rows));
    }

    if !report.settings.is_empty() {
        out.push('\n');
        out.push_str("settings\n");
        out.push_str(&render_settings_rows(&report.settings));
    }

    if !report.kits.is_empty() {
        out.push('\n');
        out.push_str("kits\n");
        let rows: Vec<Vec<String>> = report
            .kits
            .iter()
            .map(|k| {
                let env = k
                    .env
                    .iter()
                    .map(|(var, val)| format!("{}={}", esc(var), esc(val)))
                    .collect::<Vec<_>>()
                    .join(" ");
                let paths = format!(
                    "read: {}; write: {}",
                    if k.read.is_empty() {
                        "-".to_string()
                    } else {
                        k.read.iter().map(|p| esc(p)).collect::<Vec<_>>().join(", ")
                    },
                    if k.write.is_empty() {
                        "-".to_string()
                    } else {
                        k.write
                            .iter()
                            .map(|p| esc(p))
                            .collect::<Vec<_>>()
                            .join(", ")
                    },
                );
                vec![
                    format!("  {}", esc(&k.name)),
                    k.layer_text.clone(),
                    esc(&k.mode),
                    paths,
                    env,
                ]
            })
            .collect();
        out.push_str(&table(&rows));
    }

    for note in &report.notes {
        out.push('\n');
        out.push_str(&esc(note));
        out.push('\n');
    }

    out
}

fn render_settings_rows(settings: &[SettingRow]) -> String {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut last_group: Option<String> = None;
    for setting in settings {
        let (group, label, value, layer_col, marker) = match setting {
            SettingRow::Timeout { value, layer_text } => (
                "timeout".to_string(),
                "timeout".to_string(),
                value.to_string(),
                layer_text.clone(),
                String::new(),
            ),
            SettingRow::Access { value, layer_text } => (
                "access".to_string(),
                "access".to_string(),
                esc(value),
                layer_text.clone(),
                String::new(),
            ),
            SettingRow::FilesystemPath {
                kind,
                path,
                layer_text,
            } => (
                format!("filesystem.{kind}"),
                format!("filesystem.{kind}"),
                esc(path),
                layer_text.clone(),
                String::new(),
            ),
            SettingRow::PassthroughEnv { name, layer_text } => (
                "agent.passthrough_env".to_string(),
                "agent.passthrough_env".to_string(),
                esc(name),
                layer_text.clone(),
                String::new(),
            ),
            SettingRow::AgentEnv {
                key,
                value_display,
                layer_text,
                overrides,
                unapproved,
            } => {
                let layer_col = match overrides {
                    Some(o) => format!("{layer_text} (overrides {o})"),
                    None => layer_text.clone(),
                };
                let marker = if *unapproved {
                    "(unapproved)".to_string()
                } else {
                    String::new()
                };
                (
                    format!("agent.env.{}", esc(key)),
                    format!("agent.env.{}", esc(key)),
                    esc(value_display),
                    layer_col,
                    marker,
                )
            }
        };
        let shown_label = if last_group.as_deref() == Some(group.as_str()) {
            String::new()
        } else {
            label
        };
        last_group = Some(group);
        rows.push(vec![format!("  {shown_label}"), value, layer_col, marker]);
    }
    table(&rows)
}

/// `--paths`: the layer paths, trust store, runtime dir/socket and tool
/// state base, one labelled line each.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathsReport {
    pub global_config: String,
    pub repo: Option<String>,
    pub local: Option<String>,
    pub trust_store: String,
    pub runtime_dir: String,
    pub socket: String,
    pub tool_state_base: String,
}

pub fn render_paths(report: &PathsReport) -> String {
    let mut rows = vec![vec![
        "global config".to_string(),
        esc(&report.global_config),
    ]];
    if let Some(repo) = &report.repo {
        rows.push(vec!["repo config".to_string(), esc(repo)]);
    }
    if let Some(local) = &report.local {
        rows.push(vec!["local config".to_string(), esc(local)]);
    }
    rows.push(vec!["trust store".to_string(), esc(&report.trust_store)]);
    rows.push(vec!["runtime dir".to_string(), esc(&report.runtime_dir)]);
    rows.push(vec!["socket".to_string(), esc(&report.socket)]);
    rows.push(vec!["tool state".to_string(), esc(&report.tool_state_base)]);
    table(&rows)
}

/// Where the paths `--paths` prints come from, resolved by the caller
/// (`main.rs`, via `anchors`/`runtime_dir`) so this module never computes
/// them itself.
#[derive(Debug, Clone)]
pub struct ConfigPaths {
    pub global_config: PathBuf,
    pub trust_store: PathBuf,
    pub runtime_dir: PathBuf,
    pub socket: PathBuf,
    pub tool_state_base: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct ConfigOptions {
    pub config: Option<PathBuf>,
    pub no_project_config: bool,
    pub paths: bool,
}

fn discovery_mode(config: &Option<PathBuf>, no_project_config: bool) -> DiscoveryMode {
    if let Some(path) = config {
        DiscoveryMode::ConfigFile(path.clone())
    } else if no_project_config {
        DiscoveryMode::NoProjectConfig
    } else {
        DiscoveryMode::Default
    }
}

fn secret_layer_text(provenance: Option<SecretProvenance>) -> (String, Option<LayerKind>) {
    match provenance {
        Some(SecretProvenance::Direct(kind)) => (layer_label(kind).to_string(), Some(kind)),
        Some(SecretProvenance::LocalOverride) => ("local".to_string(), Some(LayerKind::Local)),
        Some(SecretProvenance::GlobalLink) => {
            ("local → global".to_string(), Some(LayerKind::Local))
        }
        None => (String::new(), None),
    }
}

fn secret_source_text(spec: &RawSecretSpec) -> String {
    match spec.source.as_deref() {
        Some("env") => format!("env: {}", spec.from.clone().unwrap_or_default()),
        Some("command") => format!(
            "command: {}",
            spec.command.clone().unwrap_or_default().join(" ")
        ),
        _ => String::new(),
    }
}

fn agent_env_value_display(value: &RawEnvValue) -> String {
    match value {
        RawEnvValue::Static(s) => format!("{s:?}"),
        RawEnvValue::SecretRef(r) => format!("<secret \"{}\">", r.secret),
    }
}

/// Builds the [`ConfigReport`] for a successfully merged config: secrets,
/// tools and settings, each annotated with the layer it came from and
/// whether that layer is still unapproved.
fn build_config_report(merged: &MergedConfig, layer_rows: &[LayerRow]) -> ConfigReport {
    let approvals: HashMap<LayerKind, ApprovalState> =
        layer_rows.iter().map(|r| (r.kind, r.state)).collect();
    let wire = merged.to_wire();
    let prov = merged.provenance();

    let mut secrets = Vec::new();
    if let Some(raw_secrets) = &wire.secrets {
        let mut labels: Vec<&String> = raw_secrets.keys().collect();
        labels.sort();
        for label in labels {
            let spec = &raw_secrets[label];
            let (layer_text, owning_layer) = secret_layer_text(prov.secrets.get(label).copied());
            let unapproved = owning_layer.is_some_and(|k| !is_layer_approved(k, &approvals));
            secrets.push(SecretRow {
                label: label.clone(),
                layer_text,
                source_text: secret_source_text(spec),
                unapproved,
            });
        }
    }

    let mut tools = Vec::new();
    if let Some(raw_tools) = &wire.tools {
        let mut names: Vec<&String> = raw_tools.keys().collect();
        names.sort();
        for name in names {
            let tool = &raw_tools[name];
            let provenance = prov.tools.get(name).copied();
            let layer = provenance.map_or(LayerKind::Global, |p| p.layer);
            let replaces_global = provenance.is_some_and(|p| p.replaced.is_some());
            let unapproved = !is_layer_approved(layer, &approvals);
            let mut secret_env = Vec::new();
            if let Some(env) = &tool.env {
                let mut vars: Vec<&String> = env.keys().collect();
                vars.sort();
                for var in vars {
                    if let RawEnvValue::SecretRef(r) = &env[var] {
                        secret_env.push((var.clone(), r.secret.clone()));
                    }
                }
            }
            let access_text = match &tool.access {
                Some(a) => format!("{a} ({})", layer_label(layer)),
                None => match (&wire.access, prov.settings.access) {
                    (Some(v), Some(top_layer)) => format!("{v} ({})", layer_label(top_layer)),
                    (Some(v), None) => v.clone(),
                    (None, _) => "default".to_string(),
                },
            };
            tools.push(ToolRow {
                name: name.clone(),
                layer_text: layer_label(layer).to_string(),
                description: tool.description.clone().unwrap_or_default(),
                secret_env,
                access_text,
                replaces_global,
                unapproved,
            });
        }
    }

    let mut settings = Vec::new();
    if let (Some(value), Some(layer)) = (wire.timeout, prov.settings.timeout) {
        settings.push(SettingRow::Timeout {
            value,
            layer_text: layer_label(layer).to_string(),
        });
    }
    if let (Some(value), Some(layer)) = (&wire.access, prov.settings.access) {
        settings.push(SettingRow::Access {
            value: value.clone(),
            layer_text: layer_label(layer).to_string(),
        });
    }
    for (path, layer) in &prov.settings.filesystem_read {
        settings.push(SettingRow::FilesystemPath {
            kind: "read",
            path: path.clone(),
            layer_text: layer_label(*layer).to_string(),
        });
    }
    for (path, layer) in &prov.settings.filesystem_write {
        settings.push(SettingRow::FilesystemPath {
            kind: "write",
            path: path.clone(),
            layer_text: layer_label(*layer).to_string(),
        });
    }
    for (name, layer) in &prov.settings.agent_passthrough_env {
        settings.push(SettingRow::PassthroughEnv {
            name: name.clone(),
            layer_text: layer_label(*layer).to_string(),
        });
    }
    if let Some(agent) = &wire.agent {
        let mut keys: Vec<&String> = agent.env.keys().collect();
        keys.sort();
        for key in keys {
            let Some(p): Option<&AgentEnvProvenance> = prov.settings.agent_env.get(key) else {
                continue;
            };
            let unapproved = !is_layer_approved(p.layer, &approvals);
            settings.push(SettingRow::AgentEnv {
                key: key.clone(),
                value_display: agent_env_value_display(&agent.env[key]),
                layer_text: layer_label(p.layer).to_string(),
                overrides: p.overrides.map(|o| layer_label(o).to_string()),
                unapproved,
            });
        }
    }

    let mut notes = Vec::new();
    for row in layer_rows {
        if row.kind == LayerKind::Global {
            continue;
        }
        let name = file_name_only(&row.path_display);
        match row.state {
            ApprovalState::ChangedSinceTrusted => notes.push(format!(
                "{name} changed since you trusted it; the next session start asks about it."
            )),
            ApprovalState::NotTrustedYet => notes.push(format!(
                "{name} is not trusted yet; the next session start asks about it."
            )),
            _ => {}
        }
    }

    ConfigReport {
        layers: layer_rows.to_vec(),
        secrets,
        tools,
        settings,
        // Filled in separately by config_cmd (build_kit_rows), which needs
        // inputs (home, env snapshot, platform) this function does not take.
        kits: Vec::new(),
        notes,
    }
}

/// `airlock config [--config P] [--no-project-config] [--paths]`.
///
/// Loads the project's config layers and merges them, then prints exactly
/// what `render_config` (or, with `--paths`, `render_paths`) produces.
/// Never prompts and never writes the trust store: `TrustStore::state` only
/// reads it. A config with errors still prints whatever layers were read
/// before printing the error, so the user can see which file is at fault;
/// exit code is 125 either way discovery or merging failed.
///
/// `in_sandbox` controls only whether a missing global layer is shown as
/// absent (normal case) or as [`ApprovalState::NotReadable`] (running
/// inside the agent sandbox, which is never granted read access to it).
#[allow(clippy::too_many_arguments)]
pub fn config_cmd(
    opts: &ConfigOptions,
    cwd: &Path,
    home: &Path,
    global_config_path: &Path,
    tool_state_base: &Path,
    env_snapshot: &std::collections::BTreeMap<String, String>,
    paths: &ConfigPaths,
    in_sandbox: bool,
    out: &mut dyn Write,
) -> ExitCode {
    let mode = discovery_mode(&opts.config, opts.no_project_config);

    let loaded = match layers::load_layers(&mode, cwd, home, global_config_path) {
        Ok(l) => l,
        Err(e) => {
            writeln!(out, "error: {e}").ok();
            return ExitCode::from(125);
        }
    };

    let trust_store = match TrustStore::open(&paths.trust_store) {
        Ok(t) => t,
        Err(e) => {
            writeln!(out, "error: {e}").ok();
            return ExitCode::from(125);
        }
    };

    let layer_rows =
        match build_layer_rows(&loaded, home, &trust_store, in_sandbox, global_config_path) {
            Ok(rows) => rows,
            Err(e) => {
                writeln!(out, "error: {e}").ok();
                return ExitCode::from(125);
            }
        };

    if opts.paths {
        let report = PathsReport {
            global_config: display_path(global_config_path, home),
            repo: loaded.repo.as_ref().map(|f| display_path(&f.path, home)),
            local: loaded.local.as_ref().map(|f| display_path(&f.path, home)),
            trust_store: display_path(&paths.trust_store, home),
            runtime_dir: display_path(&paths.runtime_dir, home),
            socket: display_path(&paths.socket, home),
            tool_state_base: display_path(&paths.tool_state_base, home),
        };
        write!(out, "{}", render_paths(&report)).ok();
        return ExitCode::SUCCESS;
    }

    let ctx = MergeContext {
        root: loaded.root.clone(),
        home: home.to_path_buf(),
        tool_state_base: tool_state_base.to_path_buf(),
    };
    match layers::merge(&loaded, &ctx) {
        Ok(merged) => {
            let mut report = build_config_report(&merged, &layer_rows);
            match build_kit_rows(&merged, home, tool_state_base, env_snapshot) {
                Ok(kits) => report.kits = kits,
                Err(e) => {
                    write!(out, "{}", render_config(&report)).ok();
                    writeln!(out, "error: {e}").ok();
                    return ExitCode::from(125);
                }
            }
            write!(out, "{}", render_config(&report)).ok();
            ExitCode::SUCCESS
        }
        Err(e) => {
            let report = ConfigReport {
                layers: layer_rows,
                ..Default::default()
            };
            write!(out, "{}", render_config(&report)).ok();
            writeln!(out, "error: {e}").ok();
            ExitCode::from(125)
        }
    }
}

/// Builds the `kits` section: every active kit (`agent.kits`, unioned
/// across layers by `layers::merge`), fully expanded exactly like `airlock
/// run` would expand it — same inputs, same [`kits::expand_all`]. Each kit
/// is expanded on its own (rather than once for the whole active list) so
/// each row shows only its own paths/env.
fn build_kit_rows(
    merged: &MergedConfig,
    home: &Path,
    tool_state_base: &Path,
    env_snapshot: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<KitRow>, config::ConfigError> {
    let raw_config = merged.to_wire();
    kits::validate_all(merged.kits())?;
    let active = kits::resolve_active(&raw_config, &[], merged.kits())?;
    kits::check_env_collision(raw_config.agent.as_ref(), &active, merged.kits())?;

    let project_id = config::project_id(merged.root());
    let mut rows = Vec::with_capacity(active.len());
    for name in &active {
        let inputs = kits::Inputs {
            home,
            env: env_snapshot,
            platform: kits::Platform::current(),
            project_id: &project_id,
            tool_state_base,
            root: merged.root(),
        };
        let expanded = kits::expand_all(std::slice::from_ref(name), merged.kits(), &inputs)?;
        let mode = expanded
            .active
            .first()
            .and_then(|(_, m)| *m)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let layer_text = match merged.provenance().kits.get(name) {
            Some(kind) => layer_label(*kind).to_string(),
            None => merged
                .provenance()
                .settings
                .agent_kits
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, kind)| layer_label(*kind).to_string())
                .unwrap_or_default(),
        };
        let mut read: Vec<String> = expanded
            .read
            .iter()
            .map(|p| display_path(p, home))
            .collect();
        read.sort();
        let mut write: Vec<String> = expanded
            .write
            .iter()
            .map(|p| display_path(p, home))
            .collect();
        write.extend(expanded.write_files.iter().map(|p| display_path(p, home)));
        write.sort();
        let mut env: Vec<(String, String)> = expanded
            .env
            .iter()
            .map(|(k, v)| (k.clone(), display_path(Path::new(v), home)))
            .collect();
        env.sort();
        rows.push(KitRow {
            name: name.clone(),
            layer_text,
            mode,
            read,
            write,
            env,
        });
    }
    Ok(rows)
}

// ─── `airlock status` ───────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
const SERVICE_LABEL: &str = "launchd service";
#[cfg(target_os = "linux")]
const SERVICE_LABEL: &str = "systemd service";
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const SERVICE_LABEL: &str = "service";

/// The daemon's own state, built from its `Hello` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonStatus {
    pub pid: u32,
    pub version: String,
    pub mode: DaemonMode,
    /// Unix time it started. Only meaningful (and only shown) for
    /// [`DaemonMode::Automatic`].
    pub started_unix: Option<u64>,
    pub addr: String,
}

/// This project's layers, for the `project` block of `airlock status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectStatus {
    pub root_display: String,
    pub layers: Vec<LayerRow>,
}

/// One session row under `sessions`, display-ready: `render_status` itself
/// does no I/O, so whether the config changed is decided by the caller
/// (which can re-read the files) rather than recomputed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub id: String,
    pub name: String,
    pub started_unix: u64,
    pub execs: u64,
    pub config_changed: bool,
}

fn format_relative(now_unix: u64, then_unix: u64) -> String {
    let secs = now_unix.saturating_sub(then_unix);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// `HH:MM` in the viewer's local time zone, matching the UX transcript
/// ("Every day" shows `10:42`, `11:30`). Goes through `libc::localtime_r`
/// rather than the `time` crate's local-offset lookup, which is unsound to
/// call once a process may have spawned threads (true of this binary, which
/// creates a tokio runtime for most commands).
pub fn format_hhmm_local(unix: u64) -> String {
    let secs = unix.min(i64::MAX as u64) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&secs, &mut tm) };
    format!("{:02}:{:02}", tm.tm_hour, tm.tm_min)
}

fn daemon_mode_text(daemon: &DaemonStatus, now_unix: u64) -> String {
    match daemon.mode {
        DaemonMode::Automatic => {
            let ago = daemon
                .started_unix
                .map_or_else(|| "0s".to_string(), |t| format_relative(now_unix, t));
            format!("started on demand {ago} ago")
        }
        DaemonMode::Manual => "started by hand".to_string(),
        DaemonMode::Service => SERVICE_LABEL.to_string(),
    }
}

fn render_session_rows(sessions: &[SessionRow]) -> String {
    let rows: Vec<Vec<String>> = sessions
        .iter()
        .map(|s| {
            vec![
                format!("  {}", s.id),
                s.name.clone(),
                format_hhmm_local(s.started_unix),
                format!("{} execs", s.execs),
                if s.config_changed {
                    "config changed".to_string()
                } else {
                    String::new()
                },
            ]
        })
        .collect();
    table(&rows)
}

/// Renders the `airlock status` transcript from `docs/airlock-v2-ux.md`
/// ("Every day"): the daemon line, its address, this project's layers (if
/// any), and the sessions here and in total. `daemon.is_none()` renders
/// `"daemon not running\n"` and nothing else — the caller maps that case to
/// exit code 3.
pub fn render_status(
    daemon: Option<&DaemonStatus>,
    project: Option<&ProjectStatus>,
    sessions_here: &[SessionRow],
    sessions_total: usize,
    now_unix: u64,
) -> String {
    let Some(daemon) = daemon else {
        return "daemon not running\n".to_string();
    };

    const LABEL_WIDTH: usize = 10; // len("sessions") + 2

    let mut out = String::new();
    out.push_str(&format!(
        "{:<LABEL_WIDTH$}running, PID {}, {}\n",
        "daemon",
        daemon.pid,
        daemon_mode_text(daemon, now_unix)
    ));
    out.push_str(&format!("{:<LABEL_WIDTH$}{}\n", "address", daemon.addr));

    if let Some(project) = project {
        out.push('\n');
        out.push_str(&format!(
            "{:<LABEL_WIDTH$}{}\n",
            "project", project.root_display
        ));
        out.push_str(&layer_rows_table(&project.layers));
    }

    out.push('\n');
    out.push_str(&format!(
        "{:<LABEL_WIDTH$}{} here, {} in total\n",
        "sessions",
        sessions_here.len(),
        sessions_total
    ));
    out.push_str(&render_session_rows(sessions_here));

    out
}

/// What `status_cmd` needs to ask the daemon. A trait rather than a
/// concrete client, so this module never depends on the admin client that
/// `main.rs`/`admin.rs` provide, and so tests can supply a fake.
pub trait DaemonProbe {
    /// `None` when the daemon does not answer (not running, or an
    /// unreachable socket).
    fn hello(&mut self) -> Option<DaemonStatus>;
    /// Every session on the daemon. Only called after a successful
    /// [`DaemonProbe::hello`].
    fn list_sessions(&mut self) -> Vec<SessionInfo>;
}

#[derive(Debug, Clone, Default)]
pub struct StatusOptions {
    pub config: Option<PathBuf>,
    pub no_project_config: bool,
}

fn session_config_changed(session: &SessionInfo) -> bool {
    session
        .layers
        .iter()
        .any(|layer| match std::fs::read(&layer.path) {
            Ok(bytes) => config::sha256_hex(&bytes) != layer.sha256,
            // Unreadable: skip it rather than guess ("Checks" in
            // docs/airlock-v2-design.md treats an unreadable credential path
            // the same way).
            Err(_) => false,
        })
}

/// `airlock status [--config] [--no-project-config]`.
///
/// Returns exit code 3 (not running) or 0 (running) per "Inspecting config
/// and sessions" in `docs/airlock-v2-design.md`. `now_unix` is the wall
/// clock, read once by the caller so this function stays deterministic.
#[allow(clippy::too_many_arguments)]
pub fn status_cmd(
    opts: &StatusOptions,
    cwd: &Path,
    home: &Path,
    global_config_path: &Path,
    trust_store_dir: &Path,
    probe: &mut dyn DaemonProbe,
    now_unix: u64,
    out: &mut dyn Write,
) -> ExitCode {
    let Some(daemon) = probe.hello() else {
        writeln!(out, "daemon not running").ok();
        return ExitCode::from(3);
    };

    let mode = discovery_mode(&opts.config, opts.no_project_config);
    let loaded = layers::load_layers(&mode, cwd, home, global_config_path).ok();
    let trust_store = TrustStore::open(trust_store_dir).ok();

    let (project, root) = match (&loaded, &trust_store) {
        (Some(loaded), Some(trust_store)) => {
            let rows = build_layer_rows(loaded, home, trust_store, false, global_config_path)
                .unwrap_or_default();
            (
                Some(ProjectStatus {
                    root_display: display_path(&loaded.root, home),
                    layers: rows,
                }),
                Some(loaded.root.clone()),
            )
        }
        _ => (None, None),
    };

    let sessions = probe.list_sessions();
    let sessions_total = sessions.len();
    let sessions_here: Vec<SessionRow> = sessions
        .iter()
        .filter(|s| root.as_deref() == Some(s.root.as_path()))
        .map(|s| SessionRow {
            id: s.id.to_string(),
            name: s.name.clone(),
            started_unix: s.started_unix,
            execs: s.execs,
            config_changed: session_config_changed(s),
        })
        .collect();

    write!(
        out,
        "{}",
        render_status(
            Some(&daemon),
            project.as_ref(),
            &sessions_here,
            sessions_total,
            now_unix
        )
    )
    .ok();
    ExitCode::SUCCESS
}

// ─── `airlock init` ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitKind {
    /// `airlock init`: the repo layer.
    Plain,
    /// `airlock init --local`.
    Local,
    /// `airlock init --global`.
    Global,
}

/// Runs `git check-ignore -q <file>` (or an equivalent) so `init --local`
/// can tell the user whether their new file needs a `.gitignore` entry.
/// Injectable so tests never spawn a real `git`.
pub trait GitRunner {
    /// `Some(true)`: git ignores `file`. `Some(false)`: it does not.
    /// `None`: `cwd` is not a git repository (or git could not be run at
    /// all), in which case `init --local` says nothing about it.
    fn check_ignore(&self, cwd: &Path, file: &str) -> Option<bool>;
}

/// The real `git check-ignore`, for `main.rs` to pass to [`init_cmd`].
pub struct RealGitRunner;

impl GitRunner for RealGitRunner {
    fn check_ignore(&self, cwd: &Path, file: &str) -> Option<bool> {
        let output = std::process::Command::new("git")
            .args(["check-ignore", "-q", file])
            .current_dir(cwd)
            .output()
            .ok()?;
        match output.status.code() {
            Some(0) => Some(true),
            Some(1) => Some(false),
            // 128: not a git repository (or another fatal git error).
            _ => None,
        }
    }
}

fn create_dir_0700(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// Labels in `[secrets.<label>]` with neither `source` nor `from` — the
/// repo's own "this project needs X, bind it yourself" requests.
fn unbound_repo_labels(repo: &config::RawConfig) -> Vec<(String, Option<String>)> {
    let Some(secrets) = &repo.secrets else {
        return Vec::new();
    };
    let mut out: Vec<(String, Option<String>)> = secrets
        .iter()
        .filter(|(_, spec)| spec.source.is_none() && spec.from.is_none())
        .map(|(label, spec)| (label.clone(), spec.description.clone()))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Labels the global layer binds with a concrete source of its own.
fn bound_global_labels(global: Option<&config::RawConfig>) -> Vec<String> {
    let Some(secrets) = global.and_then(|c| c.secrets.as_ref()) else {
        return Vec::new();
    };
    let mut out: Vec<String> = secrets
        .iter()
        .filter(|(_, spec)| spec.source.is_some())
        .map(|(label, _)| label.clone())
        .collect();
    out.sort();
    out
}

/// The per-label summary `init --local` prints under `created <path>` when
/// the repo has unbound labels, e.g. `GH_TOKEN  from = "global" (your
/// global config binds it)`.
pub fn render_local_bindings_summary(
    repo_labels: &[(String, Option<String>)],
    global_bound: &[String],
) -> String {
    let rows: Vec<Vec<String>> = repo_labels
        .iter()
        .map(|(label, _description)| {
            let binding = if global_bound.iter().any(|g| g == label) {
                "from = \"global\" (your global config binds it)".to_string()
            } else {
                "not bound: edit airlock.local.toml".to_string()
            };
            vec![format!("  {label}"), binding]
        })
        .collect();
    table(&rows)
}

/// The trailing git-ignore note `init --local` prints, or an empty string
/// when `cwd` is not a git repository at all.
pub fn render_git_ignore_note(ignored: Option<bool>) -> String {
    let file = config::local_config_filename();
    match ignored {
        None => String::new(),
        Some(true) => format!("{file} is ignored by git\n"),
        Some(false) => format!(
            "warning: {file} is not ignored by git. To ignore it in every repo:\n         echo {file} >> ~/.config/git/ignore\n"
        ),
    }
}

/// Reads and parses a config file the way loading a layer does, so `init`
/// gets the same symlink, ownership and size checks.
fn read_raw_config(kind: LayerKind, path: &Path) -> Result<config::RawConfig, String> {
    layers::LayerFile::read(kind, path, config::current_euid())
        .and_then(|file| file.parse())
        .map_err(|e| e.to_string())
}

fn init_plain(cwd: &Path, home: &Path, out: &mut dyn Write) -> ExitCode {
    let path = cwd.join(config::config_filename());
    if path.exists() {
        writeln!(out, "error: {} already exists", display_path(&path, home)).ok();
        return ExitCode::from(125);
    }
    if let Err(e) = std::fs::write(&path, config::default_config_template()) {
        writeln!(
            out,
            "error: failed to write {}: {e}",
            display_path(&path, home)
        )
        .ok();
        return ExitCode::from(125);
    }
    writeln!(out, "created {}", display_path(&path, home)).ok();
    writeln!(
        out,
        "edit it to declare your tools, then run `airlock run --profile claude`"
    )
    .ok();
    ExitCode::SUCCESS
}

fn init_global(home: &Path, global_config: &Path, out: &mut dyn Write) -> ExitCode {
    let path = global_config;
    let dir = path
        .parent()
        .expect("the global config path always has a parent");
    if path.exists() {
        writeln!(out, "error: {} already exists", display_path(path, home)).ok();
        return ExitCode::from(125);
    }
    if let Err(e) = create_dir_0700(dir) {
        writeln!(
            out,
            "error: failed to create {}: {e}",
            display_path(dir, home)
        )
        .ok();
        return ExitCode::from(125);
    }
    if let Err(e) = std::fs::write(path, config::global_config_template()) {
        writeln!(
            out,
            "error: failed to write {}: {e}",
            display_path(path, home)
        )
        .ok();
        return ExitCode::from(125);
    }
    writeln!(out, "created {}", display_path(path, home)).ok();
    ExitCode::SUCCESS
}

fn init_local(
    cwd: &Path,
    home: &Path,
    global_config: &Path,
    git: &dyn GitRunner,
    out: &mut dyn Write,
) -> ExitCode {
    let local_path = cwd.join(config::local_config_filename());
    if local_path.exists() {
        writeln!(
            out,
            "error: {} already exists",
            display_path(&local_path, home)
        )
        .ok();
        return ExitCode::from(125);
    }

    let repo_path = cwd.join(config::config_filename());
    let (content, bindings_summary, standalone) = if repo_path.exists() {
        let repo_raw = match read_raw_config(LayerKind::Repo, &repo_path) {
            Ok(r) => r,
            Err(e) => {
                writeln!(out, "error: {e}").ok();
                return ExitCode::from(125);
            }
        };
        let global_raw = if global_config.exists() {
            match read_raw_config(LayerKind::Global, global_config) {
                Ok(r) => Some(r),
                Err(e) => {
                    writeln!(out, "error: {e}").ok();
                    return ExitCode::from(125);
                }
            }
        } else {
            None
        };

        let unbound = unbound_repo_labels(&repo_raw);
        let bound_globally = bound_global_labels(global_raw.as_ref());
        let content = config::local_stub(&unbound, &bound_globally);
        let summary = render_local_bindings_summary(&unbound, &bound_globally);
        (content, summary, false)
    } else {
        (
            config::local_config_template_standalone().to_string(),
            String::new(),
            true,
        )
    };

    if let Err(e) = std::fs::write(&local_path, &content) {
        writeln!(
            out,
            "error: failed to write {}: {e}",
            display_path(&local_path, home)
        )
        .ok();
        return ExitCode::from(125);
    }

    if standalone {
        writeln!(
            out,
            "created {} (no airlock.toml here, so a standalone config)",
            display_path(&local_path, home)
        )
        .ok();
    } else {
        writeln!(out, "created {}", display_path(&local_path, home)).ok();
        if !bindings_summary.is_empty() {
            write!(out, "{bindings_summary}").ok();
        }
    }

    let ignored = git.check_ignore(cwd, config::local_config_filename());
    write!(out, "{}", render_git_ignore_note(ignored)).ok();

    ExitCode::SUCCESS
}

/// `airlock init [--local | --global]`.
///
/// Writing is always attempted and fails if the target file already
/// exists; the caller is responsible for refusing `--global` inside the
/// agent sandbox (`docs/airlock-v2-design.md`, "Commands refused inside the
/// sandbox") before calling this with [`InitKind::Global`].
pub fn init_cmd(
    kind: InitKind,
    cwd: &Path,
    home: &Path,
    global_config: &Path,
    git: &dyn GitRunner,
    out: &mut dyn Write,
) -> ExitCode {
    match kind {
        InitKind::Plain => init_plain(cwd, home, out),
        InitKind::Global => init_global(home, global_config, out),
        InitKind::Local => init_local(cwd, home, global_config, git, out),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use tempfile::tempdir;

    // ── display_path ────────────────────────────────────────────────────

    #[test]
    fn display_path_substitutes_home() {
        let home = Path::new("/home/me");
        assert_eq!(
            display_path(Path::new("/home/me/src/app"), home),
            "~/src/app"
        );
        assert_eq!(display_path(home, home), "~");
        assert_eq!(
            display_path(Path::new("/opt/homebrew/share"), home),
            "/opt/homebrew/share"
        );
    }

    // ── table ────────────────────────────────────────────────────────────

    #[test]
    fn table_pads_columns_and_trims_trailing_whitespace() {
        let rows = vec![
            vec!["a".to_string(), "bb".to_string(), "".to_string()],
            vec!["aaa".to_string(), "b".to_string(), "c".to_string()],
        ];
        let out = table(&rows);
        assert_eq!(out, "a    bb\naaa  b   c\n");
    }

    #[test]
    fn table_empty_is_empty_string() {
        assert_eq!(table(&[]), "");
    }

    // ── render_config ────────────────────────────────────────────────────

    /// Collapses runs of whitespace to a single space, so a test can assert
    /// on a line's content and column order without depending on `table`'s
    /// exact padding (which varies with the width of every other row in the
    /// same section).
    fn norm_lines(s: &str) -> Vec<String> {
        s.lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect()
    }

    fn layer(kind: LayerKind, path: &str, state: ApprovalState) -> LayerRow {
        LayerRow {
            kind,
            path_display: path.to_string(),
            state,
        }
    }

    #[test]
    fn render_config_matches_the_ux_doc_shape() {
        // Mirrors docs/airlock-v2-ux.md, "`airlock config` output".
        let report = ConfigReport {
            layers: vec![
                layer(LayerKind::Global, "~/.config/airlock/airlock.toml", ApprovalState::UserFile),
                layer(LayerKind::Repo, "~/src/app/airlock.toml", ApprovalState::Trusted),
                layer(LayerKind::Local, "~/src/app/airlock.local.toml", ApprovalState::ChangedSinceTrusted),
            ],
            secrets: vec![
                SecretRow {
                    label: "GH_TOKEN".to_string(),
                    layer_text: "local → global".to_string(),
                    source_text: "command: op read op://Private/GitHub/token".to_string(),
                    unapproved: true,
                },
                SecretRow {
                    label: "CLOUDFLARE_API_TOKEN".to_string(),
                    layer_text: "local".to_string(),
                    source_text: "command: op read op://Private/Cloudflare/token".to_string(),
                    unapproved: true,
                },
            ],
            tools: vec![
                ToolRow {
                    name: "aws".to_string(),
                    layer_text: "global".to_string(),
                    description: "AWS CLI".to_string(),
                    secret_env: vec![],
                    access_text: "default".to_string(),
                    replaces_global: false,
                    unapproved: false,
                },
                ToolRow {
                    name: "gh".to_string(),
                    layer_text: "repo".to_string(),
                    description: "GitHub CLI".to_string(),
                    secret_env: vec![("GH_TOKEN".to_string(), "GH_TOKEN".to_string())],
                    access_text: "default".to_string(),
                    replaces_global: false,
                    unapproved: false,
                },
                ToolRow {
                    name: "psql".to_string(),
                    layer_text: "local".to_string(),
                    description: "Postgres shell".to_string(),
                    secret_env: vec![],
                    access_text: "none (local)".to_string(),
                    replaces_global: false,
                    unapproved: true,
                },
            ],
            settings: vec![
                SettingRow::Timeout { value: 120, layer_text: "repo".to_string() },
                SettingRow::FilesystemPath {
                    kind: "read",
                    path: "/opt/homebrew/share".to_string(),
                    layer_text: "repo".to_string(),
                },
                SettingRow::PassthroughEnv { name: "COLORTERM".to_string(), layer_text: "global".to_string() },
                SettingRow::PassthroughEnv { name: "NO_COLOR".to_string(), layer_text: "repo".to_string() },
                SettingRow::AgentEnv {
                    key: "LOG_LEVEL".to_string(),
                    value_display: "\"debug\"".to_string(),
                    layer_text: "local".to_string(),
                    overrides: Some("repo".to_string()),
                    unapproved: true,
                },
            ],
            kits: vec![],
            notes: vec![
                "airlock.local.toml changed since you trusted it; the next session start asks about it.".to_string(),
            ],
        };

        let out = render_config(&report);
        let lines = norm_lines(&out);

        assert!(out.starts_with("layers\n"));
        assert!(lines.contains(&"global ~/.config/airlock/airlock.toml user file".to_string()));
        assert!(lines.contains(&"repo ~/src/app/airlock.toml trusted".to_string()));
        assert!(
            lines.contains(&"local ~/src/app/airlock.local.toml changed since trusted".to_string())
        );

        assert!(out.contains("secrets\n"));
        assert!(
            lines.contains(
                &"GH_TOKEN local → global command: op read op://Private/GitHub/token (unapproved)"
                    .to_string()
            )
        );

        assert!(out.contains("tools\n"));
        assert!(
            lines.contains(
                &"gh repo GitHub CLI GH_TOKEN = <secret \"GH_TOKEN\"> default".to_string()
            )
        );
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("psql local Postgres shell") && l.ends_with("(unapproved)"))
        );
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("psql") && l.contains("none (local)"))
        );

        assert!(out.contains("settings\n"));
        assert!(lines.contains(&"timeout 120 repo".to_string()));
        assert!(lines.contains(&"agent.passthrough_env COLORTERM global".to_string()));
        // The second passthrough_env row repeats no label.
        assert!(lines.contains(&"NO_COLOR repo".to_string()));
        assert!(lines.contains(
            &"agent.env.LOG_LEVEL \"debug\" local (overrides repo) (unapproved)".to_string()
        ));

        assert!(out.ends_with(
            "airlock.local.toml changed since you trusted it; the next session start asks about it.\n"
        ));
    }

    #[test]
    fn render_config_with_only_layers_has_no_empty_sections() {
        let report = ConfigReport {
            layers: vec![layer(
                LayerKind::Repo,
                "airlock.toml",
                ApprovalState::Trusted,
            )],
            ..Default::default()
        };
        let out = render_config(&report);
        assert_eq!(out, "layers\n  repo  airlock.toml  trusted\n");
    }

    // ── build_config_report: access level provenance ─────────────────────

    #[test]
    fn build_config_report_shows_tool_access_with_provenance() {
        let tmp = tempdir().unwrap();
        let home = tmp.path();
        let root = home.join("project");
        std::fs::create_dir(&root).unwrap();
        let global = home.join("global.toml");
        std::fs::write(&global, "").unwrap();
        std::fs::write(
            root.join("airlock.toml"),
            r#"
access = "system"

[tools.aws]
description = "AWS CLI"

[tools.gh]
description = "GitHub CLI"
access = "none"
"#,
        )
        .unwrap();

        let loaded = layers::load_layers(&DiscoveryMode::Default, &root, home, &global).unwrap();
        let ctx = MergeContext {
            root: loaded.root.clone(),
            home: home.to_path_buf(),
            tool_state_base: home.to_path_buf(),
        };
        let merged = layers::merge(&loaded, &ctx).unwrap();
        let report = build_config_report(&merged, &[]);

        // "aws" doesn't set its own access — it shows the effective
        // top-level default and which layer set it.
        let aws = report.tools.iter().find(|t| t.name == "aws").unwrap();
        assert_eq!(aws.access_text, "system (repo)");

        // "gh" overrides access on the tool itself — provenance is the
        // tool's own layer, independent of the top-level setting.
        let gh = report.tools.iter().find(|t| t.name == "gh").unwrap();
        assert_eq!(gh.access_text, "none (repo)");

        assert!(report.settings.iter().any(|s| matches!(
            s,
            SettingRow::Access { value, layer_text }
                if value == "system" && layer_text == "repo"
        )));
    }

    #[test]
    fn build_config_report_tool_access_defaults_when_nothing_sets_it() {
        let tmp = tempdir().unwrap();
        let home = tmp.path();
        let root = home.join("project");
        std::fs::create_dir(&root).unwrap();
        let global = home.join("global.toml");
        std::fs::write(&global, "").unwrap();
        std::fs::write(
            root.join("airlock.toml"),
            "[tools.aws]\ndescription = \"AWS CLI\"\n",
        )
        .unwrap();

        let loaded = layers::load_layers(&DiscoveryMode::Default, &root, home, &global).unwrap();
        let ctx = MergeContext {
            root: loaded.root.clone(),
            home: home.to_path_buf(),
            tool_state_base: home.to_path_buf(),
        };
        let merged = layers::merge(&loaded, &ctx).unwrap();
        let report = build_config_report(&merged, &[]);

        let aws = report.tools.iter().find(|t| t.name == "aws").unwrap();
        assert_eq!(aws.access_text, "default");
        assert!(
            !report
                .settings
                .iter()
                .any(|s| matches!(s, SettingRow::Access { .. }))
        );
    }

    #[test]
    fn render_config_tool_replacing_global_is_marked() {
        let report = ConfigReport {
            layers: vec![layer(
                LayerKind::Repo,
                "airlock.toml",
                ApprovalState::Trusted,
            )],
            tools: vec![ToolRow {
                name: "gh".to_string(),
                layer_text: "repo".to_string(),
                description: "GitHub CLI".to_string(),
                secret_env: vec![],
                access_text: "default".to_string(),
                replaces_global: true,
                unapproved: false,
            }],
            ..Default::default()
        };
        let out = render_config(&report);
        // Matches docs/airlock-v2-design.md, "Duplicate tool".
        assert!(
            norm_lines(&out).contains(&"gh repo GitHub CLI default (replaces global)".to_string())
        );
    }

    #[test]
    fn render_config_escapes_untrusted_control_characters() {
        // A description from an unapproved config file could carry a bidi
        // override (U+202E) or an ESC byte that starts an ANSI escape —
        // `airlock config` must never let either reach the terminal raw.
        let report = ConfigReport {
            layers: vec![layer(
                LayerKind::Repo,
                "airlock.toml",
                ApprovalState::NotTrustedYet,
            )],
            tools: vec![ToolRow {
                name: "gh".to_string(),
                layer_text: "repo".to_string(),
                description: "evil\u{202e}desc\x1b[31m".to_string(),
                secret_env: vec![],
                access_text: "default".to_string(),
                replaces_global: false,
                unapproved: true,
            }],
            ..Default::default()
        };
        let out = render_config(&report);
        assert!(!out.contains('\u{202e}'));
        assert!(!out.contains('\x1b'));
        assert!(out.contains("\\u{202e}"));
        assert!(out.contains("\\u{1b}"));
    }

    // ── render_paths ─────────────────────────────────────────────────────

    #[test]
    fn render_paths_lists_one_per_line() {
        let report = PathsReport {
            global_config: "~/.config/airlock/airlock.toml".to_string(),
            repo: Some("~/src/app/airlock.toml".to_string()),
            local: None,
            trust_store: "~/.local/state/airlock/trust".to_string(),
            runtime_dir: "/run/user/501/airlock".to_string(),
            socket: "/run/user/501/airlock/airlock.sock".to_string(),
            tool_state_base: "~/.cache/airlock".to_string(),
        };
        let out = render_paths(&report);
        assert!(out.contains("global config  ~/.config/airlock/airlock.toml\n"));
        assert!(out.contains("repo config    ~/src/app/airlock.toml\n"));
        assert!(!out.contains("local config"));
        assert!(out.contains("socket         /run/user/501/airlock/airlock.sock\n"));
    }

    // ── render_status ────────────────────────────────────────────────────

    #[test]
    fn render_status_daemon_not_running() {
        assert_eq!(render_status(None, None, &[], 0, 0), "daemon not running\n");
    }

    #[test]
    fn render_status_matches_the_ux_every_day_transcript() {
        // Arbitrary fixed instant; the daemon started 2h before `now` below.
        let daemon_started = 1_700_000_000u64;
        let daemon = DaemonStatus {
            pid: 48211,
            version: "0.6.0".to_string(),
            mode: DaemonMode::Automatic,
            started_unix: Some(daemon_started),
            addr: "unix:///run/user/501/airlock/airlock.sock".to_string(),
        };
        let project = ProjectStatus {
            root_display: "~/src/app".to_string(),
            layers: vec![
                layer(
                    LayerKind::Global,
                    "~/.config/airlock/airlock.toml",
                    ApprovalState::UserFile,
                ),
                layer(LayerKind::Repo, "airlock.toml", ApprovalState::Trusted),
                layer(
                    LayerKind::Local,
                    "airlock.local.toml",
                    ApprovalState::Trusted,
                ),
            ],
        };
        // Arbitrary fixed instants, 48 minutes apart; the exact HH:MM they
        // render as depends on the test runner's time zone, so the
        // assertions below compute the expected label with the function
        // under test rather than hard-coding one (which the UX transcript's
        // `10:42`/`11:30` are only an example of, in some unstated zone).
        let claude_started = daemon_started + 3600; // 1h after the daemon started.
        let codex_started = claude_started + 48 * 60;
        let sessions = vec![
            SessionRow {
                id: "7f3a9c".to_string(),
                name: "claude".to_string(),
                started_unix: claude_started,
                execs: 14,
                config_changed: false,
            },
            SessionRow {
                id: "b20e51".to_string(),
                name: "codex".to_string(),
                started_unix: codex_started,
                execs: 2,
                config_changed: false,
            },
        ];
        let now = daemon_started + 2 * 3600;

        let out = render_status(Some(&daemon), Some(&project), &sessions, 3, now);
        let lines = norm_lines(&out);

        assert!(out.starts_with("daemon    running, PID 48211, started on demand 2h ago\n"));
        assert!(lines.contains(&"address unix:///run/user/501/airlock/airlock.sock".to_string()));
        assert!(lines.contains(&"project ~/src/app".to_string()));
        assert!(lines.contains(&"global ~/.config/airlock/airlock.toml user file".to_string()));
        assert!(lines.contains(&"sessions 2 here, 3 in total".to_string()));
        assert!(lines.contains(&format!(
            "7f3a9c claude {} 14 execs",
            format_hhmm_local(claude_started)
        )));
        assert!(lines.contains(&format!(
            "b20e51 codex {} 2 execs",
            format_hhmm_local(codex_started)
        )));
        // Still a sane HH:MM shape regardless of zone.
        for s in [claude_started, codex_started] {
            let hhmm = format_hhmm_local(s);
            assert_eq!(hhmm.len(), 5);
            assert_eq!(hhmm.as_bytes()[2], b':');
        }
    }

    #[test]
    fn render_status_manual_and_service_mode_text() {
        let manual = DaemonStatus {
            pid: 1,
            version: "x".to_string(),
            mode: DaemonMode::Manual,
            started_unix: None,
            addr: "unix:///sock".to_string(),
        };
        assert!(render_status(Some(&manual), None, &[], 0, 0).contains("started by hand"));

        let service = DaemonStatus {
            pid: 811,
            version: "x".to_string(),
            mode: DaemonMode::Service,
            started_unix: None,
            addr: "unix:///sock".to_string(),
        };
        assert!(render_status(Some(&service), None, &[], 0, 0).contains(SERVICE_LABEL));
    }

    #[test]
    fn render_status_marks_config_changed() {
        let daemon = DaemonStatus {
            pid: 1,
            version: "x".to_string(),
            mode: DaemonMode::Manual,
            started_unix: None,
            addr: "unix:///sock".to_string(),
        };
        let sessions = vec![SessionRow {
            id: "aaaaaa".to_string(),
            name: "claude".to_string(),
            started_unix: 0,
            execs: 0,
            config_changed: true,
        }];
        let out = render_status(Some(&daemon), None, &sessions, 1, 0);
        assert!(out.contains("config changed"));
    }

    // ── status_cmd ───────────────────────────────────────────────────────

    struct FakeProbe {
        hello: Option<DaemonStatus>,
        sessions: Vec<SessionInfo>,
    }

    impl DaemonProbe for FakeProbe {
        fn hello(&mut self) -> Option<DaemonStatus> {
            self.hello.clone()
        }
        fn list_sessions(&mut self) -> Vec<SessionInfo> {
            self.sessions.clone()
        }
    }

    #[test]
    fn status_cmd_exit_3_when_daemon_not_running() {
        let mut out = Vec::new();
        let mut probe = FakeProbe {
            hello: None,
            sessions: vec![],
        };
        let tmp = tempdir().unwrap();
        let code = status_cmd(
            &StatusOptions::default(),
            tmp.path(),
            tmp.path(),
            &tmp.path().join("no-global.toml"),
            &tmp.path().join("trust"),
            &mut probe,
            0,
            &mut out,
        );
        assert_eq!(code, ExitCode::from(3));
        assert_eq!(String::from_utf8(out).unwrap(), "daemon not running\n");
    }

    #[test]
    fn status_cmd_exit_0_when_daemon_running() {
        let mut out = Vec::new();
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("airlock.toml"), "[tools.t]\n").unwrap();
        let mut probe = FakeProbe {
            hello: Some(DaemonStatus {
                pid: 1,
                version: "x".to_string(),
                mode: DaemonMode::Manual,
                started_unix: None,
                addr: "unix:///sock".to_string(),
            }),
            sessions: vec![],
        };
        let code = status_cmd(
            &StatusOptions::default(),
            tmp.path(),
            tmp.path(),
            &tmp.path().join("no-global.toml"),
            &tmp.path().join("trust"),
            &mut probe,
            0,
            &mut out,
        );
        assert_eq!(code, ExitCode::SUCCESS);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("started by hand"));
        assert!(text.contains("sessions  0 here, 0 in total"));
    }

    // ── init_cmd ─────────────────────────────────────────────────────────

    struct FakeGit {
        ignored: RefCell<Option<Option<bool>>>,
    }

    impl GitRunner for FakeGit {
        fn check_ignore(&self, _cwd: &Path, _file: &str) -> Option<bool> {
            self.ignored.borrow().unwrap_or(None)
        }
    }

    fn fake_git(answer: Option<bool>) -> FakeGit {
        FakeGit {
            ignored: RefCell::new(Some(answer)),
        }
    }

    #[test]
    fn init_plain_writes_template_and_hints_next_step() {
        let tmp = tempdir().unwrap();
        let mut out = Vec::new();
        let git = fake_git(None);
        let code = init_cmd(
            InitKind::Plain,
            tmp.path(),
            tmp.path(),
            &tmp.path().join(".config/airlock/airlock.toml"),
            &git,
            &mut out,
        );
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(tmp.path().join("airlock.toml").exists());
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("created "));
        assert!(text.contains("airlock run --profile claude"));
    }

    #[test]
    fn init_plain_fails_if_file_exists() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("airlock.toml"), "x").unwrap();
        let mut out = Vec::new();
        let git = fake_git(None);
        let code = init_cmd(
            InitKind::Plain,
            tmp.path(),
            tmp.path(),
            &tmp.path().join(".config/airlock/airlock.toml"),
            &git,
            &mut out,
        );
        assert_eq!(code, ExitCode::from(125));
        assert!(String::from_utf8(out).unwrap().starts_with("error: "));
    }

    #[test]
    fn init_global_creates_dir_and_file_mode_0700() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempdir().unwrap();
        let xdg = tmp.path().join("xdg-config");
        let mut out = Vec::new();
        let git = fake_git(None);
        let code = init_cmd(
            InitKind::Global,
            tmp.path(),
            tmp.path(),
            &xdg.join("airlock").join("airlock.toml"),
            &git,
            &mut out,
        );
        assert_eq!(code, ExitCode::SUCCESS);
        let path = xdg.join("airlock").join("airlock.toml");
        assert!(path.exists());
        let mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn init_local_standalone_when_no_repo_file() {
        let tmp = tempdir().unwrap();
        let mut out = Vec::new();
        let git = fake_git(Some(false));
        let code = init_cmd(
            InitKind::Local,
            tmp.path(),
            tmp.path(),
            &tmp.path().join(".config/airlock/airlock.toml"),
            &git,
            &mut out,
        );
        assert_eq!(code, ExitCode::SUCCESS);
        let content = std::fs::read_to_string(tmp.path().join("airlock.local.toml")).unwrap();
        assert_eq!(content, config::local_config_template_standalone());
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("(no airlock.toml here, so a standalone config)"));
        assert!(text.contains("warning: airlock.local.toml is not ignored by git"));
        assert!(text.contains("echo airlock.local.toml >> ~/.config/git/ignore"));
    }

    #[test]
    fn init_local_matches_the_joining_a_team_repo_transcript() {
        let tmp = tempdir().unwrap();
        std::fs::write(
            tmp.path().join("airlock.toml"),
            "[secrets.GH_TOKEN]\ndescription = \"GitHub token with read access to acme/app\"\n\n\
             [secrets.CLOUDFLARE_API_TOKEN]\ndescription = \"Cloudflare token, Zone:Read on acme.dev\"\n",
        )
        .unwrap();
        let xdg = tmp.path().join("xdg-config");
        std::fs::create_dir_all(xdg.join("airlock")).unwrap();
        std::fs::write(
            xdg.join("airlock").join("airlock.toml"),
            "[secrets.GH_TOKEN]\nsource = \"command\"\ncommand = [\"op\", \"read\", \"op://Private/GitHub/token\"]\n",
        )
        .unwrap();

        let mut out = Vec::new();
        let git = fake_git(Some(true));
        let code = init_cmd(
            InitKind::Local,
            tmp.path(),
            tmp.path(),
            &xdg.join("airlock").join("airlock.toml"),
            &git,
            &mut out,
        );
        assert_eq!(code, ExitCode::SUCCESS);

        let content = std::fs::read_to_string(tmp.path().join("airlock.local.toml")).unwrap();
        assert!(content.contains("[secrets.GH_TOKEN]\nfrom = \"global\"\n"));
        assert!(content.contains("CLOUDFLARE_API_TOKEN"));

        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("created "));
        assert!(!text.contains("standalone"));
        assert!(
            text.contains("GH_TOKEN              from = \"global\" (your global config binds it)")
        );
        assert!(text.contains("CLOUDFLARE_API_TOKEN  not bound: edit airlock.local.toml"));
        assert!(text.contains("airlock.local.toml is ignored by git\n"));
    }

    #[test]
    fn init_local_fails_if_file_exists() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("airlock.local.toml"), "x").unwrap();
        let mut out = Vec::new();
        let git = fake_git(None);
        let code = init_cmd(
            InitKind::Local,
            tmp.path(),
            tmp.path(),
            &tmp.path().join(".config/airlock/airlock.toml"),
            &git,
            &mut out,
        );
        assert_eq!(code, ExitCode::from(125));
    }

    #[test]
    fn init_local_refuses_a_symlinked_repo_config() {
        let tmp = tempdir().unwrap();
        let elsewhere = tmp.path().join("elsewhere.toml");
        std::fs::write(&elsewhere, "[tools.gh]\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, tmp.path().join("airlock.toml")).unwrap();
        let mut out = Vec::new();
        let git = fake_git(None);
        let code = init_cmd(
            InitKind::Local,
            tmp.path(),
            tmp.path(),
            &tmp.path().join(".config/airlock/airlock.toml"),
            &git,
            &mut out,
        );
        assert_eq!(code, ExitCode::from(125));
        assert!(!tmp.path().join("airlock.local.toml").exists());
    }

    #[test]
    fn render_local_bindings_summary_matches_ux_doc() {
        let labels = vec![
            ("GH_TOKEN".to_string(), None),
            ("CLOUDFLARE_API_TOKEN".to_string(), None),
        ];
        let out = render_local_bindings_summary(&labels, &["GH_TOKEN".to_string()]);
        assert_eq!(
            out,
            "  GH_TOKEN              from = \"global\" (your global config binds it)\n  CLOUDFLARE_API_TOKEN  not bound: edit airlock.local.toml\n"
        );
    }

    #[test]
    fn render_git_ignore_note_variants() {
        assert_eq!(render_git_ignore_note(None), "");
        assert_eq!(
            render_git_ignore_note(Some(true)),
            "airlock.local.toml is ignored by git\n"
        );
        assert_eq!(
            render_git_ignore_note(Some(false)),
            "warning: airlock.local.toml is not ignored by git. To ignore it in every repo:\n         echo airlock.local.toml >> ~/.config/git/ignore\n"
        );
    }

    // ── build_kit_rows ────────────────────────────────────────────────

    fn merge_for(root: &Path, home: &Path, tool_state_base: &Path) -> MergedConfig {
        let no_global = home.join("no-such-global.toml");
        let loaded = layers::load_layers(&DiscoveryMode::Default, root, home, &no_global).unwrap();
        let ctx = MergeContext {
            root: loaded.root.clone(),
            home: home.to_path_buf(),
            tool_state_base: tool_state_base.to_path_buf(),
        };
        layers::merge(&loaded, &ctx).unwrap()
    }

    #[test]
    fn build_kit_rows_shows_isolated_builtin_env_and_layer() {
        let tmp = tempdir().unwrap();
        let home = tmp.path().join("home");
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("airlock.toml"), "[agent]\nkits = [\"rust\"]\n").unwrap();
        let tool_state_base = tmp.path().join("cache/airlock");

        let merged = merge_for(&project, &home, &tool_state_base);
        let rows = build_kit_rows(
            &merged,
            &home,
            &tool_state_base,
            &std::collections::BTreeMap::new(),
        )
        .unwrap();

        assert_eq!(rows.len(), 1);
        let rust = &rows[0];
        assert_eq!(rust.name, "rust");
        assert_eq!(rust.layer_text, "repo");
        assert_eq!(rust.mode, "isolated");
        assert!(rust.env.iter().any(|(k, _)| k == "CARGO_HOME"));
        assert!(rust.read.iter().any(|p| p.ends_with(".cargo/bin")));
    }

    #[test]
    fn build_kit_rows_shows_shared_builtin_with_no_env() {
        let tmp = tempdir().unwrap();
        let home = tmp.path().join("home");
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("airlock.toml"), "[agent]\nkits = [\"go\"]\n").unwrap();
        std::fs::write(
            project.join("airlock.local.toml"),
            "[kits.go]\nmode = \"shared\"\n",
        )
        .unwrap();
        let tool_state_base = tmp.path().join("cache/airlock");

        let merged = merge_for(&project, &home, &tool_state_base);
        let rows = build_kit_rows(
            &merged,
            &home,
            &tool_state_base,
            &std::collections::BTreeMap::new(),
        )
        .unwrap();

        assert_eq!(rows.len(), 1);
        let go = &rows[0];
        assert_eq!(go.mode, "shared");
        assert!(go.env.is_empty());
        assert_eq!(go.layer_text, "local");
        assert!(go.write.iter().any(|p| p.ends_with("pkg/mod")));
    }

    #[test]
    fn build_kit_rows_surfaces_unknown_kit_as_an_error() {
        let tmp = tempdir().unwrap();
        let home = tmp.path().join("home");
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("airlock.toml"), "[agent]\nkits = [\"nope\"]\n").unwrap();
        let tool_state_base = tmp.path().join("cache/airlock");

        let merged = merge_for(&project, &home, &tool_state_base);
        let err = build_kit_rows(
            &merged,
            &home,
            &tool_state_base,
            &std::collections::BTreeMap::new(),
        )
        .unwrap_err();
        assert!(matches!(err, config::ConfigError::UnknownKit { .. }));
    }
}
