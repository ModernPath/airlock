//! Config layering for Airlock v2: discovery of the global, parent, repo
//! and local files, merging them into one config, and the cross-layer rules
//! that decide which tool or secret binding wins.
//!
//! This module reads no environment variables and creates nothing on disk:
//! every input that would otherwise come from the process environment (the
//! home directory, the working directory, the global config's location, the
//! tool-state base) is a parameter, supplied by the launcher. That keeps
//! layering deterministic and testable, and keeps the daemon's own config
//! resolution ([`crate::config::resolve_wire_config`]) free of project
//! discovery entirely — only the launcher ever calls into this module.
//!
//! See "Config layers" and "Trust" in `docs/airlock-v2-design.md` for the
//! rules this module implements, and "Messages → Launcher" in
//! `docs/airlock-v2-ux.md` for the exact wording of the errors below.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use crate::config::{
    self, ConfigError, EnvOwner, RawConfig, RawEnvValue, RawKitConfig, RawSecretRef, RawSecretSpec,
    RawToolConfig, SecretSource,
};

// ─── Discovery ──────────────────────────────────────────────────────────────

/// How the project's config layers are found, set by `--config` /
/// `--no-project-config` or left at the default walk.
#[derive(Debug, Clone)]
pub enum DiscoveryMode {
    /// Walk up from the working directory to `$HOME` (inclusive) looking for
    /// `airlock.toml` or `airlock.local.toml`, then on up from the root for
    /// parent configs that set `cascade = true`.
    Default,
    /// Use exactly this file as the project's only (repo-position) layer.
    /// No global layer, no local layer, no parent configs. The project root
    /// is its parent directory.
    ConfigFile(PathBuf),
    /// Ignore `airlock.toml` and `airlock.local.toml` even if present. The
    /// project root is the canonical working directory; the config is the
    /// global layer alone, which may be absent.
    NoProjectConfig,
}

/// Which file a [`LayerFile`] came from.
///
/// `ConfigFile` sits in the same merge "slot" as `Repo` (project-declared
/// tools and secret labels), but is tracked separately because it has its
/// own trust-store slot (keyed by file name, not always `airlock.toml`) and
/// its own display name.
pub use crate::protocol::LayerKind;

/// One config file, read once. The same bytes are hashed (for the trust
/// store) and parsed (for merging) — there is no separate read between the
/// approval check and use.
#[derive(Debug, Clone)]
pub struct LayerFile {
    pub kind: LayerKind,
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

impl LayerFile {
    pub(crate) fn read(kind: LayerKind, path: &Path, euid: u32) -> Result<Self, ConfigError> {
        let contents = config::read_config_securely(path, euid)?;
        let bytes = contents.into_bytes();
        let sha256 = config::sha256_hex(&bytes);
        Ok(LayerFile {
            kind,
            path: path.to_path_buf(),
            bytes,
            sha256,
        })
    }

    pub(crate) fn parse(&self) -> Result<RawConfig, ConfigError> {
        let text = std::str::from_utf8(&self.bytes).map_err(|_| ConfigError::ReadError {
            path: self.path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, "not valid UTF-8"),
        })?;
        toml::from_str(text).map_err(|e| ConfigError::ParseError {
            path: self.path.clone(),
            source: e,
        })
    }
}

/// A directory above the project root whose config sets `cascade = true`,
/// and so applies to the project as a parent config.
#[derive(Debug)]
pub struct ParentLayers {
    /// The canonical directory. Relative paths in its files resolve against
    /// it, and its files' trust-store slots are keyed by it.
    pub dir: PathBuf,
    /// Its `airlock.toml`, with [`LayerKind::Repo`] as its kind: within its
    /// own directory it follows the repo layer's rules.
    pub repo: Option<LayerFile>,
    /// Its `airlock.local.toml`, with [`LayerKind::Local`] as its kind.
    pub local: Option<LayerFile>,
}

/// The layers found for one project, before merging.
#[derive(Debug)]
pub struct LoadedLayers {
    /// The project root, which is also the sandbox root.
    pub root: PathBuf,
    pub global: Option<LayerFile>,
    /// Parent configs that cascade to this project, outermost first. Always
    /// empty under `--config` and `--no-project-config`.
    pub parents: Vec<ParentLayers>,
    /// The project-declared layer: `airlock.toml`, or (in
    /// [`DiscoveryMode::ConfigFile`]) the `--config` file, in which case its
    /// [`LayerFile::kind`] is [`LayerKind::ConfigFile`] rather than
    /// [`LayerKind::Repo`].
    pub repo: Option<LayerFile>,
    pub local: Option<LayerFile>,
}

/// One file that must be approved before a session uses it.
pub struct ApprovableFile<'a> {
    /// The directory its trust-store slot is keyed by: the project root, or
    /// the parent directory the file sits in.
    pub dir: &'a Path,
    /// How it is shown and sent on the wire: [`LayerKind::Parent`] for
    /// either of a parent's files, the file's own kind otherwise.
    pub kind: LayerKind,
    pub file: &'a LayerFile,
}

impl LoadedLayers {
    /// Every file that needs approval: each parent's, outermost first, then
    /// the project's own. The global file is never approved.
    pub fn approvable_files(&self) -> Vec<ApprovableFile<'_>> {
        let mut out = Vec::new();
        for parent in &self.parents {
            for file in [&parent.repo, &parent.local].into_iter().flatten() {
                out.push(ApprovableFile {
                    dir: &parent.dir,
                    kind: LayerKind::Parent,
                    file,
                });
            }
        }
        for file in [&self.repo, &self.local].into_iter().flatten() {
            out.push(ApprovableFile {
                dir: &self.root,
                kind: file.kind,
                file,
            });
        }
        out
    }
}

/// Read the project's config layers.
///
/// `home` and `global_config_path` are the anchor-derived inputs that would
/// otherwise come from the environment — the caller (the launcher) resolves
/// them once, from `crate::anchors`, and passes the literal paths down, so
/// this function never reads `$HOME` or `$XDG_*` itself.
pub fn load_layers(
    mode: &DiscoveryMode,
    cwd: &Path,
    home: &Path,
    global_config_path: &Path,
) -> Result<LoadedLayers, ConfigError> {
    let euid = config::current_euid();
    let global = load_optional_layer(global_config_path, LayerKind::Global, euid)?;

    match mode {
        DiscoveryMode::NoProjectConfig => {
            let root = canonicalize_dir(cwd)?;
            Ok(LoadedLayers {
                root,
                global,
                parents: Vec::new(),
                repo: None,
                local: None,
            })
        }
        DiscoveryMode::ConfigFile(path) => {
            let parent = path.parent().ok_or_else(|| ConfigError::ReadError {
                path: path.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "config path has no parent directory",
                ),
            })?;
            let root = canonicalize_dir(parent)?;
            let repo = LayerFile::read(LayerKind::ConfigFile, path, euid)?;
            Ok(LoadedLayers {
                root,
                global,
                parents: Vec::new(),
                repo: Some(repo),
                local: None,
            })
        }
        DiscoveryMode::Default => {
            let (root, repo_path, local_path) = discover_project_root(cwd, home, euid)?;
            let repo = repo_path
                .map(|p| LayerFile::read(LayerKind::Repo, &p, euid))
                .transpose()?;
            let local = local_path
                .map(|p| LayerFile::read(LayerKind::Local, &p, euid))
                .transpose()?;
            // A project file that does not parse fails in `merge` instead,
            // after `airlock config` has shown which layers were found.
            let inherit = inheritance_flags(repo.as_ref(), local.as_ref())
                .map_or(true, |(_, inherit)| inherit);
            let parents = if inherit {
                discover_parents(&root, home, euid)?
            } else {
                Vec::new()
            };
            Ok(LoadedLayers {
                root,
                global,
                parents,
                repo,
                local,
            })
        }
    }
}

fn canonicalize_dir(dir: &Path) -> Result<PathBuf, ConfigError> {
    std::fs::canonicalize(dir).map_err(|e| ConfigError::CanonicalizationError {
        path: dir.to_path_buf(),
        source: e,
    })
}

fn load_optional_layer(
    path: &Path,
    kind: LayerKind,
    euid: u32,
) -> Result<Option<LayerFile>, ConfigError> {
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(LayerFile::read(kind, path, euid)?))
}

/// Walk from `cwd` upward to `home` (inclusive), looking for the first
/// directory holding `airlock.toml` or `airlock.local.toml` owned by
/// `euid`. Returns the canonical root and which of the two files are
/// present there.
fn discover_project_root(
    cwd: &Path,
    home: &Path,
    euid: u32,
) -> Result<(PathBuf, Option<PathBuf>, Option<PathBuf>), ConfigError> {
    let start_canonical = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let home_canonical = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());

    let mut current = start_canonical;
    loop {
        let repo_candidate = current.join(config::config_filename());
        let local_candidate = current.join(config::local_config_filename());
        let repo_present = config::is_owned_by(&repo_candidate, euid);
        let local_present = config::is_owned_by(&local_candidate, euid);

        if repo_present || local_present {
            let root = canonicalize_dir(&current)?;
            return Ok((
                root,
                repo_present.then_some(repo_candidate),
                local_present.then_some(local_candidate),
            ));
        }

        if current == home_canonical {
            break;
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent.to_path_buf(),
            _ => break,
        }
    }

    Err(ConfigError::NoProjectConfig {
        start_dir: cwd.to_path_buf(),
        home_dir: home.to_path_buf(),
    })
}

/// A directory's `cascade` and `inherit`, its local file's over its repo
/// file's: whether its config applies to projects below it (default no),
/// and whether it takes parent configs itself (default yes).
fn inheritance_flags(
    repo: Option<&LayerFile>,
    local: Option<&LayerFile>,
) -> Result<(bool, bool), ConfigError> {
    let repo = repo.map(LayerFile::parse).transpose()?;
    let local = local.map(LayerFile::parse).transpose()?;
    let flag = |get: fn(&RawConfig) -> Option<bool>| {
        local
            .as_ref()
            .and_then(get)
            .or_else(|| repo.as_ref().and_then(get))
    };
    Ok((
        flag(|c| c.cascade).unwrap_or(false),
        flag(|c| c.inherit).unwrap_or(true),
    ))
}

/// Walk up from just above `root` to just below `home`, collecting each
/// directory whose config sets `cascade = true`, until one of them sets
/// `inherit = false`. A directory whose config does not cascade is skipped,
/// not a stop. `$HOME` itself is never a parent — the global config already
/// covers everything under it — and a root outside `$HOME` has none.
/// Outermost first.
fn discover_parents(root: &Path, home: &Path, euid: u32) -> Result<Vec<ParentLayers>, ConfigError> {
    let home = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let mut parents = Vec::new();
    let mut dir = root;
    while let Some(above) = dir.parent() {
        if above == home || !above.starts_with(&home) {
            break;
        }
        dir = above;
        let repo = load_owned_layer(&dir.join(config::config_filename()), LayerKind::Repo, euid)?;
        let local = load_owned_layer(
            &dir.join(config::local_config_filename()),
            LayerKind::Local,
            euid,
        )?;
        if repo.is_none() && local.is_none() {
            continue;
        }
        let (cascade, inherit) = inheritance_flags(repo.as_ref(), local.as_ref())?;
        if !cascade {
            continue;
        }
        parents.push(ParentLayers {
            dir: dir.to_path_buf(),
            repo,
            local,
        });
        if !inherit {
            break;
        }
    }
    parents.reverse();
    Ok(parents)
}

/// Reads `path` if it exists and is owned by `euid` — the same test
/// [`discover_project_root`] applies to a candidate project file.
fn load_owned_layer(
    path: &Path,
    kind: LayerKind,
    euid: u32,
) -> Result<Option<LayerFile>, ConfigError> {
    if !config::is_owned_by(path, euid) {
        return Ok(None);
    }
    LayerFile::read(kind, path, euid).map(Some)
}

pub use crate::config::project_id;

// ─── Merge ──────────────────────────────────────────────────────────────────

/// Inputs to [`merge`] that would otherwise come from the environment.
pub struct MergeContext {
    /// The project root, as found by [`load_layers`]. `{sandbox_root}` and
    /// `{tool_state}` resolve against it in every layer, parents included.
    pub root: PathBuf,
    /// The user's home directory, for `~` expansion.
    pub home: PathBuf,
    /// `$XDG_CACHE_HOME/airlock` (default `~/.cache/airlock`) — the base for
    /// `{tool_state}`.
    pub tool_state_base: PathBuf,
}

/// Where a merged tool's definition came from, and what (if anything) it
/// replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolProvenance {
    pub layer: LayerKind,
    pub replaced: Option<LayerKind>,
}

/// Where a merged secret's binding came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretProvenance {
    /// Bound directly in this layer.
    Direct(LayerKind),
    /// A local `[secrets.<label>]` replaced the repo's binding with its own
    /// `source`.
    LocalOverride,
    /// A local `from = "global"` link, resolved to the global binding.
    GlobalLink,
    /// A local `from = "parent"` link, resolved to the parent configs'
    /// binding.
    ParentLink,
}

/// Where a merged `[agent.env.<key>]` entry's value came from, and which
/// lower-precedence layer it overrode (if any) — `airlock config` shows that
/// as `local (overrides repo)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentEnvProvenance {
    pub layer: LayerKind,
    pub overrides: Option<LayerKind>,
}

/// Where each unioned or highest-wins scalar setting came from, for
/// `airlock config`'s `settings` section. Lists carry one `(item, layer)`
/// pair per entry in the order the entry first appeared, matching the
/// corresponding list in [`MergedConfig::to_wire`].
#[derive(Debug, Default)]
pub struct SettingsProvenance {
    pub timeout: Option<LayerKind>,
    pub access: Option<LayerKind>,
    pub filesystem_read: Vec<(String, LayerKind)>,
    pub filesystem_write: Vec<(String, LayerKind)>,
    pub agent_passthrough_env: Vec<(String, LayerKind)>,
    pub agent_env: HashMap<String, AgentEnvProvenance>,
    /// `(kit name, layer)` for each name first added to `agent.kits`, in
    /// the order it appeared.
    pub agent_kits: Vec<(String, LayerKind)>,
}

/// Provenance recorded during [`merge`], kept for `airlock config` and the
/// trust-prompt annotation.
#[derive(Debug, Default)]
pub struct Provenance {
    pub tools: HashMap<String, ToolProvenance>,
    pub secrets: HashMap<String, SecretProvenance>,
    pub settings: SettingsProvenance,
    /// Which layer's `[kits.<name>]` table won, by kit name.
    pub kits: HashMap<String, LayerKind>,
}

/// The result of merging a project's layers: a wire-ready [`RawConfig`] plus
/// the bookkeeping the launcher and `airlock config` need around it.
#[derive(Debug)]
pub struct MergedConfig {
    raw: RawConfig,
    root: PathBuf,
    tool_state_dirs: Vec<PathBuf>,
    provenance: Provenance,
    kits: BTreeMap<String, RawKitConfig>,
}

impl MergedConfig {
    /// The merged config, normalized for the wire (decision #3 in the v2
    /// implementation contract): every path absolute, every secret with a
    /// concrete source, no `override` flags.
    pub fn to_wire(&self) -> RawConfig {
        self.raw.clone()
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `{tool_state}` directories the launcher must create (mode 0700)
    /// before sending this config to the daemon. Already included in the
    /// relevant tool's `extra_write` in [`Self::to_wire`]; listed again here
    /// because config resolution never creates directories itself.
    pub fn tool_state_dirs(&self) -> &[PathBuf] {
        &self.tool_state_dirs
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// The merged `[kits.<name>]` tables (global/local only; local wins by
    /// name). Launcher-only — never part of [`Self::to_wire`]. See
    /// [`crate::kits`].
    pub fn kits(&self) -> &BTreeMap<String, RawKitConfig> {
        &self.kits
    }
}

/// A `[secrets.<label>]` entry, classified against the layer it sits in.
/// The raw shape ([`RawSecretSpec`]) parses every legal combination the
/// same way; this is where "legal for *this* layer" is decided.
#[derive(Clone)]
enum ClassifiedSecret {
    /// The repo (or `--config`) layer declared this label with no source —
    /// a request each user binds with `airlock init --local`.
    Unbound { description: Option<String> },
    /// The local layer wrote `from = "global"`.
    GlobalLink { description: Option<String> },
    /// The local layer wrote `from = "parent"`.
    ParentLink { description: Option<String> },
    /// A concrete, resolved source.
    Bound {
        description: Option<String>,
        source: SecretSource,
    },
}

impl ClassifiedSecret {
    fn description(&self) -> Option<String> {
        match self {
            ClassifiedSecret::Unbound { description }
            | ClassifiedSecret::GlobalLink { description }
            | ClassifiedSecret::ParentLink { description }
            | ClassifiedSecret::Bound { description, .. } => description.clone(),
        }
    }

    /// This entry, keeping `fallback` as its description if it has none of
    /// its own — a local binding of a repo label inherits the repo's.
    fn with_description_or(mut self, fallback: Option<String>) -> Self {
        let (ClassifiedSecret::Unbound { description }
        | ClassifiedSecret::GlobalLink { description }
        | ClassifiedSecret::ParentLink { description }
        | ClassifiedSecret::Bound { description, .. }) = &mut self;
        if description.is_none() {
            *description = fallback;
        }
        self
    }
}

fn classify_secret(
    file: &Path,
    label: &str,
    spec: &RawSecretSpec,
    kind: LayerKind,
) -> Result<ClassifiedSecret, ConfigError> {
    match (&spec.source, &spec.from) {
        (None, None) => {
            if kind == LayerKind::Local {
                Err(ConfigError::LocalSecretUnbound {
                    file: file.to_path_buf(),
                    label: label.to_string(),
                })
            } else {
                Ok(ClassifiedSecret::Unbound {
                    description: spec.description.clone(),
                })
            }
        }
        (None, Some(value)) => {
            if value != "global" && value != "parent" {
                return Err(ConfigError::InvalidFromValue {
                    file: file.to_path_buf(),
                    label: label.to_string(),
                    value: value.clone(),
                });
            }
            if kind != LayerKind::Local {
                return Err(ConfigError::FromOutsideLocal {
                    file: file.to_path_buf(),
                    label: label.to_string(),
                    from: value.clone(),
                });
            }
            let description = spec.description.clone();
            Ok(if value == "global" {
                ClassifiedSecret::GlobalLink { description }
            } else {
                ClassifiedSecret::ParentLink { description }
            })
        }
        (Some(_), _) => {
            let source = config::resolve_bound_secret_source(label, spec)?;
            Ok(ClassifiedSecret::Bound {
                description: spec.description.clone(),
                source,
            })
        }
    }
}

/// Classify every `[secrets.<label>]` entry of one layer, applying the
/// layer-wide rules [`classify_secret`] cannot see on its own: the global
/// layer's labels must all be `Bound` (nothing else makes sense for your
/// own file), the repo/config layer's must not be links (`from` is
/// local-only — already enforced by `classify_secret`, kept here as the
/// single place that owns "what can a layer contain").
fn classify_layer_secrets(
    file: Option<&Path>,
    raw: Option<&RawConfig>,
    kind: LayerKind,
) -> Result<HashMap<String, ClassifiedSecret>, ConfigError> {
    let mut out = HashMap::new();
    let Some(raw) = raw else { return Ok(out) };
    let Some(file) = file else { return Ok(out) };
    let Some(secrets) = &raw.secrets else {
        return Ok(out);
    };
    for (label, spec) in secrets {
        let classified = classify_secret(file, label, spec, kind)?;
        if kind == LayerKind::Global
            && let ClassifiedSecret::Unbound { .. } = &classified
        {
            return Err(ConfigError::SecretFieldMismatch {
                label: label.clone(),
                reason: "has no source".to_string(),
            });
        }
        out.insert(label.clone(), classified);
    }
    Ok(out)
}

/// The bindings a local `from` link resolves against.
struct LinkTargets<'a> {
    /// The global file's own labels, for `from = "global"`.
    global: &'a HashMap<String, ClassifiedSecret>,
    /// Every label the parent configs bind, for `from = "parent"`; `None`
    /// when no parent config cascades to this directory.
    parent: Option<&'a HashMap<String, ClassifiedSecret>>,
}

/// Resolve one `HashMap` of classified secrets into concrete sources,
/// following `from` links into `links` as needed.
fn resolve_pool(
    file: &Path,
    classified: &HashMap<String, ClassifiedSecret>,
    links: &LinkTargets<'_>,
) -> Result<HashMap<String, SecretSource>, ConfigError> {
    let mut out = HashMap::with_capacity(classified.len());
    for (label, c) in classified {
        let (target, from) = match c {
            ClassifiedSecret::Bound { source, .. } => {
                out.insert(label.clone(), source.clone());
                continue;
            }
            ClassifiedSecret::Unbound { .. } => continue,
            ClassifiedSecret::GlobalLink { .. } => (Some(links.global), "global"),
            ClassifiedSecret::ParentLink { .. } => (links.parent, "parent"),
        };
        match target.and_then(|t| t.get(label)) {
            Some(ClassifiedSecret::Bound { source, .. }) => {
                out.insert(label.clone(), source.clone());
            }
            _ => {
                return Err(ConfigError::UnboundLink {
                    file: file.to_path_buf(),
                    label: label.clone(),
                    from: from.to_string(),
                });
            }
        }
    }
    Ok(out)
}

fn pool_as_spec_map(pool: &HashMap<String, SecretSource>) -> HashMap<String, config::SecretSpec> {
    pool.iter()
        .map(|(label, source)| {
            (
                label.clone(),
                config::SecretSpec {
                    label: label.clone(),
                    source: source.clone(),
                },
            )
        })
        .collect()
}

fn source_to_raw(source: &SecretSource, description: Option<String>) -> RawSecretSpec {
    match source {
        SecretSource::Env { from } => RawSecretSpec {
            description,
            source: Some("env".to_string()),
            from: Some(from.clone()),
            ..Default::default()
        },
        SecretSource::Command {
            argv,
            timeout,
            refresh,
            env,
        } => RawSecretSpec {
            description,
            source: Some("command".to_string()),
            command: Some(argv.clone()),
            timeout: Some(timeout.as_secs()),
            refresh: refresh.as_ref().map(|r| r.interval.as_secs()),
            refresh_max_backoff: refresh.as_ref().map(|r| r.max_backoff.as_secs()),
            env: if env.set.is_empty() {
                None
            } else {
                Some(
                    env.set
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                )
            },
            env_clear: env.clear,
            ..Default::default()
        },
    }
}

/// Which item (tool or `"agent"`) a secret/env reference lives in, scoped
/// to the layer that must declare the label it uses.
#[derive(Clone, Copy)]
enum RefScope<'a> {
    Global { file: &'a Path },
    RepoLike { file: &'a Path },
    Local,
}

/// Resolve one `env` table (a tool's or the agent's), rendering `{sandbox_root}`
/// / `{tool_state}` in static values (unless `render` is off) and checking
/// every secret reference against the scope-appropriate pool. Returns the
/// rendered env (ready for the wire) and any new `{tool_state}` directories
/// it introduced.
#[allow(clippy::too_many_arguments)]
fn resolve_env_table(
    owner: EnvOwner<'_>,
    raw_env: HashMap<String, RawEnvValue>,
    scope: RefScope<'_>,
    ctx: &MergeContext,
    project_id: &str,
    pool: &HashMap<String, SecretSource>,
    global_pool: &HashMap<String, SecretSource>,
    is_proxy_tool: bool,
    render: bool,
    tool_state_dirs: &mut Vec<PathBuf>,
    referenced_global_labels: &mut std::collections::HashSet<String>,
    undeclared_refs: &mut Vec<(String, String, String)>,
) -> Result<HashMap<String, RawEnvValue>, ConfigError> {
    let item = owner.item();
    let mut out = HashMap::with_capacity(raw_env.len());
    for (var_name, raw_value) in raw_env {
        config::check_env_entry(owner, &var_name, &raw_value, is_proxy_tool)?;
        let value = match raw_value {
            RawEnvValue::Static(s) if !render => RawEnvValue::Static(s),
            RawEnvValue::Static(s) => {
                let tool_state_dir = if config::uses_tool_state_placeholder(&s) {
                    Some(config::resolve_tool_state_path(
                        &ctx.tool_state_base,
                        project_id,
                        item,
                    ))
                } else {
                    None
                };
                let rendered = config::render_env_template(
                    &s,
                    &ctx.root,
                    tool_state_dir.as_deref(),
                    item,
                    &var_name,
                )?;
                if let Some(dir) = tool_state_dir {
                    tool_state_dirs.push(dir);
                }
                RawEnvValue::Static(rendered)
            }
            RawEnvValue::SecretRef(RawSecretRef { secret }) => {
                if !pool.contains_key(&secret) {
                    match scope {
                        RefScope::Global { file } => {
                            return Err(ConfigError::GlobalItemUsesNonGlobalLabel {
                                file: file.to_path_buf(),
                                item: item.to_string(),
                                label: secret,
                            });
                        }
                        RefScope::RepoLike { file } => {
                            return Err(ConfigError::RepoItemUsesNonRepoLabel {
                                file: file.to_path_buf(),
                                item: item.to_string(),
                                label: secret,
                            });
                        }
                        RefScope::Local => {
                            undeclared_refs.push((
                                owner.location(),
                                var_name.clone(),
                                secret.clone(),
                            ));
                        }
                    }
                } else if global_pool.contains_key(&secret) {
                    // Resolved through the global pool — either because the
                    // item itself is global-owned, or (local items only)
                    // because the label has no repo/local binding and the
                    // combined pool fell through to the global one. Either
                    // way the final secrets table needs this label.
                    referenced_global_labels.insert(secret.clone());
                }
                RawEnvValue::SecretRef(RawSecretRef { secret })
            }
        };
        out.insert(var_name, value);
    }
    Ok(out)
}

fn resolve_path_list(raw: &[String], dir: &Path, home: &Path) -> Vec<String> {
    config::resolve_paths_with_home(raw, dir, home)
        .into_iter()
        .map(|p| p.display().to_string())
        .collect()
}

/// Refuse a relative entry in a global-layer path list — see "Relative
/// paths" in the v2 design.
fn check_global_paths_absolute(file: &Path, raw: &[String]) -> Result<(), ConfigError> {
    for p in raw {
        let absolute = p.starts_with('/') || p.starts_with('~');
        if !absolute {
            return Err(ConfigError::RelativePathInGlobal {
                file: file.to_path_buf(),
                path: p.clone(),
            });
        }
    }
    Ok(())
}

/// Refuse `override = true` on any tool in a layer other than the local one.
fn reject_override(
    file: &Path,
    tools: Option<&HashMap<String, RawToolConfig>>,
) -> Result<(), ConfigError> {
    for (name, t) in tools.into_iter().flatten() {
        if t.r#override {
            return Err(ConfigError::OverrideOutsideLocal {
                file: file.to_path_buf(),
                tool: name.clone(),
            });
        }
    }
    Ok(())
}

/// The secret pool an item owned by each layer resolves its references
/// against, and the scope that decides what an unresolved one means.
struct LayerPools<'a> {
    base_file: Option<&'a Path>,
    repo_file: Option<&'a Path>,
    base: &'a HashMap<String, SecretSource>,
    repo: &'a HashMap<String, SecretSource>,
    /// Base, repo and local-only labels together: a local item may use any
    /// of them.
    local: &'a HashMap<String, SecretSource>,
}

impl<'a> LayerPools<'a> {
    fn for_layer(&self, kind: LayerKind) -> (RefScope<'a>, &'a HashMap<String, SecretSource>) {
        match kind {
            LayerKind::Global | LayerKind::Parent => (
                RefScope::Global {
                    file: self
                        .base_file
                        .expect("an item owned by the base has a file"),
                },
                self.base,
            ),
            LayerKind::Local => (RefScope::Local, self.local),
            LayerKind::Repo | LayerKind::ConfigFile => (
                RefScope::RepoLike {
                    file: self
                        .repo_file
                        .expect("an item owned by the repo layer has a file"),
                },
                self.repo,
            ),
        }
    }
}

/// The value the highest-precedence layer that sets it gives, and which
/// layer that was. `ordered` runs lowest to highest.
fn highest_wins<T: Clone>(
    ordered: &[(LayerKind, Option<&RawConfig>)],
    get: impl Fn(&RawConfig) -> Option<&T>,
) -> (Option<T>, Option<LayerKind>) {
    ordered
        .iter()
        .rev()
        .find_map(|(kind, raw)| Some((raw.and_then(&get)?.clone(), *kind)))
        .map_or((None, None), |(value, kind)| (Some(value), Some(kind)))
}

/// Appends each of `items` not already in `acc`, recording `kind` as the
/// layer that first brought it in. Order is first-seen.
fn union_with_layer(
    acc: &mut Vec<(String, LayerKind)>,
    kind: LayerKind,
    items: impl IntoIterator<Item = String>,
) {
    for item in items {
        if !acc.iter().any(|(seen, _)| *seen == item) {
            acc.push((item, kind));
        }
    }
}

fn items_of(acc: &[(String, LayerKind)]) -> Vec<String> {
    acc.iter().map(|(item, _)| item.clone()).collect()
}

/// The layer the first `(item, layer)` pair for `item` in `list` names.
fn layer_of(list: &[(String, LayerKind)], item: &str) -> Option<LayerKind> {
    list.iter().find(|(i, _)| i == item).map(|(_, kind)| *kind)
}

/// What one directory's own files merge on top of: the global file alone,
/// or the global file with every cascading parent above that directory
/// already merged in. A directory's files treat it exactly as they treat
/// the global layer: a repo or local tool replaces a base tool, a repo item
/// cannot reference a base label, and a local file links one with `from`.
struct Base {
    /// The global file, or the nearest parent's file — what an error about
    /// a base item names.
    file: Option<PathBuf>,
    /// Shaped like a global file: every path absolute, static env values
    /// not yet rendered, no `override`. Its secrets are in `secrets`.
    raw: Option<RawConfig>,
    /// Every label an item owned by the base resolves against, all bound.
    secrets: HashMap<String, ClassifiedSecret>,
    /// The global file's own labels, which `from = "global"` links to.
    global_secrets: HashMap<String, ClassifiedSecret>,
    /// Whether a parent config is merged in, so `from = "parent"` has
    /// something to link to.
    has_parent: bool,
    /// Where the base got each item. An item with no entry came from the
    /// global file.
    provenance: Provenance,
}

impl Base {
    /// The global file on its own, after the rules only it has: no
    /// `override`, absolute paths, no `cascade` or `inherit`.
    fn global(file: Option<&LayerFile>) -> Result<Base, ConfigError> {
        let raw = file.map(LayerFile::parse).transpose()?;
        let path = file.map(|f| f.path.clone());
        if let (Some(global), Some(file)) = (&raw, &path) {
            reject_override(file, global.tools.as_ref())?;
            if let Some(fs) = &global.filesystem {
                check_global_paths_absolute(file, &fs.read)?;
                check_global_paths_absolute(file, &fs.write)?;
            }
            if let Some(tools) = &global.tools {
                for t in tools.values() {
                    check_global_paths_absolute(file, &t.extra_read)?;
                    check_global_paths_absolute(file, &t.extra_write)?;
                }
            }
            if let Some(agent) = &global.agent
                && let Some(fs) = &agent.filesystem
            {
                check_global_paths_absolute(file, &fs.read)?;
                check_global_paths_absolute(file, &fs.write)?;
            }
            if let Some(kits) = &global.kits {
                for def in kits.values() {
                    check_global_paths_absolute(file, &def.read)?;
                    check_global_paths_absolute(file, &def.write)?;
                }
            }
            for (key, set) in [
                ("cascade", global.cascade.is_some()),
                ("inherit", global.inherit.is_some()),
            ] {
                if set {
                    return Err(ConfigError::InheritanceKeyInGlobal {
                        file: file.clone(),
                        key,
                    });
                }
            }
        }
        let secrets = classify_layer_secrets(path.as_deref(), raw.as_ref(), LayerKind::Global)?;
        Ok(Base {
            file: path,
            raw,
            global_secrets: secrets.clone(),
            secrets,
            has_parent: false,
            provenance: Provenance::default(),
        })
    }

    /// The base for the directories below a parent: that parent's files,
    /// merged on top of `self` as `level`, with everything they contributed
    /// attributed to [`LayerKind::Parent`].
    fn with_parent(self, level: Level, file: PathBuf) -> Base {
        let Level {
            raw,
            mut provenance,
            kits,
            pool,
            ..
        } = level;
        inherit_provenance(&mut provenance, &self.provenance);
        relabel_as_parent(&mut provenance);
        for label in pool.keys() {
            if !provenance.secrets.contains_key(label) {
                let from_base = self
                    .provenance
                    .secrets
                    .get(label)
                    .copied()
                    .unwrap_or(SecretProvenance::Direct(LayerKind::Global));
                provenance.secrets.insert(label.clone(), from_base);
            }
        }
        let allow_home_root = self.raw.as_ref().and_then(|c| c.allow_home_root);
        Base {
            file: Some(file),
            raw: Some(RawConfig {
                secrets: None,
                allow_home_root,
                kits: Some(kits.into_iter().collect()),
                ..raw
            }),
            secrets: pool,
            global_secrets: self.global_secrets,
            has_parent: true,
            provenance,
        }
    }
}

/// Which directory a [`merge_level`] call merges.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// A parent: its result becomes the next [`Base`], so its static env
    /// values stay unrendered until the project merges them.
    Parent,
    /// The project root itself.
    Project,
}

/// One directory's files merged on top of a [`Base`]. Its provenance still
/// says [`LayerKind::Global`] for everything that came from the base.
struct Level {
    raw: RawConfig,
    tool_state_dirs: Vec<PathBuf>,
    provenance: Provenance,
    kits: BTreeMap<String, RawKitConfig>,
    /// Every label a local item in this directory could use — the base's,
    /// the repo's as bound and the local file's own — all bound. The next
    /// [`Base`]'s secrets.
    pool: HashMap<String, ClassifiedSecret>,
}

/// Merge a project's loaded layers into one normalized, wire-ready config.
///
/// Folds the layers from lowest to highest precedence: the global file is
/// the first [`Base`], each cascading parent's own files merge on top of it
/// and become the next one, and the project's files merge last. Every step
/// applies the same rules ("Tools across layers", "Secret labels across
/// layers" in the v2 design), with the base in the global layer's place.
pub fn merge(layers: &LoadedLayers, ctx: &MergeContext) -> Result<MergedConfig, ConfigError> {
    let base = fold_parents(layers, ctx)?;
    let Level {
        raw,
        tool_state_dirs,
        mut provenance,
        kits,
        ..
    } = merge_level(
        &base,
        layers.repo.as_ref(),
        layers.local.as_ref(),
        &ctx.root,
        Stage::Project,
        ctx,
    )?;
    inherit_provenance(&mut provenance, &base.provenance);
    Ok(MergedConfig {
        raw,
        root: ctx.root.clone(),
        tool_state_dirs,
        provenance,
        kits,
    })
}

/// The global file with every cascading parent merged on top of it: the
/// base the project's own files merge onto.
fn fold_parents(layers: &LoadedLayers, ctx: &MergeContext) -> Result<Base, ConfigError> {
    let mut base = Base::global(layers.global.as_ref())?;
    for parent in &layers.parents {
        let level = merge_level(
            &base,
            parent.repo.as_ref(),
            parent.local.as_ref(),
            &parent.dir,
            Stage::Parent,
            ctx,
        )?;
        let file = parent
            .local
            .as_ref()
            .or(parent.repo.as_ref())
            .expect("a parent has at least one file")
            .path
            .clone();
        base = base.with_parent(level, file);
    }
    Ok(base)
}

/// The labels the parent configs themselves bind for the project in
/// `layers`, sorted — what `airlock init --local` stubs with
/// `from = "parent"`. A label a parent only passes through from the global
/// file is left out: `from = "global"` says that more plainly.
pub fn parent_bound_labels(layers: &LoadedLayers, home: &Path) -> Result<Vec<String>, ConfigError> {
    let ctx = MergeContext {
        root: layers.root.clone(),
        home: home.to_path_buf(),
        // Parent stages never render `{tool_state}`.
        tool_state_base: PathBuf::new(),
    };
    let base = fold_parents(layers, &ctx)?;
    let mut labels: Vec<String> = base
        .secrets
        .keys()
        .filter(|label| {
            matches!(
                base.provenance.secrets.get(*label),
                Some(SecretProvenance::Direct(LayerKind::Parent) | SecretProvenance::ParentLink)
            )
        })
        .cloned()
        .collect();
    labels.sort();
    Ok(labels)
}

/// Replaces each [`LayerKind::Global`] attribution in `prov` — which, from
/// one [`merge_level`] call, means "from the base" — with where the base
/// itself got that item.
fn inherit_provenance(prov: &mut Provenance, base: &Provenance) {
    let from_base = |kind: LayerKind, found: Option<LayerKind>| match kind {
        LayerKind::Global => found.unwrap_or(LayerKind::Global),
        other => other,
    };

    for (name, p) in prov.tools.iter_mut() {
        let Some(b) = base.tools.get(name) else {
            continue;
        };
        if p.layer == LayerKind::Global {
            *p = *b;
        } else if p.replaced == Some(LayerKind::Global) {
            p.replaced = Some(b.layer);
        }
    }
    for (label, p) in prov.secrets.iter_mut() {
        if *p == SecretProvenance::Direct(LayerKind::Global)
            && let Some(b) = base.secrets.get(label)
        {
            *p = *b;
        }
    }

    let s = &mut prov.settings;
    let b = &base.settings;
    s.timeout = s.timeout.map(|k| from_base(k, b.timeout));
    s.access = s.access.map(|k| from_base(k, b.access));
    for (list, base_list) in [
        (&mut s.filesystem_read, &b.filesystem_read),
        (&mut s.filesystem_write, &b.filesystem_write),
        (&mut s.agent_passthrough_env, &b.agent_passthrough_env),
        (&mut s.agent_kits, &b.agent_kits),
    ] {
        for (item, kind) in list.iter_mut() {
            *kind = from_base(*kind, layer_of(base_list, item));
        }
    }
    for (key, p) in s.agent_env.iter_mut() {
        let Some(found) = b.agent_env.get(key) else {
            continue;
        };
        if p.layer == LayerKind::Global {
            *p = *found;
        } else if p.overrides == Some(LayerKind::Global) {
            p.overrides = Some(found.layer);
        }
    }
    for (name, kind) in prov.kits.iter_mut() {
        *kind = from_base(*kind, base.kits.get(name).copied());
    }
}

/// Attributes everything a parent's own files contributed to
/// [`LayerKind::Parent`]: below that parent, its repo and local files are
/// one layer.
fn relabel_as_parent(prov: &mut Provenance) {
    let parent = |kind: LayerKind| match kind {
        LayerKind::Repo | LayerKind::Local | LayerKind::ConfigFile => LayerKind::Parent,
        other => other,
    };
    for p in prov.tools.values_mut() {
        p.layer = parent(p.layer);
        p.replaced = p.replaced.map(parent);
    }
    for p in prov.secrets.values_mut() {
        *p = match *p {
            SecretProvenance::Direct(kind) => SecretProvenance::Direct(parent(kind)),
            SecretProvenance::LocalOverride => SecretProvenance::Direct(LayerKind::Parent),
            link @ (SecretProvenance::GlobalLink | SecretProvenance::ParentLink) => link,
        };
    }
    let s = &mut prov.settings;
    s.timeout = s.timeout.map(parent);
    s.access = s.access.map(parent);
    for list in [
        &mut s.filesystem_read,
        &mut s.filesystem_write,
        &mut s.agent_passthrough_env,
        &mut s.agent_kits,
    ] {
        for (_, kind) in list.iter_mut() {
            *kind = parent(*kind);
        }
    }
    for p in s.agent_env.values_mut() {
        p.layer = parent(p.layer);
        p.overrides = p.overrides.map(parent);
    }
    for kind in prov.kits.values_mut() {
        *kind = parent(*kind);
    }
}

/// Merge one directory's repo and local files on top of `base`.
///
/// Parses each file, applies the per-layer structural rules (repo cannot
/// set `allow_home_root`, `[kits.*]` or `override`), then the cross-layer
/// rules against the base, then the existing merged-config validation
/// (proxy tools, undeclared refs) that already lived in `config.rs`.
/// Relative paths resolve against `dir`.
fn merge_level(
    base: &Base,
    repo: Option<&LayerFile>,
    local: Option<&LayerFile>,
    dir: &Path,
    stage: Stage,
    ctx: &MergeContext,
) -> Result<Level, ConfigError> {
    let base_raw = base.raw.as_ref();
    let repo_raw = repo.map(LayerFile::parse).transpose()?;
    let local_raw = local.map(LayerFile::parse).transpose()?;

    let base_file = base.file.as_deref();
    let repo_file = repo.map(|f| f.path.as_path());
    let local_file = local.map(|f| f.path.as_path());
    let repo_kind = repo.map_or(LayerKind::Repo, |f| f.kind);
    // Lowest to highest precedence. The base sits in the global layer's
    // place; `merge` maps what came from it back to where the base got it.
    let ordered: [(LayerKind, Option<&RawConfig>); 3] = [
        (LayerKind::Global, base_raw),
        (repo_kind, repo_raw.as_ref()),
        (LayerKind::Local, local_raw.as_ref()),
    ];
    // Static env values are rendered once, when the project merges them:
    // `{sandbox_root}` and `{tool_state}` mean the project root even in a
    // parent's file, and rendering twice would undo a `\{` escape.
    let render = stage == Stage::Project;

    // ── Per-layer structural rules ──────────────────────────────────────

    if let (Some(repo), Some(file)) = (&repo_raw, repo_file) {
        if repo.allow_home_root.is_some() {
            return Err(ConfigError::AllowHomeRootInRepo {
                file: file.to_path_buf(),
            });
        }
        if repo.kits.is_some() {
            return Err(ConfigError::KitsInRepo {
                file: file.to_path_buf(),
            });
        }
        reject_override(file, repo.tools.as_ref())?;
    }

    // ── Home-root guard ──────────────────────────────────────────────────

    // A parent is always strictly below $HOME, so only the project root can
    // be $HOME itself.
    if stage == Stage::Project {
        let merged_allow_home_root = base_raw.and_then(|c| c.allow_home_root) == Some(true)
            || local_raw.as_ref().and_then(|c| c.allow_home_root) == Some(true);
        // Canonical on both sides: the root is canonical already, and a home
        // reached through a symlink must not slip past the guard.
        let home = std::fs::canonicalize(&ctx.home).unwrap_or_else(|_| ctx.home.clone());
        if ctx.root == home && !merged_allow_home_root {
            return Err(ConfigError::HomeRootNotAllowed {
                home: ctx.root.clone(),
            });
        }
    }

    // ── Kits: base and local `[kits.<name>]` tables, local overriding the
    //    base's whole, by name ─────────────────────────────────────────────
    // (The repo layer is already refused above.) Table-shape validation
    // (built-in vs. user-defined field restrictions, {tool_state}, env var
    // names) and resolving `agent.kits` into an active list happen later, in
    // crate::kits, called from crate::launcher::prepare — this only needs
    // to merge the raw tables and record which layer each came from.
    let mut kits: BTreeMap<String, RawKitConfig> = BTreeMap::new();
    let mut kit_provenance: HashMap<String, LayerKind> = HashMap::new();
    if let Some(from_base) = base_raw.and_then(|c| c.kits.as_ref()) {
        for (name, def) in from_base {
            kits.insert(name.clone(), def.clone());
            kit_provenance.insert(name.clone(), LayerKind::Global);
        }
    }
    if let Some(local) = local_raw.as_ref().and_then(|c| c.kits.as_ref()) {
        for (name, def) in local {
            let mut def = def.clone();
            if stage == Stage::Parent {
                // crate::kits resolves a relative path against the project
                // root, not the parent directory this file sits in.
                def.read = resolve_path_list(&def.read, dir, &ctx.home);
                def.write = resolve_path_list(&def.write, dir, &ctx.home);
            }
            kits.insert(name.clone(), def);
            kit_provenance.insert(name.clone(), LayerKind::Local);
        }
    }

    // ── Secret classification and the unbound-labels check ──────────────

    let repo_secrets = classify_layer_secrets(repo_file, repo_raw.as_ref(), repo_kind)?;
    let local_secrets = classify_layer_secrets(local_file, local_raw.as_ref(), LayerKind::Local)?;

    let mut unbound: Vec<(String, Option<String>)> = Vec::new();
    for (label, classified) in &repo_secrets {
        if matches!(classified, ClassifiedSecret::Unbound { .. })
            && !local_secrets.contains_key(label)
        {
            unbound.push((label.clone(), classified.description()));
        }
    }
    if !unbound.is_empty() {
        unbound.sort_by(|a, b| a.0.cmp(&b.0));
        return Err(ConfigError::UnboundSecretLabels {
            repo_file: repo_file
                .map(Path::to_path_buf)
                .unwrap_or_else(|| dir.join(config::config_filename())),
            labels: unbound,
        });
    }

    // ── Resolve the three pools of concrete secret sources ──────────────

    let links = LinkTargets {
        global: &base.global_secrets,
        parent: base.has_parent.then_some(&base.secrets),
    };
    let base_pool = resolve_pool(base_file.unwrap_or(dir), &base.secrets, &links)?;

    // repo_secrets, with any local override applied in place.
    let repo_effective: HashMap<String, ClassifiedSecret> = repo_secrets
        .iter()
        .map(|(label, classified)| {
            let effective = match local_secrets.get(label) {
                Some(local_classified) => local_classified
                    .clone()
                    .with_description_or(classified.description()),
                None => classified.clone(),
            };
            (label.clone(), effective)
        })
        .collect();
    let repo_pool = resolve_pool(
        local_file.or(repo_file).unwrap_or(dir),
        &repo_effective,
        &links,
    )?;

    let local_only: HashMap<String, ClassifiedSecret> = local_secrets
        .iter()
        .filter(|(label, _)| !repo_secrets.contains_key(*label))
        .map(|(label, c)| (label.clone(), c.clone()))
        .collect();
    let local_only_pool = resolve_pool(local_file.unwrap_or(dir), &local_only, &links)?;

    let combined_for_local: HashMap<String, SecretSource> = base_pool
        .iter()
        .chain(repo_pool.iter())
        .chain(local_only_pool.iter())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let pools = LayerPools {
        base_file,
        repo_file,
        base: &base_pool,
        repo: &repo_pool,
        local: &combined_for_local,
    };

    // ── Tool merge ───────────────────────────────────────────────────────

    let empty_tools: HashMap<String, RawToolConfig> = HashMap::new();
    let base_tools = base_raw
        .and_then(|c| c.tools.as_ref())
        .unwrap_or(&empty_tools);
    let repo_tools = repo_raw
        .as_ref()
        .and_then(|c| c.tools.as_ref())
        .unwrap_or(&empty_tools);
    let local_tools = local_raw
        .as_ref()
        .and_then(|c| c.tools.as_ref())
        .unwrap_or(&empty_tools);

    let mut tool_names: Vec<&String> = base_tools
        .keys()
        .chain(repo_tools.keys())
        .chain(local_tools.keys())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    tool_names.sort();

    let mut final_tools: HashMap<String, RawToolConfig> = HashMap::new();
    let mut tool_provenance: HashMap<String, ToolProvenance> = HashMap::new();
    let mut tool_state_dirs: Vec<PathBuf> = Vec::new();
    let mut referenced_base_labels: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut undeclared_refs: Vec<(String, String, String)> = Vec::new();

    let project_id = config::project_id(&ctx.root);

    for name in tool_names {
        config::validate_tool_name(name)?;

        let in_repo = repo_tools.contains_key(name);
        let in_local = local_tools.contains_key(name);
        let in_base = base_tools.contains_key(name);

        let (winning, owning_layer): (&RawToolConfig, LayerKind) = if in_local {
            let local_tool = &local_tools[name];
            if in_repo {
                if !local_tool.r#override {
                    return Err(ConfigError::DuplicateTool {
                        tool: name.clone(),
                        repo_file: repo_file.unwrap().to_path_buf(),
                        local_file: local_file.unwrap().to_path_buf(),
                    });
                }
                (local_tool, LayerKind::Local)
            } else if local_tool.r#override {
                return Err(ConfigError::OverrideWithoutRepoTool {
                    local_file: local_file.unwrap().to_path_buf(),
                    tool: name.clone(),
                });
            } else {
                (local_tool, LayerKind::Local)
            }
        } else if in_repo {
            (&repo_tools[name], repo_kind)
        } else {
            (&base_tools[name], LayerKind::Global)
        };

        let replaced = if in_base && owning_layer != LayerKind::Global {
            Some(LayerKind::Global)
        } else {
            None
        };
        tool_provenance.insert(
            name.clone(),
            ToolProvenance {
                layer: owning_layer,
                replaced,
            },
        );

        let (scope, pool) = pools.for_layer(owning_layer);

        let raw_env = winning.env.clone().unwrap_or_default();
        let env = resolve_env_table(
            EnvOwner::Tool(name),
            raw_env,
            scope,
            ctx,
            &project_id,
            pool,
            &base_pool,
            winning.proxy,
            render,
            &mut tool_state_dirs,
            &mut referenced_base_labels,
            &mut undeclared_refs,
        )?;

        let visible_secrets = pool_as_spec_map(pool);
        // Validation only: resolve_proxy_policy's typed ProxyPolicy is for
        // the daemon's own resolve_wire_config, not the wire form itself —
        // the raw `routes` travel through unchanged below.
        config::resolve_proxy_policy(
            name,
            winning.proxy,
            winning.routes.clone(),
            &visible_secrets,
        )?;

        let mut extra_write = resolve_path_list(&winning.extra_write, dir, &ctx.home);
        // {tool_state} dirs used by this tool's env were pushed onto
        // tool_state_dirs by resolve_env_table already; also grant them to
        // this tool specifically.
        for dir in &tool_state_dirs {
            if dir.starts_with(ctx.tool_state_base.join(&project_id).join(name)) {
                let s = dir.display().to_string();
                if !extra_write.contains(&s) {
                    extra_write.push(s);
                }
            }
        }

        final_tools.insert(
            name.clone(),
            RawToolConfig {
                env: Some(env),
                extra_read: resolve_path_list(&winning.extra_read, dir, &ctx.home),
                extra_write,
                timeout: winning.timeout,
                access: winning.access.clone(),
                description: winning.description.clone(),
                proxy: winning.proxy,
                routes: winning.routes.clone(),
                r#override: false,
            },
        );
    }

    // ── Agent merge ──────────────────────────────────────────────────────

    let layered_agents: Vec<(LayerKind, Option<&config::RawAgentConfig>)> = ordered
        .iter()
        .map(|(kind, raw)| (*kind, raw.and_then(|c| c.agent.as_ref())))
        .collect();

    // Agent merge result plus the provenance `SettingsProvenance` needs,
    // which the `if`/`else` below has no other way to hand back out of its
    // local bookkeeping.
    type AgentMergeResult = (
        Option<config::RawAgentConfig>,
        Vec<(String, LayerKind)>,
        HashMap<String, AgentEnvProvenance>,
        Vec<(String, LayerKind)>,
    );

    let any_agent = layered_agents.iter().any(|(_, a)| a.is_some());
    let (agent, passthrough_env_prov, agent_env_prov, agent_kits_prov): AgentMergeResult =
        if !any_agent {
            (None, Vec::new(), HashMap::new(), Vec::new())
        } else {
            let mut timeout: Option<u64> = None;
            let mut passthrough_env_prov: Vec<(String, LayerKind)> = Vec::new();
            let mut env_by_key: HashMap<String, (LayerKind, RawEnvValue)> = HashMap::new();
            // Every layer (in merge order) that set a given `agent.env` key, so
            // the winner (last) and what it overrode (the one before it, if
            // any) can both be reported — `airlock config`'s `local (overrides
            // repo)` annotation.
            let mut env_history: HashMap<String, Vec<LayerKind>> = HashMap::new();
            let mut fs_read: Vec<(String, LayerKind)> = Vec::new();
            let mut fs_write: Vec<(String, LayerKind)> = Vec::new();
            let mut agent_kits_prov: Vec<(String, LayerKind)> = Vec::new();

            for (kind, agent_cfg) in &layered_agents {
                let Some(a) = agent_cfg else { continue };
                if a.timeout.is_some() {
                    timeout = a.timeout;
                }
                union_with_layer(&mut passthrough_env_prov, *kind, a.passthrough_env.clone());
                for (k, v) in &a.env {
                    env_by_key.insert(k.clone(), (*kind, v.clone()));
                    env_history.entry(k.clone()).or_default().push(*kind);
                }
                if let Some(fs) = &a.filesystem {
                    union_with_layer(
                        &mut fs_read,
                        *kind,
                        resolve_path_list(&fs.read, dir, &ctx.home),
                    );
                    union_with_layer(
                        &mut fs_write,
                        *kind,
                        resolve_path_list(&fs.write, dir, &ctx.home),
                    );
                }
                // Any layer; union across layers (same rule as
                // passthrough_env) — see "Merge rules" in the v2 design.
                union_with_layer(&mut agent_kits_prov, *kind, a.kits.clone());
            }

            let agent_env_prov: HashMap<String, AgentEnvProvenance> = env_history
                .into_iter()
                .map(|(key, layers_seen)| {
                    let winner = *layers_seen.last().expect("push always precedes a read");
                    let overrides =
                        (layers_seen.len() > 1).then(|| layers_seen[layers_seen.len() - 2]);
                    (
                        key,
                        AgentEnvProvenance {
                            layer: winner,
                            overrides,
                        },
                    )
                })
                .collect();

            let mut final_env: HashMap<String, RawEnvValue> =
                HashMap::with_capacity(env_by_key.len());
            for (key, (kind, value)) in env_by_key {
                let (scope, pool) = pools.for_layer(kind);
                let mut single = HashMap::with_capacity(1);
                single.insert(key.clone(), value);
                let resolved = resolve_env_table(
                    EnvOwner::Agent,
                    single,
                    scope,
                    ctx,
                    &project_id,
                    pool,
                    &base_pool,
                    false,
                    render,
                    &mut tool_state_dirs,
                    &mut referenced_base_labels,
                    &mut undeclared_refs,
                )?;
                final_env.extend(resolved);
            }

            (
                Some(config::RawAgentConfig {
                    timeout,
                    passthrough_env: items_of(&passthrough_env_prov),
                    env: final_env,
                    filesystem: if fs_read.is_empty() && fs_write.is_empty() {
                        None
                    } else {
                        Some(config::RawAgentFilesystem {
                            read: items_of(&fs_read),
                            write: items_of(&fs_write),
                        })
                    },
                    kits: items_of(&agent_kits_prov),
                }),
                passthrough_env_prov,
                agent_env_prov,
                agent_kits_prov,
            )
        };

    if !undeclared_refs.is_empty() {
        return Err(ConfigError::UndeclaredSecretRefs {
            refs: undeclared_refs,
        });
    }

    // ── Final secrets table: every repo/local label, plus referenced
    //    base ones ─────────────────────────────────────────────────────

    let link_provenance = |label: &str| match local_secrets.get(label) {
        Some(ClassifiedSecret::GlobalLink { .. }) => Some(SecretProvenance::GlobalLink),
        Some(ClassifiedSecret::ParentLink { .. }) => Some(SecretProvenance::ParentLink),
        _ => None,
    };
    let mut secret_provenance: HashMap<String, SecretProvenance> = HashMap::new();
    let mut final_secrets: HashMap<String, RawSecretSpec> = HashMap::new();

    for (label, source) in &repo_pool {
        let description = repo_effective
            .get(label)
            .and_then(|c| c.description())
            .or_else(|| repo_secrets.get(label).and_then(|c| c.description()));
        final_secrets.insert(label.clone(), source_to_raw(source, description));
        let provenance = link_provenance(label).unwrap_or(match local_secrets.get(label) {
            Some(ClassifiedSecret::Bound { .. }) => SecretProvenance::LocalOverride,
            _ => SecretProvenance::Direct(repo_kind),
        });
        secret_provenance.insert(label.clone(), provenance);
    }
    for (label, source) in &local_only_pool {
        let description = local_only.get(label).and_then(|c| c.description());
        final_secrets.insert(label.clone(), source_to_raw(source, description));
        let provenance =
            link_provenance(label).unwrap_or(SecretProvenance::Direct(LayerKind::Local));
        secret_provenance.insert(label.clone(), provenance);
    }
    for label in &referenced_base_labels {
        if final_secrets.contains_key(label) {
            continue;
        }
        if let Some(source) = base_pool.get(label) {
            let description = base.secrets.get(label).and_then(|c| c.description());
            final_secrets.insert(label.clone(), source_to_raw(source, description));
            secret_provenance.insert(label.clone(), SecretProvenance::Direct(LayerKind::Global));
        }
    }

    // ── Top-level scalars and lists ──────────────────────────────────────

    let (timeout, timeout_layer) = highest_wins(&ordered, |c| c.timeout.as_ref());
    let (access, access_layer) = highest_wins(&ordered, |c| c.access.as_ref());

    let mut fs_read_prov: Vec<(String, LayerKind)> = Vec::new();
    let mut fs_write_prov: Vec<(String, LayerKind)> = Vec::new();
    for (kind, raw) in ordered {
        if let Some(fs) = raw.and_then(|r| r.filesystem.as_ref()) {
            union_with_layer(
                &mut fs_read_prov,
                kind,
                resolve_path_list(&fs.read, dir, &ctx.home),
            );
            union_with_layer(
                &mut fs_write_prov,
                kind,
                resolve_path_list(&fs.write, dir, &ctx.home),
            );
        }
    }
    let fs_read = items_of(&fs_read_prov);
    let fs_write = items_of(&fs_write_prov);

    let raw = RawConfig {
        timeout,
        access,
        filesystem: if fs_read.is_empty() && fs_write.is_empty() {
            None
        } else {
            Some(config::RawFilesystem {
                read: fs_read,
                write: fs_write,
            })
        },
        secrets: if final_secrets.is_empty() {
            None
        } else {
            Some(final_secrets)
        },
        tools: if final_tools.is_empty() {
            None
        } else {
            Some(final_tools)
        },
        agent,
        allow_home_root: None,
        // Launcher-only (crate::kits and discovery); never sent to the
        // daemon.
        kits: None,
        cascade: None,
        inherit: None,
    };

    // What the next directory down may link to or use: every label a local
    // item here could.
    let pool = combined_for_local
        .into_iter()
        .map(|(label, source)| {
            let description = local_secrets
                .get(&label)
                .and_then(ClassifiedSecret::description)
                .or_else(|| {
                    repo_secrets
                        .get(&label)
                        .and_then(ClassifiedSecret::description)
                })
                .or_else(|| {
                    base.secrets
                        .get(&label)
                        .and_then(ClassifiedSecret::description)
                });
            (
                label,
                ClassifiedSecret::Bound {
                    description,
                    source,
                },
            )
        })
        .collect();

    Ok(Level {
        raw,
        tool_state_dirs,
        provenance: Provenance {
            tools: tool_provenance,
            secrets: secret_provenance,
            settings: SettingsProvenance {
                timeout: timeout_layer,
                access: access_layer,
                filesystem_read: fs_read_prov,
                filesystem_write: fs_write_prov,
                agent_passthrough_env: passthrough_env_prov,
                agent_env: agent_env_prov,
                agent_kits: agent_kits_prov,
            },
            kits: kit_provenance,
        },
        kits,
        pool,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    /// The tests put the project at the top of a temp dir that also stands in
    /// for home when loading layers; merging against that home would trip the
    /// home-root guard, so the merge sees a home elsewhere.
    fn ctx(root: &Path, home: &Path) -> MergeContext {
        MergeContext {
            root: root.to_path_buf(),
            home: PathBuf::from("/nonexistent-airlock-test-home"),
            tool_state_base: home.join(".cache").join("airlock"),
        }
    }

    /// Loads `dir`'s layers by the default walk (with `dir` standing in
    /// for home too) and merges them.
    fn merge_default(dir: &Path) -> Result<MergedConfig, ConfigError> {
        let layers = load_default(dir, dir).unwrap();
        merge(&layers, &ctx(&layers.root.clone(), dir))
    }

    fn load_default(cwd: &Path, home: &Path) -> Result<LoadedLayers, ConfigError> {
        // No real global file in these tests unless a test writes one;
        // point at a path that does not exist, which load_layers treats as
        // an absent (not an error) global layer.
        load_layers(
            &DiscoveryMode::Default,
            cwd,
            home,
            &home.join("airlock-global-does-not-exist.toml"),
        )
    }

    // ── Discovery ─────────────────────────────────────────────────────

    #[test]
    fn undeclared_ref_names_the_same_location_as_the_daemon() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "airlock.local.toml",
            "[tools.gh.env]\nGH_TOKEN = { secret = \"ghost\" }\n\n[agent.env]\nX = { secret = \"ghost\" }\n",
        );
        let err = merge_default(tmp.path()).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("[tools.gh.env.GH_TOKEN]"), "{message}");
        assert!(message.contains("[agent.env.X]"), "{message}");
    }

    #[test]
    fn discover_repo_only() {
        let tmp = tempdir().unwrap();
        write(tmp.path(), "airlock.toml", "[tools.t]\n");
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        assert!(layers.repo.is_some());
        assert!(layers.local.is_none());
        assert_eq!(layers.repo.unwrap().kind, LayerKind::Repo);
    }

    #[test]
    fn discover_local_only() {
        let tmp = tempdir().unwrap();
        write(tmp.path(), "airlock.local.toml", "[tools.t]\n");
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        assert!(layers.repo.is_none());
        assert!(layers.local.is_some());
    }

    #[test]
    fn discover_both() {
        let tmp = tempdir().unwrap();
        write(tmp.path(), "airlock.toml", "[tools.t]\n");
        write(tmp.path(), "airlock.local.toml", "[tools.u]\n");
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        assert!(layers.repo.is_some());
        assert!(layers.local.is_some());
    }

    #[test]
    fn discover_none_errors() {
        let tmp = tempdir().unwrap();
        let err = load_default(tmp.path(), tmp.path()).unwrap_err();
        assert!(matches!(err, ConfigError::NoProjectConfig { .. }));
        assert!(err.to_string().contains("airlock init"));
    }

    #[test]
    fn discover_config_file_mode_has_no_global_or_local() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("custom.toml");
        std::fs::write(&path, "[tools.t]\n").unwrap();
        let layers = load_layers(
            &DiscoveryMode::ConfigFile(path.clone()),
            tmp.path(),
            tmp.path(),
            &tmp.path().join("no-global.toml"),
        )
        .unwrap();
        assert_eq!(layers.repo.as_ref().unwrap().kind, LayerKind::ConfigFile);
        assert!(layers.local.is_none());
        assert!(layers.global.is_none());
        assert_eq!(layers.root, std::fs::canonicalize(tmp.path()).unwrap());
    }

    #[test]
    fn discover_no_project_config_mode_ignores_present_files() {
        let tmp = tempdir().unwrap();
        write(tmp.path(), "airlock.toml", "[tools.t]\n");
        let layers = load_layers(
            &DiscoveryMode::NoProjectConfig,
            tmp.path(),
            tmp.path(),
            &tmp.path().join("no-global.toml"),
        )
        .unwrap();
        assert!(layers.repo.is_none());
        assert!(layers.local.is_none());
        assert_eq!(layers.root, std::fs::canonicalize(tmp.path()).unwrap());
    }

    #[test]
    fn discover_walks_up_to_home() {
        let tmp = tempdir().unwrap();
        let home = tmp.path().join("home");
        let project = home.join("src").join("app");
        std::fs::create_dir_all(&project).unwrap();
        write(&home, "airlock.toml", "[tools.t]\n");
        let layers = load_default(&project, &home).unwrap();
        assert_eq!(layers.root, std::fs::canonicalize(&home).unwrap());
    }

    // ── project_id ────────────────────────────────────────────────────

    #[test]
    fn project_id_is_stable_and_16_hex_chars() {
        let id1 = project_id(Path::new("/some/project"));
        let id2 = project_id(Path::new("/some/project"));
        let id3 = project_id(Path::new("/some/other"));
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
        assert_eq!(id1.len(), 16);
        assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── Merge rules ───────────────────────────────────────────────────

    #[test]
    fn merge_global_tool_replaced_by_repo_is_recorded() {
        let tmp = tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        std::fs::write(&global, "[tools.gh]\ndescription = \"global gh\"\n").unwrap();
        write(
            tmp.path(),
            "airlock.toml",
            "[tools.gh]\ndescription = \"repo gh\"\n",
        );
        let layers = load_layers(&DiscoveryMode::Default, tmp.path(), tmp.path(), &global).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
        let prov = merged.provenance().tools.get("gh").unwrap();
        assert_eq!(prov.layer, LayerKind::Repo);
        assert_eq!(prov.replaced, Some(LayerKind::Global));
        let wire = merged.to_wire();
        assert_eq!(
            wire.tools.unwrap()["gh"].description.as_deref(),
            Some("repo gh")
        );
    }

    #[test]
    fn merge_duplicate_tool_without_override_errors() {
        let tmp = tempdir().unwrap();
        write(tmp.path(), "airlock.toml", "[tools.gh]\n");
        write(tmp.path(), "airlock.local.toml", "[tools.gh]\n");
        let err = merge_default(tmp.path()).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateTool { ref tool, .. } if tool == "gh"));
        assert!(err.to_string().contains("override = true"));
    }

    #[test]
    fn merge_duplicate_tool_with_override_uses_local() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "airlock.toml",
            "[tools.gh]\ndescription = \"repo\"\n",
        );
        write(
            tmp.path(),
            "airlock.local.toml",
            "[tools.gh]\ndescription = \"local\"\noverride = true\n",
        );
        let merged = merge_default(tmp.path()).unwrap();
        let wire = merged.to_wire();
        assert_eq!(
            wire.tools.unwrap()["gh"].description.as_deref(),
            Some("local")
        );
    }

    #[test]
    fn merge_override_without_repo_tool_errors() {
        let tmp = tempdir().unwrap();
        write(tmp.path(), "airlock.toml", "[tools.other]\n");
        write(
            tmp.path(),
            "airlock.local.toml",
            "[tools.gh]\noverride = true\n",
        );
        let err = merge_default(tmp.path()).unwrap_err();
        assert!(
            matches!(err, ConfigError::OverrideWithoutRepoTool { ref tool, .. } if tool == "gh")
        );
    }

    #[test]
    fn merge_override_in_repo_layer_errors() {
        let tmp = tempdir().unwrap();
        write(tmp.path(), "airlock.toml", "[tools.gh]\noverride = true\n");
        let err = merge_default(tmp.path()).unwrap_err();
        assert!(matches!(err, ConfigError::OverrideOutsideLocal { .. }));
    }

    #[test]
    fn merge_allow_home_root_in_repo_errors() {
        let tmp = tempdir().unwrap();
        write(tmp.path(), "airlock.toml", "allow_home_root = true\n");
        let err = merge_default(tmp.path()).unwrap_err();
        assert!(matches!(err, ConfigError::AllowHomeRootInRepo { .. }));
    }

    #[test]
    fn merge_unbound_repo_label_without_local_binding_errors() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "airlock.toml",
            "[secrets.GH_TOKEN]\ndescription = \"GitHub token\"\n",
        );
        let err = merge_default(tmp.path()).unwrap_err();
        match err {
            ConfigError::UnboundSecretLabels { labels, .. } => {
                assert_eq!(
                    labels,
                    vec![("GH_TOKEN".to_string(), Some("GitHub token".to_string()))]
                );
            }
            other => panic!("expected UnboundSecretLabels, got: {other:?}"),
        }
    }

    #[test]
    fn merge_local_binds_repo_label_with_own_source() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "airlock.toml",
            "[secrets.GH_TOKEN]\n[tools.gh.env]\nGH_TOKEN = { secret = \"GH_TOKEN\" }\n",
        );
        write(
            tmp.path(),
            "airlock.local.toml",
            "[secrets.GH_TOKEN]\nsource = \"env\"\nfrom = \"MY_GH\"\n",
        );
        let merged = merge_default(tmp.path()).unwrap();
        let wire = merged.to_wire();
        let secrets = wire.secrets.unwrap();
        assert_eq!(secrets["GH_TOKEN"].source.as_deref(), Some("env"));
        assert_eq!(secrets["GH_TOKEN"].from.as_deref(), Some("MY_GH"));
    }

    #[test]
    fn merge_local_binds_repo_label_from_global() {
        let tmp = tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        std::fs::write(
            &global,
            "[secrets.GH_TOKEN]\nsource = \"command\"\ncommand = [\"op\", \"read\", \"x\"]\n",
        )
        .unwrap();
        write(
            tmp.path(),
            "airlock.toml",
            "[secrets.GH_TOKEN]\n[tools.gh.env]\nGH_TOKEN = { secret = \"GH_TOKEN\" }\n",
        );
        write(
            tmp.path(),
            "airlock.local.toml",
            "[secrets.GH_TOKEN]\nfrom = \"global\"\n",
        );
        let layers = load_layers(&DiscoveryMode::Default, tmp.path(), tmp.path(), &global).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
        let wire = merged.to_wire();
        let secrets = wire.secrets.unwrap();
        assert_eq!(secrets["GH_TOKEN"].source.as_deref(), Some("command"));
        assert_eq!(
            secrets["GH_TOKEN"].command.as_deref(),
            Some(&["op".to_string(), "read".to_string(), "x".to_string()][..])
        );
        assert_eq!(
            merged.provenance().secrets.get("GH_TOKEN"),
            Some(&SecretProvenance::GlobalLink)
        );
    }

    #[test]
    fn merge_global_item_using_non_global_label_errors() {
        let tmp = tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        std::fs::write(&global, "[tools.aws.env]\nX = { secret = \"NOPE\" }\n").unwrap();
        write(tmp.path(), "airlock.toml", "[tools.other]\n");
        let layers = load_layers(&DiscoveryMode::Default, tmp.path(), tmp.path(), &global).unwrap();
        let err = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::GlobalItemUsesNonGlobalLabel { .. }
        ));
    }

    #[test]
    fn merge_repo_item_using_non_repo_label_errors() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "airlock.toml",
            "[tools.gh.env]\nX = { secret = \"NOPE\" }\n",
        );
        let err = merge_default(tmp.path()).unwrap_err();
        assert!(matches!(err, ConfigError::RepoItemUsesNonRepoLabel { .. }));
    }

    #[test]
    fn merge_local_item_may_reference_global_label_directly() {
        let tmp = tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        std::fs::write(
            &global,
            "[secrets.GH_TOKEN]\nsource = \"env\"\nfrom = \"GH\"\n",
        )
        .unwrap();
        write(tmp.path(), "airlock.toml", "[tools._placeholder]\n");
        write(
            tmp.path(),
            "airlock.local.toml",
            "[tools.gh.env]\nGH_TOKEN = { secret = \"GH_TOKEN\" }\n",
        );
        let layers = load_layers(&DiscoveryMode::Default, tmp.path(), tmp.path(), &global).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
        let wire = merged.to_wire();
        assert!(wire.secrets.unwrap().contains_key("GH_TOKEN"));
    }

    #[test]
    fn merge_refuses_a_project_at_home_reached_through_a_symlink() {
        let tmp = tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let link = tmp.path().join("home-link");
        std::os::unix::fs::symlink(&home, &link).unwrap();
        write(&home, "airlock.toml", "[tools.t]\n");
        let layers = load_default(&home, &home).unwrap();
        let c = MergeContext {
            root: layers.root.clone(),
            home: link,
            tool_state_base: tmp.path().join("cache"),
        };
        let err = merge(&layers, &c).unwrap_err();
        assert!(
            matches!(err, ConfigError::HomeRootNotAllowed { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn merge_tool_state_placeholder_resolves_and_grants_write() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "airlock.toml",
            "[tools.gh.env]\nGH_CONFIG_DIR = \"{tool_state}\"\n",
        );
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        let c = ctx(&layers.root.clone(), tmp.path());
        let merged = merge(&layers, &c).unwrap();
        let id = project_id(&layers.root);
        let expected = c.tool_state_base.join(&id).join("gh");
        assert_eq!(merged.tool_state_dirs(), std::slice::from_ref(&expected));
        let wire = merged.to_wire();
        let tool = &wire.tools.unwrap()["gh"];
        assert!(tool.extra_write.contains(&expected.display().to_string()));
        match &tool.env.as_ref().unwrap()["GH_CONFIG_DIR"] {
            RawEnvValue::Static(s) => assert_eq!(s, &expected.display().to_string()),
            other => panic!("expected Static, got {other:?}"),
        }
    }

    #[test]
    fn merge_relative_path_in_global_errors() {
        let tmp = tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        std::fs::write(&global, "[filesystem]\nread = [\"relative/path\"]\n").unwrap();
        write(tmp.path(), "airlock.toml", "[tools.t]\n");
        let layers = load_layers(&DiscoveryMode::Default, tmp.path(), tmp.path(), &global).unwrap();
        let err = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap_err();
        assert!(matches!(err, ConfigError::RelativePathInGlobal { .. }));
    }

    #[test]
    fn merge_settings_union_and_highest_wins() {
        // Mirrors "Worked examples → Three layers and the merged result" in
        // docs/airlock-v2-design.md.
        let tmp = tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        std::fs::write(
            &global,
            r#"
[secrets.GH_TOKEN]
source  = "command"
command = ["op", "read", "op://Private/GitHub/token"]

[tools.aws]
description = "AWS CLI"
[tools.aws.env]
AWS_PROFILE = "personal"

[agent]
passthrough_env = ["COLORTERM"]
"#,
        )
        .unwrap();
        write(
            tmp.path(),
            "airlock.toml",
            r#"
timeout = 120

[secrets.GH_TOKEN]
source = "env"

[tools.gh]
description = "GitHub CLI"
[tools.gh.env]
GH_TOKEN = { secret = "GH_TOKEN" }

[agent]
passthrough_env = ["NO_COLOR"]
[agent.env]
LOG_LEVEL = "info"
"#,
        );
        write(
            tmp.path(),
            "airlock.local.toml",
            r#"
[secrets.GH_TOKEN]
source  = "command"
command = ["gh", "auth", "token"]

[tools.psql]
description = "Postgres shell"
[tools.psql.env]
PGSERVICE = "app-dev"

[agent.env]
LOG_LEVEL = "debug"
"#,
        );

        let layers = load_layers(&DiscoveryMode::Default, tmp.path(), tmp.path(), &global).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
        let wire = merged.to_wire();

        assert_eq!(wire.timeout, Some(120));

        let secrets = wire.secrets.unwrap();
        assert_eq!(secrets["GH_TOKEN"].source.as_deref(), Some("command"));
        assert_eq!(
            secrets["GH_TOKEN"].command.as_deref(),
            Some(&["gh".to_string(), "auth".to_string(), "token".to_string()][..])
        );

        let tools = wire.tools.unwrap();
        assert_eq!(tools.len(), 3);
        assert!(tools.contains_key("aws"));
        assert!(tools.contains_key("gh"));
        assert!(tools.contains_key("psql"));

        let agent = wire.agent.unwrap();
        let mut passthrough = agent.passthrough_env.clone();
        passthrough.sort();
        assert_eq!(
            passthrough,
            vec!["COLORTERM".to_string(), "NO_COLOR".to_string()]
        );
        match &agent.env["LOG_LEVEL"] {
            RawEnvValue::Static(s) => assert_eq!(s, "debug"),
            other => panic!("expected Static, got {other:?}"),
        }
    }

    #[test]
    fn merge_access_top_level_highest_layer_wins_and_tool_access_travels_with_tool() {
        // Top-level `access` merges like `timeout`: the highest layer that
        // sets it wins. A tool's own `access` travels with its definition
        // under the existing tool-replacement rules, independent of the
        // top-level value.
        let tmp = tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        std::fs::write(&global, "access = \"none\"\n").unwrap();
        write(
            tmp.path(),
            "airlock.toml",
            r#"
access = "system"

[tools.gh]
description = "GitHub CLI"
access = "default"
"#,
        );

        let layers = load_layers(&DiscoveryMode::Default, tmp.path(), tmp.path(), &global).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
        let wire = merged.to_wire();

        // The repo layer's `access` beats the global layer's.
        assert_eq!(wire.access.as_deref(), Some("system"));
        assert_eq!(merged.provenance().settings.access, Some(LayerKind::Repo));

        let tools = wire.tools.unwrap();
        assert_eq!(tools["gh"].access.as_deref(), Some("default"));
    }

    #[test]
    fn merge_settings_provenance_matches_the_design_doc_worked_example() {
        // Mirrors "Worked examples → Three layers and the merged result":
        // timeout from repo, GH_TOKEN's source from local (a LocalOverride
        // of a repo label), passthrough_env entries from their own layers,
        // and LOG_LEVEL overriding the repo's value.
        let tmp = tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        std::fs::write(
            &global,
            r#"
[secrets.GH_TOKEN]
source  = "command"
command = ["op", "read", "op://Private/GitHub/token"]

[agent]
passthrough_env = ["COLORTERM"]
"#,
        )
        .unwrap();
        write(
            tmp.path(),
            "airlock.toml",
            r#"
timeout = 120

[secrets.GH_TOKEN]
source = "env"

[tools.gh.env]
GH_TOKEN = { secret = "GH_TOKEN" }

[filesystem]
read = ["/opt/homebrew/share"]

[agent]
passthrough_env = ["NO_COLOR"]
[agent.env]
LOG_LEVEL = "info"
"#,
        );
        write(
            tmp.path(),
            "airlock.local.toml",
            r#"
[secrets.GH_TOKEN]
source  = "command"
command = ["gh", "auth", "token"]

[agent.env]
LOG_LEVEL = "debug"
"#,
        );

        let layers = load_layers(&DiscoveryMode::Default, tmp.path(), tmp.path(), &global).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
        let settings = &merged.provenance().settings;

        assert_eq!(settings.timeout, Some(LayerKind::Repo));
        assert_eq!(
            settings.filesystem_read,
            vec![("/opt/homebrew/share".to_string(), LayerKind::Repo)]
        );
        assert_eq!(
            settings.agent_passthrough_env,
            vec![
                ("COLORTERM".to_string(), LayerKind::Global),
                ("NO_COLOR".to_string(), LayerKind::Repo),
            ]
        );
        let log_level = settings.agent_env.get("LOG_LEVEL").unwrap();
        assert_eq!(log_level.layer, LayerKind::Local);
        assert_eq!(log_level.overrides, Some(LayerKind::Repo));
    }

    // ── Kits ──────────────────────────────────────────────────────────

    #[test]
    fn merge_kits_in_repo_layer_errors() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "airlock.toml",
            "[kits.rust]\nmode = \"shared\"\n",
        );
        let err = merge_default(tmp.path()).unwrap_err();
        assert!(matches!(err, ConfigError::KitsInRepo { .. }));
    }

    #[test]
    fn merge_kits_in_local_layer_is_allowed_and_not_on_the_wire() {
        let tmp = tempdir().unwrap();
        write(tmp.path(), "airlock.toml", "[tools.t]\n");
        write(
            tmp.path(),
            "airlock.local.toml",
            "[kits.rust]\nmode = \"shared\"\n",
        );
        let merged = merge_default(tmp.path()).unwrap();
        assert_eq!(
            merged.kits().get("rust").and_then(|d| d.mode.as_deref()),
            Some("shared")
        );
        assert!(merged.provenance().kits.get("rust").copied() == Some(LayerKind::Local));
        // The wire RawConfig sent to the daemon never carries [kits.*].
        assert!(merged.to_wire().kits.is_none());
    }

    #[test]
    fn merge_kits_in_global_layer_is_allowed() {
        let tmp = tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        std::fs::write(&global, "[kits.go]\nmode = \"shared\"\n").unwrap();
        write(tmp.path(), "airlock.toml", "[tools.t]\n");
        let layers = load_layers(&DiscoveryMode::Default, tmp.path(), tmp.path(), &global).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
        assert_eq!(
            merged.kits().get("go").and_then(|d| d.mode.as_deref()),
            Some("shared")
        );
        assert_eq!(
            merged.provenance().kits.get("go").copied(),
            Some(LayerKind::Global)
        );
    }

    #[test]
    fn merge_local_kit_table_overrides_global_whole() {
        let tmp = tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        std::fs::write(&global, "[kits.rust]\nmode = \"shared\"\n").unwrap();
        write(tmp.path(), "airlock.toml", "[tools.t]\n");
        write(
            tmp.path(),
            "airlock.local.toml",
            "[kits.rust]\nmode = \"isolated\"\n",
        );
        let layers = load_layers(&DiscoveryMode::Default, tmp.path(), tmp.path(), &global).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
        assert_eq!(
            merged.kits().get("rust").and_then(|d| d.mode.as_deref()),
            Some("isolated")
        );
        assert_eq!(
            merged.provenance().kits.get("rust").copied(),
            Some(LayerKind::Local)
        );
    }

    #[test]
    fn merge_global_kit_relative_path_errors() {
        let tmp = tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        std::fs::write(&global, "[kits.bazel]\nread = [\"relative\"]\n").unwrap();
        write(tmp.path(), "airlock.toml", "[tools.t]\n");
        let layers = load_layers(&DiscoveryMode::Default, tmp.path(), tmp.path(), &global).unwrap();
        let err = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap_err();
        assert!(matches!(err, ConfigError::RelativePathInGlobal { .. }));
    }

    #[test]
    fn merge_agent_kits_unions_across_layers_and_records_provenance() {
        let tmp = tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        std::fs::write(&global, "[agent]\nkits = [\"rust\"]\n").unwrap();
        write(tmp.path(), "airlock.toml", "[agent]\nkits = [\"node\"]\n");
        write(
            tmp.path(),
            "airlock.local.toml",
            "[agent]\nkits = [\"rust\", \"go\"]\n",
        );
        let layers = load_layers(&DiscoveryMode::Default, tmp.path(), tmp.path(), &global).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
        let wire = merged.to_wire();
        assert_eq!(
            wire.agent.unwrap().kits,
            vec!["rust".to_string(), "node".to_string(), "go".to_string()]
        );
        assert_eq!(
            merged.provenance().settings.agent_kits,
            vec![
                ("rust".to_string(), LayerKind::Global),
                ("node".to_string(), LayerKind::Repo),
                ("go".to_string(), LayerKind::Local),
            ]
        );
    }

    // ── Wire round trip ───────────────────────────────────────────────

    #[test]
    fn wire_round_trip_preserves_tools_and_secrets() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "airlock.toml",
            "[secrets.API_KEY]\nsource = \"env\"\n[tools.t.env]\nAPI_KEY = { secret = \"API_KEY\" }\n",
        );
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
        let wire = merged.to_wire();

        let json = serde_json::to_string(&wire).unwrap();
        let round_tripped: RawConfig = serde_json::from_str(&json).unwrap();
        let resolved = config::resolve_wire_config(round_tripped, &layers.root).unwrap();

        assert_eq!(resolved.tools.len(), 1);
        assert_eq!(resolved.secrets.len(), 1);
        assert!(matches!(
            resolved.secrets["API_KEY"].source,
            SecretSource::Env { .. }
        ));
    }

    #[test]
    fn to_wire_rejects_deny_unknown_fields_round_trip_via_toml() {
        let tmp = tempdir().unwrap();
        write(tmp.path(), "airlock.toml", "[tools.t]\n");
        let merged = merge_default(tmp.path()).unwrap();
        let wire = merged.to_wire();
        let toml_text = toml::to_string(&wire).unwrap();
        let reparsed: RawConfig = toml::from_str(&toml_text).unwrap();
        assert!(reparsed.tools.unwrap().contains_key("t"));
    }

    // ── Parent configs ────────────────────────────────────────────────

    /// `<tmp>/ws` (the parent, with `parent_toml` as its `airlock.toml`)
    /// and `<tmp>/ws/proj` (the project, with `proj_toml`), `<tmp>` standing
    /// in for home. Returns the temp dir and the canonical project root.
    fn workspace(parent_toml: &str, proj_toml: &str) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempdir().unwrap();
        let ws = tmp.path().join("ws");
        let proj = ws.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write(&ws, "airlock.toml", parent_toml);
        write(&proj, "airlock.toml", proj_toml);
        let root = std::fs::canonicalize(&proj).unwrap();
        (tmp, root)
    }

    fn load_and_merge(cwd: &Path, home: &Path) -> Result<MergedConfig, ConfigError> {
        let layers = load_default(cwd, home)?;
        merge(&layers, &ctx(&layers.root.clone(), home))
    }

    #[test]
    fn discover_cascading_parent_is_loaded_and_root_stays_the_project() {
        let (tmp, root) = workspace("cascade = true\n", "");
        let layers = load_default(&root, tmp.path()).unwrap();
        assert_eq!(layers.root, root);
        assert_eq!(layers.parents.len(), 1);
        assert_eq!(layers.parents[0].dir, root.parent().unwrap());
        let files = layers.approvable_files();
        let kinds: Vec<_> = files
            .iter()
            .map(|a| (a.kind, a.dir.to_path_buf()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (LayerKind::Parent, root.parent().unwrap().to_path_buf()),
                (LayerKind::Repo, root.clone()),
            ]
        );
    }

    #[test]
    fn discover_parent_without_cascade_is_ignored() {
        let (tmp, root) = workspace("[tools.kubectl]\n", "");
        let layers = load_default(&root, tmp.path()).unwrap();
        assert!(layers.parents.is_empty());
    }

    #[test]
    fn discover_inherit_false_in_the_project_ignores_parents() {
        let (tmp, root) = workspace("cascade = true\n", "inherit = false\n");
        let layers = load_default(&root, tmp.path()).unwrap();
        assert!(layers.parents.is_empty());
    }

    #[test]
    fn discover_local_inherit_overrides_repo() {
        let (tmp, root) = workspace("cascade = true\n", "inherit = false\n");
        write(&root, "airlock.local.toml", "inherit = true\n");
        let layers = load_default(&root, tmp.path()).unwrap();
        assert_eq!(layers.parents.len(), 1);
    }

    #[test]
    fn discover_skips_a_non_cascading_dir_and_stops_at_inherit_false() {
        // <tmp>/a (cascades) > <tmp>/a/b (cascades, inherit = false) >
        // <tmp>/a/b/c (no cascade) > <tmp>/a/b/c/proj.
        let tmp = tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = a.join("b");
        let c = b.join("c");
        let proj = c.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write(&a, "airlock.toml", "cascade = true\n");
        write(
            &b,
            "airlock.local.toml",
            "cascade = true\ninherit = false\n",
        );
        write(&c, "airlock.toml", "");
        write(&proj, "airlock.toml", "");
        let layers = load_default(&proj, tmp.path()).unwrap();
        let dirs: Vec<_> = layers.parents.iter().map(|p| p.dir.clone()).collect();
        assert_eq!(dirs, vec![std::fs::canonicalize(&b).unwrap()]);
    }

    #[test]
    fn discover_home_is_never_a_parent() {
        let tmp = tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write(tmp.path(), "airlock.toml", "cascade = true\n");
        write(&proj, "airlock.toml", "");
        let layers = load_default(&proj, tmp.path()).unwrap();
        assert!(layers.parents.is_empty());
    }

    #[test]
    fn discover_config_file_mode_has_no_parents() {
        let (_tmp, root) = workspace("cascade = true\n", "");
        let layers = load_layers(
            &DiscoveryMode::ConfigFile(root.join("airlock.toml")),
            &root,
            root.parent().unwrap().parent().unwrap(),
            Path::new("/nonexistent-airlock-global.toml"),
        )
        .unwrap();
        assert!(layers.parents.is_empty());
    }

    #[test]
    fn merge_parent_tool_is_inherited_with_parent_provenance() {
        let (tmp, root) = workspace(
            "cascade = true\n[secrets.KUBE]\nsource = \"env\"\n[tools.kubectl.env]\nKUBECONFIG = { secret = \"KUBE\" }\n",
            "",
        );
        let merged = load_and_merge(&root, tmp.path()).unwrap();
        let wire = merged.to_wire();
        assert!(wire.tools.as_ref().unwrap().contains_key("kubectl"));
        assert!(wire.secrets.as_ref().unwrap().contains_key("KUBE"));
        let prov = merged.provenance();
        assert_eq!(prov.tools["kubectl"].layer, LayerKind::Parent);
        assert_eq!(
            prov.secrets["KUBE"],
            SecretProvenance::Direct(LayerKind::Parent)
        );
        assert!(wire.cascade.is_none() && wire.inherit.is_none());
    }

    #[test]
    fn merge_project_tool_replaces_parent_tool() {
        let (tmp, root) = workspace("cascade = true\n[tools.gh]\n", "[tools.gh]\n");
        let merged = load_and_merge(&root, tmp.path()).unwrap();
        assert_eq!(
            merged.provenance().tools["gh"],
            ToolProvenance {
                layer: LayerKind::Repo,
                replaced: Some(LayerKind::Parent),
            }
        );
    }

    #[test]
    fn merge_project_repo_item_cannot_use_a_parent_label() {
        let (tmp, root) = workspace(
            "cascade = true\n[secrets.GCP]\nsource = \"env\"\n",
            "[tools.gcloud.env]\nTOKEN = { secret = \"GCP\" }\n",
        );
        let err = load_and_merge(&root, tmp.path()).unwrap_err();
        assert!(
            matches!(err, ConfigError::RepoItemUsesNonRepoLabel { .. }),
            "{err}"
        );
    }

    #[test]
    fn merge_local_from_parent_binds_a_repo_label() {
        let (tmp, root) = workspace(
            "cascade = true\n[secrets.GCP]\nsource = \"command\"\ncommand = [\"gcp-token\"]\n",
            "[secrets.GCP]\n[tools.gcloud.env]\nTOKEN = { secret = \"GCP\" }\n",
        );
        write(
            &root,
            "airlock.local.toml",
            "[secrets.GCP]\nfrom = \"parent\"\n",
        );
        let merged = load_and_merge(&root, tmp.path()).unwrap();
        let spec = &merged.to_wire().secrets.unwrap()["GCP"];
        assert_eq!(
            spec.command.as_deref(),
            Some(&["gcp-token".to_string()][..])
        );
        assert_eq!(
            merged.provenance().secrets["GCP"],
            SecretProvenance::ParentLink
        );
    }

    #[test]
    fn merge_from_parent_without_a_parent_errors() {
        let tmp = tempdir().unwrap();
        write(tmp.path(), "airlock.toml", "[secrets.GCP]\n");
        write(
            tmp.path(),
            "airlock.local.toml",
            "[secrets.GCP]\nfrom = \"parent\"\n",
        );
        let err = merge_default(tmp.path()).unwrap_err();
        assert!(
            matches!(&err, ConfigError::UnboundLink { from, .. } if from == "parent"),
            "{err}"
        );
    }

    #[test]
    fn merge_from_global_skips_the_parent_binding() {
        let tmp = tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        std::fs::write(
            &global,
            "[secrets.GH]\nsource = \"env\"\nfrom = \"GLOBAL_GH\"\n",
        )
        .unwrap();
        let ws = tmp.path().join("ws");
        let proj = ws.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write(
            &ws,
            "airlock.toml",
            "cascade = true\n[secrets.GH]\nsource = \"env\"\nfrom = \"WORK_GH\"\n",
        );
        write(
            &proj,
            "airlock.toml",
            "[secrets.GH]\n[tools.gh.env]\nGH_TOKEN = { secret = \"GH\" }\n",
        );
        write(
            &proj,
            "airlock.local.toml",
            "[secrets.GH]\nfrom = \"global\"\n",
        );
        let layers = load_layers(&DiscoveryMode::Default, &proj, tmp.path(), &global).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
        let spec = &merged.to_wire().secrets.unwrap()["GH"];
        assert_eq!(spec.from.as_deref(), Some("GLOBAL_GH"));
    }

    #[test]
    fn merge_global_parent_and_project_keep_their_own_provenance() {
        let tmp = tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        std::fs::write(
            &global,
            "[secrets.GH]\nsource = \"env\"\n[tools.gh.env]\nGH_TOKEN = { secret = \"GH\" }\n[agent]\npassthrough_env = [\"TERM\"]\n",
        )
        .unwrap();
        let ws = tmp.path().join("ws");
        let proj = ws.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        // The parent's own tool uses a global label: a parent's local file
        // may, like any local file.
        write(
            &ws,
            "airlock.toml",
            "cascade = true\n[agent]\npassthrough_env = [\"LANG\"]\n",
        );
        write(
            &ws,
            "airlock.local.toml",
            "[tools.argocd.env]\nT = { secret = \"GH\" }\n",
        );
        write(&proj, "airlock.toml", "[tools.make]\n");
        let layers = load_layers(&DiscoveryMode::Default, &proj, tmp.path(), &global).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
        let prov = merged.provenance();
        assert_eq!(prov.tools["gh"].layer, LayerKind::Global);
        assert_eq!(prov.tools["argocd"].layer, LayerKind::Parent);
        assert_eq!(prov.tools["make"].layer, LayerKind::Repo);
        assert_eq!(
            prov.secrets["GH"],
            SecretProvenance::Direct(LayerKind::Global)
        );
        assert_eq!(
            prov.settings.agent_passthrough_env,
            vec![
                ("TERM".to_string(), LayerKind::Global),
                ("LANG".to_string(), LayerKind::Parent),
            ]
        );
    }

    #[test]
    fn merge_parent_relative_paths_resolve_against_the_parent_dir() {
        let (tmp, root) = workspace(
            "cascade = true\n[filesystem]\nread = [\"shared\"]\n[tools.t]\nextra_read = [\"bin\"]\n",
            "[filesystem]\nread = [\"own\"]\n",
        );
        let ws = root.parent().unwrap();
        let wire = load_and_merge(&root, tmp.path()).unwrap().to_wire();
        let fs = wire.filesystem.unwrap();
        assert!(
            fs.read.contains(&ws.join("shared").display().to_string()),
            "{fs:?}"
        );
        assert!(
            fs.read.contains(&root.join("own").display().to_string()),
            "{fs:?}"
        );
        let tool = &wire.tools.unwrap()["t"];
        assert_eq!(tool.extra_read, vec![ws.join("bin").display().to_string()]);
    }

    #[test]
    fn merge_parent_placeholders_render_against_the_project_root() {
        let (tmp, root) = workspace(
            "cascade = true\n[tools.t.env]\nA = \"{sandbox_root}/x\"\nB = \"{tool_state}\"\nC = \"\\\\{literal\\\\}\"\n",
            "",
        );
        let layers = load_default(&root, tmp.path()).unwrap();
        let c = ctx(&layers.root.clone(), tmp.path());
        let merged = merge(&layers, &c).unwrap();
        let state = c.tool_state_base.join(project_id(&root)).join("t");
        assert_eq!(merged.tool_state_dirs(), std::slice::from_ref(&state));
        let wire = merged.to_wire();
        let tool = &wire.tools.unwrap()["t"];
        let env = tool.env.as_ref().unwrap();
        let text = |k: &str| match &env[k] {
            RawEnvValue::Static(s) => s.clone(),
            other => panic!("expected Static, got {other:?}"),
        };
        assert_eq!(text("A"), format!("{}/x", root.display()));
        assert_eq!(text("B"), state.display().to_string());
        assert_eq!(text("C"), "{literal}");
        assert!(tool.extra_write.contains(&state.display().to_string()));
    }

    #[test]
    fn merge_parent_local_kit_paths_resolve_against_the_parent_dir() {
        let (tmp, root) = workspace("cascade = true\n", "");
        let ws = root.parent().unwrap();
        write(ws, "airlock.local.toml", "[kits.tools]\nread = [\"opt\"]\n");
        let merged = load_and_merge(&root, tmp.path()).unwrap();
        assert_eq!(
            merged.kits()["tools"].read,
            vec![ws.join("opt").display().to_string()]
        );
        assert_eq!(merged.provenance().kits["tools"], LayerKind::Parent);
    }

    #[test]
    fn merge_parent_repo_file_keeps_the_repo_rules() {
        let (tmp, root) = workspace("cascade = true\nallow_home_root = true\n", "");
        let err = load_and_merge(&root, tmp.path()).unwrap_err();
        assert!(
            matches!(err, ConfigError::AllowHomeRootInRepo { .. }),
            "{err}"
        );
    }

    #[test]
    fn merge_cascade_in_global_errors() {
        let tmp = tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        std::fs::write(&global, "cascade = true\n").unwrap();
        write(tmp.path(), "airlock.toml", "");
        let layers = load_layers(&DiscoveryMode::Default, tmp.path(), tmp.path(), &global).unwrap();
        let err = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::InheritanceKeyInGlobal { key: "cascade", .. }
            ),
            "{err}"
        );
    }
}
