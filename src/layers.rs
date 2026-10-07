//! Config layering for Airlock v2: discovery of the global/repo/local
//! files, merging them into one config, and the cross-layer rules that
//! decide which tool or secret binding wins.
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
    /// `airlock.toml` or `airlock.local.toml`.
    Default,
    /// Use exactly this file as the project's only (repo-position) layer.
    /// No global layer, no local layer. The project root is its parent
    /// directory.
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

/// The layers found for one project, before merging.
#[derive(Debug)]
pub struct LoadedLayers {
    /// The project root, which is also the sandbox root.
    pub root: PathBuf,
    pub global: Option<LayerFile>,
    /// The project-declared layer: `airlock.toml`, or (in
    /// [`DiscoveryMode::ConfigFile`]) the `--config` file, in which case its
    /// [`LayerFile::kind`] is [`LayerKind::ConfigFile`] rather than
    /// [`LayerKind::Repo`].
    pub repo: Option<LayerFile>,
    pub local: Option<LayerFile>,
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
            Ok(LoadedLayers {
                root,
                global,
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

pub use crate::config::project_id;

// ─── Merge ──────────────────────────────────────────────────────────────────

/// Inputs to [`merge`] that would otherwise come from the environment.
pub struct MergeContext {
    /// The project root, as found by [`load_layers`].
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
            | ClassifiedSecret::Bound { description, .. } => description.clone(),
        }
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
            if value != "global" {
                return Err(ConfigError::InvalidFromValue {
                    file: file.to_path_buf(),
                    label: label.to_string(),
                    value: value.clone(),
                });
            }
            if kind != LayerKind::Local {
                return Err(ConfigError::FromGlobalOutsideLocal {
                    file: file.to_path_buf(),
                    label: label.to_string(),
                });
            }
            Ok(ClassifiedSecret::GlobalLink {
                description: spec.description.clone(),
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
/// own file), the repo/config layer's must not be `GlobalLink` (`from =
/// "global"` is local-only — already enforced by `classify_secret`, kept
/// here as the single place that owns "what can a layer contain").
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

/// Resolve one `HashMap` of classified secrets into concrete sources,
/// looking up `from = "global"` links in `global` as needed.
fn resolve_pool(
    file: &Path,
    classified: &HashMap<String, ClassifiedSecret>,
    global: &HashMap<String, ClassifiedSecret>,
) -> Result<HashMap<String, SecretSource>, ConfigError> {
    let mut out = HashMap::with_capacity(classified.len());
    for (label, c) in classified {
        let source = match c {
            ClassifiedSecret::Bound { source, .. } => source.clone(),
            ClassifiedSecret::GlobalLink { .. } => match global.get(label) {
                Some(ClassifiedSecret::Bound { source, .. }) => source.clone(),
                _ => {
                    return Err(ConfigError::FromGlobalOutsideLocal {
                        file: file.to_path_buf(),
                        label: label.clone(),
                    });
                }
            },
            ClassifiedSecret::Unbound { .. } => continue,
        };
        out.insert(label.clone(), source);
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
/// / `{tool_state}` in static values and checking every secret reference
/// against the scope-appropriate pool. Returns the rendered env (ready for
/// the wire) and any new `{tool_state}` directories it introduced.
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
    tool_state_dirs: &mut Vec<PathBuf>,
    referenced_global_labels: &mut std::collections::HashSet<String>,
    undeclared_refs: &mut Vec<(String, String, String)>,
) -> Result<HashMap<String, RawEnvValue>, ConfigError> {
    let item = owner.item();
    let mut out = HashMap::with_capacity(raw_env.len());
    for (var_name, raw_value) in raw_env {
        config::check_env_entry(owner, &var_name, &raw_value, is_proxy_tool)?;
        let value = match raw_value {
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

fn resolve_path_list(raw: &[String], ctx: &MergeContext) -> Vec<String> {
    config::resolve_paths_with_home(raw, &ctx.root, &ctx.home)
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
    global_file: Option<&'a Path>,
    repo_file: Option<&'a Path>,
    global: &'a HashMap<String, SecretSource>,
    repo: &'a HashMap<String, SecretSource>,
    /// Global, repo and local-only labels together: a local item may use
    /// any of them.
    local: &'a HashMap<String, SecretSource>,
}

impl<'a> LayerPools<'a> {
    fn for_layer(&self, kind: LayerKind) -> (RefScope<'a>, &'a HashMap<String, SecretSource>) {
        match kind {
            LayerKind::Global => (
                RefScope::Global {
                    file: self
                        .global_file
                        .expect("an item owned by the global layer has a file"),
                },
                self.global,
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

/// Merge a project's loaded layers into one normalized, wire-ready config.
///
/// Parses each layer, applies the per-layer structural rules (repo cannot
/// set `allow_home_root` or `override`, global paths must be absolute),
/// then the cross-layer rules ("Tools across layers", "Secret labels across
/// layers" in the v2 design), then the existing merged-config validation
/// (proxy tools, undeclared refs) that already lived in `config.rs`.
pub fn merge(layers: &LoadedLayers, ctx: &MergeContext) -> Result<MergedConfig, ConfigError> {
    let global_raw = layers.global.as_ref().map(|f| f.parse()).transpose()?;
    let repo_raw = layers.repo.as_ref().map(|f| f.parse()).transpose()?;
    let local_raw = layers.local.as_ref().map(|f| f.parse()).transpose()?;

    let global_file = layers.global.as_ref().map(|f| f.path.as_path());
    let repo_file = layers.repo.as_ref().map(|f| f.path.as_path());
    let local_file = layers.local.as_ref().map(|f| f.path.as_path());
    let repo_kind = layers.repo.as_ref().map_or(LayerKind::Repo, |f| f.kind);
    // Lowest to highest precedence.
    let ordered: [(LayerKind, Option<&RawConfig>); 3] = [
        (LayerKind::Global, global_raw.as_ref()),
        (repo_kind, repo_raw.as_ref()),
        (LayerKind::Local, local_raw.as_ref()),
    ];

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
    if let (Some(global), Some(file)) = (&global_raw, global_file) {
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
    }

    // ── Home-root guard ──────────────────────────────────────────────────

    let merged_allow_home_root = global_raw.as_ref().and_then(|c| c.allow_home_root) == Some(true)
        || local_raw.as_ref().and_then(|c| c.allow_home_root) == Some(true);
    // Canonical on both sides: the root is canonical already, and a home
    // reached through a symlink must not slip past the guard.
    let home = std::fs::canonicalize(&ctx.home).unwrap_or_else(|_| ctx.home.clone());
    if ctx.root == home && !merged_allow_home_root {
        return Err(ConfigError::HomeRootNotAllowed {
            home: ctx.root.clone(),
        });
    }

    // ── Kits: global/local `[kits.<name>]` tables, local overriding global
    //    whole, by name ────────────────────────────────────────────────────
    // (The repo layer is already refused above.) Table-shape validation
    // (built-in vs. user-defined field restrictions, {tool_state}, env var
    // names) and resolving `agent.kits` into an active list happen later, in
    // crate::kits, called from crate::launcher::prepare — this only needs
    // to merge the raw tables and record which layer each came from.
    let mut kits: BTreeMap<String, RawKitConfig> = BTreeMap::new();
    let mut kit_provenance: HashMap<String, LayerKind> = HashMap::new();
    if let Some(global) = global_raw.as_ref().and_then(|c| c.kits.as_ref()) {
        for (name, def) in global {
            kits.insert(name.clone(), def.clone());
            kit_provenance.insert(name.clone(), LayerKind::Global);
        }
    }
    if let Some(local) = local_raw.as_ref().and_then(|c| c.kits.as_ref()) {
        for (name, def) in local {
            kits.insert(name.clone(), def.clone());
            kit_provenance.insert(name.clone(), LayerKind::Local);
        }
    }

    // ── Secret classification and the unbound-labels check ──────────────

    let global_secrets =
        classify_layer_secrets(global_file, global_raw.as_ref(), LayerKind::Global)?;
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
                .unwrap_or_else(|| ctx.root.join(config::config_filename())),
            labels: unbound,
        });
    }

    // ── Resolve the three pools of concrete secret sources ──────────────

    let global_pool = resolve_pool(
        global_file.unwrap_or(&ctx.root),
        &global_secrets,
        &global_secrets,
    )?;

    // repo_secrets, with any local override applied in place.
    let mut repo_effective: HashMap<String, ClassifiedSecret> = HashMap::new();
    for (label, classified) in &repo_secrets {
        if let Some(local_classified) = local_secrets.get(label) {
            match local_classified {
                ClassifiedSecret::Bound {
                    description,
                    source,
                } => {
                    repo_effective.insert(
                        label.clone(),
                        ClassifiedSecret::Bound {
                            description: description.clone().or_else(|| classified.description()),
                            source: source.clone(),
                        },
                    );
                }
                ClassifiedSecret::GlobalLink { description } => {
                    repo_effective.insert(
                        label.clone(),
                        ClassifiedSecret::GlobalLink {
                            description: description.clone().or_else(|| classified.description()),
                        },
                    );
                }
                ClassifiedSecret::Unbound { .. } => unreachable!(
                    "classify_layer_secrets never produces Unbound for the local layer"
                ),
            }
        } else {
            repo_effective.insert(label.clone(), classified.clone());
        }
    }
    let repo_pool = resolve_pool(
        local_file.or(repo_file).unwrap_or(&ctx.root),
        &repo_effective,
        &global_secrets,
    )?;

    let local_only: HashMap<String, ClassifiedSecret> = local_secrets
        .iter()
        .filter(|(label, _)| !repo_secrets.contains_key(*label))
        .map(|(label, c)| (label.clone(), c.clone()))
        .collect();
    let local_only_pool = resolve_pool(
        local_file.unwrap_or(&ctx.root),
        &local_only,
        &global_secrets,
    )?;

    let combined_for_local: HashMap<String, SecretSource> = global_pool
        .iter()
        .chain(repo_pool.iter())
        .chain(local_only_pool.iter())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let pools = LayerPools {
        global_file,
        repo_file,
        global: &global_pool,
        repo: &repo_pool,
        local: &combined_for_local,
    };

    // ── Tool merge ───────────────────────────────────────────────────────

    let empty_tools: HashMap<String, RawToolConfig> = HashMap::new();
    let global_tools = global_raw
        .as_ref()
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

    let mut tool_names: Vec<&String> = global_tools
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
    let mut referenced_global_labels: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut undeclared_refs: Vec<(String, String, String)> = Vec::new();

    let project_id = config::project_id(&ctx.root);

    for name in tool_names {
        config::validate_tool_name(name)?;

        let in_repo = repo_tools.contains_key(name);
        let in_local = local_tools.contains_key(name);
        let in_global = global_tools.contains_key(name);

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
            (&global_tools[name], LayerKind::Global)
        };

        let replaced = if in_global && owning_layer != LayerKind::Global {
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
            &global_pool,
            winning.proxy,
            &mut tool_state_dirs,
            &mut referenced_global_labels,
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

        let mut extra_write = resolve_path_list(&winning.extra_write, ctx);
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
                extra_read: resolve_path_list(&winning.extra_read, ctx),
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
                    union_with_layer(&mut fs_read, *kind, resolve_path_list(&fs.read, ctx));
                    union_with_layer(&mut fs_write, *kind, resolve_path_list(&fs.write, ctx));
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
                    &global_pool,
                    false,
                    &mut tool_state_dirs,
                    &mut referenced_global_labels,
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
    //    global ones ───────────────────────────────────────────────────

    let mut secret_provenance: HashMap<String, SecretProvenance> = HashMap::new();
    let mut final_secrets: HashMap<String, RawSecretSpec> = HashMap::new();

    for (label, source) in &repo_pool {
        let description = repo_effective
            .get(label)
            .and_then(|c| c.description())
            .or_else(|| repo_secrets.get(label).and_then(|c| c.description()));
        final_secrets.insert(label.clone(), source_to_raw(source, description));
        let provenance = match local_secrets.get(label) {
            Some(ClassifiedSecret::Bound { .. }) => SecretProvenance::LocalOverride,
            Some(ClassifiedSecret::GlobalLink { .. }) => SecretProvenance::GlobalLink,
            _ => SecretProvenance::Direct(repo_kind),
        };
        secret_provenance.insert(label.clone(), provenance);
    }
    for (label, source) in &local_only_pool {
        let description = local_only.get(label).and_then(|c| c.description());
        final_secrets.insert(label.clone(), source_to_raw(source, description));
        let provenance = match local_secrets.get(label) {
            Some(ClassifiedSecret::GlobalLink { .. }) => SecretProvenance::GlobalLink,
            _ => SecretProvenance::Direct(LayerKind::Local),
        };
        secret_provenance.insert(label.clone(), provenance);
    }
    for label in &referenced_global_labels {
        if final_secrets.contains_key(label) {
            continue;
        }
        if let Some(source) = global_pool.get(label) {
            let description = global_secrets.get(label).and_then(|c| c.description());
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
            union_with_layer(&mut fs_read_prov, kind, resolve_path_list(&fs.read, ctx));
            union_with_layer(&mut fs_write_prov, kind, resolve_path_list(&fs.write, ctx));
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
        // Launcher-only (crate::kits); never sent to the daemon.
        kits: None,
    };

    Ok(MergedConfig {
        raw,
        root: ctx.root.clone(),
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
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        let err = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap_err();
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
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        let err = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap_err();
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
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
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
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        let err = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap_err();
        assert!(
            matches!(err, ConfigError::OverrideWithoutRepoTool { ref tool, .. } if tool == "gh")
        );
    }

    #[test]
    fn merge_override_in_repo_layer_errors() {
        let tmp = tempdir().unwrap();
        write(tmp.path(), "airlock.toml", "[tools.gh]\noverride = true\n");
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        let err = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap_err();
        assert!(matches!(err, ConfigError::OverrideOutsideLocal { .. }));
    }

    #[test]
    fn merge_allow_home_root_in_repo_errors() {
        let tmp = tempdir().unwrap();
        write(tmp.path(), "airlock.toml", "allow_home_root = true\n");
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        let err = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap_err();
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
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        let err = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap_err();
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
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
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
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        let err = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap_err();
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
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        let err = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap_err();
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
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
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
        let layers = load_default(tmp.path(), tmp.path()).unwrap();
        let merged = merge(&layers, &ctx(&layers.root.clone(), tmp.path())).unwrap();
        let wire = merged.to_wire();
        let toml_text = toml::to_string(&wire).unwrap();
        let reparsed: RawConfig = toml::from_str(&toml_text).unwrap();
        assert!(reparsed.tools.unwrap().contains_key("t"));
    }
}
