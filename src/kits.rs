//! Agent "kits": composable, per-kind-of-work additions to the `airlock
//! run` agent sandbox — language toolchain and package-cache access,
//! layered independently of the harness profile (`--profile claude`, see
//! [`crate::run::Profile`]).
//!
//! Kits apply only to the agent sandbox and environment [`crate::run`]
//! builds. They never reach a tool sandbox, and never apply to `session
//! start` (an external harness owns that sandbox) — see "Kits" in
//! `docs/airlock-v2-design.md`.
//!
//! This module is a pure data/expansion layer: every input that would
//! otherwise come from the environment (home, the env snapshot, the
//! platform, the project id, `tool_state_base`, the sandbox root) is a
//! parameter on [`Inputs`], so [`expand_all`] is unit-testable without a
//! real filesystem or process environment. [`crate::launcher::prepare`] is
//! the only caller that supplies real values; it also validates (before
//! expanding) and creates whatever directories/files [`Expanded`] says a
//! kit needs.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use crate::config::{self, ConfigError, RawAgentConfig, RawConfig, RawKitConfig};

// ─── Built-in kits ──────────────────────────────────────────────────────────

/// The built-in kit names, in the order they're documented.
pub const BUILTIN_KITS: &[&str] = &["rust", "node", "python", "go", "elixir"];

/// Whether `name` is one of [`BUILTIN_KITS`].
pub fn is_builtin(name: &str) -> bool {
    BUILTIN_KITS.contains(&name)
}

/// A built-in kit's mode: whether its caches live inside Airlock's
/// per-project `{kit_state}` directory (isolated, the default) or at the
/// tool's real, shared location (shared).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Isolated,
    Shared,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "isolated" => Some(Mode::Isolated),
            "shared" => Some(Mode::Shared),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Isolated => "isolated",
            Mode::Shared => "shared",
        }
    }
}

/// The platform a kit expands for — a parameter rather than a `cfg!` read
/// inside expansion, so both platforms' defaults are unit-testable from a
/// single build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Linux,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Platform::MacOs
        } else {
            Platform::Linux
        }
    }
}

/// Resolve a kit's mode from its (possibly absent) `[kits.<name>]` table.
/// Only meaningful for a built-in kit — callers never ask for a
/// user-defined one's "mode".
fn mode_of(name: &str, kit_defs: &BTreeMap<String, RawKitConfig>) -> Mode {
    kit_defs
        .get(name)
        .and_then(|d| d.mode.as_deref())
        .and_then(Mode::parse)
        .unwrap_or_default()
}

/// `{kit_state}`: `<tool_state_base>/kits/<project_id>/<kit>`, a sibling
/// tree of `{tool_state}` (`<tool_state_base>/<project_id>/<tool>`,
/// [`config::resolve_tool_state_path`]). A project id is 16 hex characters
/// ([`config::project_id`]), so it can never equal the literal `kits`.
pub fn kit_state_dir(tool_state_base: &Path, project_id: &str, kit: &str) -> PathBuf {
    tool_state_base.join("kits").join(project_id).join(kit)
}

/// The env var names a kit sets, for the `[agent.env.<key>]`-vs-kit
/// collision check ([`check_env_collision`]). A built-in's names are read
/// off its own expansion, not kept in a second list that would have to be
/// updated by hand alongside it; which names a mode sets never depends on
/// the inputs, only their values do.
fn env_var_names(name: &str, mode: Mode, kit_defs: &BTreeMap<String, RawKitConfig>) -> Vec<String> {
    if is_builtin(name) {
        let no_env = BTreeMap::new();
        let inputs = Inputs {
            home: Path::new("/"),
            env: &no_env,
            platform: Platform::current(),
            project_id: "",
            tool_state_base: Path::new("/"),
            root: Path::new("/"),
        };
        expand_builtin(name, mode, &inputs, Path::new("/"))
            .env
            .into_keys()
            .collect()
    } else {
        kit_defs
            .get(name)
            .map(|d| d.env.keys().cloned().collect())
            .unwrap_or_default()
    }
}

// ─── Validation ─────────────────────────────────────────────────────────────

/// Validates every `[kits.<name>]` table's shape: built-in kits may only
/// set `mode` (to `"isolated"`/`"shared"`); user-defined kits may not set
/// `mode`, may not reference `{tool_state}` anywhere in `read`/`write`/
/// `env`, and their `env` keys must be valid POSIX names.
///
/// Placement (global/local only, never repo) is checked in
/// [`crate::layers::merge`], which is the only place with per-layer
/// `RawConfig`s in scope.
pub fn validate_all(kit_defs: &BTreeMap<String, RawKitConfig>) -> Result<(), ConfigError> {
    for (name, def) in kit_defs {
        validate_def(name, def)?;
    }
    Ok(())
}

fn validate_def(name: &str, def: &RawKitConfig) -> Result<(), ConfigError> {
    if is_builtin(name) {
        if !def.read.is_empty() {
            return Err(ConfigError::KitBuiltinExtraField {
                kit: name.to_string(),
                field: "read",
            });
        }
        if !def.write.is_empty() {
            return Err(ConfigError::KitBuiltinExtraField {
                kit: name.to_string(),
                field: "write",
            });
        }
        if !def.env.is_empty() {
            return Err(ConfigError::KitBuiltinExtraField {
                kit: name.to_string(),
                field: "env",
            });
        }
        if let Some(m) = &def.mode
            && Mode::parse(m).is_none()
        {
            return Err(ConfigError::KitUnknownMode {
                kit: name.to_string(),
                mode: m.clone(),
            });
        }
    } else {
        if def.mode.is_some() {
            return Err(ConfigError::KitUserDefinedHasMode {
                kit: name.to_string(),
            });
        }
        for (field, list) in [("read", &def.read), ("write", &def.write)] {
            if list.iter().any(|p| p.contains("{tool_state}")) {
                return Err(ConfigError::KitToolStateForbidden {
                    kit: name.to_string(),
                    field,
                });
            }
        }
        for (var, value) in &def.env {
            if !config::is_valid_env_var_name(var) {
                return Err(ConfigError::KitInvalidEnvVarName {
                    kit: name.to_string(),
                    name: var.clone(),
                });
            }
            if value.contains("{tool_state}") {
                return Err(ConfigError::KitToolStateForbidden {
                    kit: name.to_string(),
                    field: "env",
                });
            }
            // Surfaces a malformed template or an unknown placeholder at
            // config-validation time, not first use — render the same
            // template expand_user will, against a throwaway state path.
            render_kit_env_value(value, Path::new("/kit-state"), name, var)?;
        }
    }
    Ok(())
}

/// Resolves the agent's active kit list: the merged config's `agent.kits`
/// (already unioned across layers by `layers::merge`) plus `--kit` CLI
/// flags (run-only; empty elsewhere), deduplicated, validated against the
/// known kit names (built-ins plus any `[kits.<name>]` table).
pub fn resolve_active(
    raw_config: &RawConfig,
    cli_kits: &[String],
    kit_defs: &BTreeMap<String, RawKitConfig>,
) -> Result<Vec<String>, ConfigError> {
    let mut active: Vec<String> = raw_config
        .agent
        .as_ref()
        .map(|a| a.kits.clone())
        .unwrap_or_default();
    for k in cli_kits {
        if !active.contains(k) {
            active.push(k.clone());
        }
    }
    for name in &active {
        if !is_builtin(name) && !kit_defs.contains_key(name) {
            let mut known: Vec<String> = BUILTIN_KITS.iter().map(|s| s.to_string()).collect();
            known.extend(kit_defs.keys().cloned());
            known.sort();
            known.dedup();
            return Err(ConfigError::UnknownKit {
                kit: name.clone(),
                known,
            });
        }
    }
    Ok(active)
}

/// Checks that no `[agent.env.<key>]` entry collides with an env var one of
/// `active`'s kits also sets (at `active`'s resolved modes).
pub fn check_env_collision(
    agent: Option<&RawAgentConfig>,
    active: &[String],
    kit_defs: &BTreeMap<String, RawKitConfig>,
) -> Result<(), ConfigError> {
    let Some(agent) = agent else { return Ok(()) };
    let mut owner: HashMap<String, String> = HashMap::new();
    for name in active {
        let mode = mode_of(name, kit_defs);
        for var in env_var_names(name, mode, kit_defs) {
            owner.insert(var, name.clone());
        }
    }
    let mut keys: Vec<&String> = agent.env.keys().collect();
    keys.sort();
    for key in keys {
        if let Some(kit) = owner.get(key) {
            return Err(ConfigError::AgentEnvSetByKit {
                key: key.clone(),
                kit: kit.clone(),
            });
        }
    }
    Ok(())
}

// ─── Expansion ──────────────────────────────────────────────────────────────

/// Inputs to [`expand_all`] that would otherwise come from the environment
/// or the project's own discovery — every one a parameter, so expansion is
/// testable without a real filesystem or process environment.
pub struct Inputs<'a> {
    pub home: &'a Path,
    /// The launcher's environment snapshot — consulted only for a shared
    /// built-in kit's own override variable (`CARGO_HOME`, `GOPATH`, ...).
    pub env: &'a BTreeMap<String, String>,
    pub platform: Platform,
    pub project_id: &'a str,
    pub tool_state_base: &'a Path,
    /// The project (sandbox) root, for resolving a relative path in a
    /// user-defined kit's `read`/`write` list.
    pub root: &'a Path,
}

/// Every active kit's expanded contribution to the agent sandbox and
/// environment, folded together.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expanded {
    /// Read-only grants. Not filtered by existence — the caller
    /// ([`crate::run::run_agent`]) does that, same as
    /// [`crate::run::detect_toolchain_paths`].
    pub read: Vec<PathBuf>,
    /// Directories to grant read-write and create (mode 0700) if missing.
    pub write: Vec<PathBuf>,
    /// Individual files to grant read-write and create (empty) if missing
    /// — Landlock can only grant a path that exists.
    pub write_files: Vec<PathBuf>,
    /// Each active kit's own `{kit_state}` directory (isolated built-ins
    /// and every user-defined kit) — validated like a tool's `{tool_state}`
    /// dir before creation.
    pub state_dirs: Vec<PathBuf>,
    /// Environment variables to set on the agent (isolated built-ins and
    /// user-defined kits only; empty for a shared built-in).
    pub env: BTreeMap<String, String>,
    /// `(name, mode)` for display (`airlock run -v`, `airlock config`).
    /// `mode` is `None` for a user-defined kit, which has no mode concept.
    pub active: Vec<(String, Option<Mode>)>,
}

/// Expands every kit in `active` and folds the results together. `kit_defs`
/// is the merged `[kits.<name>]` table map ([`crate::layers::MergedConfig::kits`]);
/// `active` is expected to already be validated by [`resolve_active`] (every
/// name built-in or present in `kit_defs`).
pub fn expand_all(
    active: &[String],
    kit_defs: &BTreeMap<String, RawKitConfig>,
    inputs: &Inputs<'_>,
) -> Result<Expanded, ConfigError> {
    let mut out = Expanded::default();
    for name in active {
        let state = kit_state_dir(inputs.tool_state_base, inputs.project_id, name);
        if is_builtin(name) {
            let mode = mode_of(name, kit_defs);
            let one = expand_builtin(name, mode, inputs, &state);
            if mode == Mode::Isolated {
                out.state_dirs.push(state);
            }
            out.read.extend(one.read);
            out.write.extend(one.write);
            out.write_files.extend(one.write_files);
            out.env.extend(one.env);
            out.active.push((name.clone(), Some(mode)));
        } else {
            let def = kit_defs
                .get(name)
                .expect("resolve_active already checked every non-builtin name has a table");
            let one = expand_user(name, def, inputs, &state)?;
            out.state_dirs.push(state);
            out.read.extend(one.read);
            out.write.extend(one.write);
            out.env.extend(one.env);
            out.active.push((name.clone(), None));
        }
    }
    Ok(out)
}

fn expand_builtin(kit: &str, mode: Mode, inputs: &Inputs<'_>, state: &Path) -> Expanded {
    match kit {
        "rust" => expand_rust(mode, inputs, state),
        "node" => expand_node(mode, inputs, state),
        "python" => expand_python(mode, inputs, state),
        "go" => expand_go(mode, inputs, state),
        "elixir" => expand_elixir(mode, inputs, state),
        _ => Expanded::default(),
    }
}

/// `$VAR` from the env snapshot, or `default` when absent.
impl Inputs<'_> {
    /// A per-user location under `home` that differs by platform:
    /// `macos` on macOS (usually under `Library/`), `linux` on Linux
    /// (usually an XDG-style dot directory).
    fn home_path(&self, macos: &str, linux: &str) -> PathBuf {
        self.home.join(match self.platform {
            Platform::MacOs => macos,
            Platform::Linux => linux,
        })
    }
}

fn env_or(inputs: &Inputs<'_>, var: &str, default: PathBuf) -> PathBuf {
    inputs.env.get(var).map(PathBuf::from).unwrap_or(default)
}

fn expand_rust(mode: Mode, inputs: &Inputs<'_>, state: &Path) -> Expanded {
    let home = inputs.home;
    let mut out = Expanded {
        read: vec![home.join(".rustup"), home.join(".cargo/bin")],
        ..Default::default()
    };
    match mode {
        Mode::Isolated => {
            let cargo_home = state.join("cargo");
            out.env
                .insert("CARGO_HOME".to_string(), cargo_home.display().to_string());
            out.write.push(cargo_home);
        }
        Mode::Shared => {
            let cargo_home = env_or(inputs, "CARGO_HOME", home.join(".cargo"));
            // The user's own cargo settings (aliases, build flags, registry
            // sources) and registry credentials apply to the agent too, so
            // private registries and `cargo publish` work. Read-only: a
            // writable config could set `build.rustc-wrapper` and run code
            // in the user's next unsandboxed build. The extensionless names
            // are the pre-1.39 ones.
            for f in ["config.toml", "config", "credentials.toml", "credentials"] {
                out.read.push(cargo_home.join(f));
            }
            out.write.push(cargo_home.join("registry"));
            out.write.push(cargo_home.join("git"));
            // `.global-cache` is a SQLite database; its rollback journal is
            // created and deleted around every write. Seatbelt lets a
            // single-file grant do both. Landlock can't grant creating one
            // name in a directory, so on Linux cargo warns that it couldn't
            // record last-use data, and the build itself is unaffected.
            for f in [
                ".package-cache",
                ".package-cache-mutate",
                ".global-cache",
                ".global-cache-journal",
            ] {
                out.write_files.push(cargo_home.join(f));
            }
        }
    }
    out
}

fn expand_node(mode: Mode, inputs: &Inputs<'_>, state: &Path) -> Expanded {
    let home = inputs.home;
    let mut out = Expanded {
        read: vec![
            home.join(".nvm"),
            home.join(".volta"),
            inputs.home_path("Library/Application Support/fnm", ".local/share/fnm"),
            home.join(".bun/bin"),
        ],
        ..Default::default()
    };
    match mode {
        Mode::Isolated => {
            for (var, sub) in [
                ("npm_config_cache", "npm"),
                ("YARN_CACHE_FOLDER", "yarn"),
                ("npm_config_store_dir", "pnpm"),
                ("BUN_INSTALL_CACHE_DIR", "bun"),
                ("COREPACK_HOME", "corepack"),
            ] {
                let dir = state.join(sub);
                out.env.insert(var.to_string(), dir.display().to_string());
                out.write.push(dir);
            }
        }
        Mode::Shared => {
            out.write
                .push(env_or(inputs, "npm_config_cache", home.join(".npm")));
            out.write.push(env_or(
                inputs,
                "YARN_CACHE_FOLDER",
                inputs.home_path("Library/Caches/Yarn", ".cache/yarn"),
            ));
            out.write.push(env_or(
                inputs,
                "npm_config_store_dir",
                inputs.home_path("Library/pnpm/store", ".local/share/pnpm/store"),
            ));
            out.write.push(env_or(
                inputs,
                "BUN_INSTALL_CACHE_DIR",
                home.join(".bun/install/cache"),
            ));
            out.write.push(env_or(
                inputs,
                "COREPACK_HOME",
                inputs.home_path("Library/Caches/node/corepack", ".cache/node/corepack"),
            ));
            // Registry settings and auth tokens, read-only: npm and pnpm
            // read the user npmrc, Yarn 2+ its own yarnrc. A writable npmrc
            // could set `script-shell` or `node-options` and run code
            // outside the sandbox.
            let npmrc = inputs
                .env
                .get("npm_config_userconfig")
                .or_else(|| inputs.env.get("NPM_CONFIG_USERCONFIG"))
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".npmrc"));
            out.read.push(npmrc);
            out.read.push(home.join(".yarnrc.yml"));
        }
    }
    out
}

fn expand_python(mode: Mode, inputs: &Inputs<'_>, state: &Path) -> Expanded {
    let home = inputs.home;
    let mut out = Expanded {
        read: vec![home.join(".pyenv"), home.join(".local/share/uv/python")],
        ..Default::default()
    };
    match mode {
        Mode::Isolated => {
            for (var, sub) in [
                ("PIP_CACHE_DIR", "pip"),
                ("UV_CACHE_DIR", "uv"),
                ("POETRY_CACHE_DIR", "poetry"),
            ] {
                let dir = state.join(sub);
                out.env.insert(var.to_string(), dir.display().to_string());
                out.write.push(dir);
            }
        }
        Mode::Shared => {
            out.write.push(env_or(
                inputs,
                "PIP_CACHE_DIR",
                inputs.home_path("Library/Caches/pip", ".cache/pip"),
            ));
            // Index settings and upload credentials, read-only: pip's user
            // config (a PIP_CONFIG_FILE override, the platform location, and
            // the legacy ~/.pip), uv's user config, and twine's ~/.pypirc.
            if let Some(file) = inputs.env.get("PIP_CONFIG_FILE") {
                out.read.push(PathBuf::from(file));
            }
            if inputs.platform == Platform::MacOs {
                out.read
                    .push(home.join("Library/Application Support/pip/pip.conf"));
            }
            out.read.push(home.join(".config/pip/pip.conf"));
            out.read.push(home.join(".pip/pip.conf"));
            out.read.push(home.join(".config/uv/uv.toml"));
            out.read.push(home.join(".pypirc"));
            // uv does not follow platform cache-dir convention on macOS;
            // it uses ~/.cache/uv (or $XDG_CACHE_HOME/uv) on every platform.
            out.write
                .push(env_or(inputs, "UV_CACHE_DIR", home.join(".cache/uv")));
            out.write.push(env_or(
                inputs,
                "POETRY_CACHE_DIR",
                inputs.home_path("Library/Caches/pypoetry", ".cache/pypoetry"),
            ));
        }
    }
    out
}

fn expand_go(mode: Mode, inputs: &Inputs<'_>, state: &Path) -> Expanded {
    let home = inputs.home;
    let mut out = Expanded {
        read: vec![home.join("go/bin"), home.join("sdk")],
        ..Default::default()
    };
    match mode {
        Mode::Isolated => {
            // GOPATH is isolated too, not just GOMODCACHE/GOCACHE: `go
            // install`'s output and the sumdb cache
            // ($GOPATH/pkg/sumdb) live under GOPATH and have no env var
            // of their own, so leaving GOPATH at its default would let
            // the agent write into the user's real ~/go after all.
            let gomodcache = state.join("mod");
            let gocache = state.join("build");
            let gopath = state.join("go");
            out.env
                .insert("GOMODCACHE".to_string(), gomodcache.display().to_string());
            out.env
                .insert("GOCACHE".to_string(), gocache.display().to_string());
            out.env
                .insert("GOPATH".to_string(), gopath.display().to_string());
            out.write.push(gomodcache);
            out.write.push(gocache);
            out.write.push(gopath);
        }
        Mode::Shared => {
            let gopath = env_or(inputs, "GOPATH", home.join("go"));
            out.write
                .push(env_or(inputs, "GOMODCACHE", gopath.join("pkg/mod")));
            out.write.push(gopath.join("pkg/sumdb"));
            out.write.push(env_or(
                inputs,
                "GOCACHE",
                inputs.home_path("Library/Caches/go-build", ".cache/go-build"),
            ));
        }
    }
    out
}

/// `~/.mix` holds both archives (code Mix loads — the hex and rebar
/// archives) and escripts (executables); writing it in shared mode would be
/// a sandbox escape, the same way `~/.cargo/bin` is. Of `~/.hex`, shared
/// mode writes only `~/.hex/packages`, the package cache, and reads
/// `hex.config`, which holds the user's Hex API key and repo settings, so
/// private repos and `mix hex.publish` work.
fn expand_elixir(mode: Mode, inputs: &Inputs<'_>, state: &Path) -> Expanded {
    let home = inputs.home;
    // Both modes need to know where the real ~/.mix lives, honoring an
    // existing MIX_HOME override, to read the already-installed hex/rebar
    // archives and the rebar3 escript Mix keeps under
    // `<real_mix_home>/elixir/<version>/` — mix local.rebar's install
    // location.
    let real_mix_home = env_or(inputs, "MIX_HOME", home.join(".mix"));
    let mut out = Expanded {
        read: vec![home.join(".asdf"), home.join(".kiex")],
        ..Default::default()
    };
    match mode {
        Mode::Isolated => {
            let mix_home = state.join("mix");
            let hex_home = state.join("hex");
            let rebar_cache = state.join("rebar3");
            out.env
                .insert("MIX_HOME".to_string(), mix_home.display().to_string());
            out.env
                .insert("HEX_HOME".to_string(), hex_home.display().to_string());
            out.env.insert(
                "REBAR_CACHE_DIR".to_string(),
                rebar_cache.display().to_string(),
            );
            out.write.push(mix_home);
            out.write.push(hex_home);
            out.write.push(rebar_cache);
            // MIX_ARCHIVES points isolated Mix at the user's real, already
            // installed hex/rebar archives (read-only) so the agent does
            // not need to run `mix local.hex`/`mix local.rebar` again; the
            // rebar3 escript itself lives one level up, under `elixir/`.
            out.env.insert(
                "MIX_ARCHIVES".to_string(),
                real_mix_home.join("archives").display().to_string(),
            );
            out.read.push(real_mix_home.join("archives"));
            out.read.push(real_mix_home.join("elixir"));
        }
        Mode::Shared => {
            out.read.push(real_mix_home);
            let hex_home = env_or(inputs, "HEX_HOME", home.join(".hex"));
            out.read.push(hex_home.join("hex.config"));
            out.write.push(hex_home.join("packages"));
            out.write.push(env_or(
                inputs,
                "REBAR_CACHE_DIR",
                home.join(".cache/rebar3"),
            ));
        }
    }
    out
}

fn expand_user(
    kit: &str,
    def: &RawKitConfig,
    inputs: &Inputs<'_>,
    state: &Path,
) -> Result<Expanded, ConfigError> {
    let read = config::resolve_paths_with_home(&def.read, inputs.root, inputs.home);
    let write = config::resolve_paths_with_home(&def.write, inputs.root, inputs.home);
    let mut env = BTreeMap::new();
    let mut names: Vec<&String> = def.env.keys().collect();
    names.sort();
    for var in names {
        let rendered = render_kit_env_value(&def.env[var], state, kit, var)?;
        env.insert(var.clone(), rendered);
    }
    Ok(Expanded {
        read,
        write,
        write_files: Vec::new(),
        state_dirs: Vec::new(),
        env,
        active: Vec::new(),
    })
}

/// Renders a user-defined kit's static `env` value as a leon template. Only
/// `{kit_state}` is a recognized placeholder — `{tool_state}` is refused
/// earlier, with its own error, by [`validate_def`].
fn render_kit_env_value(
    raw: &str,
    kit_state: &Path,
    kit: &str,
    var_name: &str,
) -> Result<String, ConfigError> {
    let template = leon::Template::parse(raw).map_err(|e| ConfigError::KitEnvTemplateParse {
        kit: kit.to_string(),
        var_name: var_name.to_string(),
        message: e.to_string(),
    })?;
    let state = kit_state.display().to_string();
    let mut values: HashMap<&str, &str> = HashMap::with_capacity(1);
    values.insert("kit_state", state.as_str());
    template.render(&values).map_err(|e| match e {
        leon::RenderError::MissingKey(key) => ConfigError::KitUnknownEnvPlaceholder {
            kit: kit.to_string(),
            var_name: var_name.to_string(),
            placeholder: key,
        },
        other => ConfigError::KitEnvTemplateParse {
            kit: kit.to_string(),
            var_name: var_name.to_string(),
            message: other.to_string(),
        },
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs<'a>(
        home: &'a Path,
        env: &'a BTreeMap<String, String>,
        platform: Platform,
        root: &'a Path,
    ) -> Inputs<'a> {
        Inputs {
            home,
            env,
            platform,
            project_id: "deadbeefdeadbeef",
            tool_state_base: Path::new("/cache/airlock"),
            root,
        }
    }

    fn empty_env() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    // ── kit_state_dir ─────────────────────────────────────────────────

    #[test]
    fn kit_state_dir_is_a_sibling_of_tool_state() {
        let state = kit_state_dir(Path::new("/cache/airlock"), "proj123", "rust");
        assert_eq!(state, PathBuf::from("/cache/airlock/kits/proj123/rust"));
        let tool_state =
            config::resolve_tool_state_path(Path::new("/cache/airlock"), "proj123", "gh");
        assert_eq!(tool_state, PathBuf::from("/cache/airlock/proj123/gh"));
        assert!(state != tool_state);
    }

    // ── validate_def ─────────────────────────────────────────────────

    #[test]
    fn validate_builtin_rejects_read_write_env() {
        let def = RawKitConfig {
            read: vec!["~/.x".to_string()],
            ..Default::default()
        };
        assert!(matches!(
            validate_def("rust", &def),
            Err(ConfigError::KitBuiltinExtraField { field: "read", .. })
        ));
    }

    #[test]
    fn validate_builtin_rejects_unknown_mode() {
        let def = RawKitConfig {
            mode: Some("sandboxed".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            validate_def("go", &def),
            Err(ConfigError::KitUnknownMode { .. })
        ));
    }

    #[test]
    fn validate_builtin_accepts_isolated_and_shared() {
        for m in ["isolated", "shared"] {
            let def = RawKitConfig {
                mode: Some(m.to_string()),
                ..Default::default()
            };
            validate_def("node", &def).expect("valid mode");
        }
    }

    #[test]
    fn validate_user_defined_rejects_mode() {
        let def = RawKitConfig {
            mode: Some("isolated".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            validate_def("bazel", &def),
            Err(ConfigError::KitUserDefinedHasMode { .. })
        ));
    }

    #[test]
    fn validate_user_defined_rejects_tool_state_in_read() {
        let def = RawKitConfig {
            read: vec!["{tool_state}/x".to_string()],
            ..Default::default()
        };
        assert!(matches!(
            validate_def("bazel", &def),
            Err(ConfigError::KitToolStateForbidden { field: "read", .. })
        ));
    }

    #[test]
    fn validate_user_defined_rejects_tool_state_in_env() {
        let mut env = HashMap::new();
        env.insert("X".to_string(), "{tool_state}/x".to_string());
        let def = RawKitConfig {
            env,
            ..Default::default()
        };
        assert!(matches!(
            validate_def("bazel", &def),
            Err(ConfigError::KitToolStateForbidden { field: "env", .. })
        ));
    }

    #[test]
    fn validate_user_defined_rejects_bad_env_var_name() {
        let mut env = HashMap::new();
        env.insert("not valid".to_string(), "x".to_string());
        let def = RawKitConfig {
            env,
            ..Default::default()
        };
        assert!(matches!(
            validate_def("bazel", &def),
            Err(ConfigError::KitInvalidEnvVarName { .. })
        ));
    }

    #[test]
    fn validate_user_defined_rejects_unknown_placeholder() {
        let mut env = HashMap::new();
        env.insert("X".to_string(), "{sandbox_root}/x".to_string());
        let def = RawKitConfig {
            env,
            ..Default::default()
        };
        assert!(matches!(
            validate_def("bazel", &def),
            Err(ConfigError::KitUnknownEnvPlaceholder { .. })
        ));
    }

    #[test]
    fn validate_user_defined_rejects_malformed_template() {
        let mut env = HashMap::new();
        env.insert("X".to_string(), "{unbalanced".to_string());
        let def = RawKitConfig {
            env,
            ..Default::default()
        };
        assert!(matches!(
            validate_def("bazel", &def),
            Err(ConfigError::KitEnvTemplateParse { .. })
        ));
    }

    #[test]
    fn validate_user_defined_accepts_kit_state_placeholder() {
        let mut env = HashMap::new();
        env.insert(
            "BAZEL_OUTPUT_USER_ROOT".to_string(),
            "{kit_state}/out".to_string(),
        );
        let def = RawKitConfig {
            env,
            ..Default::default()
        };
        validate_def("bazel", &def).expect("kit_state is valid");
    }

    // ── resolve_active ───────────────────────────────────────────────

    #[test]
    fn resolve_active_unions_config_and_cli_kits() {
        let raw = RawConfig {
            agent: Some(RawAgentConfig {
                kits: vec!["rust".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let active = resolve_active(&raw, &["node".to_string()], &BTreeMap::new()).unwrap();
        assert_eq!(active, vec!["rust".to_string(), "node".to_string()]);
    }

    #[test]
    fn resolve_active_dedups() {
        let raw = RawConfig {
            agent: Some(RawAgentConfig {
                kits: vec!["rust".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let active = resolve_active(&raw, &["rust".to_string()], &BTreeMap::new()).unwrap();
        assert_eq!(active, vec!["rust".to_string()]);
    }

    #[test]
    fn resolve_active_accepts_user_defined_kit_with_table() {
        let raw = RawConfig {
            agent: Some(RawAgentConfig {
                kits: vec!["bazel".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut kit_defs = BTreeMap::new();
        kit_defs.insert("bazel".to_string(), RawKitConfig::default());
        resolve_active(&raw, &[], &kit_defs).expect("bazel is known");
    }

    #[test]
    fn resolve_active_rejects_unknown_kit_and_lists_known_ones() {
        let raw = RawConfig {
            agent: Some(RawAgentConfig {
                kits: vec!["rust".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut kit_defs = BTreeMap::new();
        kit_defs.insert("bazel".to_string(), RawKitConfig::default());
        let err = resolve_active(&raw, &["nope".to_string()], &kit_defs).unwrap_err();
        match err {
            ConfigError::UnknownKit { kit, known } => {
                assert_eq!(kit, "nope");
                assert_eq!(
                    known,
                    vec![
                        "bazel".to_string(),
                        "elixir".to_string(),
                        "go".to_string(),
                        "node".to_string(),
                        "python".to_string(),
                        "rust".to_string(),
                    ]
                );
            }
            other => panic!("expected UnknownKit, got {other:?}"),
        }
    }

    // ── check_env_collision ──────────────────────────────────────────

    #[test]
    fn check_env_collision_catches_isolated_builtin() {
        let mut env = HashMap::new();
        env.insert(
            "CARGO_HOME".to_string(),
            crate::config::RawEnvValue::Static("/x".to_string()),
        );
        let agent = RawAgentConfig {
            env,
            ..Default::default()
        };
        let err =
            check_env_collision(Some(&agent), &["rust".to_string()], &BTreeMap::new()).unwrap_err();
        assert!(matches!(err, ConfigError::AgentEnvSetByKit { kit, .. } if kit == "rust"));
    }

    #[test]
    fn check_env_collision_catches_every_var_an_isolated_builtin_sets() {
        let agent = RawAgentConfig {
            env: HashMap::from([(
                "MIX_ARCHIVES".to_string(),
                crate::config::RawEnvValue::Static("/x".to_string()),
            )]),
            ..Default::default()
        };
        let err = check_env_collision(Some(&agent), &["elixir".to_string()], &BTreeMap::new())
            .unwrap_err();
        assert!(matches!(err, ConfigError::AgentEnvSetByKit { kit, .. } if kit == "elixir"));
    }

    #[test]
    fn check_env_collision_ignores_shared_builtin() {
        let mut env = HashMap::new();
        env.insert(
            "CARGO_HOME".to_string(),
            crate::config::RawEnvValue::Static("/x".to_string()),
        );
        let agent = RawAgentConfig {
            env,
            ..Default::default()
        };
        let mut kit_defs = BTreeMap::new();
        kit_defs.insert(
            "rust".to_string(),
            RawKitConfig {
                mode: Some("shared".to_string()),
                ..Default::default()
            },
        );
        check_env_collision(Some(&agent), &["rust".to_string()], &kit_defs)
            .expect("shared rust sets no env");
    }

    #[test]
    fn check_env_collision_catches_user_defined_kit() {
        let mut agent_env = HashMap::new();
        agent_env.insert(
            "BAZEL_OUTPUT_USER_ROOT".to_string(),
            crate::config::RawEnvValue::Static("/x".to_string()),
        );
        let agent = RawAgentConfig {
            env: agent_env,
            ..Default::default()
        };
        let mut kit_env = HashMap::new();
        kit_env.insert(
            "BAZEL_OUTPUT_USER_ROOT".to_string(),
            "{kit_state}/out".to_string(),
        );
        let mut kit_defs = BTreeMap::new();
        kit_defs.insert(
            "bazel".to_string(),
            RawKitConfig {
                env: kit_env,
                ..Default::default()
            },
        );
        let err = check_env_collision(Some(&agent), &["bazel".to_string()], &kit_defs).unwrap_err();
        assert!(matches!(err, ConfigError::AgentEnvSetByKit { kit, .. } if kit == "bazel"));
    }

    // ── expand_all: rust ─────────────────────────────────────────────

    #[test]
    fn expand_rust_isolated_sets_cargo_home_under_kit_state() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let env = empty_env();
        let inp = inputs(&home, &env, Platform::MacOs, &root);
        let expanded = expand_all(&["rust".to_string()], &BTreeMap::new(), &inp).unwrap();
        assert_eq!(
            expanded.env.get("CARGO_HOME").map(String::as_str),
            Some("/cache/airlock/kits/deadbeefdeadbeef/rust/cargo")
        );
        assert!(expanded.write.contains(&PathBuf::from(
            "/cache/airlock/kits/deadbeefdeadbeef/rust/cargo"
        )));
        assert!(expanded.read.contains(&home.join(".rustup")));
        assert!(expanded.read.contains(&home.join(".cargo/bin")));
        assert_eq!(
            expanded.state_dirs,
            vec![PathBuf::from("/cache/airlock/kits/deadbeefdeadbeef/rust")]
        );
    }

    #[test]
    fn expand_rust_shared_uses_default_cargo_home_when_unset() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let env = empty_env();
        let inp = inputs(&home, &env, Platform::MacOs, &root);
        let mut kit_defs = BTreeMap::new();
        kit_defs.insert(
            "rust".to_string(),
            RawKitConfig {
                mode: Some("shared".to_string()),
                ..Default::default()
            },
        );
        let expanded = expand_all(&["rust".to_string()], &kit_defs, &inp).unwrap();
        assert!(expanded.env.is_empty(), "shared mode sets no env");
        assert!(expanded.write.contains(&home.join(".cargo/registry")));
        assert!(expanded.write.contains(&home.join(".cargo/git")));
        assert!(
            expanded
                .write_files
                .contains(&home.join(".cargo/.package-cache"))
        );
        assert!(
            expanded
                .write_files
                .contains(&home.join(".cargo/.package-cache-mutate"))
        );
        assert!(
            expanded
                .write_files
                .contains(&home.join(".cargo/.global-cache"))
        );
        assert!(
            expanded
                .write_files
                .contains(&home.join(".cargo/.global-cache-journal"))
        );
        assert!(expanded.read.contains(&home.join(".cargo/config.toml")));
        assert!(expanded.read.contains(&home.join(".cargo/config")));
        let everything: Vec<&PathBuf> = expanded
            .read
            .iter()
            .chain(&expanded.write)
            .chain(&expanded.write_files)
            .collect();
        assert!(
            expanded
                .read
                .contains(&home.join(".cargo/credentials.toml"))
        );
        assert!(
            !everything.iter().any(|p| p.ends_with(".cargo")),
            "shared mode must not grant CARGO_HOME itself: {everything:?}"
        );
        assert!(
            !expanded
                .write
                .iter()
                .chain(&expanded.write_files)
                .any(|p| p.to_string_lossy().contains("credentials")
                    || p.to_string_lossy().contains("config")),
            "credentials and config must stay read-only: {everything:?}"
        );
        assert!(
            expanded.state_dirs.is_empty(),
            "shared mode has no kit_state"
        );
    }

    #[test]
    fn expand_rust_shared_honors_cargo_home_override() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let mut env = empty_env();
        env.insert("CARGO_HOME".to_string(), "/custom/cargo".to_string());
        let inp = inputs(&home, &env, Platform::MacOs, &root);
        let mut kit_defs = BTreeMap::new();
        kit_defs.insert(
            "rust".to_string(),
            RawKitConfig {
                mode: Some("shared".to_string()),
                ..Default::default()
            },
        );
        let expanded = expand_all(&["rust".to_string()], &kit_defs, &inp).unwrap();
        assert!(
            expanded
                .write
                .contains(&PathBuf::from("/custom/cargo/registry"))
        );
        assert!(!expanded.write.contains(&home.join(".cargo/registry")));
        assert!(
            expanded
                .read
                .contains(&PathBuf::from("/custom/cargo/config.toml"))
        );
    }

    // ── expand_all: node (platform-dependent defaults) ───────────────

    #[test]
    fn expand_node_shared_macos_defaults() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let env = empty_env();
        let inp = inputs(&home, &env, Platform::MacOs, &root);
        let mut kit_defs = BTreeMap::new();
        kit_defs.insert(
            "node".to_string(),
            RawKitConfig {
                mode: Some("shared".to_string()),
                ..Default::default()
            },
        );
        let expanded = expand_all(&["node".to_string()], &kit_defs, &inp).unwrap();
        assert!(expanded.write.contains(&home.join(".npm")));
        assert!(expanded.write.contains(&home.join("Library/Caches/Yarn")));
        assert!(expanded.write.contains(&home.join("Library/pnpm/store")));
        assert!(expanded.write.contains(&home.join(".bun/install/cache")));
        assert!(
            expanded
                .write
                .contains(&home.join("Library/Caches/node/corepack"))
        );
        assert!(expanded.read.contains(&home.join(".npmrc")));
        assert!(expanded.read.contains(&home.join(".yarnrc.yml")));
        assert!(!expanded.write.contains(&home.join(".npmrc")));
    }

    #[test]
    fn expand_node_shared_honors_npm_userconfig_override() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let mut env = empty_env();
        env.insert(
            "NPM_CONFIG_USERCONFIG".to_string(),
            "/custom/npmrc".to_string(),
        );
        let inp = inputs(&home, &env, Platform::Linux, &root);
        let mut kit_defs = BTreeMap::new();
        kit_defs.insert(
            "node".to_string(),
            RawKitConfig {
                mode: Some("shared".to_string()),
                ..Default::default()
            },
        );
        let expanded = expand_all(&["node".to_string()], &kit_defs, &inp).unwrap();
        assert!(expanded.read.contains(&PathBuf::from("/custom/npmrc")));
        assert!(!expanded.read.contains(&home.join(".npmrc")));
    }

    #[test]
    fn isolated_kits_grant_no_registry_credentials() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let env = empty_env();
        let inp = inputs(&home, &env, Platform::MacOs, &root);
        let kits: Vec<String> = BUILTIN_KITS.iter().map(|k| k.to_string()).collect();
        let expanded = expand_all(&kits, &BTreeMap::new(), &inp).unwrap();
        for file in [
            ".cargo/credentials.toml",
            ".npmrc",
            ".yarnrc.yml",
            ".pypirc",
            ".hex/hex.config",
        ] {
            assert!(
                !expanded.read.contains(&home.join(file)),
                "isolated mode must not grant {file}"
            );
        }
    }

    #[test]
    fn expand_node_shared_linux_defaults() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let env = empty_env();
        let inp = inputs(&home, &env, Platform::Linux, &root);
        let mut kit_defs = BTreeMap::new();
        kit_defs.insert(
            "node".to_string(),
            RawKitConfig {
                mode: Some("shared".to_string()),
                ..Default::default()
            },
        );
        let expanded = expand_all(&["node".to_string()], &kit_defs, &inp).unwrap();
        assert!(expanded.write.contains(&home.join(".npm")));
        assert!(expanded.write.contains(&home.join(".cache/yarn")));
        assert!(
            expanded
                .write
                .contains(&home.join(".local/share/pnpm/store"))
        );
        assert!(expanded.write.contains(&home.join(".cache/node/corepack")));
        assert!(expanded.read.contains(&home.join(".local/share/fnm")));
    }

    #[test]
    fn expand_node_isolated_sets_all_five_vars() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let env = empty_env();
        let inp = inputs(&home, &env, Platform::MacOs, &root);
        let expanded = expand_all(&["node".to_string()], &BTreeMap::new(), &inp).unwrap();
        for var in [
            "npm_config_cache",
            "YARN_CACHE_FOLDER",
            "npm_config_store_dir",
            "BUN_INSTALL_CACHE_DIR",
            "COREPACK_HOME",
        ] {
            assert!(expanded.env.contains_key(var), "missing {var}");
        }
    }

    // ── expand_all: python ───────────────────────────────────────────

    #[test]
    fn expand_python_shared_uv_ignores_macos_convention() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let env = empty_env();
        let inp = inputs(&home, &env, Platform::MacOs, &root);
        let mut kit_defs = BTreeMap::new();
        kit_defs.insert(
            "python".to_string(),
            RawKitConfig {
                mode: Some("shared".to_string()),
                ..Default::default()
            },
        );
        let expanded = expand_all(&["python".to_string()], &kit_defs, &inp).unwrap();
        assert!(expanded.write.contains(&home.join(".cache/uv")));
        assert!(expanded.write.contains(&home.join("Library/Caches/pip")));
        assert!(
            expanded
                .write
                .contains(&home.join("Library/Caches/pypoetry"))
        );
        assert!(expanded.read.contains(&home.join(".pypirc")));
        assert!(
            expanded
                .read
                .contains(&home.join("Library/Application Support/pip/pip.conf"))
        );
        assert!(expanded.read.contains(&home.join(".config/pip/pip.conf")));
        assert!(expanded.read.contains(&home.join(".config/uv/uv.toml")));
        assert!(!expanded.write.contains(&home.join(".pypirc")));
    }

    // ── expand_all: go ────────────────────────────────────────────────

    #[test]
    fn expand_go_isolated_sets_gopath_too() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let env = empty_env();
        let inp = inputs(&home, &env, Platform::Linux, &root);
        let expanded = expand_all(&["go".to_string()], &BTreeMap::new(), &inp).unwrap();
        assert!(expanded.env.contains_key("GOMODCACHE"));
        assert!(expanded.env.contains_key("GOCACHE"));
        assert!(expanded.env.contains_key("GOPATH"));
    }

    #[test]
    fn expand_go_shared_defaults_and_sumdb_under_gopath() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let env = empty_env();
        let inp = inputs(&home, &env, Platform::MacOs, &root);
        let mut kit_defs = BTreeMap::new();
        kit_defs.insert(
            "go".to_string(),
            RawKitConfig {
                mode: Some("shared".to_string()),
                ..Default::default()
            },
        );
        let expanded = expand_all(&["go".to_string()], &kit_defs, &inp).unwrap();
        assert!(expanded.write.contains(&home.join("go/pkg/mod")));
        assert!(expanded.write.contains(&home.join("go/pkg/sumdb")));
        assert!(
            expanded
                .write
                .contains(&home.join("Library/Caches/go-build"))
        );
    }

    #[test]
    fn expand_go_shared_honors_gomodcache_override_independent_of_gopath() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let mut env = empty_env();
        env.insert("GOMODCACHE".to_string(), "/custom/mod".to_string());
        let inp = inputs(&home, &env, Platform::MacOs, &root);
        let mut kit_defs = BTreeMap::new();
        kit_defs.insert(
            "go".to_string(),
            RawKitConfig {
                mode: Some("shared".to_string()),
                ..Default::default()
            },
        );
        let expanded = expand_all(&["go".to_string()], &kit_defs, &inp).unwrap();
        assert!(expanded.write.contains(&PathBuf::from("/custom/mod")));
        assert!(expanded.write.contains(&home.join("go/pkg/sumdb")));
    }

    // ── expand_all: elixir ────────────────────────────────────────────

    #[test]
    fn expand_elixir_isolated_sets_mix_hex_rebar_and_reads_real_archives() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let env = empty_env();
        let inp = inputs(&home, &env, Platform::MacOs, &root);
        let expanded = expand_all(&["elixir".to_string()], &BTreeMap::new(), &inp).unwrap();
        assert_eq!(
            expanded.env.get("MIX_HOME").map(String::as_str),
            Some("/cache/airlock/kits/deadbeefdeadbeef/elixir/mix")
        );
        assert_eq!(
            expanded.env.get("HEX_HOME").map(String::as_str),
            Some("/cache/airlock/kits/deadbeefdeadbeef/elixir/hex")
        );
        assert_eq!(
            expanded.env.get("REBAR_CACHE_DIR").map(String::as_str),
            Some("/cache/airlock/kits/deadbeefdeadbeef/elixir/rebar3")
        );
        assert_eq!(
            expanded.env.get("MIX_ARCHIVES").map(String::as_str),
            Some("/home/u/.mix/archives")
        );
        assert!(expanded.read.contains(&home.join(".mix/archives")));
        assert!(expanded.read.contains(&home.join(".mix/elixir")));
        assert!(expanded.read.contains(&home.join(".asdf")));
        assert!(expanded.read.contains(&home.join(".kiex")));
        // Never the whole ~/.mix, and never ~/.hex at all (hex.config).
        assert!(!expanded.read.contains(&home.join(".mix")));
        assert!(
            !expanded
                .read
                .iter()
                .any(|p| p.starts_with(home.join(".hex")))
        );
        assert!(
            !expanded
                .write
                .iter()
                .any(|p| p.starts_with(home.join(".hex")))
        );
        assert!(
            !expanded
                .write
                .iter()
                .any(|p| p.starts_with(home.join(".mix")))
        );
    }

    #[test]
    fn expand_elixir_shared_reads_mix_write_hex_packages_and_rebar_cache_only() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let env = empty_env();
        let inp = inputs(&home, &env, Platform::MacOs, &root);
        let mut kit_defs = BTreeMap::new();
        kit_defs.insert(
            "elixir".to_string(),
            RawKitConfig {
                mode: Some("shared".to_string()),
                ..Default::default()
            },
        );
        let expanded = expand_all(&["elixir".to_string()], &kit_defs, &inp).unwrap();
        assert!(expanded.env.is_empty(), "shared mode sets no env");
        assert!(expanded.read.contains(&home.join(".mix")));
        assert!(expanded.write.contains(&home.join(".hex/packages")));
        assert!(expanded.write.contains(&home.join(".cache/rebar3")));
        // Shared mode must never write ~/.mix (archives/escripts are code
        // and binaries) and never touch ~/.hex/hex.config (the API key).
        assert!(
            !expanded
                .write
                .iter()
                .any(|p| p.starts_with(home.join(".mix")))
        );
        assert!(!expanded.write.contains(&home.join(".hex")));
        assert!(!expanded.read.contains(&home.join(".hex")));
        assert!(expanded.read.contains(&home.join(".hex/hex.config")));
    }

    #[test]
    fn expand_elixir_shared_honors_mix_home_and_hex_home_overrides() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let mut env = empty_env();
        env.insert("MIX_HOME".to_string(), "/custom/mix".to_string());
        env.insert("HEX_HOME".to_string(), "/custom/hex".to_string());
        let inp = inputs(&home, &env, Platform::MacOs, &root);
        let mut kit_defs = BTreeMap::new();
        kit_defs.insert(
            "elixir".to_string(),
            RawKitConfig {
                mode: Some("shared".to_string()),
                ..Default::default()
            },
        );
        let expanded = expand_all(&["elixir".to_string()], &kit_defs, &inp).unwrap();
        assert!(expanded.read.contains(&PathBuf::from("/custom/mix")));
        assert!(
            expanded
                .write
                .contains(&PathBuf::from("/custom/hex/packages"))
        );
    }

    // ── expand_all: user-defined kit ──────────────────────────────────

    #[test]
    fn expand_user_defined_kit_renders_kit_state_and_resolves_tilde() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let env = empty_env();
        let inp = inputs(&home, &env, Platform::MacOs, &root);
        let mut env = HashMap::new();
        env.insert(
            "BAZEL_OUTPUT_USER_ROOT".to_string(),
            "{kit_state}/out".to_string(),
        );
        let mut kit_defs = BTreeMap::new();
        kit_defs.insert(
            "bazel".to_string(),
            RawKitConfig {
                read: vec!["~/.bazelrc".to_string()],
                write: vec!["~/.cache/bazel".to_string()],
                env,
                ..Default::default()
            },
        );
        let expanded = expand_all(&["bazel".to_string()], &kit_defs, &inp).unwrap();
        assert_eq!(expanded.read, vec![home.join(".bazelrc")]);
        assert_eq!(expanded.write, vec![home.join(".cache/bazel")]);
        assert_eq!(
            expanded
                .env
                .get("BAZEL_OUTPUT_USER_ROOT")
                .map(String::as_str),
            Some("/cache/airlock/kits/deadbeefdeadbeef/bazel/out")
        );
        assert_eq!(
            expanded.state_dirs,
            vec![PathBuf::from("/cache/airlock/kits/deadbeefdeadbeef/bazel")]
        );
    }

    #[test]
    fn expand_all_folds_multiple_active_kits() {
        let home = PathBuf::from("/home/u");
        let root = PathBuf::from("/proj");
        let env = empty_env();
        let inp = inputs(&home, &env, Platform::MacOs, &root);
        let expanded = expand_all(
            &["rust".to_string(), "go".to_string()],
            &BTreeMap::new(),
            &inp,
        )
        .unwrap();
        assert_eq!(expanded.active.len(), 2);
        assert!(expanded.env.contains_key("CARGO_HOME"));
        assert!(expanded.env.contains_key("GOPATH"));
    }
}
