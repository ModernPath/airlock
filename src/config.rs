//! Configuration discovery, parsing, and validation for Airlock.
//!
//! This module is responsible for:
//! - Verifying config file ownership against the current effective uid
//! - Parsing the TOML config into strongly-typed structures
//! - Resolving paths (tilde expansion, relative-to-sandbox-root resolution)
//! - Validating tool names (no path separators)
//!
//! Discovery itself — walking from a directory up to `$HOME`, merging the
//! global/repo/local layers — is [`crate::layers`]; this module resolves the
//! merged, normalized wire form ([`resolve_wire_config`]) the daemon
//! actually runs against.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::proxy::{HostPattern, Inject, PathRule, ProxyPolicy, ProxyRoute, RouteError};

// ─── Constants ────────────────────────────────────────────────────────────────

/// The repo config file name searched for during discovery.
pub(crate) const CONFIG_FILENAME: &str = "airlock.toml";

/// The local config file name — the user and agent's own layer, approved
/// like the repo file but never committed.
pub(crate) const LOCAL_CONFIG_FILENAME: &str = "airlock.local.toml";

/// Maximum bytes to read from a config file. A real config is well under
/// this; the cap bounds allocation when something (or someone) points the
/// daemon at an oversized file.
pub(crate) const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Default global timeout in seconds (5 minutes).
const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Default timeout in seconds for `source = "command"` secret fetching.
const DEFAULT_COMMAND_SECRET_TIMEOUT_SECS: u64 = 10;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors that can occur during config discovery, parsing, or validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// No valid `airlock.toml` was found between the starting directory and `$HOME`.
    #[error("no valid airlock.toml found between {start_dir} and $HOME ({home_dir})")]
    NotFound {
        /// The directory where the search started.
        start_dir: PathBuf,
        /// The `$HOME` directory where the search stopped.
        home_dir: PathBuf,
    },

    /// The `$HOME` environment variable is not set.
    ///
    /// Required for tilde expansion and as the discovery walk boundary.
    #[error("$HOME environment variable is not set")]
    HomeNotSet,

    /// The config file could not be read from disk.
    #[error("failed to read config file {path}: {source}")]
    ReadError {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The config file contains invalid TOML syntax or structure.
    #[error("failed to parse config file {path}: {source}")]
    ParseError {
        /// The path of the file that failed to parse.
        path: PathBuf,
        /// The underlying TOML parse error.
        source: toml::de::Error,
    },

    /// A tool name contains a character outside the allowed set.
    ///
    /// Tool names must be bare identifiers (e.g., `"mytool"`, `"python3"`):
    /// ASCII letters, digits, `.`, `_`, `+` and `-` only. This is narrower
    /// than "not a path separator" because the name is interpolated,
    /// unescaped, into error messages a user reads before ever approving
    /// the config that chose it — a control character, bidi override or
    /// zero-width character in the name could otherwise reorder or hide
    /// terminal text at that point.
    #[error(
        "invalid tool name {name:?}: tool names may only contain ASCII letters, digits, '.', '_', '+' and '-'"
    )]
    InvalidToolName {
        /// The offending tool name.
        name: String,
    },

    /// Failed to canonicalize the sandbox root directory.
    #[error("failed to canonicalize sandbox root {path}: {source}")]
    CanonicalizationError {
        /// The path that could not be canonicalized.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The discovered `airlock.toml` sits directly at `$HOME`, which would make
    /// the entire home directory the sandbox root. Airlock refuses this by
    /// default; set `allow_home_root = true` in `airlock.toml` to opt in.
    #[error(
        "refusing to use $HOME ({home}) as the sandbox root\n\n\
         airlock.toml was discovered directly in the home directory, which would \
         expose the entire home directory to sandboxed tools. If this is intentional, \
         add `allow_home_root = true` to airlock.toml. Otherwise, move airlock.toml \
         into a more narrowly-scoped project directory."
    )]
    HomeRootNotAllowed {
        /// The home directory that was refused as a sandbox root.
        home: PathBuf,
    },

    /// A key in a `[tools.<tool>.env]` table is not a valid POSIX environment
    /// variable name.
    ///
    /// Names must match `^[A-Za-z_][A-Za-z0-9_]*$` — start with a letter or
    /// underscore, followed by letters, digits, or underscores.
    #[error("invalid environment variable name in [tools.{tool}.env]: {name:?}")]
    InvalidEnvVarName {
        /// The tool whose env table contains the invalid name.
        tool: String,
        /// The offending env var name.
        name: String,
    },

    /// A static value in `[tools.<tool>.env]` is a malformed template —
    /// unbalanced braces, empty key, etc.
    #[error("[tools.{tool}.env.{var_name}] is not a valid template: {message}")]
    EnvTemplateParse {
        /// The tool whose env entry failed to parse.
        tool: String,
        /// The env var name.
        var_name: String,
        /// The underlying parser message.
        message: String,
    },

    /// A static value in `[tools.<tool>.env]` references a placeholder that
    /// Airlock does not recognize. The only supported key is `{sandbox_root}`.
    #[error(
        "[tools.{tool}.env.{var_name}] references unknown placeholder {{{placeholder}}}; \
         only {{sandbox_root}} is supported"
    )]
    UnknownEnvPlaceholder {
        /// The tool whose env entry contains the bad placeholder.
        tool: String,
        /// The env var name.
        var_name: String,
        /// The unrecognized placeholder key.
        placeholder: String,
    },

    /// Rendering a `[tools.<tool>.env]` template failed for a reason other
    /// than a missing key (e.g. an I/O error from the template engine).
    #[error("[tools.{tool}.env.{var_name}] failed to render: {message}")]
    EnvTemplateRender {
        /// The tool whose env entry failed to render.
        tool: String,
        /// The env var name.
        var_name: String,
        /// The underlying render error message.
        message: String,
    },

    /// One or more `[tools.<tool>.env]` or `[agent.env]` entries reference a
    /// secret label that is not declared in `[secrets]`.
    ///
    /// Reports all undeclared references in a single error so the operator can
    /// fix them in one pass rather than discovering them one at a time.
    ///
    /// The first element of each tuple is the TOML location prefix (e.g.
    /// `"tools.mytool"` or `"agent"`); the second is the env var name; the
    /// third is the undeclared label.
    #[error(
        "{} env entries reference undeclared secret label(s): {}",
        refs.len(),
        refs.iter()
            .map(|(location, env, label)| format!("[{location}.env.{env}] -> {label:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    )]
    UndeclaredSecretRefs {
        /// Tuples of (TOML location, env var name, referenced label).
        ///
        /// The location is `"tools.<name>"` for per-tool entries and `"agent"`
        /// for agent env entries.
        refs: Vec<(String, String, String)>,
    },

    /// A `[secrets.<label>]` entry with `source = "command"` has an empty
    /// `command` array.
    #[error("[secrets.{label}] has an empty command array; at least one argv element is required")]
    EmptyCommandArgv {
        /// The secret label whose command is empty.
        label: String,
    },

    /// A `[secrets.<label>]` `refresh` value is invalid (zero, or shorter
    /// than the command `timeout`).
    #[error("[secrets.{label}] invalid refresh interval: {reason}")]
    InvalidRefreshInterval {
        /// The secret label.
        label: String,
        /// Why the value was rejected.
        reason: &'static str,
    },

    /// A `[secrets.<label>]` `refresh_max_backoff` is set without `refresh`,
    /// or is shorter than the command `timeout`.
    #[error("[secrets.{label}] invalid refresh config: {reason}")]
    InvalidRefreshConfig {
        /// The secret label.
        label: String,
        /// Why the value was rejected.
        reason: &'static str,
    },

    /// A key in `[secrets.<label>].env` is not a valid POSIX env var name.
    #[error("[secrets.{label}] invalid environment variable name: {name:?}")]
    InvalidSecretEnvVarName {
        /// The secret label.
        label: String,
        /// The offending env var name.
        name: String,
    },

    /// `proxy` and `routes` disagree: routes without `proxy = true`, or a
    /// proxy tool with no routes (which could not reach anything).
    #[error("[tools.{tool}] {reason}")]
    ProxyRoutesMismatch {
        /// The offending tool.
        tool: String,
        /// Which way the two fields disagree.
        reason: &'static str,
    },

    /// A proxy tool's `env` references a secret. The point of a proxy tool is
    /// that the agent fully controls its arguments, so anything in its
    /// environment must be assumed readable by the agent.
    #[error(
        "[tools.{tool}.env.{var_name}] references a secret, but {tool:?} is a proxy tool; \
         proxy tools must not receive secrets in their environment — attach the \
         credential with a route's `inject` instead"
    )]
    ProxyToolSecretEnv {
        /// The offending tool.
        tool: String,
        /// The env var holding the secret reference.
        var_name: String,
    },

    /// A proxy tool's `env` sets a variable the daemon itself must control to
    /// keep the tool pointed at the proxy and trusting its CA.
    #[error(
        "[tools.{tool}.env.{var_name}] is managed by Airlock for proxy tools and cannot be set"
    )]
    ProxyReservedEnvVar {
        /// The offending tool.
        tool: String,
        /// The reserved env var name.
        var_name: String,
    },

    /// A `[[tools.<tool>.routes]]` entry failed validation.
    #[error("[[tools.{tool}.routes]] entry {index}: {source}")]
    InvalidProxyRoute {
        /// The offending tool.
        tool: String,
        /// Zero-based position of the route in the `routes` array.
        index: usize,
        /// What was wrong with it.
        source: RouteError,
    },

    /// Two routes of one tool declare the same `host`, leaving it ambiguous
    /// which rules and credential apply.
    #[error("[[tools.{tool}.routes]] declares host {host:?} more than once")]
    DuplicateProxyRouteHost {
        /// The offending tool.
        tool: String,
        /// The repeated host pattern.
        host: String,
    },

    /// A route's `inject.secret` names a label not declared in `[secrets]`.
    #[error(
        "[[tools.{tool}.routes]] host {host:?}: inject references undeclared secret label {label:?}"
    )]
    UndeclaredProxySecret {
        /// The offending tool.
        tool: String,
        /// The route's host pattern.
        host: String,
        /// The undeclared label.
        label: String,
    },

    /// A `[secrets.<label>]` entry sets fields that disagree with its own
    /// `source` (e.g. `source = "env"` with a `command` array), or is
    /// missing a field its `source` requires.
    #[error("[secrets.{label}] {reason}")]
    SecretFieldMismatch {
        /// The secret label.
        label: String,
        /// Which fields disagree and why.
        reason: String,
    },

    /// A `[secrets.<label>]` `source` value is not `"env"` or `"command"`.
    #[error("[secrets.{label}] unknown source {got:?}; expected \"env\" or \"command\"")]
    UnknownSecretSource {
        /// The secret label.
        label: String,
        /// The offending value.
        got: String,
    },

    /// A `[secrets.<label>]` entry has no `source`, parsed in a context
    /// (the legacy single-file loaders) where nothing can bind it later.
    #[error(
        "[secrets.{label}] has no source; a source is required outside the repo/local layering"
    )]
    SecretMissingSource {
        /// The secret label.
        label: String,
    },

    /// A path in the global layer is not absolute. The global file applies
    /// to every project, so a relative path would mean something different
    /// in each one.
    #[error("{file}: {path:?} is a relative path, which is not allowed in the global config")]
    RelativePathInGlobal {
        /// The global config file.
        file: PathBuf,
        /// The offending raw path string.
        path: String,
    },

    /// `allow_home_root` was set in the repo layer, which is not allowed —
    /// only the global and local layers may opt into a `$HOME` sandbox root.
    #[error("{file}: allow_home_root is not allowed in the repo config")]
    AllowHomeRootInRepo {
        /// The repo config file.
        file: PathBuf,
    },

    /// `[tools.<name>] override = true` was set outside the local layer.
    #[error("{file}: tool {tool:?} sets override, which is only allowed in airlock.local.toml")]
    OverrideOutsideLocal {
        /// The file that set it.
        file: PathBuf,
        /// The offending tool.
        tool: String,
    },

    /// `[kits.<name>]` was set in the repo layer, which is not allowed —
    /// same spirit as [`ConfigError::AllowHomeRootInRepo`]: a teammate's
    /// checked-in file must not decide what a kit may write in your home.
    #[error(
        "{file}: [kits.*] is not allowed in the repo config; set it in airlock.local.toml or your global config"
    )]
    KitsInRepo {
        /// The repo config file.
        file: PathBuf,
    },
    /// A built-in kit's `[kits.<name>]` table set `read`, `write` or `env`,
    /// which only a user-defined kit may use.
    #[error(
        "[kits.{kit}] is a built-in kit; only `mode` is allowed ({field} is not — built-in kits \
         have their own fixed paths and env)"
    )]
    KitBuiltinExtraField {
        /// The built-in kit name.
        kit: String,
        /// The field it illegally set (`"read"`, `"write"`, or `"env"`).
        field: &'static str,
    },
    /// A built-in kit's `[kits.<name>]` table set `mode` to something other
    /// than `"isolated"` or `"shared"`.
    #[error("[kits.{kit}] mode {mode:?} is not valid; use \"isolated\" or \"shared\"")]
    KitUnknownMode {
        /// The built-in kit name.
        kit: String,
        /// The offending mode string.
        mode: String,
    },
    /// A user-defined kit's `[kits.<name>]` table set `mode`, which only a
    /// built-in kit has.
    #[error("[kits.{kit}] sets mode, which only a built-in kit (rust, node, python, go) has")]
    KitUserDefinedHasMode {
        /// The user-defined kit name.
        kit: String,
    },
    /// A kit's `read`, `write` or `env` references `{tool_state}` — the
    /// agent must never see a tool's own state.
    #[error(
        "[kits.{kit}].{field} references {{tool_state}}, which is reserved for tools; the \
         agent sandbox has no access to it"
    )]
    KitToolStateForbidden {
        /// The kit name.
        kit: String,
        /// Where the placeholder appeared (`"read"`, `"write"`, or `"env"`).
        field: &'static str,
    },
    /// A key in a user-defined kit's `env` table is not a valid POSIX
    /// environment variable name.
    #[error("[kits.{kit}.env] invalid environment variable name: {name:?}")]
    KitInvalidEnvVarName {
        /// The kit name.
        kit: String,
        /// The offending env var name.
        name: String,
    },
    /// A static value in a user-defined kit's `env` table references a
    /// placeholder other than `{kit_state}`.
    #[error(
        "[kits.{kit}.env.{var_name}] references unknown placeholder {{{placeholder}}}; only {{kit_state}} is supported"
    )]
    KitUnknownEnvPlaceholder {
        /// The kit name.
        kit: String,
        /// The env var name.
        var_name: String,
        /// The unrecognized placeholder key.
        placeholder: String,
    },
    /// A static value in a user-defined kit's `env` table is a malformed
    /// template.
    #[error("[kits.{kit}.env.{var_name}] is not a valid template: {message}")]
    KitEnvTemplateParse {
        /// The kit name.
        kit: String,
        /// The env var name.
        var_name: String,
        /// The underlying parser message.
        message: String,
    },
    /// `agent.kits` names a kit that is neither built-in nor declared by any
    /// `[kits.<name>]` table.
    #[error(
        "agent.kits names {kit:?}, which is not a built-in kit and has no [kits.{kit}] table; \
         known kits: {}",
        known.join(", ")
    )]
    UnknownKit {
        /// The offending name.
        kit: String,
        /// Every kit name known at merge/resolve time (built-ins plus any
        /// `[kits.<name>]` table), sorted.
        known: Vec<String>,
    },
    /// An `[agent.env.<key>]` entry collides with an env var an active kit
    /// also sets.
    #[error("[agent.env.{key}] is also set by kit {kit}; drop one of them")]
    AgentEnvSetByKit {
        /// The colliding env var name.
        key: String,
        /// The kit that sets it too.
        kit: String,
    },

    /// `[secrets.<label>] from = "<value>"` where `<value>` is not
    /// `"global"` — the only link a layer file may express without its own
    /// `source`.
    #[error(
        "{file}: [secrets.{label}] from = {value:?} is invalid; the only value a label without \
         its own source can take is \"global\""
    )]
    InvalidFromValue {
        /// The file that set it.
        file: PathBuf,
        /// The secret label.
        label: String,
        /// The offending value.
        value: String,
    },

    /// `[secrets.<label>] from = "global"` appeared outside the local layer.
    #[error("{file}: [secrets.{label}] from = \"global\" is only allowed in airlock.local.toml")]
    FromGlobalOutsideLocal {
        /// The file that set it.
        file: PathBuf,
        /// The secret label.
        label: String,
    },

    /// A local `[secrets.<label>]` has neither its own `source` nor
    /// `from = "global"`, so it binds nothing.
    #[error(
        "{file}: [secrets.{label}] needs a source or from = \"global\"; a local secret must bind \
         to something"
    )]
    LocalSecretUnbound {
        /// The local config file.
        file: PathBuf,
        /// The secret label.
        label: String,
    },

    /// No `airlock.toml` or `airlock.local.toml` was found walking up from
    /// the working directory to `$HOME`.
    #[error(
        "no airlock.toml or airlock.local.toml in {start_dir} or a parent directory up to {home_dir}\n\n\
         run `airlock init` to create one, or pass --no-project-config to use the global config alone"
    )]
    NoProjectConfig {
        /// The directory the walk started from.
        start_dir: PathBuf,
        /// The `$HOME` directory where the walk stopped.
        home_dir: PathBuf,
    },

    /// A tool of the same name is defined in both the repo and local layers,
    /// and the local layer did not set `override = true`.
    #[error(
        "tool {tool:?} is defined in both {repo_file} and {local_file};\n       add `override = true` to the tool in airlock.local.toml to replace the repo's"
    )]
    DuplicateTool {
        /// The tool name.
        tool: String,
        /// The repo layer's file.
        repo_file: PathBuf,
        /// The local layer's file.
        local_file: PathBuf,
    },

    /// `[tools.<name>] override = true` in the local layer, but the repo
    /// layer defines no tool of that name.
    #[error("{local_file}: tool {tool:?} sets override, but the repo defines no {tool:?}")]
    OverrideWithoutRepoTool {
        /// The local layer's file.
        local_file: PathBuf,
        /// The tool name.
        tool: String,
    },

    /// One or more repo-declared secret labels have no source and no local
    /// binding.
    #[error(
        "{} secret(s) in {repo_file} have no source:\n{}\n\
         the project leaves these to you. `airlock init --local` creates\n\
         airlock.local.toml with a stub for each.",
        labels.len(),
        labels
            .iter()
            .map(|(label, description)| match description {
                Some(d) => format!("  {label}  {d}"),
                None => format!("  {label}"),
            })
            .collect::<Vec<_>>()
            .join("\n")
    )]
    UnboundSecretLabels {
        /// The repo layer's file.
        repo_file: PathBuf,
        /// `(label, description)` pairs, in a stable order.
        labels: Vec<(String, Option<String>)>,
    },

    /// A global-layer tool or `agent.env` entry references a secret label
    /// the global layer does not itself declare.
    #[error(
        "{file}: tool {item:?} uses secret {label:?}, which your global config does not declare"
    )]
    GlobalItemUsesNonGlobalLabel {
        /// The global config file.
        file: PathBuf,
        /// The tool (or `"agent"`) that referenced it.
        item: String,
        /// The undeclared label.
        label: String,
    },

    /// A repo-layer tool or `agent.env` entry references a secret label the
    /// repo layer does not itself declare. Crossing into another layer's
    /// label needs the local layer's explicit opt-in.
    #[error("{file}: tool {item:?} uses secret {label:?}, which the repo config does not declare")]
    RepoItemUsesNonRepoLabel {
        /// The repo config file.
        file: PathBuf,
        /// The tool (or `"agent"`) that referenced it.
        item: String,
        /// The undeclared label.
        label: String,
    },
}

// ─── Raw TOML structures (serde) ──────────────────────────────────────────────
//
// These types are the wire format too (decision #3 in the v2 implementation
// contract): the launcher sends the merged config to the daemon as a
// `RawConfig`, normalized so every path is absolute and every secret has a
// concrete source. `deny_unknown_fields` applies at every level, including
// the top, so an unknown key is a config error in a file and a protocol
// error on the wire alike.

/// Raw deserialized representation of `airlock.toml` (or `airlock.local.toml`,
/// or a `--config` file). Which fields a given layer may use is validated
/// after parsing, in [`crate::layers`] — the raw shape here is deliberately
/// permissive enough to parse any layer unambiguously.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    /// Global timeout in seconds. Defaults to 300 (5 minutes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,

    /// Global filesystem access paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<RawFilesystem>,

    /// Secret sources. Each entry declares a logical label and the source
    /// used to fetch its value at daemon startup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<HashMap<String, RawSecretSpec>>,

    /// Per-tool definitions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<HashMap<String, RawToolConfig>>,

    /// Agent section — typed and validated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<RawAgentConfig>,

    /// Explicit opt-in to using `$HOME` as the sandbox root.
    ///
    /// When the project root is `$HOME`, the sandbox root becomes the entire
    /// home directory. This is almost always wrong; Airlock refuses unless
    /// the global or local layer has explicitly set this flag to `true`. A
    /// config error in the repo layer — see
    /// [`ConfigError::AllowHomeRootInRepo`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_home_root: Option<bool>,

    /// `[kits.<name>]` tables: options for a built-in kit, or the
    /// read/write/env lists of a user-defined one. A launcher-only concept
    /// (see [`crate::kits`]) — never present on the wire sent to the daemon,
    /// and a config error in the repo layer (see
    /// [`ConfigError::KitsInRepo`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kits: Option<HashMap<String, RawKitConfig>>,
}

/// Raw deserialized `[kits.<name>]` entry.
///
/// Which fields are legal depends on whether `name` is one of the built-in
/// kits (`rust`, `node`, `python`, `go`) — see [`crate::kits`], which also
/// does all expansion. A flat, fully-optional struct for the same reason as
/// [`RawSecretSpec`]: parsing has to accept any legal shape unambiguously,
/// and [`crate::kits::validate_all`] decides which shape applies to which
/// kit.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawKitConfig {
    /// Built-in kits only: `"isolated"` (the default) or `"shared"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// User-defined kits only: additional read-only paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read: Vec<String>,
    /// User-defined kits only: additional read-write paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write: Vec<String>,
    /// User-defined kits only: environment variables set on the agent.
    /// Static strings only (no secret refs) — may use `{kit_state}`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
}

/// Raw deserialized `[filesystem]` section.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawFilesystem {
    /// Global read-only paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read: Vec<String>,
    /// Global read-write paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write: Vec<String>,
}

/// Raw deserialized `[agent.filesystem]` subsection.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawAgentFilesystem {
    /// Additional read-only paths for the agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read: Vec<String>,
    /// Additional read-write paths for the agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write: Vec<String>,
}

/// Raw deserialized `[agent]` section.
///
/// Uses `#[serde(deny_unknown_fields)]` to surface typos and
/// `#[serde(default)]` on all fields so a bare `[agent]` header with no
/// fields is valid.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawAgentConfig {
    /// Agent session timeout in seconds. `None` (absent) means no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Environment variable names to inherit from the host environment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passthrough_env: Vec<String>,
    /// Environment variables set for the agent process.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, RawEnvValue>,
    /// Additional filesystem paths for the agent sandbox.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<RawAgentFilesystem>,
    /// Kits (built-in or user-defined) to add to the agent sandbox — see
    /// [`crate::kits`]. Unioned across layers; rides on the wire unused by
    /// the daemon, only so it contributes to the agent hash
    /// ([`crate::launcher::prepare`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kits: Vec<String>,
}

/// Raw deserialized `[secrets.<label>]` entry.
///
/// A flat, fully-optional struct rather than a tagged enum, because which
/// fields are legal depends on the *layer* the entry sits in, not just on
/// `source` — the repo layer may omit `source` entirely (a label the
/// project needs but leaves to the user), and the local layer may write
/// `from = "global"` instead of a `source` of its own. [`crate::layers`]
/// validates the combination per layer; this type only has to parse every
/// legal shape unambiguously. `deny_unknown_fields` still catches typos.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawSecretSpec {
    /// What the project needs this secret for. Shown in the "unbound repo
    /// labels" error and by `airlock init --local`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `"env"` or `"command"`. Optional only in the repo layer and
    /// `--config` files (a label with no source yet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Two unrelated meanings depending on `source`: with
    /// `source = "env"`, the env var name to read (defaults to the label).
    /// With no `source` at all, the only legal value is `"global"` — a
    /// local-layer link to the global binding of the same label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Argv list for `source = "command"`. The first element is the
    /// program, the rest are args. No shell interpolation is performed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// Maximum seconds to wait for `source = "command"`. Defaults to
    /// [`DEFAULT_COMMAND_SECRET_TIMEOUT_SECS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Background refresh interval in seconds for `source = "command"`.
    /// When set, the daemon re-runs `command` on this cadence and replaces
    /// the in-memory value. Omit to fetch only at daemon startup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<u64>,
    /// Cap (seconds) on the exponential-backoff sleep applied when a
    /// refresh fails. Defaults to `refresh` when omitted; meaningless
    /// without `refresh`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_max_backoff: Option<u64>,
    /// Env vars set (or overridden) when spawning a `source = "command"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,
    /// When `true`, spawn a `source = "command"` with an empty environment.
    /// `env` still applies on top.
    #[serde(default)]
    pub env_clear: bool,
}

/// Raw deserialized value inside `[tools.<tool>.env]`.
///
/// A bare string is a static value; an inline table `{ secret = "label" }`
/// references an entry in `[secrets]`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RawEnvValue {
    /// Inline table: `NAME = { secret = "label" }`. Declared first so serde
    /// tries it before falling back to the scalar string variant.
    SecretRef(RawSecretRef),
    /// Bare TOML string: `NAME = "some value"`.
    Static(String),
}

/// Inline-table form of an env var value that references a secret by label.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawSecretRef {
    /// Label of the entry in `[secrets.<label>]` whose resolved value is
    /// injected as this env var.
    pub secret: String,
}

/// Raw deserialized `[tools.X]` entry.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawToolConfig {
    /// Environment variables set when spawning this tool. Optional; a tool
    /// with no `env` table runs with just the base passthrough env.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, RawEnvValue>>,
    /// Additional read-only paths for this tool.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_read: Vec<String>,
    /// Additional read-write paths for this tool.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_write: Vec<String>,
    /// Per-tool timeout override in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Human-readable description of what this tool does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Marks this tool as a proxy tool: no direct network, all HTTP(S) via
    /// the daemon's proxy, governed by `routes`.
    #[serde(default)]
    pub proxy: bool,
    /// Egress routes. Required when `proxy = true`, rejected otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<RawProxyRoute>,
    /// Local-layer-only: replace the repo's whole definition of a tool of
    /// the same name. A config error on a tool the repo does not define,
    /// and outside the local layer. Never set on the wire — the launcher
    /// resolves it away before sending the merged config to the daemon.
    #[serde(default, rename = "override", skip_serializing_if = "is_false")]
    pub r#override: bool,
}

/// Raw deserialized `[[tools.X.routes]]` entry.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawProxyRoute {
    /// DNS name or `*.`-prefixed DNS name.
    pub host: String,
    /// Credential header to attach to permitted requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject: Option<RawInject>,
    /// `METHOD /path` rules; if non-empty a request must match one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// `METHOD /path` rules; a match refuses the request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

/// Raw deserialized `inject = { header, value, secret }` inline table.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawInject {
    pub header: String,
    pub value: String,
    pub secret: String,
}

/// `skip_serializing_if` helper for a plain `bool` field.
fn is_false(b: &bool) -> bool {
    !*b
}

// ─── Public types ─────────────────────────────────────────────────────────────

/// A fully parsed and validated Airlock configuration.
///
/// All paths have been resolved (tilde expanded, relative paths resolved
/// against the sandbox root).
#[derive(Debug)]
pub struct Config {
    /// The canonicalized directory containing the discovered `airlock.toml`.
    pub sandbox_root: PathBuf,

    /// Global timeout for tool execution.
    pub timeout: Duration,

    /// Global read-only filesystem paths.
    pub filesystem_read: Vec<PathBuf>,

    /// Global read-write filesystem paths.
    pub filesystem_write: Vec<PathBuf>,

    /// Secret sources, keyed by logical label.
    pub secrets: HashMap<String, SecretSpec>,

    /// Per-tool configuration, keyed by tool name.
    pub tools: HashMap<String, ToolConfig>,

    /// The `[agent]` section, fully resolved.
    pub agent: Option<AgentConfig>,

    /// Directories introduced by a `{tool_state}` placeholder in some tool's
    /// `env`. Already included in that tool's `extra_write` (so sandbox
    /// policy sees them); listed again here so the launcher can create them
    /// with mode 0700 before spawning anything — config.rs never creates
    /// directories itself.
    pub tool_state_dirs: Vec<PathBuf>,
}

/// Fully resolved `[secrets.<label>]` entry.
#[derive(Debug, Clone)]
pub struct SecretSpec {
    /// The logical label (same as the map key in [`Config::secrets`]).
    pub label: String,
    /// Where the value is fetched from.
    pub source: SecretSource,
}

/// The source a `SecretSpec` fetches its value from.
#[derive(Debug, Clone)]
pub enum SecretSource {
    /// Read from one of the daemon's own environment variables.
    Env {
        /// Env var name the daemon reads at startup.
        from: String,
    },
    /// Spawn a command at daemon startup and take its stdout as the value.
    Command {
        /// Argv list; `argv[0]` is the program.
        argv: Vec<String>,
        /// Maximum time to wait for the command to produce output.
        timeout: Duration,
        /// Background-refresh policy. `None` means fetch only at startup;
        /// `Some(spec)` means a tokio task re-runs the command on a cadence.
        refresh: Option<RefreshSpec>,
        /// Environment overrides applied when spawning the command.
        env: CommandEnv,
    },
}

/// Environment overrides for a `source = "command"` secret.
///
/// The spawn sequence is: optionally clear the inherited env, then apply
/// `set`. Empty/default means "inherit the daemon's env unchanged" — the
/// historical behavior before these knobs existed.
#[derive(Debug, Clone, Default)]
pub struct CommandEnv {
    /// When `true`, start from an empty environment instead of inheriting
    /// the daemon's.
    pub clear: bool,
    /// Names (and values) explicitly set, applied after `clear`.
    pub set: BTreeMap<String, String>,
}

/// Background-refresh policy for a `source = "command"` secret.
#[derive(Debug, Clone)]
pub struct RefreshSpec {
    /// Cadence between successful refreshes.
    pub interval: Duration,
    /// Cap on exponential-backoff sleep when refresh fails.
    pub max_backoff: Duration,
}

/// A single env var value in a resolved [`ToolConfig::env`].
#[derive(Debug, Clone)]
pub enum EnvValue {
    /// Literal value injected as-is.
    Static(String),
    /// Reference to a `[secrets.<label>]` entry. The label is validated at
    /// config-load time to resolve to an existing entry in [`Config::secrets`].
    SecretRef(String),
}

/// Configuration for a single tool, as declared in `[tools.X]`.
#[derive(Debug, Clone)]
pub struct ToolConfig {
    /// Environment variables set when spawning the tool, in deterministic
    /// (alphabetical) order.
    pub env: BTreeMap<String, EnvValue>,

    /// Additional read-only paths for this tool (resolved).
    pub extra_read: Vec<PathBuf>,

    /// Additional read-write paths for this tool (resolved).
    pub extra_write: Vec<PathBuf>,

    /// Optional per-tool timeout override.
    pub timeout: Option<Duration>,

    /// Human-readable description of what this tool does.
    pub description: Option<String>,

    /// Egress policy when this is a proxy tool; `None` for ordinary tools.
    pub proxy: Option<ProxyPolicy>,
}

/// Resolved configuration for the `[agent]` section.
///
/// All paths are fully resolved (tilde-expanded, relative paths resolved
/// against the sandbox root). Environment variables are validated.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Session timeout for the agent process. Zero means no limit.
    pub timeout: Duration,

    /// Environment variable names inherited from the host process.
    pub passthrough_env: Vec<String>,

    /// Environment variables set for the agent process, in deterministic
    /// (alphabetical) order.
    pub env: BTreeMap<String, EnvValue>,

    /// Additional read-only filesystem paths for the agent sandbox (resolved).
    pub filesystem_read: Vec<PathBuf>,

    /// Additional read-write filesystem paths for the agent sandbox (resolved).
    pub filesystem_write: Vec<PathBuf>,
}

/// Every path this config grants write access to: `filesystem.write`, every
/// tool's `extra_write` (which already includes its `{tool_state}` dir, if
/// any), and `agent.filesystem.write`.
///
/// This is the set the anchor checks and the filtered `PATH` (B2, B4 in the
/// v2 design) treat as "writable from some sandbox" — a superset of any one
/// sandbox's own grants, since the point is to protect the anchors and the
/// resolved tool binary from every sandbox the daemon can spawn, not just
/// the one currently running.
pub fn write_grants(config: &Config) -> Vec<PathBuf> {
    let mut grants = config.filesystem_write.clone();
    for tool in config.tools.values() {
        grants.extend(tool.extra_write.iter().cloned());
    }
    if let Some(agent) = &config.agent {
        grants.extend(agent.filesystem_write.iter().cloned());
    }
    grants
}

// ─── Discovery ────────────────────────────────────────────────────────────────

/// Get the current effective uid of the process.
pub(crate) fn current_euid() -> u32 {
    // SAFETY: geteuid(2) is always safe — it reads a process attribute
    // without modifying any state.
    unsafe { libc::geteuid() }
}

/// Check whether the file at `path` is a regular file owned by `expected_uid`,
/// refusing to follow symlinks.
///
/// Opens the file with `O_NOFOLLOW | O_RDONLY` and `fstat`s the resulting fd.
/// Using `fstat` on an open fd (rather than `stat` on a path) avoids a TOCTOU
/// window where an attacker could swap the file between the ownership check
/// and a subsequent open.
///
/// Returns `false` for:
/// - A missing file.
/// - A symlink (rejected by `O_NOFOLLOW`).
/// - A non-regular file (directory, socket, device, etc.).
/// - A file owned by a different UID.
pub(crate) fn is_owned_by(path: &Path, expected_uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(_) => return false,
    };

    match file.metadata() {
        Ok(meta) => meta.is_file() && meta.uid() == expected_uid,
        Err(_) => false,
    }
}

/// Atomically open `path` (with `O_NOFOLLOW`), verify it is a regular file
/// owned by `expected_uid`, and read up to `MAX_CONFIG_BYTES` of its contents.
///
/// The ownership check runs against `fstat` on the open fd, closing the TOCTOU
/// window between stat-by-path and read: an attacker cannot swap the file
/// between the check and the read because both operate on the same fd.
pub(crate) fn read_config_securely(path: &Path, expected_uid: u32) -> Result<String, ConfigError> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| ConfigError::ReadError {
            path: path.to_path_buf(),
            source: e,
        })?;

    let meta = file.metadata().map_err(|e| ConfigError::ReadError {
        path: path.to_path_buf(),
        source: e,
    })?;

    if !meta.is_file() {
        return Err(ConfigError::ReadError {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "airlock.toml is not a regular file",
            ),
        });
    }

    if meta.uid() != expected_uid {
        return Err(ConfigError::ReadError {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "airlock.toml ownership changed between discovery and load",
            ),
        });
    }

    let mut buf = String::new();
    file.by_ref()
        .take(MAX_CONFIG_BYTES)
        .read_to_string(&mut buf)
        .map_err(|e| ConfigError::ReadError {
            path: path.to_path_buf(),
            source: e,
        })?;

    // If we hit exactly MAX_CONFIG_BYTES, there may be more data we didn't read.
    // Detect by trying to read one more byte.
    let mut probe = [0u8; 1];
    if let Ok(n) = file.read(&mut probe)
        && n > 0
    {
        return Err(ConfigError::ReadError {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("airlock.toml exceeds {MAX_CONFIG_BYTES} bytes"),
            ),
        });
    }

    Ok(buf)
}

// ─── Path resolution ──────────────────────────────────────────────────────────

/// Resolve a path string according to Airlock path resolution rules:
/// - Tilde (`~`) at the start is expanded to `home`
/// - Relative paths are resolved relative to `sandbox_root`
/// - Absolute paths are left unchanged
///
/// Takes `home` explicitly rather than reading `$HOME` itself — used by
/// [`crate::layers`], which must not read the process environment.
pub(crate) fn resolve_path_with_home(raw: &str, sandbox_root: &Path, home: &Path) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        home.join(rest)
    } else if raw == "~" {
        home.to_path_buf()
    } else {
        let path = Path::new(raw);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            // Relative path — resolve against sandbox root.
            sandbox_root.join(path)
        }
    }
}

/// Resolve a list of path strings — used by [`crate::layers`].
pub(crate) fn resolve_paths_with_home(
    raw_paths: &[String],
    sandbox_root: &Path,
    home: &Path,
) -> Vec<PathBuf> {
    raw_paths
        .iter()
        .map(|p| resolve_path_with_home(p, sandbox_root, home))
        .collect()
}

/// Render a static `[tools.<tool>.env]` (or `[agent.env]`) value as a leon
/// template.
///
/// `{sandbox_root}` expands to the canonicalized sandbox root everywhere.
/// `{tool_state}` expands to `tool_state`'s value when the caller supplies
/// one (only tool `env`, not `agent.env` — see
/// [`resolve_tool_state_path`]); otherwise it is just another unknown
/// placeholder. Literal braces can be included with `\{` / `\}`. Any other
/// placeholder (`{home}`, typos like `{sandbox-root}`) is a hard error —
/// failing at config load is preferable to silently shipping a broken env
/// value to a tool.
pub(crate) fn render_env_template(
    raw: &str,
    sandbox_root: &Path,
    tool_state: Option<&Path>,
    tool: &str,
    var_name: &str,
) -> Result<String, ConfigError> {
    let template = leon::Template::parse(raw).map_err(|e| ConfigError::EnvTemplateParse {
        tool: tool.to_string(),
        var_name: var_name.to_string(),
        message: e.to_string(),
    })?;

    let root = sandbox_root.display().to_string();
    let mut values: HashMap<&str, &str> = HashMap::with_capacity(2);
    values.insert("sandbox_root", root.as_str());
    let tool_state_display = tool_state.map(|p| p.display().to_string());
    if let Some(ts) = &tool_state_display {
        values.insert("tool_state", ts.as_str());
    }

    template.render(&values).map_err(|e| match e {
        leon::RenderError::MissingKey(key) => ConfigError::UnknownEnvPlaceholder {
            tool: tool.to_string(),
            var_name: var_name.to_string(),
            placeholder: key,
        },
        other => ConfigError::EnvTemplateRender {
            tool: tool.to_string(),
            var_name: var_name.to_string(),
            message: other.to_string(),
        },
    })
}

/// Whether a static env value uses the `{tool_state}` placeholder.
///
/// A plain substring check, not a template parse: `{tool_state}` is never
/// meaningful escaped (`\{tool_state\}`) in a real config, and treating the
/// escaped form as "uses tool_state anyway" only means creating a directory
/// nothing reads, not a security gap.
pub(crate) fn uses_tool_state_placeholder(raw: &str) -> bool {
    raw.contains("{tool_state}")
}

/// Resolve `{tool_state}` for one tool: `<tool_state_base>/<project_id>/<tool>`.
///
/// Mode 0700 and creation are the launcher's job (decision in the v2 design,
/// "Tool state outside the project") — this just computes the path.
pub fn resolve_tool_state_path(tool_state_base: &Path, project_id: &str, tool: &str) -> PathBuf {
    tool_state_base.join(project_id).join(tool)
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use ring::digest::{SHA256, digest};
    let hash = digest(&SHA256, bytes);
    hash.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// A project's id: the first 16 hex characters of the SHA-256 of its
/// canonical root path. Used as the trust store's directory name and as the
/// `<id>` in `{tool_state}`'s resolved path — both need a name that is
/// stable for a given root but changes when the project moves, so approval
/// and tool state do not silently follow a path to a new place.
pub fn project_id(root: &Path) -> String {
    let hex = sha256_hex(root.as_os_str().as_encoded_bytes());
    hex[..16].to_string()
}

// ─── Tool name validation ─────────────────────────────────────────────────────

/// Validate that a tool name does not contain path separators.
///
/// Both forward slash (`/`) and backslash (`\`) are rejected, at config load
/// time rather than request time, so a malformed tool name is a config error
/// up front and `exec::resolve_binary_in` never has to consider it.
/// `\` is also rejected for cross-platform safety.
pub(crate) fn validate_tool_name(name: &str) -> Result<(), ConfigError> {
    let is_sane = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'));
    if !is_sane {
        return Err(ConfigError::InvalidToolName {
            name: name.to_string(),
        });
    }
    Ok(())
}

// ─── Env var name validation ──────────────────────────────────────────────────

/// Check whether `name` matches `^[A-Za-z_][A-Za-z0-9_]*$` — the POSIX
/// environment variable name shape, case-permissive.
pub(crate) fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Resolve and validate `refresh` / `refresh_max_backoff` from raw seconds to
/// a [`RefreshSpec`] (or `None` when refresh is disabled).
///
/// Rules:
/// - `refresh` must be `> 0` and `>= timeout` (so the next tick can't fire
///   before the previous command finishes).
/// - `refresh_max_backoff` is meaningful only when `refresh` is set; defaults
///   to `refresh` when omitted; must be `>= timeout`.
pub(crate) fn resolve_refresh_spec(
    label: &str,
    timeout: Duration,
    refresh: Option<u64>,
    refresh_max_backoff: Option<u64>,
) -> Result<Option<RefreshSpec>, ConfigError> {
    let Some(secs) = refresh else {
        if refresh_max_backoff.is_some() {
            return Err(ConfigError::InvalidRefreshConfig {
                label: label.to_string(),
                reason: "refresh_max_backoff requires refresh to be set",
            });
        }
        return Ok(None);
    };

    if secs == 0 {
        return Err(ConfigError::InvalidRefreshInterval {
            label: label.to_string(),
            reason: "must be greater than 0",
        });
    }
    let interval = Duration::from_secs(secs);
    if interval < timeout {
        return Err(ConfigError::InvalidRefreshInterval {
            label: label.to_string(),
            reason: "must be greater than or equal to timeout",
        });
    }

    let max_backoff = match refresh_max_backoff {
        Some(b) => {
            let dur = Duration::from_secs(b);
            if dur < timeout {
                return Err(ConfigError::InvalidRefreshConfig {
                    label: label.to_string(),
                    reason: "refresh_max_backoff must be greater than or equal to timeout",
                });
            }
            dur
        }
        None => interval,
    };

    Ok(Some(RefreshSpec {
        interval,
        max_backoff,
    }))
}

/// Validate and resolve the `env` / `env_clear` fields from a
/// `source = "command"` secret into a [`CommandEnv`].
pub(crate) fn resolve_secret_command_env(
    label: &str,
    env: Option<HashMap<String, String>>,
    env_clear: bool,
) -> Result<CommandEnv, ConfigError> {
    let mut set: BTreeMap<String, String> = BTreeMap::new();
    if let Some(raw) = env {
        for (name, value) in raw {
            if !is_valid_env_var_name(&name) {
                return Err(ConfigError::InvalidSecretEnvVarName {
                    label: label.to_string(),
                    name,
                });
            }
            set.insert(name, value);
        }
    }

    Ok(CommandEnv {
        clear: env_clear,
        set,
    })
}

// ─── Proxy tools ──────────────────────────────────────────────────────────────

/// Validate a tool's `proxy` / `routes` pair into a [`ProxyPolicy`], or `None`
/// for an ordinary tool.
pub(crate) fn resolve_proxy_policy(
    tool: &str,
    proxy: bool,
    raw_routes: Vec<RawProxyRoute>,
    secrets: &HashMap<String, SecretSpec>,
) -> Result<Option<ProxyPolicy>, ConfigError> {
    if !proxy {
        if !raw_routes.is_empty() {
            return Err(ConfigError::ProxyRoutesMismatch {
                tool: tool.to_string(),
                reason: "has routes but is not a proxy tool; add `proxy = true`",
            });
        }
        return Ok(None);
    }
    if raw_routes.is_empty() {
        return Err(ConfigError::ProxyRoutesMismatch {
            tool: tool.to_string(),
            reason: "is a proxy tool with no routes; it could not reach any host",
        });
    }

    let mut routes: Vec<ProxyRoute> = Vec::with_capacity(raw_routes.len());
    for (index, raw) in raw_routes.into_iter().enumerate() {
        let invalid = |source| ConfigError::InvalidProxyRoute {
            tool: tool.to_string(),
            index,
            source,
        };

        let host = HostPattern::parse(&raw.host).map_err(invalid)?;
        if routes.iter().any(|r| r.host == host) {
            return Err(ConfigError::DuplicateProxyRouteHost {
                tool: tool.to_string(),
                host: host.to_string(),
            });
        }

        let inject = match raw.inject {
            None => None,
            Some(i) => {
                let inject = Inject::parse(&i.header, &i.value, &i.secret).map_err(invalid)?;
                if !secrets.contains_key(&inject.secret) {
                    return Err(ConfigError::UndeclaredProxySecret {
                        tool: tool.to_string(),
                        host: host.to_string(),
                        label: inject.secret,
                    });
                }
                Some(inject)
            }
        };

        let parse_rules = |rules: &[String]| -> Result<Vec<PathRule>, ConfigError> {
            rules
                .iter()
                .map(|r| PathRule::parse(r).map_err(invalid))
                .collect()
        };

        routes.push(ProxyRoute {
            host,
            inject,
            allow: parse_rules(&raw.allow)?,
            deny: parse_rules(&raw.deny)?,
        });
    }

    Ok(Some(ProxyPolicy { routes }))
}

/// Resolve a `[secrets.<label>]` entry's own `source` into a [`SecretSource`].
///
/// Assumes `spec.source` is `Some` — callers that allow an absent source
/// (the repo layer, awaiting a local binding) classify that case themselves
/// before reaching here.
pub(crate) fn resolve_bound_secret_source(
    label: &str,
    spec: &RawSecretSpec,
) -> Result<SecretSource, ConfigError> {
    let mismatch = |reason: &str| ConfigError::SecretFieldMismatch {
        label: label.to_string(),
        reason: reason.to_string(),
    };

    match spec.source.as_deref() {
        Some("env") => {
            if spec.command.is_some()
                || spec.refresh.is_some()
                || spec.refresh_max_backoff.is_some()
                || spec.env.is_some()
                || spec.env_clear
            {
                return Err(mismatch(
                    "source = \"env\" does not accept command, refresh, refresh_max_backoff, env, or env_clear",
                ));
            }
            Ok(SecretSource::Env {
                from: spec.from.clone().unwrap_or_else(|| label.to_string()),
            })
        }
        Some("command") => {
            if spec.from.is_some() {
                return Err(mismatch("source = \"command\" does not accept `from`"));
            }
            let command = spec
                .command
                .clone()
                .ok_or_else(|| mismatch("source = \"command\" requires `command`"))?;
            if command.is_empty() {
                return Err(ConfigError::EmptyCommandArgv {
                    label: label.to_string(),
                });
            }
            let timeout =
                Duration::from_secs(spec.timeout.unwrap_or(DEFAULT_COMMAND_SECRET_TIMEOUT_SECS));
            let refresh =
                resolve_refresh_spec(label, timeout, spec.refresh, spec.refresh_max_backoff)?;
            let env = resolve_secret_command_env(label, spec.env.clone(), spec.env_clear)?;
            Ok(SecretSource::Command {
                argv: command,
                timeout,
                refresh,
                env,
            })
        }
        Some(other) => Err(ConfigError::UnknownSecretSource {
            label: label.to_string(),
            got: other.to_string(),
        }),
        None => Err(mismatch("has no source")),
    }
}

/// Resolve a merged, normalized [`RawConfig`] — the wire form the launcher
/// sends over the socket (decision #3 in the v2 implementation contract) —
/// into a [`Config`], against the already-decided project `root`.
///
/// Reads no environment and creates nothing on disk: the launcher has
/// already expanded every path (`~`, `{sandbox_root}`, `{tool_state}`) and
/// resolved every secret to a concrete `source` (no `from = "global"`,
/// no `override`), so this is just the daemon's own, independent check that
/// what it received is well-formed — it does not re-discover or re-approve
/// anything.
pub fn resolve_wire_config(raw: RawConfig, root: &Path) -> Result<Config, ConfigError> {
    let sandbox_root = root.to_path_buf();

    let timeout = Duration::from_secs(raw.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS));

    let (filesystem_read, filesystem_write) = match raw.filesystem {
        Some(fs) => (
            fs.read.into_iter().map(PathBuf::from).collect(),
            fs.write.into_iter().map(PathBuf::from).collect(),
        ),
        None => (Vec::new(), Vec::new()),
    };

    let raw_secrets = raw.secrets.unwrap_or_default();
    let mut secrets: HashMap<String, SecretSpec> = HashMap::with_capacity(raw_secrets.len());
    for (label, spec) in &raw_secrets {
        if spec.source.is_none() {
            return Err(ConfigError::SecretMissingSource {
                label: label.clone(),
            });
        }
        let source = resolve_bound_secret_source(label, spec)?;
        secrets.insert(
            label.clone(),
            SecretSpec {
                label: label.clone(),
                source,
            },
        );
    }

    let raw_tools = raw.tools.unwrap_or_default();
    let mut tools = HashMap::with_capacity(raw_tools.len());
    let mut undeclared_refs: Vec<(String, String, String)> = Vec::new();

    for (name, raw_tool) in raw_tools {
        validate_tool_name(&name)?;

        let mut env: BTreeMap<String, EnvValue> = BTreeMap::new();
        if let Some(raw_env) = raw_tool.env {
            for (var_name, raw_value) in raw_env {
                if !is_valid_env_var_name(&var_name) {
                    return Err(ConfigError::InvalidEnvVarName {
                        tool: name.clone(),
                        name: var_name,
                    });
                }
                if raw_tool.proxy && crate::proxy::is_reserved_env_var(&var_name) {
                    return Err(ConfigError::ProxyReservedEnvVar {
                        tool: name.clone(),
                        var_name,
                    });
                }
                let value = match raw_value {
                    // Already rendered by the launcher — copied verbatim,
                    // not re-templated.
                    RawEnvValue::Static(s) => EnvValue::Static(s),
                    RawEnvValue::SecretRef(RawSecretRef { secret }) => {
                        if raw_tool.proxy {
                            return Err(ConfigError::ProxyToolSecretEnv {
                                tool: name.clone(),
                                var_name,
                            });
                        }
                        if !secrets.contains_key(&secret) {
                            undeclared_refs.push((
                                format!("tools.{name}"),
                                var_name.clone(),
                                secret.clone(),
                            ));
                        }
                        EnvValue::SecretRef(secret)
                    }
                };
                env.insert(var_name, value);
            }
        }

        let proxy = resolve_proxy_policy(&name, raw_tool.proxy, raw_tool.routes, &secrets)?;

        let tool_config = ToolConfig {
            env,
            extra_read: raw_tool.extra_read.into_iter().map(PathBuf::from).collect(),
            extra_write: raw_tool
                .extra_write
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            timeout: raw_tool.timeout.map(Duration::from_secs),
            description: raw_tool.description,
            proxy,
        };

        tools.insert(name, tool_config);
    }

    let agent = match raw.agent {
        None => None,
        Some(raw_agent) => {
            let agent_timeout = Duration::from_secs(raw_agent.timeout.unwrap_or(0));

            let mut agent_env: BTreeMap<String, EnvValue> = BTreeMap::new();
            for (var_name, raw_value) in raw_agent.env {
                if !is_valid_env_var_name(&var_name) {
                    return Err(ConfigError::InvalidEnvVarName {
                        tool: "agent".to_string(),
                        name: var_name,
                    });
                }
                let value = match raw_value {
                    RawEnvValue::Static(s) => EnvValue::Static(s),
                    RawEnvValue::SecretRef(RawSecretRef { secret }) => {
                        if !secrets.contains_key(&secret) {
                            undeclared_refs.push((
                                "agent".to_string(),
                                var_name.clone(),
                                secret.clone(),
                            ));
                        }
                        EnvValue::SecretRef(secret)
                    }
                };
                agent_env.insert(var_name, value);
            }

            let (agent_fs_read, agent_fs_write) = match raw_agent.filesystem {
                Some(fs) => (
                    fs.read.into_iter().map(PathBuf::from).collect(),
                    fs.write.into_iter().map(PathBuf::from).collect(),
                ),
                None => (Vec::new(), Vec::new()),
            };

            Some(AgentConfig {
                timeout: agent_timeout,
                passthrough_env: raw_agent.passthrough_env,
                env: agent_env,
                filesystem_read: agent_fs_read,
                filesystem_write: agent_fs_write,
            })
        }
    };

    if !undeclared_refs.is_empty() {
        return Err(ConfigError::UndeclaredSecretRefs {
            refs: undeclared_refs,
        });
    }

    Ok(Config {
        sandbox_root,
        timeout,
        filesystem_read,
        filesystem_write,
        secrets,
        tools,
        agent,
        // The launcher already created every {tool_state} dir before
        // normalizing paths into this wire form; nothing left to create.
        tool_state_dirs: Vec::new(),
    })
}

/// Return the repo config file name (`airlock.toml`).
///
/// Exposed so that other modules (e.g. the `init` command) can reference the
/// canonical file name without duplicating the constant.
pub fn config_filename() -> &'static str {
    CONFIG_FILENAME
}

/// Return the local config file name (`airlock.local.toml`).
pub fn local_config_filename() -> &'static str {
    LOCAL_CONFIG_FILENAME
}

/// Return a default `airlock.toml` template suitable for new projects.
///
/// The template contains commented-out examples of every supported section
/// so that users can quickly uncomment and customise what they need.
pub fn default_config_template() -> &'static str {
    r#"# Airlock configuration — the repo layer. Commit this file; it is approved
# like any other code change (`airlock trust`), and `airlock run --profile
# claude` checks it before every session.
# See https://github.com/ModernPath/airlock for documentation.

# Global timeout for tool execution in seconds (default: 300).
# timeout = 300

# Global filesystem access paths. The directory containing this file is always
# read-write, and a baseline of system paths (/usr/lib, /etc, /dev/{null,
# random,urandom}, ...) is always readable. Use [filesystem] only for paths
# beyond that baseline — e.g. a writable /tmp for tools that need scratch space.
# [filesystem]
# read = ["/usr/share/something-extra"]
# write = ["/tmp"]

# Declare secret sources. Each label can be referenced from any tool's env.
# `from` defaults to the label, so [secrets.API_KEY] reads the API_KEY env var.
# [secrets.API_KEY]
# source = "env"

# Or fetch a secret by running a command (stdout becomes the value):
# [secrets.GCLOUD_ACCESS_TOKEN]
# source  = "command"
# command = ["gcloud", "auth", "print-access-token"]
# timeout = 10

# Or leave the binding to each user: a label with only a description is a
# request each teammate fills in with `airlock init --local`.
# [secrets.PERSONAL_TOKEN]
# description = "..."

# Define tools and the environment they run with. `env` entries are either
# static strings or references to a [secrets.<label>] entry. {sandbox_root}
# expands to the project directory; {tool_state} expands to a writable
# directory outside the project, private to this tool
# ($XDG_CACHE_HOME/airlock/<id>/<tool>) — use it for a tool's own config
# directory (GH_CONFIG_DIR, CLOUDSDK_CONFIG, KUBECONFIG, ...) so the agent
# cannot read it and git never sees it.
# [tools.example]
# extra_read  = []
# extra_write = []
# timeout     = 60
#
# [tools.example.env]
# API_KEY        = { secret = "API_KEY" }
# LOG_LEVEL      = "info"
# EXAMPLE_CONFIG = "{tool_state}"

# Configure the AI agent sandbox launched by `airlock run`.
# [agent]
# # Maximum agent session time in seconds. 0 = no limit.
# timeout = 0
#
# # Environment variable names inherited from the host process.
# passthrough_env = ["COLORTERM", "NO_COLOR"]
#
# # Kits: language toolchain/package-cache access for `airlock run`'s agent
# # sandbox — see the global config template for what they are and the
# # built-in names. [kits.*] tables themselves may only live in your global
# # config or airlock.local.toml, never here.
# # kits = ["rust", "node"]
#
# [agent.env]
# # Static value injected into the agent's environment.
# LOG_LEVEL = "info"
# # Reference a declared secret — the value is injected at runtime.
# API_KEY = { secret = "API_KEY" }
#
# [agent.filesystem]
# # Extra read-only paths beyond the project directory baseline.
# read = ["~/.config/myapp"]
# # Extra read-write paths beyond the project directory baseline.
# write = ["/tmp/agent-scratch"]
#
# # For interactive-ergonomics relaxations (clipboard, `open <url>`, shell
# # init dotfiles, ~/Library/Keychains write), use the `claude-relaxed`
# # built-in profile via `airlock run --profile claude-relaxed` instead of
# # a config flag. See SECURITY.md for the tradeoffs.
"#
}

/// Return a default `airlock.toml` template for the global layer
/// (`$XDG_CONFIG_HOME/airlock/airlock.toml`, default
/// `~/.config/airlock/airlock.toml`).
///
/// Unlike the repo and local layers, the global file is never approved —
/// it is the user's own file, protected by the anchor checks instead — and
/// every path in it must be absolute, since it applies to every project.
pub fn global_config_template() -> &'static str {
    r#"# Airlock configuration — your global defaults, applied to every project.
# This file is never approved like airlock.toml or airlock.local.toml: it is
# your own file, outside any project, protected by Airlock's anchor checks
# instead. Paths here must be absolute (~, {sandbox_root}, and {tool_state}
# still work; a bare relative path is a config error, since it would mean
# something different in each project).

# Bind secrets you use across projects. A project's own airlock.toml binds
# the label GH_TOKEN itself only through airlock.local.toml's
# `from = "global"` — see `airlock init --local`.
# [secrets.GH_TOKEN]
# source  = "command"
# command = ["op", "read", "op://Private/GitHub/token"]

# Tools you want available everywhere, even in projects that don't declare
# them. A project's own [tools.<name>] of the same name takes precedence.
# [tools.aws]
# description = "AWS CLI"
# [tools.aws.env]
# AWS_PROFILE = "personal"

# Kits add a language toolchain's cache access to `airlock run`'s agent
# sandbox, on top of whatever harness profile you use. Built-in kits: rust,
# node, python, go, elixir. List the ones you want on [agent] below (any
# config layer; unioned across them), and optionally set a built-in kit's
# mode here or in airlock.local.toml (never in a project's own airlock.toml):
# "isolated" (the default) points the toolchain's cache env vars at a
# directory private to this project, so the agent never touches your real
# caches; "shared" instead grants write to the real ones. Prefer isolated —
# shared lets the agent poison a cache (e.g. ~/.cargo/registry/src) that an
# unsandboxed build later trusts without re-verifying.
# [kits.rust]
# mode = "isolated"

# A user-defined kit works like a built-in one but you supply its own
# read/write paths and env (no mode — always the paths/env you give it):
# [kits.bazel]
# read  = ["~/.bazelrc"]
# write = ["~/.cache/bazel"]
# env   = { BAZEL_OUTPUT_USER_ROOT = "{kit_state}/out" }

# [agent]
# passthrough_env = ["COLORTERM"]
# kits = ["rust"]
"#
}

/// Return a standalone `airlock.local.toml` template, written by
/// `airlock init --local` in a repo with no `airlock.toml` of its own (a
/// repo whose team has not adopted Airlock). It is the same shape as
/// [`default_config_template`] but documented as the user's own file.
pub fn local_config_template_standalone() -> &'static str {
    r#"# Airlock configuration — a personal, local-only config. This project has
# no airlock.toml of its own, so this file stands alone: it is approved like
# any local file (`airlock trust`), but nothing here is shared with anyone
# else who clones this repo.
# See https://github.com/ModernPath/airlock for documentation.

# [secrets.API_KEY]
# source = "env"

# [tools.example]
# [tools.example.env]
# API_KEY = { secret = "API_KEY" }

# [agent]
# kits = ["rust"]   # built-in kits: rust, node, python, go, elixir

# A built-in kit's mode ("isolated", the default, or "shared") may be set
# here or in your global config, never in a project's own airlock.toml.
# [kits.rust]
# mode = "isolated"
"#
}

/// Build the `airlock.local.toml` stub `airlock init --local` writes in a
/// repo whose `airlock.toml` leaves one or more secret labels unbound.
///
/// `global_bound` are labels the global layer binds — each gets
/// `from = "global"`. The rest of `repo_labels` get a commented `command` /
/// `env` example under their description. Both lists carry `(label,
/// description)` pairs in the order they should appear.
pub fn local_stub(repo_labels: &[(String, Option<String>)], global_bound: &[String]) -> String {
    let mut out = String::from(
        "# Your bindings for this project. Keep it out of git.\n\
         # Run `airlock config` to see the merged result.\n",
    );
    for (label, description) in repo_labels {
        out.push('\n');
        if let Some(d) = description {
            out.push_str(&format!("# {d}\n"));
        }
        if global_bound.iter().any(|g| g == label) {
            out.push_str(&format!("[secrets.{label}]\nfrom = \"global\"\n"));
        } else {
            out.push_str(&format!(
                "# Uncomment one:\n\
                 # [secrets.{label}]\n\
                 # source  = \"command\"\n\
                 # command = [\"op\", \"read\", \"op://Private/{label}/token\"]\n\
                 #\n\
                 # [secrets.{label}]\n\
                 # source = \"env\"        # read from the environment of `airlock run`\n"
            ));
        }
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "tests may read/set the process environment freely; only request-path code is bound by the session isolation rule"
)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Create an `airlock.toml` with the given content at the specified directory.
    fn write_config(dir: &Path, content: &str) {
        fs::write(dir.join(CONFIG_FILENAME), content).expect("failed to write config");
    }

    /// Create an `airlock.local.toml` — the one layer besides global that
    /// may set `allow_home_root` (v2: it is a config error in the repo
    /// layer, see [`ConfigError::AllowHomeRootInRepo`]).
    fn write_local_config(dir: &Path, content: &str) {
        fs::write(dir.join(LOCAL_CONFIG_FILENAME), content).expect("failed to write local config");
    }

    /// Minimal valid config with one tool and one secret.
    fn minimal_config() -> &'static str {
        r#"
[secrets.my_secret]
source = "env"
from = "MY_SECRET"

[tools.mytool.env]
MY_SECRET = { secret = "my_secret" }
"#
    }

    /// Fully populated config with all optional fields.
    fn full_config() -> &'static str {
        r#"
timeout = 120

[filesystem]
read = ["/usr/share", "~/docs"]
write = ["/tmp/output"]

[secrets.api_key]
source = "env"
from = "API_KEY"

[secrets.db_password]
source = "env"
from = "DB_PASSWORD"

[secrets.api_token]
source = "env"
from = "API_TOKEN"

[tools.grep]
extra_read = ["/etc/config"]
extra_write = ["/tmp/results"]
timeout = 60

[tools.grep.env]
API_KEY = { secret = "api_key" }
LOG_LEVEL = "info"

[tools.python3]
extra_read = ["data"]
extra_write = ["output"]

[tools.python3.env]
DB_PASSWORD = { secret = "db_password" }
API_TOKEN = { secret = "api_token" }

[agent]
timeout = 30
passthrough_env = ["TERM"]
"#
    }

    // ── v1→v2 test shim ───────────────────────────────────────────────────
    //
    // The rest of this suite was written against the v1 loaders
    // (`load_config`, `load_config_from_file`), deleted along with the
    // single-file discovery they drove — the daemon now only ever resolves
    // the already-merged wire config (`resolve_wire_config`), and discovery
    // itself lives in `layers::load_layers`/`merge`. Rather than rewrite
    // every call site, these two functions run the real v2 pipeline
    // (`load_layers` → `merge` → `to_wire` → `resolve_wire_config`) against
    // the single file `write_config` wrote, so every existing assertion
    // below still exercises genuine, current code.

    fn resolve_through_v2_pipeline(
        mode: &crate::layers::DiscoveryMode,
        cwd: &Path,
        home: &Path,
    ) -> Result<Config, ConfigError> {
        let no_global = home.join("no-such-global.toml");
        let loaded = crate::layers::load_layers(mode, cwd, home, &no_global)?;
        let ctx = crate::layers::MergeContext {
            root: loaded.root.clone(),
            home: home.to_path_buf(),
            tool_state_base: home.join(".cache/airlock"),
        };
        let merged = crate::layers::merge(&loaded, &ctx)?;
        resolve_wire_config(merged.to_wire(), &loaded.root)
    }

    /// A `$HOME` that is never equal to a test's project directory, so the
    /// home-root guard (`ctx.root == home`) never fires for a test that
    /// isn't specifically exercising it — none of these tests' configs set
    /// `allow_home_root`, which v2 refuses in the repo layer anyway.
    fn decoy_home() -> &'static Path {
        Path::new("/no/such/home")
    }

    /// Replaces v1's `load_config(dir)`.
    fn load_config(dir: &Path) -> Result<Config, ConfigError> {
        resolve_through_v2_pipeline(&crate::layers::DiscoveryMode::Default, dir, decoy_home())
    }

    /// Like [`load_config`], but `$HOME` is given explicitly — for the
    /// home-root guard's own tests, which need `cwd`/`home` to actually
    /// match (or not) on request.
    fn load_config_at(cwd: &Path, home: &Path) -> Result<Config, ConfigError> {
        resolve_through_v2_pipeline(&crate::layers::DiscoveryMode::Default, cwd, home)
    }

    /// Replaces v1's `load_config_from_file(path)`.
    fn load_config_from_file(path: &Path) -> Result<Config, ConfigError> {
        resolve_through_v2_pipeline(
            &crate::layers::DiscoveryMode::ConfigFile(path.to_path_buf()),
            decoy_home(),
            decoy_home(),
        )
    }

    // ── Parsing: minimal valid config ────────────────────────────────────

    #[test]
    fn parse_minimal_config() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();

        assert_eq!(config.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        assert!(config.filesystem_read.is_empty());
        assert!(config.filesystem_write.is_empty());
        assert_eq!(config.tools.len(), 1);
        assert_eq!(config.secrets.len(), 1);

        let secret = config.secrets.get("my_secret").expect("my_secret spec");
        match &secret.source {
            SecretSource::Env { from } => assert_eq!(from, "MY_SECRET"),
            other => panic!("expected Env source, got: {other:?}"),
        }

        let tool = config.tools.get("mytool").expect("mytool should exist");
        assert_eq!(tool.env.len(), 1);
        match tool.env.get("MY_SECRET").unwrap() {
            EnvValue::SecretRef(label) => assert_eq!(label, "my_secret"),
            other => panic!("expected SecretRef, got: {other:?}"),
        }
        assert!(tool.extra_read.is_empty());
        assert!(tool.extra_write.is_empty());
        assert!(tool.timeout.is_none());
    }

    // ── Parsing: fully populated config ──────────────────────────────────

    #[test]
    fn parse_full_config() {
        let tmp = tempdir().unwrap();
        let home = tempdir().unwrap();
        write_config(tmp.path(), full_config());

        let config = load_config_at(tmp.path(), home.path()).unwrap();

        // Global timeout.
        assert_eq!(config.timeout, Duration::from_secs(120));

        // Filesystem section.
        assert_eq!(config.filesystem_read.len(), 2);
        assert!(
            config
                .filesystem_read
                .contains(&PathBuf::from("/usr/share"))
        );
        // ~/docs should be expanded to {home}/docs.
        let expected_home_docs = home.path().join("docs");
        assert!(
            config.filesystem_read.contains(&expected_home_docs),
            "filesystem_read should contain expanded ~/docs = {:?}, got {:?}",
            expected_home_docs,
            config.filesystem_read
        );

        assert_eq!(config.filesystem_write.len(), 1);
        assert!(
            config
                .filesystem_write
                .contains(&PathBuf::from("/tmp/output"))
        );

        // Tools.
        assert_eq!(config.tools.len(), 2);

        let grep = config.tools.get("grep").expect("grep should exist");
        assert!(matches!(
            grep.env.get("API_KEY"),
            Some(EnvValue::SecretRef(l)) if l == "api_key"
        ));
        assert!(matches!(
            grep.env.get("LOG_LEVEL"),
            Some(EnvValue::Static(s)) if s == "info"
        ));
        assert_eq!(grep.extra_read, vec![PathBuf::from("/etc/config")]);
        assert_eq!(grep.extra_write, vec![PathBuf::from("/tmp/results")]);
        assert_eq!(grep.timeout, Some(Duration::from_secs(60)));

        let python = config.tools.get("python3").expect("python3 should exist");
        assert!(matches!(
            python.env.get("DB_PASSWORD"),
            Some(EnvValue::SecretRef(l)) if l == "db_password"
        ));
        assert!(matches!(
            python.env.get("API_TOKEN"),
            Some(EnvValue::SecretRef(l)) if l == "api_token"
        ));
        // "data" is relative — should resolve to sandbox_root/data.
        let sandbox_root = &config.sandbox_root;
        assert_eq!(python.extra_read, vec![sandbox_root.join("data")]);
        assert_eq!(python.extra_write, vec![sandbox_root.join("output")]);
        assert!(python.timeout.is_none());

        // Secrets.
        assert_eq!(config.secrets.len(), 3);
        for label in ["api_key", "db_password", "api_token"] {
            assert!(
                config.secrets.contains_key(label),
                "expected secrets to include {label}"
            );
        }
    }

    // ── Parsing: agent section is accepted ───────────────────────────────

    #[test]
    fn parse_agent_section() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[tools.mytool]

[agent]
timeout = 60
passthrough_env = ["TERM", "COLORTERM"]
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        let agent = config
            .agent
            .expect("agent section should be parsed without error");
        assert_eq!(agent.timeout, Duration::from_secs(60));
        assert_eq!(agent.passthrough_env, vec!["TERM", "COLORTERM"]);
    }

    #[test]
    fn parse_agent_rejects_legacy_relaxed_field() {
        // `[agent] relaxed = true` was retired in favour of the
        // `claude-relaxed` profile. `deny_unknown_fields` should now reject
        // the legacy spelling so users are not silently downgraded to the
        // strict profile.
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[tools.mytool]

[agent]
relaxed = true
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let result = load_config(tmp.path());
        assert!(
            result.is_err(),
            "legacy `relaxed` field should be rejected, got: {result:?}"
        );
    }

    // ── Parsing: missing optional fields default correctly ───────────────

    #[test]
    fn parse_missing_optional_fields_default() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.one]
source = "env"
from = "ONE"

[tools.simple.env]
ONE = { secret = "one" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();

        // Global defaults.
        assert_eq!(config.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        assert!(config.filesystem_read.is_empty());
        assert!(config.filesystem_write.is_empty());
        assert!(config.agent.is_none());

        // Tool defaults.
        let tool = config.tools.get("simple").unwrap();
        assert!(tool.extra_read.is_empty());
        assert!(tool.extra_write.is_empty());
        assert!(tool.timeout.is_none());
    }

    // ── Parsing: empty tools section ─────────────────────────────────────

    #[test]
    fn parse_empty_tools_section() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[tools]
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        assert!(
            config.tools.is_empty(),
            "empty [tools] section should parse to empty map"
        );
    }

    // ── Parsing: invalid TOML produces error with file path ──────────────

    #[test]
    fn parse_invalid_toml_includes_path() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), "this is not valid toml [[[");
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let result = load_config(tmp.path());
        assert!(result.is_err());

        let err = result.unwrap_err();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("airlock.toml"),
            "error message should include the file path, got: {err_msg}"
        );
        assert!(
            matches!(err, ConfigError::ParseError { .. }),
            "should be a ParseError variant"
        );
    }

    // ── Parsing: unknown top-level keys are rejected (v2: no catch-all) ──

    #[test]
    fn parse_unknown_top_level_keys_rejected() {
        // v2 drops the top-level `#[serde(flatten)] _extra` catch-all: an
        // unknown top-level key is now a config error, matching every
        // nested table's deny_unknown_fields.
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"
future_field = "hello"

[secrets.s]
source = "env"
from = "S"

[tools.mytool.env]
S = { secret = "s" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let err = load_config(tmp.path()).unwrap_err();
        assert!(
            matches!(err, ConfigError::ParseError { .. }),
            "unknown top-level key should be a ParseError, got: {err:?}"
        );
    }

    // ── Path resolution: tilde expansion ─────────────────────────────────

    #[test]
    fn path_tilde_expansion() {
        let tmp = tempdir().unwrap();

        let resolved = resolve_path_with_home("~/documents", tmp.path(), tmp.path());
        let expected = PathBuf::from(format!("{}/documents", tmp.path().display()));
        assert_eq!(resolved, expected);
    }

    #[test]
    fn path_tilde_only() {
        let tmp = tempdir().unwrap();

        let resolved = resolve_path_with_home("~", tmp.path(), tmp.path());
        assert_eq!(resolved, tmp.path().to_path_buf());
    }

    // ── Path resolution: relative paths ──────────────────────────────────

    #[test]
    fn path_relative_resolved_against_sandbox_root() {
        let sandbox = PathBuf::from("/fake/sandbox/root");
        let home = PathBuf::from("/fake/home");
        let resolved = resolve_path_with_home("data/input", &sandbox, &home);
        assert_eq!(resolved, PathBuf::from("/fake/sandbox/root/data/input"));
    }

    // ── Path resolution: absolute paths unchanged ────────────────────────

    #[test]
    fn path_absolute_unchanged() {
        let sandbox = PathBuf::from("/fake/sandbox/root");
        let home = PathBuf::from("/fake/home");
        let resolved = resolve_path_with_home("/usr/bin/tool", &sandbox, &home);
        assert_eq!(resolved, PathBuf::from("/usr/bin/tool"));
    }

    // ── Derived paths: sandbox root ──────────────────────────────────────

    #[test]
    fn sandbox_root_is_canonicalized_parent() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        let canonical = std::fs::canonicalize(tmp.path()).unwrap();
        assert_eq!(
            config.sandbox_root, canonical,
            "sandbox root should be the canonicalized directory containing airlock.toml"
        );
    }

    // ── Tool name validation: valid names ────────────────────────────────

    #[test]
    fn tool_name_bare_identifier_accepted() {
        assert!(validate_tool_name("mytool").is_ok());
        assert!(validate_tool_name("python3").is_ok());
        assert!(validate_tool_name("my-tool").is_ok());
        assert!(validate_tool_name("my_tool").is_ok());
        assert!(validate_tool_name("TOOL").is_ok());
        assert!(validate_tool_name("my.tool").is_ok());
        assert!(validate_tool_name("my+tool").is_ok());
    }

    // ── Tool name validation: forward slash rejected ─────────────────────

    #[test]
    fn tool_name_forward_slash_rejected() {
        let result = validate_tool_name("path/to/tool");
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ConfigError::InvalidToolName { name } if name == "path/to/tool")
        );
    }

    // ── Tool name validation: backslash rejected ─────────────────────────

    #[test]
    fn tool_name_backslash_rejected() {
        let result = validate_tool_name("path\\to\\tool");
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ConfigError::InvalidToolName { name } if name == "path\\to\\tool")
        );
    }

    // ── Tool name validation: terminal-hostile characters rejected ───────
    //
    // A tool name is interpolated unescaped into error messages printed
    // before the config that chose it has been trusted (`report_launcher_error`
    // and friends in src/main.rs). These would otherwise let an untrusted
    // config manipulate that terminal output.

    #[test]
    fn tool_name_control_character_rejected() {
        assert!(matches!(
            validate_tool_name("tool\x1b[31mred"),
            Err(ConfigError::InvalidToolName { .. })
        ));
        assert!(matches!(
            validate_tool_name("tool\nname"),
            Err(ConfigError::InvalidToolName { .. })
        ));
    }

    #[test]
    fn tool_name_bidi_override_rejected() {
        // U+202E RIGHT-TO-LEFT OVERRIDE.
        assert!(matches!(
            validate_tool_name("tool\u{202e}loot"),
            Err(ConfigError::InvalidToolName { .. })
        ));
    }

    #[test]
    fn tool_name_zero_width_character_rejected() {
        // U+200B ZERO WIDTH SPACE.
        assert!(matches!(
            validate_tool_name("too\u{200b}l"),
            Err(ConfigError::InvalidToolName { .. })
        ));
    }

    #[test]
    fn tool_name_space_rejected() {
        assert!(matches!(
            validate_tool_name("my tool"),
            Err(ConfigError::InvalidToolName { .. })
        ));
    }

    #[test]
    fn tool_name_empty_rejected() {
        assert!(matches!(
            validate_tool_name(""),
            Err(ConfigError::InvalidToolName { .. })
        ));
    }

    // ── Tool name validation in parsing context ──────────────────────────

    #[test]
    fn parse_rejects_tool_name_with_forward_slash() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[tools."bad/name"]
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let result = load_config(tmp.path());
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ConfigError::InvalidToolName { .. }),
            "should reject tool name with forward slash"
        );
    }

    #[test]
    fn parse_rejects_tool_name_with_backslash() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[tools."bad\\name"]
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let result = load_config(tmp.path());
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ConfigError::InvalidToolName { .. }),
            "should reject tool name with backslash"
        );
    }

    // ── Home-root opt-in guard ───────────────────────────────────────────

    #[test]
    fn load_refuses_home_root_without_opt_in() {
        let tmp = tempdir().unwrap();
        // Config without allow_home_root anywhere.
        write_config(
            tmp.path(),
            r#"
[tools.mytool]
"#,
        );

        let result = load_config_at(tmp.path(), tmp.path());
        match result {
            Err(ConfigError::HomeRootNotAllowed { .. }) => {}
            other => panic!("expected HomeRootNotAllowed, got: {other:?}"),
        }
    }

    #[test]
    fn load_accepts_home_root_with_opt_in() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        // v2: allow_home_root is a config error in the repo layer — only
        // the local (or global) layer may opt in.
        write_local_config(tmp.path(), "allow_home_root = true\n");

        load_config_at(tmp.path(), tmp.path())
            .expect("allow_home_root=true in the local layer should permit $HOME as sandbox root");
    }

    #[test]
    fn load_non_home_root_ignores_opt_in_flag() {
        let tmp = tempdir().unwrap();
        // Put the config in a subdirectory so sandbox_root != $HOME.
        let project = tmp.path().join("project");
        fs::create_dir(&project).unwrap();
        write_config(
            &project,
            r#"
[tools.mytool]
"#,
        );

        load_config_at(&project, tmp.path())
            .expect("non-home sandbox root should load without opt-in");
    }

    // ── [secrets] + tools.env schema ─────────────────────────────────────

    #[test]
    fn parse_env_source_from_defaults_to_label() {
        // When `from` is omitted, the label itself is the env var name.
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.GH_TOKEN]
source = "env"

[tools.gh.env]
GH_TOKEN = { secret = "GH_TOKEN" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        match &config.secrets["GH_TOKEN"].source {
            SecretSource::Env { from } => assert_eq!(from, "GH_TOKEN"),
            other => panic!("expected Env source, got: {other:?}"),
        }
    }

    #[test]
    fn parse_command_source_with_default_timeout() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.cmd_token]
source = "command"
command = ["echo", "hello"]

[tools.runner.env]
TOKEN = { secret = "cmd_token" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        match &config.secrets["cmd_token"].source {
            SecretSource::Command {
                argv,
                timeout,
                refresh,
                env,
            } => {
                assert_eq!(argv, &vec!["echo".to_string(), "hello".to_string()]);
                assert_eq!(
                    *timeout,
                    Duration::from_secs(DEFAULT_COMMAND_SECRET_TIMEOUT_SECS)
                );
                assert!(refresh.is_none());
                assert!(!env.clear);
                assert!(env.set.is_empty());
            }
            other => panic!("expected Command source, got: {other:?}"),
        }
    }

    #[test]
    fn parse_command_secret_with_refresh_resolves_spec() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.gcp_token]
source = "command"
command = ["gcloud", "auth", "print-access-token"]
timeout = 10
refresh = 3000
refresh_max_backoff = 600

[tools.runner.env]
TOKEN = { secret = "gcp_token" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());
        let config = load_config(tmp.path()).unwrap();
        match &config.secrets["gcp_token"].source {
            SecretSource::Command {
                refresh: Some(spec),
                ..
            } => {
                assert_eq!(spec.interval, Duration::from_secs(3000));
                assert_eq!(spec.max_backoff, Duration::from_secs(600));
            }
            other => panic!("expected Command source with refresh, got: {other:?}"),
        }
    }

    #[test]
    fn parse_command_secret_refresh_max_backoff_defaults_to_refresh() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.tok]
source = "command"
command = ["echo", "hi"]
timeout = 5
refresh = 60

[tools.runner.env]
TOKEN = { secret = "tok" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());
        let config = load_config(tmp.path()).unwrap();
        match &config.secrets["tok"].source {
            SecretSource::Command {
                refresh: Some(spec),
                ..
            } => {
                assert_eq!(spec.interval, Duration::from_secs(60));
                assert_eq!(spec.max_backoff, Duration::from_secs(60));
            }
            other => panic!("expected refresh spec, got: {other:?}"),
        }
    }

    #[test]
    fn parse_command_secret_refresh_zero_rejected() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.tok]
source = "command"
command = ["echo", "hi"]
timeout = 1
refresh = 0

[tools.runner.env]
TOKEN = { secret = "tok" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());
        let err = load_config(tmp.path()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidRefreshInterval { ref label, .. } if label == "tok"),
            "got: {err:?}"
        );
    }

    #[test]
    fn parse_command_secret_refresh_shorter_than_timeout_rejected() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.tok]
source = "command"
command = ["echo", "hi"]
timeout = 30
refresh = 5

[tools.runner.env]
TOKEN = { secret = "tok" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());
        let err = load_config(tmp.path()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidRefreshInterval { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn parse_command_secret_refresh_max_backoff_without_refresh_rejected() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.tok]
source = "command"
command = ["echo", "hi"]
refresh_max_backoff = 30

[tools.runner.env]
TOKEN = { secret = "tok" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());
        let err = load_config(tmp.path()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidRefreshConfig { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn parse_command_secret_refresh_max_backoff_shorter_than_timeout_rejected() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.tok]
source = "command"
command = ["echo", "hi"]
timeout = 30
refresh = 60
refresh_max_backoff = 5

[tools.runner.env]
TOKEN = { secret = "tok" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());
        let err = load_config(tmp.path()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidRefreshConfig { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn parse_command_secret_env_fields_resolve() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.tok]
source = "command"
command = ["gcloud", "auth", "print-access-token"]
env = { CLOUDSDK_CONFIG = "/home/user/.config/gcloud" }
env_clear = true

[tools.runner.env]
TOKEN = { secret = "tok" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());
        let config = load_config(tmp.path()).unwrap();
        match &config.secrets["tok"].source {
            SecretSource::Command { env, .. } => {
                assert!(env.clear);
                assert_eq!(
                    env.set.get("CLOUDSDK_CONFIG").map(String::as_str),
                    Some("/home/user/.config/gcloud")
                );
            }
            other => panic!("expected Command source, got: {other:?}"),
        }
    }

    #[test]
    fn parse_command_secret_env_rejects_invalid_var_name() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.tok]
source = "command"
command = ["echo", "hi"]

[secrets.tok.env]
"1BAD" = "nope"

[tools.runner.env]
TOKEN = { secret = "tok" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());
        let err = load_config(tmp.path()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidSecretEnvVarName { ref label, ref name } if label == "tok" && name == "1BAD"),
            "got: {err:?}"
        );
    }

    #[test]
    fn parse_env_secret_with_refresh_field_rejected() {
        // The v1 tagged enum made this a serde-level deny_unknown_fields
        // rejection (ParseError). v2's flat RawSecretSpec parses `refresh`
        // unconditionally (it's a legal field of the struct, just not of
        // `source = "env"`), so the mismatch is now caught by
        // resolve_bound_secret_source instead.
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.tok]
source = "env"
refresh = 60

[tools.runner.env]
TOKEN = { secret = "tok" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());
        let err = load_config(tmp.path()).unwrap_err();
        assert!(
            matches!(err, ConfigError::SecretFieldMismatch { ref label, .. } if label == "tok"),
            "got: {err:?}"
        );
    }

    #[test]
    fn parse_tool_env_mixes_static_and_secret() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.api_key]
source = "env"
from = "API_KEY"

[tools.app.env]
API_KEY = { secret = "api_key" }
LOG_LEVEL = "debug"
REGION = "eu-north-1"
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        let tool = &config.tools["app"];
        assert_eq!(tool.env.len(), 3);
        assert!(matches!(
            tool.env.get("API_KEY"),
            Some(EnvValue::SecretRef(l)) if l == "api_key"
        ));
        assert!(matches!(
            tool.env.get("LOG_LEVEL"),
            Some(EnvValue::Static(s)) if s == "debug"
        ));
        assert!(matches!(
            tool.env.get("REGION"),
            Some(EnvValue::Static(s)) if s == "eu-north-1"
        ));
    }

    #[test]
    fn reject_undeclared_secret_ref_lists_all() {
        // See the comment in agent_env_undeclared_secret_ref_error: this
        // goes straight through resolve_wire_config for the same reason.
        let raw: RawConfig = toml::from_str(
            r#"
[secrets.known]
source = "env"
from = "KNOWN"

[tools.a.env]
A = { secret = "ghost_a" }

[tools.b.env]
B = { secret = "ghost_b" }
KNOWN = { secret = "known" }
"#,
        )
        .unwrap();

        let err = resolve_wire_config(raw, Path::new("/project")).unwrap_err();
        match err {
            ConfigError::UndeclaredSecretRefs { refs } => {
                assert_eq!(refs.len(), 2);
                assert!(refs.iter().any(|(_, _, l)| l == "ghost_a"));
                assert!(refs.iter().any(|(_, _, l)| l == "ghost_b"));
            }
            other => panic!("expected UndeclaredSecretRefs, got: {other:?}"),
        }
    }

    // ── Proxy tools ───────────────────────────────────────────────────────

    /// Load a config consisting of a declared `gcp_token` secret plus `body`.
    fn load_with_gcp_secret(body: &str) -> Result<Config, ConfigError> {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            &format!(
                r#"

[secrets.gcp_token]
source = "env"
from = "GCP_TOKEN"
{body}"#
            ),
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());
        load_config(tmp.path())
    }

    #[test]
    fn parse_proxy_tool_with_routes() {
        let config = load_with_gcp_secret(
            r#"
[tools.curl]
proxy = true

[[tools.curl.routes]]
host = "*.googleapis.com"
inject = { header = "Authorization", value = "Bearer {secret}", secret = "gcp_token" }
allow = ["GET /**", "POST /v2/projects/*/locations/*/services"]
deny = ["DELETE /**"]

[[tools.curl.routes]]
host = "example.com"
"#,
        )
        .unwrap();

        let policy = config.tools["curl"].proxy.as_ref().unwrap();
        assert_eq!(policy.routes.len(), 2);

        let google = policy.find_route("run.googleapis.com").unwrap();
        let inject = google.inject.as_ref().unwrap();
        assert_eq!(inject.header, "Authorization");
        assert_eq!(inject.prefix, "Bearer ");
        assert_eq!(inject.secret, "gcp_token");
        assert!(google.permits("GET", "/v2/projects/p/locations/l/services"));
        assert!(google.permits("POST", "/v2/projects/p/locations/l/services"));
        assert!(!google.permits("DELETE", "/v2/projects/p/locations/l/services/s"));
        assert!(!google.permits("PATCH", "/v2/projects/p/locations/l/services/s"));

        let plain = policy.find_route("example.com").unwrap();
        assert!(plain.inject.is_none());
        assert!(policy.find_route("attacker.test").is_none());
    }

    #[test]
    fn ordinary_tool_has_no_proxy_policy() {
        let config = load_with_gcp_secret("\n[tools.gh]\n").unwrap();
        assert!(config.tools["gh"].proxy.is_none());
    }

    #[test]
    fn reject_routes_without_proxy_flag() {
        let err = load_with_gcp_secret(
            r#"
[tools.curl]

[[tools.curl.routes]]
host = "example.com"
"#,
        )
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::ProxyRoutesMismatch { ref tool, .. } if tool == "curl"),
            "got: {err:?}"
        );
    }

    #[test]
    fn reject_proxy_tool_without_routes() {
        let err = load_with_gcp_secret("\n[tools.curl]\nproxy = true\n").unwrap_err();
        assert!(
            matches!(err, ConfigError::ProxyRoutesMismatch { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn reject_proxy_tool_with_secret_in_env() {
        let err = load_with_gcp_secret(
            r#"
[tools.curl]
proxy = true

[tools.curl.env]
TOKEN = { secret = "gcp_token" }

[[tools.curl.routes]]
host = "example.com"
"#,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::ProxyToolSecretEnv { ref tool, ref var_name }
                    if tool == "curl" && var_name == "TOKEN"
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn reject_proxy_tool_overriding_proxy_env_in_either_case() {
        for var in ["HTTPS_PROXY", "https_proxy", "CURL_CA_BUNDLE", "no_proxy"] {
            let err = load_with_gcp_secret(&format!(
                r#"
[tools.curl]
proxy = true

[tools.curl.env]
{var} = "x"

[[tools.curl.routes]]
host = "example.com"
"#
            ))
            .unwrap_err();
            assert!(
                matches!(err, ConfigError::ProxyReservedEnvVar { ref var_name, .. } if var_name == var),
                "{var}: got {err:?}"
            );
        }
    }

    #[test]
    fn ordinary_tool_may_still_set_proxy_env() {
        let config = load_with_gcp_secret(
            r#"
[tools.gh.env]
HTTPS_PROXY = "http://corp-proxy.internal:3128"
"#,
        )
        .unwrap();
        assert!(config.tools["gh"].env.contains_key("HTTPS_PROXY"));
    }

    #[test]
    fn proxy_tool_may_set_static_env() {
        let config = load_with_gcp_secret(
            r#"
[tools.curl]
proxy = true

[tools.curl.env]
CLOUDSDK_CORE_PROJECT = "my-project"

[[tools.curl.routes]]
host = "example.com"
"#,
        )
        .unwrap();
        assert!(
            config.tools["curl"]
                .env
                .contains_key("CLOUDSDK_CORE_PROJECT")
        );
    }

    #[test]
    fn reject_invalid_route_reports_tool_and_index() {
        let err = load_with_gcp_secret(
            r#"
[tools.curl]
proxy = true

[[tools.curl.routes]]
host = "example.com"

[[tools.curl.routes]]
host = "10.0.0.1"
"#,
        )
        .unwrap_err();
        match err {
            ConfigError::InvalidProxyRoute {
                tool,
                index,
                source,
            } => {
                assert_eq!(tool, "curl");
                assert_eq!(index, 1);
                assert!(matches!(source, RouteError::InvalidHost { .. }));
            }
            other => panic!("expected InvalidProxyRoute, got: {other:?}"),
        }
    }

    #[test]
    fn reject_invalid_rule_and_inject() {
        let err = load_with_gcp_secret(
            r#"
[tools.curl]
proxy = true

[[tools.curl.routes]]
host = "example.com"
allow = ["get /**"]
"#,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::InvalidProxyRoute {
                    source: RouteError::InvalidRule { .. },
                    ..
                }
            ),
            "got: {err:?}"
        );

        let err = load_with_gcp_secret(
            r#"
[tools.curl]
proxy = true

[[tools.curl.routes]]
host = "example.com"
inject = { header = "Host", value = "{secret}", secret = "gcp_token" }
"#,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::InvalidProxyRoute {
                    source: RouteError::InvalidInject { .. },
                    ..
                }
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn reject_duplicate_route_host_case_insensitively() {
        let err = load_with_gcp_secret(
            r#"
[tools.curl]
proxy = true

[[tools.curl.routes]]
host = "example.com"

[[tools.curl.routes]]
host = "Example.COM"
"#,
        )
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::DuplicateProxyRouteHost { ref host, .. } if host == "example.com"),
            "got: {err:?}"
        );
    }

    #[test]
    fn reject_route_with_undeclared_secret() {
        let err = load_with_gcp_secret(
            r#"
[tools.curl]
proxy = true

[[tools.curl.routes]]
host = "example.com"
inject = { header = "Authorization", value = "Bearer {secret}", secret = "ghost" }
"#,
        )
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::UndeclaredProxySecret { ref label, .. } if label == "ghost"),
            "got: {err:?}"
        );
    }

    #[test]
    fn reject_unknown_route_field() {
        let err = load_with_gcp_secret(
            r#"
[tools.curl]
proxy = true

[[tools.curl.routes]]
host = "example.com"
alow = ["GET /**"]
"#,
        )
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::ParseError { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn reject_invalid_env_var_name() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[tools.bad.env]
"1LEADING_DIGIT" = "nope"
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let err = load_config(tmp.path()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidEnvVarName { .. }));
    }

    // ── Env value templating: {sandbox_root} ──────────────────────────────

    #[test]
    fn env_value_substitutes_sandbox_root() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[tools.gh.env]
GH_CONFIG_DIR = "{sandbox_root}/.config/gh"
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        let expected = format!("{}/.config/gh", config.sandbox_root.display());
        assert!(matches!(
            config.tools["gh"].env.get("GH_CONFIG_DIR"),
            Some(EnvValue::Static(s)) if *s == expected
        ));
    }

    #[test]
    fn env_value_substitutes_multiple_occurrences() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[tools.t.env]
BOTH = "{sandbox_root}:{sandbox_root}"
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        let root = config.sandbox_root.display().to_string();
        let expected = format!("{root}:{root}");
        assert!(matches!(
            config.tools["t"].env.get("BOTH"),
            Some(EnvValue::Static(s)) if *s == expected
        ));
    }

    #[test]
    fn env_value_escape_literal_brace() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[tools.t.env]
LIT = "\\{sandbox_root\\}"
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        assert!(matches!(
            config.tools["t"].env.get("LIT"),
            Some(EnvValue::Static(s)) if s == "{sandbox_root}"
        ));
    }

    #[test]
    fn env_value_unknown_placeholder_errors() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[tools.t.env]
X = "{home}"
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let err = load_config(tmp.path()).unwrap_err();
        match err {
            ConfigError::UnknownEnvPlaceholder {
                tool,
                var_name,
                placeholder,
            } => {
                assert_eq!(tool, "t");
                assert_eq!(var_name, "X");
                assert_eq!(placeholder, "home");
            }
            other => panic!("expected UnknownEnvPlaceholder, got: {other:?}"),
        }
    }

    #[test]
    fn env_value_malformed_template_errors() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[tools.t.env]
X = "{sandbox_root"
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let err = load_config(tmp.path()).unwrap_err();
        assert!(
            matches!(err, ConfigError::EnvTemplateParse { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn env_value_secret_ref_label_not_templated() {
        // Brace characters inside a secret label are passed through untouched —
        // the label is a key, not a template. (Note: '{' is not a valid env-var
        // name character, so we place the braces in the label string itself.)
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets."weird{label}"]
source = "env"
from = "WEIRD"

[tools.t.env]
WEIRD = { secret = "weird{label}" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        assert!(matches!(
            config.tools["t"].env.get("WEIRD"),
            Some(EnvValue::SecretRef(l)) if l == "weird{label}"
        ));
    }

    #[test]
    fn env_value_plain_string_passes_through() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[tools.t.env]
HOST = "github.com"
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        assert!(matches!(
            config.tools["t"].env.get("HOST"),
            Some(EnvValue::Static(s)) if s == "github.com"
        ));
    }

    #[test]
    fn reject_empty_command_argv() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.bad]
source = "command"
command = []
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let err = load_config(tmp.path()).unwrap_err();
        assert!(matches!(err, ConfigError::EmptyCommandArgv { .. }));
    }

    #[test]
    fn reject_unknown_source_value() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.x]
source = "vault"
address = "https://vault"
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let err = load_config(tmp.path()).unwrap_err();
        assert!(matches!(err, ConfigError::ParseError { .. }));
    }

    #[test]
    fn reject_unknown_field_in_secret_ref() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.x]
source = "env"
from = "X"

[tools.t.env]
X = { secret = "x", type = "string" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        // The untagged enum in RawEnvValue means this falls through to
        // Static(String), then fails as a non-string. Either way it must
        // surface as ParseError.
        let err = load_config(tmp.path()).unwrap_err();
        assert!(matches!(err, ConfigError::ParseError { .. }));
    }

    #[test]
    fn is_valid_env_var_name_accepts_and_rejects() {
        assert!(is_valid_env_var_name("FOO"));
        assert!(is_valid_env_var_name("_FOO_BAR"));
        assert!(is_valid_env_var_name("foo_bar_1"));
        assert!(is_valid_env_var_name("F"));
        assert!(!is_valid_env_var_name(""));
        assert!(!is_valid_env_var_name("1FOO"));
        assert!(!is_valid_env_var_name("FOO-BAR"));
        assert!(!is_valid_env_var_name("FOO BAR"));
        assert!(!is_valid_env_var_name("FOO.BAR"));
    }

    // ── Error type uses thiserror ────────────────────────────────────────

    #[test]
    fn config_error_is_std_error() {
        // Verify ConfigError implements std::error::Error (via thiserror).
        fn assert_error<E: std::error::Error>() {}
        assert_error::<ConfigError>();
    }

    #[test]
    fn config_error_display_messages() {
        let err = ConfigError::NotFound {
            start_dir: PathBuf::from("/some/dir"),
            home_dir: PathBuf::from("/home/user"),
        };
        let msg = err.to_string();
        assert!(msg.contains("/some/dir"));
        assert!(msg.contains("/home/user"));

        let err = ConfigError::HomeNotSet;
        assert!(err.to_string().contains("HOME"));

        let err = ConfigError::InvalidToolName {
            name: "bad/tool".to_string(),
        };
        assert!(err.to_string().contains("bad/tool"));
    }

    // ── Helper: temporary environment variable override ──────────────────

    use std::sync::MutexGuard;

    /// RAII guard that sets an environment variable for the duration of a test
    /// and restores it when dropped. Holds [`crate::test_support::ENV_MUTEX`]
    /// — the crate-wide lock — to serialize against every other test that
    /// touches the process environment, in any module. Using a single mutex
    /// across the test suite is what keeps `HOME`-mutating tests in
    /// `config`, `run`, and `sandbox` from racing each other.
    struct TempEnvVar {
        key: String,
        prev: Option<String>,
        _lock: MutexGuard<'static, ()>,
    }

    impl TempEnvVar {
        fn new(key: &str, value: &str) -> Self {
            // Acquire the crate-wide env mutex first to ensure exclusive
            // access. Poisoned-lock recovery is fine here: a panicked test
            // already restored its own var via the Drop below.
            let lock = crate::test_support::ENV_MUTEX
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let prev = std::env::var(key).ok();
            // SAFETY: we hold the crate-wide ENV_MUTEX, so no other test
            // thread anywhere in the suite is reading or writing env vars
            // concurrently.
            unsafe { std::env::set_var(key, value) };
            Self {
                key: key.to_string(),
                prev,
                _lock: lock,
            }
        }
    }

    impl Drop for TempEnvVar {
        fn drop(&mut self) {
            match &self.prev {
                // SAFETY: We still hold ENV_MUTEX (dropped after this).
                Some(v) => unsafe { std::env::set_var(&self.key, v) },
                None => unsafe { std::env::remove_var(&self.key) },
            }
        }
    }

    // ── Default config template ──────────────────────────────────────────

    #[test]
    fn default_config_template_is_valid_toml() {
        let template = default_config_template();
        // The template is all comments, so it should parse as an empty TOML.
        let parsed: Result<RawConfig, _> = toml::from_str(template);
        assert!(
            parsed.is_ok(),
            "default config template should be valid TOML: {:?}",
            parsed.err()
        );
    }

    #[test]
    fn global_config_template_is_valid_toml() {
        let parsed: Result<RawConfig, _> = toml::from_str(global_config_template());
        assert!(
            parsed.is_ok(),
            "global config template should be valid TOML: {:?}",
            parsed.err()
        );
    }

    #[test]
    fn local_config_template_standalone_is_valid_toml() {
        let parsed: Result<RawConfig, _> = toml::from_str(local_config_template_standalone());
        assert!(
            parsed.is_ok(),
            "local standalone template should be valid TOML: {:?}",
            parsed.err()
        );
    }

    /// Uncommenting the global template's kits section (`[agent] kits =
    /// [...]`, `[kits.rust] mode = "..."`, the `[kits.bazel]` example) must
    /// still parse — a quick guard against the example drifting from the
    /// real schema.
    #[test]
    fn global_config_template_kits_section_still_parses_uncommented() {
        let uncommented = r#"
[kits.rust]
mode = "isolated"

[kits.bazel]
read  = ["~/.bazelrc"]
write = ["~/.cache/bazel"]
env   = { BAZEL_OUTPUT_USER_ROOT = "{kit_state}/out" }

[agent]
passthrough_env = ["COLORTERM"]
kits = ["rust"]
"#;
        let parsed: RawConfig =
            toml::from_str(uncommented).expect("uncommented kits section parses");
        assert_eq!(parsed.agent.unwrap().kits, vec!["rust".to_string()]);
        assert_eq!(parsed.kits.unwrap().len(), 2);
    }

    #[test]
    fn config_filename_returns_expected_name() {
        assert_eq!(config_filename(), "airlock.toml");
    }

    // ── AgentConfig: no [agent] section → Config::agent is None ─────────

    #[test]
    fn agent_absent_is_none() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        assert!(
            config.agent.is_none(),
            "agent should be None when [agent] is absent"
        );
    }

    // ── AgentConfig: bare [agent] header defaults to zero/empty ─────────

    #[test]
    fn agent_bare_header_defaults() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[agent]
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        let agent = config
            .agent
            .expect("bare [agent] header should produce Some(AgentConfig)");
        assert_eq!(
            agent.timeout,
            Duration::ZERO,
            "default timeout should be zero"
        );
        assert!(
            agent.passthrough_env.is_empty(),
            "default passthrough_env should be empty"
        );
        assert!(agent.env.is_empty(), "default env should be empty");
        assert!(
            agent.filesystem_read.is_empty(),
            "default filesystem_read should be empty"
        );
        assert!(
            agent.filesystem_write.is_empty(),
            "default filesystem_write should be empty"
        );
    }

    // ── AgentConfig: timeout = 0 → zero Duration; positive → seconds ────

    #[test]
    fn agent_timeout_zero_is_zero_duration() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[agent]
timeout = 0
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        assert_eq!(
            config.agent.unwrap().timeout,
            Duration::ZERO,
            "timeout = 0 should parse as zero Duration"
        );
    }

    #[test]
    fn agent_timeout_positive_is_seconds() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[agent]
timeout = 120
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        assert_eq!(
            config.agent.unwrap().timeout,
            Duration::from_secs(120),
            "timeout = 120 should parse as 120-second Duration"
        );
    }

    // ── AgentConfig: passthrough_env parses correctly ────────────────────

    #[test]
    fn agent_passthrough_env_parses() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[agent]
passthrough_env = ["COLORTERM", "NO_COLOR"]
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        let agent = config.agent.unwrap();
        assert_eq!(
            agent.passthrough_env,
            vec!["COLORTERM".to_string(), "NO_COLOR".to_string()],
        );
    }

    // ── AgentConfig: agent.env static value → EnvValue::Static ──────────

    #[test]
    fn agent_env_static_value() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[agent.env]
LOG_LEVEL = "info"
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        let agent = config.agent.unwrap();
        assert!(
            matches!(agent.env.get("LOG_LEVEL"), Some(EnvValue::Static(s)) if s == "info"),
            "static value should parse as EnvValue::Static"
        );
    }

    // ── AgentConfig: agent.env secret ref → EnvValue::SecretRef ─────────

    #[test]
    fn agent_env_secret_ref() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.API_KEY]
source = "env"
from = "API_KEY"

[agent.env]
API_KEY = { secret = "API_KEY" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        let agent = config.agent.unwrap();
        assert!(
            matches!(agent.env.get("API_KEY"), Some(EnvValue::SecretRef(l)) if l == "API_KEY"),
            "secret reference should parse as EnvValue::SecretRef"
        );
    }

    // ── AgentConfig: undeclared secret ref → UndeclaredSecretRefs ───────

    #[test]
    fn agent_env_undeclared_secret_ref_error() {
        // v2's layers::merge additionally scope-checks a repo-layer item's
        // secret refs before resolve_wire_config ever runs — bypass it and
        // call resolve_wire_config directly, which is what actually owns
        // the UndeclaredSecretRefs accumulation this test is about.
        let raw: RawConfig = toml::from_str(
            r#"
[agent.env]
MISSING = { secret = "nonexistent_label" }
"#,
        )
        .unwrap();

        let err = resolve_wire_config(raw, Path::new("/project")).unwrap_err();
        match err {
            ConfigError::UndeclaredSecretRefs { ref refs } => {
                assert_eq!(refs.len(), 1);
                // The location field should identify the agent section.
                let (location, env_var, label) = &refs[0];
                assert_eq!(
                    location, "agent",
                    "location should be 'agent' for agent env refs"
                );
                assert_eq!(env_var, "MISSING");
                assert_eq!(label, "nonexistent_label");
                // Error message should mention [agent.env].
                let msg = err.to_string();
                assert!(
                    msg.contains("[agent.env"),
                    "error message should identify [agent.env] location, got: {msg}"
                );
            }
            other => panic!("expected UndeclaredSecretRefs, got: {other:?}"),
        }
    }

    // ── AgentConfig: undeclared refs from both tool and agent env ────────

    #[test]
    fn undeclared_refs_accumulates_tool_and_agent() {
        // See the comment in agent_env_undeclared_secret_ref_error: this
        // goes straight through resolve_wire_config for the same reason.
        let raw: RawConfig = toml::from_str(
            r#"
[tools.mytool.env]
A = { secret = "tool_ghost" }

[agent.env]
B = { secret = "agent_ghost" }
"#,
        )
        .unwrap();

        let err = resolve_wire_config(raw, Path::new("/project")).unwrap_err();
        match err {
            ConfigError::UndeclaredSecretRefs { refs } => {
                assert_eq!(refs.len(), 2, "both tool and agent refs should be reported");
                assert!(refs.iter().any(|(_, _, l)| l == "tool_ghost"));
                assert!(refs.iter().any(|(_, _, l)| l == "agent_ghost"));
                // Verify location markers.
                let tool_ref = refs.iter().find(|(_, _, l)| l == "tool_ghost").unwrap();
                assert!(
                    tool_ref.0.starts_with("tools."),
                    "tool ref location should start with 'tools.'"
                );
                let agent_ref = refs.iter().find(|(_, _, l)| l == "agent_ghost").unwrap();
                assert_eq!(agent_ref.0, "agent", "agent ref location should be 'agent'");
            }
            other => panic!("expected UndeclaredSecretRefs, got: {other:?}"),
        }
    }

    // ── AgentConfig: filesystem paths are resolved ───────────────────────

    #[test]
    fn agent_filesystem_paths_resolved() {
        let tmp = tempdir().unwrap();
        let home = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[agent.filesystem]
read = ["~/projects", "relative/path"]
write = ["/tmp/agent"]
"#,
        );

        let config = load_config_at(tmp.path(), home.path()).unwrap();
        let agent = config.agent.unwrap();

        // Tilde expansion.
        let expected_projects = home.path().join("projects");
        assert!(
            agent.filesystem_read.contains(&expected_projects),
            "~/projects should expand to {{HOME}}/projects, got: {:?}",
            agent.filesystem_read
        );

        // Relative path resolved against sandbox root.
        let expected_relative = config.sandbox_root.join("relative/path");
        assert!(
            agent.filesystem_read.contains(&expected_relative),
            "relative/path should resolve to sandbox_root/relative/path, got: {:?}",
            agent.filesystem_read
        );

        // Absolute path unchanged.
        assert!(
            agent
                .filesystem_write
                .contains(&PathBuf::from("/tmp/agent")),
            "absolute path should be unchanged, got: {:?}",
            agent.filesystem_write
        );
    }

    // ── load_config_from_file: loads and validates correctly ─────────────

    #[test]
    fn load_config_from_file_success() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config_path = tmp.path().join(CONFIG_FILENAME);
        let config = load_config_from_file(&config_path).unwrap();

        let canonical = std::fs::canonicalize(tmp.path()).unwrap();
        assert_eq!(
            config.sandbox_root, canonical,
            "sandbox_root should be the canonicalized parent of the config file"
        );
        assert_eq!(config.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        assert_eq!(config.tools.len(), 1);
    }

    #[test]
    fn load_config_from_file_missing_path_returns_error() {
        let tmp = tempdir().unwrap();
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        // Parent directory exists; file does not. This surfaces as ReadError
        // (not CanonicalizationError) — the spec's recommended variant.
        let missing = tmp.path().join("nonexistent.toml");
        let result = load_config_from_file(&missing);
        assert!(result.is_err(), "missing file should return an error");
        assert!(
            matches!(result.unwrap_err(), ConfigError::ReadError { .. }),
            "missing file should return ReadError"
        );
    }

    #[test]
    fn load_config_from_file_rejects_wrong_owner() {
        // We can't easily change file ownership in tests without root, so we
        // verify the check runs by testing with a uid that is not ours.
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config_path = tmp.path().join(CONFIG_FILENAME);
        let euid = current_euid();

        // File is owned by us — should succeed.
        assert!(
            is_owned_by(&config_path, euid),
            "file should be owned by current euid"
        );

        // A different uid should not match (verifies the check is wired up).
        assert!(
            !is_owned_by(&config_path, euid.wrapping_add(1)),
            "file should not appear owned by a different uid"
        );
    }

    #[test]
    fn discover_paths_from_file_applies_ownership_check() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());

        let config_path = tmp.path().join(CONFIG_FILENAME);
        let euid = current_euid();

        // File owned by us — should succeed.
        assert!(is_owned_by(&config_path, euid));

        // Verify the ownership check function works with a wrong uid.
        assert!(!is_owned_by(&config_path, euid.wrapping_add(1)));
    }

    // ── default_config_template: contains [agent] section ───────────────

    #[test]
    fn default_config_template_contains_agent_section() {
        let template = default_config_template();
        assert!(
            template.contains("[agent]"),
            "template should contain a commented-out [agent] section"
        );
        assert!(
            template.contains("timeout"),
            "template should show the timeout field"
        );
        assert!(
            template.contains("passthrough_env"),
            "template should show the passthrough_env field"
        );
        assert!(
            template.contains("[agent.env]"),
            "template should show the [agent.env] subsection"
        );
        assert!(
            template.contains("[agent.filesystem]"),
            "template should show the [agent.filesystem] subsection"
        );
    }

    // ── Regression: existing tools configs still parse identically ───────

    #[test]
    fn tools_parsing_regression() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[secrets.tok]
source = "env"
from = "TOK"

[tools.mytool]
extra_read = ["/etc/hosts"]
extra_write = ["output"]
timeout = 30
description = "a test tool"

[tools.mytool.env]
TOK = { secret = "tok" }
LOG_LEVEL = "debug"
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        assert!(config.agent.is_none());
        let tool = config.tools.get("mytool").unwrap();
        assert_eq!(tool.extra_read, vec![PathBuf::from("/etc/hosts")]);
        assert_eq!(tool.extra_write, vec![config.sandbox_root.join("output")]);
        assert_eq!(tool.timeout, Some(Duration::from_secs(30)));
        assert_eq!(tool.description.as_deref(), Some("a test tool"));
        assert!(matches!(
            tool.env.get("TOK"),
            Some(EnvValue::SecretRef(l)) if l == "tok"
        ));
        assert!(matches!(
            tool.env.get("LOG_LEVEL"),
            Some(EnvValue::Static(s)) if s == "debug"
        ));
    }

    // ── Verify UndeclaredSecretRefs error message for tool entries ───────

    #[test]
    fn undeclared_secret_ref_error_message_format() {
        // See the comment in agent_env_undeclared_secret_ref_error: this
        // goes straight through resolve_wire_config for the same reason.
        let raw: RawConfig = toml::from_str(
            r#"
[tools.mytool.env]
A = { secret = "ghost" }
"#,
        )
        .unwrap();

        let err = resolve_wire_config(raw, Path::new("/project")).unwrap_err();
        let msg = err.to_string();
        // Error message should show [tools.mytool.env.A] -> "ghost"
        assert!(
            msg.contains("[tools.mytool.env.A]"),
            "tool undeclared ref message should contain [tools.mytool.env.A], got: {msg}"
        );
    }

    // ── AgentConfig: agent.env is stored in alphabetical BTreeMap order ──

    #[test]
    fn agent_env_is_sorted() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[agent.env]
ZEBRA = "z"
ALPHA = "a"
MANGO = "m"
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        let agent = config.agent.unwrap();
        let keys: Vec<&str> = agent.env.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["ALPHA", "MANGO", "ZEBRA"]);
    }

    // ── AgentConfig: invalid env var name in [agent.env] ────────────────

    #[test]
    fn agent_env_invalid_var_name_rejected() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[agent.env]
"1INVALID" = "value"
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let err = load_config(tmp.path()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidEnvVarName { .. }),
            "invalid env var name in [agent.env] should be rejected: {err:?}"
        );
    }

    // ── AgentConfig: unknown field in [agent] rejected by serde ─────────

    #[test]
    fn agent_unknown_field_rejected() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[agent]
unknown_field = "should fail"
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let err = load_config(tmp.path()).unwrap_err();
        assert!(
            matches!(err, ConfigError::ParseError { .. }),
            "unknown field in [agent] should cause ParseError: {err:?}"
        );
    }

    // ── load_config_from_file: sandbox_root equals canonicalized parent ──

    #[test]
    fn load_config_from_file_sandbox_root_is_parent() {
        let tmp = tempdir().unwrap();
        // Place config in a sub-project directory.
        let project = tmp.path().join("project");
        fs::create_dir(&project).unwrap();
        write_config(&project, minimal_config());

        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config_path = project.join(CONFIG_FILENAME);
        let config = load_config_from_file(&config_path).unwrap();

        let canonical_project = std::fs::canonicalize(&project).unwrap();
        assert_eq!(
            config.sandbox_root, canonical_project,
            "sandbox_root should be the canonicalized parent of the explicit config file"
        );
    }

    // ── AgentConfig: agent.env {sandbox_root} template renders ──────────

    #[test]
    fn agent_env_sandbox_root_template() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[agent.env]
WORK_DIR = "{sandbox_root}/work"
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        let expected = format!("{}/work", config.sandbox_root.display());
        let agent = config.agent.unwrap();
        assert!(
            matches!(
                agent.env.get("WORK_DIR"),
                Some(EnvValue::Static(s)) if *s == expected
            ),
            "agent env {{sandbox_root}} template should be rendered"
        );
    }

    // ── write_grants ──────────────────────────────────────────────────

    #[test]
    fn write_grants_unions_filesystem_tools_and_agent() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"

[filesystem]
write = ["/tmp/global-write"]

[tools.a]
extra_write = ["/tmp/a-write"]

[tools.b]
extra_write = ["/tmp/b-write"]

[agent.filesystem]
write = ["/tmp/agent-write"]
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        let grants = write_grants(&config);
        for expected in [
            "/tmp/global-write",
            "/tmp/a-write",
            "/tmp/b-write",
            "/tmp/agent-write",
        ] {
            assert!(
                grants.contains(&PathBuf::from(expected)),
                "write_grants missing {expected}: {grants:?}"
            );
        }
    }

    #[test]
    fn write_grants_empty_config_is_empty() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), "");
        let config = load_config(tmp.path()).unwrap();
        assert!(write_grants(&config).is_empty());
    }

    // ── resolve_wire_config ───────────────────────────────────────────

    #[test]
    fn resolve_wire_config_accepts_already_rendered_static_env() {
        // The wire form never re-renders {sandbox_root}/{tool_state} — the
        // launcher already expanded them — so a literal value containing a
        // brace-shaped string that is *not* a placeholder must still pass
        // through untouched.
        let mut tools = HashMap::new();
        tools.insert(
            "t".to_string(),
            RawToolConfig {
                env: Some(HashMap::from([(
                    "LITERAL".to_string(),
                    RawEnvValue::Static("{not a known placeholder}".to_string()),
                )])),
                ..Default::default()
            },
        );
        let raw = RawConfig {
            tools: Some(tools),
            ..Default::default()
        };
        let resolved = resolve_wire_config(raw, Path::new("/project")).unwrap();
        let tool = &resolved.tools["t"];
        match tool.env.get("LITERAL").unwrap() {
            EnvValue::Static(s) => assert_eq!(s, "{not a known placeholder}"),
            other => panic!("expected Static, got {other:?}"),
        }
    }

    #[test]
    fn resolve_wire_config_reads_no_home_env_var() {
        // Removing HOME must not break resolve_wire_config: unlike the
        // legacy loaders, it takes the root directly and never expands `~`.
        let _guard = crate::test_support::ENV_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("HOME").ok();
        // SAFETY: holding the crate-wide ENV_MUTEX (see TempEnvVar above).
        unsafe { std::env::remove_var("HOME") };
        let result = resolve_wire_config(RawConfig::default(), Path::new("/project"));
        // SAFETY: still holding ENV_MUTEX.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        assert!(result.is_ok(), "got: {result:?}");
    }
}
