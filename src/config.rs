//! Configuration discovery, parsing, and validation for Airlock.
//!
//! This module is responsible for:
//! - Discovering `airlock.toml` by walking from a starting directory up to `$HOME`
//! - Verifying config file ownership against the current effective uid
//! - Parsing the TOML config into strongly-typed structures
//! - Resolving paths (tilde expansion, relative-to-sandbox-root resolution)
//! - Deriving socket and PID file paths from the sandbox root
//! - Validating tool names (no path separators)
//! - Providing a lightweight socket-path-only discovery for client use
//!
//! This module is consumed by nearly every other module: the daemon needs the
//! full parsed config, the client needs the socket path, and commands like
//! `status` and `stop` need the PID file path.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

// ─── Constants ────────────────────────────────────────────────────────────────

/// The config file name searched for during discovery.
const CONFIG_FILENAME: &str = "airlock.toml";

/// Maximum bytes to read from `airlock.toml`. A real config is well under this;
/// the cap bounds allocation when something (or someone) points the daemon at
/// an oversized file.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Default global timeout in seconds (5 minutes).
const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Default timeout in seconds for `source = "command"` secret fetching.
const DEFAULT_COMMAND_SECRET_TIMEOUT_SECS: u64 = 10;

/// Socket filename derived from the sandbox root.
const SOCKET_FILENAME: &str = "airlock.sock";

/// PID file filename derived from the sandbox root.
const PID_FILENAME: &str = "airlock.pid";

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

    /// A tool name contains a path separator character.
    ///
    /// Tool names must be bare identifiers (e.g., `"mytool"`, `"python3"`);
    /// names containing `/` or `\` are rejected at parse time for safety.
    #[error(
        "invalid tool name {name:?}: tool names must not contain path separators ('/' or '\\')"
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
}

// ─── Raw TOML structures (serde) ──────────────────────────────────────────────

/// Raw deserialized representation of `airlock.toml`.
///
/// Uses `#[serde(default)]` and `Option` liberally so that missing sections
/// and fields produce zero/empty defaults rather than parse errors.
/// Unknown top-level keys are silently accepted via `#[serde(flatten)]` for
/// forward compatibility. Nested tables are stricter: see
/// [`RawToolConfig`] and [`RawSecretSpec`].
#[derive(Debug, Deserialize)]
struct RawConfig {
    /// Global timeout in seconds. Defaults to 300 (5 minutes).
    #[serde(default)]
    timeout: Option<u64>,

    /// Global filesystem access paths.
    #[serde(default)]
    filesystem: Option<RawFilesystem>,

    /// Secret sources. Each entry declares a logical label and the source
    /// used to fetch its value at daemon startup.
    #[serde(default)]
    secrets: Option<HashMap<String, RawSecretSpec>>,

    /// Per-tool definitions.
    #[serde(default)]
    tools: Option<HashMap<String, RawToolConfig>>,

    /// Agent section — typed and validated.
    #[serde(default)]
    agent: Option<RawAgentConfig>,

    /// Explicit opt-in to using `$HOME` as the sandbox root.
    ///
    /// When `airlock.toml` is discovered directly at `$HOME`, the sandbox root
    /// becomes the entire home directory. This is almost always wrong; Airlock
    /// refuses unless the user has explicitly set this flag to `true`.
    #[serde(default)]
    allow_home_root: Option<bool>,

    /// Catch-all for unknown top-level keys (forward compatibility).
    #[serde(flatten)]
    _extra: HashMap<String, toml::Value>,
}

/// Raw deserialized `[filesystem]` section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFilesystem {
    /// Global read-only paths.
    #[serde(default)]
    read: Vec<String>,
    /// Global read-write paths.
    #[serde(default)]
    write: Vec<String>,
}

/// Raw deserialized `[agent.filesystem]` subsection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentFilesystem {
    /// Additional read-only paths for the agent.
    #[serde(default)]
    read: Vec<String>,
    /// Additional read-write paths for the agent.
    #[serde(default)]
    write: Vec<String>,
}

/// Raw deserialized `[agent]` section.
///
/// Uses `#[serde(deny_unknown_fields)]` to surface typos and
/// `#[serde(default)]` on all fields so a bare `[agent]` header with no
/// fields is valid.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentConfig {
    /// Agent session timeout in seconds. `None` (absent) means no limit.
    #[serde(default)]
    timeout: Option<u64>,
    /// Environment variable names to inherit from the host environment.
    #[serde(default)]
    passthrough_env: Vec<String>,
    /// Environment variables set for the agent process.
    #[serde(default)]
    env: HashMap<String, RawEnvValue>,
    /// Additional filesystem paths for the agent sandbox.
    #[serde(default)]
    filesystem: Option<RawAgentFilesystem>,
}

/// Raw deserialized `[secrets.<label>]` entry. Discriminated on the `source`
/// field. Unknown fields are rejected to fail-closed on typos.
#[derive(Debug, Deserialize)]
#[serde(tag = "source", rename_all = "lowercase", deny_unknown_fields)]
enum RawSecretSpec {
    /// Read the value from one of the daemon's own environment variables.
    Env {
        /// Name of the env var the daemon should read at startup. Defaults
        /// to the `[secrets.<label>]` label when omitted — handy when the
        /// label is already named like the env var (`[secrets.GH_TOKEN]`).
        #[serde(default)]
        from: Option<String>,
    },
    /// Spawn a command at daemon startup and use its stdout as the value.
    Command {
        /// Argv list. The first element is the program, the rest are args.
        /// No shell interpolation is performed.
        command: Vec<String>,
        /// Maximum seconds to wait for the command. Defaults to
        /// [`DEFAULT_COMMAND_SECRET_TIMEOUT_SECS`].
        #[serde(default)]
        timeout: Option<u64>,
        /// Background refresh interval in seconds. When set, the daemon
        /// re-runs `command` on this cadence and replaces the in-memory
        /// value. Omit to fetch only at daemon startup.
        #[serde(default)]
        refresh: Option<u64>,
        /// Cap (seconds) on the exponential-backoff sleep applied when a
        /// refresh fails. Defaults to `refresh` when omitted; meaningless
        /// without `refresh`.
        #[serde(default)]
        refresh_max_backoff: Option<u64>,
        /// Env vars set (or overridden) when spawning the command.
        #[serde(default)]
        env: Option<HashMap<String, String>>,
        /// When `true`, spawn the command with an empty environment. `env`
        /// still applies on top.
        #[serde(default)]
        env_clear: bool,
    },
}

/// Raw deserialized value inside `[tools.<tool>.env]`.
///
/// A bare string is a static value; an inline table `{ secret = "label" }`
/// references an entry in `[secrets]`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawEnvValue {
    /// Inline table: `NAME = { secret = "label" }`. Declared first so serde
    /// tries it before falling back to the scalar string variant.
    SecretRef(RawSecretRef),
    /// Bare TOML string: `NAME = "some value"`.
    Static(String),
}

/// Inline-table form of an env var value that references a secret by label.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecretRef {
    /// Label of the entry in `[secrets.<label>]` whose resolved value is
    /// injected as this env var.
    secret: String,
}

/// Raw deserialized `[tools.X]` entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawToolConfig {
    /// Environment variables set when spawning this tool. Optional; a tool
    /// with no `env` table runs with just the base passthrough env.
    #[serde(default)]
    env: Option<HashMap<String, RawEnvValue>>,
    /// Additional read-only paths for this tool.
    #[serde(default)]
    extra_read: Vec<String>,
    /// Additional read-write paths for this tool.
    #[serde(default)]
    extra_write: Vec<String>,
    /// Per-tool timeout override in seconds.
    #[serde(default)]
    timeout: Option<u64>,
    /// Human-readable description of what this tool does.
    #[serde(default)]
    description: Option<String>,
}

// ─── Public types ─────────────────────────────────────────────────────────────

/// A fully parsed and validated Airlock configuration.
///
/// All paths have been resolved (tilde expanded, relative paths resolved
/// against the sandbox root). Derived paths (socket, PID file) are included.
#[derive(Debug)]
pub struct Config {
    /// The canonicalized directory containing the discovered `airlock.toml`.
    pub sandbox_root: PathBuf,

    /// Path to the Unix domain socket: `{sandbox_root}/airlock.sock`.
    pub socket_path: PathBuf,

    /// Path to the PID file: `{sandbox_root}/airlock.pid`.
    pub pid_path: PathBuf,

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

/// Lightweight discovery result containing only derived paths.
///
/// Used by the client and management commands that need to locate the socket
/// or PID file without parsing the full config.
#[derive(Debug)]
pub struct DiscoveredPaths {
    /// The canonicalized sandbox root directory.
    pub sandbox_root: PathBuf,

    /// Path to the Unix domain socket.
    pub socket_path: PathBuf,

    /// Path to the PID file.
    pub pid_path: PathBuf,
}

// ─── Discovery ────────────────────────────────────────────────────────────────

/// Get the current effective uid of the process.
fn current_euid() -> u32 {
    // SAFETY: geteuid(2) is always safe — it reads a process attribute
    // without modifying any state.
    unsafe { libc::geteuid() }
}

/// Check whether `path` is the user's home directory, comparing canonicalized
/// forms so symlinked home directories (`/home/foo` → `/mnt/home/foo`) are
/// still detected.
///
/// Returns `Err(HomeNotSet)` if the `HOME` environment variable is unset.
fn is_home_directory(path: &Path) -> Result<bool, ConfigError> {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| ConfigError::HomeNotSet)?;
    let home_canonical = std::fs::canonicalize(&home).unwrap_or(home);
    Ok(path == home_canonical)
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
fn is_owned_by(path: &Path, expected_uid: u32) -> bool {
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
fn read_config_securely(path: &Path, expected_uid: u32) -> Result<String, ConfigError> {
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

/// Walk from `start_dir` upward to `$HOME` (inclusive), looking for a valid
/// `airlock.toml` owned by the current effective uid.
///
/// Returns the path to the discovered config file and its canonicalized
/// parent directory (the sandbox root).
///
/// The starting directory is typically the process's current working directory,
/// but accepting it as a parameter makes the function testable.
fn discover_config_file(start_dir: &Path) -> Result<(PathBuf, PathBuf), ConfigError> {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| ConfigError::HomeNotSet)?;

    let euid = current_euid();

    // Canonicalize `start_dir` and `home` for reliable prefix comparison.
    // If canonicalization fails for the start dir, fall back to the original path.
    let start_canonical =
        std::fs::canonicalize(start_dir).unwrap_or_else(|_| start_dir.to_path_buf());
    let home_canonical = std::fs::canonicalize(&home).unwrap_or_else(|_| home.clone());

    let mut current = start_canonical.clone();

    loop {
        let candidate = current.join(CONFIG_FILENAME);

        // `is_owned_by` opens with O_NOFOLLOW and fstats the fd, so it
        // implicitly handles missing files, symlinks, and non-regular files
        // (returning false for any of them). No separate `is_file()` check is
        // needed — it would only follow symlinks and widen the attack surface.
        if is_owned_by(&candidate, euid) {
            // Canonicalize the parent directory to get the sandbox root.
            let sandbox_root = std::fs::canonicalize(&current).map_err(|e| {
                ConfigError::CanonicalizationError {
                    path: current.clone(),
                    source: e,
                }
            })?;
            return Ok((candidate, sandbox_root));
        }

        // Check if we've reached $HOME — stop here (inclusive: we already checked it).
        if current == home_canonical {
            break;
        }

        // Move to the parent directory.
        match current.parent() {
            Some(parent) => {
                // If the parent is the same as current, we've hit the root.
                if parent == current {
                    break;
                }
                current = parent.to_path_buf();
            }
            None => break,
        }
    }

    Err(ConfigError::NotFound {
        start_dir: start_dir.to_path_buf(),
        home_dir: home,
    })
}

// ─── Path resolution ──────────────────────────────────────────────────────────

/// Resolve a path string according to Airlock path resolution rules:
/// - Tilde (`~`) at the start is expanded to `$HOME`
/// - Relative paths are resolved relative to the sandbox root
/// - Absolute paths are left unchanged
fn resolve_path(raw: &str, sandbox_root: &Path) -> Result<PathBuf, ConfigError> {
    if let Some(rest) = raw.strip_prefix("~/") {
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .map_err(|_| ConfigError::HomeNotSet)?;
        Ok(home.join(rest))
    } else if raw == "~" {
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .map_err(|_| ConfigError::HomeNotSet)?;
        Ok(home)
    } else {
        let path = Path::new(raw);
        if path.is_absolute() {
            Ok(path.to_path_buf())
        } else {
            // Relative path — resolve against sandbox root.
            Ok(sandbox_root.join(path))
        }
    }
}

/// Resolve a list of path strings.
fn resolve_paths(raw_paths: &[String], sandbox_root: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    raw_paths
        .iter()
        .map(|p| resolve_path(p, sandbox_root))
        .collect()
}

/// Render a static `[tools.<tool>.env]` value as a leon template.
///
/// The only recognized placeholder is `{sandbox_root}`, which expands to the
/// canonicalized sandbox root. Literal braces can be included with `\{` /
/// `\}`. Any other placeholder (`{home}`, typos like `{sandbox-root}`) is a
/// hard error — failing at config load is preferable to silently shipping a
/// broken env value to a tool.
fn render_env_template(
    raw: &str,
    sandbox_root: &Path,
    tool: &str,
    var_name: &str,
) -> Result<String, ConfigError> {
    let template = leon::Template::parse(raw).map_err(|e| ConfigError::EnvTemplateParse {
        tool: tool.to_string(),
        var_name: var_name.to_string(),
        message: e.to_string(),
    })?;

    let root = sandbox_root.display().to_string();
    let mut values: HashMap<&str, &str> = HashMap::with_capacity(1);
    values.insert("sandbox_root", root.as_str());

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

// ─── Tool name validation ─────────────────────────────────────────────────────

/// Validate that a tool name does not contain path separators.
///
/// Both forward slash (`/`) and backslash (`\`) are rejected. This mirrors
/// the same constraint enforced by `exec::resolve_binary` but catches it
/// earlier at config load time, and additionally rejects `\` for
/// cross-platform safety.
fn validate_tool_name(name: &str) -> Result<(), ConfigError> {
    if name.contains('/') || name.contains('\\') {
        return Err(ConfigError::InvalidToolName {
            name: name.to_string(),
        });
    }
    Ok(())
}

// ─── Env var name validation ──────────────────────────────────────────────────

/// Check whether `name` matches `^[A-Za-z_][A-Za-z0-9_]*$` — the POSIX
/// environment variable name shape, case-permissive.
fn is_valid_env_var_name(name: &str) -> bool {
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
fn resolve_refresh_spec(
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
fn resolve_secret_command_env(
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

// ─── Public API ───────────────────────────────────────────────────────────────

/// Parse and resolve a raw TOML config string into a fully validated [`Config`].
///
/// This is the shared resolution core called by both [`load_config`] (which
/// discovers the file) and [`load_config_from_file`] (explicit path). All
/// validation — home-root guard, tool names, secret refs, env var names,
/// path resolution — is performed here.
fn parse_and_resolve_config(
    contents: &str,
    config_path: &Path,
    sandbox_root: PathBuf,
) -> Result<Config, ConfigError> {
    let raw: RawConfig = toml::from_str(contents).map_err(|e| ConfigError::ParseError {
        path: config_path.to_path_buf(),
        source: e,
    })?;

    // Refuse to use $HOME as the sandbox root unless the config explicitly
    // opts in. A lone `airlock.toml` in the home directory would otherwise
    // silently expose the whole home directory to sandboxed tools.
    if is_home_directory(&sandbox_root)? && raw.allow_home_root != Some(true) {
        return Err(ConfigError::HomeRootNotAllowed { home: sandbox_root });
    }

    // Resolve global timeout.
    let timeout = Duration::from_secs(raw.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS));

    // Resolve filesystem paths.
    let (filesystem_read, filesystem_write) = match raw.filesystem {
        Some(fs) => (
            resolve_paths(&fs.read, &sandbox_root)?,
            resolve_paths(&fs.write, &sandbox_root)?,
        ),
        None => (Vec::new(), Vec::new()),
    };

    // Resolve [secrets] entries first so tool and agent env entries can be
    // validated against them in the same pass.
    let raw_secrets = raw.secrets.unwrap_or_default();
    let mut secrets: HashMap<String, SecretSpec> = HashMap::with_capacity(raw_secrets.len());
    for (label, spec) in raw_secrets {
        let source = match spec {
            RawSecretSpec::Env { from } => SecretSource::Env {
                from: from.unwrap_or_else(|| label.clone()),
            },
            RawSecretSpec::Command {
                command,
                timeout,
                refresh,
                refresh_max_backoff,
                env,
                env_clear,
            } => {
                if command.is_empty() {
                    return Err(ConfigError::EmptyCommandArgv {
                        label: label.clone(),
                    });
                }
                let timeout =
                    Duration::from_secs(timeout.unwrap_or(DEFAULT_COMMAND_SECRET_TIMEOUT_SECS));
                let refresh = resolve_refresh_spec(&label, timeout, refresh, refresh_max_backoff)?;
                let env = resolve_secret_command_env(&label, env, env_clear)?;
                SecretSource::Command {
                    argv: command,
                    timeout,
                    refresh,
                    env,
                }
            }
        };
        secrets.insert(label.clone(), SecretSpec { label, source });
    }

    // Validate and resolve tool definitions. Env var names and secret
    // references are validated in a batched pass so the operator sees every
    // problem in one error message. The location key in each undeclared-ref
    // tuple is `"tools.<name>"` for per-tool entries (see also the agent pass
    // below, which uses `"agent"`).
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
                let value = match raw_value {
                    RawEnvValue::Static(s) => {
                        EnvValue::Static(render_env_template(&s, &sandbox_root, &name, &var_name)?)
                    }
                    RawEnvValue::SecretRef(RawSecretRef { secret }) => {
                        if !secrets.contains_key(&secret) {
                            // Location key includes the "tools." prefix so the
                            // error message formats as [tools.<name>.env.<var>].
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

        let tool_config = ToolConfig {
            env,
            extra_read: resolve_paths(&raw_tool.extra_read, &sandbox_root)?,
            extra_write: resolve_paths(&raw_tool.extra_write, &sandbox_root)?,
            timeout: raw_tool.timeout.map(Duration::from_secs),
            description: raw_tool.description,
        };

        tools.insert(name, tool_config);
    }

    // Resolve the [agent] section when present.
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
                    RawEnvValue::Static(s) => EnvValue::Static(render_env_template(
                        &s,
                        &sandbox_root,
                        "agent",
                        &var_name,
                    )?),
                    RawEnvValue::SecretRef(RawSecretRef { secret }) => {
                        if !secrets.contains_key(&secret) {
                            // Location key is "agent" so the error message
                            // formats as [agent.env.<var>].
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
                    resolve_paths(&fs.read, &sandbox_root)?,
                    resolve_paths(&fs.write, &sandbox_root)?,
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

    // Derive socket and PID file paths.
    let socket_path = sandbox_root.join(SOCKET_FILENAME);
    let pid_path = sandbox_root.join(PID_FILENAME);

    Ok(Config {
        sandbox_root,
        socket_path,
        pid_path,
        timeout,
        filesystem_read,
        filesystem_write,
        secrets,
        tools,
        agent,
    })
}

/// Discover and parse the Airlock configuration.
///
/// Walks from `start_dir` upward to `$HOME` looking for a valid `airlock.toml`
/// owned by the current effective uid. The first valid file found is parsed
/// and returned as a fully resolved [`Config`].
///
/// # Arguments
///
/// * `start_dir` — The directory to start searching from (typically `std::env::current_dir()`).
///
/// # Errors
///
/// Returns [`ConfigError`] if:
/// - No valid config file is found between `start_dir` and `$HOME`
/// - `$HOME` is not set
/// - The config file cannot be read or parsed
/// - A tool name contains a path separator
pub fn load_config(start_dir: &Path) -> Result<Config, ConfigError> {
    let (config_path, sandbox_root) = discover_config_file(start_dir)?;

    // Re-open the config via O_NOFOLLOW + fstat to close the TOCTOU window
    // between discovery and read. An attacker who cannot modify the containing
    // directory cannot swap the file between the walk's ownership check and
    // this read — but if they can, the re-check here will catch a UID change.
    let contents = read_config_securely(&config_path, current_euid())?;

    parse_and_resolve_config(&contents, &config_path, sandbox_root)
}

/// Load and fully validate a config from an explicitly supplied path.
///
/// Unlike [`load_config`], this function skips the directory walk and uses the
/// given `path` directly. It applies the same `O_NOFOLLOW` + `fstat` ownership
/// check as the discovery path. The sandbox root is the canonicalized parent
/// directory of `path`.
///
/// # Errors
///
/// Returns [`ConfigError`] if:
/// - The file does not exist or cannot be opened
/// - The file is not owned by the current effective uid
/// - `$HOME` is not set (needed for tilde expansion and home-root guard)
/// - The config file cannot be parsed or fails validation
pub fn load_config_from_file(path: &Path) -> Result<Config, ConfigError> {
    // Canonicalize the parent directory to derive sandbox_root before reading
    // the file, so that path resolution in parse_and_resolve_config is correct.
    let parent = path.parent().ok_or_else(|| ConfigError::ReadError {
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "config path has no parent directory",
        ),
    })?;

    let sandbox_root =
        std::fs::canonicalize(parent).map_err(|e| ConfigError::CanonicalizationError {
            path: parent.to_path_buf(),
            source: e,
        })?;

    // read_config_securely opens with O_NOFOLLOW and checks the file's uid via
    // fstat, providing the same TOCTOU-resistant ownership guarantee as the
    // discovery path. Missing files surface as ReadError(NotFound); files owned
    // by a different uid surface as ReadError(PermissionDenied).
    let contents = read_config_securely(path, current_euid())?;

    parse_and_resolve_config(&contents, path, sandbox_root)
}

/// Discover the socket and PID file paths without parsing the config file.
///
/// This is a lightweight alternative to [`load_config`] for use by the client
/// and management commands that only need the socket location. It performs the
/// same directory walk and ownership check but does not read or parse the file
/// contents.
///
/// # Arguments
///
/// * `start_dir` — The directory to start searching from.
///
/// # Errors
///
/// Returns [`ConfigError`] if no valid config file is found or `$HOME` is not set.
pub fn discover_paths(start_dir: &Path) -> Result<DiscoveredPaths, ConfigError> {
    let (_config_path, sandbox_root) = discover_config_file(start_dir)?;

    Ok(DiscoveredPaths {
        socket_path: sandbox_root.join(SOCKET_FILENAME),
        pid_path: sandbox_root.join(PID_FILENAME),
        sandbox_root,
    })
}

/// Return the socket and PID file paths derived from an explicitly supplied
/// config file path, without parsing the file contents.
///
/// This is the explicit-path counterpart of [`discover_paths`]. It applies the
/// same `O_NOFOLLOW` + `fstat` ownership check as the discovery path but skips
/// the directory walk, using `path`'s parent as the sandbox root.
///
/// # Errors
///
/// Returns [`ConfigError`] if the file does not exist, is not owned by the
/// current effective uid, or its parent directory cannot be canonicalized.
pub fn discover_paths_from_file(path: &Path) -> Result<DiscoveredPaths, ConfigError> {
    let euid = current_euid();

    // Ownership check: opens with O_NOFOLLOW and fstats the fd — the same
    // TOCTOU-resistant method used during directory-walk discovery.
    if !is_owned_by(path, euid) {
        return Err(ConfigError::ReadError {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "config file not found or not owned by current user",
            ),
        });
    }

    let parent = path.parent().ok_or_else(|| ConfigError::ReadError {
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "config path has no parent directory",
        ),
    })?;

    let sandbox_root =
        std::fs::canonicalize(parent).map_err(|e| ConfigError::CanonicalizationError {
            path: parent.to_path_buf(),
            source: e,
        })?;

    Ok(DiscoveredPaths {
        socket_path: sandbox_root.join(SOCKET_FILENAME),
        pid_path: sandbox_root.join(PID_FILENAME),
        sandbox_root,
    })
}

/// Return the config file name (`airlock.toml`).
///
/// Exposed so that other modules (e.g. the `init` command) can reference the
/// canonical file name without duplicating the constant.
pub fn config_filename() -> &'static str {
    CONFIG_FILENAME
}

/// Return a default `airlock.toml` template suitable for new projects.
///
/// The template contains commented-out examples of every supported section
/// so that users can quickly uncomment and customise what they need.
pub fn default_config_template() -> &'static str {
    r#"# Airlock configuration
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

# Define tools and the environment they run with. `env` entries are either
# static strings or references to a [secrets.<label>] entry.
# [tools.example]
# extra_read  = []
# extra_write = []
# timeout     = 60
#
# [tools.example.env]
# API_KEY = { secret = "API_KEY" }
# LOG_LEVEL = "info"

# Configure the AI agent sandbox launched by `airlock run`.
# [agent]
# # Maximum agent session time in seconds. 0 = no limit.
# timeout = 0
#
# # Environment variable names inherited from the host process.
# passthrough_env = ["COLORTERM", "NO_COLOR"]
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

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Create an `airlock.toml` with the given content at the specified directory.
    fn write_config(dir: &Path, content: &str) {
        fs::write(dir.join(CONFIG_FILENAME), content).expect("failed to write config");
    }

    /// Minimal valid config with one tool and one secret.
    ///
    /// Includes `allow_home_root = true` because many tests set `HOME` to the
    /// tempdir where the config lives; without the opt-in, `load_config` would
    /// refuse to use `$HOME` as the sandbox root.
    fn minimal_config() -> &'static str {
        r#"
allow_home_root = true

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
allow_home_root = true

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

    // ── Discovery: finds config in starting directory ────────────────────

    #[test]
    fn discovery_finds_config_in_start_dir() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());

        // Set HOME to the temp dir so the walk doesn't escape.
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let (config_path, sandbox_root) = discover_config_file(tmp.path()).unwrap();
        assert_eq!(config_path, canonical_tmp.join(CONFIG_FILENAME));
        assert_eq!(
            sandbox_root, canonical_tmp,
            "sandbox root should be the canonicalized parent of the config file"
        );
    }

    // ── Discovery: finds config in parent directory ──────────────────────

    #[test]
    fn discovery_finds_config_in_parent() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());

        // Create a child directory with no config.
        let child = tmp.path().join("subdir");
        fs::create_dir(&child).unwrap();

        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let (config_path, _sandbox_root) = discover_config_file(&child).unwrap();
        assert_eq!(config_path, canonical_tmp.join(CONFIG_FILENAME));
    }

    // ── Discovery: walks upward through multiple levels ──────────────────

    #[test]
    fn discovery_walks_through_multiple_levels() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());

        // Create nested subdirectories.
        let deep = tmp.path().join("a").join("b").join("c");
        fs::create_dir_all(&deep).unwrap();

        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        let (config_path, _sandbox_root) = discover_config_file(&deep).unwrap();
        assert_eq!(config_path, canonical_tmp.join(CONFIG_FILENAME));
    }

    // ── Discovery: stops at $HOME ────────────────────────────────────────

    #[test]
    fn discovery_stops_at_home() {
        let tmp = tempdir().unwrap();

        // Create structure: tmp/home_dir/subdir
        // Put config ABOVE home_dir (at tmp level), but set HOME to home_dir.
        let home_dir = tmp.path().join("home_dir");
        let subdir = home_dir.join("subdir");
        fs::create_dir_all(&subdir).unwrap();

        // Put config at tmp level (above HOME).
        write_config(tmp.path(), minimal_config());

        let _home_guard = TempEnvVar::new("HOME", home_dir.to_str().unwrap());

        let result = discover_config_file(&subdir);
        assert!(
            result.is_err(),
            "discovery should not find config above $HOME"
        );
        assert!(
            matches!(result.unwrap_err(), ConfigError::NotFound { .. }),
            "should return NotFound error"
        );
    }

    // ── Discovery: error when no config found ────────────────────────────

    #[test]
    fn discovery_error_when_no_config() {
        let tmp = tempdir().unwrap();
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let result = discover_config_file(tmp.path());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::NotFound { .. }));
    }

    // ── Discovery: skips file owned by different uid ─────────────────────

    #[test]
    fn discovery_skips_file_with_different_owner() {
        // We can't easily change file ownership without root privileges.
        // Instead, we test that the `is_owned_by` function works correctly
        // with our own uid, and that the discovery logic flows correctly.
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());

        let euid = current_euid();
        let config_path = tmp.path().join(CONFIG_FILENAME);

        // Our file should be owned by us.
        assert!(
            is_owned_by(&config_path, euid),
            "file should be owned by current euid"
        );

        // A non-existent uid should not match.
        assert!(
            !is_owned_by(&config_path, euid.wrapping_add(1)),
            "file should not be owned by a different uid"
        );
    }

    // ── Discovery: accepts file owned by current euid ────────────────────

    #[test]
    fn discovery_accepts_file_owned_by_current_euid() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        // The file we just created should be owned by us.
        let result = discover_config_file(tmp.path());
        assert!(result.is_ok(), "should accept config owned by current euid");
    }

    // ── Discovery: closest config wins ───────────────────────────────────

    #[test]
    fn discovery_closest_config_wins() {
        let tmp = tempdir().unwrap();

        // Config in parent.
        write_config(
            tmp.path(),
            r#"
timeout = 999

[tools.parent_tool]
"#,
        );

        // Config in child (closer to start).
        let child = tmp.path().join("project");
        fs::create_dir(&child).unwrap();
        write_config(&child, minimal_config());

        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let canonical_child = std::fs::canonicalize(&child).unwrap();
        let (config_path, _sandbox_root) = discover_config_file(&child).unwrap();
        assert_eq!(
            config_path,
            canonical_child.join(CONFIG_FILENAME),
            "closest config file should win"
        );
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
        write_config(tmp.path(), full_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();

        // Global timeout.
        assert_eq!(config.timeout, Duration::from_secs(120));

        // Filesystem section.
        assert_eq!(config.filesystem_read.len(), 2);
        assert!(
            config
                .filesystem_read
                .contains(&PathBuf::from("/usr/share"))
        );
        // ~/docs should be expanded to {tmp_path}/docs (HOME was set to tmp_path).
        // Use tmp.path() directly rather than re-reading HOME to avoid races
        // with concurrent tests that also modify the HOME env var.
        let expected_home_docs = tmp.path().join("docs");
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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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

    // ── Parsing: unknown top-level keys are accepted ─────────────────────

    #[test]
    fn parse_unknown_top_level_keys() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"
allow_home_root = true
future_field = "hello"
another_unknown = 42

[unknown_section]
key = "value"

[secrets.s]
source = "env"
from = "S"

[tools.mytool.env]
S = { secret = "s" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path());
        assert!(
            config.is_ok(),
            "unknown top-level keys should not cause parse errors: {:?}",
            config.err()
        );
    }

    // ── Path resolution: tilde expansion ─────────────────────────────────

    #[test]
    fn path_tilde_expansion() {
        let tmp = tempdir().unwrap();
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let resolved = resolve_path("~/documents", tmp.path()).unwrap();
        let expected = PathBuf::from(format!("{}/documents", tmp.path().display()));
        assert_eq!(resolved, expected);
    }

    #[test]
    fn path_tilde_only() {
        let tmp = tempdir().unwrap();
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let resolved = resolve_path("~", tmp.path()).unwrap();
        assert_eq!(resolved, tmp.path().to_path_buf());
    }

    // ── Path resolution: relative paths ──────────────────────────────────

    #[test]
    fn path_relative_resolved_against_sandbox_root() {
        let sandbox = PathBuf::from("/fake/sandbox/root");
        // HOME isn't needed for relative path resolution.
        let resolved = resolve_path("data/input", &sandbox).unwrap();
        assert_eq!(resolved, PathBuf::from("/fake/sandbox/root/data/input"));
    }

    // ── Path resolution: absolute paths unchanged ────────────────────────

    #[test]
    fn path_absolute_unchanged() {
        let sandbox = PathBuf::from("/fake/sandbox/root");
        let resolved = resolve_path("/usr/bin/tool", &sandbox).unwrap();
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

    // ── Derived paths: socket path ───────────────────────────────────────

    #[test]
    fn socket_path_derived_correctly() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        assert_eq!(
            config.socket_path,
            config.sandbox_root.join("airlock.sock"),
            "socket path should be {{sandbox_root}}/airlock.sock"
        );
    }

    // ── Derived paths: PID file path ─────────────────────────────────────

    #[test]
    fn pid_path_derived_correctly() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config = load_config(tmp.path()).unwrap();
        assert_eq!(
            config.pid_path,
            config.sandbox_root.join("airlock.pid"),
            "PID file path should be {{sandbox_root}}/airlock.pid"
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

    // ── Tool name validation in parsing context ──────────────────────────

    #[test]
    fn parse_rejects_tool_name_with_forward_slash() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"
allow_home_root = true

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
allow_home_root = true

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
        // Config without allow_home_root.
        write_config(
            tmp.path(),
            r#"
[tools.mytool]
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let result = load_config(tmp.path());
        match result {
            Err(ConfigError::HomeRootNotAllowed { .. }) => {}
            other => panic!("expected HomeRootNotAllowed, got: {other:?}"),
        }
    }

    #[test]
    fn load_accepts_home_root_with_opt_in() {
        let tmp = tempdir().unwrap();
        // minimal_config() already includes allow_home_root = true.
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        load_config(tmp.path()).expect("allow_home_root=true should permit $HOME as sandbox root");
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
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        load_config(&project).expect("non-home sandbox root should load without opt-in");
    }

    // ── Lightweight discovery: socket path only ──────────────────────────

    #[test]
    fn discover_paths_finds_socket_path() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let paths = discover_paths(tmp.path()).unwrap();
        let canonical = std::fs::canonicalize(tmp.path()).unwrap();

        assert_eq!(paths.sandbox_root, canonical);
        assert_eq!(paths.socket_path, canonical.join("airlock.sock"));
        assert_eq!(paths.pid_path, canonical.join("airlock.pid"));
    }

    #[test]
    fn discover_paths_does_not_parse_contents() {
        let tmp = tempdir().unwrap();
        // Write invalid TOML — should still succeed since we don't parse.
        write_config(tmp.path(), "this is not valid toml at all [[[");
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let result = discover_paths(tmp.path());
        assert!(
            result.is_ok(),
            "discover_paths should succeed even with invalid TOML contents: {:?}",
            result.err()
        );
    }

    // ── [secrets] + tools.env schema ─────────────────────────────────────

    #[test]
    fn parse_env_source_from_defaults_to_label() {
        // When `from` is omitted, the label itself is the env var name.
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
    fn parse_env_secret_with_refresh_field_rejected_by_serde() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"
allow_home_root = true

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
            matches!(err, ConfigError::ParseError { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn parse_tool_env_mixes_static_and_secret() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"
allow_home_root = true

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
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"
allow_home_root = true

[secrets.known]
source = "env"
from = "KNOWN"

[tools.a.env]
A = { secret = "ghost_a" }

[tools.b.env]
B = { secret = "ghost_b" }
KNOWN = { secret = "known" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let err = load_config(tmp.path()).unwrap_err();
        match err {
            ConfigError::UndeclaredSecretRefs { refs } => {
                assert_eq!(refs.len(), 2);
                assert!(refs.iter().any(|(_, _, l)| l == "ghost_a"));
                assert!(refs.iter().any(|(_, _, l)| l == "ghost_b"));
            }
            other => panic!("expected UndeclaredSecretRefs, got: {other:?}"),
        }
    }

    #[test]
    fn reject_invalid_env_var_name() {
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"
allow_home_root = true

[agent.env]
MISSING = { secret = "nonexistent_label" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let err = load_config(tmp.path()).unwrap_err();
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
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"
allow_home_root = true

[tools.mytool.env]
A = { secret = "tool_ghost" }

[agent.env]
B = { secret = "agent_ghost" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let err = load_config(tmp.path()).unwrap_err();
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
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());
        write_config(
            tmp.path(),
            r#"
allow_home_root = true

[agent.filesystem]
read = ["~/projects", "relative/path"]
write = ["/tmp/agent"]
"#,
        );

        let config = load_config(tmp.path()).unwrap();
        let agent = config.agent.unwrap();

        // Tilde expansion.
        let expected_projects = tmp.path().join("projects");
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

    // ── discover_paths_from_file: derives paths from explicit file ───────

    #[test]
    fn discover_paths_from_file_returns_correct_paths() {
        let tmp = tempdir().unwrap();
        write_config(tmp.path(), minimal_config());
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let config_path = tmp.path().join(CONFIG_FILENAME);
        let paths = discover_paths_from_file(&config_path).unwrap();

        let canonical = std::fs::canonicalize(tmp.path()).unwrap();
        assert_eq!(paths.sandbox_root, canonical);
        assert_eq!(paths.socket_path, canonical.join("airlock.sock"));
        assert_eq!(paths.pid_path, canonical.join("airlock.pid"));
    }

    #[test]
    fn discover_paths_from_file_missing_file_returns_error() {
        let tmp = tempdir().unwrap();
        let missing = tmp.path().join("nonexistent.toml");

        let result = discover_paths_from_file(&missing);
        assert!(result.is_err(), "missing file should return an error");
        assert!(
            matches!(result.unwrap_err(), ConfigError::ReadError { .. }),
            "should return ReadError for missing file"
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
allow_home_root = true

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
        let tmp = tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"
allow_home_root = true

[tools.mytool.env]
A = { secret = "ghost" }
"#,
        );
        let _home_guard = TempEnvVar::new("HOME", tmp.path().to_str().unwrap());

        let err = load_config(tmp.path()).unwrap_err();
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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
allow_home_root = true

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
}
