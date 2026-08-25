//! Policy resolution: constructs [`ToolPolicy`] instances from parsed config.
//!
//! This module converts a tool's config entry into a [`ToolPolicy`] compatible
//! with the existing [`SandboxBackend::build()`](crate::sandbox::SandboxBackend::build)
//! interface. It also validates that requested tool names exist in the config
//! and that the client's working directory is within the sandbox root.
//!
//! The policy module itself does not call `SandboxBackend::build()` — it just
//! produces the `ToolPolicy`. The daemon's connection handler is responsible
//! for passing the policy to the platform backend.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::config::Config;
use crate::sandbox::{AgentPolicy, ToolPolicy};

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors that can occur during policy resolution or validation.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The requested tool name does not exist in the config's `[tools.*]` section.
    #[error("unknown tool {name:?}: not defined in airlock.toml [tools] section")]
    UnknownTool {
        /// The tool name that was not found.
        name: String,
    },

    /// The client's working directory is outside the sandbox root.
    #[error(
        "working directory {cwd} is outside the sandbox root {sandbox_root}: \
         the working directory must be within the sandbox root"
    )]
    CwdOutsideSandbox {
        /// The client's working directory (canonicalized).
        cwd: PathBuf,
        /// The sandbox root (canonicalized).
        sandbox_root: PathBuf,
    },

    /// A path could not be canonicalized during CWD validation.
    #[error("failed to canonicalize path {path}: {source}")]
    CanonicalizationError {
        /// The path that could not be canonicalized.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
}

// ─── Tool existence validation ────────────────────────────────────────────────

/// Validate that a tool name exists in the config's `[tools.*]` section.
///
/// This check should happen before any policy construction or binary resolution.
///
/// # Errors
///
/// Returns [`PolicyError::UnknownTool`] if the tool name is not found.
pub fn validate_tool_exists(tool_name: &str, config: &Config) -> Result<(), PolicyError> {
    if config.tools.contains_key(tool_name) {
        Ok(())
    } else {
        Err(PolicyError::UnknownTool {
            name: tool_name.to_string(),
        })
    }
}

// ─── CWD validation ──────────────────────────────────────────────────────────

/// Validate that a working directory path is within the sandbox root.
///
/// Both the CWD and sandbox root are canonicalized (symlinks resolved) before
/// comparison. The check uses path component prefix comparison, not string
/// prefix comparison — `/project-other` is correctly rejected as not being
/// a subdirectory of `/project`.
///
/// A CWD equal to the sandbox root itself passes validation.
///
/// # Errors
///
/// Returns [`PolicyError::CwdOutsideSandbox`] if the CWD is not within the
/// sandbox root. Returns [`PolicyError::CanonicalizationError`] if either
/// path cannot be canonicalized.
pub fn validate_cwd(cwd: &Path, sandbox_root: &Path) -> Result<(), PolicyError> {
    let canonical_cwd =
        std::fs::canonicalize(cwd).map_err(|e| PolicyError::CanonicalizationError {
            path: cwd.to_path_buf(),
            source: e,
        })?;

    let canonical_root =
        std::fs::canonicalize(sandbox_root).map_err(|e| PolicyError::CanonicalizationError {
            path: sandbox_root.to_path_buf(),
            source: e,
        })?;

    // Use starts_with which does proper path component comparison:
    // PathBuf::from("/project-other").starts_with("/project") => false
    // PathBuf::from("/project/sub").starts_with("/project") => true
    // PathBuf::from("/project").starts_with("/project") => true
    if canonical_cwd.starts_with(&canonical_root) {
        Ok(())
    } else {
        Err(PolicyError::CwdOutsideSandbox {
            cwd: canonical_cwd,
            sandbox_root: canonical_root,
        })
    }
}

// ─── ToolPolicy construction ──────────────────────────────────────────────────

/// Construct a [`ToolPolicy`] for the given tool from the parsed config.
///
/// The resulting policy merges:
/// - The sandbox root into `read_write_paths` (the tool can always read/write
///   within the project directory)
/// - Global filesystem read paths from `[filesystem]` into `read_paths`
/// - Global filesystem write paths from `[filesystem]` into `read_write_paths`
/// - The tool's `extra_read` paths into `read_paths`
/// - The tool's `extra_write` paths into `read_write_paths`
///
/// All paths in the config are already fully resolved (tilde-expanded and
/// relative paths resolved against the sandbox root) by the config module.
///
/// `requires_network` is unconditionally set to `true` for all tools.
///
/// # Errors
///
/// Returns [`PolicyError::UnknownTool`] if the tool name is not found in the
/// config's `[tools.*]` section.
pub fn build_tool_policy(tool_name: &str, config: &Config) -> Result<ToolPolicy, PolicyError> {
    // Validate tool existence first.
    validate_tool_exists(tool_name, config)?;

    let tool_config = &config.tools[tool_name];

    // Build read_paths: global filesystem read + tool's extra_read.
    let mut read_paths: Vec<PathBuf> = Vec::new();
    read_paths.extend(config.filesystem_read.iter().cloned());
    read_paths.extend(tool_config.extra_read.iter().cloned());

    // Build read_write_paths: sandbox root + global filesystem write + tool's extra_write.
    let mut read_write_paths: Vec<PathBuf> = Vec::new();
    read_write_paths.push(config.sandbox_root.clone());
    read_write_paths.extend(config.filesystem_write.iter().cloned());
    read_write_paths.extend(tool_config.extra_write.iter().cloned());

    Ok(ToolPolicy {
        read_paths,
        read_write_paths,
        requires_network: true,
        binary_path: None,
    })
}

// ─── AgentPolicy construction ─────────────────────────────────────────────────

/// Construct an [`AgentPolicy`] for the agent from the parsed config and
/// auto-detected toolchain paths.
///
/// This function is pure and infallible — all validation already happened in
/// the config module.
///
/// Path assembly:
/// - **`read_paths`**: global `filesystem_read` paths + `toolchain_paths` +
///   agent-section `filesystem.read` (when `[agent]` is present).
/// - **`read_write_paths`**: `config.sandbox_root` (always) + global
///   `filesystem_write` paths + agent-section `filesystem.write` (when
///   `[agent]` is present).
/// - **`requires_network`** and **`requires_terminal`**: always `true`.
///
/// The daemon socket lives at `{sandbox_root}/airlock.sock` and is therefore
/// already covered by the `sandbox_root` rule; it does not need a separate
/// entry. On Linux (Landlock), adding a path that does not exist yet causes
/// profile construction to fail, so the socket — which is created after the
/// sandbox profile is built — must not appear in the path lists.
///
/// All paths in `config` are already fully resolved (tilde-expanded and
/// relative paths resolved against the sandbox root) by the config module.
pub fn build_agent_policy(config: &Config, toolchain_paths: &[PathBuf]) -> AgentPolicy {
    // Build read_paths: global filesystem_read + toolchain paths + agent read paths.
    let mut read_paths: Vec<PathBuf> = Vec::new();
    read_paths.extend(config.filesystem_read.iter().cloned());
    read_paths.extend(toolchain_paths.iter().cloned());
    if let Some(agent) = &config.agent {
        read_paths.extend(agent.filesystem_read.iter().cloned());
    }

    // Build read_write_paths: sandbox_root + global write + agent write.
    // The socket ({sandbox_root}/airlock.sock) is omitted here: the
    // sandbox_root rule already covers it, and the socket file does not exist
    // at profile-build time on Linux (Landlock requires all paths to be open-able).
    let mut read_write_paths: Vec<PathBuf> = Vec::new();
    read_write_paths.push(config.sandbox_root.clone());
    read_write_paths.extend(config.filesystem_write.iter().cloned());
    if let Some(agent) = &config.agent {
        read_write_paths.extend(agent.filesystem_write.iter().cloned());
    }

    AgentPolicy {
        read_paths,
        read_write_paths,
        requires_network: true,
        requires_terminal: true,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Duration;

    use tempfile::tempdir;

    use crate::config::{AgentConfig, ToolConfig};
    use std::collections::BTreeMap;

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Build a test `Config` with the given tools and filesystem paths.
    fn make_config_with_paths(
        sandbox_root: PathBuf,
        filesystem_read: Vec<PathBuf>,
        filesystem_write: Vec<PathBuf>,
        tools: Vec<(&str, Vec<PathBuf>, Vec<PathBuf>)>,
    ) -> Config {
        let mut tool_map = HashMap::new();
        for (name, extra_read, extra_write) in tools {
            tool_map.insert(
                name.to_string(),
                ToolConfig {
                    env: BTreeMap::new(),
                    extra_read,
                    extra_write,
                    timeout: None,
                    description: None,
                },
            );
        }

        Config {
            sandbox_root: sandbox_root.clone(),
            socket_path: sandbox_root.join("airlock.sock"),
            pid_path: sandbox_root.join("airlock.pid"),
            timeout: Duration::from_secs(300),
            filesystem_read,
            filesystem_write,
            secrets: HashMap::new(),
            tools: tool_map,
            agent: None,
        }
    }

    /// Build a minimal test `Config` with a single tool.
    fn make_simple_config(sandbox_root: PathBuf) -> Config {
        make_config_with_paths(
            sandbox_root,
            Vec::new(),
            Vec::new(),
            vec![("mytool", Vec::new(), Vec::new())],
        )
    }

    // ── ToolPolicy construction tests ─────────────────────────────────────

    #[test]
    fn sandbox_root_in_read_write_paths() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config = make_simple_config(sandbox_root.clone());

        let policy = build_tool_policy("mytool", &config).unwrap();
        assert!(
            policy.read_write_paths.contains(&sandbox_root),
            "read_write_paths should contain sandbox root, got: {:?}",
            policy.read_write_paths
        );
    }

    #[test]
    fn global_filesystem_read_paths_in_policy() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config = make_config_with_paths(
            sandbox_root,
            vec![PathBuf::from("/usr/share"), PathBuf::from("/usr/lib")],
            Vec::new(),
            vec![("mytool", Vec::new(), Vec::new())],
        );

        let policy = build_tool_policy("mytool", &config).unwrap();
        assert!(
            policy.read_paths.contains(&PathBuf::from("/usr/share")),
            "read_paths should contain global /usr/share"
        );
        assert!(
            policy.read_paths.contains(&PathBuf::from("/usr/lib")),
            "read_paths should contain global /usr/lib"
        );
    }

    #[test]
    fn global_filesystem_write_paths_in_policy() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config = make_config_with_paths(
            sandbox_root,
            Vec::new(),
            vec![PathBuf::from("/tmp/output")],
            vec![("mytool", Vec::new(), Vec::new())],
        );

        let policy = build_tool_policy("mytool", &config).unwrap();
        assert!(
            policy
                .read_write_paths
                .contains(&PathBuf::from("/tmp/output")),
            "read_write_paths should contain global /tmp/output"
        );
    }

    #[test]
    fn tool_extra_read_appended_to_read_paths() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config = make_config_with_paths(
            sandbox_root,
            vec![PathBuf::from("/usr/share")],
            Vec::new(),
            vec![("mytool", vec![PathBuf::from("/etc/config")], Vec::new())],
        );

        let policy = build_tool_policy("mytool", &config).unwrap();
        assert!(
            policy.read_paths.contains(&PathBuf::from("/usr/share")),
            "read_paths should contain global path"
        );
        assert!(
            policy.read_paths.contains(&PathBuf::from("/etc/config")),
            "read_paths should contain tool's extra_read path"
        );
    }

    #[test]
    fn tool_extra_write_appended_to_read_write_paths() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config = make_config_with_paths(
            sandbox_root.clone(),
            Vec::new(),
            Vec::new(),
            vec![("mytool", Vec::new(), vec![PathBuf::from("/tmp/results")])],
        );

        let policy = build_tool_policy("mytool", &config).unwrap();
        assert!(
            policy.read_write_paths.contains(&sandbox_root),
            "read_write_paths should contain sandbox root"
        );
        assert!(
            policy
                .read_write_paths
                .contains(&PathBuf::from("/tmp/results")),
            "read_write_paths should contain tool's extra_write path"
        );
    }

    #[test]
    fn requires_network_always_true() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config = make_simple_config(sandbox_root);

        let policy = build_tool_policy("mytool", &config).unwrap();
        assert!(
            policy.requires_network,
            "requires_network should always be true"
        );
    }

    #[test]
    fn all_paths_are_absolute() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();

        // Note: config module already resolves paths, so they should be absolute.
        // The policy module passes them through as-is.
        let config = make_config_with_paths(
            sandbox_root.clone(),
            vec![PathBuf::from("/usr/share")],
            vec![PathBuf::from("/tmp/output")],
            vec![(
                "mytool",
                vec![PathBuf::from("/etc/config")],
                vec![PathBuf::from("/tmp/results")],
            )],
        );

        let policy = build_tool_policy("mytool", &config).unwrap();

        for path in &policy.read_paths {
            assert!(
                path.is_absolute(),
                "read_paths should contain only absolute paths, got: {path:?}"
            );
        }
        for path in &policy.read_write_paths {
            assert!(
                path.is_absolute(),
                "read_write_paths should contain only absolute paths, got: {path:?}"
            );
        }
    }

    // ── Tool existence tests ──────────────────────────────────────────────

    #[test]
    fn existing_tool_succeeds() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config = make_simple_config(sandbox_root);

        let result = build_tool_policy("mytool", &config);
        assert!(result.is_ok(), "should succeed for existing tool");
    }

    #[test]
    fn unknown_tool_returns_error_naming_tool() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config = make_simple_config(sandbox_root);

        let result = build_tool_policy("nonexistent", &config);
        assert!(result.is_err(), "should fail for unknown tool");

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error for unknown tool"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("nonexistent"),
            "error message should name the unknown tool, got: {msg}"
        );
        assert!(
            matches!(err, PolicyError::UnknownTool { ref name } if name == "nonexistent"),
            "should be UnknownTool variant with correct name"
        );
    }

    #[test]
    fn validate_tool_exists_for_present_tool() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config = make_simple_config(sandbox_root);

        assert!(validate_tool_exists("mytool", &config).is_ok());
    }

    #[test]
    fn validate_tool_exists_for_absent_tool() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config = make_simple_config(sandbox_root);

        let result = validate_tool_exists("missing_tool", &config);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("missing_tool"));
    }

    // ── CWD validation tests ──────────────────────────────────────────────

    #[test]
    fn cwd_subdirectory_passes() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();

        // Create a subdirectory.
        let subdir = tmp.path().join("subproject");
        std::fs::create_dir(&subdir).unwrap();

        let result = validate_cwd(&subdir, &sandbox_root);
        assert!(
            result.is_ok(),
            "CWD that is a subdirectory should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn cwd_equals_sandbox_root_passes() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();

        let result = validate_cwd(&sandbox_root, &sandbox_root);
        assert!(
            result.is_ok(),
            "CWD equal to sandbox root should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn cwd_outside_sandbox_root_fails() {
        let sandbox_tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(sandbox_tmp.path()).unwrap();

        let outside_tmp = tempdir().unwrap();
        let outside_dir = std::fs::canonicalize(outside_tmp.path()).unwrap();

        let result = validate_cwd(&outside_dir, &sandbox_root);
        assert!(result.is_err(), "CWD outside sandbox root should fail");

        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("outside the sandbox root"),
            "error should describe the constraint, got: {msg}"
        );
    }

    #[test]
    fn cwd_string_prefix_not_subdirectory_rejected() {
        // Test that /project-other is NOT treated as a subdirectory of /project.
        // We use tempdir to create two directories with related names.
        let parent = tempdir().unwrap();
        let parent_path = std::fs::canonicalize(parent.path()).unwrap();

        // Create two directories: "project" and "project-other"
        let project = parent_path.join("project");
        let project_other = parent_path.join("project-other");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&project_other).unwrap();

        let result = validate_cwd(&project_other, &project);
        assert!(
            result.is_err(),
            "CWD that shares string prefix but is not a true subdirectory should be rejected"
        );
    }

    #[test]
    fn cwd_and_sandbox_root_are_canonicalized() {
        // On macOS, /tmp is a symlink to /private/tmp.
        // Test that symlinks are resolved before comparison.
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();

        // Create a subdirectory.
        let subdir = tmp.path().join("deep").join("nested");
        std::fs::create_dir_all(&subdir).unwrap();

        // Use the non-canonical path as CWD — should still pass after canonicalization.
        let result = validate_cwd(&subdir, tmp.path());
        assert!(
            result.is_ok(),
            "canonicalized CWD within canonicalized sandbox root should pass: {:?}",
            result.err()
        );

        // Verify that the error type includes canonicalized paths.
        let outside_tmp = tempdir().unwrap();
        let result = validate_cwd(outside_tmp.path(), tmp.path());
        assert!(result.is_err());

        match result.unwrap_err() {
            PolicyError::CwdOutsideSandbox {
                cwd,
                sandbox_root: root,
            } => {
                // Both paths should be canonical (absolute, no symlinks).
                assert!(
                    cwd.is_absolute(),
                    "error CWD path should be canonicalized: {cwd:?}"
                );
                assert!(
                    root.is_absolute(),
                    "error sandbox root path should be canonicalized: {root:?}"
                );
                // On macOS, canonicalization resolves /var to /private/var, etc.
                assert_eq!(
                    root, sandbox_root,
                    "sandbox root in error should match canonical form"
                );
            }
            other => panic!("expected CwdOutsideSandbox, got: {other:?}"),
        }
    }

    // ── Error type tests ──────────────────────────────────────────────────

    #[test]
    fn policy_error_is_std_error() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<PolicyError>();
    }

    #[test]
    fn policy_error_display_messages() {
        let err = PolicyError::UnknownTool {
            name: "bad_tool".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("bad_tool"));
        assert!(msg.contains("unknown tool"));

        let err = PolicyError::CwdOutsideSandbox {
            cwd: PathBuf::from("/outside"),
            sandbox_root: PathBuf::from("/project"),
        };
        let msg = err.to_string();
        assert!(msg.contains("/outside"));
        assert!(msg.contains("/project"));
    }

    // ── AgentPolicy construction tests ────────────────────────────────────

    /// Build a minimal `Config` with no tools and an optional agent config.
    fn make_config_for_agent_tests(
        sandbox_root: PathBuf,
        filesystem_read: Vec<PathBuf>,
        filesystem_write: Vec<PathBuf>,
        agent: Option<AgentConfig>,
    ) -> Config {
        Config {
            sandbox_root: sandbox_root.clone(),
            socket_path: sandbox_root.join("airlock.sock"),
            pid_path: sandbox_root.join("airlock.pid"),
            timeout: Duration::from_secs(300),
            filesystem_read,
            filesystem_write,
            secrets: HashMap::new(),
            tools: HashMap::new(),
            agent,
        }
    }

    fn minimal_agent_config() -> AgentConfig {
        AgentConfig {
            timeout: Duration::ZERO,
            passthrough_env: Vec::new(),
            env: BTreeMap::new(),
            filesystem_read: Vec::new(),
            filesystem_write: Vec::new(),
        }
    }

    #[test]
    fn build_agent_policy_global_read_paths_in_read_paths() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config = make_config_for_agent_tests(
            sandbox_root.clone(),
            vec![PathBuf::from("/usr/share"), PathBuf::from("/usr/lib")],
            Vec::new(),
            None,
        );

        let policy = build_agent_policy(&config, &[]);

        assert!(
            policy.read_paths.contains(&PathBuf::from("/usr/share")),
            "global /usr/share should be in read_paths"
        );
        assert!(
            policy.read_paths.contains(&PathBuf::from("/usr/lib")),
            "global /usr/lib should be in read_paths"
        );
    }

    #[test]
    fn build_agent_policy_agent_filesystem_read_in_read_paths() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let agent = AgentConfig {
            filesystem_read: vec![PathBuf::from("/opt/tools")],
            ..minimal_agent_config()
        };
        let config =
            make_config_for_agent_tests(sandbox_root.clone(), Vec::new(), Vec::new(), Some(agent));

        let policy = build_agent_policy(&config, &[]);

        assert!(
            policy.read_paths.contains(&PathBuf::from("/opt/tools")),
            "agent.filesystem.read should be in read_paths"
        );
    }

    #[test]
    fn build_agent_policy_toolchain_paths_in_read_paths() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config =
            make_config_for_agent_tests(sandbox_root.clone(), Vec::new(), Vec::new(), None);
        let toolchain = vec![PathBuf::from("/usr/local"), PathBuf::from("/opt/homebrew")];

        let policy = build_agent_policy(&config, &toolchain);

        assert!(
            policy.read_paths.contains(&PathBuf::from("/usr/local")),
            "auto-detected /usr/local should be in read_paths"
        );
        assert!(
            policy.read_paths.contains(&PathBuf::from("/opt/homebrew")),
            "auto-detected /opt/homebrew should be in read_paths"
        );
    }

    #[test]
    fn build_agent_policy_sandbox_root_always_in_read_write_paths() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config =
            make_config_for_agent_tests(sandbox_root.clone(), Vec::new(), Vec::new(), None);

        let policy = build_agent_policy(&config, &[]);

        assert!(
            policy.read_write_paths.contains(&sandbox_root),
            "sandbox_root should always be in read_write_paths"
        );
    }

    #[test]
    fn build_agent_policy_socket_covered_by_sandbox_root() {
        // The socket lives at {sandbox_root}/airlock.sock, which is covered by
        // the sandbox_root PathBeneath rule; it must NOT appear as a separate
        // entry (doing so would cause Landlock profile construction to fail on
        // Linux because the socket file does not exist at profile-build time).
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config =
            make_config_for_agent_tests(sandbox_root.clone(), Vec::new(), Vec::new(), None);
        let socket_path = sandbox_root.join("airlock.sock");

        let policy = build_agent_policy(&config, &[]);

        assert!(
            !policy.read_write_paths.contains(&socket_path),
            "socket_path must not be a separate entry; sandbox_root covers it"
        );
        assert!(
            policy.read_write_paths.contains(&sandbox_root),
            "sandbox_root must be present to cover the socket"
        );
    }

    #[test]
    fn build_agent_policy_agent_filesystem_write_in_read_write_paths() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let agent = AgentConfig {
            filesystem_write: vec![PathBuf::from("/tmp/agent-output")],
            ..minimal_agent_config()
        };
        let config =
            make_config_for_agent_tests(sandbox_root.clone(), Vec::new(), Vec::new(), Some(agent));

        let policy = build_agent_policy(&config, &[]);

        assert!(
            policy
                .read_write_paths
                .contains(&PathBuf::from("/tmp/agent-output")),
            "agent.filesystem.write should be in read_write_paths"
        );
    }

    #[test]
    fn build_agent_policy_no_agent_section_does_not_panic() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config =
            make_config_for_agent_tests(sandbox_root.clone(), Vec::new(), Vec::new(), None);

        // Must not panic; agent-section paths must not appear.
        let policy = build_agent_policy(&config, &[]);

        // Only sandbox_root should be in read_write_paths (socket is covered by it).
        assert_eq!(policy.read_write_paths.len(), 1);
        // No agent-section read paths.
        assert!(policy.read_paths.is_empty());
    }

    #[test]
    fn build_agent_policy_requires_network_and_terminal_always_true() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();
        let config =
            make_config_for_agent_tests(sandbox_root.clone(), Vec::new(), Vec::new(), None);

        let policy = build_agent_policy(&config, &[]);

        assert!(
            policy.requires_network,
            "requires_network should always be true"
        );
        assert!(
            policy.requires_terminal,
            "requires_terminal should always be true"
        );
    }

    // ── Full integration-style test with all path types ───────────────────

    #[test]
    fn full_policy_construction_with_all_path_types() {
        let tmp = tempdir().unwrap();
        let sandbox_root = std::fs::canonicalize(tmp.path()).unwrap();

        let config = make_config_with_paths(
            sandbox_root.clone(),
            vec![PathBuf::from("/usr/share"), PathBuf::from("/usr/lib")],
            vec![PathBuf::from("/tmp/output")],
            vec![(
                "mytool",
                vec![PathBuf::from("/etc/config")],
                vec![PathBuf::from("/tmp/results")],
            )],
        );

        let policy = build_tool_policy("mytool", &config).unwrap();

        // read_paths: global reads + tool extra_read
        assert_eq!(policy.read_paths.len(), 3);
        assert!(policy.read_paths.contains(&PathBuf::from("/usr/share")));
        assert!(policy.read_paths.contains(&PathBuf::from("/usr/lib")));
        assert!(policy.read_paths.contains(&PathBuf::from("/etc/config")));

        // read_write_paths: sandbox_root + global writes + tool extra_write
        assert_eq!(policy.read_write_paths.len(), 3);
        assert!(policy.read_write_paths.contains(&sandbox_root));
        assert!(
            policy
                .read_write_paths
                .contains(&PathBuf::from("/tmp/output"))
        );
        assert!(
            policy
                .read_write_paths
                .contains(&PathBuf::from("/tmp/results"))
        );

        // Network always enabled.
        assert!(policy.requires_network);
    }
}
