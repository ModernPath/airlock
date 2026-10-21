//! The three locations that decide what the daemon trusts and how clients
//! reach it: the trust store, the global config, and the runtime base.
//!
//! The XDG variables that locate the trust store and global config are
//! honored, which makes the environment an attack path: a committed
//! `mise.toml` or `.envrc` can redirect `XDG_STATE_HOME` once the user `cd`s
//! in. Validation here closes that off by requiring every anchor to sit
//! outside the project root and outside every sandbox write grant, after
//! canonicalizing the longest prefix that actually exists on disk.
//!
//! Callers pass the environment in as a closure rather than this module
//! reading it directly, so daemon-side code — which must never read the
//! process environment — cannot accidentally depend on this module to do
//! so, and so tests can exercise it without mutating process state.

use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::runtime_dir::RuntimeDir;

/// The trust store, global config and runtime base, resolved from the
/// environment (or its defaults) and ready for validation.
#[derive(Debug, Clone)]
pub struct Anchors {
    /// `$XDG_STATE_HOME/airlock/trust`, default `~/.local/state/airlock/trust`.
    pub trust_store: PathBuf,
    /// The XDG variable and value that produced `trust_store`, e.g.
    /// `"XDG_STATE_HOME=/x"`, when it was not the default.
    pub trust_store_source: Option<String>,
    /// `$XDG_CONFIG_HOME/airlock/airlock.toml`, default
    /// `~/.config/airlock/airlock.toml` (on macOS too).
    pub global_config: PathBuf,
    /// The XDG variable and value that produced `global_config`'s
    /// directory, when it was not the default.
    pub global_config_source: Option<String>,
    /// `$XDG_CACHE_HOME/airlock`, default `~/.cache/airlock`.
    pub tool_state_base: PathBuf,
    /// The XDG variable and value that produced `tool_state_base`, when it
    /// was not the default. Used only to name the variable in
    /// [`validate_tool_state_dir`]'s error — `tool_state_base` itself is not
    /// one of the three anchors `validate` checks.
    pub tool_state_base_source: Option<String>,
    /// The daemon's runtime directory base.
    pub runtime_base: PathBuf,
}

impl Anchors {
    /// The three anchors that must never be forgeable or redirected by a
    /// sandboxed process, each labeled for error messages. `tool_state_base`
    /// is not an anchor in this sense — it is a fresh per-tool scratch
    /// directory with no trust record of its own.
    fn named(&self) -> [(&Path, &'static str, Option<&str>); 3] {
        [
            (
                self.trust_store.as_path(),
                "trust store",
                self.trust_store_source.as_deref(),
            ),
            (
                self.global_config.as_path(),
                "global config",
                self.global_config_source.as_deref(),
            ),
            (self.runtime_base.as_path(), "runtime dir", None),
        ]
    }
}

/// Resolves the anchors from the environment. `env` is a lookup function
/// rather than `std::env::var` directly, so this is testable and so
/// daemon-side code never reads the process environment through it.
pub fn resolve(env: &dyn Fn(&str) -> Option<String>, home: &Path, runtime: &RuntimeDir) -> Anchors {
    let (state_dir, trust_store_source) = xdg_dir(env, home, "XDG_STATE_HOME", ".local/state");
    let (global_config, global_config_source) = global_config_path(env, home);
    let (cache_dir, tool_state_base_source) = xdg_dir(env, home, "XDG_CACHE_HOME", ".cache");

    Anchors {
        trust_store: state_dir.join("airlock").join("trust"),
        trust_store_source,
        global_config,
        global_config_source,
        tool_state_base: cache_dir.join("airlock"),
        tool_state_base_source,
        runtime_base: runtime.base().to_path_buf(),
    }
}

/// The global config file, `$XDG_CONFIG_HOME/airlock/airlock.toml`, and the
/// `XDG_CONFIG_HOME=...` it came from when that variable was used.
pub fn global_config_path(
    env: &dyn Fn(&str) -> Option<String>,
    home: &Path,
) -> (PathBuf, Option<String>) {
    let (config_dir, source) = xdg_dir(env, home, "XDG_CONFIG_HOME", ".config");
    (config_dir.join("airlock").join("airlock.toml"), source)
}

/// Resolves one XDG base directory variable, falling back to
/// `home/default_rel` when it is unset or empty. Returns the variable's
/// `NAME=value` form for error messages when it was actually used.
fn xdg_dir(
    env: &dyn Fn(&str) -> Option<String>,
    home: &Path,
    var: &str,
    default_rel: &str,
) -> (PathBuf, Option<String>) {
    match env(var) {
        Some(value) if !value.is_empty() => (PathBuf::from(&value), Some(format!("{var}={value}"))),
        _ => (home.join(default_rel), None),
    }
}

/// Validates the three anchors: ownership and mode, outside the project
/// root, and outside every sandbox write grant. Creates the trust store
/// directory (mode 0700) if it does not exist yet.
pub fn validate(
    anchors: &Anchors,
    project_root: Option<&Path>,
    write_grants: &[PathBuf],
) -> Result<(), AnchorError> {
    create_trust_store_dir(&anchors.trust_store)?;

    check_strict_dir(
        &anchors.trust_store,
        "trust store",
        anchors.trust_store_source.as_deref(),
    )?;
    check_strict_dir(&anchors.runtime_base, "runtime dir", None)?;
    check_global_config(
        &anchors.global_config,
        anchors.global_config_source.as_deref(),
    )?;

    for (path, label, source) in anchors.named() {
        check_outside_root(path, label, source, project_root)?;
        check_not_granted(path, label, write_grants)?;
    }

    Ok(())
}

/// Validates one tool's `{tool_state}` directory (design doc, "Tool state
/// outside the project"): like the three true anchors, it is refused if it
/// resolves inside the project root, so a redirected `XDG_CACHE_HOME`
/// cannot move it there, and it must not overlap an anchor either — that
/// would hand a sandboxed tool write access to Airlock's own files.
/// `tool_state_base` itself is not one of [`Anchors::named`]'s three
/// anchors, so this is a separate check from [`validate`].
pub fn validate_tool_state_dir(
    anchors: &Anchors,
    project_root: &Path,
    dir: &Path,
) -> Result<(), AnchorError> {
    check_outside_root(
        dir,
        "tool state",
        anchors.tool_state_base_source.as_deref(),
        Some(project_root),
    )?;
    for (anchor_path, anchor_label, _source) in anchors.named() {
        if overlaps(dir, anchor_path) {
            return Err(AnchorError::ToolStateOverlapsAnchor {
                path: dir.to_path_buf(),
                anchor: anchor_label.to_string(),
                anchor_path: anchor_path.to_path_buf(),
            });
        }
    }
    Ok(())
}

/// Checks a config's write grants against the anchors, in the direction a
/// config error takes: a grant that covers an anchor is refused at load
/// time, before the sandbox that would use it ever starts.
pub fn check_grants_against_anchors(
    anchors: &Anchors,
    grants: &[Grant<'_>],
) -> Result<(), AnchorError> {
    for grant in grants {
        for (anchor_path, anchor_label, _source) in anchors.named() {
            if !overlaps(grant.path, anchor_path) {
                continue;
            }
            if anchor_label == "runtime dir"
                && cfg!(target_os = "macos")
                && is_strict_ancestor(grant.path, anchor_path)
            {
                // The macOS $TMPDIR exception: the Seatbelt baseline grants
                // read-write to all of $TMPDIR, and the runtime base
                // normally sits inside it. The daemon carves the base back
                // out with a trailing deny rule (see sandbox.rs), so a
                // grant that merely contains the base, without reaching
                // inside it, is not a real path to the anchor.
                continue;
            }
            return Err(AnchorError::Covered {
                file: grant.file.to_string(),
                path: grant.path.to_path_buf(),
                anchor: anchor_label.to_string(),
            });
        }
    }
    Ok(())
}

/// One sandbox write grant from a loaded config, with enough context to
/// name where it came from in an error message.
pub struct Grant<'a> {
    /// The file that declared this grant, e.g. `"airlock.toml"`.
    pub file: &'a str,
    pub path: &'a Path,
}

fn check_strict_dir(
    path: &Path,
    label: &'static str,
    source: Option<&str>,
) -> Result<(), AnchorError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| AnchorError::Missing {
        label: label.to_string(),
        path: path.to_path_buf(),
        source: e,
    })?;

    if meta.file_type().is_symlink() {
        return Err(AnchorError::IsSymlink {
            label: label.to_string(),
            path: path.to_path_buf(),
        });
    }
    if !meta.is_dir() {
        return Err(AnchorError::NotADirectory {
            label: label.to_string(),
            path: path.to_path_buf(),
        });
    }

    check_owned_by_euid(path, &meta, label, source)?;

    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(AnchorError::BadMode {
            label: label.to_string(),
            path: path.to_path_buf(),
            mode,
            xdg_source: source.map(str::to_string),
        });
    }

    Ok(())
}

/// Checks the global config file and its directory, only when they exist —
/// an absent global config is not an error.
fn check_global_config(path: &Path, source: Option<&str>) -> Result<(), AnchorError> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        check_owned_by_euid(path, &meta, "global config", source)?;
        check_not_group_or_world_writable(path, &meta, "global config", source)?;
    }
    if let Some(dir) = path.parent()
        && let Ok(meta) = std::fs::symlink_metadata(dir)
    {
        check_owned_by_euid(dir, &meta, "global config directory", source)?;
        check_not_group_or_world_writable(dir, &meta, "global config directory", source)?;
    }
    Ok(())
}

fn check_owned_by_euid(
    path: &Path,
    meta: &std::fs::Metadata,
    label: &str,
    source: Option<&str>,
) -> Result<(), AnchorError> {
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(AnchorError::WrongOwner {
            label: label.to_string(),
            path: path.to_path_buf(),
            owner: meta.uid(),
            euid,
            xdg_source: source.map(str::to_string),
        });
    }
    Ok(())
}

fn check_not_group_or_world_writable(
    path: &Path,
    meta: &std::fs::Metadata,
    label: &str,
    source: Option<&str>,
) -> Result<(), AnchorError> {
    let mode = meta.mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(AnchorError::GroupOrWorldWritable {
            label: label.to_string(),
            path: path.to_path_buf(),
            mode,
            xdg_source: source.map(str::to_string),
        });
    }
    Ok(())
}

fn check_outside_root(
    path: &Path,
    label: &'static str,
    source: Option<&str>,
    project_root: Option<&Path>,
) -> Result<(), AnchorError> {
    let Some(root) = project_root else {
        return Ok(());
    };
    if is_inside(path, root) {
        return Err(AnchorError::InsideRoot {
            label: label.to_string(),
            path: path.to_path_buf(),
            root: root.to_path_buf(),
            xdg_source: source.map(str::to_string),
        });
    }
    Ok(())
}

fn check_not_granted(
    path: &Path,
    label: &'static str,
    write_grants: &[PathBuf],
) -> Result<(), AnchorError> {
    for grant in write_grants {
        if !overlaps(path, grant) {
            continue;
        }
        if label == "runtime dir" && cfg!(target_os = "macos") && is_strict_ancestor(grant, path) {
            continue;
        }
        return Err(AnchorError::Covered {
            file: "sandbox configuration".to_string(),
            path: grant.clone(),
            anchor: label.to_string(),
        });
    }
    Ok(())
}

/// Creates the trust store directory if nothing is at that path yet. What
/// is already there, symlink or not, is left for validation to judge.
pub fn create_trust_store_dir(dir: &Path) -> Result<(), AnchorError> {
    if std::fs::symlink_metadata(dir).is_ok() {
        return Ok(());
    }
    create_private_dir_all(dir).map_err(|source| AnchorError::Create {
        path: dir.to_path_buf(),
        source,
    })
}

/// Creates `dir` and any missing parents, each mode 0700 from the moment it
/// exists rather than created and narrowed afterwards. An existing
/// directory is left as it is.
pub(crate) fn create_private_dir_all(dir: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// True when `a` and `b` overlap: one is equal to, or inside, the other.
/// Canonicalizes the longest prefix of each that actually exists on disk,
/// so a not-yet-created path still compares correctly against a real one.
pub fn overlaps(a: &Path, b: &Path) -> bool {
    let ca = canonicalize_longest_prefix(a);
    let cb = canonicalize_longest_prefix(b);
    ca.starts_with(&cb) || cb.starts_with(&ca)
}

/// True when `path` is equal to, or inside, `dir`.
pub fn is_inside(path: &Path, dir: &Path) -> bool {
    canonicalize_longest_prefix(path).starts_with(canonicalize_longest_prefix(dir))
}

/// True when `ancestor` properly contains `path` (not equal to it).
fn is_strict_ancestor(ancestor: &Path, path: &Path) -> bool {
    let ca = canonicalize_longest_prefix(ancestor);
    let cp = canonicalize_longest_prefix(path);
    cp != ca && cp.starts_with(&ca)
}

/// Canonicalizes the longest prefix of `path` that exists on disk (resolving
/// symlinks in it), then re-appends the remaining, not-yet-existing
/// components unchanged.
fn canonicalize_longest_prefix(path: &Path) -> PathBuf {
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    let mut current = path.to_path_buf();

    loop {
        if let Ok(canonical) = std::fs::canonicalize(&current) {
            let mut result = canonical;
            for component in suffix.iter().rev() {
                result.push(component);
            }
            return result;
        }

        match (
            current.file_name().map(|n| n.to_os_string()),
            current.parent(),
        ) {
            (Some(name), Some(parent)) if !parent.as_os_str().is_empty() => {
                suffix.push(name);
                current = parent.to_path_buf();
            }
            _ => {
                // Nothing on the path exists, not even its root. Return the
                // original, unresolved — there is nothing left to canonicalize.
                return path.to_path_buf();
            }
        }
    }
}

/// Errors validating or creating the anchors.
#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("could not create {}: {source}", path.display())]
    Create {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("{label} {} does not exist: {source}", path.display())]
    Missing {
        label: String,
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("{label} {} is a symlink", path.display())]
    IsSymlink { label: String, path: PathBuf },

    #[error("{label} {} is not a directory", path.display())]
    NotADirectory { label: String, path: PathBuf },

    #[error(
        "{label} {} is owned by uid {owner}, not you ({euid}){}",
        path.display(),
        xdg_source.as_deref().map(|s| format!(" (from {s})")).unwrap_or_default()
    )]
    WrongOwner {
        label: String,
        path: PathBuf,
        owner: u32,
        euid: u32,
        xdg_source: Option<String>,
    },

    #[error(
        "{label} {} has mode {mode:03o}, expected 0700{}",
        path.display(),
        xdg_source.as_deref().map(|s| format!(" (from {s})")).unwrap_or_default()
    )]
    BadMode {
        label: String,
        path: PathBuf,
        mode: u32,
        xdg_source: Option<String>,
    },

    #[error(
        "{label} {} has mode {mode:03o}, which is writable by group or other{}",
        path.display(),
        xdg_source.as_deref().map(|s| format!(" (from {s})")).unwrap_or_default()
    )]
    GroupOrWorldWritable {
        label: String,
        path: PathBuf,
        mode: u32,
        xdg_source: Option<String>,
    },

    #[error(
        "{label} {} is inside the project root {}{}; refusing to use it",
        path.display(),
        root.display(),
        xdg_source.as_deref().map(|s| format!(" (from {s})")).unwrap_or_default()
    )]
    InsideRoot {
        label: String,
        path: PathBuf,
        root: PathBuf,
        xdg_source: Option<String>,
    },

    #[error(
        "{file}: filesystem.write \"{}\" covers {anchor}; Airlock's own files cannot be writable from a sandbox",
        path.display()
    )]
    Covered {
        file: String,
        path: PathBuf,
        anchor: String,
    },

    #[error(
        "tool state {} overlaps the {anchor} {}; refusing to use it",
        path.display(),
        anchor_path.display()
    )]
    ToolStateOverlapsAnchor {
        path: PathBuf,
        anchor: String,
        anchor_path: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn global_config_path_treats_an_empty_xdg_config_home_as_unset() {
        let home = Path::new("/home/u");
        let empty = |k: &str| (k == "XDG_CONFIG_HOME").then(String::new);
        assert_eq!(
            global_config_path(&empty, home),
            (PathBuf::from("/home/u/.config/airlock/airlock.toml"), None)
        );
    }

    fn fixed_runtime(base: PathBuf) -> RuntimeDir {
        RuntimeDir::at(base)
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    // ─── resolve ────────────────────────────────────────────────────────

    #[test]
    fn resolve_defaults_under_home_when_env_unset() {
        let home = PathBuf::from("/home/u");
        let runtime = fixed_runtime(PathBuf::from("/run/u"));
        let anchors = resolve(&no_env, &home, &runtime);

        assert_eq!(
            anchors.trust_store,
            PathBuf::from("/home/u/.local/state/airlock/trust")
        );
        assert_eq!(anchors.trust_store_source, None);
        assert_eq!(
            anchors.global_config,
            PathBuf::from("/home/u/.config/airlock/airlock.toml")
        );
        assert_eq!(anchors.global_config_source, None);
        assert_eq!(
            anchors.tool_state_base,
            PathBuf::from("/home/u/.cache/airlock")
        );
        assert_eq!(anchors.runtime_base, PathBuf::from("/run/u"));
    }

    #[test]
    fn resolve_honors_xdg_vars_and_records_source() {
        let home = PathBuf::from("/home/u");
        let runtime = fixed_runtime(PathBuf::from("/run/u"));
        let env = |name: &str| match name {
            "XDG_STATE_HOME" => Some("/custom/state".to_string()),
            "XDG_CONFIG_HOME" => Some("/custom/config".to_string()),
            "XDG_CACHE_HOME" => Some("/custom/cache".to_string()),
            _ => None,
        };
        let anchors = resolve(&env, &home, &runtime);

        assert_eq!(
            anchors.trust_store,
            PathBuf::from("/custom/state/airlock/trust")
        );
        assert_eq!(
            anchors.trust_store_source.as_deref(),
            Some("XDG_STATE_HOME=/custom/state")
        );
        assert_eq!(
            anchors.global_config,
            PathBuf::from("/custom/config/airlock/airlock.toml")
        );
        assert_eq!(
            anchors.global_config_source.as_deref(),
            Some("XDG_CONFIG_HOME=/custom/config")
        );
        assert_eq!(
            anchors.tool_state_base,
            PathBuf::from("/custom/cache/airlock")
        );
    }

    #[test]
    fn resolve_treats_empty_env_var_as_unset() {
        let home = PathBuf::from("/home/u");
        let runtime = fixed_runtime(PathBuf::from("/run/u"));
        let env = |name: &str| {
            if name == "XDG_STATE_HOME" {
                Some(String::new())
            } else {
                None
            }
        };
        let anchors = resolve(&env, &home, &runtime);

        assert_eq!(
            anchors.trust_store,
            PathBuf::from("/home/u/.local/state/airlock/trust")
        );
        assert_eq!(anchors.trust_store_source, None);
    }

    // ─── overlaps / is_inside ───────────────────────────────────────────

    #[test]
    fn overlaps_true_for_equal_paths() {
        let dir = tempdir();
        assert!(overlaps(dir.path(), dir.path()));
    }

    #[test]
    fn overlaps_true_when_one_is_inside_the_other() {
        let dir = tempdir();
        let child = dir.path().join("a").join("b");
        std::fs::create_dir_all(&child).unwrap();
        assert!(overlaps(dir.path(), &child));
        assert!(overlaps(&child, dir.path()));
    }

    #[test]
    fn overlaps_false_for_disjoint_siblings() {
        let dir = tempdir();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        assert!(!overlaps(&a, &b));
    }

    #[test]
    fn overlaps_handles_not_yet_created_descendant() {
        let dir = tempdir();
        let not_yet = dir.path().join("exists").join("not-yet-created");
        std::fs::create_dir_all(dir.path().join("exists")).unwrap();
        assert!(overlaps(dir.path(), &not_yet));
    }

    #[test]
    fn is_inside_resolves_symlinked_prefix() {
        let dir = tempdir();
        let real = dir.path().join("real");
        std::fs::create_dir_all(real.join("sub")).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Through the symlink, "link/sub" and "real/sub" are the same place.
        assert!(is_inside(&link.join("sub"), &real));
    }

    // ─── create_trust_store_dir ─────────────────────────────────────────

    #[test]
    fn create_trust_store_dir_creates_it_and_its_parents_mode_0700() {
        let dir = tempdir();
        let trust = dir.path().join("state").join("airlock").join("trust");

        create_trust_store_dir(&trust).unwrap();

        for created in [&trust, trust.parent().unwrap()] {
            let mode = std::fs::metadata(created).unwrap().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", created.display());
        }
    }

    #[test]
    fn create_trust_store_dir_is_idempotent() {
        let dir = tempdir();
        let trust = dir.path().join("trust");
        create_trust_store_dir(&trust).unwrap();
        create_trust_store_dir(&trust).unwrap();
    }

    // ─── validate ───────────────────────────────────────────────────────

    struct Fixture {
        _dir: tempfile::TempDir,
        anchors: Anchors,
    }

    fn fixture() -> Fixture {
        let dir = tempdir();
        let trust_store = dir.path().join("state/airlock/trust");
        std::fs::create_dir_all(trust_store.parent().unwrap()).unwrap();
        let global_config = dir.path().join("config/airlock/airlock.toml");
        std::fs::create_dir_all(global_config.parent().unwrap()).unwrap();
        // Lives under its own subtree, disjoint from trust_store/global_config,
        // so a grant that is a strict ancestor of just the runtime base (the
        // macOS $TMPDIR exception) does not also cover the other anchors.
        let runtime_base = dir.path().join("rt-area").join("run");
        std::fs::create_dir_all(&runtime_base).unwrap();
        std::fs::set_permissions(&runtime_base, std::fs::Permissions::from_mode(0o700)).unwrap();

        let anchors = Anchors {
            trust_store,
            trust_store_source: None,
            global_config,
            global_config_source: None,
            tool_state_base: dir.path().join("cache/airlock"),
            tool_state_base_source: None,
            runtime_base,
        };
        Fixture { _dir: dir, anchors }
    }

    #[test]
    fn validate_creates_missing_trust_store_and_succeeds() {
        let f = fixture();
        assert!(!f.anchors.trust_store.exists());
        validate(&f.anchors, None, &[]).expect("validate");
        assert!(f.anchors.trust_store.is_dir());
    }

    #[test]
    fn validate_rejects_group_writable_trust_store() {
        let f = fixture();
        std::fs::create_dir_all(&f.anchors.trust_store).unwrap();
        std::fs::set_permissions(
            &f.anchors.trust_store,
            std::fs::Permissions::from_mode(0o750),
        )
        .unwrap();

        assert!(matches!(
            validate(&f.anchors, None, &[]),
            Err(AnchorError::BadMode { .. })
        ));
    }

    #[test]
    fn validate_rejects_trust_store_symlink() {
        let f = fixture();
        let real = f.anchors.trust_store.parent().unwrap().join("real-trust");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&real)
            .unwrap();
        std::os::unix::fs::symlink(&real, &f.anchors.trust_store).unwrap();

        assert!(matches!(
            validate(&f.anchors, None, &[]),
            Err(AnchorError::IsSymlink { .. })
        ));
    }

    #[test]
    fn validate_accepts_global_config_absent() {
        let f = fixture();
        assert!(!f.anchors.global_config.exists());
        validate(&f.anchors, None, &[]).expect("absent global config is fine");
    }

    #[test]
    fn validate_rejects_group_writable_global_config() {
        let f = fixture();
        std::fs::write(&f.anchors.global_config, b"").unwrap();
        std::fs::set_permissions(
            &f.anchors.global_config,
            std::fs::Permissions::from_mode(0o664),
        )
        .unwrap();

        assert!(matches!(
            validate(&f.anchors, None, &[]),
            Err(AnchorError::GroupOrWorldWritable { .. })
        ));
    }

    #[test]
    fn validate_accepts_normal_mode_global_config() {
        let f = fixture();
        std::fs::write(&f.anchors.global_config, b"").unwrap();
        std::fs::set_permissions(
            &f.anchors.global_config,
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        validate(&f.anchors, None, &[]).expect("0644 global config is fine");
    }

    #[test]
    fn validate_rejects_anchor_inside_project_root() {
        let f = fixture();
        let root = f.anchors.trust_store.parent().unwrap().parent().unwrap();

        assert!(matches!(
            validate(&f.anchors, Some(root), &[]),
            Err(AnchorError::InsideRoot { .. })
        ));
    }

    #[test]
    fn validate_rejects_write_grant_covering_runtime_base() {
        let f = fixture();
        let grant = f.anchors.runtime_base.clone();

        assert!(matches!(
            validate(&f.anchors, None, &[grant]),
            Err(AnchorError::Covered { .. })
        ));
    }

    #[test]
    fn validate_rejects_write_grant_inside_runtime_base() {
        let f = fixture();
        let grant = f.anchors.runtime_base.join("inside");

        assert!(matches!(
            validate(&f.anchors, None, &[grant]),
            Err(AnchorError::Covered { .. })
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn validate_allows_strict_ancestor_grant_of_runtime_base_on_macos() {
        let f = fixture();
        let grant = f.anchors.runtime_base.parent().unwrap().to_path_buf();

        validate(&f.anchors, None, &[grant]).expect("macOS $TMPDIR ancestor exception");
    }

    #[test]
    fn validate_rejects_grant_covering_unrelated_anchor_without_exception() {
        let f = fixture();
        // The ancestor exception is specific to the runtime base; a grant
        // that is a strict ancestor of the trust store is always refused,
        // on every platform.
        let grant = f.anchors.trust_store.parent().unwrap().to_path_buf();

        assert!(matches!(
            validate(&f.anchors, None, &[grant]),
            Err(AnchorError::Covered { .. })
        ));
    }

    // ─── validate_tool_state_dir ────────────────────────────────────────

    #[test]
    fn validate_tool_state_dir_accepts_dir_outside_everything() {
        let f = fixture();
        let root = f.anchors.trust_store.parent().unwrap().parent().unwrap();
        let dir = f.anchors.tool_state_base.join("proj123").join("gh");

        validate_tool_state_dir(&f.anchors, root, &dir).expect("disjoint tool state dir");
    }

    #[test]
    fn validate_tool_state_dir_rejects_dir_inside_project_root() {
        let f = fixture();
        let root = f.anchors.trust_store.parent().unwrap().parent().unwrap();
        // A redirected XDG_CACHE_HOME moving {tool_state} into the project.
        let dir = root.join(".cache/airlock/proj123/gh");

        let err = validate_tool_state_dir(&f.anchors, root, &dir).unwrap_err();
        assert!(matches!(err, AnchorError::InsideRoot { .. }));
        assert!(err.to_string().contains("tool state"));
        assert!(err.to_string().contains("is inside the project root"));
    }

    #[test]
    fn validate_tool_state_dir_rejects_overlap_with_an_anchor() {
        let f = fixture();
        let root = f.anchors.trust_store.parent().unwrap().parent().unwrap();
        let dir = f.anchors.runtime_base.join("gh");

        let err = validate_tool_state_dir(&f.anchors, root, &dir).unwrap_err();
        assert!(matches!(err, AnchorError::ToolStateOverlapsAnchor { .. }));
        assert!(err.to_string().contains("overlaps the runtime dir"));
    }

    // ─── check_grants_against_anchors ──────────────────────────────────

    #[test]
    fn check_grants_against_anchors_reports_file_and_anchor() {
        let f = fixture();
        std::fs::create_dir_all(&f.anchors.trust_store).unwrap();
        let grants = [Grant {
            file: "airlock.toml",
            path: &f.anchors.trust_store,
        }];

        let err = check_grants_against_anchors(&f.anchors, &grants).unwrap_err();
        let message = err.to_string();
        assert!(message.starts_with("airlock.toml: filesystem.write \""));
        assert!(message.contains("covers trust store"));
        assert!(message.ends_with("Airlock's own files cannot be writable from a sandbox"));
    }

    #[test]
    fn check_grants_against_anchors_allows_disjoint_grant() {
        let f = fixture();
        let elsewhere = f.anchors.trust_store.parent().unwrap().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let grants = [Grant {
            file: "airlock.toml",
            path: &elsewhere,
        }];

        check_grants_against_anchors(&f.anchors, &grants).expect("disjoint grant is fine");
    }
}
