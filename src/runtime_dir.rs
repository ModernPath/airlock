//! The daemon's per-user runtime directory: socket, PID file, admin token
//! and proxy CA certificates.
//!
//! The base is never taken from `TMPDIR` or `XDG_RUNTIME_DIR` — both vary
//! between shells of the same user (Nix shells, tmux, `sudo -u`, containers),
//! which would let two shells disagree about where the daemon lives. macOS
//! uses `confstr(_CS_DARWIN_USER_TEMP_DIR)`; Linux uses `/run/user/<uid>`
//! when the system has set it up correctly, falling back to a predictable
//! `/tmp` path otherwise.

use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use thiserror::Error;

const SOCKET_FILENAME: &str = "airlock.sock";
const PID_FILENAME: &str = "airlock.pid";
const ADMIN_TOKEN_FILENAME: &str = "admin.token";
const CA_DIRNAME: &str = "ca";

/// Debug-only escape hatch for integration tests, which cannot rely on a
/// fixed, real per-user runtime directory across machines. Release builds
/// never read the environment for the runtime base.
#[cfg(debug_assertions)]
const TEST_OVERRIDE_VAR: &str = "AIRLOCK_TEST_RUNTIME_DIR";

/// Maximum length of a `sun_path` on this platform, including the
/// terminating NUL `bind(2)` requires `sockaddr_un` to hold.
#[cfg(target_os = "macos")]
const SUN_PATH_CAPACITY: usize = 104;
#[cfg(target_os = "linux")]
const SUN_PATH_CAPACITY: usize = 108;

/// The daemon's per-user runtime directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDir {
    base: PathBuf,
}

impl RuntimeDir {
    /// Locates the runtime base for this platform.
    ///
    /// Never reads `TMPDIR` or `XDG_RUNTIME_DIR`. Under `cfg(debug_assertions)`
    /// only, `AIRLOCK_TEST_RUNTIME_DIR` (an absolute path) replaces the base
    /// outright, for integration tests that need a predictable location.
    pub fn locate() -> Result<Self, RuntimeDirError> {
        #[cfg(debug_assertions)]
        if let Some(value) = std::env::var_os(TEST_OVERRIDE_VAR) {
            let base = PathBuf::from(value);
            if !base.is_absolute() {
                return Err(RuntimeDirError::TestOverrideNotAbsolute { path: base });
            }
            return Ok(Self { base });
        }

        Self::locate_platform()
    }

    #[cfg(target_os = "macos")]
    fn locate_platform() -> Result<Self, RuntimeDirError> {
        let raw = darwin_user_temp_dir()?;
        let canonical = std::fs::canonicalize(&raw)
            .map_err(|source| RuntimeDirError::Canonicalize { path: raw, source })?;
        Ok(Self {
            base: canonical.join("airlock"),
        })
    }

    #[cfg(target_os = "linux")]
    fn locate_platform() -> Result<Self, RuntimeDirError> {
        let uid = unsafe { libc::geteuid() };
        let run_user = PathBuf::from(format!("/run/user/{uid}"));
        if run_user_dir_usable(&run_user, uid) {
            Ok(Self {
                base: run_user.join("airlock"),
            })
        } else {
            Ok(Self {
                base: PathBuf::from(format!("/tmp/airlock-{uid}")),
            })
        }
    }

    /// Builds a `RuntimeDir` directly from a base path. For tests, and for
    /// the debug-only test override.
    pub fn at(base: PathBuf) -> Self {
        Self { base }
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    /// Creates `<base>` and `<base>/ca` with mode 0700 if they do not exist,
    /// then validates both, then checks that the socket path fits in a
    /// `sockaddr_un`.
    pub fn create_and_validate(&self) -> Result<(), RuntimeDirError> {
        ensure_dir_0700(&self.base)?;
        self.validate()?;

        let ca = self.ca_dir();
        ensure_dir_0700(&ca)?;
        validate_dir(&ca, "runtime CA directory")?;

        self.check_socket_path_length()
    }

    /// Validates `<base>`: it must be a directory, not a symlink, owned by
    /// the effective uid, and restricted to the owner (`mode & 0o077 == 0`).
    pub fn validate(&self) -> Result<(), RuntimeDirError> {
        validate_dir(&self.base, "runtime dir")
    }

    fn check_socket_path_length(&self) -> Result<(), RuntimeDirError> {
        let path = self.socket_path();
        // sockaddr_un needs room for a trailing NUL after the path bytes.
        let len = path.as_os_str().as_bytes().len();
        if len >= SUN_PATH_CAPACITY {
            return Err(RuntimeDirError::SocketPathTooLong {
                path,
                len,
                max: SUN_PATH_CAPACITY - 1,
            });
        }
        Ok(())
    }

    pub fn socket_path(&self) -> PathBuf {
        self.base.join(SOCKET_FILENAME)
    }

    pub fn pid_path(&self) -> PathBuf {
        self.base.join(PID_FILENAME)
    }

    pub fn admin_token_path(&self) -> PathBuf {
        self.base.join(ADMIN_TOKEN_FILENAME)
    }

    pub fn ca_dir(&self) -> PathBuf {
        self.base.join(CA_DIRNAME)
    }

    pub fn ca_path(&self, session_id: &str) -> PathBuf {
        self.ca_dir().join(format!("{session_id}.pem"))
    }

    pub fn addr(&self) -> String {
        format!("unix://{}", self.socket_path().display())
    }
}

/// Parses a daemon address. Only `unix://` addresses are accepted; the
/// runtime directory is never discovered from a network address.
pub fn parse_addr(addr: &str) -> Result<PathBuf, RuntimeDirError> {
    addr.strip_prefix("unix://")
        .map(PathBuf::from)
        .ok_or_else(|| RuntimeDirError::UnsupportedAddr {
            addr: addr.to_string(),
        })
}

#[cfg(target_os = "macos")]
fn darwin_user_temp_dir() -> Result<PathBuf, RuntimeDirError> {
    let mut len = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, std::ptr::null_mut(), 0) };
    if len == 0 {
        return Err(RuntimeDirError::Confstr {
            source: io::Error::last_os_error(),
        });
    }

    let mut buf = vec![0u8; len];
    len = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    if len == 0 || len > buf.len() {
        return Err(RuntimeDirError::Confstr {
            source: io::Error::last_os_error(),
        });
    }

    // confstr's returned length includes the trailing NUL.
    buf.truncate(len - 1);
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(&buf)))
}

#[cfg(target_os = "linux")]
fn run_user_dir_usable(path: &Path, uid: u32) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.is_dir() && meta.uid() == uid && meta.mode() & 0o777 == 0o700,
        Err(_) => false,
    }
}

fn ensure_dir_0700(path: &Path) -> Result<(), RuntimeDirError> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(source) => Err(RuntimeDirError::Create {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn validate_dir(path: &Path, label: &str) -> Result<(), RuntimeDirError> {
    let meta = std::fs::symlink_metadata(path).map_err(|source| RuntimeDirError::Missing {
        label: label.to_string(),
        path: path.to_path_buf(),
        source,
    })?;

    if meta.file_type().is_symlink() {
        return Err(RuntimeDirError::IsSymlink {
            label: label.to_string(),
            path: path.to_path_buf(),
        });
    }
    if !meta.is_dir() {
        return Err(RuntimeDirError::NotADirectory {
            label: label.to_string(),
            path: path.to_path_buf(),
        });
    }

    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(RuntimeDirError::WrongOwner {
            label: label.to_string(),
            path: path.to_path_buf(),
            owner: meta.uid(),
            euid,
        });
    }

    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(RuntimeDirError::BadMode {
            label: label.to_string(),
            path: path.to_path_buf(),
            mode,
        });
    }

    Ok(())
}

/// Errors from locating, creating or validating the runtime directory.
#[derive(Debug, Error)]
pub enum RuntimeDirError {
    #[cfg(target_os = "macos")]
    #[error("could not determine the per-user temp directory (confstr failed): {source}")]
    Confstr { source: io::Error },

    #[cfg(target_os = "macos")]
    #[error("could not resolve the per-user temp directory {}: {source}", path.display())]
    Canonicalize { path: PathBuf, source: io::Error },

    #[error("could not create runtime dir {}: {source}", path.display())]
    Create { path: PathBuf, source: io::Error },

    #[error("{label} {} does not exist: {source}", path.display())]
    Missing {
        label: String,
        path: PathBuf,
        source: io::Error,
    },

    #[error("{label} {} is a symlink", path.display())]
    IsSymlink { label: String, path: PathBuf },

    #[error("{label} {} is not a directory", path.display())]
    NotADirectory { label: String, path: PathBuf },

    #[error("{label} {} is owned by uid {owner}, not you ({euid})", path.display())]
    WrongOwner {
        label: String,
        path: PathBuf,
        owner: u32,
        euid: u32,
    },

    #[error("{label} {} has mode {mode:03o}, expected 0700", path.display())]
    BadMode {
        label: String,
        path: PathBuf,
        mode: u32,
    },

    #[error(
        "runtime socket path {} is {len} bytes, which exceeds the {max}-byte limit for a Unix socket path on this platform",
        path.display()
    )]
    SocketPathTooLong {
        path: PathBuf,
        len: usize,
        max: usize,
    },

    #[error("unsupported address {addr:?}: only unix:// addresses are accepted")]
    UnsupportedAddr { addr: String },

    #[cfg(debug_assertions)]
    #[error("AIRLOCK_TEST_RUNTIME_DIR must be an absolute path, got {}", path.display())]
    TestOverrideNotAbsolute { path: PathBuf },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ENV_MUTEX;
    use std::os::unix::fs::symlink;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn socket_pid_admin_ca_paths_join_base() {
        let rt = RuntimeDir::at(PathBuf::from("/base"));
        assert_eq!(rt.socket_path(), PathBuf::from("/base/airlock.sock"));
        assert_eq!(rt.pid_path(), PathBuf::from("/base/airlock.pid"));
        assert_eq!(rt.admin_token_path(), PathBuf::from("/base/admin.token"));
        assert_eq!(rt.ca_dir(), PathBuf::from("/base/ca"));
        assert_eq!(rt.ca_path("abc123"), PathBuf::from("/base/ca/abc123.pem"));
    }

    #[test]
    fn addr_is_unix_scheme_plus_socket_path() {
        let rt = RuntimeDir::at(PathBuf::from("/base"));
        assert_eq!(rt.addr(), "unix:///base/airlock.sock");
    }

    #[test]
    fn parse_addr_accepts_unix_scheme() {
        assert_eq!(
            parse_addr("unix:///base/airlock.sock").unwrap(),
            PathBuf::from("/base/airlock.sock")
        );
    }

    #[test]
    fn parse_addr_rejects_other_schemes() {
        assert!(parse_addr("tcp://127.0.0.1:1234").is_err());
        assert!(parse_addr("/base/airlock.sock").is_err());
    }

    #[test]
    fn create_and_validate_creates_base_and_ca_with_mode_0700() {
        let dir = tempdir();
        let base = dir.path().join("rt");
        let rt = RuntimeDir::at(base.clone());

        rt.create_and_validate().expect("create_and_validate");

        let base_mode = std::fs::metadata(&base).unwrap().mode() & 0o777;
        let ca_mode = std::fs::metadata(rt.ca_dir()).unwrap().mode() & 0o777;
        assert_eq!(base_mode, 0o700);
        assert_eq!(ca_mode, 0o700);
    }

    #[test]
    fn create_and_validate_is_idempotent() {
        let dir = tempdir();
        let base = dir.path().join("rt");
        let rt = RuntimeDir::at(base);

        rt.create_and_validate().expect("first call");
        rt.create_and_validate().expect("second call");
    }

    #[test]
    fn validate_rejects_missing_directory() {
        let dir = tempdir();
        let rt = RuntimeDir::at(dir.path().join("missing"));
        assert!(matches!(
            rt.validate(),
            Err(RuntimeDirError::Missing { .. })
        ));
    }

    #[test]
    fn validate_rejects_symlink() {
        let dir = tempdir();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();

        let rt = RuntimeDir::at(link);
        assert!(matches!(
            rt.validate(),
            Err(RuntimeDirError::IsSymlink { .. })
        ));
    }

    #[test]
    fn validate_rejects_non_directory() {
        let dir = tempdir();
        let file = dir.path().join("afile");
        std::fs::write(&file, b"x").unwrap();

        let rt = RuntimeDir::at(file);
        assert!(matches!(
            rt.validate(),
            Err(RuntimeDirError::NotADirectory { .. })
        ));
    }

    #[test]
    fn validate_rejects_group_or_world_accessible_mode() {
        let dir = tempdir();
        let base = dir.path().join("rt");
        std::fs::DirBuilder::new()
            .mode(0o750)
            .create(&base)
            .unwrap();

        let rt = RuntimeDir::at(base);
        assert!(matches!(
            rt.validate(),
            Err(RuntimeDirError::BadMode { .. })
        ));
    }

    #[test]
    fn validate_accepts_mode_0700() {
        let dir = tempdir();
        let base = dir.path().join("rt");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&base)
            .unwrap();

        let rt = RuntimeDir::at(base);
        rt.validate().expect("mode 0700 is valid");
    }

    #[test]
    fn create_and_validate_rejects_socket_path_over_sun_path_limit() {
        let dir = tempdir();
        // Pad the base with a long component so the resulting socket path
        // exceeds the platform's sun_path capacity (104 on macOS, 108 on
        // Linux), without needing a path so long the filesystem itself
        // would refuse it.
        let padding = "x".repeat(120);
        let base = dir.path().join(padding);
        let rt = RuntimeDir::at(base);

        assert!(matches!(
            rt.create_and_validate(),
            Err(RuntimeDirError::SocketPathTooLong { .. })
        ));
    }

    #[test]
    fn locate_honors_debug_test_override() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let dir = tempdir();
        let path = dir.path().join("override-base");

        unsafe {
            std::env::set_var(TEST_OVERRIDE_VAR, &path);
        }
        let result = RuntimeDir::locate();
        unsafe {
            std::env::remove_var(TEST_OVERRIDE_VAR);
        }

        assert_eq!(result.unwrap().base(), path.as_path());
    }

    #[test]
    fn locate_rejects_relative_test_override() {
        let _guard = ENV_MUTEX.lock().unwrap();

        unsafe {
            std::env::set_var(TEST_OVERRIDE_VAR, "relative/path");
        }
        let result = RuntimeDir::locate();
        unsafe {
            std::env::remove_var(TEST_OVERRIDE_VAR);
        }

        assert!(matches!(
            result,
            Err(RuntimeDirError::TestOverrideNotAbsolute { .. })
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn locate_platform_resolves_under_darwin_user_temp_dir() {
        let rt = RuntimeDir::locate_platform().expect("locate_platform");
        assert!(rt.base().ends_with("airlock"));
        assert!(rt.base().is_absolute());
    }
}
