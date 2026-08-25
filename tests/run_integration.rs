//! Sandbox filesystem confinement tests for `airlock run`.
//!
//! Verifies that the OS-level sandbox (Seatbelt on macOS, Landlock on Linux)
//! correctly enforces the filesystem policy built from the agent config.
//!
//! Platform-specific tests are gated with `#[cfg(target_os = "...")]` submodules.

// Only compile on macOS or Linux — the sandbox backends are not available elsewhere.
#![cfg(any(target_os = "macos", target_os = "linux"))]

mod e2e_helpers;

use std::path::Path;
use std::process::Command;

use e2e_helpers::*;

/// Get the path to the `airlock` binary built by `cargo test`.
fn airlock_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().expect("failed to get test exe path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("airlock");
    assert!(
        path.exists(),
        "airlock binary not found at {:?}. Run `cargo build` first.",
        path
    );
    path
}

// ─── Restricted agent config helpers ─────────────────────────────────────────
//
// These configs intentionally omit broad paths (e.g. `/var`, `/private/var`,
// `/tmp`) that would cover sibling temp directories used as denied paths in
// confinement tests.
//
// On macOS, tempfile creates dirs under `/private/var/folders/…`.  Including
// `/var` or `/private/var` in read_paths would allow the agent to read ALL
// temp dirs, defeating the test.
//
// On Linux, tempfile creates dirs under `/tmp/…`.  Including `/tmp` in
// write_paths would allow the agent to write ALL temp dirs.

/// Read paths needed to execute a binary on this platform, excluding broad
/// paths that would cover sibling temp directories.
fn execution_base_read_paths() -> Vec<String> {
    let mut paths: Vec<String> = vec![
        "/usr/lib".to_string(),
        "/usr/bin".to_string(),
        "/bin".to_string(),
        "/dev".to_string(),
        "/etc".to_string(),
    ];

    #[cfg(target_os = "macos")]
    {
        // Intentionally NO /var or /private/var.
        for p in [
            "/System",
            "/Library",
            "/private/etc",
            "/usr/share",
            "/sbin",
            "/usr/local",
        ] {
            paths.push(p.to_string());
        }
    }

    #[cfg(target_os = "linux")]
    {
        for p in ["/lib", "/lib64", "/usr/lib64", "/sbin", "/usr/sbin"] {
            if Path::new(p).exists() {
                paths.push(p.to_string());
            }
        }
    }

    // Nix-managed binaries need /nix/store for libraries.
    // Homebrew on Apple Silicon lives under /opt/homebrew.
    for p in ["/nix", "/opt"] {
        if Path::new(p).exists() {
            paths.push(p.to_string());
        }
    }

    paths
}

/// Build a TOML config string with restricted filesystem access for confinement
/// tests.  No broad `/var` or `/tmp` paths — only the base execution paths.
fn restricted_agent_run_config() -> String {
    let read_str = execution_base_read_paths()
        .iter()
        .map(|p| format!("\"{}\"", p))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        r#"allow_home_root = true

[filesystem]
read = [{read_str}]
write = []
"#
    )
}

/// Build a config that also allows reading an extra directory.
fn config_with_extra_agent_read(extra_path: &Path) -> String {
    let extra = extra_path.to_string_lossy();
    format!(
        "{base}\n[agent.filesystem]\nread = [\"{extra}\"]\n",
        base = restricted_agent_run_config()
    )
}

/// Build a config that also allows writing to an extra directory.
fn config_with_extra_agent_write(extra_path: &Path) -> String {
    let extra = extra_path.to_string_lossy();
    format!(
        "{base}\n[agent.filesystem]\nwrite = [\"{extra}\"]\n",
        base = restricted_agent_run_config()
    )
}

// ─── Cross-platform confinement tests ────────────────────────────────────────

/// The agent can read a file located inside the sandbox root (the temp dir
/// containing the config).
#[test]
fn agent_can_read_sandbox_root() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &restricted_agent_run_config());

    // Write a file inside the sandbox root.
    let test_file = tmp.path().join("read_test.txt");
    std::fs::write(&test_file, "sandbox_read_content").unwrap();

    let canonical_file = std::fs::canonicalize(&test_file).unwrap();
    let cmd = format!("cat '{}'", canonical_file.display());

    let output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "sh", "-c", &cmd])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "agent should be able to read file inside sandbox root; \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("sandbox_read_content"),
        "agent stdout should contain file content, got: {stdout}"
    );
}

/// The agent cannot read a file in a sibling temp directory (outside the
/// sandbox root).
#[test]
fn agent_cannot_read_outside_sandbox_root() {
    let sandbox_tmp = tempfile::tempdir().unwrap();
    let denied_tmp = tempfile::tempdir().unwrap();
    write_config(sandbox_tmp.path(), &restricted_agent_run_config());

    // Write a file in the denied directory.
    let denied_file = denied_tmp.path().join("secret.txt");
    std::fs::write(&denied_file, "secret_data").unwrap();

    let canonical_denied = std::fs::canonicalize(&denied_file).unwrap();
    let cmd = format!("cat '{}'", canonical_denied.display());

    let output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "sh", "-c", &cmd])
        .current_dir(sandbox_tmp.path())
        .env("HOME", sandbox_tmp.path())
        // Point TMPDIR inside sandbox_tmp so the sandbox's implicit
        // TMPDIR grant doesn't cover `denied_tmp` (which sits under the
        // real system TMPDIR — the same `/var/folders/…` tree as
        // sandbox_tmp).
        .env("TMPDIR", sandbox_tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        !output.status.success(),
        "agent should NOT be able to read file outside sandbox root; \
         stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// The agent can create a file inside the sandbox root.
#[test]
fn agent_can_write_inside_sandbox_root() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &restricted_agent_run_config());

    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let new_file = canonical_tmp.join("written_by_agent.txt");
    let cmd = format!("echo agent_wrote > '{}'", new_file.display());

    let output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "sh", "-c", &cmd])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "agent should be able to write inside sandbox root; \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        new_file.exists(),
        "file created by agent should exist at {new_file:?}"
    );
}

/// The agent cannot create a file in a sibling temp directory.
#[test]
fn agent_cannot_write_outside_sandbox_root() {
    let sandbox_tmp = tempfile::tempdir().unwrap();
    let denied_tmp = tempfile::tempdir().unwrap();
    write_config(sandbox_tmp.path(), &restricted_agent_run_config());

    let canonical_denied = std::fs::canonicalize(denied_tmp.path()).unwrap();
    let denied_file = canonical_denied.join("should_not_exist.txt");
    let cmd = format!("echo test > '{}'", denied_file.display());

    let output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "sh", "-c", &cmd])
        .current_dir(sandbox_tmp.path())
        .env("HOME", sandbox_tmp.path())
        // See `agent_cannot_read_outside_sandbox_root` — scope the
        // TMPDIR grant to sandbox_tmp so the real system TMPDIR doesn't
        // cover denied_tmp.
        .env("TMPDIR", sandbox_tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        !output.status.success(),
        "agent should NOT be able to write outside sandbox root"
    );
    assert!(
        !denied_file.exists(),
        "file should not have been created in denied directory"
    );
}

/// The agent can execute a standard system binary (e.g. `true`).
///
/// Verifies that auto-detected toolchain paths and the platform baseline are
/// applied correctly so that common binaries are accessible.
#[test]
fn agent_can_execute_binary_in_path() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &restricted_agent_run_config());

    let output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "agent should be able to execute `true`; \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// An extra read path declared in `[agent.filesystem] read` is accessible.
#[test]
fn agent_user_read_path_accessible() {
    let sandbox_tmp = tempfile::tempdir().unwrap();
    let extra_read_tmp = tempfile::tempdir().unwrap();

    let canonical_extra = std::fs::canonicalize(extra_read_tmp.path()).unwrap();

    // Write a file in the user-specified extra read directory.
    let extra_file = canonical_extra.join("extra_readable.txt");
    std::fs::write(&extra_file, "extra_read_content").unwrap();

    write_config(
        sandbox_tmp.path(),
        &config_with_extra_agent_read(&canonical_extra),
    );

    let cmd = format!("cat '{}'", extra_file.display());

    let output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "sh", "-c", &cmd])
        .current_dir(sandbox_tmp.path())
        .env("HOME", sandbox_tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "agent should be able to read from [agent.filesystem] read path; \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("extra_read_content"),
        "agent stdout should contain the file content, got: {stdout}"
    );
}

/// An extra write path declared in `[agent.filesystem] write` is writable.
#[test]
fn agent_user_write_path_writable() {
    let sandbox_tmp = tempfile::tempdir().unwrap();
    let extra_write_tmp = tempfile::tempdir().unwrap();

    let canonical_extra = std::fs::canonicalize(extra_write_tmp.path()).unwrap();

    write_config(
        sandbox_tmp.path(),
        &config_with_extra_agent_write(&canonical_extra),
    );

    let new_file = canonical_extra.join("written_by_agent_extra.txt");
    let cmd = format!("echo extra_write > '{}'", new_file.display());

    let output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "sh", "-c", &cmd])
        .current_dir(sandbox_tmp.path())
        .env("HOME", sandbox_tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "agent should be able to write to [agent.filesystem] write path; \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        new_file.exists(),
        "file created by agent should exist in the user-specified write path"
    );
}

// ─── macOS-specific sandbox confinement tests ─────────────────────────────────

#[cfg(target_os = "macos")]
mod macos_sandbox {
    use super::*;

    /// The agent can access `/dev/tty` — verifies the
    /// `(allow file-read* (literal "/dev/tty"))` rule in the agent Seatbelt profile.
    #[test]
    fn macos_agent_can_access_dev_tty() {
        let tmp = tempfile::tempdir().unwrap();
        write_config(tmp.path(), &restricted_agent_run_config());

        let output = Command::new(airlock_bin())
            .args(["run", "--no-daemon", "--", "sh", "-c", "stat /dev/tty"])
            .current_dir(tmp.path())
            .env("HOME", tmp.path())
            .output()
            .expect("failed to run airlock run");

        assert!(
            output.status.success(),
            "agent should be able to stat /dev/tty; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// The agent can send SIGTERM to its own child process — verifies
    /// `(allow signal (target same-sandbox))` in the agent Seatbelt profile.
    #[test]
    fn macos_agent_can_signal_own_child() {
        let tmp = tempfile::tempdir().unwrap();
        write_config(tmp.path(), &restricted_agent_run_config());

        // Spawn a background sleep, send SIGTERM to it, and check the kill
        // command exits 0 (meaning it successfully sent the signal).
        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-daemon",
                "--",
                "sh",
                "-c",
                "sleep 60 & P=$!; kill -TERM $P",
            ])
            .current_dir(tmp.path())
            .env("HOME", tmp.path())
            .output()
            .expect("failed to run airlock run");

        assert!(
            output.status.success(),
            "agent should be able to signal its own child process (same-sandbox); \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// The agent cannot send a signal to the unsandboxed `airlock run` process.
    /// Verifies that `(allow signal (target same-sandbox))` blocks signals to
    /// non-sandbox processes.
    ///
    /// Strategy: from the sandboxed shell, attempt `kill -0 $PPID` where
    /// `$PPID` is the shell's parent PID — i.e., `airlock run` (unsandboxed,
    /// not a `same-sandbox` target).  Because the sandbox only allows signals
    /// to `same-sandbox` targets, the null-signal to the parent should be
    /// denied by Seatbelt even though both processes run as the same user.
    #[test]
    fn macos_agent_cannot_signal_unsandboxed_parent() {
        let tmp = tempfile::tempdir().unwrap();
        write_config(tmp.path(), &restricted_agent_run_config());

        // `kill -0 $PPID` sends a null signal to airlock run. Without the
        // sandbox, same-user kill -0 would succeed (exit 0). With the sandbox,
        // `(allow signal (target same-sandbox))` denies it → kill exits non-zero.
        let output = Command::new(airlock_bin())
            .args(["run", "--no-daemon", "--", "sh", "-c", "kill -0 $PPID"])
            .current_dir(tmp.path())
            .env("HOME", tmp.path())
            .output()
            .expect("failed to run airlock run");

        assert!(
            !output.status.success(),
            "agent should NOT be able to send null signal to the unsandboxed \
             airlock run process (same-sandbox signal rule); \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// ─── --no-config flag tests ───────────────────────────────────────────────────
//
// These tests verify the --no-config / AIRLOCK_SANDBOX_ROOT code path.
// Tests that exercise the OS sandbox (confinement) are in the platform-specific
// sub-modules below — the first four tests only check CLI error handling and
// successful startup, which works on any platform that compiles the binary.

/// `--no-config` without `AIRLOCK_SANDBOX_ROOT` set → exits non-zero and stderr
/// explicitly names `AIRLOCK_SANDBOX_ROOT`.
#[test]
fn no_config_without_sandbox_root_exits_nonzero() {
    let tmp = tempfile::tempdir().unwrap();

    let output = Command::new(airlock_bin())
        .args(["run", "--no-config", "--no-daemon", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        // Explicitly remove the variable so the test process's env doesn't leak in.
        .env_remove("AIRLOCK_SANDBOX_ROOT")
        .output()
        .expect("failed to run airlock");

    assert!(
        !output.status.success(),
        "should exit non-zero when AIRLOCK_SANDBOX_ROOT is absent"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("AIRLOCK_SANDBOX_ROOT"),
        "stderr should name AIRLOCK_SANDBOX_ROOT, got: {stderr}"
    );
}

/// `--no-config` with `AIRLOCK_SANDBOX_ROOT` pointing to a non-existent path →
/// exits non-zero before spawning any agent and stderr includes the path.
#[test]
fn no_config_with_nonexistent_sandbox_root_exits_nonzero() {
    let tmp = tempfile::tempdir().unwrap();
    let nonexistent = tmp.path().join("does_not_exist_sandbox_dir");
    // Confirm the path really doesn't exist.
    assert!(!nonexistent.exists());

    let output = Command::new(airlock_bin())
        .args(["run", "--no-config", "--no-daemon", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("AIRLOCK_SANDBOX_ROOT", &nonexistent)
        .output()
        .expect("failed to run airlock");

    assert!(
        !output.status.success(),
        "should exit non-zero when AIRLOCK_SANDBOX_ROOT path does not exist"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(nonexistent.to_string_lossy().as_ref()),
        "stderr should name the non-existent path, got: {stderr}"
    );
}

/// `--no-config` with a valid `AIRLOCK_SANDBOX_ROOT` and no `airlock.toml`
/// present → exits zero when running a trivial command (`true`).
#[test]
fn no_config_with_valid_sandbox_root_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    // No airlock.toml written — the whole point of --no-config.

    let output = Command::new(airlock_bin())
        .args(["run", "--no-config", "--no-daemon", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("AIRLOCK_SANDBOX_ROOT", tmp.path())
        .output()
        .expect("failed to run airlock");

    assert!(
        output.status.success(),
        "should exit zero with a valid AIRLOCK_SANDBOX_ROOT and no airlock.toml; \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// When `airlock.toml` exists in the current directory but `--no-config` is
/// set, the file is not read — even if it contains intentionally malformed TOML
/// the binary must not emit any parse error.
#[test]
fn no_config_ignores_malformed_toml_in_cwd() {
    let tmp = tempfile::tempdir().unwrap();
    // Write intentionally invalid TOML.
    std::fs::write(
        tmp.path().join("airlock.toml"),
        "this is ] not [ valid = toml at all !!!",
    )
    .unwrap();

    let output = Command::new(airlock_bin())
        .args(["run", "--no-config", "--no-daemon", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("AIRLOCK_SANDBOX_ROOT", tmp.path())
        .output()
        .expect("failed to run airlock");

    assert!(
        output.status.success(),
        "--no-config must ignore a malformed airlock.toml; \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ─── --no-config confinement tests (platform-specific) ───────────────────────
//
// These tests verify that the OS sandbox is applied correctly even when
// --no-config is used.  They require macOS (Seatbelt) or Linux (Landlock).
// Mark them appropriately so they are skipped on unsupported kernels/platforms.

#[cfg(target_os = "macos")]
mod no_config_macos_confinement {
    use super::*;

    /// `--no-config` with `AIRLOCK_SANDBOX_ROOT` set → agent can read a file
    /// inside the sandbox root directory.
    #[test]
    fn no_config_agent_can_read_inside_sandbox_root() {
        let tmp = tempfile::tempdir().unwrap();

        // Write a file inside the sandbox root.
        let test_file = tmp.path().join("accessible.txt");
        std::fs::write(&test_file, "accessible_content").unwrap();
        let canonical_file = std::fs::canonicalize(&test_file).unwrap();
        let cmd = format!("cat '{}'", canonical_file.display());

        let output = Command::new(airlock_bin())
            .args(["run", "--no-config", "--no-daemon", "--", "sh", "-c", &cmd])
            .current_dir(tmp.path())
            .env("HOME", tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "agent should be able to read a file inside AIRLOCK_SANDBOX_ROOT; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("accessible_content"),
            "stdout should contain the file content, got: {stdout}"
        );
    }

    /// `--no-config` with `AIRLOCK_SANDBOX_ROOT` set → agent cannot read a file
    /// in a sibling directory that is outside the sandbox root.
    #[test]
    fn no_config_agent_cannot_read_outside_sandbox_root() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let denied_tmp = tempfile::tempdir().unwrap();

        // Write a file in the denied directory (outside sandbox root).
        let denied_file = denied_tmp.path().join("secret.txt");
        std::fs::write(&denied_file, "secret_data").unwrap();
        let canonical_denied = std::fs::canonicalize(&denied_file).unwrap();
        let cmd = format!("cat '{}'", canonical_denied.display());

        let output = Command::new(airlock_bin())
            .args(["run", "--no-config", "--no-daemon", "--", "sh", "-c", &cmd])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            // Scope TMPDIR to sandbox_tmp so that the Seatbelt $TMPDIR grant
            // does not cover denied_tmp (which sits under the real system TMPDIR).
            .env("TMPDIR", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            !output.status.success(),
            "agent should NOT be able to read a file outside AIRLOCK_SANDBOX_ROOT"
        );
    }
}

#[cfg(target_os = "linux")]
mod no_config_linux_confinement {
    use super::*;

    /// `--no-config` with `AIRLOCK_SANDBOX_ROOT` set → agent can read a file
    /// inside the sandbox root directory.
    #[test]
    fn no_config_agent_can_read_inside_sandbox_root() {
        let tmp = tempfile::tempdir().unwrap();

        // Write a file inside the sandbox root.
        let test_file = tmp.path().join("accessible.txt");
        std::fs::write(&test_file, "accessible_content").unwrap();
        let canonical_file = std::fs::canonicalize(&test_file).unwrap();
        let cmd = format!("cat '{}'", canonical_file.display());

        let output = Command::new(airlock_bin())
            .args(["run", "--no-config", "--no-daemon", "--", "sh", "-c", &cmd])
            .current_dir(tmp.path())
            .env("HOME", tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "agent should be able to read a file inside AIRLOCK_SANDBOX_ROOT; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("accessible_content"),
            "stdout should contain the file content, got: {stdout}"
        );
    }

    /// `--no-config` with `AIRLOCK_SANDBOX_ROOT` set → agent cannot read a file
    /// in a sibling directory that is outside the sandbox root.
    #[test]
    fn no_config_agent_cannot_read_outside_sandbox_root() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let denied_tmp = tempfile::tempdir().unwrap();

        // Write a file in the denied directory (outside sandbox root).
        let denied_file = denied_tmp.path().join("secret.txt");
        std::fs::write(&denied_file, "secret_data").unwrap();
        let canonical_denied = std::fs::canonicalize(&denied_file).unwrap();
        let cmd = format!("cat '{}'", canonical_denied.display());

        let output = Command::new(airlock_bin())
            .args(["run", "--no-config", "--no-daemon", "--", "sh", "-c", &cmd])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            !output.status.success(),
            "agent should NOT be able to read a file outside AIRLOCK_SANDBOX_ROOT"
        );
    }
}

// ─── Linux-specific sandbox confinement tests ─────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_sandbox {
    use super::*;

    /// The agent cannot read `/proc/self/maps` — verifies that `/proc` is absent
    /// from the Landlock ruleset and therefore inaccessible.
    ///
    /// Uses `/proc/self/maps` (rather than `/proc/1/status`) because maps is
    /// always owned by the current user, so any failure is definitively a
    /// Landlock denial rather than a permission issue.
    #[test]
    fn linux_proc_not_accessible() {
        let tmp = tempfile::tempdir().unwrap();
        write_config(tmp.path(), &restricted_agent_run_config());

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-daemon",
                "--",
                "sh",
                "-c",
                "cat /proc/self/maps",
            ])
            .current_dir(tmp.path())
            .env("HOME", tmp.path())
            .output()
            .expect("failed to run airlock run");

        assert!(
            !output.status.success(),
            "agent should NOT be able to read /proc/self/maps (Landlock blocks /proc)"
        );
    }

    /// The agent can list `/usr/bin` — verifies that the Linux agent baseline
    /// includes standard toolchain paths.
    #[test]
    fn linux_agent_baseline_paths_readable() {
        let tmp = tempfile::tempdir().unwrap();
        write_config(tmp.path(), &restricted_agent_run_config());

        let output = Command::new(airlock_bin())
            .args(["run", "--no-daemon", "--", "sh", "-c", "ls /usr/bin"])
            .current_dir(tmp.path())
            .env("HOME", tmp.path())
            .output()
            .expect("failed to run airlock run");

        assert!(
            output.status.success(),
            "agent should be able to list /usr/bin (Linux agent baseline); \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// ─── --allow-read / --allow-write flag: cross-platform startup tests ─────────
//
// These tests verify flag behaviour that does not depend on the OS sandbox
// backend — primarily that the binary starts up cleanly even when supplied
// with unusual (e.g. non-existent) paths.

/// A non-existent path passed to `--allow-read` must not cause a startup
/// error — the binary should run the agent command normally and exit zero.
#[test]
fn allow_read_nonexistent_path_does_not_cause_startup_error() {
    let tmp = tempfile::tempdir().unwrap();
    // Deliberately construct a path that cannot exist.
    let nonexistent = tmp.path().join("does_not_exist_dir_allow_read");
    assert!(!nonexistent.exists());

    let output = Command::new(airlock_bin())
        .args([
            "run",
            "--no-config",
            "--no-daemon",
            "--allow-read",
            &nonexistent.to_string_lossy(),
            "--",
            "true",
        ])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("AIRLOCK_SANDBOX_ROOT", tmp.path())
        .output()
        .expect("failed to run airlock");

    assert!(
        output.status.success(),
        "airlock should start cleanly with a non-existent --allow-read path; \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A non-existent path passed to `--allow-write` must not cause a startup
/// error — the binary should run the agent command normally and exit zero.
#[test]
fn allow_write_nonexistent_path_does_not_cause_startup_error() {
    let tmp = tempfile::tempdir().unwrap();
    let nonexistent = tmp.path().join("does_not_exist_dir_allow_write");
    assert!(!nonexistent.exists());

    let output = Command::new(airlock_bin())
        .args([
            "run",
            "--no-config",
            "--no-daemon",
            "--allow-write",
            &nonexistent.to_string_lossy(),
            "--",
            "true",
        ])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("AIRLOCK_SANDBOX_ROOT", tmp.path())
        .output()
        .expect("failed to run airlock");

    assert!(
        output.status.success(),
        "airlock should start cleanly with a non-existent --allow-write path; \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ─── --allow-read and --allow-write flag tests (macOS) ───────────────────────
//
// These tests verify that the --allow-read and --allow-write CLI flags correctly
// extend the agent's filesystem policy. All tests use --no-config,
// AIRLOCK_SANDBOX_ROOT, and --no-daemon to remain self-contained.

#[cfg(target_os = "macos")]
mod allow_flags_macos {
    use super::*;

    /// Without `--allow-read`, a sibling directory outside the sandbox root is
    /// not readable.
    #[test]
    fn allow_read_not_set_sibling_dir_inaccessible() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let sibling_tmp = tempfile::tempdir().unwrap();

        let sibling_file = sibling_tmp.path().join("secret.txt");
        std::fs::write(&sibling_file, "secret_data").unwrap();
        let canonical_file = std::fs::canonicalize(&sibling_file).unwrap();
        let cmd = format!("cat '{}'", canonical_file.display());

        let output = Command::new(airlock_bin())
            .args(["run", "--no-config", "--no-daemon", "--", "sh", "-c", &cmd])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("TMPDIR", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            !output.status.success(),
            "agent should NOT be able to read sibling dir without --allow-read"
        );
    }

    /// With `--allow-read <sibling-dir>`, the sibling directory becomes readable.
    #[test]
    fn allow_read_grants_read_access_to_sibling_dir() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let sibling_tmp = tempfile::tempdir().unwrap();

        let sibling_file = sibling_tmp.path().join("readable.txt");
        std::fs::write(&sibling_file, "readable_content").unwrap();
        let canonical_sibling = std::fs::canonicalize(sibling_tmp.path()).unwrap();
        let canonical_file = canonical_sibling.join("readable.txt");
        let cmd = format!("cat '{}'", canonical_file.display());

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--allow-read",
                &canonical_sibling.to_string_lossy(),
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "agent should be able to read file after --allow-read; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("readable_content"),
            "stdout should contain file content, got: {stdout}"
        );
    }

    /// `--allow-read` grants read-only access — the agent cannot write to the
    /// granted directory.
    #[test]
    fn allow_read_does_not_grant_write_access() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let sibling_tmp = tempfile::tempdir().unwrap();

        let canonical_sibling = std::fs::canonicalize(sibling_tmp.path()).unwrap();
        let new_file = canonical_sibling.join("should_not_be_written.txt");
        let cmd = format!("echo test > '{}'", new_file.display());

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--allow-read",
                &canonical_sibling.to_string_lossy(),
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            // Scope TMPDIR to sandbox_tmp so the implicit Seatbelt $TMPDIR
            // write grant does not cover sibling_tmp.
            .env("TMPDIR", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            !output.status.success(),
            "agent should NOT be able to write to --allow-read path"
        );
        assert!(
            !new_file.exists(),
            "file should not have been created in --allow-read directory"
        );
    }

    /// Without `--allow-write`, a sibling directory outside the sandbox root is
    /// not writable.
    #[test]
    fn allow_write_not_set_sibling_dir_not_writable() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let sibling_tmp = tempfile::tempdir().unwrap();

        let canonical_sibling = std::fs::canonicalize(sibling_tmp.path()).unwrap();
        let new_file = canonical_sibling.join("should_not_exist.txt");
        let cmd = format!("echo test > '{}'", new_file.display());

        let output = Command::new(airlock_bin())
            .args(["run", "--no-config", "--no-daemon", "--", "sh", "-c", &cmd])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("TMPDIR", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            !output.status.success(),
            "agent should NOT be able to write to sibling dir without --allow-write"
        );
        assert!(
            !new_file.exists(),
            "file should not have been created in denied directory"
        );
    }

    /// With `--allow-write <sibling-dir>`, the sibling directory becomes writable.
    #[test]
    fn allow_write_grants_write_access_to_sibling_dir() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let sibling_tmp = tempfile::tempdir().unwrap();

        let canonical_sibling = std::fs::canonicalize(sibling_tmp.path()).unwrap();
        let new_file = canonical_sibling.join("written_by_agent.txt");
        let cmd = format!("echo agent_wrote > '{}'", new_file.display());

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--allow-write",
                &canonical_sibling.to_string_lossy(),
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "agent should be able to write to sibling dir after --allow-write; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            new_file.exists(),
            "file created by agent should exist at {new_file:?}"
        );
    }

    /// Two `--allow-read` flags and two `--allow-write` flags — all four paths
    /// are independently accessible.
    #[test]
    fn allow_read_and_write_multiple_flags_all_accessible() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let read_tmp1 = tempfile::tempdir().unwrap();
        let read_tmp2 = tempfile::tempdir().unwrap();
        let write_tmp1 = tempfile::tempdir().unwrap();
        let write_tmp2 = tempfile::tempdir().unwrap();

        let canonical_read1 = std::fs::canonicalize(read_tmp1.path()).unwrap();
        let canonical_read2 = std::fs::canonicalize(read_tmp2.path()).unwrap();
        let canonical_write1 = std::fs::canonicalize(write_tmp1.path()).unwrap();
        let canonical_write2 = std::fs::canonicalize(write_tmp2.path()).unwrap();

        // Create readable files in both read dirs.
        std::fs::write(canonical_read1.join("file1.txt"), "content1").unwrap();
        std::fs::write(canonical_read2.join("file2.txt"), "content2").unwrap();

        // Command: read both files and write to both write dirs.
        let cmd = format!(
            "cat '{r1}/file1.txt' && cat '{r2}/file2.txt' && \
             echo w1 > '{w1}/out1.txt' && echo w2 > '{w2}/out2.txt'",
            r1 = canonical_read1.display(),
            r2 = canonical_read2.display(),
            w1 = canonical_write1.display(),
            w2 = canonical_write2.display(),
        );

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--allow-read",
                &canonical_read1.to_string_lossy(),
                "--allow-read",
                &canonical_read2.to_string_lossy(),
                "--allow-write",
                &canonical_write1.to_string_lossy(),
                "--allow-write",
                &canonical_write2.to_string_lossy(),
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "all four --allow-read/--allow-write paths should be accessible; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            canonical_write1.join("out1.txt").exists(),
            "write-tmp1 output file should exist"
        );
        assert!(
            canonical_write2.join("out2.txt").exists(),
            "write-tmp2 output file should exist"
        );
    }

    /// `--allow-read` and `--allow-write` for different sibling paths
    /// simultaneously — both are accessible with their respective permission levels.
    #[test]
    fn allow_read_and_write_different_paths_simultaneously() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let read_tmp = tempfile::tempdir().unwrap();
        let write_tmp = tempfile::tempdir().unwrap();

        let canonical_read = std::fs::canonicalize(read_tmp.path()).unwrap();
        let canonical_write = std::fs::canonicalize(write_tmp.path()).unwrap();

        std::fs::write(canonical_read.join("data.txt"), "read_data").unwrap();
        let write_out = canonical_write.join("out.txt");

        let cmd = format!(
            "cat '{r}/data.txt' && echo written > '{w}'",
            r = canonical_read.display(),
            w = write_out.display(),
        );

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--allow-read",
                &canonical_read.to_string_lossy(),
                "--allow-write",
                &canonical_write.to_string_lossy(),
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "--allow-read and --allow-write for different paths should both work; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("read_data"),
            "stdout should contain the read file content, got: {stdout}"
        );
        assert!(write_out.exists(), "write output file should exist");
    }

    /// `--allow-write` combined with `--profile claude` — both the Claude
    /// profile paths and the CLI-supplied write path are accessible.
    #[test]
    fn allow_write_combined_with_profile_claude() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let write_tmp = tempfile::tempdir().unwrap();

        // Create ~/.claude/ under HOME (sandbox_tmp) so the claude profile
        // picks it up.
        let claude_dir = sandbox_tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let canonical_claude_dir = std::fs::canonicalize(&claude_dir).unwrap();

        let canonical_write = std::fs::canonicalize(write_tmp.path()).unwrap();
        let write_out = canonical_write.join("out.txt");
        let claude_marker = canonical_claude_dir.join("profile_marker.txt");

        // Write to both the claude profile dir (via write) and the CLI path.
        let cmd = format!(
            "echo profile_write > '{c}' && echo cli_write > '{w}'",
            c = claude_marker.display(),
            w = write_out.display(),
        );

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--profile",
                "claude",
                "--allow-write",
                &canonical_write.to_string_lossy(),
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "--allow-write combined with --profile claude should grant access to both; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            claude_marker.exists(),
            "claude profile dir should be writable (via --profile claude)"
        );
        assert!(
            write_out.exists(),
            "CLI-supplied --allow-write path should be writable"
        );
    }

    /// A relative path supplied to `--allow-write` is resolved against the
    /// process working directory.
    #[test]
    fn allow_write_relative_path_resolved_against_cwd() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let sibling_tmp = tempfile::tempdir().unwrap();

        let canonical_sibling = std::fs::canonicalize(sibling_tmp.path()).unwrap();
        let new_file = canonical_sibling.join("written.txt");
        let cmd = format!("echo written > '{}'", new_file.display());

        // Build a relative path from sandbox_tmp to sibling_tmp.
        // On macOS temp dirs are siblings under the same parent.
        let sibling_name = canonical_sibling
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let parent = canonical_sibling.parent().unwrap();
        let canonical_sandbox = std::fs::canonicalize(sandbox_tmp.path()).unwrap();

        // Only run this test when both temp dirs share the same parent
        // (so the relative path "../<sibling>" is valid).
        if parent != canonical_sandbox.parent().unwrap_or(&canonical_sandbox) {
            // Temp dirs don't share a parent — skip relative-path variant.
            return;
        }

        let relative_path = format!("../{sibling_name}");

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--allow-write",
                &relative_path,
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(&canonical_sandbox)
            .env("HOME", &canonical_sandbox)
            .env("AIRLOCK_SANDBOX_ROOT", &canonical_sandbox)
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "relative --allow-write path should be resolved against CWD; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            new_file.exists(),
            "file should have been created via relative --allow-write path"
        );
    }

    /// `--allow-write` works when `airlock.toml` is present — it adds to the
    /// config-file permissions rather than replacing them.
    ///
    /// The sandbox root is readable (from config), and a sibling directory
    /// becomes writable (from `--allow-write`). Both are accessible simultaneously.
    #[test]
    fn allow_write_adds_to_config_file_permissions() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let sibling_tmp = tempfile::tempdir().unwrap();

        // Write a restricted airlock.toml — no broad paths that cover sibling_tmp.
        write_config(sandbox_tmp.path(), &restricted_agent_run_config());

        let canonical_sibling = std::fs::canonicalize(sibling_tmp.path()).unwrap();
        let new_file = canonical_sibling.join("written_via_config_run.txt");
        let cmd = format!("echo ok > '{}'", new_file.display());

        // Run WITH airlock.toml present (no --no-config) but WITH --allow-write.
        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-daemon",
                "--allow-write",
                &canonical_sibling.to_string_lossy(),
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "--allow-write should work alongside airlock.toml config; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            new_file.exists(),
            "file should have been created in --allow-write path even with airlock.toml present"
        );
    }
}

// ─── --passthrough-env flag tests ────────────────────────────────────────────
//
// These tests verify that the --passthrough-env CLI flag correctly controls
// which host environment variables are forwarded to the sandboxed agent.
// They use --no-config + AIRLOCK_SANDBOX_ROOT + --no-daemon unless the test
// specifically needs an airlock.toml (e.g. the additive-with-config test).

/// Build a config that declares the given variable in `[agent] passthrough_env`.
fn config_with_agent_passthrough_env(var: &str) -> String {
    format!(
        "{base}\n[agent]\npassthrough_env = [\"{var}\"]\n",
        base = restricted_agent_run_config()
    )
}

/// A host env var that is not in `NAMED_ESSENTIAL` is absent from the agent
/// environment when `--passthrough-env` is not supplied.
#[test]
fn passthrough_env_flag_absent_keeps_var_hidden() {
    let tmp = tempfile::tempdir().unwrap();
    // Unique name to avoid collision with host env.
    const VAR: &str = "MY_CC_RUNNER_TEST_HIDDEN_VAR_ZZZ1234";

    let output = Command::new(airlock_bin())
        .args(["run", "--no-config", "--no-daemon", "--", "sh", "-c", "env"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("AIRLOCK_SANDBOX_ROOT", tmp.path())
        // Set the var explicitly on the child process so airlock inherits it.
        .env(VAR, "should_not_appear_in_agent")
        .output()
        .expect("failed to run airlock");

    assert!(
        output.status.success(),
        "command should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(&format!("{VAR}=")),
        "host env var without --passthrough-env should not appear in agent env, stdout: {stdout}"
    );
}

/// A host env var forwarded via `--passthrough-env VAR` is visible inside
/// the sandboxed agent.
#[test]
fn passthrough_env_flag_forwards_var_to_agent() {
    let tmp = tempfile::tempdir().unwrap();
    const VAR: &str = "MY_CC_RUNNER_TEST_FORWARDED_VAR_ZZZ5678";

    let output = Command::new(airlock_bin())
        .args([
            "run",
            "--no-config",
            "--no-daemon",
            "--passthrough-env",
            VAR,
            "--",
            "sh",
            "-c",
            &format!("echo {VAR}=${VAR}"),
        ])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("AIRLOCK_SANDBOX_ROOT", tmp.path())
        .env(VAR, "forwarded_value_abc")
        .output()
        .expect("failed to run airlock");

    assert!(
        output.status.success(),
        "command should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("{VAR}=forwarded_value_abc")),
        "passthrough var should appear with its value in agent env, got: {stdout}"
    );
}

/// Multiple `--passthrough-env` flags each independently forward their named
/// variable into the sandboxed agent.
#[test]
fn passthrough_env_multiple_flags_all_forwarded() {
    let tmp = tempfile::tempdir().unwrap();
    const VAR1: &str = "MY_CC_RUNNER_MULTI_PASSTHROUGH_A_9001";
    const VAR2: &str = "MY_CC_RUNNER_MULTI_PASSTHROUGH_B_9002";

    let cmd = format!("echo {V1}=${V1} && echo {V2}=${V2}", V1 = VAR1, V2 = VAR2);

    let output = Command::new(airlock_bin())
        .args([
            "run",
            "--no-config",
            "--no-daemon",
            "--passthrough-env",
            VAR1,
            "--passthrough-env",
            VAR2,
            "--",
            "sh",
            "-c",
            &cmd,
        ])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("AIRLOCK_SANDBOX_ROOT", tmp.path())
        .env(VAR1, "value_alpha")
        .env(VAR2, "value_beta")
        .output()
        .expect("failed to run airlock");

    assert!(
        output.status.success(),
        "command should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("{VAR1}=value_alpha")),
        "first passthrough var should appear in agent env, got: {stdout}"
    );
    assert!(
        stdout.contains(&format!("{VAR2}=value_beta")),
        "second passthrough var should appear in agent env, got: {stdout}"
    );
}

/// `--passthrough-env` for a variable not set on the host — the flag is
/// accepted, the agent starts successfully, and the variable is absent in
/// the agent environment (no error).
#[test]
fn passthrough_env_unset_host_var_is_silently_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    // Use a name that is almost certainly absent from any real environment.
    const ABSENT_VAR: &str = "MY_CC_RUNNER_DEFINITELY_ABSENT_VAR_ZZZQ9999";

    let output = Command::new(airlock_bin())
        .args([
            "run",
            "--no-config",
            "--no-daemon",
            "--passthrough-env",
            ABSENT_VAR,
            "--",
            "sh",
            "-c",
            "echo ok",
        ])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("AIRLOCK_SANDBOX_ROOT", tmp.path())
        // Explicitly remove the variable so the test environment is clean.
        .env_remove(ABSENT_VAR)
        .output()
        .expect("failed to run airlock");

    assert!(
        output.status.success(),
        "--passthrough-env for an absent host var should not cause an error; \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ok"),
        "agent should have run successfully and printed 'ok', got: {stdout}"
    );
}

/// `--passthrough-env` in `--no-config` mode (no `airlock.toml`, `AIRLOCK_SANDBOX_ROOT`
/// set) — named var is forwarded correctly without a config `passthrough_env` list.
#[test]
fn passthrough_env_works_in_no_config_mode() {
    let tmp = tempfile::tempdir().unwrap();
    const VAR: &str = "MY_CC_RUNNER_NO_CONFIG_PASSTHROUGH_7777";
    // No airlock.toml is written — the whole point of --no-config.

    let output = Command::new(airlock_bin())
        .args([
            "run",
            "--no-config",
            "--no-daemon",
            "--passthrough-env",
            VAR,
            "--",
            "sh",
            "-c",
            &format!("echo {VAR}=${VAR}"),
        ])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("AIRLOCK_SANDBOX_ROOT", tmp.path())
        .env(VAR, "no_config_forwarded")
        .output()
        .expect("failed to run airlock");

    assert!(
        output.status.success(),
        "--passthrough-env should work in --no-config mode; \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("{VAR}=no_config_forwarded")),
        "passthrough var should appear in agent env in --no-config mode, got: {stdout}"
    );
}

/// `--passthrough-env` alongside an `airlock.toml` that also declares
/// `passthrough_env` in `[agent]` — both the config-declared and CLI-declared
/// variables are present in the agent environment (additive).
#[test]
fn passthrough_env_additive_with_config_passthrough_env() {
    let sandbox_tmp = tempfile::tempdir().unwrap();
    const CONFIG_VAR: &str = "MY_CC_RUNNER_CONFIG_PASSTHROUGH_3001";
    const CLI_VAR: &str = "MY_CC_RUNNER_CLI_PASSTHROUGH_3002";

    // Config declares CONFIG_VAR in [agent] passthrough_env.
    write_config(
        sandbox_tmp.path(),
        &config_with_agent_passthrough_env(CONFIG_VAR),
    );

    let cmd = format!(
        "echo {CV}=${CV} && echo {LV}=${LV}",
        CV = CONFIG_VAR,
        LV = CLI_VAR
    );

    let output = Command::new(airlock_bin())
        .args([
            "run",
            "--no-daemon",
            "--passthrough-env",
            CLI_VAR,
            "--",
            "sh",
            "-c",
            &cmd,
        ])
        .current_dir(sandbox_tmp.path())
        .env("HOME", sandbox_tmp.path())
        .env(CONFIG_VAR, "config_declared_value")
        .env(CLI_VAR, "cli_declared_value")
        .output()
        .expect("failed to run airlock");

    assert!(
        output.status.success(),
        "--passthrough-env should work alongside config-declared passthrough_env; \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("{CONFIG_VAR}=config_declared_value")),
        "config-declared passthrough var should appear in agent env, got: {stdout}"
    );
    assert!(
        stdout.contains(&format!("{CLI_VAR}=cli_declared_value")),
        "CLI-declared passthrough var should appear in agent env alongside config var, got: {stdout}"
    );
}

// ─── Combined cc-runner use-case test (platform-specific) ────────────────────
//
// This test exercises all five new features together in the exact invocation
// pattern that cc-runner generates. Because it verifies filesystem confinement
// (the db-dir must be writable; other dirs must not be), it lives in
// platform-specific modules where the OS sandbox backend is available.

#[cfg(target_os = "macos")]
mod combined_ccrunner_macos {
    use super::*;

    /// Combined cc-runner use-case: `--no-config`, `AIRLOCK_SANDBOX_ROOT`,
    /// `--profile claude`, `--allow-write <db-dir>`, and
    /// `--passthrough-env ANTHROPIC_API_KEY` all work correctly together.
    ///
    /// Simulates the exact invocation cc-runner generates when running
    /// Claude Code inside an Airlock sandbox without a pre-existing
    /// `airlock.toml`.
    #[test]
    fn combined_ccrunner_usecase_all_features() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let db_tmp = tempfile::tempdir().unwrap();

        let canonical_sandbox = std::fs::canonicalize(sandbox_tmp.path()).unwrap();
        let canonical_db = std::fs::canonicalize(db_tmp.path()).unwrap();

        // Create ~/.claude/ under HOME so the claude profile picks it up.
        let claude_dir = canonical_sandbox.join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        // Write a project marker file inside the sandbox root.
        let project_file = canonical_sandbox.join("project_marker.txt");
        std::fs::write(&project_file, "project_content").unwrap();

        let db_out = canonical_db.join("db_written.txt");

        // The agent command verifies: project dir is accessible, db dir is
        // writable, ANTHROPIC_API_KEY is set, and the command exits zero.
        let cmd = format!(
            "cat '{pf}' && \
             echo db_write > '{db}' && \
             test -n \"$ANTHROPIC_API_KEY\"",
            pf = project_file.display(),
            db = db_out.display(),
        );

        // Set AIRLOCK_SANDBOX_ROOT and ANTHROPIC_API_KEY via EnvGuard, matching
        // the way cc-runner sets them on its own process before spawning airlock.
        let _guard = EnvGuard::new(&[
            (
                "AIRLOCK_SANDBOX_ROOT",
                canonical_sandbox.to_string_lossy().as_ref(),
            ),
            ("ANTHROPIC_API_KEY", "sk-ant-dummy-test-key-for-ccrunner"),
        ]);

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--profile",
                "claude",
                "--allow-write",
                &canonical_db.to_string_lossy(),
                "--passthrough-env",
                "ANTHROPIC_API_KEY",
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(&canonical_sandbox)
            .env("HOME", &canonical_sandbox)
            // Do NOT set AIRLOCK_SANDBOX_ROOT or ANTHROPIC_API_KEY here —
            // they are inherited from the test process via EnvGuard above.
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "combined cc-runner use-case should succeed; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            db_out.exists(),
            "db output file should have been created by the agent via --allow-write"
        );
    }
}

#[cfg(target_os = "linux")]
mod combined_ccrunner_linux {
    use super::*;

    /// Combined cc-runner use-case: `--no-config`, `AIRLOCK_SANDBOX_ROOT`,
    /// `--profile claude`, `--allow-write <db-dir>`, and
    /// `--passthrough-env ANTHROPIC_API_KEY` all work correctly together.
    #[test]
    fn combined_ccrunner_usecase_all_features() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let db_tmp = tempfile::tempdir().unwrap();

        let canonical_sandbox = std::fs::canonicalize(sandbox_tmp.path()).unwrap();
        let canonical_db = std::fs::canonicalize(db_tmp.path()).unwrap();

        // Create ~/.claude/ under HOME so the claude profile picks it up.
        let claude_dir = canonical_sandbox.join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        // Write a project marker file inside the sandbox root.
        let project_file = canonical_sandbox.join("project_marker.txt");
        std::fs::write(&project_file, "project_content").unwrap();

        let db_out = canonical_db.join("db_written.txt");

        let cmd = format!(
            "cat '{pf}' && \
             echo db_write > '{db}' && \
             test -n \"$ANTHROPIC_API_KEY\"",
            pf = project_file.display(),
            db = db_out.display(),
        );

        // Set AIRLOCK_SANDBOX_ROOT and ANTHROPIC_API_KEY via EnvGuard.
        let _guard = EnvGuard::new(&[
            (
                "AIRLOCK_SANDBOX_ROOT",
                canonical_sandbox.to_string_lossy().as_ref(),
            ),
            ("ANTHROPIC_API_KEY", "sk-ant-dummy-test-key-for-ccrunner"),
        ]);

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--profile",
                "claude",
                "--allow-write",
                &canonical_db.to_string_lossy(),
                "--passthrough-env",
                "ANTHROPIC_API_KEY",
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(&canonical_sandbox)
            .env("HOME", &canonical_sandbox)
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "combined cc-runner use-case should succeed; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            db_out.exists(),
            "db output file should have been created by the agent via --allow-write"
        );
    }
}

// ─── --allow-read and --allow-write flag tests (Linux) ───────────────────────

#[cfg(target_os = "linux")]
mod allow_flags_linux {
    use super::*;

    /// Without `--allow-read`, a sibling directory outside the sandbox root is
    /// not readable.
    #[test]
    fn allow_read_not_set_sibling_dir_inaccessible() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let sibling_tmp = tempfile::tempdir().unwrap();

        let sibling_file = sibling_tmp.path().join("secret.txt");
        std::fs::write(&sibling_file, "secret_data").unwrap();
        let canonical_file = std::fs::canonicalize(&sibling_file).unwrap();
        let cmd = format!("cat '{}'", canonical_file.display());

        let output = Command::new(airlock_bin())
            .args(["run", "--no-config", "--no-daemon", "--", "sh", "-c", &cmd])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            !output.status.success(),
            "agent should NOT be able to read sibling dir without --allow-read"
        );
    }

    /// With `--allow-read <sibling-dir>`, the sibling directory becomes readable.
    #[test]
    fn allow_read_grants_read_access_to_sibling_dir() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let sibling_tmp = tempfile::tempdir().unwrap();

        let sibling_file = sibling_tmp.path().join("readable.txt");
        std::fs::write(&sibling_file, "readable_content").unwrap();
        let canonical_sibling = std::fs::canonicalize(sibling_tmp.path()).unwrap();
        let canonical_file = canonical_sibling.join("readable.txt");
        let cmd = format!("cat '{}'", canonical_file.display());

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--allow-read",
                &canonical_sibling.to_string_lossy(),
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "agent should be able to read file after --allow-read; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("readable_content"),
            "stdout should contain file content, got: {stdout}"
        );
    }

    /// `--allow-read` grants read-only access — the agent cannot write to the
    /// granted directory.
    #[test]
    fn allow_read_does_not_grant_write_access() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let sibling_tmp = tempfile::tempdir().unwrap();

        let canonical_sibling = std::fs::canonicalize(sibling_tmp.path()).unwrap();
        let new_file = canonical_sibling.join("should_not_be_written.txt");
        let cmd = format!("echo test > '{}'", new_file.display());

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--allow-read",
                &canonical_sibling.to_string_lossy(),
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            !output.status.success(),
            "agent should NOT be able to write to --allow-read path"
        );
        assert!(
            !new_file.exists(),
            "file should not have been created in --allow-read directory"
        );
    }

    /// Without `--allow-write`, a sibling directory outside the sandbox root is
    /// not writable.
    #[test]
    fn allow_write_not_set_sibling_dir_not_writable() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let sibling_tmp = tempfile::tempdir().unwrap();

        let canonical_sibling = std::fs::canonicalize(sibling_tmp.path()).unwrap();
        let new_file = canonical_sibling.join("should_not_exist.txt");
        let cmd = format!("echo test > '{}'", new_file.display());

        let output = Command::new(airlock_bin())
            .args(["run", "--no-config", "--no-daemon", "--", "sh", "-c", &cmd])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            !output.status.success(),
            "agent should NOT be able to write to sibling dir without --allow-write"
        );
        assert!(
            !new_file.exists(),
            "file should not have been created in denied directory"
        );
    }

    /// With `--allow-write <sibling-dir>`, the sibling directory becomes writable.
    #[test]
    fn allow_write_grants_write_access_to_sibling_dir() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let sibling_tmp = tempfile::tempdir().unwrap();

        let canonical_sibling = std::fs::canonicalize(sibling_tmp.path()).unwrap();
        let new_file = canonical_sibling.join("written_by_agent.txt");
        let cmd = format!("echo agent_wrote > '{}'", new_file.display());

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--allow-write",
                &canonical_sibling.to_string_lossy(),
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "agent should be able to write to sibling dir after --allow-write; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            new_file.exists(),
            "file created by agent should exist at {new_file:?}"
        );
    }

    /// Two `--allow-read` flags and two `--allow-write` flags — all four paths
    /// are independently accessible.
    #[test]
    fn allow_read_and_write_multiple_flags_all_accessible() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let read_tmp1 = tempfile::tempdir().unwrap();
        let read_tmp2 = tempfile::tempdir().unwrap();
        let write_tmp1 = tempfile::tempdir().unwrap();
        let write_tmp2 = tempfile::tempdir().unwrap();

        let canonical_read1 = std::fs::canonicalize(read_tmp1.path()).unwrap();
        let canonical_read2 = std::fs::canonicalize(read_tmp2.path()).unwrap();
        let canonical_write1 = std::fs::canonicalize(write_tmp1.path()).unwrap();
        let canonical_write2 = std::fs::canonicalize(write_tmp2.path()).unwrap();

        std::fs::write(canonical_read1.join("file1.txt"), "content1").unwrap();
        std::fs::write(canonical_read2.join("file2.txt"), "content2").unwrap();

        let cmd = format!(
            "cat '{r1}/file1.txt' && cat '{r2}/file2.txt' && \
             echo w1 > '{w1}/out1.txt' && echo w2 > '{w2}/out2.txt'",
            r1 = canonical_read1.display(),
            r2 = canonical_read2.display(),
            w1 = canonical_write1.display(),
            w2 = canonical_write2.display(),
        );

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--allow-read",
                &canonical_read1.to_string_lossy(),
                "--allow-read",
                &canonical_read2.to_string_lossy(),
                "--allow-write",
                &canonical_write1.to_string_lossy(),
                "--allow-write",
                &canonical_write2.to_string_lossy(),
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "all four --allow-read/--allow-write paths should be accessible; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            canonical_write1.join("out1.txt").exists(),
            "write-tmp1 output file should exist"
        );
        assert!(
            canonical_write2.join("out2.txt").exists(),
            "write-tmp2 output file should exist"
        );
    }

    /// `--allow-read` and `--allow-write` for different sibling paths
    /// simultaneously — both are accessible with their respective permission levels.
    #[test]
    fn allow_read_and_write_different_paths_simultaneously() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let read_tmp = tempfile::tempdir().unwrap();
        let write_tmp = tempfile::tempdir().unwrap();

        let canonical_read = std::fs::canonicalize(read_tmp.path()).unwrap();
        let canonical_write = std::fs::canonicalize(write_tmp.path()).unwrap();

        std::fs::write(canonical_read.join("data.txt"), "read_data").unwrap();
        let write_out = canonical_write.join("out.txt");

        let cmd = format!(
            "cat '{r}/data.txt' && echo written > '{w}'",
            r = canonical_read.display(),
            w = write_out.display(),
        );

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--allow-read",
                &canonical_read.to_string_lossy(),
                "--allow-write",
                &canonical_write.to_string_lossy(),
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "--allow-read and --allow-write for different paths should both work; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("read_data"),
            "stdout should contain the read file content, got: {stdout}"
        );
        assert!(write_out.exists(), "write output file should exist");
    }

    /// `--allow-write` combined with `--profile claude` — both the Claude
    /// profile paths and the CLI-supplied write path are accessible.
    #[test]
    fn allow_write_combined_with_profile_claude() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let write_tmp = tempfile::tempdir().unwrap();

        // Create ~/.claude/ under HOME (sandbox_tmp) so the claude profile
        // picks it up.
        let claude_dir = sandbox_tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let canonical_claude_dir = std::fs::canonicalize(&claude_dir).unwrap();

        let canonical_write = std::fs::canonicalize(write_tmp.path()).unwrap();
        let write_out = canonical_write.join("out.txt");
        let claude_marker = canonical_claude_dir.join("profile_marker.txt");

        let cmd = format!(
            "echo profile_write > '{c}' && echo cli_write > '{w}'",
            c = claude_marker.display(),
            w = write_out.display(),
        );

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--profile",
                "claude",
                "--allow-write",
                &canonical_write.to_string_lossy(),
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .env("AIRLOCK_SANDBOX_ROOT", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "--allow-write combined with --profile claude should grant access to both; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            claude_marker.exists(),
            "claude profile dir should be writable (via --profile claude)"
        );
        assert!(
            write_out.exists(),
            "CLI-supplied --allow-write path should be writable"
        );
    }

    /// A relative path supplied to `--allow-write` is resolved against the
    /// process working directory.
    #[test]
    fn allow_write_relative_path_resolved_against_cwd() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let sibling_tmp = tempfile::tempdir().unwrap();

        let canonical_sibling = std::fs::canonicalize(sibling_tmp.path()).unwrap();
        let new_file = canonical_sibling.join("written.txt");
        let cmd = format!("echo written > '{}'", new_file.display());

        let sibling_name = canonical_sibling
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let parent = canonical_sibling.parent().unwrap();
        let canonical_sandbox = std::fs::canonicalize(sandbox_tmp.path()).unwrap();

        // Only run this test when both temp dirs share the same parent.
        if parent != canonical_sandbox.parent().unwrap_or(&canonical_sandbox) {
            return;
        }

        let relative_path = format!("../{sibling_name}");

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-config",
                "--no-daemon",
                "--allow-write",
                &relative_path,
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(&canonical_sandbox)
            .env("HOME", &canonical_sandbox)
            .env("AIRLOCK_SANDBOX_ROOT", &canonical_sandbox)
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "relative --allow-write path should be resolved against CWD; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            new_file.exists(),
            "file should have been created via relative --allow-write path"
        );
    }

    /// `--allow-write` works when `airlock.toml` is present — it adds to the
    /// config-file permissions rather than replacing them.
    #[test]
    fn allow_write_adds_to_config_file_permissions() {
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let sibling_tmp = tempfile::tempdir().unwrap();

        write_config(sandbox_tmp.path(), &restricted_agent_run_config());

        let canonical_sibling = std::fs::canonicalize(sibling_tmp.path()).unwrap();
        let new_file = canonical_sibling.join("written_via_config_run.txt");
        let cmd = format!("echo ok > '{}'", new_file.display());

        let output = Command::new(airlock_bin())
            .args([
                "run",
                "--no-daemon",
                "--allow-write",
                &canonical_sibling.to_string_lossy(),
                "--",
                "sh",
                "-c",
                &cmd,
            ])
            .current_dir(sandbox_tmp.path())
            .env("HOME", sandbox_tmp.path())
            .output()
            .expect("failed to run airlock");

        assert!(
            output.status.success(),
            "--allow-write should work alongside airlock.toml config; \
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            new_file.exists(),
            "file should have been created in --allow-write path even with airlock.toml present"
        );
    }
}
