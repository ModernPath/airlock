//! Integration tests for `exec::spawn()` and the kill helper.
//!
//! These tests verify OS-level behaviors that cannot be tested with unit tests:
//! process group placement, kill-tree signals, stdio streaming, sandbox
//! confinement, and file descriptor hygiene.
//!
//! Platform-specific tests are gated with `#[cfg(target_os = "...")]`.

// Only compile on macOS or Linux — the sandbox backends are not available elsewhere.
#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use airlock::exec::{
    ExecRequest, SpawnedChild, build_env, kill_process_group, resolve_binary, spawn,
};
use airlock::sandbox::{SandboxBackend, ToolPolicy};

#[cfg(target_os = "macos")]
use airlock::sandbox::macos::MacOSSeatbelt;

#[cfg(target_os = "linux")]
use airlock::sandbox::linux::LinuxLandlock;

// ─── Test helpers ─────────────────────────────────────────────────────────────

/// Build a permissive `ToolPolicy` suitable for tests that do not focus on
/// sandbox confinement.
///
/// Allows reading system library and config paths needed for any binary to
/// load and run, plus read/write access to `/tmp` and the test's temp
/// directory. Confinement tests build their own purpose-specific `ToolPolicy`
/// from scratch rather than using this helper.
fn permissive_policy(tmp_dir: &Path) -> ToolPolicy {
    let mut read_paths: Vec<PathBuf> = vec![
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
        PathBuf::from("/usr/local"),
        PathBuf::from("/dev"),
        PathBuf::from("/etc"),
    ];

    #[cfg(target_os = "macos")]
    {
        read_paths.extend([
            PathBuf::from("/System"),
            PathBuf::from("/Library"),
            PathBuf::from("/private/var"),
            PathBuf::from("/var"),
            PathBuf::from("/private/etc"),
            PathBuf::from("/Applications"),
            PathBuf::from("/usr/share"),
            PathBuf::from("/sbin"),
        ]);
    }

    #[cfg(target_os = "linux")]
    {
        for p in ["/lib", "/lib64", "/proc", "/sbin"] {
            if Path::new(p).exists() {
                read_paths.push(PathBuf::from(p));
            }
        }
    }

    // If Nix is installed, binaries and libraries live under /nix/store.
    // If Homebrew on Apple Silicon is installed, binaries live under /opt/homebrew.
    for p in ["/nix", "/opt"] {
        if Path::new(p).exists() {
            read_paths.push(PathBuf::from(p));
        }
    }

    ToolPolicy {
        read_paths,
        read_write_paths: vec![PathBuf::from("/tmp"), tmp_dir.to_path_buf()],
        requires_network: false,
        binary_path: None,
    }
}

/// Build a permissive `SandboxProfile` using the platform-specific backend.
fn build_permissive_profile(tmp_dir: &Path) -> airlock::sandbox::SandboxProfile {
    let policy = permissive_policy(tmp_dir);

    #[cfg(target_os = "macos")]
    {
        MacOSSeatbelt
            .build(&policy)
            .expect("failed to build permissive sandbox profile")
    }

    #[cfg(target_os = "linux")]
    {
        LinuxLandlock
            .build(&policy)
            .expect("failed to build permissive sandbox profile")
    }
}

/// Build an `ExecRequest` for running a shell command with the permissive policy.
fn shell_request(sh_cmd: &str, tmp_dir: &Path) -> ExecRequest {
    ExecRequest {
        binary: resolve_binary("sh").expect("sh should be in PATH"),
        args: vec!["-c".to_string(), sh_cmd.to_string()],
        work_dir: tmp_dir.to_path_buf(),
        env: build_env(&[]),
        sandbox_profile: build_permissive_profile(tmp_dir),
        timeout: Duration::from_secs(30),
    }
}

// ─── Process group placement tests ────────────────────────────────────────────

/// After spawn, the child's process group ID equals its own PID,
/// confirming that `setpgid(0, 0)` ran in the `pre_exec` closure.
#[tokio::test]
async fn child_pgid_equals_child_pid() {
    let tmp = tempfile::tempdir().unwrap();
    let request = shell_request("sleep 2", tmp.path());
    let mut spawned = spawn(request).expect("spawn should succeed");
    let child_pid = spawned.pid;

    // Allow the child's process group to be established.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // SAFETY: getpgid reads kernel process state; no memory side effects.
    let pgid = unsafe { libc::getpgid(child_pid as i32) };
    assert!(pgid > 0, "getpgid should succeed, got {pgid}");
    assert_eq!(
        pgid, child_pid as i32,
        "child pgid ({pgid}) should equal child pid ({child_pid})"
    );

    // Cleanup.
    kill_process_group(child_pid, libc::SIGKILL).ok();
    spawned.child.wait().await.ok();
}

/// The daemon (test runner) process's own process group ID differs from
/// the child's process group ID — confirming the child is not in the
/// daemon's group.
#[tokio::test]
async fn child_pgid_differs_from_daemon_pgid() {
    let tmp = tempfile::tempdir().unwrap();
    let request = shell_request("sleep 2", tmp.path());
    let mut spawned = spawn(request).expect("spawn should succeed");
    let child_pid = spawned.pid;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let child_pgid = unsafe { libc::getpgid(child_pid as i32) };
    let daemon_pgid = unsafe { libc::getpgid(0) };

    assert!(child_pgid > 0, "child getpgid should succeed");
    assert!(daemon_pgid > 0, "daemon getpgid should succeed");
    assert_ne!(
        child_pgid, daemon_pgid,
        "child pgid ({child_pgid}) should differ from daemon pgid ({daemon_pgid})"
    );

    kill_process_group(child_pid, libc::SIGKILL).ok();
    spawned.child.wait().await.ok();
}

// ─── Kill-tree tests ──────────────────────────────────────────────────────────

/// Sending SIGTERM to the process group kills both the child and its grandchild.
#[tokio::test]
async fn kill_tree_terminates_child_and_grandchild() {
    let tmp = tempfile::tempdir().unwrap();
    let pid_file = tmp.path().join("grandchild.pid");
    let pid_file_str = pid_file.to_str().unwrap();

    // The child spawns a grandchild (sleep 600), writes its PID to a file,
    // then waits for the grandchild.
    let cmd = format!("sleep 600 & echo $! > '{pid_file_str}'; wait");
    let request = shell_request(&cmd, tmp.path());
    let mut spawned = spawn(request).expect("spawn should succeed");
    let child_pid = spawned.pid;

    // Wait for the grandchild PID file to be written with content.
    let mut gc_pid_str = String::new();
    for _ in 0..100 {
        if let Ok(content) = std::fs::read_to_string(&pid_file) {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                gc_pid_str = trimmed.to_string();
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        !gc_pid_str.is_empty(),
        "grandchild PID file should have been written"
    );
    let gc_pid: i32 = gc_pid_str
        .parse()
        .unwrap_or_else(|_| panic!("should parse grandchild PID from {gc_pid_str:?}"));
    assert!(gc_pid > 0, "grandchild PID should be positive");

    // Send SIGTERM to the entire process group.
    kill_process_group(child_pid, libc::SIGTERM).expect("kill should succeed");

    // Reap the child — this also confirms it exited. We must reap before
    // checking with kill(pid, 0) because zombies still respond to signal 0.
    let status = tokio::time::timeout(Duration::from_secs(5), spawned.child.wait())
        .await
        .expect("child should exit within 5 seconds after SIGTERM")
        .unwrap();
    assert!(
        !status.success(),
        "child should have non-zero exit after being killed"
    );

    // Wait briefly for the grandchild to be reaped by init/launchd after
    // its parent (the shell) exited.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify grandchild is gone (ESRCH).
    let gc_alive = unsafe { libc::kill(gc_pid, 0) };
    assert_ne!(
        gc_alive, 0,
        "grandchild should be terminated after SIGTERM to process group"
    );
}

/// Killing one process group does not affect a second independent process group.
#[tokio::test]
async fn kill_tree_does_not_affect_other_groups() {
    let tmp = tempfile::tempdir().unwrap();

    let request1 = shell_request("sleep 60", tmp.path());
    let request2 = shell_request("sleep 60", tmp.path());

    let mut spawned1 = spawn(request1).expect("spawn1 should succeed");
    let mut spawned2 = spawn(request2).expect("spawn2 should succeed");

    let pid1 = spawned1.pid;
    let pid2 = spawned2.pid;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Kill the first child's process group.
    kill_process_group(pid1, libc::SIGKILL).expect("kill should succeed");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify second child is still alive.
    let alive2 = unsafe { libc::kill(pid2 as i32, 0) };
    assert_eq!(
        alive2, 0,
        "second child should be unaffected by killing the first group"
    );

    // Cleanup.
    kill_process_group(pid2, libc::SIGKILL).ok();
    spawned1.child.wait().await.ok();
    spawned2.child.wait().await.ok();
}

// ─── Standard output streaming tests ──────────────────────────────────────────

/// Stdout receives the exact bytes written by the child.
#[tokio::test]
async fn stdout_receives_known_string() {
    let tmp = tempfile::tempdir().unwrap();
    let request = shell_request("echo hello_stdout", tmp.path());
    let mut spawned = spawn(request).expect("spawn should succeed");

    let mut buf = Vec::new();
    spawned.stdout.read_to_end(&mut buf).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&buf),
        "hello_stdout\n",
        "stdout should contain the exact output"
    );

    let status = spawned.child.wait().await.unwrap();
    assert!(status.success());
}

/// Stderr receives the exact bytes written by the child.
#[tokio::test]
async fn stderr_receives_known_string() {
    let tmp = tempfile::tempdir().unwrap();
    let request = shell_request("echo hello_stderr >&2", tmp.path());
    let mut spawned = spawn(request).expect("spawn should succeed");

    let mut buf = Vec::new();
    spawned.stderr.read_to_end(&mut buf).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&buf),
        "hello_stderr\n",
        "stderr should contain the exact output"
    );

    spawned.child.wait().await.unwrap();
}

/// When the child writes distinct content to stdout and stderr concurrently,
/// each stream is received correctly without interleaving.
#[tokio::test]
async fn stdout_and_stderr_distinct_content() {
    let tmp = tempfile::tempdir().unwrap();
    let request = shell_request("echo out_content; echo err_content >&2", tmp.path());
    let mut spawned = spawn(request).expect("spawn should succeed");

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();

    // Drain both streams concurrently.
    let (r1, r2) = tokio::join!(
        spawned.stdout.read_to_end(&mut stdout_buf),
        spawned.stderr.read_to_end(&mut stderr_buf),
    );
    r1.unwrap();
    r2.unwrap();

    assert_eq!(String::from_utf8_lossy(&stdout_buf), "out_content\n");
    assert_eq!(String::from_utf8_lossy(&stderr_buf), "err_content\n");

    spawned.child.wait().await.unwrap();
}

/// Output larger than a typical pipe buffer (>= 128 KB) is fully received
/// without truncation.
#[tokio::test]
async fn large_output_not_truncated() {
    let tmp = tempfile::tempdir().unwrap();
    // `head -c 131072 /dev/zero` produces exactly 128 KB of null bytes.
    let request = shell_request("head -c 131072 /dev/zero", tmp.path());
    let mut spawned = spawn(request).expect("spawn should succeed");

    let mut buf = Vec::new();
    spawned.stdout.read_to_end(&mut buf).await.unwrap();

    assert_eq!(
        buf.len(),
        131072,
        "should receive exactly 128 KB (131072 bytes), got {} bytes",
        buf.len()
    );

    let status = spawned.child.wait().await.unwrap();
    assert!(status.success(), "child should exit with code 0");
}

// ─── Standard input forwarding tests ──────────────────────────────────────────

/// `cat` reads from stdin and echoes to stdout; verify the echo matches
/// the input exactly.
#[tokio::test]
async fn stdin_cat_echoes_input() {
    let tmp = tempfile::tempdir().unwrap();
    let request = shell_request("cat", tmp.path());
    let spawned = spawn(request).expect("spawn should succeed");

    // Destructure to take ownership of individual handles so stdin can be
    // dropped independently.
    let SpawnedChild {
        pid: _,
        mut child,
        mut stdout,
        stderr: _,
        mut stdin,
    } = spawned;

    let input = b"hello from stdin\nline two\n";
    stdin.write_all(input).await.unwrap();
    drop(stdin); // Close the stdin pipe to signal EOF.

    let mut output = Vec::new();
    stdout.read_to_end(&mut output).await.unwrap();

    assert_eq!(output, input, "cat should echo stdin to stdout exactly");

    let status = child.wait().await.unwrap();
    assert!(status.success(), "cat should exit successfully after EOF");
}

/// When stdin is closed immediately (nothing written), the child sees EOF
/// and exits normally.
#[tokio::test]
async fn stdin_closed_immediately_child_exits_normally() {
    let tmp = tempfile::tempdir().unwrap();
    let request = shell_request("cat", tmp.path());
    let spawned = spawn(request).expect("spawn should succeed");

    let SpawnedChild {
        pid: _,
        mut child,
        mut stdout,
        stderr: _,
        stdin,
    } = spawned;

    // Drop stdin immediately — child sees EOF.
    drop(stdin);

    let mut output = Vec::new();
    stdout.read_to_end(&mut output).await.unwrap();

    assert!(
        output.is_empty(),
        "cat with immediate EOF should produce no output, got {} bytes",
        output.len()
    );

    let status = child.wait().await.unwrap();
    assert!(status.success(), "cat should exit 0 on immediate EOF");
}

// ─── Exit code tests ─────────────────────────────────────────────────────────

/// A command that exits with code 0 reports exit status 0.
#[tokio::test]
async fn exit_code_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let request = shell_request("true", tmp.path());
    let mut spawned = spawn(request).expect("spawn should succeed");

    let status = spawned.child.wait().await.unwrap();
    assert!(status.success(), "exit code should be 0");
    assert_eq!(status.code(), Some(0), "exit code should be exactly 0");
}

/// A command that exits with a non-zero code reports the exact code.
#[tokio::test]
async fn exit_code_nonzero() {
    let tmp = tempfile::tempdir().unwrap();
    let request = shell_request("exit 42", tmp.path());
    let mut spawned = spawn(request).expect("spawn should succeed");

    let status = spawned.child.wait().await.unwrap();
    assert!(!status.success(), "exit code should be non-zero");
    assert_eq!(status.code(), Some(42), "exit code should be exactly 42");
}

// ─── Timeout enforcement tests ────────────────────────────────────────────────

/// A long-running child can be killed promptly with SIGTERM via the kill helper.
#[tokio::test]
async fn kill_long_running_child_promptly() {
    let tmp = tempfile::tempdir().unwrap();
    let request = shell_request("sleep 600", tmp.path());
    let mut spawned = spawn(request).expect("spawn should succeed");
    let child_pid = spawned.pid;

    // Brief delay — well under 1 second.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Kill via the kill helper.
    kill_process_group(child_pid, libc::SIGTERM).expect("kill should succeed");

    // The child should exit promptly (well within 5 seconds).
    let status = tokio::time::timeout(Duration::from_secs(5), spawned.child.wait())
        .await
        .expect("child should exit within 5 seconds")
        .unwrap();

    assert!(!status.success(), "killed child should have non-zero exit");

    // Verify no process remains.
    let alive = unsafe { libc::kill(child_pid as i32, 0) };
    assert_ne!(alive, 0, "child should be gone after SIGTERM");
}

/// A child that ignores SIGTERM can be terminated with SIGKILL via a second
/// kill helper call.
#[tokio::test]
async fn sigkill_after_sigterm_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    // Set up a trap to ignore SIGTERM, then sleep.
    let request = shell_request("trap '' TERM; sleep 600", tmp.path());
    let mut spawned = spawn(request).expect("spawn should succeed");
    let child_pid = spawned.pid;

    // Wait for the trap to be set up.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Send SIGTERM — should be ignored by the child.
    kill_process_group(child_pid, libc::SIGTERM).ok();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Child should still be alive after SIGTERM.
    let alive_after_term = unsafe { libc::kill(child_pid as i32, 0) };
    assert_eq!(
        alive_after_term, 0,
        "child should still be alive after ignored SIGTERM"
    );

    // Send SIGKILL — cannot be caught or ignored.
    kill_process_group(child_pid, libc::SIGKILL).expect("SIGKILL should succeed");

    // Wait for the child to exit.
    let status = tokio::time::timeout(Duration::from_secs(5), spawned.child.wait())
        .await
        .expect("child should exit within 5 seconds after SIGKILL")
        .unwrap();

    assert!(!status.success(), "killed child should have non-zero exit");

    // Verify the process is gone.
    let alive_after_kill = unsafe { libc::kill(child_pid as i32, 0) };
    assert_ne!(alive_after_kill, 0, "child should be gone after SIGKILL");
}

// ─── Concurrent execution tests ──────────────────────────────────────────────

/// Two simultaneously spawned children have distinct PIDs and process group IDs.
#[tokio::test]
async fn concurrent_children_distinct_pgids() {
    let tmp = tempfile::tempdir().unwrap();

    let request1 = shell_request("sleep 5", tmp.path());
    let request2 = shell_request("sleep 5", tmp.path());

    let mut spawned1 = spawn(request1).expect("spawn1 should succeed");
    let mut spawned2 = spawn(request2).expect("spawn2 should succeed");

    let pid1 = spawned1.pid;
    let pid2 = spawned2.pid;

    assert_ne!(pid1, pid2, "children should have distinct PIDs");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let pgid1 = unsafe { libc::getpgid(pid1 as i32) };
    let pgid2 = unsafe { libc::getpgid(pid2 as i32) };

    assert!(pgid1 > 0, "getpgid for child1 should succeed");
    assert!(pgid2 > 0, "getpgid for child2 should succeed");
    assert_ne!(
        pgid1, pgid2,
        "children should have distinct process group IDs"
    );

    // Cleanup.
    kill_process_group(pid1, libc::SIGKILL).ok();
    kill_process_group(pid2, libc::SIGKILL).ok();
    spawned1.child.wait().await.ok();
    spawned2.child.wait().await.ok();
}

/// Killing one concurrent child's process group does not affect the other.
/// The surviving child's stdout can still be read.
#[tokio::test]
async fn kill_one_concurrent_child_other_unaffected() {
    let tmp = tempfile::tempdir().unwrap();

    let request1 = shell_request("sleep 60", tmp.path());
    let request2 = shell_request("echo survivor; sleep 60", tmp.path());

    let mut spawned1 = spawn(request1).expect("spawn1 should succeed");
    let mut spawned2 = spawn(request2).expect("spawn2 should succeed");

    let pid1 = spawned1.pid;
    let pid2 = spawned2.pid;

    // Give child2 time to write its output.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Kill child1's process group.
    kill_process_group(pid1, libc::SIGKILL).expect("kill should succeed");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify child2 is still alive.
    let alive2 = unsafe { libc::kill(pid2 as i32, 0) };
    assert_eq!(
        alive2, 0,
        "second child should be unaffected by killing the first group"
    );

    // Kill child2 so its stdout pipe closes, then read its output.
    kill_process_group(pid2, libc::SIGKILL).ok();

    let mut buf = Vec::new();
    spawned2.stdout.read_to_end(&mut buf).await.unwrap();
    assert!(
        String::from_utf8_lossy(&buf).contains("survivor"),
        "second child's output should be received: {:?}",
        String::from_utf8_lossy(&buf)
    );

    // Cleanup.
    spawned1.child.wait().await.ok();
    spawned2.child.wait().await.ok();
}

/// Both children's output is received by their respective callers without
/// cross-contamination.
#[tokio::test]
async fn concurrent_output_no_cross_contamination() {
    let tmp = tempfile::tempdir().unwrap();

    let request1 = shell_request("echo output_from_child_one", tmp.path());
    let request2 = shell_request("echo output_from_child_two", tmp.path());

    let mut spawned1 = spawn(request1).expect("spawn1 should succeed");
    let mut spawned2 = spawn(request2).expect("spawn2 should succeed");

    let mut buf1 = Vec::new();
    let mut buf2 = Vec::new();

    let (r1, r2) = tokio::join!(
        spawned1.stdout.read_to_end(&mut buf1),
        spawned2.stdout.read_to_end(&mut buf2),
    );
    r1.unwrap();
    r2.unwrap();

    assert_eq!(String::from_utf8_lossy(&buf1), "output_from_child_one\n");
    assert_eq!(String::from_utf8_lossy(&buf2), "output_from_child_two\n");

    spawned1.child.wait().await.ok();
    spawned2.child.wait().await.ok();
}

// ─── File descriptor hygiene tests (Linux only) ──────────────────────────────

/// Verify that the child does not inherit file descriptors from the parent
/// (daemon) beyond stdin/stdout/stderr — confirming CLOEXEC is applied to
/// inherited descriptors.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn child_does_not_inherit_parent_fds() {
    use std::os::unix::io::AsRawFd;

    let tmp = tempfile::tempdir().unwrap();

    // Open a dummy file in the parent — its fd should NOT appear in the child.
    let dummy_file = tmp.path().join("dummy.txt");
    std::fs::write(&dummy_file, "dummy content").unwrap();
    let dummy = std::fs::File::open(&dummy_file).unwrap();
    let dummy_fd = dummy.as_raw_fd();

    let request = shell_request("ls /proc/self/fd/", tmp.path());
    let mut spawned = spawn(request).expect("spawn should succeed");

    let mut buf = Vec::new();
    spawned.stdout.read_to_end(&mut buf).await.unwrap();

    let fd_listing = String::from_utf8_lossy(&buf);
    let child_fds: Vec<i32> = fd_listing
        .lines()
        .filter_map(|line| line.trim().parse::<i32>().ok())
        .collect();

    assert!(
        !child_fds.contains(&dummy_fd),
        "child should not inherit parent's fd {dummy_fd}; child fds: {child_fds:?}"
    );

    drop(dummy);
    spawned.child.wait().await.ok();
}

// ─── Sandbox confinement tests — macOS only ─────────────────────────────────

#[cfg(target_os = "macos")]
mod macos_sandbox {
    use super::*;

    /// Minimum read paths needed for a binary to load and execute on macOS.
    /// Includes system libraries, dyld shared cache, and device files.
    /// Also includes Nix store if present (for Nix-managed binaries).
    ///
    /// Intentionally excludes `/var` and `/private/var` — those broad paths
    /// would cover the denied temp directories used in confinement tests
    /// (which live under `/var/folders/`).
    fn execution_base_read_paths() -> Vec<PathBuf> {
        let mut paths = vec![
            PathBuf::from("/usr/lib"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
            PathBuf::from("/dev"),
            PathBuf::from("/System"),
            PathBuf::from("/Library"),
            PathBuf::from("/usr/share"),
        ];
        // Nix-managed binaries need /nix/store for libraries.
        for p in ["/nix", "/opt"] {
            if Path::new(p).exists() {
                paths.push(PathBuf::from(p));
            }
        }
        paths
    }

    /// A file read from a path NOT in the policy fails — verifying the
    /// sandbox denies access outside allowed paths.
    ///
    /// The denied path is a fresh temp directory that does not appear anywhere
    /// in the policy's allow lists.
    #[tokio::test]
    async fn sandbox_denies_read_outside_policy() {
        let allowed_dir = tempfile::tempdir().unwrap();
        let denied_dir = tempfile::tempdir().unwrap();

        // Write a file in the denied directory.
        let denied_file = denied_dir.path().join("secret.txt");
        std::fs::write(&denied_file, "secret data").unwrap();

        // Build policy allowing only allowed_dir — denied_dir is not included.
        let mut read_paths = execution_base_read_paths();
        read_paths.push(allowed_dir.path().to_path_buf());

        let policy = ToolPolicy {
            read_paths,
            read_write_paths: vec![allowed_dir.path().to_path_buf()],
            requires_network: false,
            binary_path: None,
        };

        let profile = MacOSSeatbelt
            .build(&policy)
            .expect("build profile should succeed");

        let cmd = format!("cat '{}'", denied_file.display());
        let request = ExecRequest {
            binary: resolve_binary("sh").unwrap(),
            args: vec!["-c".to_string(), cmd],
            work_dir: allowed_dir.path().to_path_buf(),
            env: build_env(&[]),
            sandbox_profile: profile,
            timeout: Duration::from_secs(10),
        };

        let mut spawned = spawn(request).expect("spawn should succeed");

        let mut stderr_buf = Vec::new();
        let (_, stderr_result) = tokio::join!(
            async {
                let mut stdout_buf = Vec::new();
                spawned.stdout.read_to_end(&mut stdout_buf).await.unwrap();
            },
            spawned.stderr.read_to_end(&mut stderr_buf),
        );
        stderr_result.unwrap();

        let status = spawned.child.wait().await.unwrap();
        let stderr_str = String::from_utf8_lossy(&stderr_buf);

        // The command should fail: either non-zero exit or permission error on stderr.
        assert!(
            !status.success()
                || stderr_str.contains("ermission denied")
                || stderr_str.contains("peration not permitted"),
            "reading outside policy should fail; status: {status:?}, stderr: {stderr_str:?}"
        );
    }

    /// A file read from a path IN the policy succeeds.
    #[tokio::test]
    async fn sandbox_allows_read_inside_policy() {
        let allowed_dir = tempfile::tempdir().unwrap();

        // Write a file in the allowed directory.
        let allowed_file = allowed_dir.path().join("allowed.txt");
        std::fs::write(&allowed_file, "allowed data").unwrap();

        let mut read_paths = execution_base_read_paths();
        read_paths.push(allowed_dir.path().to_path_buf());

        let policy = ToolPolicy {
            read_paths,
            read_write_paths: vec![allowed_dir.path().to_path_buf()],
            requires_network: false,
            binary_path: None,
        };

        let profile = MacOSSeatbelt
            .build(&policy)
            .expect("build profile should succeed");

        let cmd = format!("cat '{}'", allowed_file.display());
        let request = ExecRequest {
            binary: resolve_binary("sh").unwrap(),
            args: vec!["-c".to_string(), cmd],
            work_dir: allowed_dir.path().to_path_buf(),
            env: build_env(&[]),
            sandbox_profile: profile,
            timeout: Duration::from_secs(10),
        };

        let mut spawned = spawn(request).expect("spawn should succeed");

        let mut stdout_buf = Vec::new();
        spawned.stdout.read_to_end(&mut stdout_buf).await.unwrap();

        let status = spawned.child.wait().await.unwrap();
        assert!(status.success(), "reading allowed file should succeed");
        assert_eq!(
            String::from_utf8_lossy(&stdout_buf),
            "allowed data",
            "stdout should contain the file contents"
        );
    }

    /// A file write to a path NOT in the policy's write list fails.
    #[tokio::test]
    async fn sandbox_denies_write_outside_policy() {
        let allowed_dir = tempfile::tempdir().unwrap();
        let denied_dir = tempfile::tempdir().unwrap();

        // Build policy allowing write only to allowed_dir.
        let mut read_paths = execution_base_read_paths();
        read_paths.push(allowed_dir.path().to_path_buf());
        // Can read denied_dir (to resolve path) but cannot write to it.
        read_paths.push(denied_dir.path().to_path_buf());

        let policy = ToolPolicy {
            read_paths,
            read_write_paths: vec![allowed_dir.path().to_path_buf()],
            requires_network: false,
            binary_path: None,
        };

        let profile = MacOSSeatbelt
            .build(&policy)
            .expect("build profile should succeed");

        let denied_file = denied_dir.path().join("prohibited.txt");
        let cmd = format!("echo test > '{}'", denied_file.display());
        let request = ExecRequest {
            binary: resolve_binary("sh").unwrap(),
            args: vec!["-c".to_string(), cmd],
            work_dir: allowed_dir.path().to_path_buf(),
            env: build_env(&[]),
            sandbox_profile: profile,
            timeout: Duration::from_secs(10),
        };

        let mut spawned = spawn(request).expect("spawn should succeed");
        let status = spawned.child.wait().await.unwrap();

        // The write should fail.
        assert!(!status.success(), "writing to denied directory should fail");

        // Verify the file was not created.
        assert!(
            !denied_file.exists(),
            "file should not have been created in denied directory"
        );
    }
}

// ─── Sandbox confinement tests — Linux only ─────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_sandbox {
    use super::*;

    /// Minimum read paths needed for a binary to load on Linux.
    fn execution_base_read_paths() -> Vec<PathBuf> {
        let mut paths = vec![
            PathBuf::from("/usr/lib"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
            PathBuf::from("/dev"),
            PathBuf::from("/etc"),
        ];
        for p in ["/lib", "/lib64", "/nix", "/opt"] {
            if Path::new(p).exists() {
                paths.push(PathBuf::from(p));
            }
        }
        paths
    }

    /// A file read from a path NOT in the policy fails with permission denied.
    #[tokio::test]
    async fn landlock_denies_read_outside_policy() {
        let allowed_dir = tempfile::tempdir().unwrap();
        let denied_dir = tempfile::tempdir().unwrap();

        // Write a file in the denied directory.
        let denied_file = denied_dir.path().join("secret.txt");
        std::fs::write(&denied_file, "secret data").unwrap();

        let mut read_paths = execution_base_read_paths();
        read_paths.push(allowed_dir.path().to_path_buf());

        let policy = ToolPolicy {
            read_paths,
            read_write_paths: vec![allowed_dir.path().to_path_buf()],
            requires_network: false,
            binary_path: None,
        };

        let profile = LinuxLandlock
            .build(&policy)
            .expect("build profile should succeed");

        let cmd = format!("cat '{}'", denied_file.display());
        let request = ExecRequest {
            binary: resolve_binary("sh").unwrap(),
            args: vec!["-c".to_string(), cmd],
            work_dir: allowed_dir.path().to_path_buf(),
            env: build_env(&[]),
            sandbox_profile: profile,
            timeout: Duration::from_secs(10),
        };

        let mut spawned = spawn(request).expect("spawn should succeed");

        let mut stderr_buf = Vec::new();
        spawned.stderr.read_to_end(&mut stderr_buf).await.unwrap();

        let status = spawned.child.wait().await.unwrap();

        assert!(
            !status.success(),
            "reading outside policy should fail; stderr: {:?}",
            String::from_utf8_lossy(&stderr_buf)
        );
    }

    /// A file read from a path IN the policy succeeds.
    #[tokio::test]
    async fn landlock_allows_read_inside_policy() {
        let allowed_dir = tempfile::tempdir().unwrap();

        let allowed_file = allowed_dir.path().join("allowed.txt");
        std::fs::write(&allowed_file, "allowed data").unwrap();

        let mut read_paths = execution_base_read_paths();
        read_paths.push(allowed_dir.path().to_path_buf());

        let policy = ToolPolicy {
            read_paths,
            read_write_paths: vec![allowed_dir.path().to_path_buf()],
            requires_network: false,
            binary_path: None,
        };

        let profile = LinuxLandlock
            .build(&policy)
            .expect("build profile should succeed");

        let cmd = format!("cat '{}'", allowed_file.display());
        let request = ExecRequest {
            binary: resolve_binary("sh").unwrap(),
            args: vec!["-c".to_string(), cmd],
            work_dir: allowed_dir.path().to_path_buf(),
            env: build_env(&[]),
            sandbox_profile: profile,
            timeout: Duration::from_secs(10),
        };

        let mut spawned = spawn(request).expect("spawn should succeed");

        let mut stdout_buf = Vec::new();
        spawned.stdout.read_to_end(&mut stdout_buf).await.unwrap();

        let status = spawned.child.wait().await.unwrap();
        assert!(status.success(), "reading allowed file should succeed");
        assert_eq!(String::from_utf8_lossy(&stdout_buf), "allowed data",);
    }

    /// A file write to a path NOT in the policy's write list fails.
    #[tokio::test]
    async fn landlock_denies_write_outside_policy() {
        let allowed_dir = tempfile::tempdir().unwrap();
        let denied_dir = tempfile::tempdir().unwrap();

        let mut read_paths = execution_base_read_paths();
        read_paths.push(allowed_dir.path().to_path_buf());
        read_paths.push(denied_dir.path().to_path_buf());

        let policy = ToolPolicy {
            read_paths,
            read_write_paths: vec![allowed_dir.path().to_path_buf()],
            requires_network: false,
            binary_path: None,
        };

        let profile = LinuxLandlock
            .build(&policy)
            .expect("build profile should succeed");

        let denied_file = denied_dir.path().join("prohibited.txt");
        let cmd = format!("echo test > '{}'", denied_file.display());
        let request = ExecRequest {
            binary: resolve_binary("sh").unwrap(),
            args: vec!["-c".to_string(), cmd],
            work_dir: allowed_dir.path().to_path_buf(),
            env: build_env(&[]),
            sandbox_profile: profile,
            timeout: Duration::from_secs(10),
        };

        let mut spawned = spawn(request).expect("spawn should succeed");
        let status = spawned.child.wait().await.unwrap();

        assert!(!status.success(), "writing to denied directory should fail");
    }
}
