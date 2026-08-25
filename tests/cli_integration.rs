//! CLI subcommand integration tests.
//!
//! Tests that verify the CLI binary handles all subcommands correctly,
//! using `std::process::Command` to invoke the actual `airlock` binary.

#![cfg(any(target_os = "macos", target_os = "linux"))]

mod e2e_helpers;

use std::process::Command;
use std::time::Duration;

use e2e_helpers::*;

/// Get the path to the `airlock` binary built by `cargo test`.
fn airlock_bin() -> std::path::PathBuf {
    // `cargo test` places the binary in target/debug/ next to the test binary.
    let mut path = std::env::current_exe().expect("failed to get test exe path");
    // Go up from the test binary to the deps dir, then to debug dir.
    path.pop(); // remove test binary name
    if path.ends_with("deps") {
        path.pop(); // remove "deps"
    }
    path.push("airlock");
    assert!(
        path.exists(),
        "airlock binary not found at {:?}. Run `cargo build` first.",
        path
    );
    path
}

// ─── airlock daemon run starts and is stoppable ─────────────────────────────

#[test]
fn cli_daemon_run_starts_and_is_stoppable() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let pid_path = canonical_tmp.join("airlock.pid");
    let socket_path = canonical_tmp.join("airlock.sock");

    // Start the daemon via CLI in the background.
    let mut child = Command::new(airlock_bin())
        .args(["daemon", "run"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to spawn airlock daemon run");

    // Wait for PID file to appear.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !pid_path.exists() {
        if std::time::Instant::now() > deadline {
            child.kill().ok();
            panic!("daemon did not create PID file within timeout");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Verify socket exists.
    assert!(socket_path.exists(), "socket file should exist");

    // Stop the daemon with SIGTERM.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }

    // Wait for the process to exit.
    let _status = child.wait().expect("failed to wait on child");
    // On Unix, SIGTERM causes the process to exit (potentially with signal exit status).
    // The important thing is it stopped.

    // Give a moment for cleanup.
    std::thread::sleep(Duration::from_millis(500));

    // PID and socket files should be removed.
    assert!(
        !pid_path.exists(),
        "PID file should be removed after SIGTERM"
    );
    assert!(
        !socket_path.exists(),
        "socket file should be removed after SIGTERM"
    );
}

// ─── airlock daemon stop stops a running daemon ─────────────────────────────

#[test]
fn cli_daemon_stop_stops_running_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let pid_path = canonical_tmp.join("airlock.pid");

    // Start the daemon.
    let mut child = Command::new(airlock_bin())
        .args(["daemon", "run"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to spawn daemon");

    // Wait for ready.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !pid_path.exists() {
        if std::time::Instant::now() > deadline {
            child.kill().ok();
            panic!("daemon did not create PID file");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Reap the child process in a background thread so it doesn't become a zombie.
    // `airlock daemon stop` uses `kill(pid, 0)` to detect when the daemon dies,
    // which returns 0 for zombies, causing a false "still alive" detection.
    let reaper = std::thread::spawn(move || child.wait());

    // Run `airlock daemon stop` to stop it.
    let stop_output = Command::new(airlock_bin())
        .args(["daemon", "stop"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock daemon stop");

    assert!(
        stop_output.status.success(),
        "airlock daemon stop should succeed, stderr: {}",
        String::from_utf8_lossy(&stop_output.stderr)
    );

    // Wait for the reaper thread to finish.
    let _ = reaper.join();

    // Verify cleanup.
    std::thread::sleep(Duration::from_millis(500));
    assert!(!pid_path.exists(), "PID file should be cleaned up");
}

// ─── airlock daemon stop handles stale PID files ────────────────────────────

#[test]
fn cli_daemon_stop_handles_stale_pid_file() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let pid_path = canonical_tmp.join("airlock.pid");
    let socket_path = canonical_tmp.join("airlock.sock");

    // Write a stale PID file with a dead process.
    std::fs::write(&pid_path, "999999999\n").unwrap();
    std::fs::write(&socket_path, "stale-socket").unwrap();

    // Run `airlock daemon stop`.
    let output = Command::new(airlock_bin())
        .args(["daemon", "stop"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock daemon stop");

    assert!(
        output.status.success(),
        "airlock daemon stop should succeed with stale PID file, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Stale files should be cleaned up.
    assert!(!pid_path.exists(), "stale PID file should be cleaned up");
}

// ─── airlock status: running (exit 0) vs not running (exit 1) ───────────────

#[test]
fn cli_status_not_running_exits_1() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    // No daemon running.
    let output = Command::new(airlock_bin())
        .args(["status"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock status");

    assert!(
        !output.status.success(),
        "airlock status should exit with failure when daemon is not running"
    );
}

#[test]
fn cli_status_running_exits_0() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let pid_path = canonical_tmp.join("airlock.pid");

    // Start the daemon.
    let mut child = Command::new(airlock_bin())
        .args(["daemon", "run"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to spawn daemon");

    // Wait for ready.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !pid_path.exists() {
        if std::time::Instant::now() > deadline {
            child.kill().ok();
            panic!("daemon did not create PID file");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Check status.
    let output = Command::new(airlock_bin())
        .args(["status"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock status");

    assert!(
        output.status.success(),
        "airlock status should exit 0 when daemon is running, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout_str.contains("running"),
        "status output should mention 'running', got: {stdout_str}"
    );

    // Clean up: stop the daemon.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let _ = child.wait();
}

// ─── airlock list prints tool names and secret names without values ─────────

#[test]
fn cli_list_prints_tools_and_secret_names() {
    let tmp = tempfile::tempdir().unwrap();
    let config = config_with_tools(
        r#"
[secrets.SECRET_A]
source = "env"

[secrets.SECRET_B]
source = "env"

[tools.my_tool.env]
SECRET_A = { secret = "SECRET_A" }
SECRET_B = { secret = "SECRET_B" }

[tools.other_tool]
"#,
    );
    write_config(tmp.path(), &config);

    let output = Command::new(airlock_bin())
        .args(["list"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock list");

    assert!(
        output.status.success(),
        "airlock list should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain tool names.
    assert!(
        stdout.contains("my_tool"),
        "list should contain tool name 'my_tool', got: {stdout}"
    );
    assert!(
        stdout.contains("other_tool"),
        "list should contain tool name 'other_tool', got: {stdout}"
    );

    // Should contain secret names (env var names).
    assert!(
        stdout.contains("SECRET_A"),
        "list should contain secret name 'SECRET_A', got: {stdout}"
    );
    assert!(
        stdout.contains("SECRET_B"),
        "list should contain secret name 'SECRET_B', got: {stdout}"
    );

    // Should NOT contain any secret values.
    // (No secrets are set in the environment, so no values could leak.)
}

// ─── airlock logs retrieves and prints entries ──────────────────────────────

#[test]
fn cli_logs_retrieves_entries() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let pid_path = canonical_tmp.join("airlock.pid");

    // Start the daemon.
    let mut child = Command::new(airlock_bin())
        .args(["daemon", "run"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to spawn daemon");

    // Wait for ready.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !pid_path.exists() {
        if std::time::Instant::now() > deadline {
            child.kill().ok();
            panic!("daemon did not create PID file");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Fetch logs.
    let output = Command::new(airlock_bin())
        .args(["logs"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock logs");

    assert!(
        output.status.success(),
        "airlock logs should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("daemon started"),
        "logs should contain 'daemon started' entry, got: {stdout}"
    );

    // Clean up.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let _ = child.wait();
}

// ─── airlock init creates a new config file ─────────────────────────────────

#[test]
fn cli_init_creates_config_file() {
    let tmp = tempfile::tempdir().unwrap();

    let output = Command::new(airlock_bin())
        .args(["init"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock init");

    assert!(
        output.status.success(),
        "airlock init should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config_path = tmp.path().join("airlock.toml");
    assert!(config_path.exists(), "airlock.toml should be created");

    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        content.contains("Airlock configuration"),
        "config should contain header comment, got: {content}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Created"),
        "stdout should confirm file creation, got: {stdout}"
    );
}

// ─── airlock init refuses to overwrite existing config ──────────────────────

#[test]
fn cli_init_refuses_to_overwrite() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let output = Command::new(airlock_bin())
        .args(["init"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock init");

    assert!(
        !output.status.success(),
        "airlock init should fail when config already exists"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already exists"),
        "stderr should mention file already exists, got: {stderr}"
    );
}

// ─── `airlock run` helper configs ───────────────────────────────────────────

/// Config with a static [agent.env] entry.
fn agent_config_static_env(var: &str, value: &str) -> String {
    format!(
        "{base}\n[agent.env]\n{var} = \"{value}\"\n",
        base = config_with_sh_no_secrets()
    )
}

/// Config with a secret reference in [agent.env].
fn agent_config_secret_env(secret_label: &str, env_var: &str) -> String {
    format!(
        "{base}\n[secrets.{label}]\nsource = \"env\"\n\n[agent.env]\n{var} = {{ secret = \"{label}\" }}\n",
        base = config_with_sh_no_secrets(),
        label = secret_label,
        var = env_var
    )
}

/// Config with a passthrough_env entry.
fn agent_config_passthrough(var: &str) -> String {
    format!(
        "{base}\n[agent]\npassthrough_env = [\"{var}\"]\n",
        base = config_with_sh_no_secrets()
    )
}

/// Config with [agent] timeout (in seconds).
fn agent_config_with_timeout(seconds: u64) -> String {
    format!(
        "{base}\n[agent]\ntimeout = {seconds}\n",
        base = config_with_sh_no_secrets()
    )
}

// ─── airlock run: lifecycle and exit code tests ──────────────────────────────

/// `airlock run --no-daemon -- true` exits with code 0.
#[test]
fn run_propagates_exit_code_zero() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "airlock run -- true should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `airlock run -- sh -c "exit 42"` propagates exit code 42.
#[test]
fn run_propagates_exit_code_nonzero() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "sh", "-c", "exit 42"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        !output.status.success(),
        "airlock run -- sh -c 'exit 42' should exit non-zero"
    );
    assert_eq!(
        output.status.code(),
        Some(42),
        "exit code should be 42, got: {:?}",
        output.status.code()
    );
}

/// When no `airlock.toml` exists, `airlock run` exits non-zero and stderr
/// mentions `airlock init`.
#[test]
fn run_without_config_exits_with_error() {
    let tmp = tempfile::tempdir().unwrap();
    // No config written.

    let output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        !output.status.success(),
        "airlock run without config should exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("airlock init"),
        "stderr should mention 'airlock init', got: {stderr}"
    );
}

/// With `--no-daemon`, no socket file is created at any point.
#[test]
fn run_no_daemon_leaves_no_socket() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let canonical = std::fs::canonicalize(tmp.path()).unwrap();
    let socket_path = canonical.join("airlock.sock");

    assert!(!socket_path.exists(), "socket should not exist before run");

    let _output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run --no-daemon");

    assert!(
        !socket_path.exists(),
        "socket should not exist after --no-daemon run"
    );
}

/// With `--no-daemon`, no PID file is created at any point.
#[test]
fn run_no_daemon_leaves_no_pid_file() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let canonical = std::fs::canonicalize(tmp.path()).unwrap();
    let pid_path = canonical.join("airlock.pid");

    assert!(!pid_path.exists(), "PID file should not exist before run");

    let _output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run --no-daemon");

    assert!(
        !pid_path.exists(),
        "PID file should not exist after --no-daemon run"
    );
}

/// After `airlock run` (daemon mode) completes, the socket is removed.
#[test]
fn run_with_daemon_cleans_up_socket_on_exit() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let canonical = std::fs::canonicalize(tmp.path()).unwrap();
    let socket_path = canonical.join("airlock.sock");

    assert!(!socket_path.exists(), "socket should not exist before run");

    let output = Command::new(airlock_bin())
        .args(["run", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "airlock run -- true should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !socket_path.exists(),
        "socket should be removed after embedded daemon shuts down"
    );
}

/// The embedded daemon never writes a PID file. Absence is verified before
/// and after the run.
#[test]
fn run_with_daemon_leaves_no_pid_file() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let canonical = std::fs::canonicalize(tmp.path()).unwrap();
    let pid_path = canonical.join("airlock.pid");

    assert!(!pid_path.exists(), "PID file should not exist before run");

    let output = Command::new(airlock_bin())
        .args(["run", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "airlock run -- true should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !pid_path.exists(),
        "embedded daemon should never write a PID file"
    );
}

/// Regression: a SIGTERM delivered to the `airlock run` process must not tear
/// down the embedded daemon while the agent is still alive.
///
/// `airlock run` runs the embedded daemon in the *same process* as the
/// orchestrator. SIGTERM is the orchestrator's concern — `signal_loop`
/// forwards it to the agent. If the embedded daemon also reacted to SIGTERM it
/// would remove its own Unix socket while the agent (which may legitimately
/// ignore SIGTERM, as an interactive agent like Claude Code can) keeps
/// running, leaving the agent with no daemon to talk to.
///
/// The agent here traps and ignores SIGTERM; an `[agent] timeout` guarantees
/// the run is torn down regardless, so the test leaves nothing behind.
#[test]
fn run_sigterm_does_not_kill_embedded_daemon_while_agent_alive() {
    use std::io::BufRead;

    let tmp = tempfile::tempdir().unwrap();
    // `[agent] timeout = 6` is the cleanup mechanism: the agent ignores
    // SIGTERM, so signal_loop's timeout path is what eventually ends the run.
    write_config(tmp.path(), &agent_config_with_timeout(6));

    let canonical = std::fs::canonicalize(tmp.path()).unwrap();
    let socket_path = canonical.join("airlock.sock");

    // Agent: arms a SIGTERM trap to ignore the signal, announces readiness
    // *after* the trap is in place, then loops until the `[agent] timeout`
    // ends the run. The `sleep 1` keeps any orphan window short.
    let mut child = Command::new(airlock_bin())
        .args([
            "run",
            "--",
            "sh",
            "-c",
            "trap '' TERM; echo AGENT_READY; while true; do sleep 1; done",
        ])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to spawn airlock run");

    // Wait until the agent has *armed its trap*. The socket is bound before
    // the agent is even spawned, so it is not a sufficient readiness signal —
    // sending SIGTERM before the trap is in place would just kill the agent.
    // Read the agent's marker line on a side thread so the wait is bounded.
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut line = String::new();
        if std::io::BufReader::new(stdout).read_line(&mut line).is_ok() {
            let _ = tx.send(line);
        }
    });
    let ready = matches!(
        rx.recv_timeout(Duration::from_secs(15)),
        Ok(ref l) if l.trim() == "AGENT_READY"
    );
    if !ready {
        unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
        child.wait().ok();
        panic!(
            "agent never reported readiness — airlock run could not start the \
             sandboxed agent in this environment"
        );
    }

    assert!(
        socket_path.exists(),
        "daemon socket should be bound once the agent is up"
    );

    // Deliver SIGTERM to the `airlock run` process. signal_loop forwards it to
    // the agent, which ignores it — so the daemon must stay up.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };

    // Give a buggy daemon time to tear itself down if it were going to.
    std::thread::sleep(Duration::from_secs(2));

    // Capture state before asserting so cleanup always runs.
    let socket_survived = socket_path.exists();
    let run_still_alive = child.try_wait().ok().flatten().is_none();

    // The `[agent] timeout` tears the run down on its own; wait for it so no
    // agent or daemon process is left behind. Force-kill as a last resort.
    let cleanup_deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() > cleanup_deadline {
                    unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
                    child.wait().ok();
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }

    assert!(
        run_still_alive,
        "precondition: airlock run must still be alive 2s after SIGTERM \
         (the agent ignores SIGTERM); the test scenario is invalid otherwise"
    );
    assert!(
        socket_survived,
        "embedded daemon socket must survive a SIGTERM while the agent is \
         still alive — the daemon must not tear itself down on SIGTERM"
    );
}

// ─── airlock run: environment isolation tests ────────────────────────────────

/// The agent always receives `AIRLOCK_SANDBOX=1`.
#[test]
fn airlock_sandbox_var_set_in_agent() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let output = Command::new(airlock_bin())
        .args([
            "run",
            "--no-daemon",
            "--",
            "sh",
            "-c",
            "echo AIRLOCK_SANDBOX=$AIRLOCK_SANDBOX",
        ])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "command should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("AIRLOCK_SANDBOX=1"),
        "agent stdout should contain 'AIRLOCK_SANDBOX=1', got: {stdout}"
    );
}

/// A credential-like env var set in the test process does not appear in the
/// agent's environment when it is not listed in `passthrough_env` or `[agent.env]`.
#[test]
fn host_credential_absent_in_agent() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    // Set a fake credential in the current process env.
    let _guard = EnvGuard::new(&[("GITHUB_TOKEN", "test_credential_should_not_leak")]);

    let output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "sh", "-c", "env"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "command should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("GITHUB_TOKEN="),
        "GITHUB_TOKEN should not appear in agent env, stdout: {stdout}"
    );
}

/// `GITHUB_TOKEN` set on the host is not visible in the agent environment
/// when `--passthrough-env GITHUB_TOKEN` is not supplied.
///
/// Specifically tests the `--passthrough-env` boundary: the token is present
/// in the host environment but the flag is absent, so the token must stay out
/// of the sandboxed agent's environment.
#[test]
fn github_token_absent_without_passthrough_env_flag() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    // Set GITHUB_TOKEN on the test process — simulating a CI environment.
    let _guard = EnvGuard::new(&[("GITHUB_TOKEN", "ghp_secret_token_must_not_leak")]);

    let output = Command::new(airlock_bin())
        // No --passthrough-env GITHUB_TOKEN flag supplied.
        .args(["run", "--no-daemon", "--", "sh", "-c", "env"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "command should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("GITHUB_TOKEN="),
        "GITHUB_TOKEN must not appear in agent env without --passthrough-env GITHUB_TOKEN; \
         stdout: {stdout}"
    );
}

/// A static `[agent.env]` entry is visible in the agent's environment.
#[test]
fn agent_env_static_value_available() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(
        tmp.path(),
        &agent_config_static_env("MY_STATIC_AGENT_VAR", "hello_static_value"),
    );

    let output = Command::new(airlock_bin())
        .args([
            "run",
            "--no-daemon",
            "--",
            "sh",
            "-c",
            "echo MY_STATIC_AGENT_VAR=$MY_STATIC_AGENT_VAR",
        ])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "command should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("MY_STATIC_AGENT_VAR=hello_static_value"),
        "agent stdout should contain static value, got: {stdout}"
    );
}

/// A `{ secret = "…" }` reference in `[agent.env]` is resolved and injected.
#[test]
fn agent_env_secret_ref_available() {
    let tmp = tempfile::tempdir().unwrap();
    const SECRET_LABEL: &str = "TEST_RUN_SECRET_INJECT";
    const ENV_VAR: &str = "MY_INJECTED_SECRET_VAR";

    write_config(tmp.path(), &agent_config_secret_env(SECRET_LABEL, ENV_VAR));

    // Set the secret source env var in the current process so airlock can read it.
    let _guard = EnvGuard::new(&[(SECRET_LABEL, "mysecretvalue123")]);

    let output = Command::new(airlock_bin())
        .args([
            "run",
            "--no-daemon",
            "--",
            "sh",
            "-c",
            "echo MY_INJECTED_SECRET_VAR=$MY_INJECTED_SECRET_VAR",
        ])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "command should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("MY_INJECTED_SECRET_VAR=mysecretvalue123"),
        "agent stdout should contain resolved secret value, got: {stdout}"
    );
}

/// A variable listed in `passthrough_env` and set in the host process is
/// available inside the agent.
#[test]
fn passthrough_env_var_present() {
    let tmp = tempfile::tempdir().unwrap();
    const PASSTHROUGH_VAR: &str = "MY_AIRLOCK_PASSTHROUGH_PRESENT_VAR";
    write_config(tmp.path(), &agent_config_passthrough(PASSTHROUGH_VAR));

    let _guard = EnvGuard::new(&[(PASSTHROUGH_VAR, "passed_through_value")]);

    let output = Command::new(airlock_bin())
        .args([
            "run",
            "--no-daemon",
            "--",
            "sh",
            "-c",
            "echo MY_AIRLOCK_PASSTHROUGH_PRESENT_VAR=$MY_AIRLOCK_PASSTHROUGH_PRESENT_VAR",
        ])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "command should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("MY_AIRLOCK_PASSTHROUGH_PRESENT_VAR=passed_through_value"),
        "passthrough var should appear in agent env, got: {stdout}"
    );
}

/// A variable listed in `passthrough_env` but absent from the host process
/// does not appear in the agent env — not even as an empty string.
#[test]
fn passthrough_env_var_absent() {
    let tmp = tempfile::tempdir().unwrap();
    const ABSENT_VAR: &str = "MY_AIRLOCK_PASSTHROUGH_ABSENT_VAR_XYZ99";
    write_config(tmp.path(), &agent_config_passthrough(ABSENT_VAR));

    let output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "sh", "-c", "env"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        // Explicitly remove the variable so it is not inherited from the test env.
        .env_remove(ABSENT_VAR)
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "command should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(&format!("{ABSENT_VAR}=")),
        "absent passthrough var should not appear in agent env, got: {stdout}"
    );
}

// ─── airlock run: timeout test ───────────────────────────────────────────────

/// When `[agent] timeout = 1` is set and the agent runs `sleep 60`, `airlock run`
/// kills the agent within a few seconds and exits non-zero.
#[test]
fn run_timeout_kills_agent() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &agent_config_with_timeout(1));

    let output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "sleep", "60"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        !output.status.success(),
        "airlock run should exit non-zero when agent is killed by timeout"
    );
}

// ─── airlock run: global --config flag tests ─────────────────────────────────

/// `airlock --config <path> run --no-daemon -- true` succeeds when invoked
/// from a different working directory.
#[test]
fn config_flag_overrides_discovery() {
    let config_dir = tempfile::tempdir().unwrap();
    let other_dir = tempfile::tempdir().unwrap();
    write_config(config_dir.path(), &config_with_sh_no_secrets());

    let canonical_config = std::fs::canonicalize(config_dir.path()).unwrap();
    let config_file = canonical_config.join("airlock.toml");

    let output = Command::new(airlock_bin())
        .args([
            "--config",
            config_file.to_str().unwrap(),
            "run",
            "--no-daemon",
            "--",
            "true",
        ])
        .current_dir(other_dir.path())
        .env("HOME", config_dir.path())
        .output()
        .expect("failed to run airlock --config run");

    assert!(
        output.status.success(),
        "airlock --config run should succeed from a different CWD, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `airlock --config <path> daemon start` puts the PID file in the config's
/// directory, not in the CWD.
#[test]
fn config_flag_works_for_daemon_start() {
    let config_dir = tempfile::tempdir().unwrap();
    let other_dir = tempfile::tempdir().unwrap();
    write_config(config_dir.path(), &config_with_sh_no_secrets());

    let canonical_config = std::fs::canonicalize(config_dir.path()).unwrap();
    let config_file = canonical_config.join("airlock.toml");
    let pid_path = canonical_config.join("airlock.pid");

    // Start the daemon from a different CWD with explicit --config.
    let start_output = Command::new(airlock_bin())
        .args(["--config", config_file.to_str().unwrap(), "daemon", "start"])
        .current_dir(other_dir.path())
        .env("HOME", config_dir.path())
        .output()
        .expect("failed to run airlock daemon start");

    assert!(
        start_output.status.success(),
        "daemon start should succeed, stderr: {}",
        String::from_utf8_lossy(&start_output.stderr)
    );

    // PID file should be in config_dir, not other_dir.
    assert!(
        pid_path.exists(),
        "PID file should appear in the config directory"
    );
    assert!(
        !other_dir.path().join("airlock.pid").exists(),
        "PID file should NOT appear in the CWD"
    );

    // Clean up: stop the daemon.
    Command::new(airlock_bin())
        .args(["--config", config_file.to_str().unwrap(), "daemon", "stop"])
        .current_dir(other_dir.path())
        .env("HOME", config_dir.path())
        .output()
        .ok();
    // Give the daemon a moment to shut down.
    std::thread::sleep(Duration::from_millis(300));
}

/// `airlock --config <path> status` exits 0 and reports "running" when a daemon
/// is found via the explicit config path from a different CWD.
#[test]
fn config_flag_works_for_status() {
    let config_dir = tempfile::tempdir().unwrap();
    let other_dir = tempfile::tempdir().unwrap();
    write_config(config_dir.path(), &config_with_sh_no_secrets());

    let canonical_config = std::fs::canonicalize(config_dir.path()).unwrap();
    let config_file = canonical_config.join("airlock.toml");
    let pid_path = canonical_config.join("airlock.pid");

    // Start the daemon in config_dir.
    let start_output = Command::new(airlock_bin())
        .args(["--config", config_file.to_str().unwrap(), "daemon", "start"])
        .current_dir(config_dir.path())
        .env("HOME", config_dir.path())
        .output()
        .expect("failed to start daemon");

    assert!(
        start_output.status.success(),
        "daemon start should succeed, stderr: {}",
        String::from_utf8_lossy(&start_output.stderr)
    );
    assert!(
        pid_path.exists(),
        "PID file should exist after daemon start"
    );

    // Check status from other_dir using --config.
    let status_output = Command::new(airlock_bin())
        .args(["--config", config_file.to_str().unwrap(), "status"])
        .current_dir(other_dir.path())
        .env("HOME", config_dir.path())
        .output()
        .expect("failed to run airlock status");

    assert!(
        status_output.status.success(),
        "status should exit 0 when daemon is found via --config, stderr: {}",
        String::from_utf8_lossy(&status_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&status_output.stdout);
    assert!(
        stdout.contains("running"),
        "status output should mention 'running', got: {stdout}"
    );

    // Clean up.
    Command::new(airlock_bin())
        .args(["--config", config_file.to_str().unwrap(), "daemon", "stop"])
        .current_dir(other_dir.path())
        .env("HOME", config_dir.path())
        .output()
        .ok();
    std::thread::sleep(Duration::from_millis(300));
}

// ─── airlock run: existing daemon behaviour ───────────────────────────────────
//
// These two tests each run `start_daemon()`, which launches an in-process
// foreground daemon via `run_foreground`. Because `run_foreground` writes the
// test binary's own PID to the PID file, `DaemonHandle::shutdown()` sends
// SIGTERM to the test process itself — which wakes every tokio SIGTERM receiver
// currently installed in this process. If both tests run concurrently, one
// test's shutdown fires the other test's daemon's SIGTERM handler, causing it
// to exit prematurely. The mutex ensures only one in-process daemon is alive
// at a time.
static IN_PROCESS_DAEMON_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// When a daemon is already running, `airlock run` warns on stderr and still
/// succeeds.
#[test]
fn run_existing_daemon_emits_warning() {
    let _guard = IN_PROCESS_DAEMON_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let handle = start_daemon(tmp.path());

    let run_output = Command::new(airlock_bin())
        .args(["run", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run with existing daemon");

    assert!(
        run_output.status.success(),
        "airlock run should still succeed when a daemon is already running, \
         stderr: {}",
        String::from_utf8_lossy(&run_output.stderr)
    );
    let stderr = String::from_utf8_lossy(&run_output.stderr);
    assert!(
        stderr.contains("warning") || stderr.contains("already running"),
        "stderr should contain a warning about the existing daemon, got: {stderr}"
    );

    handle.shutdown();
}

/// When a daemon is already running, `airlock run` does not stop it on exit.
#[test]
fn run_existing_daemon_does_not_stop_it() {
    let _guard = IN_PROCESS_DAEMON_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let handle = start_daemon(tmp.path());
    let pid_path = handle.pid_path.clone();

    // Run airlock run — it should complete without stopping the daemon.
    let _run_output = Command::new(airlock_bin())
        .args(["run", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run with existing daemon");

    // The daemon thread should still be alive.
    assert!(
        !handle.join_handle.is_finished(),
        "daemon thread should still be running after airlock run exits"
    );

    // The PID file should still exist.
    assert!(
        pid_path.exists(),
        "daemon PID file should still exist (daemon still running)"
    );

    handle.shutdown();
}

// ─── airlock run: config with no [agent] section ─────────────────────────────

/// When the config has only a `[tools]` section and no `[agent]` section,
/// `airlock run --no-daemon -- true` succeeds.
#[test]
fn run_with_tools_only_config_uses_defaults() {
    let tmp = tempfile::tempdir().unwrap();
    // config_with_sh_no_secrets() has [tools.sh] but no [agent] section.
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let output = Command::new(airlock_bin())
        .args(["run", "--no-daemon", "--", "true"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock run");

    assert!(
        output.status.success(),
        "run with no [agent] section should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ─── airlock exec propagates the correct exit code ──────────────────────────

#[test]
fn cli_exec_propagates_exit_code() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let pid_path = canonical_tmp.join("airlock.pid");

    // Start the daemon.
    let mut daemon = Command::new(airlock_bin())
        .args(["daemon", "run"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to spawn daemon");

    // Wait for ready.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !pid_path.exists() {
        if std::time::Instant::now() > deadline {
            daemon.kill().ok();
            panic!("daemon did not create PID file");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Execute a tool that exits with code 0.
    let output_ok = Command::new(airlock_bin())
        .args(["exec", "--", "sh", "-c", "echo success; exit 0"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock exec");

    assert!(
        output_ok.status.success(),
        "airlock exec with exit 0 should succeed"
    );
    let stdout = String::from_utf8_lossy(&output_ok.stdout);
    assert!(
        stdout.contains("success"),
        "should see tool output, got: {stdout}"
    );

    // Execute a tool that exits with code 42.
    let output_42 = Command::new(airlock_bin())
        .args(["exec", "--", "sh", "-c", "exit 42"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .output()
        .expect("failed to run airlock exec");

    assert!(
        !output_42.status.success(),
        "airlock exec with exit 42 should fail"
    );
    // On Unix, the exit code is available.
    if let Some(code) = output_42.status.code() {
        assert_eq!(code, 42, "exit code should be 42, got: {code}");
    }

    // Clean up.
    unsafe { libc::kill(daemon.id() as i32, libc::SIGTERM) };
    let _ = daemon.wait();
}

// ─── airlock exec exits when parent never closes stdin pipe ──────────────────

/// Regression test for [cmd_exec](src/main.rs) calling `rt.shutdown_background()`
/// after `block_on` returns.
///
/// `tokio::io::stdin()` schedules `read(2)` on a blocking thread that
/// `JoinHandle::abort` cannot interrupt (tokio-rs/tokio#589). Before the fix,
/// when `airlock exec` was invoked with its stdin connected to a pipe whose
/// write end never closed, the runtime's default `Drop` blocked forever
/// waiting for the parked reader and the client never exited.
///
/// The test reproduces the harness shape: spawn `airlock exec` with
/// `stdin = Stdio::piped()`, keep the parent's write end alive across the
/// wait, and assert the child exits within a few seconds.
#[test]
fn cli_exec_exits_when_stdin_pipe_never_closes() {
    use std::process::Stdio;

    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());

    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let pid_path = canonical_tmp.join("airlock.pid");

    // Start the daemon.
    let mut daemon = Command::new(airlock_bin())
        .args(["daemon", "run"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn daemon");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !pid_path.exists() {
        if std::time::Instant::now() > deadline {
            daemon.kill().ok();
            panic!("daemon did not create PID file");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Spawn `airlock exec` with stdin as a piped, never-closing pipe.
    // The `_stdin_writer` binding holds the parent's write end open across
    // the wait, matching a harness that wires its own stdin to the child
    // and never closes it.
    let mut child = Command::new(airlock_bin())
        .args(["exec", "--", "sh", "-c", "echo ok; exit 0"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn airlock exec");

    let _stdin_writer = child.stdin.take().expect("stdin should be piped");

    // The agent only runs `echo ok`, so under the fix this completes well
    // under a second. Without the fix the client hangs forever in
    // `Runtime::drop` waiting for the parked stdin reader.
    let exit_deadline = std::time::Instant::now() + Duration::from_secs(15);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if std::time::Instant::now() > exit_deadline {
                    child.kill().ok();
                    let _ = child.wait();
                    unsafe { libc::kill(daemon.id() as i32, libc::SIGTERM) };
                    let _ = daemon.wait();
                    panic!(
                        "airlock exec did not exit within 15s with an open stdin pipe — \
                         cmd_exec must detach the runtime via shutdown_background so the \
                         parked tokio stdin reader does not block process exit"
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                let _ = child.kill();
                unsafe { libc::kill(daemon.id() as i32, libc::SIGTERM) };
                let _ = daemon.wait();
                panic!("try_wait failed: {e}");
            }
        }
    };

    assert!(
        status.success(),
        "airlock exec should exit successfully, got: {:?}",
        status.code()
    );

    // Clean up.
    unsafe { libc::kill(daemon.id() as i32, libc::SIGTERM) };
    let _ = daemon.wait();
}
