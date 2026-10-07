//! `airlock run` integration tests.
//!
//! Most of what `run` does before spawning the agent — discovery, merge
//! validation, trust — needs neither a daemon nor a sandbox, so it is
//! tested here against the real binary. Anything past that point needs
//! either a real v2 daemon (not in this worktree — P2-G's rewrite lands at
//! the phase-2 merge) or a nestable sandbox (this session already runs
//! inside Airlock's own Seatbelt profile, and nested Seatbelt/Landlock is
//! rejected by the kernel) — those are written but `#[ignore]`d per the v2
//! implementation contract's environment rules.

#![allow(
    clippy::disallowed_methods,
    reason = "test harness drives the real binary via its own process env, not daemon request-path code"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn airlock_bin() -> &'static str {
    env!("CARGO_BIN_EXE_airlock")
}

/// Everything a discovery-and-trust test needs: a `$HOME`, XDG dirs under
/// it, a pre-created, correctly-moded runtime dir (so `anchors::validate`'s
/// ownership/mode checks pass without a daemon ever having run), and a
/// project directory.
struct Fixture {
    home: tempfile::TempDir,
    xdg_state: tempfile::TempDir,
    xdg_config: tempfile::TempDir,
    xdg_cache: tempfile::TempDir,
    runtime: tempfile::TempDir,
    project: tempfile::TempDir,
}

// A session this fixture started (or an automatic daemon still in its idle
// grace period) would otherwise keep the daemon running long after the
// test and its runtime dir are gone.
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.runtime.path().join("airlock.sock").exists() {
            let _ = self.cmd().args(["daemon", "stop", "--yes"]).output();
        }
    }
}

impl Fixture {
    fn new() -> Self {
        let runtime = tempfile::tempdir().unwrap();
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Fixture {
            home: tempfile::tempdir().unwrap(),
            xdg_state: tempfile::tempdir().unwrap(),
            xdg_config: tempfile::tempdir().unwrap(),
            xdg_cache: tempfile::tempdir().unwrap(),
            runtime,
            project: tempfile::tempdir().unwrap(),
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new(airlock_bin());
        cmd.env_clear();
        if let Ok(path) = std::env::var("PATH") {
            cmd.env("PATH", path);
        }
        cmd.env("HOME", self.home.path());
        cmd.env("XDG_STATE_HOME", self.xdg_state.path());
        cmd.env("XDG_CONFIG_HOME", self.xdg_config.path());
        cmd.env("XDG_CACHE_HOME", self.xdg_cache.path());
        cmd.env("AIRLOCK_TEST_RUNTIME_DIR", self.runtime.path());
        cmd.current_dir(self.project.path());
        cmd.stdin(std::process::Stdio::null());
        cmd
    }

    fn write_config(&self, content: &str) -> PathBuf {
        let path = self.project.path().join("airlock.toml");
        std::fs::write(&path, content).unwrap();
        path
    }
}

fn minimal_config() -> &'static str {
    "[tools.echo]\n"
}

// ─── No project config ────────────────────────────────────────────────────────

#[test]
fn run_without_project_config_names_init_and_no_project_config() {
    let fx = Fixture::new();
    let output = fx.cmd().args(["run", "--", "echo", "hi"]).output().unwrap();
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no airlock.toml"), "{stderr}");
    assert!(stderr.contains("airlock init"), "{stderr}");
    assert!(stderr.contains("--no-project-config"), "{stderr}");
}

// ─── Untrusted config, non-interactive ───────────────────────────────────────

#[test]
fn run_with_unapproved_config_noninteractive_refuses_and_points_to_trust() {
    let fx = Fixture::new();
    fx.write_config(minimal_config());
    let output = fx.cmd().args(["run", "--", "echo", "hi"]).output().unwrap();
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("is not trusted yet"), "{stderr}");
    assert!(
        stderr.contains("run `airlock trust` in a terminal to approve it"),
        "{stderr}"
    );
}

#[test]
fn run_no_command_and_no_profile_errors() {
    let fx = Fixture::new();
    fx.write_config(minimal_config());
    let output = fx.cmd().args(["run"]).output().unwrap();
    assert_eq!(output.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no command specified"));
}

// ─── Trust, then run (reaches the sandbox — needs a nestable sandbox) ───────

#[test]
#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
fn run_no_session_after_trust_runs_the_command() {
    let fx = Fixture::new();
    fx.write_config(minimal_config());

    let trust_output = fx.cmd().args(["trust", "--yes"]).output().unwrap();
    assert!(trust_output.status.success(), "{trust_output:?}");

    let output = fx
        .cmd()
        .args(["run", "--no-session", "--", "/bin/echo", "hello"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
}

#[test]
#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
fn run_with_session_registers_and_execs_through_the_daemon() {
    let fx = Fixture::new();
    fx.write_config(minimal_config());
    let trust_output = fx.cmd().args(["trust", "--yes"]).output().unwrap();
    assert!(trust_output.status.success());

    let output = fx
        .cmd()
        .args(["run", "--", "/bin/echo", "hello"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

// The whole point of `airlock run`: the sandboxed agent reaches the daemon
// through `AIRLOCK_ADDR`/`AIRLOCK_SESSION` and runs a tool. The agent first
// outlives the 10-second request timeout the launcher's admin connection
// starts with — the lease must not inherit it, or the session ends under the
// agent. A dev build sits outside the agent's default read grants, hence
// `--allow-read` for its directory. `PATH` is pinned to the system's own
// binaries: a tool profile grants the tool binary but not the libraries a
// Nix or Homebrew build links from elsewhere, so the `echo` a dev shell puts
// first would need a `filesystem_read` this test has no reason to declare.
#[test]
#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
fn run_agent_execs_a_tool_through_its_session_after_ten_seconds() {
    let fx = Fixture::new();
    fx.write_config(minimal_config());
    let trust_output = fx.cmd().args(["trust", "--yes"]).output().unwrap();
    assert!(trust_output.status.success(), "{trust_output:?}");

    let bin_dir = Path::new(airlock_bin()).parent().unwrap();
    let agent_script = format!("sleep 11 && '{}' exec -- echo via-daemon", airlock_bin());
    let output = fx
        .cmd()
        .env("AIRLOCK_TEST_IDLE_EXIT_SECS", "1")
        .env("PATH", "/usr/bin:/bin")
        .arg("run")
        .arg("--allow-read")
        .arg(bin_dir)
        .args(["--", "/bin/sh", "-c", &agent_script])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "via-daemon\n");
}

// ─── Kits ─────────────────────────────────────────────────────────────────────
//
// `--no-session` keeps these focused on the sandbox + env the kit produces,
// the same way `run_no_session_after_trust_runs_the_command` does — no
// daemon round trip needed to prove what the agent can and cannot touch.

#[test]
#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
fn run_with_rust_kit_isolated_cannot_write_the_real_cargo_registry() {
    let fx = Fixture::new();
    fx.write_config("[agent]\nkits = [\"rust\"]\n");
    let trust_output = fx.cmd().args(["trust", "--yes"]).output().unwrap();
    assert!(trust_output.status.success(), "{trust_output:?}");

    // Pre-exists, as a real ~/.cargo/registry would on a machine that has
    // used cargo before — isolated mode must still refuse it.
    let real_registry = fx.home.path().join(".cargo/registry");
    std::fs::create_dir_all(&real_registry).unwrap();

    let script = r#"
        [ -n "$CARGO_HOME" ] || { echo NO_CARGO_HOME; exit 1; }
        case "$CARGO_HOME" in */kits/*) echo CARGO_HOME_IS_KIT_STATE ;; *) echo CARGO_HOME_WRONG ;; esac
        mkdir -p "$CARGO_HOME/registry" && echo ISOLATED_WRITE_OK
        (echo poison > "$HOME/.cargo/registry/marker" && echo REAL_REGISTRY_WRITE_OK) || echo REAL_REGISTRY_WRITE_DENIED
    "#;
    let output = fx
        .cmd()
        .args(["run", "--no-session", "--", "/bin/sh", "-c", script])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CARGO_HOME_IS_KIT_STATE"), "{stdout}");
    assert!(stdout.contains("ISOLATED_WRITE_OK"), "{stdout}");
    assert!(stdout.contains("REAL_REGISTRY_WRITE_DENIED"), "{stdout}");
    assert!(!stdout.contains("REAL_REGISTRY_WRITE_OK"), "{stdout}");
    assert!(!real_registry.join("marker").exists());
}

#[test]
#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
fn run_with_rust_kit_shared_via_global_config_writes_registry_reads_credentials_only() {
    let fx = Fixture::new();
    fx.write_config("[agent]\nkits = [\"rust\"]\n");

    // [kits.*] is global/local only — shared mode has to be set here, not
    // in the project's own airlock.toml.
    let global_dir = fx.xdg_config.path().join("airlock");
    std::fs::create_dir_all(&global_dir).unwrap();
    std::fs::write(
        global_dir.join("airlock.toml"),
        "[kits.rust]\nmode = \"shared\"\n",
    )
    .unwrap();

    let trust_output = fx.cmd().args(["trust", "--yes"]).output().unwrap();
    assert!(trust_output.status.success(), "{trust_output:?}");

    // A real ~/.cargo as cargo itself would create it. Shared mode writes
    // only the caches; the user's config and registry credentials are
    // readable so private registries work, but never writable, and
    // ~/.cargo/bin is never writable.
    let cargo_home = fx.home.path().join(".cargo");
    std::fs::create_dir_all(cargo_home.join("bin")).unwrap();
    std::fs::write(cargo_home.join("bin/rustc"), b"real rustc").unwrap();
    std::fs::write(cargo_home.join("credentials.toml"), b"token = \"secret\"").unwrap();
    std::fs::write(cargo_home.join("config.toml"), b"[alias]\n").unwrap();

    let script = r#"
        (echo ok > "$HOME/.cargo/registry/marker" && echo REGISTRY_WRITE_OK) || echo REGISTRY_WRITE_DENIED
        (echo poison > "$HOME/.cargo/bin/rustc" && echo BIN_WRITE_OK) || echo BIN_WRITE_DENIED
        (cat "$HOME/.cargo/credentials.toml" >/dev/null && echo CRED_READ_OK) || echo CRED_READ_DENIED
        (echo x >> "$HOME/.cargo/credentials.toml" && echo CRED_WRITE_OK) || echo CRED_WRITE_DENIED
        (echo x >> "$HOME/.cargo/config.toml" && echo CONFIG_WRITE_OK) || echo CONFIG_WRITE_DENIED
    "#;
    let output = fx
        .cmd()
        .args(["run", "--no-session", "--", "/bin/sh", "-c", script])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "REGISTRY_WRITE_OK",
        "BIN_WRITE_DENIED",
        "CRED_READ_OK",
        "CRED_WRITE_DENIED",
        "CONFIG_WRITE_DENIED",
    ] {
        assert!(stdout.contains(expected), "missing {expected}: {stdout}");
    }
    assert_eq!(
        std::fs::read(cargo_home.join("bin/rustc")).unwrap(),
        b"real rustc"
    );
    assert_eq!(
        std::fs::read(cargo_home.join("credentials.toml")).unwrap(),
        b"token = \"secret\""
    );
}

// Sanity check that the fixture's runtime dir is actually usable by
// `anchors::validate` the way the other tests assume (mode 0700, owned by
// us) — catches a fixture regression before it masquerades as a product
// bug in the tests above.
#[test]
fn fixture_runtime_dir_has_expected_mode() {
    let fx = Fixture::new();
    let mode = std::fs::metadata(fx.runtime.path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
    let _ = Path::new(".");
}
