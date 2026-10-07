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
        self.command(airlock_bin())
    }

    /// `program` with this fixture's environment and working directory.
    fn command(&self, program: &str) -> Command {
        let mut cmd = Command::new(program);
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

#[test]
fn trust_refuses_a_config_the_launch_would_refuse() {
    let fx = Fixture::new();
    fx.write_config(
        "[tools.echo]\n\n[agent]\nkits = [\"rust\"]\n\n[agent.env]\nCARGO_HOME = \"/x\"\n",
    );
    let output = fx.cmd().args(["trust", "-y"]).output().unwrap();
    assert_eq!(output.status.code(), Some(125));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("CARGO_HOME"), "{stderr}");
    assert!(!stdout.contains("trusted"), "{stdout}");
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

// A plain `env` from inside the agent runs the shim, which goes through the
// daemon: only the daemon-spawned `env` has the tool's `VIA`. No
// `--allow-read` for the dev build here, unlike the test above — `run`
// grants the agent the binary its shims call.
#[test]
#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
fn run_shims_a_tool_so_its_plain_name_goes_through_the_session() {
    let fx = Fixture::new();
    fx.write_config("[tools.env]\nshim = true\n\n[tools.env.env]\nVIA = \"daemon\"\n");
    let trust_output = fx.cmd().args(["trust", "--yes"]).output().unwrap();
    assert!(trust_output.status.success(), "{trust_output:?}");

    let output = fx
        .cmd()
        .env("AIRLOCK_TEST_IDLE_EXIT_SECS", "1")
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--", "/bin/sh", "-c", "env | grep '^VIA='"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "VIA=daemon\n");

    let shims = fx.runtime.path().join("shims");
    assert_eq!(std::fs::read_dir(&shims).unwrap().count(), 0);
}

// ─── Terminal ─────────────────────────────────────────────────────────────────

/// A fresh pseudo-terminal: its master, its slave, and the slave's path.
fn openpty() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd, String) {
    use rustix::fs::{Mode, OFlags};
    use rustix::pty::OpenptFlags;

    let master = rustix::pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    rustix::pty::grantpt(&master).unwrap();
    rustix::pty::unlockpt(&master).unwrap();
    let name = rustix::pty::ptsname(&master, Vec::new())
        .unwrap()
        .into_string()
        .unwrap();
    let slave =
        rustix::fs::open(name.as_str(), OFlags::RDWR | OFlags::NOCTTY, Mode::empty()).unwrap();
    (master, slave, name)
}

// The agent can reopen the terminal it was started on by name, but another
// pty — standing in for another terminal tab — only with `[agent] pty`.
#[test]
#[cfg(target_os = "macos")]
#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
fn run_agent_reaches_its_own_terminal_and_others_only_with_pty() {
    for (config, expected) in [
        (minimal_config(), 0),
        ("[tools.echo]\n\n[agent]\npty = true\n", 2),
    ] {
        let fx = Fixture::new();
        fx.write_config(config);
        let trust_output = fx.cmd().args(["trust", "--yes"]).output().unwrap();
        assert!(trust_output.status.success(), "{trust_output:?}");

        let (_own_master, own, _) = openpty();
        let (_other_master, _other, other) = openpty();
        let script = format!(r#"exec 3>"$(tty)" || exit 1; exec 4>{other} && exit 2; exit 0"#);
        let status = fx
            .cmd()
            .stdin(own.try_clone().unwrap())
            .stdout(own.try_clone().unwrap())
            .stderr(own)
            .args(["run", "--no-session", "--", "/bin/sh", "-c", &script])
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(expected), "config:\n{config}");
    }
}

// The relay end to end, with `sh` as the user's shell: the session leader
// of a pty, running `airlock run` in its foreground. Its agent reads a line
// typed at the terminal, provokes a reply the terminal sends only after the
// agent has exited, and leaves a process that writes after that. The line
// arrives; the reply is not left for the shell; the late write never
// reaches the terminal.
#[test]
#[cfg_attr(no_nested_sandbox, ignore = "needs a nestable sandbox")]
fn run_relays_the_terminal_and_leaves_the_shell_nothing() {
    use std::io::{Read, Write};
    use std::os::unix::process::CommandExt;

    let fx = Fixture::new();
    fx.write_config(minimal_config());
    let trust_output = fx.cmd().args(["trust", "--yes"]).output().unwrap();
    assert!(trust_output.status.success(), "{trust_output:?}");

    let (master, slave, _) = openpty();
    let agent = r#"IFS= read -r line; printf 'got[%s]\n' "$line"; printf '\033[6n'; (sleep 1; printf LATE) & exit 0"#;
    let shell = r#""$AIRLOCK" run --no-session -- /bin/sh -c "$AGENT"
stty -icanon -echo min 0 time 5; printf 'LEFT['; cat -v; printf ']'; sleep 2"#;
    let mut cmd = fx.command("/bin/sh");
    cmd.args(["-c", shell])
        .env("AIRLOCK", airlock_bin())
        .env("AGENT", agent)
        .stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave);
    // SAFETY: setsid and ioctl are raw syscalls, safe between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();

    // The terminal emulator: types a line, answers a cursor-position query
    // late (after the agent is gone) and a status query at once, in order.
    let mut term = std::fs::File::from(master);
    term.write_all(b"hello\r").unwrap();
    let mut screen = Vec::new();
    let mut buf = [0u8; 4096];
    let mut answered = (0, 0);
    loop {
        match term.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => screen.extend_from_slice(&buf[..n]),
        }
        let count = |q: &[u8]| screen.windows(q.len()).filter(|w| *w == q).count();
        if count(b"\x1b[6n") > answered.0 {
            answered.0 += 1;
            std::thread::sleep(std::time::Duration::from_millis(300));
            term.write_all(b"\x1b[5;1R").unwrap();
        }
        if count(b"\x1b[5n") > answered.1 {
            answered.1 += 1;
            term.write_all(b"\x1b[0n").unwrap();
        }
    }
    child.wait().unwrap();

    let screen = String::from_utf8_lossy(&screen);
    assert!(screen.contains("got[hello]"), "{screen:?}");
    assert!(screen.contains("LEFT[]"), "{screen:?}");
    assert!(!screen.contains("LATE"), "{screen:?}");
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
