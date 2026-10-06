//! Build script — captures git revision info at compile time.
//!
//! Sets two environment variables consumed by `main.rs` via `env!()`:
//!
//! - `GIT_HASH`: the short commit hash (e.g. "a1b2c3d"), or "unknown" if
//!   git is unavailable or the directory is not a git repo.
//! - `GIT_DIRTY`: "true" if the working tree has uncommitted changes,
//!   "false" otherwise.
//!
//! Build systems that know the revision but cannot run git can supply either
//! value directly as `AIRLOCK_GIT_HASH` / `AIRLOCK_GIT_DIRTY`. The Nix build
//! does: its sandbox has no git and builds from a store copy with no `.git`.
//!
//! It also sets the `no_nested_sandbox` cfg when the build runs where an OS
//! sandbox cannot be applied: inside an Airlock sandbox (`AIRLOCK_SANDBOX=1`;
//! macOS refuses to nest Seatbelt profiles) or wherever the builder says so
//! with `AIRLOCK_NO_NESTED_SANDBOX=1` (the Nix build sandbox). Tests that
//! apply a sandbox are ignored under that cfg and run everywhere else.

use std::env;
use std::process::Command;

// This is the build script, not the `airlock` daemon or client — it runs at
// compile time, once per build, long before any daemon process or session
// exists. The session-isolation lint (clippy.toml) is about the daemon's own
// process environment at request time; it doesn't apply here.
#[allow(
    clippy::disallowed_methods,
    reason = "build-time only: not daemon or client code, runs before any binary exists"
)]
fn main() {
    // Re-run if the git HEAD changes (new commit, checkout, etc.).
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-env-changed=AIRLOCK_GIT_HASH");
    println!("cargo:rerun-if-env-changed=AIRLOCK_GIT_DIRTY");
    println!("cargo:rerun-if-env-changed=AIRLOCK_SANDBOX");
    println!("cargo:rerun-if-env-changed=AIRLOCK_NO_NESTED_SANDBOX");
    println!("cargo:rustc-check-cfg=cfg(no_nested_sandbox)");

    let flag_set = |name: &str| env::var(name).is_ok_and(|v| v == "1");
    if flag_set("AIRLOCK_SANDBOX") || flag_set("AIRLOCK_NO_NESTED_SANDBOX") {
        println!("cargo:rustc-cfg=no_nested_sandbox");
    }

    let hash = env::var("AIRLOCK_GIT_HASH").unwrap_or_else(|_| {
        Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    });

    let dirty = env::var("AIRLOCK_GIT_DIRTY").unwrap_or_else(|_| {
        Command::new("git")
            .args(["diff", "--quiet", "HEAD"])
            .status()
            .map(|s| if s.success() { "false" } else { "true" })
            .unwrap_or("false")
            .to_string()
    });

    println!("cargo:rustc-env=GIT_HASH={hash}");
    println!("cargo:rustc-env=GIT_DIRTY={dirty}");
}
