//! Build script — captures git revision info at compile time.
//!
//! Sets two environment variables consumed by `main.rs` via `env!()`:
//!
//! - `GIT_HASH`: the short commit hash (e.g. "a1b2c3d"), or "unknown" if
//!   git is unavailable or the directory is not a git repo.
//! - `GIT_DIRTY`: "true" if the working tree has uncommitted changes,
//!   "false" otherwise.

use std::process::Command;

fn main() {
    // Re-run if the git HEAD changes (new commit, checkout, etc.).
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");

    let hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let dirty = Command::new("git")
        .args(["diff", "--quiet", "HEAD"])
        .status()
        .map(|s| if s.success() { "false" } else { "true" })
        .unwrap_or("false");

    println!("cargo:rustc-env=GIT_HASH={hash}");
    println!("cargo:rustc-env=GIT_DIRTY={dirty}");
}
