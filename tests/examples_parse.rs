//! Every file in `examples/` has to parse and merge under the real v2
//! schema, not just read as plausible TOML. This test loads each one
//! through the same public `airlock::layers` API a launcher uses, as the
//! layer kind the example is meant to occupy, and fails if the schema and
//! the examples have drifted apart.
//!
//! It needs no sandbox and no daemon: `layers::load_layers` only reads
//! files and hashes bytes, and `layers::merge` only parses TOML and
//! resolves paths as strings, so this runs the same everywhere `cargo
//! test` does.

use std::path::{Path, PathBuf};

use airlock::layers::{self, DiscoveryMode, LayerKind, MergeContext};

/// `examples/` relative to the crate root, regardless of the test binary's
/// own working directory.
fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples")
}

fn merge_context(root: PathBuf, home: PathBuf) -> MergeContext {
    MergeContext {
        root,
        tool_state_base: home.join(".cache").join("airlock"),
        home,
    }
}

/// A single-file example (`examples/*.toml`) is meant to be copied straight
/// to a project's `airlock.toml` — the repo layer, on its own, with no
/// global or local layer. Copy it into a scratch directory under that exact
/// name and run it through the same discovery + merge a launcher would.
fn assert_repo_example_merges(example: &Path) {
    // The project sits one level below the stand-in home: a project at home
    // itself would be refused without allow_home_root.
    let tmp = tempfile::tempdir().expect("tempdir");
    let project = tmp.path().join("project");
    std::fs::create_dir(&project).expect("create project dir");
    let bytes = std::fs::read(example).unwrap_or_else(|e| panic!("read {example:?}: {e}"));
    std::fs::write(project.join("airlock.toml"), bytes).expect("write airlock.toml");

    // No global layer: point at a path that doesn't exist, as a real
    // project with no ~/.config/airlock/airlock.toml would have.
    let no_global = tmp.path().join("no-global.toml");

    let layers = layers::load_layers(&DiscoveryMode::Default, &project, tmp.path(), &no_global)
        .unwrap_or_else(|e| panic!("{example:?}: load_layers failed: {e}"));

    assert!(
        layers.global.is_none(),
        "{example:?}: expected no global layer"
    );
    assert!(
        layers.local.is_none(),
        "{example:?}: expected no local layer"
    );
    let repo = layers
        .repo
        .as_ref()
        .unwrap_or_else(|| panic!("{example:?}: expected a repo layer"));
    assert_eq!(
        repo.kind,
        LayerKind::Repo,
        "{example:?}: expected the Repo layer kind"
    );

    let ctx = merge_context(layers.root.clone(), tmp.path().to_path_buf());
    layers::merge(&layers, &ctx).unwrap_or_else(|e| panic!("{example:?}: merge failed: {e}"));
}

#[test]
fn every_single_file_example_parses_and_merges_as_a_repo_layer() {
    let dir = examples_dir();
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}")) {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        // The `team/` trio is tested separately below: those three files
        // are meant to be read together, as three different layer kinds,
        // not each copied in as a standalone repo file.
        assert_repo_example_merges(&path);
        checked += 1;
    }
    assert!(
        checked >= 6,
        "expected several single-file examples under {dir:?}, found {checked}"
    );
}

/// `examples/team/` is the worked "team and personal config" example: a
/// repo file with unbound secret labels, a local file that binds them (one
/// with `from = "global"`, one with its own `command`), and a global file
/// the local file links to. Read individually, `team/airlock.toml` would
/// fail — its two labels have no source and nothing yet binds them, which
/// is exactly the first-run error the README and UX doc walk through. The
/// trio has to be read together, as the launcher would for this project.
#[test]
fn team_example_trio_merges_successfully() {
    let dir = examples_dir().join("team");
    let global_path = dir.join("global.toml");
    assert!(global_path.is_file(), "missing {global_path:?}");
    assert!(dir.join("airlock.toml").is_file());
    assert!(dir.join("airlock.local.toml").is_file());

    let layers = layers::load_layers(&DiscoveryMode::Default, &dir, &dir, &global_path)
        .unwrap_or_else(|e| panic!("team example: load_layers failed: {e}"));

    let global = layers
        .global
        .as_ref()
        .expect("team example: expected a global layer");
    assert_eq!(global.kind, LayerKind::Global);

    let repo = layers
        .repo
        .as_ref()
        .expect("team example: expected a repo layer");
    assert_eq!(repo.kind, LayerKind::Repo);

    let local = layers
        .local
        .as_ref()
        .expect("team example: expected a local layer");
    assert_eq!(local.kind, LayerKind::Local);

    let home = tempfile::tempdir().expect("tempdir");
    let ctx = merge_context(layers.root.clone(), home.path().to_path_buf());
    let merged =
        layers::merge(&layers, &ctx).unwrap_or_else(|e| panic!("team example: merge failed: {e}"));

    // Sanity check the merge actually combined all three layers, rather
    // than silently dropping one and happening to still succeed.
    let wire = merged.to_wire();
    let tools = wire.tools.unwrap_or_default();
    for name in ["gh", "tofu", "aws", "psql"] {
        assert!(
            tools.contains_key(name),
            "team example: merged config is missing tool {name:?} (have {:?})",
            tools.keys().collect::<Vec<_>>()
        );
    }
}
