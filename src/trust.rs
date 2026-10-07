//! Config trust: approve project config by content, review changes, and
//! render the diffs and prompts a launcher or `airlock trust` shows the user.
//!
//! An agent runs as the user and can edit the project's `airlock.toml` or
//! `airlock.local.toml`. Those files can grant filesystem access and name
//! the commands that produce secrets, so Airlock never loads a changed file
//! without the user reviewing it first. This module holds the three pieces
//! that make that possible:
//!
//! - [`TrustStore`] — a copy of each approved file, keyed by project and
//!   file name, so a later load can diff against exactly what was approved.
//! - [`escape_for_terminal`] and [`render_review`] — turn a file's bytes (or
//!   a diff against the approved copy) into text that is safe to print: a
//!   TOML file can hold control characters, bidi overrides and zero-width
//!   characters that would otherwise make a diff read differently from what
//!   it does.
//! - [`decide`] and [`prompt_yes_no`] — the `--yes` / `--expect-sha256`
//!   decision for scripted approval, and the interactive prompt for a
//!   terminal.
//!
//! The daemon never reads project config, so none of this runs there: it is
//! all launcher-side (`airlock run`, `session start`, `session reload`,
//! `airlock trust`).

use std::io::{self, BufRead, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use similar::{ChangeTag, TextDiff};
use thiserror::Error;

// ─── Trust store ────────────────────────────────────────────────────────────

pub use crate::config::{project_id, sha256_hex};

/// Errors from reading or writing the trust store.
#[derive(Debug, Error)]
pub enum TrustError {
    /// An I/O error on a specific path.
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },

    /// A path inside the trust store is a symlink. The store is written only
    /// by Airlock itself (temp file + rename), so a symlink in it means
    /// something else wrote there; never follow it.
    #[error("{path} is a symlink; refusing to follow it inside the trust store")]
    Symlink { path: PathBuf },

    /// A path that must be a directory (or must not exist yet) is something
    /// else.
    #[error("{path} exists and is not a directory")]
    NotADirectory { path: PathBuf },
}

impl TrustError {
    fn io(path: &Path, source: io::Error) -> Self {
        TrustError::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

/// The approval state of a file's current bytes against the trust store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Approval {
    /// Current bytes match the approved copy.
    Approved,
    /// Current bytes differ from the approved copy, which is kept here so a
    /// diff can be shown.
    Changed { approved: Vec<u8> },
    /// No copy has ever been approved for this project and file name.
    New,
}

/// `$XDG_STATE_HOME/airlock/trust`, or wherever the caller resolved that
/// anchor to. Layout: `<dir>/<project_id>/root` (the canonical project root,
/// for debugging the store by hand) and `<dir>/<project_id>/<file_name>`
/// (the approved copy of that file).
#[derive(Debug)]
pub struct TrustStore {
    dir: PathBuf,
}

impl TrustStore {
    /// Opens the trust store rooted at `dir`, creating it (mode `0700`) if
    /// it does not exist yet.
    pub fn open(dir: &Path) -> Result<Self, TrustError> {
        ensure_dir(dir)?;
        Ok(TrustStore {
            dir: dir.to_path_buf(),
        })
    }

    /// The trust store's root directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn project_dir(&self, root: &Path) -> PathBuf {
        self.dir.join(project_id(root))
    }

    /// Compares `bytes` (the file's current contents) against the approved
    /// copy, if any, of the project rooted at `root`'s file named
    /// `file_name`.
    pub fn state(
        &self,
        root: &Path,
        file_name: &str,
        bytes: &[u8],
    ) -> Result<Approval, TrustError> {
        let copy_path = self.project_dir(root).join(file_name);
        match read_store_file(&copy_path)? {
            None => Ok(Approval::New),
            Some(approved) => {
                if approved == bytes {
                    Ok(Approval::Approved)
                } else {
                    Ok(Approval::Changed { approved })
                }
            }
        }
    }

    /// Records `bytes` as the approved copy of `file_name` for the project
    /// rooted at `root`. Writes via a temp file and `rename` in the same
    /// directory, so a reader never observes a partial file.
    pub fn approve(&self, root: &Path, file_name: &str, bytes: &[u8]) -> Result<(), TrustError> {
        let project_dir = self.project_dir(root);
        ensure_dir(&project_dir)?;
        write_store_file(&project_dir.join("root"), root.as_os_str().as_bytes())?;
        write_store_file(&project_dir.join(file_name), bytes)?;
        Ok(())
    }
}

/// Creates `dir` with mode `0700` if it does not exist. Refuses a symlink or
/// a non-directory at that path.
fn ensure_dir(dir: &Path) -> Result<(), TrustError> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => Err(TrustError::Symlink {
            path: dir.to_path_buf(),
        }),
        Ok(meta) if !meta.is_dir() => Err(TrustError::NotADirectory {
            path: dir.to_path_buf(),
        }),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir).map_err(|source| TrustError::io(dir, source))?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|source| TrustError::io(dir, source))?;
            Ok(())
        }
        Err(source) => Err(TrustError::io(dir, source)),
    }
}

/// Reads a file from inside the trust store, refusing to follow a symlink.
/// `Ok(None)` means the file has never been approved.
fn read_store_file(path: &Path) -> Result<Option<Vec<u8>>, TrustError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(TrustError::Symlink {
            path: path.to_path_buf(),
        }),
        Ok(_) => {
            let bytes = std::fs::read(path).map_err(|source| TrustError::io(path, source))?;
            Ok(Some(bytes))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(TrustError::io(path, source)),
    }
}

/// Writes `bytes` to `path` (mode `0600`) via a temp file and `rename` in
/// the same directory, so a concurrent reader sees either the old or the new
/// content, never a partial write.
fn write_store_file(path: &Path, bytes: &[u8]) -> Result<(), TrustError> {
    let dir = path
        .parent()
        .expect("trust store file path always has a parent directory");

    let mut attempt: u32 = 0;
    let (tmp_path, mut file) = loop {
        let tmp_path = dir.join(format!(".tmp-{}-{attempt}", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
        {
            Ok(file) => break (tmp_path, file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt < u32::MAX => {
                attempt += 1;
            }
            Err(source) => return Err(TrustError::io(&tmp_path, source)),
        }
    };

    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| TrustError::io(&tmp_path, source));
    drop(file);
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    std::fs::rename(&tmp_path, path).map_err(|source| TrustError::io(path, source))
}

// ─── Escaping ───────────────────────────────────────────────────────────────

/// Escapes characters that could make printed text read differently from
/// what it does: control characters (other than `\n` and `\t`), ANSI
/// escapes, C1 controls, bidirectional overrides and isolates, and
/// zero-width characters. Each is shown as `\u{...}` (Rust-style, lowercase
/// hex, no padding).
///
/// TOML strings and comments accept all of these, so a file is escaped
/// before it is ever printed for review: without this, an agent could write
/// a diff that the user reads one way while it parses another.
pub fn escape_for_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if needs_escape(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

fn needs_escape(c: char) -> bool {
    match c {
        '\n' | '\t' => false,
        // C0 controls, including ESC (0x1b), which starts an ANSI escape.
        c if (c as u32) < 0x20 => true,
        // DEL.
        '\u{7f}' => true,
        // C1 controls.
        c if ('\u{80}'..='\u{9f}').contains(&c) => true,
        // Zero-width space/joiners and the left-to-right/right-to-left marks.
        '\u{200b}'..='\u{200f}' => true,
        // Bidirectional embeddings and overrides.
        '\u{202a}'..='\u{202e}' => true,
        // Bidirectional isolates.
        '\u{2066}'..='\u{2069}' => true,
        // Line and paragraph separators.
        '\u{2028}' | '\u{2029}' => true,
        // Byte-order mark / zero-width no-break space.
        '\u{feff}' => true,
        // Arabic letter mark.
        '\u{061c}' => true,
        _ => false,
    }
}

// ─── Review rendering ───────────────────────────────────────────────────────

/// Renders the text a launcher or `airlock trust` shows before asking the
/// user to approve `path_display`: a unified diff against the approved copy
/// for [`Approval::Changed`], or the full (escaped) contents for
/// [`Approval::New`]. Returns an empty string for [`Approval::Approved`],
/// since nothing needs review.
///
/// `annotate` is called with each line's raw (unescaped) text; when it
/// returns `Some(note)`, the displayed line gets `       # → <note>`
/// appended. This is for `from = "global"` lines, whose prompt shows what
/// the link resolves to right now — display only, not part of the approved
/// bytes.
pub fn render_review(
    path_display: &str,
    approval: &Approval,
    current: &[u8],
    annotate: &dyn Fn(&str) -> Option<String>,
) -> String {
    match approval {
        Approval::Approved => String::new(),
        Approval::New => {
            let mut out = format!("{path_display} is not trusted yet. Contents:\n\n");
            let text = String::from_utf8_lossy(current);
            for line in text.lines() {
                out.push_str("    ");
                out.push_str(&annotated_line(line, annotate));
                out.push('\n');
            }
            out
        }
        Approval::Changed { approved } => {
            let mut out = format!("{path_display} has changed since you last trusted it:\n\n");
            let old_text = String::from_utf8_lossy(approved);
            let new_text = String::from_utf8_lossy(current);
            out.push_str(&render_unified_diff(
                &old_text,
                &new_text,
                path_display,
                annotate,
            ));
            out
        }
    }
}

fn annotated_line(line: &str, annotate: &dyn Fn(&str) -> Option<String>) -> String {
    let escaped = escape_for_terminal(line);
    match annotate(line) {
        Some(note) => format!("{escaped}       # \u{2192} {note}"),
        None => escaped,
    }
}

fn render_unified_diff(
    old_text: &str,
    new_text: &str,
    path_display: &str,
    annotate: &dyn Fn(&str) -> Option<String>,
) -> String {
    let diff = TextDiff::from_lines(old_text, new_text);
    let mut out = String::new();
    out.push_str("--- trusted\n");
    out.push_str(&format!("+++ {path_display}\n"));

    for group in diff.grouped_ops(3) {
        if group.is_empty() {
            continue;
        }
        let header = similar::udiff::UnifiedHunkHeader::new(&group);
        out.push_str(&format!("{header}\n"));
        for op in &group {
            for change in diff.iter_changes(op) {
                let prefix = match change.tag() {
                    ChangeTag::Equal => ' ',
                    ChangeTag::Delete => '-',
                    ChangeTag::Insert => '+',
                };
                let text = change.to_string_lossy();
                let line = text.strip_suffix('\n').unwrap_or(&text);
                out.push(prefix);
                out.push_str(&annotated_line(line, annotate));
                out.push('\n');
            }
        }
    }

    out
}

// ─── Prompts ────────────────────────────────────────────────────────────────

/// Which command is asking, since the question text differs slightly
/// between the launcher (which also starts the agent on `y`) and
/// `airlock trust` (which only records the approval).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    /// `airlock run`, `session start`, `session reload`.
    Launcher,
    /// `airlock trust`.
    TrustCommand,
}

/// The exact question text for `kind`, given the file's approval state
/// (a never-approved file is asked about with "this file", a changed one
/// with "this version").
pub fn prompt_question(kind: PromptKind, approval: &Approval) -> &'static str {
    let is_new = matches!(approval, Approval::New);
    match (kind, is_new) {
        (PromptKind::Launcher, true) => "Trust this file and continue? [y/N]",
        (PromptKind::Launcher, false) => "Trust this version and continue? [y/N]",
        (PromptKind::TrustCommand, true) => "Trust this file? [y/N]",
        (PromptKind::TrustCommand, false) => "Trust this version? [y/N]",
    }
}

/// Whether this process can prompt: both stdin and stderr are terminals.
/// `stderr`, because that is where Airlock's own notes and questions go;
/// `stdin`, because that is what a non-interactive caller (a script, a CI
/// job) typically redirects.
pub fn is_interactive() -> bool {
    // SAFETY: isatty is always safe to call with a valid file descriptor;
    // stdin and stderr are valid for the life of the process.
    unsafe { libc::isatty(libc::STDIN_FILENO) != 0 && libc::isatty(libc::STDERR_FILENO) != 0 }
}

/// Asks `question` on the controlling terminal (`/dev/tty`, not stdin: a
/// piped agent can still have a pty-backed controlling terminal, and the
/// question must reach the user there, not into the pipe) and reads one line
/// in response. Defaults to `false` (No) for anything but an explicit yes.
pub fn prompt_yes_no(question: &str) -> io::Result<bool> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    write!(tty, "{question} ")?;
    tty.flush()?;
    read_yes_no(&mut tty)
}

/// The read side of [`prompt_yes_no`], taking any reader so tests can supply
/// one instead of a real terminal.
fn read_yes_no<R: Read>(reader: &mut R) -> io::Result<bool> {
    let mut line = String::new();
    io::BufReader::new(reader).read_line(&mut line)?;
    let answer = line.trim();
    Ok(answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"))
}

// ─── `--yes` / `--expect-sha256` decision ──────────────────────────────────

/// One file in a batch awaiting approval, as the decision logic sees it: a
/// display path and the SHA-256 of its current bytes.
#[derive(Debug, Clone)]
pub struct UnapprovedFile {
    pub path_display: String,
    pub sha256_current: String,
}

/// What to do about a batch of unapproved files, decided without asking
/// anything interactively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Approve every file in the batch.
    Approve,
    /// Prompt the user for each file one at a time (an interactive terminal
    /// with neither `--yes` nor `--expect-sha256`).
    Prompt,
    /// Refuse the whole batch; nothing is approved.
    Refuse { message: String },
}

/// The `--yes` / `--expect-sha256` decision for a batch of unapproved files.
///
/// - `yes` approves every file, unconditionally.
/// - Otherwise, a non-empty `expect_sha256` approves the batch only if every
///   file's current hash is in that list, and otherwise refuses, naming the
///   first file that does not match and its actual hash.
/// - Otherwise, an interactive caller should prompt file by file
///   ([`Decision::Prompt`]); a non-interactive one is refused and pointed at
///   `airlock trust`.
pub fn decide(
    files: &[UnapprovedFile],
    interactive: bool,
    yes: bool,
    expect_sha256: &[String],
) -> Decision {
    if yes {
        return Decision::Approve;
    }

    if !expect_sha256.is_empty() {
        for file in files {
            let matches = expect_sha256
                .iter()
                .any(|expected| expected.eq_ignore_ascii_case(&file.sha256_current));
            if !matches {
                return Decision::Refuse {
                    message: format!(
                        "{} does not match any --expect-sha256 hash (current: {})",
                        file.path_display, file.sha256_current
                    ),
                };
            }
        }
        return Decision::Approve;
    }

    if interactive {
        Decision::Prompt
    } else {
        Decision::Refuse {
            message: "run `airlock trust` in a terminal to approve it".to_string(),
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    // --- TrustStore ---

    #[test]
    fn new_file_has_no_approval() {
        let dir = tempdir().unwrap();
        let store = TrustStore::open(dir.path()).unwrap();
        let root = Path::new("/home/me/src/app");
        let state = store.state(root, "airlock.toml", b"hello").unwrap();
        assert_eq!(state, Approval::New);
    }

    #[test]
    fn approve_then_state_round_trips() {
        let dir = tempdir().unwrap();
        let store = TrustStore::open(dir.path()).unwrap();
        let root = Path::new("/home/me/src/app");

        store.approve(root, "airlock.toml", b"version one").unwrap();
        let state = store.state(root, "airlock.toml", b"version one").unwrap();
        assert_eq!(state, Approval::Approved);
    }

    #[test]
    fn changed_bytes_are_reported_with_the_approved_copy() {
        let dir = tempdir().unwrap();
        let store = TrustStore::open(dir.path()).unwrap();
        let root = Path::new("/home/me/src/app");

        store.approve(root, "airlock.toml", b"version one").unwrap();
        let state = store.state(root, "airlock.toml", b"version two").unwrap();
        assert_eq!(
            state,
            Approval::Changed {
                approved: b"version one".to_vec()
            }
        );
    }

    #[test]
    fn different_file_names_are_independent() {
        let dir = tempdir().unwrap();
        let store = TrustStore::open(dir.path()).unwrap();
        let root = Path::new("/home/me/src/app");

        store.approve(root, "airlock.toml", b"repo").unwrap();
        // The local file for the same project has never been approved.
        let state = store.state(root, "airlock.local.toml", b"local").unwrap();
        assert_eq!(state, Approval::New);
    }

    #[test]
    fn different_roots_are_independent() {
        let dir = tempdir().unwrap();
        let store = TrustStore::open(dir.path()).unwrap();

        store
            .approve(
                Path::new("/home/me/src/app"),
                "airlock.toml",
                b"app's config",
            )
            .unwrap();
        let state = store
            .state(
                Path::new("/home/me/src/other"),
                "airlock.toml",
                b"app's config",
            )
            .unwrap();
        assert_eq!(state, Approval::New);
    }

    #[test]
    fn store_dir_is_mode_0700() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let store_dir = dir.path().join("trust");
        TrustStore::open(&store_dir).unwrap();

        let mode = std::fs::metadata(&store_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn approved_copy_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let store = TrustStore::open(dir.path()).unwrap();
        let root = Path::new("/home/me/src/app");
        store.approve(root, "airlock.toml", b"hello").unwrap();

        let copy_path = dir.path().join(project_id(root)).join("airlock.toml");
        let mode = std::fs::metadata(&copy_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let root_path = dir.path().join(project_id(root)).join("root");
        let root_mode = std::fs::metadata(&root_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(root_mode, 0o600);
        assert_eq!(
            std::fs::read(&root_path).unwrap(),
            root.as_os_str().as_bytes()
        );
    }

    #[test]
    fn project_dir_itself_mode_0700() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let store = TrustStore::open(dir.path()).unwrap();
        let root = Path::new("/home/me/src/app");
        store.approve(root, "airlock.toml", b"hello").unwrap();

        let project_dir = dir.path().join(project_id(root));
        let mode = std::fs::metadata(&project_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn refuses_a_symlinked_store_dir() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();

        let err = TrustStore::open(&link).unwrap_err();
        assert!(matches!(err, TrustError::Symlink { .. }));
    }

    #[test]
    fn refuses_a_symlinked_approved_copy() {
        let dir = tempdir().unwrap();
        let store = TrustStore::open(dir.path()).unwrap();
        let root = Path::new("/home/me/src/app");

        // Plant a symlink where an approved copy would live, bypassing the
        // store's own writer.
        let project_dir = dir.path().join(project_id(root));
        std::fs::create_dir_all(&project_dir).unwrap();
        let outside = dir.path().join("outside.toml");
        std::fs::write(&outside, b"not actually approved").unwrap();
        symlink(&outside, project_dir.join("airlock.toml")).unwrap();

        let err = store.state(root, "airlock.toml", b"whatever").unwrap_err();
        assert!(matches!(err, TrustError::Symlink { .. }));
    }

    #[test]
    fn refuses_a_symlinked_project_dir() {
        let dir = tempdir().unwrap();
        let store = TrustStore::open(dir.path()).unwrap();
        let root = Path::new("/home/me/src/app");

        let real = dir.path().join("real-project-dir");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, dir.path().join(project_id(root))).unwrap();

        let err = store.approve(root, "airlock.toml", b"hello").unwrap_err();
        assert!(matches!(err, TrustError::Symlink { .. }));
    }

    #[test]
    fn project_id_is_stable_and_distinguishes_roots() {
        let a = project_id(Path::new("/home/me/src/app"));
        let a_again = project_id(Path::new("/home/me/src/app"));
        let b = project_id(Path::new("/home/me/src/other"));

        assert_eq!(a, a_again);
        assert_ne!(a, b);
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sha256_hex_is_lowercase_and_64_chars() {
        let hash = sha256_hex(b"");
        assert_eq!(hash.len(), 64);
        assert!(
            hash.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        // Known SHA-256 of the empty string.
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // --- Escaping ---

    #[test]
    fn escape_preserves_newline_and_tab() {
        assert_eq!(escape_for_terminal("a\nb\tc"), "a\nb\tc");
    }

    #[test]
    fn escape_c0_control_and_esc() {
        assert_eq!(escape_for_terminal("\u{01}"), "\\u{1}");
        assert_eq!(escape_for_terminal("\u{1b}"), "\\u{1b}"); // ESC: starts ANSI escapes
        assert_eq!(escape_for_terminal("\u{1b}[31m"), "\\u{1b}[31m");
    }

    #[test]
    fn escape_del_and_c1_controls() {
        assert_eq!(escape_for_terminal("\u{7f}"), "\\u{7f}");
        assert_eq!(escape_for_terminal("\u{85}"), "\\u{85}"); // NEL, a C1 control
        assert_eq!(escape_for_terminal("\u{9f}"), "\\u{9f}");
    }

    #[test]
    fn escape_bidi_overrides_and_isolates() {
        assert_eq!(escape_for_terminal("\u{202e}"), "\\u{202e}"); // RLO
        assert_eq!(escape_for_terminal("\u{202a}"), "\\u{202a}"); // LRE
        assert_eq!(escape_for_terminal("\u{2066}"), "\\u{2066}"); // LRI
        assert_eq!(escape_for_terminal("\u{2069}"), "\\u{2069}"); // PDI
    }

    #[test]
    fn escape_zero_width_and_marks() {
        assert_eq!(escape_for_terminal("\u{200b}"), "\\u{200b}"); // ZWSP
        assert_eq!(escape_for_terminal("\u{200e}"), "\\u{200e}"); // LRM
        assert_eq!(escape_for_terminal("\u{feff}"), "\\u{feff}"); // BOM
        assert_eq!(escape_for_terminal("\u{061c}"), "\\u{61c}"); // ALM
    }

    #[test]
    fn escape_line_and_paragraph_separators() {
        assert_eq!(escape_for_terminal("\u{2028}"), "\\u{2028}");
        assert_eq!(escape_for_terminal("\u{2029}"), "\\u{2029}");
    }

    #[test]
    fn escape_leaves_ordinary_text_alone() {
        let s = "description = \"GitHub CLI\"";
        assert_eq!(escape_for_terminal(s), s);
    }

    #[test]
    fn escape_matches_the_ux_doc_hidden_edit_example() {
        // docs/airlock-v2-ux.md, "The agent changes the config": a bidi
        // override hidden in a string must come out visibly.
        let s = "description = \"GitHub CLI\u{202e}\"";
        assert_eq!(
            escape_for_terminal(s),
            "description = \"GitHub CLI\\u{202e}\""
        );
    }

    // --- Review rendering ---

    fn no_annotation(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn render_new_file_shows_indented_contents() {
        let content =
            b"[secrets.GH_TOKEN]\nsource  = \"command\"\ncommand = [\"gh\", \"auth\", \"token\"]\n";
        let out = render_review(
            "~/src/app/airlock.toml",
            &Approval::New,
            content,
            &no_annotation,
        );
        assert_eq!(
            out,
            "~/src/app/airlock.toml is not trusted yet. Contents:\n\n\
             \x20   [secrets.GH_TOKEN]\n\
             \x20   source  = \"command\"\n\
             \x20   command = [\"gh\", \"auth\", \"token\"]\n"
        );
    }

    #[test]
    fn render_approved_is_empty() {
        let out = render_review(
            "~/src/app/airlock.toml",
            &Approval::Approved,
            b"anything",
            &no_annotation,
        );
        assert_eq!(out, "");
    }

    #[test]
    fn render_changed_file_is_a_unified_diff() {
        // docs/airlock-v2-design.md, "A changed file at session start".
        let old = "secrets block\n\nGH_TOKEN = { secret = \"GH_TOKEN\" }\n\n[filesystem]\nread = [\"/opt/homebrew/share\"]\n";
        let new = "secrets block\n\nGH_TOKEN = { secret = \"GH_TOKEN\" }\n\n[filesystem]\nread = [\"/opt/homebrew/share\"]\nwrite = [\"~/.ssh\"]\n";

        let approval = Approval::Changed {
            approved: old.as_bytes().to_vec(),
        };
        let out = render_review(
            "~/src/app/airlock.toml",
            &approval,
            new.as_bytes(),
            &no_annotation,
        );

        assert!(
            out.starts_with("~/src/app/airlock.toml has changed since you last trusted it:\n\n")
        );
        assert!(out.contains("--- trusted\n"));
        assert!(out.contains("+++ ~/src/app/airlock.toml\n"));
        assert!(out.contains("@@ "));
        assert!(out.contains("+write = [\"~/.ssh\"]\n"));
        // Unchanged lines carry the unified-diff context prefix, not the
        // 4-space indent used for a never-approved file's full contents.
        assert!(out.contains(" [filesystem]\n"));
    }

    #[test]
    fn render_changed_file_matches_full_expected_diff() {
        let old = (1..=9).map(|n| format!("line{n}\n")).collect::<String>()
            + "GH_TOKEN = { secret = \"GH_TOKEN\" }\n\n[filesystem]\nread = [\"/opt/homebrew/share\"]\n";
        let new = (1..=9).map(|n| format!("line{n}\n")).collect::<String>()
            + "GH_TOKEN = { secret = \"GH_TOKEN\" }\n\n[filesystem]\nread = [\"/opt/homebrew/share\"]\nwrite = [\"~/.ssh\"]\n";

        let approval = Approval::Changed {
            approved: old.into_bytes(),
        };
        let out = render_review(
            "~/src/app/airlock.toml",
            &approval,
            new.as_bytes(),
            &no_annotation,
        );

        let expected = "~/src/app/airlock.toml has changed since you last trusted it:\n\n\
--- trusted\n\
+++ ~/src/app/airlock.toml\n\
@@ -11,3 +11,4 @@\n\
\x20\n\
\x20[filesystem]\n\
\x20read = [\"/opt/homebrew/share\"]\n\
+write = [\"~/.ssh\"]\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn render_annotates_matching_lines_only() {
        let content = b"[secrets.GH_TOKEN]\nfrom = \"global\"\n";
        let annotate = |line: &str| {
            if line == "from = \"global\"" {
                Some("global: command op read op://Private/GitHub/token".to_string())
            } else {
                None
            }
        };
        let out = render_review(
            "~/src/app/airlock.local.toml",
            &Approval::New,
            content,
            &annotate,
        );
        assert!(out.contains(
            "    from = \"global\"       # \u{2192} global: command op read op://Private/GitHub/token\n"
        ));
        assert!(out.contains("    [secrets.GH_TOKEN]\n"));
    }

    #[test]
    fn render_escapes_hostile_bytes_before_annotating() {
        let content = "name = \"x\u{202e}\"\n".as_bytes().to_vec();
        let out = render_review("f.toml", &Approval::New, &content, &no_annotation);
        assert!(out.contains("\\u{202e}"));
        assert!(!out.contains('\u{202e}'));
    }

    // --- Prompts ---

    #[test]
    fn prompt_question_text_matches_the_ux_doc() {
        assert_eq!(
            prompt_question(PromptKind::Launcher, &Approval::New),
            "Trust this file and continue? [y/N]"
        );
        assert_eq!(
            prompt_question(
                PromptKind::Launcher,
                &Approval::Changed { approved: vec![] }
            ),
            "Trust this version and continue? [y/N]"
        );
        assert_eq!(
            prompt_question(PromptKind::TrustCommand, &Approval::New),
            "Trust this file? [y/N]"
        );
        assert_eq!(
            prompt_question(
                PromptKind::TrustCommand,
                &Approval::Changed { approved: vec![] }
            ),
            "Trust this version? [y/N]"
        );
    }

    #[test]
    fn read_yes_no_accepts_y_and_yes_case_insensitively() {
        for input in ["y\n", "Y\n", "yes\n", "YES\n", "y\r\n"] {
            let mut cursor = std::io::Cursor::new(input.as_bytes());
            assert!(
                read_yes_no(&mut cursor).unwrap(),
                "input {input:?} should be yes"
            );
        }
    }

    #[test]
    fn read_yes_no_defaults_to_no() {
        for input in ["n\n", "no\n", "\n", "", "anything else\n"] {
            let mut cursor = std::io::Cursor::new(input.as_bytes());
            assert!(
                !read_yes_no(&mut cursor).unwrap(),
                "input {input:?} should be no"
            );
        }
    }

    // --- Decision logic ---

    fn file(path: &str, hash: &str) -> UnapprovedFile {
        UnapprovedFile {
            path_display: path.to_string(),
            sha256_current: hash.to_string(),
        }
    }

    #[test]
    fn decide_yes_approves_regardless_of_everything_else() {
        let files = vec![file("a.toml", "aaaa")];
        assert_eq!(decide(&files, false, true, &[]), Decision::Approve);
        assert_eq!(
            decide(&files, true, true, &["zzzz".to_string()]),
            Decision::Approve
        );
    }

    #[test]
    fn decide_non_interactive_without_flags_refuses() {
        let files = vec![file("a.toml", "aaaa")];
        let decision = decide(&files, false, false, &[]);
        assert_eq!(
            decision,
            Decision::Refuse {
                message: "run `airlock trust` in a terminal to approve it".to_string()
            }
        );
    }

    #[test]
    fn decide_interactive_without_flags_prompts() {
        let files = vec![file("a.toml", "aaaa")];
        assert_eq!(decide(&files, true, false, &[]), Decision::Prompt);
    }

    #[test]
    fn decide_expect_sha256_approves_when_every_file_matches() {
        let files = vec![file("a.toml", "aaaa"), file("b.toml", "bbbb")];
        let expected = vec!["aaaa".to_string(), "bbbb".to_string(), "cccc".to_string()];
        assert_eq!(decide(&files, false, false, &expected), Decision::Approve);
    }

    #[test]
    fn decide_expect_sha256_refuses_naming_the_mismatch() {
        let files = vec![file("a.toml", "aaaa"), file("b.toml", "bbbb")];
        let expected = vec!["aaaa".to_string()];
        let decision = decide(&files, true, false, &expected);
        match decision {
            Decision::Refuse { message } => {
                assert!(message.contains("b.toml"));
                assert!(message.contains("bbbb"));
            }
            other => panic!("expected Refuse, got {other:?}"),
        }
    }

    #[test]
    fn decide_expect_sha256_is_case_insensitive() {
        let files = vec![file("a.toml", "aaaa")];
        let expected = vec!["AAAA".to_string()];
        assert_eq!(decide(&files, false, false, &expected), Decision::Approve);
    }
}
