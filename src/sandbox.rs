//! Sandbox abstractions and platform-specific implementations.
//!
//! This module defines the `SandboxBackend` trait, `ToolPolicy` input type, and
//! `SandboxProfile` output type, along with platform-specific implementations.
//!
//! The design constraint is that by the time `exec::spawn()` calls `pre_exec`,
//! all allocation-heavy work must already be complete. `SandboxProfile` satisfies
//! this — on macOS it stores a fully-formed null-terminated C string ready to be
//! handed to `sandbox_init()` FFI; on Linux it stores the raw integer of a
//! pre-built Landlock ruleset fd that the child inherits across fork.

use std::path::PathBuf;

use thiserror::Error;

/// Errors that can occur during sandbox profile generation.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// A path contains an ASCII control character (0x00–0x1F or 0x7F).
    ///
    /// These are rejected rather than stripped to prevent SBPL injection: a
    /// null byte (0x00) would truncate the profile string; a newline or other
    /// control character could break the surrounding S-expression.
    #[error(
        "path contains a control character and cannot be safely embedded in an SBPL profile: {0:?}"
    )]
    ControlCharacterInPath(PathBuf),
    /// Profile generation failed for a reason not tied to a specific path.
    #[error("failed to build sandbox profile: {0}")]
    ProfileBuildError(String),
}

/// Describes what a tool is allowed to access.
///
/// Used as input to a `SandboxBackend` to produce a `SandboxProfile`.
pub struct ToolPolicy {
    /// Filesystem paths the tool may read (from global `[filesystem]` and tool's `extra_read`).
    pub read_paths: Vec<PathBuf>,
    /// Filesystem paths the tool may read and write (from tool's `extra_write`).
    pub read_write_paths: Vec<PathBuf>,
    /// Whether the tool requires any network access.
    ///
    /// Derived from whether `allowed_hosts` is non-empty in the config.
    /// On macOS, this drives a binary allow/deny decision — per-hostname filtering
    /// is not supported by the Seatbelt framework.
    pub requires_network: bool,
    /// The resolved absolute path to the tool's executable binary.
    ///
    /// On macOS, Security.framework re-reads the process's own binary at runtime
    /// for code signature verification (e.g. when calling `SecPolicyCreateSSL`
    /// for TLS). Without `file-read*` on this path, TLS certificate verification
    /// fails even though `process-exec*` allowed the initial execution.
    ///
    /// Set by the daemon after binary resolution; `None` in unit tests that
    /// don't exercise the full daemon flow.
    pub binary_path: Option<PathBuf>,
}

/// Describes what an agent process is allowed to access.
///
/// Used as input to `SandboxBackend::build_agent` to produce a `SandboxProfile`.
/// Unlike `ToolPolicy`, there is no `binary_path` field — the entire interactive
/// session is sandboxed, so there is no single binary path to allow.
pub struct AgentPolicy {
    /// Filesystem paths the agent may read (global filesystem list, toolchain paths,
    /// and any user-declared agent read paths).
    pub read_paths: Vec<PathBuf>,
    /// Filesystem paths the agent may read and write (sandbox root, socket path,
    /// and any user-declared agent write paths).
    pub read_write_paths: Vec<PathBuf>,
    /// Whether the agent requires network access.
    ///
    /// Always `true` for agents, but included as an explicit field so the
    /// profile generator can be read without assuming.
    pub requires_network: bool,
    /// Whether the agent requires terminal device access.
    ///
    /// Always `true` for agents, but included as an explicit field so the
    /// profile generator can be read without assuming.
    pub requires_terminal: bool,
}

/// An opaque, pre-built sandbox configuration produced by a `SandboxBackend`.
///
/// Consumed by `exec::spawn()` in the `pre_exec` closure. Must be
/// `Send + Sync + 'static` so it can be moved into the `pre_exec` closure.
///
/// The internal representation is platform-specific and not exposed outside
/// the `sandbox` module.
pub struct SandboxProfile {
    // The inner type is platform-specific; on unsupported platforms the field
    // is written during construction but never read (hence dead_code suppression).
    #[allow(dead_code)]
    inner: SandboxProfileInner,
}

impl std::fmt::Debug for SandboxProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SandboxProfile { .. }")
    }
}

// Compiler-verified Send + Sync + 'static constraints.
const _: fn() = || {
    fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<SandboxProfile>();
};

// ─── Platform type aliases ────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
type SandboxProfileInner = macos::MacOSProfile;

#[cfg(target_os = "linux")]
type SandboxProfileInner = linux::LinuxProfile;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
type SandboxProfileInner = NoopProfile;

/// Placeholder profile type for platforms other than macOS and Linux.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
struct NoopProfile;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
unsafe impl Send for NoopProfile {}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
unsafe impl Sync for NoopProfile {}

// ─── SandboxProfile platform-specific methods ─────────────────────────────────

impl SandboxProfile {
    /// Returns a raw pointer to the null-terminated SBPL bytes (macOS only).
    ///
    /// The pointer is valid for the lifetime of this `SandboxProfile`. Intended
    /// for use inside the `pre_exec` closure when calling `sandbox_init()`.
    #[cfg(target_os = "macos")]
    pub(crate) fn as_ptr(&self) -> *const std::ffi::c_char {
        self.inner.as_ptr()
    }

    /// Returns the raw Landlock ruleset fd integer (Linux only).
    ///
    /// The integer is valid in the parent until `close_ruleset_fd()` is called,
    /// and is inherited by the child across fork. The child uses it directly
    /// in raw `prctl` and `landlock_restrict_self` syscalls.
    #[cfg(target_os = "linux")]
    pub(crate) fn raw_fd(&self) -> i32 {
        self.inner.raw_fd()
    }

    /// Explicitly closes the parent's copy of the Landlock ruleset fd (Linux only).
    ///
    /// Called by `exec::spawn()` after spawn succeeds. Using an explicit method
    /// rather than `Drop` makes the close site visible at the call site and
    /// prevents accidental early closure if the profile is moved before spawn.
    #[cfg(target_os = "linux")]
    pub(crate) fn close_ruleset_fd(&mut self) {
        self.inner.close_ruleset_fd();
    }

    /// Test-only constructor that creates a Linux profile from an arbitrary raw fd.
    ///
    /// Used exclusively by `exec.rs` test code to construct a profile with a
    /// known-invalid fd to trigger child-side `pre_exec` failures without going
    /// through the Landlock builder chain.
    #[cfg(all(target_os = "linux", test))]
    pub(crate) fn new_for_test(raw_fd: i32) -> Self {
        SandboxProfile {
            inner: linux::LinuxProfile::new_for_test(raw_fd),
        }
    }

    /// Noop profile constructor for platforms other than macOS and Linux.
    ///
    /// Returns a profile whose inner representation is the no-op placeholder.
    /// Used by the noop `SandboxBackend` implementation on unsupported platforms.
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub(crate) fn new_noop() -> Self {
        SandboxProfile { inner: NoopProfile }
    }
}

// ─── AgentProfileKind ─────────────────────────────────────────────────────────

/// Identifies a built-in agent profile for platform-specific sandbox extras
/// that can't be expressed as plain read/write paths.
///
/// The run-time `run::Profile` enum is mapped to this sandbox-side kind so
/// that backends can emit tailored rules (e.g. Seatbelt regex patterns)
/// without the sandbox layer depending on `run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentProfileKind {
    /// Claude Code: on macOS, widens write access to `~/.claude.json`'s
    /// sibling lock and per-pid temp files used during atomic config writes.
    Claude,
    /// Claude Code with interactive-ergonomics relaxations: everything
    /// `Claude` provides plus clipboard, `open <url>` via Launch Services,
    /// default-browser lookup, shell init dotfile reads, and read/write to
    /// `~/Library/Keychains/` so that `security add-generic-password` (used
    /// by Claude Code's OAuth token save path) does not fall back to the
    /// `~/.claude/.credentials.json` plaintext file. Each of these is a
    /// deliberate widening of the data-leak surface; the standard `Claude`
    /// profile excludes them.
    ClaudeRelaxed,
}

// ─── SandboxBackend trait ─────────────────────────────────────────────────────

/// A `SandboxBackend` produces a `SandboxProfile` from a `ToolPolicy`.
///
/// Both the macOS (`MacOSSeatbelt`) and Linux (`LinuxLandlock`) implementations
/// implement this trait. The trait itself is platform-independent; implementations
/// are conditionally compiled.
pub trait SandboxBackend {
    /// Build a `SandboxProfile` from the given policy.
    ///
    /// All allocation-heavy work must complete inside this method. The returned
    /// `SandboxProfile` must be usable from a `pre_exec` closure without any
    /// further allocation.
    fn build(&self, policy: &ToolPolicy) -> Result<SandboxProfile, SandboxError>;

    /// Build an agent `SandboxProfile` from the given agent policy.
    ///
    /// Produces a profile for an agent process with broader signal scope
    /// (`(target same-sandbox)` instead of `(target self)`), terminal device
    /// access, and mandatory network access. All allocation-heavy work must
    /// complete inside this method.
    ///
    /// `profile` optionally identifies a built-in agent profile, allowing the
    /// backend to emit platform-specific extras that cannot be expressed as
    /// read/write paths alone. Backends that cannot honour a profile (e.g.
    /// Landlock lacks regex support) ignore it silently.
    fn build_agent(
        &self,
        policy: &AgentPolicy,
        profile: Option<AgentProfileKind>,
    ) -> Result<SandboxProfile, SandboxError>;
}

// ─── Noop backend (non-macOS, non-Linux platforms) ────────────────────────────

/// No-op sandbox backend for platforms that do not support sandboxing.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
struct NoopBackend;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl SandboxBackend for NoopBackend {
    fn build(&self, _policy: &ToolPolicy) -> Result<SandboxProfile, SandboxError> {
        Ok(SandboxProfile::new_noop())
    }

    fn build_agent(
        &self,
        _policy: &AgentPolicy,
        _profile: Option<AgentProfileKind>,
    ) -> Result<SandboxProfile, SandboxError> {
        Ok(SandboxProfile::new_noop())
    }
}

// ─── macOS implementation ───────────────────────────────────────────────────

#[cfg(target_os = "macos")]
pub mod macos {
    use std::ffi::{CString, c_char};
    use std::path::{Path, PathBuf};

    use super::{AgentPolicy, AgentProfileKind, SandboxError, SandboxProfile, ToolPolicy};

    // ─── FFI bindings ────────────────────────────────────────────────────────

    #[link(name = "sandbox")]
    unsafe extern "C" {
        /// Initialise the Seatbelt sandbox for the calling process.
        ///
        /// `flags` is `u64` (not `u32`) per the macOS SDK declaration.
        pub(crate) fn sandbox_init(
            profile: *const c_char,
            flags: u64,
            errorbuf: *mut *mut c_char,
        ) -> i32;

        /// Free an error string previously returned via `sandbox_init`.
        pub(crate) fn sandbox_free_error(errorbuf: *mut c_char);
    }

    // ─── Internal profile type ───────────────────────────────────────────────

    /// Internal macOS profile — wraps the fully-built SBPL as a `CString`.
    pub struct MacOSProfile {
        sbpl: CString,
    }

    // SAFETY: CString is Send + Sync; no interior mutability.
    unsafe impl Send for MacOSProfile {}
    unsafe impl Sync for MacOSProfile {}

    impl MacOSProfile {
        /// Returns a raw pointer to the null-terminated SBPL bytes.
        pub(crate) fn as_ptr(&self) -> *const c_char {
            self.sbpl.as_ptr()
        }

        /// Returns the SBPL bytes including the null terminator (used in tests).
        #[cfg(test)]
        pub(crate) fn as_bytes_with_nul(&self) -> &[u8] {
            self.sbpl.as_bytes_with_nul()
        }
    }

    // ─── Path helpers ────────────────────────────────────────────────────────

    /// Validate and escape a path for safe embedding in an SBPL quoted string.
    ///
    /// # Errors
    /// Returns `SandboxError::ControlCharacterInPath` if the path contains any
    /// ASCII control character (0x00–0x1F, 0x7F). These are rejected rather than
    /// stripped to prevent SBPL injection attacks.
    fn escape_path(path: &Path) -> Result<String, SandboxError> {
        let s = path.to_string_lossy();
        for ch in s.chars() {
            let code = ch as u32;
            if code <= 0x1F || code == 0x7F {
                return Err(SandboxError::ControlCharacterInPath(path.to_path_buf()));
            }
        }
        // Escape backslashes first, then double-quotes.
        Ok(s.replace('\\', "\\\\").replace('"', "\\\""))
    }

    /// Emit ancestor directory metadata-access rules for a path.
    ///
    /// For every ancestor directory (from the parent up to but not including `/`),
    /// emits a `file-read-metadata` rule so that path resolution and symlink
    /// traversal succeed inside the sandbox.
    fn emit_ancestor_rules(path: &Path, out: &mut String) -> Result<(), SandboxError> {
        let mut current = path.parent();
        while let Some(dir) = current {
            // Stop before the root `/` — root gets only enumeration metadata (see below).
            if dir == Path::new("/") || dir == Path::new("") {
                break;
            }
            let escaped = escape_path(dir)?;
            out.push_str(&format!(
                "(allow file-read-metadata (literal \"{escaped}\"))\n"
            ));
            current = dir.parent();
        }
        Ok(())
    }

    /// Resolve a path's canonical form via `std::fs::canonicalize`.
    ///
    /// Returns `None` if canonicalization fails (path doesn't exist yet, etc.).
    fn try_canonicalize(path: &Path) -> Option<PathBuf> {
        std::fs::canonicalize(path).ok().and_then(|canonical| {
            if canonical != path {
                Some(canonical)
            } else {
                None
            }
        })
    }

    // ─── SBPL generation ────────────────────────────────────────────────────

    /// Emit SBPL rules shared by both tool and agent profiles: preamble,
    /// process operations, sysctl, Mach IPC (with credential-service denies),
    /// root-directory access, system read paths, and device-file entries.
    ///
    /// `process_scope` controls the `signal` and `process-info*` target:
    /// - `"self"` — restricts to the process itself (appropriate for
    ///   single-process tools that never spawn sandboxed children).
    /// - `"same-sandbox"` — extends to all processes sharing the sandbox
    ///   (required for agents whose child processes inherit the profile).
    fn emit_common_rules(process_scope: &str, out: &mut String) {
        // ── Preamble ─────────────────────────────────────────────────────────
        out.push_str("(version 1)\n");
        out.push_str("(deny default)\n");

        // ── Process operations (always allowed) ───────────────────────────────
        // Without these the exec'd binary cannot load or run.
        out.push_str("(allow process-exec)\n");
        out.push_str("(allow process-fork)\n");

        // ── Process scope ─────────────────────────────────────────────────────
        // Programs commonly query their own PID, send signals to themselves
        // (e.g. SIGTERM handlers), and inspect their own process state.
        // The filter target controls which processes these operations may reach.
        out.push_str(&format!("(allow signal (target {process_scope}))\n"));
        out.push_str(&format!("(allow process-info* (target {process_scope}))\n"));

        // ── System information (named sysctl allowlist) ──────────────────────
        // Many runtimes (Go, Rust std, etc.) call sysctl(3) very early —
        // often before main() — to query hardware parameters such as the
        // page size or CPU count. Named allowlist instead of blanket allow
        // to avoid exposing every kernel parameter.
        out.push_str("(allow sysctl-read\n");
        out.push_str("  (sysctl-name \"hw.activecpu\")\n");
        out.push_str("  (sysctl-name \"hw.busfrequency_compat\")\n");
        out.push_str("  (sysctl-name \"hw.byteorder\")\n");
        out.push_str("  (sysctl-name \"hw.cacheconfig\")\n");
        out.push_str("  (sysctl-name \"hw.cachelinesize_compat\")\n");
        out.push_str("  (sysctl-name \"hw.cpufamily\")\n");
        out.push_str("  (sysctl-name \"hw.cpufrequency\")\n");
        out.push_str("  (sysctl-name \"hw.cpufrequency_compat\")\n");
        out.push_str("  (sysctl-name \"hw.cputype\")\n");
        out.push_str("  (sysctl-name \"hw.l1dcachesize_compat\")\n");
        out.push_str("  (sysctl-name \"hw.l1icachesize_compat\")\n");
        out.push_str("  (sysctl-name \"hw.l2cachesize_compat\")\n");
        out.push_str("  (sysctl-name \"hw.l3cachesize_compat\")\n");
        out.push_str("  (sysctl-name \"hw.logicalcpu\")\n");
        out.push_str("  (sysctl-name \"hw.logicalcpu_max\")\n");
        out.push_str("  (sysctl-name \"hw.machine\")\n");
        out.push_str("  (sysctl-name \"hw.memsize\")\n");
        out.push_str("  (sysctl-name \"hw.ncpu\")\n");
        out.push_str("  (sysctl-name \"hw.nperflevels\")\n");
        out.push_str("  (sysctl-name \"hw.packages\")\n");
        out.push_str("  (sysctl-name \"hw.pagesize_compat\")\n");
        out.push_str("  (sysctl-name \"hw.pagesize\")\n");
        out.push_str("  (sysctl-name \"hw.physicalcpu\")\n");
        out.push_str("  (sysctl-name \"hw.physicalcpu_max\")\n");
        out.push_str("  (sysctl-name \"hw.tbfrequency_compat\")\n");
        out.push_str("  (sysctl-name \"hw.vectorunit\")\n");
        out.push_str("  (sysctl-name \"kern.argmax\")\n");
        out.push_str("  (sysctl-name \"kern.bootargs\")\n");
        out.push_str("  (sysctl-name \"kern.hostname\")\n");
        out.push_str("  (sysctl-name \"kern.maxfiles\")\n");
        out.push_str("  (sysctl-name \"kern.maxfilesperproc\")\n");
        out.push_str("  (sysctl-name \"kern.maxproc\")\n");
        out.push_str("  (sysctl-name \"kern.ngroups\")\n");
        out.push_str("  (sysctl-name \"kern.osproductversion\")\n");
        out.push_str("  (sysctl-name \"kern.osrelease\")\n");
        out.push_str("  (sysctl-name \"kern.ostype\")\n");
        out.push_str("  (sysctl-name \"kern.osvariant_status\")\n");
        out.push_str("  (sysctl-name \"kern.osversion\")\n");
        out.push_str("  (sysctl-name \"kern.secure_kernel\")\n");
        out.push_str("  (sysctl-name \"kern.tcsm_available\")\n");
        out.push_str("  (sysctl-name \"kern.tcsm_enable\")\n");
        out.push_str("  (sysctl-name \"kern.usrstack64\")\n");
        out.push_str("  (sysctl-name \"kern.version\")\n");
        out.push_str("  (sysctl-name \"kern.willshutdown\")\n");
        out.push_str("  (sysctl-name \"machdep.cpu.brand_string\")\n");
        out.push_str("  (sysctl-name \"machdep.ptrauth_enabled\")\n");
        out.push_str("  (sysctl-name \"security.mac.lockdown_mode_state\")\n");
        // The MAC sandbox sentinel is the per-process token Seatbelt derives
        // for the active sandbox. `/usr/bin/security` reads it on the keychain
        // write path so it can pass a stable sandbox identity to `securityd`
        // over XPC; when the read is denied, securityd cannot resolve the
        // caller's sandbox and fails the keychain write, which Claude Code
        // catches and silently falls back to writing
        // `~/.claude/.credentials.json` in plaintext. The value just echoes
        // the caller's own sandbox identity back at it (nothing the process
        // doesn't already know about itself), so granting read is safe across
        // both tool and agent profiles.
        out.push_str("  (sysctl-name \"security.mac.sandbox.sentinel\")\n");
        out.push_str("  (sysctl-name \"sysctl.proc_cputype\")\n");
        out.push_str("  (sysctl-name \"vm.loadavg\")\n");
        out.push_str("  (sysctl-name-prefix \"hw.optional.arm\")\n");
        out.push_str("  (sysctl-name-prefix \"hw.optional.arm.\")\n");
        out.push_str("  (sysctl-name-prefix \"hw.optional.armv8_\")\n");
        out.push_str("  (sysctl-name-prefix \"hw.perflevel\")\n");
        out.push_str("  (sysctl-name-prefix \"kern.proc.all\")\n");
        out.push_str("  (sysctl-name-prefix \"kern.proc.pgrp.\")\n");
        out.push_str("  (sysctl-name-prefix \"kern.proc.pid.\")\n");
        out.push_str("  (sysctl-name-prefix \"machdep.cpu.\")\n");
        out.push_str("  (sysctl-name-prefix \"net.routetable.\")\n");
        out.push_str(")\n");

        // ── Mach IPC (explicit allowlist) ─────────────────────────────────────
        // Explicit allowlist of the system services programs routinely need.
        // All keychain-bearing endpoints (`com.apple.SecurityServer`,
        // `com.apple.securityd.xpc`, `com.apple.security.agent`,
        // `com.apple.security.keychaind`, `com.apple.secd`) are intentionally
        // omitted: they let any client read keychain items subject only to
        // per-item ACL, which gives sandboxed agents visibility into other
        // apps' OAuth tokens, saved passwords, and certs. TLS trust evaluation
        // (`SecTrustEvaluate`, `SecPolicyCreateSSL`) reaches the network and
        // validates cert chains through `com.apple.trustd.agent` alone —
        // verified empirically — so dropping SecurityServer does not break
        // HTTPS. Profiles that genuinely need keychain access (e.g.
        // `claude-relaxed`) opt in by re-adding the services in their own
        // profile rules. Privileged Mach operations remain denied by default.
        //
        // `com.apple.FSEvents` is the fseventsd endpoint behind
        // `FSEventStreamCreate`. Without it every file watcher on macOS
        // breaks, and the failures are unrecognisable: libuv reports the
        // failed `FSEventStreamStart` as `EMFILE` (`node --watch`, nodemon,
        // vite), Bun as "Error starting FSEvents stream". It grants change
        // notifications only — reading a changed file still goes through the
        // filesystem rules — but the event stream itself carries paths, so a
        // watcher rooted outside the sandbox learns names of files it cannot
        // open. That metadata channel is the price of working dev servers.
        out.push_str("(allow mach-lookup\n");
        out.push_str("  (global-name \"com.apple.audio.systemsoundserver\")\n");
        out.push_str("  (global-name \"com.apple.distributed_notifications@Uv3\")\n");
        out.push_str("  (global-name \"com.apple.FontObjectsServer\")\n");
        out.push_str("  (global-name \"com.apple.FSEvents\")\n");
        out.push_str("  (global-name \"com.apple.fonts\")\n");
        out.push_str("  (global-name \"com.apple.logd\")\n");
        out.push_str("  (global-name \"com.apple.lsd.mapdb\")\n");
        out.push_str("  (global-name \"com.apple.PowerManagement.control\")\n");
        out.push_str("  (global-name \"com.apple.system.logger\")\n");
        out.push_str("  (global-name \"com.apple.system.notification_center\")\n");
        out.push_str("  (global-name \"com.apple.system.opendirectoryd.libinfo\")\n");
        out.push_str("  (global-name \"com.apple.system.opendirectoryd.membership\")\n");
        out.push_str("  (global-name \"com.apple.bsd.dirhelper\")\n");
        out.push_str("  (global-name \"com.apple.coreservices.launchservicesd\")\n");
        out.push_str("  (global-name \"com.apple.trustd.agent\")\n");
        out.push_str(")\n");

        // ── AF_SYSTEM socket (kernel monitoring, non-network) ─────────────────
        // Protocol 2 on AF_SYSTEM is used by system utilities (vm_stat, top,
        // netstat) for kernel statistics. Scoped to one protocol so it cannot
        // be used for external network traffic.
        out.push_str(
            "(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))\n",
        );

        // ── POSIX IPC ─────────────────────────────────────────────────────────
        // Shared memory: GPU libraries, V8, and many runtimes use shm segments.
        // Semaphores: Python multiprocessing and other tools require them.
        out.push_str("(allow ipc-posix-shm)\n");
        out.push_str("(allow ipc-posix-sem)\n");

        // ── IOKit ─────────────────────────────────────────────────────────────
        // Specific IOKit user-client classes needed by system libraries for
        // graphics surface allocation (IOSurface) and power management queries
        // (RootDomainUserClient). iokit-get-properties covers basic hardware
        // property reads that many programs make at startup.
        out.push_str("(allow iokit-open\n");
        out.push_str("  (iokit-registry-entry-class \"IOSurfaceRootUserClient\")\n");
        out.push_str("  (iokit-registry-entry-class \"RootDomainUserClient\")\n");
        out.push_str("  (iokit-user-client-class \"IOSurfaceSendRight\"))\n");
        out.push_str("(allow iokit-get-properties)\n");

        // ── Root directory access ─────────────────────────────────────────────
        // Allow full read access on `/` (the root directory) so the dynamic
        // linker (dyld) can enumerate top-level directories when resolving
        // library paths. `file-read-metadata` alone is insufficient — dyld
        // needs to read directory entries, which is a `file-read-data` operation.
        // `file-read*` on the root literal grants this without exposing any
        // file contents in subdirectories (those require separate subpath rules).
        out.push_str("(allow file-read* (literal \"/\"))\n");

        // ── System read paths (always allowed, read-only) ───────────────────
        // These are macOS system directories that virtually every program
        // needs at runtime. They contain no user secrets — only OS
        // frameworks, shared libraries, certificates, and configuration.
        //
        //  /usr/lib       — system shared libraries (libSystem, dyld stubs)
        //  /usr/bin       — system binaries (ls, git, ssh, curl, ...)
        //  /usr/sbin      — system admin binaries
        //  /usr/share     — shared data (locale, timezone, terminfo)
        //  /bin           — core binaries (sh, ls, cat, ...)
        //  /sbin          — core admin binaries
        //  /System        — OS frameworks, Security.framework trust stores,
        //                   system keychains (SystemRootCertificates.keychain)
        //  /Library       — system-wide frameworks, keychains, CA certs
        //  /private/etc   — system configuration (ssl/openssl.cnf, hosts,
        //                   resolv.conf); canonical path of /etc symlink
        //  /dev/null      — required by many programs for I/O redirection
        //                   (read and write: shells open it O_WRONLY for 2>/dev/null)
        //  /dev/zero      — source of zero bytes; many programs read it
        //  /dev/random    — cryptographic random number generation
        //  /dev/urandom   — non-blocking random number generation
        out.push_str("(allow file-read* (subpath \"/usr/lib\"))\n");
        out.push_str("(allow file-read* (subpath \"/usr/bin\"))\n");
        out.push_str("(allow file-read* (subpath \"/usr/sbin\"))\n");
        out.push_str("(allow file-read* (subpath \"/usr/share\"))\n");
        out.push_str("(allow file-read* (subpath \"/bin\"))\n");
        out.push_str("(allow file-read* (subpath \"/sbin\"))\n");
        out.push_str("(allow file-read* (subpath \"/System\"))\n");
        out.push_str("(allow file-read* (subpath \"/Library\"))\n");
        out.push_str("(allow file-read* (subpath \"/private/etc\"))\n");
        out.push_str("(allow file-read* (subpath \"/etc\"))\n");
        out.push_str("(allow file-read* (literal \"/dev/null\"))\n");
        out.push_str("(allow file-read* (literal \"/dev/zero\"))\n");
        out.push_str("(allow file-read* (literal \"/dev/random\"))\n");
        out.push_str("(allow file-read* (literal \"/dev/urandom\"))\n");
        // `/dev/dtracehelper` is opened read-write by the libc DTrace USDT shim
        // at process startup. `/dev/autofs_nowait` is opened by libc during
        // path resolution to suppress autofs wait-for-mount behaviour. Both
        // fail benignly but spam the log; allowing them keeps the denial log
        // focused on real problems.
        out.push_str("(allow file-read* (literal \"/dev/dtracehelper\"))\n");
        out.push_str("(allow file-read* (literal \"/dev/autofs_nowait\"))\n");
        out.push_str("(allow file-write* (literal \"/dev/null\"))\n");
        // Ancestor metadata for path traversal into the above directories.
        out.push_str("(allow file-read-metadata (literal \"/usr\"))\n");
        out.push_str("(allow file-read-metadata (literal \"/private\"))\n");
        out.push_str("(allow file-read-metadata (literal \"/dev\"))\n");

        // ── File I/O on device files ──────────────────────────────────────────
        // Programs commonly call ioctl() on standard device nodes. Without
        // these rules the sandbox returns EPERM even for benign operations
        // (e.g. querying the terminal window size on /dev/tty).
        out.push_str("(allow file-ioctl (literal \"/dev/null\"))\n");
        out.push_str("(allow file-ioctl (literal \"/dev/zero\"))\n");
        out.push_str("(allow file-ioctl (literal \"/dev/random\"))\n");
        out.push_str("(allow file-ioctl (literal \"/dev/urandom\"))\n");
        out.push_str("(allow file-ioctl (literal \"/dev/dtracehelper\"))\n");
        out.push_str("(allow file-ioctl (literal \"/dev/tty\"))\n");
        out.push_str("(allow file-ioctl file-read-data file-write-data\n");
        out.push_str("  (require-all\n");
        out.push_str("    (literal \"/dev/null\")\n");
        out.push_str("    (vnode-type CHARACTER-DEVICE)))\n");
    }

    /// Emit SBPL filesystem read and write rules for the given path lists.
    ///
    /// For every path in `read_paths ∪ read_write_paths`:
    /// - Emits ancestor `file-read-metadata` rules for path resolution.
    /// - Emits a `file-read*` subpath rule (plus canonical form if symlinked).
    ///
    /// For every path in `read_write_paths`:
    /// - Emits a `file-write*` subpath rule (plus canonical form if symlinked).
    ///
    /// Write rules are emitted after all read rules to respect SBPL precedence.
    fn emit_filesystem_rules(
        read_paths: &[PathBuf],
        read_write_paths: &[PathBuf],
        out: &mut String,
    ) -> Result<(), SandboxError> {
        let all_read_paths: Vec<&PathBuf> =
            read_paths.iter().chain(read_write_paths.iter()).collect();

        for path in &all_read_paths {
            // Ancestor metadata rules for path resolution.
            emit_ancestor_rules(path, out)?;

            // If the path has a different canonical form (e.g., /tmp → /private/tmp),
            // emit ancestor and read rules for both.
            if let Some(canonical) = try_canonicalize(path) {
                emit_ancestor_rules(&canonical, out)?;
                let escaped = escape_path(&canonical)?;
                out.push_str(&format!("(allow file-read* (subpath \"{escaped}\"))\n"));
            }

            let escaped = escape_path(path)?;
            out.push_str(&format!("(allow file-read* (subpath \"{escaped}\"))\n"));
        }

        // Write rules are emitted after read rules to respect SBPL precedence.
        for path in read_write_paths {
            // Emit canonical form write rule if needed.
            if let Some(canonical) = try_canonicalize(path) {
                let escaped = escape_path(&canonical)?;
                out.push_str(&format!("(allow file-write* (subpath \"{escaped}\"))\n"));
            }

            let escaped = escape_path(path)?;
            out.push_str(&format!("(allow file-write* (subpath \"{escaped}\"))\n"));
        }

        Ok(())
    }

    /// Emit SBPL network rules: outbound connections, DNS via mDNSResponder,
    /// and local Unix-socket binds.
    fn emit_network_rules(out: &mut String) {
        // Allow all outbound network connections.
        out.push_str("(allow network-outbound)\n");
        // Allow system socket operations required for networking.
        out.push_str("(allow system-socket)\n");

        // ── DNS resolution via mDNSResponder ──────────────────────────────
        // On macOS, `getaddrinfo()` resolves DNS by connecting to the
        // `mDNSResponder` daemon via a Unix domain socket at
        // `/var/run/mDNSResponder` (symlink to `/private/var/run/mDNSResponder`).
        //
        // The `network-outbound` rule alone is not sufficient — the DNS
        // resolver library also needs `file-read*` access to the socket
        // file for the connection to succeed. Without it, the sandbox
        // blocks the file access and DNS resolution fails with
        // "Could not resolve host".
        //
        // Ancestor directory metadata rules (`file-read-metadata`) are
        // required so that path resolution can traverse from `/` down to
        // the socket file.
        out.push_str("(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n");
        out.push_str("(allow network-outbound (literal \"/var/run/mDNSResponder\"))\n");
        out.push_str("(allow file-read* (literal \"/private/var/run/mDNSResponder\"))\n");
        out.push_str("(allow file-read* (literal \"/var/run/mDNSResponder\"))\n");
        out.push_str("(allow file-read-metadata (literal \"/private/var\"))\n");
        out.push_str("(allow file-read-metadata (literal \"/private/var/run\"))\n");
        out.push_str("(allow file-read-metadata (literal \"/var\"))\n");
        out.push_str("(allow file-read-metadata (literal \"/var/run\"))\n");

        // ── Local IPC via Unix domain sockets ─────────────────────────────
        // Some tools (argocd SSO login, language servers, CLIs doing
        // loopback IPC) need to `bind()` a Unix domain socket — typically
        // under `/tmp` or `$TMPDIR`. The default-deny blocks this with
        // `bind: operation not permitted`.
        //
        // Scope is `(local unix-socket)` only: TCP/UDP listens remain
        // denied, so a tool cannot become a network-reachable service.
        out.push_str("(allow network-bind (local unix-socket))\n");
    }

    fn generate_profile(policy: &ToolPolicy) -> Result<String, SandboxError> {
        let mut out = String::with_capacity(4096);

        // Tool profiles restrict signal and process-info scope to the process
        // itself — tools run as single processes, not process trees.
        emit_common_rules("self", &mut out);

        // ── Binary executable read access ────────────────────────────────────
        // On macOS, Security.framework re-reads the process's own binary at
        // runtime for code signature verification (e.g. during TLS handshake
        // via `SecPolicyCreateSSL`). `process-exec*` covers loading the binary
        // into memory during exec, but this subsequent re-read is a separate
        // `file-read-data` operation that the sandbox must explicitly allow.
        // Without it, TLS certificate verification fails with
        // "SecPolicyCreateSSL error: 0".
        if let Some(ref binary) = policy.binary_path {
            emit_ancestor_rules(binary, &mut out)?;
            let escaped = escape_path(binary)?;
            out.push_str(&format!("(allow file-read* (literal \"{escaped}\"))\n"));
            // If the binary path has a different canonical form (e.g., the
            // daemon resolved a symlink), emit rules for both.
            if let Some(canonical) = try_canonicalize(binary) {
                emit_ancestor_rules(&canonical, &mut out)?;
                let escaped = escape_path(&canonical)?;
                out.push_str(&format!("(allow file-read* (literal \"{escaped}\"))\n"));
            }
        }

        emit_filesystem_rules(&policy.read_paths, &policy.read_write_paths, &mut out)?;

        if policy.requires_network {
            emit_network_rules(&mut out);
        }
        // If requires_network is false, the default deny handles blocking;
        // no explicit rule is needed.

        Ok(out)
    }

    /// Escape ERE metacharacters so a literal path can be safely embedded in
    /// a Seatbelt `(regex #"...")` pattern.
    ///
    /// The output of this function is subsequently passed through
    /// [`escape_path`]-style escaping for the surrounding SBPL string: a
    /// literal `\` in the regex produces `\\` in the emitted Rust source.
    fn regex_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 8);
        for ch in s.chars() {
            match ch {
                '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|'
                | '\\' => {
                    out.push('\\');
                    out.push(ch);
                }
                _ => out.push(ch),
            }
        }
        out
    }

    fn generate_agent_profile(
        policy: &AgentPolicy,
        profile: Option<AgentProfileKind>,
    ) -> Result<String, SandboxError> {
        let mut out = String::with_capacity(4096);

        // Agent profiles extend signal and process-info scope to same-sandbox so
        // the agent can signal and inspect its own child processes, which inherit
        // the profile. Tool profiles use `(target self)` instead, which is
        // narrower and appropriate for single-process tools.
        emit_common_rules("same-sandbox", &mut out);

        // ── Agent-only system permissions ─────────────────────────────────────
        // User preferences (NSUserDefaults) and distributed notifications are
        // used by interactive agent sessions. Short-lived tool invocations don't
        // need them, so these are omitted from the tool profile.
        out.push_str("(allow user-preference-read)\n");
        out.push_str("(allow distributed-notification-post)\n");
        // mach-priv-task-port is needed by debuggers and profilers to obtain the
        // task port of other processes in the same sandbox. All other mach-priv*
        // operations remain denied by (deny default).
        out.push_str("(allow mach-priv-task-port (target same-sandbox))\n");

        // ── Terminal device access ────────────────────────────────────────────
        // Agents drive interactive sessions and need read/write access to the
        // controlling terminal (`/dev/tty`) and the pseudo-terminal device tree
        // (`/dev/ttys*`). Tool profiles intentionally omit these rules.
        //
        // `pseudo-tty` is a distinct SBPL operation class (separate from
        // `file-ioctl`) that covers PTY-specific ioctls — TIOCSETA/TIOCGETA
        // (tcsetattr/tcgetattr), TIOCPTYGNAME, and friends. Without it,
        // interactive programs (nano, vim, less, etc.) cannot switch the
        // terminal into raw mode: tcsetattr returns EPERM, the terminal
        // stays in cooked mode, arrow keys emit raw escape sequences that
        // echo as garbage (^[[A, ^[[B, …), and signal generation misbehaves.
        // `file-ioctl` on /dev/ttys* and /dev/pty* is also required for
        // non-pseudo-tty ioctls (TIOCGWINSZ for window size, etc.).
        if policy.requires_terminal {
            out.push_str("(allow pseudo-tty)\n");
            out.push_str("(allow file-read* file-write* (literal \"/dev/tty\"))\n");
            out.push_str("(allow file-read* file-write* (regex #\"^/dev/ttys[0-9]+$\"))\n");
            out.push_str("(allow file-read* file-write* (regex #\"^/dev/pty[a-z][0-9a-f]+$\"))\n");
            out.push_str("(allow file-read* file-write* (literal \"/dev/ptmx\"))\n");
            out.push_str("(allow file-ioctl (regex #\"^/dev/ttys[0-9]+$\"))\n");
            out.push_str("(allow file-ioctl (regex #\"^/dev/pty[a-z][0-9a-f]+$\"))\n");
            out.push_str("(allow file-ioctl (literal \"/dev/ptmx\"))\n");
        }

        // ── /Applications read access ─────────────────────────────────────────
        // Agent sessions need to read from installed app bundles: terminal
        // emulators ship their own terminfo (iTerm → /Applications/iTerm.app/
        // Contents/Resources/terminfo), editors ship helper binaries, and CLI
        // tools installed via app bundles put their shared libs here. Bundle
        // contents are user-installed public data, not secrets. Tool profiles
        // stay narrower and do not inherit this rule.
        out.push_str("(allow file-read* (subpath \"/Applications\"))\n");

        // `$HOME/Applications` is the per-user Applications directory macOS
        // uses for user-scoped installs (e.g. Claude Code's URL handler
        // bundle). Resolved at profile-build time; skipped silently when HOME
        // is unset.
        if let Ok(home) = std::env::var("HOME") {
            let user_apps = std::path::PathBuf::from(&home).join("Applications");
            let escaped = escape_path(&user_apps)?;
            out.push_str(&format!("(allow file-read* (subpath \"{escaped}\"))\n"));
        }

        // ── Timezone data ─────────────────────────────────────────────────────
        // libc time functions (localtime, strftime, etc.) read the zoneinfo
        // database. Without access, `TZ` falls back to UTC and timestamps in
        // logs/telemetry are off. Both paths are public, read-only system data.
        out.push_str("(allow file-read* (subpath \"/usr/share/zoneinfo\"))\n");
        out.push_str("(allow file-read* (subpath \"/private/var/db/timezone\"))\n");

        // ── /dev directory enumeration ────────────────────────────────────────
        // Agents stat and list /dev to discover the controlling TTY and other
        // device nodes. Individual devices (ttys, ptmx, null, random, ...)
        // already have explicit rules; this allows the top-level directory
        // lookup itself.
        out.push_str("(allow file-read-metadata (literal \"/dev\"))\n");
        out.push_str("(allow file-read-data (literal \"/dev\"))\n");

        // ── Default shell selector ────────────────────────────────────────────
        // `/private/var/select/sh` is the macOS pointer to the active `/bin/sh`.
        // Consulted by libSystem whenever a subprocess spawns `sh` (popen,
        // system(), make, npm scripts, shell-based tooling). Read-only system
        // metadata; no credentials.
        out.push_str("(allow file-read-metadata (literal \"/private/var/select/sh\"))\n");

        // ── /tmp existence probe ──────────────────────────────────────────────
        // Tools frequently `stat("/tmp")` as a prelude to `mkdtemp()` or a
        // `TMPDIR` fallback. Granting only file-read-metadata on the directory
        // literals lets these probes succeed without exposing any contents —
        // general read/write of /tmp contents remains denied. The per-session
        // macOS scratch directory (`$TMPDIR`, typically `/var/folders/...`) is
        // granted full access below.
        out.push_str("(allow file-read-metadata (literal \"/tmp\"))\n");
        out.push_str("(allow file-read-metadata (literal \"/private/tmp\"))\n");

        // ── $TMPDIR (per-session scratch) ─────────────────────────────────────
        // macOS gives each user/session a private scratch directory under
        // `/var/folders/...` and exports it via `TMPDIR`. Processes use it for
        // atomic writes, caches, and `mkstemp` output. Canonicalised at
        // profile-build time (the `/var` → `/private/var` symlink must be
        // resolved because Seatbelt evaluates rules against the resolved path).
        // Silently skipped when `TMPDIR` is unset or cannot be resolved.
        if let Ok(tmpdir) = std::env::var("TMPDIR") {
            let tmpdir_path = std::path::PathBuf::from(&tmpdir);
            if let Ok(canonical) = std::fs::canonicalize(&tmpdir_path) {
                let escaped = escape_path(&canonical)?;
                out.push_str(&format!(
                    "(allow file-read* file-write* (subpath \"{escaped}\"))\n"
                ));
            }
        }

        // ── ~/.CFUserTextEncoding ─────────────────────────────────────────────
        // Per-user text encoding hint consulted by Core Foundation and several
        // Apple frameworks before they initialise locale-dependent behaviour.
        // Contents are a single short numeric line (encoding id + region); no
        // credentials. Resolved at profile-build time from $HOME; skipped
        // silently if HOME is unset.
        if let Ok(home) = std::env::var("HOME") {
            let encoding_path = std::path::PathBuf::from(home).join(".CFUserTextEncoding");
            let escaped = escape_path(&encoding_path)?;
            out.push_str(&format!("(allow file-read* (literal \"{escaped}\"))\n"));
        }

        emit_filesystem_rules(&policy.read_paths, &policy.read_write_paths, &mut out)?;

        // ── Profile-specific rules ────────────────────────────────────────────
        // Extras that cannot be expressed as simple subpath allows and are
        // therefore not routed through `emit_filesystem_rules`.
        if let Some(kind) = profile {
            emit_profile_rules(kind, &mut out)?;
        }

        // Agents always require network access; the field governs this conditional
        // for forward-compatibility.
        if policy.requires_network {
            emit_network_rules(&mut out);

            // ── Loopback TCP/UDP bind + inbound ───────────────────────────────
            // Agents commonly spin up ephemeral loopback listeners: OAuth
            // redirect catchers, local MCP servers, LSPs, test harnesses. The
            // base `emit_network_rules` only permits Unix-socket binds; widen
            // that here to TCP/UDP on `localhost` (127.0.0.1 / ::1) so these
            // services work without letting the agent become reachable on
            // external interfaces. `network-inbound` lets `accept()` succeed
            // on the same scope; without it the listen socket binds but the
            // kernel rejects every incoming connection. Tool profiles stay
            // narrower and do not inherit these rules.
            out.push_str("(allow network-bind (local tcp \"localhost:*\"))\n");
            out.push_str("(allow network-bind (local udp \"localhost:*\"))\n");
            out.push_str("(allow network-inbound (local tcp \"localhost:*\"))\n");
            out.push_str("(allow network-inbound (local udp \"localhost:*\"))\n");
        }

        Ok(out)
    }

    /// Emit SBPL rules tailored to a specific built-in agent profile.
    ///
    /// These rules typically rely on regex patterns — Seatbelt-only — to grant
    /// access to file-name families that can't be covered by a single subpath
    /// rule (atomic-write lockfiles and per-pid temp files, for example).
    fn emit_profile_rules(kind: AgentProfileKind, out: &mut String) -> Result<(), SandboxError> {
        match kind {
            AgentProfileKind::Claude => emit_claude_profile_rules(out),
            AgentProfileKind::ClaudeRelaxed => {
                emit_claude_profile_rules(out)?;
                emit_claude_relaxed_profile_rules(out)
            }
        }
    }

    /// Emit the interactive-ergonomics bundle on top of the base Claude rules:
    /// clipboard, `open <url>` via Launch Services, default-browser lookup, and
    /// shell init dotfile reads. Each entry is a deliberate widening of the
    /// data-leak surface — clipboard reads can yield password-manager tokens,
    /// `open <url>` exposes URLs (including OAuth redirect tokens) to the
    /// browser process, and the dotfiles often carry exported credentials
    /// (`AWS_*`, `GITHUB_TOKEN`). Gated by the explicit `claude-relaxed`
    /// profile choice rather than the standard `claude` profile.
    fn emit_claude_relaxed_profile_rules(out: &mut String) -> Result<(), SandboxError> {
        // Keychain Mach endpoints. `com.apple.securityd.xpc` is the modern
        // `securityd`/Keychain Services entry point used by `SecItem*`;
        // `com.apple.SecurityServer` is the legacy alias the
        // `SecKeychainItem*` APIs (and `/usr/bin/security`) still reach for
        // during writes. Both are intentionally absent from the baseline so
        // the standard `claude` profile cannot read other apps' keychain
        // items; the relaxed profile opts back in alongside the
        // `~/Library/Keychains/` filesystem write that the legacy write API
        // also needs. See [SECURITY.md](SECURITY.md) for the trade-offs.
        out.push_str("(allow mach-lookup\n");
        out.push_str("  (global-name \"com.apple.securityd.xpc\")\n");
        out.push_str("  (global-name \"com.apple.SecurityServer\")\n");
        out.push_str(")\n");

        // Clipboard. The pasteboard server (`com.apple.pasteboard.1`)
        // brokers all reads and writes of the system clipboard.
        out.push_str("(allow mach-lookup (global-name \"com.apple.pasteboard.1\"))\n");

        // URL opening via `/usr/bin/open`. Goes through Launch Services:
        // `lsd.open` + `coreservicesd` resolve the URL handler, then a
        // `GURL` Apple Event is dispatched via `coreservices.appleevents`.
        // The sibling services (quarantine-resolver, sharedfilelistd,
        // DiskArbitration, metadata.mds.legacy) are consulted during
        // bundle validation and recent-items tracking.
        //
        // Intentionally excluded: `com.apple.SharedWebCredentials`
        // (keychain-adjacent) and `com.apple.analyticsd` /
        // `com.apple.diagnosticd` (telemetry — denied everywhere by design).
        out.push_str("(allow mach-lookup\n");
        out.push_str("  (global-name \"com.apple.lsd.open\")\n");
        out.push_str("  (global-name \"com.apple.CoreServices.coreservicesd\")\n");
        out.push_str("  (global-name \"com.apple.coreservices.appleevents\")\n");
        out.push_str("  (global-name \"com.apple.coreservices.quarantine-resolver\")\n");
        out.push_str("  (global-name \"com.apple.coreservices.sharedfilelistd.xpc\")\n");
        out.push_str("  (global-name \"com.apple.DiskArbitration.diskarbitrationd\")\n");
        out.push_str("  (global-name \"com.apple.metadata.mds.legacy\")\n");
        out.push_str(")\n");

        // Seatbelt gates the actual LSOpen/LSOpenCFURLRef call via a
        // dedicated `lsopen` operation class separate from `mach-lookup`.
        // Without it the Mach services above can be reached but
        // `open <url>` still fails with `deny(1) lsopen`.
        out.push_str("(allow lsopen)\n");

        // Launch Services consults `.GlobalPreferences{,_m}.plist` and
        // the per-host `ByHost/.GlobalPreferences.<UUID>.plist` to pick
        // the default URL handler. The UUID in the ByHost filename is
        // host-specific and unknown at compile time, so match it with a
        // regex. No credentials live in these plists — they are
        // app-binding and locale preferences.
        if let Ok(home) = std::env::var("HOME") {
            let prefs = std::path::PathBuf::from(&home).join("Library/Preferences");
            let pattern = format!(
                "^{}/(ByHost/)?\\.GlobalPreferences.*\\.plist$",
                regex_escape(&prefs.to_string_lossy())
            );
            out.push_str(&format!("(allow file-read* (regex #\"{pattern}\"))\n"));
        }

        // Shell initialisation files. `bash`/`zsh` source these on every
        // interactive spawn — without them the shell starts in a bare
        // environment and the user's PATH, aliases, and prompt functions
        // are missing. Read-only; the agent cannot modify them.
        if let Ok(home) = std::env::var("HOME") {
            const DOTFILES: &[&str] = &[
                ".bashrc",
                ".bash_profile",
                ".bash_login",
                ".profile",
                ".zshrc",
                ".zprofile",
                ".zshenv",
                ".zlogin",
                ".inputrc",
            ];
            let home_path = std::path::PathBuf::from(&home);
            for name in DOTFILES {
                let escaped = escape_path(&home_path.join(name))?;
                out.push_str(&format!("(allow file-read* (literal \"{escaped}\"))\n"));
            }
        }

        Ok(())
    }

    /// Widen write access around `~/.claude.json` to cover the sibling lock
    /// file and per-pid `.tmp.*` files Claude Code creates during atomic
    /// config writes (`{path}.lock`, `{path}.tmp.{pid}.{ts}`), plus the
    /// top-level `~/.claude.lock` Claude Code uses to serialize concurrent
    /// instances. Skipped silently if `HOME` is unset.
    fn emit_claude_profile_rules(out: &mut String) -> Result<(), SandboxError> {
        let Ok(home) = std::env::var("HOME") else {
            return Ok(());
        };

        let base = std::path::PathBuf::from(&home).join(".claude.json");
        // Reject control characters in the path (same invariant as
        // `escape_path`) — they would be unsafe inside the SBPL regex literal.
        for ch in base.to_string_lossy().chars() {
            let code = ch as u32;
            if code <= 0x1F || code == 0x7F {
                return Err(SandboxError::ControlCharacterInPath(base.clone()));
            }
        }

        // Build an ERE that matches `{base}` plus `{base}.lock` and
        // `{base}.tmp.<anything>`. SBPL `#"..."` is a raw regex literal, so
        // backslashes pass through unescaped.
        let pattern = format!(
            "^{}(\\.lock|\\.tmp\\..*)?$",
            regex_escape(&base.to_string_lossy())
        );
        out.push_str(&format!(
            "(allow file-read* file-write* (regex #\"{pattern}\"))\n"
        ));

        let lock = std::path::PathBuf::from(&home).join(".claude.lock");
        let escaped_lock = escape_path(&lock)?;
        out.push_str(&format!(
            "(allow file-read* file-write* (literal \"{escaped_lock}\"))\n"
        ));

        Ok(())
    }

    // ─── MacOSSeatbelt ───────────────────────────────────────────────────────

    /// macOS Seatbelt sandbox backend.
    ///
    /// Translates a `ToolPolicy` into a pre-built SBPL profile stored as a
    /// null-terminated C string. All work is done in `build()` before any fork,
    /// so the `pre_exec` closure can apply the sandbox with zero allocation.
    pub struct MacOSSeatbelt;

    impl super::SandboxBackend for MacOSSeatbelt {
        fn build(&self, policy: &ToolPolicy) -> Result<SandboxProfile, SandboxError> {
            let sbpl = generate_profile(policy)?;
            let cstring = CString::new(sbpl).map_err(|_| {
                SandboxError::ProfileBuildError(
                    "generated SBPL contained an interior null byte".to_string(),
                )
            })?;
            Ok(SandboxProfile {
                inner: MacOSProfile { sbpl: cstring },
            })
        }

        fn build_agent(
            &self,
            policy: &AgentPolicy,
            profile: Option<AgentProfileKind>,
        ) -> Result<SandboxProfile, SandboxError> {
            let sbpl = generate_agent_profile(policy, profile)?;
            let cstring = CString::new(sbpl).map_err(|_| {
                SandboxError::ProfileBuildError(
                    "generated SBPL contained an interior null byte".to_string(),
                )
            })?;
            Ok(SandboxProfile {
                inner: MacOSProfile { sbpl: cstring },
            })
        }
    }

    // ─── Tests ───────────────────────────────────────────────────────────────

    #[cfg(test)]
    mod tests {
        use std::path::PathBuf;

        use super::super::{SandboxBackend, ToolPolicy};
        use super::MacOSSeatbelt;

        fn read_only_policy(path: &str) -> ToolPolicy {
            ToolPolicy {
                read_paths: vec![PathBuf::from(path)],
                read_write_paths: vec![],
                requires_network: false,
                binary_path: None,
            }
        }

        fn read_write_policy(path: &str) -> ToolPolicy {
            ToolPolicy {
                read_paths: vec![],
                read_write_paths: vec![PathBuf::from(path)],
                requires_network: false,
                binary_path: None,
            }
        }

        fn empty_policy() -> ToolPolicy {
            ToolPolicy {
                read_paths: vec![],
                read_write_paths: vec![],
                requires_network: false,
                binary_path: None,
            }
        }

        fn network_policy() -> ToolPolicy {
            ToolPolicy {
                read_paths: vec![],
                read_write_paths: vec![],
                requires_network: true,
                binary_path: None,
            }
        }

        /// Extract the SBPL string from a profile for inspection in tests.
        ///
        /// Uses `SandboxProfile::as_ptr()` (the same interface used by exec::spawn)
        /// via an unsafe CStr conversion, exercising the full public API path.
        fn sbpl_from_profile(policy: &ToolPolicy) -> String {
            let backend = MacOSSeatbelt;
            let profile = backend.build(policy).expect("build should succeed");
            // SAFETY: as_ptr() returns a pointer to a valid, null-terminated CString
            // owned by `profile`, which is live for the duration of this call.
            unsafe {
                std::ffi::CStr::from_ptr(profile.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            }
        }

        // ── Trait bound compile-time verification ────────────────────────────

        /// Verify at compile time that `MacOSSeatbelt` implements `SandboxBackend`.
        #[test]
        fn macos_seatbelt_implements_sandbox_backend() {
            fn accepts_backend<B: SandboxBackend>(_b: &B) {}
            accepts_backend(&MacOSSeatbelt);
        }

        // ── SandboxProfile Send + Sync + 'static ─────────────────────────────

        #[test]
        fn sandbox_profile_is_send_sync_static() {
            use super::super::SandboxProfile;

            fn assert_send_sync_static<T: Send + Sync + 'static>() {}
            assert_send_sync_static::<SandboxProfile>();

            // Also exercise moving a profile into a spawned thread.
            let profile = MacOSSeatbelt
                .build(&empty_policy())
                .expect("build should succeed");
            let handle = std::thread::spawn(move || {
                // Touch the profile via its public interface to confirm Send + Sync.
                // SAFETY: pointer is valid for the lifetime of profile.
                let _ = unsafe { std::ffi::CStr::from_ptr(profile.as_ptr()) };
            });
            handle.join().expect("thread should not panic");
        }

        // ── Empty policy ─────────────────────────────────────────────────────

        #[test]
        fn empty_policy_produces_valid_sbpl() {
            let sbpl = sbpl_from_profile(&empty_policy());
            assert!(
                sbpl.starts_with("(version 1)"),
                "SBPL should start with (version 1), got: {sbpl}"
            );
            assert!(
                sbpl.contains("(deny default)"),
                "SBPL should contain (deny default), got: {sbpl}"
            );
            assert!(
                sbpl.contains("(allow process-exec)\n"),
                "SBPL should contain (allow process-exec), got: {sbpl}"
            );
            assert!(
                sbpl.contains("(allow sysctl-read\n"),
                "SBPL should contain sysctl-read block, got: {sbpl}"
            );
            assert!(
                sbpl.contains("\"hw.pagesize\""),
                "SBPL sysctl-read block should include hw.pagesize, got: {sbpl}"
            );
        }

        // ── Process self-inspection ─────────────────────────────────────────

        #[test]
        fn profile_allows_signal_and_process_info_for_self() {
            let sbpl = sbpl_from_profile(&empty_policy());
            assert!(
                sbpl.contains("(allow signal (target self))"),
                "SBPL should allow signal (target self), got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("(allow process-info* (target self))"),
                "SBPL should allow process-info* (target self), got:\n{sbpl}"
            );
        }

        // ── Mach IPC ─────────────────────────────────────────────────────────

        #[test]
        fn profile_allows_mach_lookup_via_allowlist() {
            let sbpl = sbpl_from_profile(&empty_policy());
            // Profile must use the allowlist form, not a blanket (allow mach-lookup).
            assert!(
                sbpl.contains("(allow mach-lookup\n"),
                "SBPL should contain mach-lookup allowlist block, got:\n{sbpl}"
            );
            assert!(
                !sbpl.contains("(allow mach-lookup)\n"),
                "SBPL must not use blanket (allow mach-lookup), got:\n{sbpl}"
            );
            // A representative set of services from the allowlist. `trustd.agent`
            // is the load-bearing one for TLS — verify it's present so a
            // future refactor doesn't accidentally break HTTPS.
            for service in &[
                "com.apple.logd",
                "com.apple.fonts",
                "com.apple.trustd.agent",
            ] {
                assert!(
                    sbpl.contains(&format!("(global-name \"{service}\")")),
                    "SBPL mach-lookup allowlist should include {service}, got:\n{sbpl}"
                );
            }
        }

        #[test]
        fn profile_allows_fsevents_mach_service() {
            // File watchers (node --watch, vite, bun, cargo-watch) fail with
            // misleading errors — EMFILE from libuv — when fseventsd is
            // unreachable. Both profiles must reach it.
            let sbpl = sbpl_from_profile(&empty_policy());
            assert!(
                sbpl.contains("(global-name \"com.apple.FSEvents\")"),
                "SBPL should allow the FSEvents Mach service, got:\n{sbpl}"
            );
        }

        #[test]
        fn profile_mach_lookup_excludes_keychain_services() {
            let sbpl = sbpl_from_profile(&empty_policy());
            // Every Mach service that backs keychain access must be absent
            // from the baseline. The canonical modern endpoints
            // (`com.apple.securityd.xpc`, `com.apple.SecurityServer`) and the
            // legacy/alternative names are all denied by (deny default) — no
            // explicit (deny) rules are required, but we assert their absence
            // so a future refactor cannot silently grant keychain access.
            for service in &[
                "com.apple.SecurityServer",
                "com.apple.securityd.xpc",
                "com.apple.securityd",
                "com.apple.security.keychaind",
                "com.apple.secd",
                "com.apple.security.agent",
            ] {
                assert!(
                    !sbpl.contains(&format!("(global-name \"{service}\")")),
                    "SBPL must not include keychain service {service}, got:\n{sbpl}"
                );
            }
        }

        #[test]
        fn profile_denies_mach_priv_by_default() {
            // mach-priv* is denied by (deny default); no explicit rule is needed.
            let sbpl = sbpl_from_profile(&empty_policy());
            assert!(
                !sbpl.contains("mach-priv"),
                "tool SBPL should not contain any mach-priv rule (denied by default), got:\n{sbpl}"
            );
        }

        // ── sysctl allowlist ──────────────────────────────────────────────────

        #[test]
        fn profile_sysctl_read_uses_named_allowlist() {
            let sbpl = sbpl_from_profile(&empty_policy());
            assert!(
                !sbpl.contains("(allow sysctl-read)\n"),
                "SBPL must not use blanket (allow sysctl-read), got:\n{sbpl}"
            );
            for name in &["hw.pagesize", "hw.memsize", "kern.osproductversion"] {
                assert!(
                    sbpl.contains(&format!("(sysctl-name \"{name}\")")),
                    "SBPL sysctl allowlist should include {name}, got:\n{sbpl}"
                );
            }
        }

        // ── POSIX IPC ─────────────────────────────────────────────────────────

        #[test]
        fn profile_allows_posix_ipc() {
            let sbpl = sbpl_from_profile(&empty_policy());
            assert!(
                sbpl.contains("(allow ipc-posix-shm)"),
                "SBPL should allow ipc-posix-shm, got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("(allow ipc-posix-sem)"),
                "SBPL should allow ipc-posix-sem, got:\n{sbpl}"
            );
        }

        // ── IOKit ─────────────────────────────────────────────────────────────

        #[test]
        fn profile_allows_iokit() {
            let sbpl = sbpl_from_profile(&empty_policy());
            assert!(
                sbpl.contains("(allow iokit-open\n"),
                "SBPL should allow iokit-open, got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("IOSurfaceRootUserClient"),
                "SBPL iokit-open should include IOSurfaceRootUserClient, got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("(allow iokit-get-properties)"),
                "SBPL should allow iokit-get-properties, got:\n{sbpl}"
            );
        }

        // ── File ioctl on device files ────────────────────────────────────────

        #[test]
        fn profile_allows_file_ioctl_on_devices() {
            let sbpl = sbpl_from_profile(&empty_policy());
            for dev in &[
                "/dev/null",
                "/dev/zero",
                "/dev/random",
                "/dev/urandom",
                "/dev/tty",
            ] {
                assert!(
                    sbpl.contains(&format!("(allow file-ioctl (literal \"{dev}\"))")),
                    "SBPL should allow file-ioctl on {dev}, got:\n{sbpl}"
                );
            }
        }

        // ── AF_SYSTEM socket ──────────────────────────────────────────────────

        #[test]
        fn profile_allows_af_system_socket() {
            let sbpl = sbpl_from_profile(&empty_policy());
            assert!(
                sbpl.contains(
                    "(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))"
                ),
                "SBPL should allow AF_SYSTEM protocol-2 socket, got:\n{sbpl}"
            );
        }

        // ── System read paths ─────────────────────────────────────────────────

        #[test]
        fn profile_includes_system_read_paths() {
            let sbpl = sbpl_from_profile(&empty_policy());
            for path in &[
                "/usr/lib",
                "/usr/bin",
                "/usr/sbin",
                "/usr/share",
                "/bin",
                "/sbin",
                "/System",
                "/Library",
                "/private/etc",
                "/etc",
            ] {
                assert!(
                    sbpl.contains(&format!("(allow file-read* (subpath \"{path}\"))")),
                    "SBPL should grant file-read* on system path {path}, got:\n{sbpl}"
                );
            }
            for dev in &["/dev/null", "/dev/random", "/dev/urandom"] {
                assert!(
                    sbpl.contains(&format!("(allow file-read* (literal \"{dev}\"))")),
                    "SBPL should grant file-read* on {dev}, got:\n{sbpl}"
                );
            }
            assert!(
                sbpl.contains("(allow file-write* (literal \"/dev/null\"))"),
                "SBPL should grant file-write* on /dev/null (required for shell 2>/dev/null redirection), got:\n{sbpl}"
            );
        }

        // ── Read-only path ───────────────────────────────────────────────────

        #[test]
        fn read_only_path_produces_file_read_rule() {
            let sbpl = sbpl_from_profile(&read_only_policy("/usr/local/bin"));
            assert!(
                sbpl.contains("(allow file-read* (subpath \"/usr/local/bin\"))"),
                "SBPL should contain file-read* rule for path, got:\n{sbpl}"
            );
        }

        // ── Read-write path ──────────────────────────────────────────────────

        #[test]
        fn read_write_path_produces_both_rules() {
            let sbpl = sbpl_from_profile(&read_write_policy("/tmp/workdir"));
            assert!(
                sbpl.contains("file-read*"),
                "SBPL should contain file-read* rule, got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("file-write*"),
                "SBPL should contain file-write* rule, got:\n{sbpl}"
            );
            // Write rules must appear after read rules.
            let read_pos = sbpl.find("file-read*").unwrap();
            let write_pos = sbpl.find("file-write*").unwrap();
            assert!(
                write_pos > read_pos,
                "file-write* rule must appear after file-read* rule"
            );
        }

        // ── Network: requires_network = true ─────────────────────────────────

        #[test]
        fn network_policy_produces_allow_network_outbound() {
            let sbpl = sbpl_from_profile(&network_policy());
            assert!(
                sbpl.contains("(allow network-outbound)"),
                "SBPL should contain (allow network-outbound), got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("mDNSResponder"),
                "SBPL should contain mDNSResponder socket path, got:\n{sbpl}"
            );
        }

        // ── Network: DNS resolution requires file-read on mDNSResponder ─────

        #[test]
        fn network_policy_grants_file_read_on_mdnsresponder_socket() {
            let sbpl = sbpl_from_profile(&network_policy());
            // The DNS resolver library needs file-read access to the socket,
            // not just network-outbound permission.
            assert!(
                sbpl.contains("(allow file-read* (literal \"/private/var/run/mDNSResponder\"))"),
                "SBPL should grant file-read* on mDNSResponder canonical path, got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("(allow file-read* (literal \"/var/run/mDNSResponder\"))"),
                "SBPL should grant file-read* on mDNSResponder symlink path, got:\n{sbpl}"
            );
        }

        #[test]
        fn network_policy_grants_ancestor_metadata_for_mdnsresponder() {
            let sbpl = sbpl_from_profile(&network_policy());
            // Ancestor directory metadata is needed for path resolution.
            assert!(
                sbpl.contains("(allow file-read-metadata (literal \"/private/var\"))"),
                "SBPL should grant file-read-metadata on /private/var, got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("(allow file-read-metadata (literal \"/private/var/run\"))"),
                "SBPL should grant file-read-metadata on /private/var/run, got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("(allow file-read-metadata (literal \"/var\"))"),
                "SBPL should grant file-read-metadata on /var, got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("(allow file-read-metadata (literal \"/var/run\"))"),
                "SBPL should grant file-read-metadata on /var/run, got:\n{sbpl}"
            );
        }

        #[test]
        fn network_policy_allows_unix_socket_bind_only() {
            let sbpl = sbpl_from_profile(&network_policy());
            assert!(
                sbpl.contains("(allow network-bind (local unix-socket))"),
                "SBPL should allow Unix socket bind, got:\n{sbpl}"
            );
            assert!(
                !sbpl.contains("(allow network-bind (local ip"),
                "SBPL must not allow IP bind (TCP/UDP listen), got:\n{sbpl}"
            );
        }

        #[test]
        fn no_network_policy_omits_bind_rule() {
            let sbpl = sbpl_from_profile(&empty_policy());
            assert!(
                !sbpl.contains("network-bind"),
                "SBPL should not contain network-bind when network is off, got:\n{sbpl}"
            );
        }

        #[test]
        fn no_network_policy_omits_mdnsresponder_file_read() {
            let sbpl = sbpl_from_profile(&empty_policy());
            assert!(
                !sbpl.contains("mDNSResponder"),
                "SBPL should not contain any mDNSResponder rule when network is off, got:\n{sbpl}"
            );
        }

        // ── Network: requires_network = false ────────────────────────────────

        #[test]
        fn no_network_policy_contains_no_allow_network_rule() {
            let sbpl = sbpl_from_profile(&empty_policy());
            assert!(
                !sbpl.contains("allow network"),
                "SBPL should not contain any allow network rule, got:\n{sbpl}"
            );
        }

        // ── Null termination ─────────────────────────────────────────────────

        #[test]
        fn sandbox_profile_cstring_is_null_terminated_with_no_interior_nulls() {
            let backend = MacOSSeatbelt;
            let profile = backend
                .build(&read_only_policy("/usr/bin"))
                .expect("build should succeed");
            let bytes = profile.inner.as_bytes_with_nul();
            // Last byte must be NUL.
            assert_eq!(*bytes.last().unwrap(), 0, "CString must be null-terminated");
            // No interior NUL bytes.
            let interior = &bytes[..bytes.len() - 1];
            assert!(
                !interior.contains(&0u8),
                "CString must not contain interior null bytes"
            );
        }

        // ── Control character rejection ───────────────────────────────────────

        #[test]
        fn control_character_in_path_returns_error() {
            use super::super::SandboxError;

            let policy = ToolPolicy {
                read_paths: vec![PathBuf::from("/usr/local\nbad")],
                read_write_paths: vec![],
                requires_network: false,
                binary_path: None,
            };
            let result = MacOSSeatbelt.build(&policy);
            assert!(
                matches!(result, Err(SandboxError::ControlCharacterInPath(_))),
                "Expected ControlCharacterInPath error, got: {:?}",
                result
            );
        }

        // ── Symlink expansion ────────────────────────────────────────────────

        #[test]
        fn symlinked_path_produces_rules_for_both_original_and_canonical() {
            // On macOS, /tmp is a symlink to /private/tmp.
            // We check that both forms appear in the profile.
            let sbpl = sbpl_from_profile(&read_only_policy("/tmp"));
            // Original path rule.
            assert!(
                sbpl.contains("\"/tmp\""),
                "SBPL should contain rule for original path /tmp, got:\n{sbpl}"
            );
            // Canonical path rule.
            assert!(
                sbpl.contains("\"/private/tmp\""),
                "SBPL should contain rule for canonical path /private/tmp, got:\n{sbpl}"
            );
        }

        // ── Binary path (TLS code signature verification) ──────────────────

        #[test]
        fn binary_path_produces_file_read_literal_rule() {
            // When binary_path is set, the profile must contain a file-read*
            // literal rule for the binary so Security.framework can re-read
            // it during TLS certificate verification (SecPolicyCreateSSL).
            let policy = ToolPolicy {
                read_paths: vec![],
                read_write_paths: vec![],
                requires_network: true,
                binary_path: Some(PathBuf::from("/usr/local/bin/mytool")),
            };
            let sbpl = sbpl_from_profile(&policy);
            assert!(
                sbpl.contains("(allow file-read* (literal \"/usr/local/bin/mytool\"))"),
                "SBPL should contain file-read* literal rule for binary_path, got:\n{sbpl}"
            );
        }

        #[test]
        fn binary_path_emits_ancestor_metadata_rules() {
            // The sandbox must allow metadata reads on ancestor directories
            // so the kernel can traverse from / to the binary's location.
            let policy = ToolPolicy {
                read_paths: vec![],
                read_write_paths: vec![],
                requires_network: false,
                binary_path: Some(PathBuf::from("/opt/homebrew/Cellar/gh/2.0/bin/gh")),
            };
            let sbpl = sbpl_from_profile(&policy);
            for ancestor in &[
                "/opt/homebrew/Cellar/gh/2.0/bin",
                "/opt/homebrew/Cellar/gh/2.0",
                "/opt/homebrew/Cellar/gh",
                "/opt/homebrew/Cellar",
                "/opt/homebrew",
                "/opt",
            ] {
                assert!(
                    sbpl.contains(&format!(
                        "(allow file-read-metadata (literal \"{ancestor}\"))"
                    )),
                    "SBPL should contain ancestor metadata rule for {ancestor}, got:\n{sbpl}"
                );
            }
        }

        #[test]
        fn binary_path_none_omits_binary_read_rule() {
            // When binary_path is None (e.g. in unit tests), no binary-specific
            // file-read rules should appear.
            let sbpl = sbpl_from_profile(&empty_policy());
            // The profile should not contain any literal file-read rule for
            // /opt or /usr/local paths (beyond the hardcoded system paths).
            assert!(
                !sbpl.contains("/opt/"),
                "SBPL should not contain /opt/ rules when binary_path is None, got:\n{sbpl}"
            );
        }

        #[test]
        fn binary_path_symlink_produces_rules_for_both_forms() {
            // If the binary_path is a symlink, rules should be emitted for
            // both the original (symlink) and canonical (resolved) paths.
            // /tmp is a known macOS symlink to /private/tmp — use a path
            // under it to exercise both forms.
            let tmp = tempfile::NamedTempFile::new_in("/tmp").expect("create temp file");
            let symlink_path = tmp.path().to_path_buf();
            let canonical_path = std::fs::canonicalize(&symlink_path).unwrap();

            // Only run the assertion if the paths actually differ (symlink exists).
            if canonical_path != symlink_path {
                let policy = ToolPolicy {
                    read_paths: vec![],
                    read_write_paths: vec![],
                    requires_network: false,
                    binary_path: Some(symlink_path.clone()),
                };
                let sbpl = sbpl_from_profile(&policy);
                let symlink_escaped = symlink_path.to_string_lossy();
                let canonical_escaped = canonical_path.to_string_lossy();
                assert!(
                    sbpl.contains(&format!(
                        "(allow file-read* (literal \"{symlink_escaped}\"))"
                    )),
                    "SBPL should contain rule for symlink path, got:\n{sbpl}"
                );
                assert!(
                    sbpl.contains(&format!(
                        "(allow file-read* (literal \"{canonical_escaped}\"))"
                    )),
                    "SBPL should contain rule for canonical path, got:\n{sbpl}"
                );
            }
        }

        // ── AgentPolicy helpers ───────────────────────────────────────────────

        fn agent_policy_empty() -> super::super::AgentPolicy {
            super::super::AgentPolicy {
                read_paths: vec![],
                read_write_paths: vec![],
                requires_network: true,
                requires_terminal: true,
            }
        }

        fn agent_policy_with_read(path: &str) -> super::super::AgentPolicy {
            super::super::AgentPolicy {
                read_paths: vec![PathBuf::from(path)],
                read_write_paths: vec![],
                requires_network: true,
                requires_terminal: true,
            }
        }

        fn agent_policy_with_write(path: &str) -> super::super::AgentPolicy {
            super::super::AgentPolicy {
                read_paths: vec![],
                read_write_paths: vec![PathBuf::from(path)],
                requires_network: true,
                requires_terminal: true,
            }
        }

        /// Extract the SBPL string from an agent profile for inspection in tests.
        fn sbpl_from_agent_profile(policy: &super::super::AgentPolicy) -> String {
            sbpl_from_agent_profile_with_kind(policy, None)
        }

        fn sbpl_from_agent_profile_with_kind(
            policy: &super::super::AgentPolicy,
            kind: Option<super::super::AgentProfileKind>,
        ) -> String {
            let backend = MacOSSeatbelt;
            let profile = backend
                .build_agent(policy, kind)
                .expect("build_agent should succeed");
            // SAFETY: as_ptr() returns a pointer to a valid, null-terminated CString
            // owned by `profile`, which is live for the duration of this call.
            unsafe {
                std::ffi::CStr::from_ptr(profile.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            }
        }

        // ── AgentPolicy: signal scope ─────────────────────────────────────────

        #[test]
        fn agent_profile_uses_same_sandbox_for_signal() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            assert!(
                sbpl.contains("(allow signal (target same-sandbox))"),
                "agent SBPL should allow signal (target same-sandbox), got:\n{sbpl}"
            );
            assert!(
                !sbpl.contains("(allow signal (target self))"),
                "agent SBPL must NOT contain (allow signal (target self)), got:\n{sbpl}"
            );
        }

        // ── AgentPolicy: process-info scope ──────────────────────────────────

        #[test]
        fn agent_profile_uses_same_sandbox_for_process_info() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            assert!(
                sbpl.contains("(allow process-info* (target same-sandbox))"),
                "agent SBPL should allow process-info* (target same-sandbox), got:\n{sbpl}"
            );
            assert!(
                !sbpl.contains("(allow process-info* (target self))"),
                "agent SBPL must NOT contain (allow process-info* (target self)), got:\n{sbpl}"
            );
        }

        // ── AgentPolicy: terminal device access ───────────────────────────────

        #[test]
        fn agent_profile_includes_terminal_device_rules() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            assert!(
                sbpl.contains("(allow file-read* file-write* (literal \"/dev/tty\"))"),
                "agent SBPL should include /dev/tty read+write literal rule, got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("(allow file-read* file-write* (regex #\"^/dev/ttys[0-9]+$\"))"),
                "agent SBPL should include /dev/ttys regex read+write rule, got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("(allow file-ioctl (regex #\"^/dev/ttys[0-9]+$\"))"),
                "agent SBPL should include /dev/ttys file-ioctl regex rule (for tcsetattr/TIOCGWINSZ), got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("(allow pseudo-tty)"),
                "agent SBPL should include (allow pseudo-tty) for tcsetattr/raw-mode ioctls, got:\n{sbpl}"
            );
        }

        // ── AgentPolicy: network ──────────────────────────────────────────────

        #[test]
        fn agent_profile_includes_network_outbound() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            assert!(
                sbpl.contains("(allow network-outbound)"),
                "agent SBPL should contain (allow network-outbound), got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("mDNSResponder"),
                "agent SBPL should contain mDNSResponder rules, got:\n{sbpl}"
            );
        }

        // ── AgentPolicy: read_paths ───────────────────────────────────────────

        #[test]
        fn agent_profile_applies_read_paths() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_with_read("/usr/local/bin"));
            assert!(
                sbpl.contains("(allow file-read* (subpath \"/usr/local/bin\"))"),
                "agent SBPL should contain file-read* for read_paths entry, got:\n{sbpl}"
            );
        }

        // ── AgentPolicy: read_write_paths ─────────────────────────────────────

        #[test]
        fn agent_profile_applies_read_write_paths() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_with_write("/tmp/workdir"));
            assert!(
                sbpl.contains("file-read*"),
                "agent SBPL should contain file-read* rule for read_write path, got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("file-write*"),
                "agent SBPL should contain file-write* rule for read_write path, got:\n{sbpl}"
            );
            let read_pos = sbpl.find("file-read*").unwrap();
            let write_pos = sbpl.find("file-write*").unwrap();
            assert!(
                write_pos > read_pos,
                "file-write* rule must appear after file-read* rules in agent profile"
            );
        }

        // ── Tool profile unchanged: still uses (target self) ─────────────────

        #[test]
        fn tool_profile_still_uses_target_self_not_same_sandbox() {
            let sbpl = sbpl_from_profile(&empty_policy());
            assert!(
                sbpl.contains("(allow signal (target self))"),
                "tool SBPL should still use (target self) for signal, got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("(allow process-info* (target self))"),
                "tool SBPL should still use (target self) for process-info*, got:\n{sbpl}"
            );
            assert!(
                !sbpl.contains("(target same-sandbox)"),
                "tool SBPL must NOT contain (target same-sandbox), got:\n{sbpl}"
            );
        }

        // ── AgentPolicy: no binary_path rule ─────────────────────────────────

        #[test]
        fn agent_profile_has_no_binary_path_rule() {
            // AgentPolicy has no binary_path field; the agent profile must not
            // contain any literal file-read rule for a specific binary executable
            // beyond what is in the system baseline.
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            // The system baseline includes /usr/lib etc. but no user binaries.
            // Check that no literal file-read rule points to an arbitrary binary.
            assert!(
                !sbpl.contains("(allow file-read* (literal \"/opt/"),
                "agent SBPL must not contain literal binary path rules, got:\n{sbpl}"
            );
        }

        // ── AgentPolicy: system baseline present ──────────────────────────────

        #[test]
        fn agent_profile_includes_system_baseline() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            for path in &[
                "/usr/lib",
                "/usr/bin",
                "/usr/sbin",
                "/usr/share",
                "/bin",
                "/sbin",
                "/System",
                "/Library",
                "/private/etc",
                "/etc",
            ] {
                assert!(
                    sbpl.contains(&format!("(allow file-read* (subpath \"{path}\"))")),
                    "agent SBPL should include system baseline path {path}, got:\n{sbpl}"
                );
            }
        }

        // ── AgentPolicy: control character in path returns error ──────────────

        #[test]
        fn agent_profile_control_char_in_path_returns_error() {
            use super::super::SandboxError;

            let policy = super::super::AgentPolicy {
                read_paths: vec![PathBuf::from("/usr/local\nbad")],
                read_write_paths: vec![],
                requires_network: true,
                requires_terminal: true,
            };
            let result = MacOSSeatbelt.build_agent(&policy, None);
            assert!(
                matches!(result, Err(SandboxError::ControlCharacterInPath(_))),
                "Expected ControlCharacterInPath error, got: {:?}",
                result
            );
        }

        // ── AgentPolicy: agent-only permissions ──────────────────────────────

        #[test]
        fn agent_profile_includes_user_preference_read() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            assert!(
                sbpl.contains("(allow user-preference-read)"),
                "agent SBPL should include user-preference-read, got:\n{sbpl}"
            );
        }

        #[test]
        fn agent_profile_includes_distributed_notification_post() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            assert!(
                sbpl.contains("(allow distributed-notification-post)"),
                "agent SBPL should include distributed-notification-post, got:\n{sbpl}"
            );
        }

        #[test]
        fn agent_profile_allows_mach_priv_task_port_same_sandbox() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            assert!(
                sbpl.contains("(allow mach-priv-task-port (target same-sandbox))"),
                "agent SBPL should allow mach-priv-task-port (target same-sandbox), got:\n{sbpl}"
            );
        }

        #[test]
        fn agent_profile_allows_fsevents_mach_service() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            assert!(
                sbpl.contains("(global-name \"com.apple.FSEvents\")"),
                "agent SBPL should allow the FSEvents Mach service, got:\n{sbpl}"
            );
        }

        #[test]
        fn tool_profile_excludes_agent_only_permissions() {
            let sbpl = sbpl_from_profile(&empty_policy());
            assert!(
                !sbpl.contains("(allow user-preference-read)"),
                "tool SBPL must not contain user-preference-read, got:\n{sbpl}"
            );
            assert!(
                !sbpl.contains("(allow distributed-notification-post)"),
                "tool SBPL must not contain distributed-notification-post, got:\n{sbpl}"
            );
            assert!(
                !sbpl.contains("mach-priv-task-port"),
                "tool SBPL must not contain mach-priv-task-port, got:\n{sbpl}"
            );
            assert!(
                !sbpl.contains("(allow file-read* (subpath \"/Applications\"))"),
                "tool SBPL must not grant /Applications read, got:\n{sbpl}"
            );
        }

        #[test]
        fn agent_profile_includes_applications_read() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            assert!(
                sbpl.contains("(allow file-read* (subpath \"/Applications\"))"),
                "agent SBPL should grant read on /Applications (terminfo, app bundles), got:\n{sbpl}"
            );
        }

        #[test]
        fn agent_profile_includes_timezone_data_reads() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            assert!(
                sbpl.contains("(allow file-read* (subpath \"/usr/share/zoneinfo\"))"),
                "agent SBPL should grant read on /usr/share/zoneinfo, got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("(allow file-read* (subpath \"/private/var/db/timezone\"))"),
                "agent SBPL should grant read on /private/var/db/timezone, got:\n{sbpl}"
            );
        }

        #[test]
        fn agent_profile_includes_dev_directory_enumeration() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            assert!(
                sbpl.contains("(allow file-read-metadata (literal \"/dev\"))"),
                "agent SBPL should allow file-read-metadata on /dev, got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("(allow file-read-data (literal \"/dev\"))"),
                "agent SBPL should allow file-read-data on /dev (readdir), got:\n{sbpl}"
            );
        }

        #[test]
        fn agent_profile_includes_cf_user_text_encoding_when_home_set() {
            // HOME is read by the profile generator; serialize against any
            // other test that mutates HOME to avoid a flaky parallel race.
            let _guard = crate::test_support::ENV_MUTEX.lock().unwrap();
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            let home = std::env::var("HOME").expect("HOME should be set in test env");
            let expected = format!("(allow file-read* (literal \"{home}/.CFUserTextEncoding\"))");
            assert!(
                sbpl.contains(&expected),
                "agent SBPL should grant read on $HOME/.CFUserTextEncoding, \
                 expected line: {expected}\ngot:\n{sbpl}"
            );
        }

        #[test]
        fn agent_profile_claude_emits_dotclaude_json_regex() {
            let _guard = crate::test_support::ENV_MUTEX.lock().unwrap();
            let sbpl = sbpl_from_agent_profile_with_kind(
                &agent_policy_empty(),
                Some(super::super::AgentProfileKind::Claude),
            );
            let home = std::env::var("HOME").expect("HOME should be set in test env");
            // Build the expected ERE pattern the same way emit_claude_profile_rules
            // does: regex-escape the literal path and add the lock/tmp suffix.
            let escaped_home = super::regex_escape(&home);
            let expected = format!(
                "(allow file-read* file-write* (regex #\"^{escaped_home}/\\.claude\\.json(\\.lock|\\.tmp\\..*)?$\"))"
            );
            assert!(
                sbpl.contains(&expected),
                "Claude profile SBPL should grant rw regex on .claude.json family, \
                 expected line: {expected}\ngot:\n{sbpl}"
            );
            let expected_lock =
                format!("(allow file-read* file-write* (literal \"{home}/.claude.lock\"))");
            assert!(
                sbpl.contains(&expected_lock),
                "Claude profile SBPL should grant rw on ~/.claude.lock, \
                 expected line: {expected_lock}\ngot:\n{sbpl}"
            );
        }

        #[test]
        fn agent_profile_without_kind_omits_claude_regex() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            assert!(
                !sbpl.contains(".claude.json"),
                "non-Claude agent SBPL should not mention .claude.json, got:\n{sbpl}"
            );
        }

        #[test]
        fn agent_profile_claude_relaxed_reenables_keychain_mach_services() {
            // The baseline drops `com.apple.SecurityServer` and
            // `com.apple.securityd.xpc` so the strict `claude` profile cannot
            // reach the keychain at all. `claude-relaxed` must opt back in,
            // otherwise `security` reads/writes fail under the relaxed
            // profile too and the `~/Library/Keychains/` write rule we add is
            // pointless.
            let _guard = crate::test_support::ENV_MUTEX.lock().unwrap();
            let relaxed = sbpl_from_agent_profile_with_kind(
                &agent_policy_empty(),
                Some(super::super::AgentProfileKind::ClaudeRelaxed),
            );
            for service in &["com.apple.SecurityServer", "com.apple.securityd.xpc"] {
                assert!(
                    relaxed.contains(&format!("(global-name \"{service}\")")),
                    "ClaudeRelaxed must allow keychain Mach service {service}, got:\n{relaxed}"
                );
            }

            // The plain `claude` profile, by contrast, must NOT grant either
            // service — keychain stays out of reach for the strict variant.
            let strict = sbpl_from_agent_profile_with_kind(
                &agent_policy_empty(),
                Some(super::super::AgentProfileKind::Claude),
            );
            for service in &["com.apple.SecurityServer", "com.apple.securityd.xpc"] {
                assert!(
                    !strict.contains(&format!("(global-name \"{service}\")")),
                    "plain Claude profile must NOT allow keychain Mach service {service}, got:\n{strict}"
                );
            }
        }

        #[test]
        fn agent_profile_claude_relaxed_includes_base_claude_rules() {
            // `ClaudeRelaxed` must be a superset of `Claude`: the base
            // `.claude.json` regex and `.claude.lock` literal must both appear,
            // alongside the relaxed extras.
            let _guard = crate::test_support::ENV_MUTEX.lock().unwrap();
            let sbpl = sbpl_from_agent_profile_with_kind(
                &agent_policy_empty(),
                Some(super::super::AgentProfileKind::ClaudeRelaxed),
            );
            let home = std::env::var("HOME").expect("HOME should be set in test env");
            let escaped_home = super::regex_escape(&home);
            let expected_json = format!(
                "(allow file-read* file-write* (regex #\"^{escaped_home}/\\.claude\\.json(\\.lock|\\.tmp\\..*)?$\"))"
            );
            assert!(
                sbpl.contains(&expected_json),
                "ClaudeRelaxed must inherit the base .claude.json regex from Claude, \
                 expected line: {expected_json}\ngot:\n{sbpl}"
            );
            let expected_lock =
                format!("(allow file-read* file-write* (literal \"{home}/.claude.lock\"))");
            assert!(
                sbpl.contains(&expected_lock),
                "ClaudeRelaxed must inherit the base .claude.lock rule from Claude, \
                 expected line: {expected_lock}\ngot:\n{sbpl}"
            );
        }

        #[test]
        fn agent_profile_omits_relaxed_bundle_without_profile_kind() {
            // Without the ClaudeRelaxed profile, the agent must not see
            // clipboard, URL-opening services, lsopen, GlobalPreferences, or
            // shell-dotfile reads — each is gated behind that profile.
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            for needle in [
                "com.apple.pasteboard",
                "com.apple.lsd.open",
                "com.apple.coreservices.appleevents",
                "(allow lsopen)",
                "GlobalPreferences",
                ".bashrc",
                ".zshrc",
            ] {
                assert!(
                    !sbpl.contains(needle),
                    "non-relaxed SBPL must not contain {needle}, got:\n{sbpl}"
                );
            }
        }

        #[test]
        fn agent_profile_emits_relaxed_bundle_for_claude_relaxed_kind() {
            // Lock ENV_MUTEX — the relaxed bundle consults HOME for both the
            // GlobalPreferences regex and the shell-dotfile literal paths.
            let _guard = crate::test_support::ENV_MUTEX.lock().unwrap();
            let sbpl = sbpl_from_agent_profile_with_kind(
                &agent_policy_empty(),
                Some(super::super::AgentProfileKind::ClaudeRelaxed),
            );

            // Clipboard.
            assert!(
                sbpl.contains("(allow mach-lookup (global-name \"com.apple.pasteboard.1\"))"),
                "ClaudeRelaxed SBPL should allow pasteboard, got:\n{sbpl}"
            );

            // Launch Services mach services + lsopen op class.
            for name in [
                "com.apple.lsd.open",
                "com.apple.CoreServices.coreservicesd",
                "com.apple.coreservices.appleevents",
            ] {
                assert!(
                    sbpl.contains(&format!("(global-name \"{name}\")")),
                    "ClaudeRelaxed SBPL should allow mach-lookup {name}, got:\n{sbpl}"
                );
            }
            assert!(
                sbpl.contains("(allow lsopen)"),
                "ClaudeRelaxed SBPL should allow lsopen, got:\n{sbpl}"
            );

            // GlobalPreferences plist regex.
            let home = std::env::var("HOME").expect("HOME should be set in test env");
            let escaped_home = super::regex_escape(&home);
            let expected_regex = format!(
                "(allow file-read* (regex #\"^{escaped_home}/Library/Preferences/(ByHost/)?\\.GlobalPreferences.*\\.plist$\"))"
            );
            assert!(
                sbpl.contains(&expected_regex),
                "ClaudeRelaxed SBPL should allow GlobalPreferences plist reads, \
                 expected line: {expected_regex}\ngot:\n{sbpl}"
            );

            // Shell init dotfiles.
            for rc in [".bashrc", ".zshrc", ".profile", ".zshenv"] {
                let expected = format!("(allow file-read* (literal \"{home}/{rc}\"))");
                assert!(
                    sbpl.contains(&expected),
                    "ClaudeRelaxed SBPL should allow {rc}, got:\n{sbpl}"
                );
            }
        }

        #[test]
        fn agent_profile_omits_relaxed_bundle_for_plain_claude_kind() {
            // The standard Claude profile must NOT emit any of the relaxed extras.
            let _guard = crate::test_support::ENV_MUTEX.lock().unwrap();
            let sbpl = sbpl_from_agent_profile_with_kind(
                &agent_policy_empty(),
                Some(super::super::AgentProfileKind::Claude),
            );
            for needle in [
                "com.apple.pasteboard",
                "com.apple.lsd.open",
                "com.apple.coreservices.appleevents",
                "(allow lsopen)",
                "GlobalPreferences",
                ".bashrc",
            ] {
                assert!(
                    !sbpl.contains(needle),
                    "plain Claude SBPL must not contain {needle}, got:\n{sbpl}"
                );
            }
        }

        #[test]
        fn tool_profile_does_not_include_relaxed_bundle() {
            // The relaxed bundle is agent-only; tool profiles stay narrow.
            let sbpl = sbpl_from_profile(&network_policy());
            for needle in [
                "com.apple.pasteboard",
                "com.apple.lsd.open",
                "com.apple.coreservices.appleevents",
                "(allow lsopen)",
                "GlobalPreferences",
                ".bashrc",
            ] {
                assert!(
                    !sbpl.contains(needle),
                    "tool SBPL must not contain {needle}, got:\n{sbpl}"
                );
            }
        }

        #[test]
        fn agent_profile_allows_loopback_tcp_udp_bind() {
            let sbpl = sbpl_from_agent_profile(&agent_policy_empty());
            assert!(
                sbpl.contains("(allow network-bind (local tcp \"localhost:*\"))"),
                "agent SBPL should allow loopback TCP bind, got:\n{sbpl}"
            );
            assert!(
                sbpl.contains("(allow network-bind (local udp \"localhost:*\"))"),
                "agent SBPL should allow loopback UDP bind, got:\n{sbpl}"
            );
        }

        #[test]
        fn tool_profile_does_not_include_loopback_tcp_bind() {
            // Loopback TCP/UDP bind is agent-only; tool profiles stay narrower.
            let sbpl = sbpl_from_profile(&network_policy());
            assert!(
                !sbpl.contains("(allow network-bind (local tcp"),
                "tool SBPL must not grant loopback TCP bind, got:\n{sbpl}"
            );
            assert!(
                !sbpl.contains("(allow network-bind (local udp"),
                "tool SBPL must not grant loopback UDP bind, got:\n{sbpl}"
            );
        }
    }
}

// ─── Linux implementation ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub mod linux {
    use std::os::unix::io::{AsRawFd, OwnedFd};

    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr,
    };

    use super::{AgentPolicy, SandboxBackend, SandboxError, SandboxProfile, ToolPolicy};

    /// Convert any `Display`-able Landlock error into a [`SandboxError::ProfileBuildError`].
    ///
    /// Extracted to deduplicate the identical error-mapping closure that appeared
    /// six times in `LinuxLandlock::build()`.
    fn to_profile_err(e: impl std::fmt::Display) -> SandboxError {
        SandboxError::ProfileBuildError(format!("{e}"))
    }

    /// Baseline read-only paths granted to every tool, mirroring the macOS
    /// Seatbelt baseline. These are the files virtually every dynamically
    /// linked program needs at runtime — the dynamic linker, libc, system
    /// configuration, and entropy. They contain no user secrets.
    ///
    /// Paths that don't exist on the running distro (e.g. `/lib64` on
    /// non-x86_64 systems, or `/usr/bin` on a stripped image) are silently
    /// skipped — `PathFd::new` fails with `ENOENT` and we move on.
    const LINUX_BASELINE_READ_PATHS: &[&str] = &[
        // Shared libraries and the dynamic linker.
        "/usr/lib",
        "/usr/lib64",
        "/lib",
        "/lib64",
        // Shared data: locale, terminfo, CA bundles.
        "/usr/share",
        // System binaries — many tools fork helpers (`gh` calls `git`,
        // `gcloud` calls `python`, etc.).
        "/usr/bin",
        "/bin",
        // System configuration: /etc/ssl/certs, /etc/resolv.conf,
        // /etc/hosts, /etc/nsswitch.conf, ...
        "/etc",
        // Entropy and the canonical bit-bucket.
        "/dev/null",
        "/dev/random",
        "/dev/urandom",
    ];

    /// Extended baseline read-only paths granted to every agent process.
    ///
    /// Includes all paths from [`LINUX_BASELINE_READ_PATHS`] plus `/usr/sbin`,
    /// which agents need because they may invoke administrative helpers that
    /// tools do not require. Listed explicitly to keep the definition
    /// independently readable.
    const LINUX_AGENT_BASELINE_READ_PATHS: &[&str] = &[
        // Shared libraries and the dynamic linker.
        "/usr/lib",
        "/usr/lib64",
        "/lib",
        "/lib64",
        // Shared data: locale, terminfo, CA bundles.
        "/usr/share",
        // System binaries — many tools fork helpers (`gh` calls `git`,
        // `gcloud` calls `python`, etc.).
        "/usr/bin",
        "/bin",
        // System administrative binaries — agents may invoke these when
        // driving interactive sessions (tools do not require this path).
        "/usr/sbin",
        // System configuration: /etc/ssl/certs, /etc/resolv.conf,
        // /etc/hosts, /etc/nsswitch.conf, ...
        "/etc",
        // Entropy and the canonical bit-bucket.
        "/dev/null",
        "/dev/random",
        "/dev/urandom",
    ];

    // ─── Internal profile type ───────────────────────────────────────────────

    /// Internal Linux profile — wraps the raw Landlock ruleset fd and its owner.
    ///
    /// On Linux, `SandboxProfile` stores two values:
    /// - `fd`: the raw integer captured by the `pre_exec` closure; `Copy`,
    ///   `Send`, `Sync`, `'static` — can be moved into any closure safely.
    /// - `owned_fd`: the `OwnedFd` that keeps the kernel Landlock ruleset object
    ///   alive until after `exec::spawn()` returns.
    pub struct LinuxProfile {
        /// Raw fd integer inherited by the child across fork.
        fd: i32,
        /// Owns the underlying kernel object. Closed via `close_ruleset_fd()`.
        owned_fd: Option<OwnedFd>,
    }

    // SAFETY: `i32` is trivially Send + Sync. `OwnedFd` is Send + Sync per std.
    // No interior mutability in either field.
    unsafe impl Send for LinuxProfile {}
    unsafe impl Sync for LinuxProfile {}

    impl LinuxProfile {
        /// Returns the raw fd integer for use inside the `pre_exec` closure.
        ///
        /// Valid until `close_ruleset_fd()` is called. The value is `Copy` and
        /// safe to capture by value in the `pre_exec` closure.
        pub(crate) fn raw_fd(&self) -> i32 {
            self.fd
        }

        /// Explicitly closes the parent's copy of the Landlock ruleset fd.
        ///
        /// Drops the `OwnedFd`, which closes the underlying file descriptor.
        /// The close site is intentionally explicit (not `Drop`) so it is
        /// visible at the `exec::spawn()` call site.
        pub(crate) fn close_ruleset_fd(&mut self) {
            // `take()` extracts the OwnedFd from the Option and drops it,
            // closing the fd. Subsequent calls are safe no-ops.
            self.owned_fd.take();
        }

        /// Test-only constructor for creating a profile with an arbitrary raw fd.
        ///
        /// Intended exclusively for `exec.rs` test code to construct a profile
        /// with a known-invalid fd to trigger child-side `pre_exec` failures
        /// without going through the Landlock builder chain.
        #[cfg(test)]
        pub(crate) fn new_for_test(fd: i32) -> Self {
            LinuxProfile { fd, owned_fd: None }
        }
    }

    /// Test-only probe for asserting that a raw fd was closed by the code
    /// under test.
    ///
    /// `fcntl(fd, F_GETFD)` cannot answer that reliably inside the test
    /// binary: other test threads and the tokio runtime open and close fds
    /// concurrently, so the moment `fd` is closed its number can be handed to
    /// someone else and the probe reports a stranger's fd as "still open".
    /// The probe therefore marks the *open file description* rather than the
    /// number — it stamps the description's owner (`F_SETOWN`) with our own
    /// pid, which lives on the description for exactly as long as some fd
    /// still refers to it. Probes are serialised so at most one marked
    /// description exists at a time; that is what makes a stranger's fd
    /// distinguishable — it can never carry the mark.
    #[cfg(test)]
    pub(crate) struct FdClosedProbe {
        fd: i32,
        _serial: std::sync::MutexGuard<'static, ()>,
    }

    #[cfg(test)]
    impl FdClosedProbe {
        /// Marks the description behind `fd`. Call before the code under test
        /// closes it, and call [`assert_closed`](Self::assert_closed) before
        /// any `.await` so the serialising lock is never held across one.
        pub(crate) fn arm(fd: i32) -> Self {
            static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            // SAFETY: `fcntl(F_SETOWN)` and `getpid` only touch kernel state;
            // `fd` is a live fd owned by the caller.
            let rc = unsafe { libc::fcntl(fd, libc::F_SETOWN, libc::getpid()) };
            assert_eq!(
                rc,
                0,
                "F_SETOWN on fd {fd} failed: {}",
                std::io::Error::last_os_error()
            );
            Self {
                fd,
                _serial: serial,
            }
        }

        /// Panics unless the marked fd no longer refers to the marked
        /// description — either its number is closed, or it now belongs to
        /// someone else.
        pub(crate) fn assert_closed(self) {
            let fd = self.fd;
            // SAFETY: `fcntl(F_GETOWN)` reads kernel fd-table state only and is
            // defined for any integer, returning -1 with EBADF for a closed fd.
            let owner = unsafe { libc::fcntl(fd, libc::F_GETOWN) };
            if owner == -1 {
                let errno = std::io::Error::last_os_error()
                    .raw_os_error()
                    .expect("last_os_error must have an errno");
                assert_eq!(
                    errno,
                    libc::EBADF,
                    "F_GETOWN on fd {fd} failed with errno {errno}, expected EBADF"
                );
                return;
            }
            // SAFETY: `getpid` has no preconditions.
            let me = unsafe { libc::getpid() };
            assert_ne!(
                owner, me,
                "fd {fd} still refers to the marked open file description — it was not closed"
            );
        }
    }

    // ─── Availability check ───────────────────────────────────────────────────

    /// Probes whether the running kernel supports Landlock at any ABI level.
    ///
    /// Intended to be called once at daemon startup. Returns an error with a
    /// descriptive message if the running kernel predates Linux 5.13 (the
    /// minimum version that introduced Landlock V1).
    ///
    /// Absence of Landlock is treated as a fatal configuration error — no
    /// degraded or no-op mode is attempted.
    pub fn check_landlock_availability() -> Result<(), SandboxError> {
        // Attempt to create a minimal ruleset with V1 access rights under
        // HardRequirement: if either call fails, the kernel does not support
        // Landlock at the minimum required ABI level.
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI::V1))
            .map_err(|e| {
                SandboxError::ProfileBuildError(format!(
                    "Landlock is not supported by the running kernel \
                     (requires Linux 5.13+): {e}"
                ))
            })?
            .create()
            .map_err(|e| {
                SandboxError::ProfileBuildError(format!(
                    "Landlock is not supported by the running kernel \
                     (requires Linux 5.13+): {e}"
                ))
            })?;
        Ok(())
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    /// Returns read-only Landlock access rights appropriate for the path type.
    ///
    /// `AccessFs::from_read` includes `ReadDir`, which is directory-only. Passing
    /// it for a file fd causes `HardRequirement` to reject the rule with an
    /// "incompatible directory-only access-rights" error. Non-directory paths get
    /// only the file-compatible subset (`Execute | ReadFile`).
    fn read_access_for_path(path: &std::path::Path, abi: ABI) -> landlock::BitFlags<AccessFs> {
        if path.is_dir() {
            AccessFs::from_read(abi)
        } else {
            AccessFs::Execute | AccessFs::ReadFile
        }
    }

    // ─── Shared profile builder ───────────────────────────────────────────────

    /// Build a Landlock profile from explicit path lists and a baseline slice.
    ///
    /// Shared by `LinuxLandlock::build` (tool baseline) and
    /// `LinuxLandlock::build_agent` (agent baseline + `/usr/sbin`).
    /// The caller selects the baseline constant; all other logic is identical.
    fn build_landlock_profile(
        baseline: &[&str],
        read_paths: &[std::path::PathBuf],
        read_write_paths: &[std::path::PathBuf],
    ) -> Result<SandboxProfile, SandboxError> {
        let abi = ABI::V1;

        // ── Build the ruleset header ───────────────────────────────────────
        // `handle_access(AccessFs::from_all(abi))` registers all V1 filesystem
        // access rights in the ruleset header. Any access right listed in the
        // header but *not* covered by an explicit rule is denied by default —
        // this gives deny-by-default semantics for paths not in the policy.
        //
        // `HardRequirement` ensures we fail immediately if the kernel does not
        // support Landlock V1, rather than silently degrading to a no-op.
        let mut ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(abi))
            .map_err(to_profile_err)?
            .create()
            .map_err(to_profile_err)?;

        // ── Baseline read-only system paths ───────────────────────────────
        // Always-allowed reads for the dynamic linker, libc, system
        // config, and entropy. Mirrors the macOS Seatbelt baseline so
        // programs work out of the box without listing every /usr/lib
        // variant in config. Missing paths are silently skipped.
        for path in baseline {
            let Ok(path_fd) = PathFd::new(path) else {
                continue;
            };
            let access = read_access_for_path(std::path::Path::new(path), abi);
            ruleset = ruleset
                .add_rule(PathBeneath::new(path_fd, access))
                .map_err(to_profile_err)?;
        }

        // ── Read-only path rules ──────────────────────────────────────────
        // Grant read access (and its sub-rights) to each listed path and all
        // of its descendants via PathBeneath.
        //
        // Non-existent paths are silently skipped: Landlock requires an open
        // fd to anchor rules, so a path that does not exist yet cannot be
        // added to the ruleset. Callers that pass a non-existent path (e.g.
        // via `--allow-read`) expect no startup error — the path simply
        // remains inaccessible (nothing is there anyway).
        for path in read_paths {
            let Ok(path_fd) = PathFd::new(path) else {
                continue;
            };
            let access = read_access_for_path(path, abi);
            ruleset = ruleset
                .add_rule(PathBeneath::new(path_fd, access))
                .map_err(to_profile_err)?;
        }

        // ── Read-write path rules ─────────────────────────────────────────
        // Grant full access (read + write + all sub-rights) to each listed
        // path and all of its descendants.
        //
        // Non-existent paths are silently skipped for the same reason as the
        // read-only loop above.
        for path in read_write_paths {
            let Ok(path_fd) = PathFd::new(path) else {
                continue;
            };
            let access = if path.is_dir() {
                AccessFs::from_all(abi)
            } else {
                AccessFs::from_file(abi)
            };
            ruleset = ruleset
                .add_rule(PathBeneath::new(path_fd, access))
                .map_err(to_profile_err)?;
        }

        // ── Extract the raw fd ────────────────────────────────────────────
        // `From<RulesetCreated> for Option<OwnedFd>` extracts the underlying
        // kernel object. On kernels that support Landlock, this is `Some(fd)`.
        // `None` indicates the ruleset is a no-op (kernel unsupported) — but
        // since we used `HardRequirement` above, we should never reach here
        // with `None`; the check is a safety net.
        let owned_fd: Option<OwnedFd> = ruleset.into();
        let owned_fd = owned_fd.ok_or_else(|| {
            SandboxError::ProfileBuildError(
                "Landlock ruleset fd is None — the running kernel does not \
                 support Landlock (requires Linux 5.13+)"
                    .to_string(),
            )
        })?;
        let fd = owned_fd.as_raw_fd();

        Ok(SandboxProfile {
            inner: LinuxProfile {
                fd,
                owned_fd: Some(owned_fd),
            },
        })
    }

    // ─── LinuxLandlock ────────────────────────────────────────────────────────

    /// Linux Landlock sandbox backend.
    ///
    /// Translates a policy into a pre-built Landlock ruleset kernel object,
    /// identified by a raw file descriptor integer. All allocation-heavy work
    /// runs in `build()` / `build_agent()` (parent process) before any fork.
    /// The child only needs to execute two raw syscalls (`prctl` +
    /// `landlock_restrict_self`) using the inherited fd — no allocation occurs
    /// in the `pre_exec` closure.
    pub struct LinuxLandlock;

    impl SandboxBackend for LinuxLandlock {
        fn build(&self, policy: &ToolPolicy) -> Result<SandboxProfile, SandboxError> {
            build_landlock_profile(
                LINUX_BASELINE_READ_PATHS,
                &policy.read_paths,
                &policy.read_write_paths,
            )
        }

        fn build_agent(
            &self,
            policy: &AgentPolicy,
            _profile: Option<super::AgentProfileKind>,
        ) -> Result<SandboxProfile, SandboxError> {
            // Landlock is path-based and lacks regex support; profile extras
            // that rely on filename patterns (e.g. atomic-write `.tmp.*` files)
            // are silently ignored on Linux.
            build_landlock_profile(
                LINUX_AGENT_BASELINE_READ_PATHS,
                &policy.read_paths,
                &policy.read_write_paths,
            )
        }
    }

    // ─── Tests ───────────────────────────────────────────────────────────────

    #[cfg(test)]
    mod tests {
        use std::path::PathBuf;

        use super::super::{SandboxBackend, ToolPolicy};
        use super::{FdClosedProbe, LinuxLandlock, check_landlock_availability};

        fn read_only_policy(path: &str) -> ToolPolicy {
            ToolPolicy {
                read_paths: vec![PathBuf::from(path)],
                read_write_paths: vec![],
                requires_network: false,
                binary_path: None,
            }
        }

        fn read_write_policy(path: &str) -> ToolPolicy {
            ToolPolicy {
                read_paths: vec![],
                read_write_paths: vec![PathBuf::from(path)],
                requires_network: false,
                binary_path: None,
            }
        }

        fn empty_policy() -> ToolPolicy {
            ToolPolicy {
                read_paths: vec![],
                read_write_paths: vec![],
                requires_network: false,
                binary_path: None,
            }
        }

        // ── Trait bound compile-time verification ────────────────────────────

        /// Verify at compile time that `LinuxLandlock` implements `SandboxBackend`.
        #[test]
        fn linux_landlock_implements_sandbox_backend() {
            fn accepts_backend<B: SandboxBackend>(_b: &B) {}
            accepts_backend(&LinuxLandlock);
        }

        // ── Read-only policy produces valid fd ────────────────────────────────

        #[test]
        fn read_only_policy_produces_valid_fd() {
            let profile = LinuxLandlock
                .build(&read_only_policy("/tmp"))
                .expect("build should succeed for read-only policy");
            let fd = profile.raw_fd();
            assert!(
                fd > 2,
                "fd should be > 2 (not stdin/stdout/stderr), got {fd}"
            );
        }

        // ── Read-write policy produces valid fd ───────────────────────────────

        #[test]
        fn read_write_policy_produces_valid_fd() {
            let profile = LinuxLandlock
                .build(&read_write_policy("/tmp"))
                .expect("build should succeed for read-write policy");
            let fd = profile.raw_fd();
            assert!(
                fd > 2,
                "fd should be > 2 (not stdin/stdout/stderr), got {fd}"
            );
        }

        // ── Empty policy produces a deny-all fd ───────────────────────────────

        #[test]
        fn empty_policy_produces_valid_deny_all_fd() {
            let profile = LinuxLandlock
                .build(&empty_policy())
                .expect("build should succeed for an empty (deny-all) policy");
            let fd = profile.raw_fd();
            assert!(
                fd > 2,
                "fd should be > 2 (not stdin/stdout/stderr), got {fd}"
            );
        }

        // ── Explicit fd close invalidates fd in parent ────────────────────────

        #[test]
        fn close_ruleset_fd_invalidates_fd_in_parent() {
            let mut profile = LinuxLandlock
                .build(&read_only_policy("/tmp"))
                .expect("build should succeed");
            let fd = profile.raw_fd();
            assert!(fd > 2, "fd should be > 2 before close");
            let probe = FdClosedProbe::arm(fd);

            // Invoke the explicit close — this is the same call made by
            // exec::spawn() after the child is forked.
            profile.close_ruleset_fd();

            probe.assert_closed();
        }

        // ── Availability check succeeds on supported kernels ──────────────────

        /// The availability check must return `Ok(())` on kernels that support
        /// Landlock (Linux 5.13+). This test is expected to pass on any modern
        /// Linux system used for CI or development.
        #[test]
        fn availability_check_succeeds_on_supported_kernel() {
            check_landlock_availability()
                .expect("Landlock should be available on this kernel (requires Linux 5.13+)");
        }

        // ── AgentPolicy: build_agent smoke test ───────────────────────────────

        #[test]
        fn build_agent_empty_policy_produces_valid_fd() {
            // Smoke test: verify build_agent completes without error for an empty
            // AgentPolicy, exercising the extended baseline constant.
            let policy = super::super::AgentPolicy {
                read_paths: vec![],
                read_write_paths: vec![],
                requires_network: true,
                requires_terminal: true,
            };
            let profile = LinuxLandlock
                .build_agent(&policy, None)
                .expect("build_agent should succeed for an empty AgentPolicy");
            let fd = profile.raw_fd();
            assert!(
                fd > 2,
                "fd should be > 2 (not stdin/stdout/stderr), got {fd}"
            );
        }

        // ── Agent baseline includes /usr/sbin ─────────────────────────────────

        #[test]
        fn linux_agent_baseline_includes_usr_sbin() {
            // Verify the agent baseline constant contains every path from the
            // tool baseline plus /usr/sbin, by inspecting the slice contents.
            use super::{LINUX_AGENT_BASELINE_READ_PATHS, LINUX_BASELINE_READ_PATHS};

            // Every path in the tool baseline must appear in the agent baseline.
            for tool_path in LINUX_BASELINE_READ_PATHS {
                assert!(
                    LINUX_AGENT_BASELINE_READ_PATHS.contains(tool_path),
                    "agent baseline is missing tool baseline path: {tool_path}"
                );
            }
            // The agent baseline must additionally include /usr/sbin.
            assert!(
                LINUX_AGENT_BASELINE_READ_PATHS.contains(&"/usr/sbin"),
                "agent baseline must include /usr/sbin"
            );
            // The agent baseline must be strictly larger than the tool baseline.
            assert!(
                LINUX_AGENT_BASELINE_READ_PATHS.len() > LINUX_BASELINE_READ_PATHS.len(),
                "agent baseline must have more entries than tool baseline"
            );
        }

        // ── build_platform_agent_sandbox_profile smoke test (Linux) ──────────

        #[test]
        fn platform_agent_dispatcher_returns_ok_for_minimal_policy() {
            let policy = super::super::AgentPolicy {
                read_paths: vec![],
                read_write_paths: vec![],
                requires_network: true,
                requires_terminal: true,
            };
            super::super::build_platform_agent_sandbox_profile(&policy, None)
                .expect("build_platform_agent_sandbox_profile should return Ok on Linux");
        }
    }
}

// ─── Platform dispatcher ──────────────────────────────────────────────────────

/// Build an agent sandbox profile using the platform-appropriate backend.
///
/// On macOS, uses `MacOSSeatbelt`. On Linux, uses `LinuxLandlock`.
/// On other platforms, delegates to `NoopBackend` which returns an inert profile.
///
/// This is the function called by `run.rs` to produce the profile used when
/// spawning the agent process.
pub(crate) fn build_platform_agent_sandbox_profile(
    policy: &AgentPolicy,
    profile: Option<AgentProfileKind>,
) -> Result<SandboxProfile, SandboxError> {
    #[cfg(target_os = "macos")]
    {
        macos::MacOSSeatbelt.build_agent(policy, profile)
    }

    #[cfg(target_os = "linux")]
    {
        linux::LinuxLandlock.build_agent(policy, profile)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        NoopBackend.build_agent(policy, profile)
    }
}
