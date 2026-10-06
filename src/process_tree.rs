//! Process identity and ancestry, used to bind a session token to the
//! process tree that received it.
//!
//! A session token sits in the environment of every process the harness
//! starts. Any unsandboxed process of the same uid can read it — through
//! `KERN_PROCARGS2` on macOS or `/proc/<pid>/environ` on Linux — so the
//! token alone is not enough. The daemon additionally takes the peer PID
//! off the socket and checks that the session's anchor process is one of
//! its ancestors. The anchor is recorded together with its start time, so a
//! reused PID cannot forge membership once the original process has exited.

use std::io;

/// A process identity: its pid and start time. Equality requires both —
/// a reused pid with a different start time is a different process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcId {
    pub pid: i32,
    pub start: u64,
}

/// Looks up a process's identity (pid plus start time).
pub fn proc_id(pid: i32) -> io::Result<ProcId> {
    Ok(ProcId {
        pid,
        start: start_time(pid)?,
    })
}

/// Looks up a process's parent pid.
pub fn parent_pid(pid: i32) -> io::Result<i32> {
    platform::parent_pid(pid)
}

fn start_time(pid: i32) -> io::Result<u64> {
    platform::start_time(pid)
}

/// Walks the parent chain starting at `pid` (which counts as its own
/// ancestor) looking for `anchor`, stopping at pid 1 or 0 or after 256
/// steps. A process that cannot be inspected (already exited, or a
/// permission error) is treated as not a descendant.
pub fn is_descendant_of(pid: i32, anchor: &ProcId) -> bool {
    let mut current = pid;

    for _ in 0..256 {
        let Ok(id) = proc_id(current) else {
            return false;
        };
        if id == *anchor {
            return true;
        }
        if current <= 1 {
            return false;
        }
        match parent_pid(current) {
            Ok(parent) if parent > 0 && parent != current => current = parent,
            _ => return false,
        }
    }

    false
}

/// The peer pid and uid of a connected Unix stream.
pub fn peer_pid_uid(stream: &tokio::net::UnixStream) -> io::Result<(i32, u32)> {
    let cred = stream.peer_cred()?;
    let pid = cred
        .pid()
        .ok_or_else(|| io::Error::other("peer pid unavailable for this platform"))?;
    Ok((pid, cred.uid()))
}

#[cfg(target_os = "macos")]
mod platform {
    use std::io;
    use std::mem;

    fn bsdinfo(pid: i32) -> io::Result<libc::proc_bsdinfo> {
        let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
        let size = mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let ret = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        if ret != size {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }

    pub(super) fn start_time(pid: i32) -> io::Result<u64> {
        let info = bsdinfo(pid)?;
        // Microsecond resolution is plenty to disambiguate a reused pid;
        // it need not match any particular unit, only be stable per process.
        Ok(info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
    }

    pub(super) fn parent_pid(pid: i32) -> io::Result<i32> {
        Ok(bsdinfo(pid)?.pbi_ppid as i32)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::io;

    /// Reads a process's parent pid (field 4) and start time in clock
    /// ticks (field 22) from `/proc/<pid>/stat`.
    ///
    /// `comm` (field 2) is parenthesized but is not escaped: a process can
    /// name itself `1234) 5 6 (7` and the kernel writes it verbatim. The
    /// only reliable split is the *last* `)` in the line — fields after it
    /// are space-separated and never contain parens themselves — so we
    /// locate that instead of assuming `comm` has no spaces or parens.
    fn fields(pid: i32) -> io::Result<(i32, u64)> {
        let contents = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let close = contents.rfind(')').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed /proc/<pid>/stat: no comm field",
            )
        })?;
        let rest = contents[close + 1..].trim_start();
        let fields: Vec<&str> = rest.split_whitespace().collect();

        // `rest` starts at field 3 (state), so field N is at index N - 3.
        let ppid = fields
            .get(4 - 3)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed /proc/<pid>/stat: missing ppid",
                )
            })?
            .parse::<i32>()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed /proc/<pid>/stat: bad ppid",
                )
            })?;
        let starttime = fields
            .get(22 - 3)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed /proc/<pid>/stat: missing starttime",
                )
            })?
            .parse::<u64>()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed /proc/<pid>/stat: bad starttime",
                )
            })?;

        Ok((ppid, starttime))
    }

    pub(super) fn start_time(pid: i32) -> io::Result<u64> {
        Ok(fields(pid)?.1)
    }

    pub(super) fn parent_pid(pid: i32) -> io::Result<i32> {
        Ok(fields(pid)?.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn current_pid() -> i32 {
        std::process::id() as i32
    }

    #[test]
    fn current_process_is_its_own_descendant() {
        let me = proc_id(current_pid()).expect("proc_id(self)");
        assert!(is_descendant_of(current_pid(), &me));
    }

    #[test]
    fn spawned_child_is_a_descendant_of_the_test_process() {
        let me = proc_id(current_pid()).expect("proc_id(self)");
        let mut child = Command::new("sleep").arg("5").spawn().expect("spawn sleep");
        let child_pid = child.id() as i32;

        assert!(is_descendant_of(child_pid, &me));

        child.kill().ok();
        child.wait().ok();
    }

    #[test]
    fn test_process_is_not_a_descendant_of_its_child() {
        let mut child = Command::new("sleep").arg("5").spawn().expect("spawn sleep");
        let child_pid = child.id() as i32;
        let child_anchor = proc_id(child_pid).expect("proc_id(child)");

        assert!(!is_descendant_of(current_pid(), &child_anchor));

        child.kill().ok();
        child.wait().ok();
    }

    #[test]
    fn wrong_start_time_does_not_match() {
        let mut me = proc_id(current_pid()).expect("proc_id(self)");
        me.start = me.start.wrapping_add(1);
        assert!(!is_descendant_of(current_pid(), &me));
    }

    #[test]
    fn parent_pid_of_child_is_the_test_process() {
        let mut child = Command::new("sleep").arg("5").spawn().expect("spawn sleep");
        let child_pid = child.id() as i32;

        assert_eq!(parent_pid(child_pid).expect("parent_pid"), current_pid());

        child.kill().ok();
        child.wait().ok();
    }

    #[tokio::test]
    async fn peer_pid_uid_reports_this_process() {
        let (a, _b) = tokio::net::UnixStream::pair().expect("UnixStream::pair");
        let (pid, uid) = peer_pid_uid(&a).expect("peer_pid_uid");
        assert_eq!(pid, current_pid());
        assert_eq!(uid, unsafe { libc::geteuid() });
    }
}
