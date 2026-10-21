//! The pseudo-terminal between `airlock run`'s agent and the user's
//! terminal.
//!
//! The agent never gets a descriptor to the user's terminal. `airlock run`
//! allocates a pty, gives the agent its slave side as stdin/stdout/stderr
//! and controlling terminal, and relays bytes between the master side and
//! the real terminal, the way `ssh -t` and `script` do. A process the agent
//! leaves running holds only the slave, which is worthless once the relay
//! stops; and when the agent exits, [`Relay::finish`] reads the terminal's
//! input up to the answer to a query of its own before handing the terminal
//! back, so no reply the agent provoked is left for the user's shell to read
//! as typed input. With [`filter`] on, the agent's output also loses the
//! escape sequences the terminal would act on by itself. See SECURITY.md,
//! "The agent's terminal".

mod filter;

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{Mode, OFlags};
use rustix::pty::OpenptFlags;
use rustix::termios::{OptionalActions, QueueSelector, Termios};

use self::filter::Filter;

/// Asks the terminal for a status report. Every VT100-compatible terminal
/// answers [`STATUS_OK`], and answers queries in the order it got them, so
/// once that answer is read, so is every reply sent before it.
const STATUS_QUERY: &[u8] = b"\x1b[5n";
const STATUS_OK: &[u8] = b"\x1b[0n";

/// How long [`Relay::finish`] waits for [`STATUS_OK`]: a terminal that
/// never answers, or a slow ssh link, can't hold the exit up longer.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// The most agent output [`Relay::finish`] still forwards after the agent
/// exited: what was in flight when it did, not whatever a process it left
/// running keeps writing.
const FINAL_OUTPUT_LIMIT: usize = 64 * 1024;

/// Keyboard input buffered for an agent that isn't reading it; past this,
/// the relay stops reading the terminal until the agent catches up.
const MAX_PENDING_INPUT: usize = 64 * 1024;

pub struct Relay {
    /// The user's terminal: one of `airlock run`'s own stdio fds, the one
    /// agent output is written to and whose modes and size the pty copies.
    terminal: BorrowedFd<'static>,
    /// `airlock run`'s stdin; read only when `input` is set.
    stdin: BorrowedFd<'static>,
    /// Which of stdin/stdout/stderr are the terminal: the agent gets the
    /// slave in exactly those, and inherits the rest.
    is_tty: [bool; 3],
    /// Whether keyboard input is relayed: stdin is the terminal, and this
    /// process is in its foreground. A background `airlock run` changing
    /// the terminal's modes or reading it would be stopped with
    /// SIGTTOU/SIGTTIN.
    input: bool,
    master: Arc<OwnedFd>,
    /// This process's own copy of the slave, kept until the agent has its
    /// own copies; see [`Relay::start`].
    slave: Option<OwnedFd>,
    slave_path: PathBuf,
    /// The terminal's modes before raw mode, restored on drop.
    saved: Option<Termios>,
    /// The output filter, when on. The relay thread has it while it runs.
    filter: Option<Filter>,
    /// The relay thread and the write end of the pipe that stops it.
    running: Option<(OwnedFd, JoinHandle<Option<Filter>>)>,
}

impl Relay {
    /// A pty for the agent, if any of `stdio` (stdin, stdout, stderr) is a
    /// terminal. `None` means there is no terminal to protect, and the agent
    /// inherits `stdio` as is. `filter` runs the agent's output through
    /// [`Filter`].
    pub fn open(stdio: [BorrowedFd<'static>; 3], filter: bool) -> io::Result<Option<Self>> {
        let is_tty = stdio.map(rustix::termios::isatty);
        let Some(terminal) = [1, 2, 0].into_iter().find(|&i| is_tty[i]).map(|i| stdio[i]) else {
            return Ok(None);
        };
        let foreground =
            rustix::termios::tcgetpgrp(terminal).ok() == Some(rustix::process::getpgrp());

        let master = rustix::pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
        // Not an `openpt` flag on macOS. The agent must never inherit the
        // master: holding it, it could keep its pty alive and feed itself
        // input.
        rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC)?;
        rustix::pty::grantpt(&master)?;
        rustix::pty::unlockpt(&master)?;
        let name = rustix::pty::ptsname(&master, Vec::new())?;
        let slave_path = PathBuf::from(OsString::from_vec(name.into_bytes()));
        let slave = rustix::fs::open(
            &slave_path,
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        // The agent's terminal starts out like the user's: the same modes
        // (erase key, UTF-8 input, ...) and the same size.
        if let Ok(modes) = rustix::termios::tcgetattr(terminal) {
            rustix::termios::tcsetattr(&slave, OptionalActions::Now, &modes)?;
        }
        if let Ok(size) = rustix::termios::tcgetwinsize(terminal) {
            rustix::termios::tcsetwinsize(&master, size)?;
        }
        rustix::fs::fcntl_setfl(&master, OFlags::NONBLOCK)?;

        Ok(Some(Relay {
            terminal,
            stdin: stdio[0],
            is_tty,
            input: is_tty[0] && foreground,
            master: Arc::new(master),
            slave: Some(slave),
            slave_path,
            saved: None,
            filter: filter.then(Filter::new),
            running: None,
        }))
    }

    /// The agent's terminal device, the only one its sandbox may open.
    pub fn slave_path(&self) -> &Path {
        &self.slave_path
    }

    /// The slave fd, for the agent's `TIOCSCTTY` in `pre_exec`: it is still
    /// open there, `CLOEXEC` closing it only at `exec`.
    pub fn slave_fd(&self) -> RawFd {
        self.slave
            .as_ref()
            .expect("the slave is open until start")
            .as_raw_fd()
    }

    /// What the agent gets as stdio fd `fd` (0, 1 or 2): the slave where
    /// `airlock run` has the terminal, its own fd otherwise.
    pub fn stdio(&self, fd: usize) -> io::Result<Stdio> {
        Ok(if self.is_tty[fd] {
            Stdio::from(
                self.slave
                    .as_ref()
                    .expect("the slave is open until start")
                    .try_clone()?,
            )
        } else {
            Stdio::inherit()
        })
    }

    /// Starts relaying, once the agent is spawned with its own copies of
    /// the slave. Closes this process's copy, so the master sees a hangup
    /// once every process holding the slave has exited.
    pub fn start(&mut self) -> io::Result<()> {
        self.slave = None;
        if self.input {
            let saved = rustix::termios::tcgetattr(self.terminal)?;
            let mut raw = saved.clone();
            raw.make_raw();
            rustix::termios::tcsetattr(self.terminal, OptionalActions::Now, &raw)?;
            self.saved = Some(saved);
        }
        // Created only now, after the agent is spawned, so it never
        // inherits either end; CLOEXEC keeps it that way.
        let (stop_rx, stop_tx) = rustix::pipe::pipe()?;
        for end in [&stop_rx, &stop_tx] {
            rustix::io::fcntl_setfd(end, rustix::io::FdFlags::CLOEXEC)?;
        }
        let master = Arc::clone(&self.master);
        let stdin = self.input.then_some(self.stdin);
        let terminal = self.terminal;
        let filter = self.filter.take();
        let thread = std::thread::spawn(move || pump(&master, stdin, terminal, &stop_rx, filter));
        self.running = Some((stop_tx, thread));
        Ok(())
    }

    /// Passes the terminal's new size on to the agent's (on SIGWINCH).
    pub fn resize(&self) {
        if let Ok(size) = rustix::termios::tcgetwinsize(self.terminal) {
            let _ = rustix::termios::tcsetwinsize(&*self.master, size);
        }
    }

    /// Hands the terminal back once the agent has exited: stops relaying,
    /// forwards what the agent wrote just before exiting, then discards
    /// every reply the agent provoked that is still on its way, up to the
    /// answer to [`STATUS_QUERY`]. Dropping the relay afterwards restores
    /// the terminal's modes and closes the master, which leaves any process
    /// still holding the slave writing into nothing.
    pub fn finish(mut self) {
        self.stop();
        forward_available(
            &self.master,
            self.terminal,
            FINAL_OUTPUT_LIMIT,
            self.filter.as_mut(),
        );
        if let Some(filter) = &mut self.filter {
            let mut tail = Vec::new();
            filter.close(&mut tail);
            let _ = write_all(self.terminal, &tail);
        }
        if self.input {
            drain_replies(self.stdin, self.terminal);
        }
    }

    fn stop(&mut self) {
        if let Some((stop_tx, thread)) = self.running.take() {
            let _ = rustix::io::write(&stop_tx, b"x");
            if let Ok(filter) = thread.join() {
                self.filter = filter;
            }
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop();
        if let Some(saved) = &self.saved {
            let _ = rustix::termios::tcsetattr(self.terminal, OptionalActions::Now, saved);
        }
    }
}

/// The relay loop: agent output from the master to the terminal (through
/// `filter`, when on), keyboard input from stdin (when relayed) to the
/// master, until `stop` is readable. Hands `filter` back, mid-sequence
/// state and all, for [`Relay::finish`]. The master is non-blocking, so an
/// agent that stops reading its input can't wedge the loop; writes to the
/// terminal block, as they would for the agent writing to it directly.
fn pump(
    master: &OwnedFd,
    stdin: Option<BorrowedFd<'_>>,
    terminal: BorrowedFd<'_>,
    stop: &OwnedFd,
    mut filter: Option<Filter>,
) -> Option<Filter> {
    let mut stdin = stdin;
    let mut master_open = true;
    let mut to_agent: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    let mut filtered = Vec::new();

    loop {
        let mut master_events = PollFlags::IN;
        if !to_agent.is_empty() {
            master_events |= PollFlags::OUT;
        }
        let reading_stdin = stdin.filter(|_| to_agent.len() < MAX_PENDING_INPUT);

        let mut fds = vec![PollFd::new(stop, PollFlags::IN)];
        // A hung-up master reports POLLHUP whatever it is asked for, so it
        // leaves the set for good rather than spin the loop.
        if master_open {
            fds.push(PollFd::new(master, master_events));
        }
        if let Some(fd) = reading_stdin {
            fds.push(PollFd::from_borrowed_fd(fd, PollFlags::IN));
        }
        match rustix::event::poll(&mut fds, None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return filter,
        }
        let stop_ready = !fds[0].revents().is_empty();
        let master_ready = if master_open {
            fds[1].revents()
        } else {
            PollFlags::empty()
        };
        let stdin_ready = match reading_stdin {
            Some(_) => fds[fds.len() - 1].revents(),
            None => PollFlags::empty(),
        };
        drop(fds);

        if stop_ready {
            return filter;
        }

        if master_ready.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR) {
            match rustix::io::read(master, &mut buf) {
                Ok(0) => master_open = false,
                Ok(n) => {
                    let _ = write_all(terminal, through(filter.as_mut(), &buf[..n], &mut filtered));
                }
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                // EIO: every process holding the slave has closed it.
                Err(_) => master_open = false,
            }
            if !master_open {
                to_agent.clear();
            }
        }

        if master_open && master_ready.contains(PollFlags::OUT) {
            match rustix::io::write(master, &to_agent) {
                Ok(n) => {
                    to_agent.drain(..n);
                }
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                Err(_) => to_agent.clear(),
            }
        }

        if let Some(fd) = reading_stdin
            && stdin_ready.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
        {
            match rustix::io::read(fd, &mut buf) {
                Ok(0) => stdin = None,
                Ok(n) if master_open => to_agent.extend_from_slice(&buf[..n]),
                Ok(_) => {}
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                Err(_) => stdin = None,
            }
        }
    }
}

/// `bytes` as they should reach the terminal: through `filter` when on,
/// using `scratch` for the result.
fn through<'a>(filter: Option<&mut Filter>, bytes: &'a [u8], scratch: &'a mut Vec<u8>) -> &'a [u8] {
    match filter {
        Some(filter) => {
            scratch.clear();
            filter.push(bytes, scratch);
            scratch
        }
        None => bytes,
    }
}

/// Forwards agent output already waiting in the master, up to `limit`
/// bytes, without waiting for more.
fn forward_available(
    master: &OwnedFd,
    terminal: BorrowedFd<'_>,
    limit: usize,
    filter: Option<&mut Filter>,
) {
    let mut filter = filter;
    let mut buf = vec![0u8; 16 * 1024];
    let mut filtered = Vec::new();
    let mut forwarded = 0;
    while forwarded < limit {
        let want = buf.len().min(limit - forwarded);
        match rustix::io::read(master, &mut buf[..want]) {
            Ok(0) => return,
            Ok(n) => {
                let bytes = through(filter.as_deref_mut(), &buf[..n], &mut filtered);
                if write_all(terminal, bytes).is_err() {
                    return;
                }
                forwarded += n;
            }
            Err(rustix::io::Errno::INTR) => {}
            // AGAIN: nothing more waiting. EIO: the slave is closed.
            Err(_) => return,
        }
    }
}

/// Sends [`STATUS_QUERY`] and reads `stdin` until its answer arrives (or
/// [`DRAIN_TIMEOUT`] passes), discarding everything up to it — every reply
/// the terminal sent before. Keys the user types meanwhile are discarded
/// too. Then flushes what's left, in case the terminal never answered.
fn drain_replies(stdin: BorrowedFd<'_>, terminal: BorrowedFd<'_>) {
    if write_all(terminal, STATUS_QUERY).is_ok() {
        let deadline = Instant::now() + DRAIN_TIMEOUT;
        let mut tail: Vec<u8> = Vec::new();
        let mut buf = [0u8; 1024];
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            let timeout = Timespec::try_from(left).expect("a sub-second timeout fits");
            let mut fds = [PollFd::from_borrowed_fd(stdin, PollFlags::IN)];
            match rustix::event::poll(&mut fds, Some(&timeout)) {
                Ok(0) => break,
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => break,
            }
            match rustix::io::read(stdin, &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    tail.extend_from_slice(&buf[..n]);
                    if tail.windows(STATUS_OK.len()).any(|w| w == STATUS_OK) {
                        break;
                    }
                    // Keep just enough to match an answer split across reads.
                    let excess = tail.len().saturating_sub(STATUS_OK.len() - 1);
                    tail.drain(..excess);
                }
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                Err(_) => break,
            }
        }
    }
    let _ = rustix::termios::tcflush(stdin, QueueSelector::IFlush);
}

fn write_all(fd: BorrowedFd<'_>, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        match rustix::io::write(fd, bytes) {
            Ok(n) => bytes = &bytes[n..],
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    /// A pty standing in for the user's terminal: the test plays the
    /// terminal emulator on `master`; `slave` is what `airlock run` would
    /// have as its stdio.
    struct FakeTerminal {
        master: OwnedFd,
        slave: OwnedFd,
    }

    impl FakeTerminal {
        fn new() -> Self {
            let master = rustix::pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
            rustix::pty::grantpt(&master).unwrap();
            rustix::pty::unlockpt(&master).unwrap();
            let name = rustix::pty::ptsname(&master, Vec::new()).unwrap();
            let slave = rustix::fs::open(
                name.as_c_str(),
                OFlags::RDWR | OFlags::NOCTTY,
                Mode::empty(),
            )
            .unwrap();
            FakeTerminal { master, slave }
        }

        /// `slave` as all three stdio fds. Leaked: `Relay` holds
        /// `'static` fds, as it does for the real stdio.
        fn stdio(&self) -> [BorrowedFd<'static>; 3] {
            let fd: &'static OwnedFd = Box::leak(Box::new(self.slave.try_clone().unwrap()));
            [fd.as_fd(); 3]
        }
    }

    /// Reads `fd` until `want` shows up or two seconds pass.
    fn read_until(fd: &OwnedFd, want: &[u8]) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        while !got.windows(want.len()).any(|w| w == want) {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            let mut fds = [PollFd::new(fd, PollFlags::IN)];
            if rustix::event::poll(&mut fds, Some(&Timespec::try_from(left).unwrap())).unwrap() == 0
            {
                break;
            }
            match rustix::io::read(fd, &mut buf) {
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        got
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn no_terminal_means_no_relay() {
        let (r, w) = rustix::pipe::pipe().unwrap();
        let r: &'static OwnedFd = Box::leak(Box::new(r));
        let w: &'static OwnedFd = Box::leak(Box::new(w));
        assert!(
            Relay::open([r.as_fd(), w.as_fd(), w.as_fd()], true)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn agent_output_reaches_the_terminal_until_finish_and_never_after() {
        let term = FakeTerminal::new();
        let mut relay = Relay::open(term.stdio(), true).unwrap().unwrap();
        let agent = rustix::fs::open(relay.slave_path(), OFlags::RDWR, Mode::empty()).unwrap();
        relay.start().unwrap();

        write_all(agent.as_fd(), b"from the agent").unwrap();
        assert!(contains(
            &read_until(&term.master, b"from the agent"),
            b"from the agent"
        ));

        relay.finish();
        // A process the agent left running still holds the slave; nothing
        // it writes reaches the terminal any more.
        let _ = write_all(agent.as_fd(), b"too late");
        assert!(!contains(
            &read_until(&term.master, b"too late"),
            b"too late"
        ));
    }

    #[test]
    fn output_in_flight_at_exit_is_still_forwarded() {
        let term = FakeTerminal::new();
        let mut relay = Relay::open(term.stdio(), true).unwrap().unwrap();
        let agent = rustix::fs::open(relay.slave_path(), OFlags::RDWR, Mode::empty()).unwrap();
        relay.start().unwrap();
        // Stop the relay thread first, so the bytes below are still in the
        // master when `finish` runs: what `forward_available` is for.
        relay.stop();
        write_all(agent.as_fd(), b"\x1b[?1049l").unwrap();
        relay.finish();
        assert!(contains(
            &read_until(&term.master, b"\x1b[?1049l"),
            b"\x1b[?1049l"
        ));
    }

    #[test]
    fn filtered_relay_keeps_line_breaks_out_of_the_clipboard() {
        use base64::Engine;
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);

        for (filter, expected) in [(true, "rm -rf ~ "), (false, "rm -rf ~\n")] {
            let term = FakeTerminal::new();
            let mut relay = Relay::open(term.stdio(), filter).unwrap().unwrap();
            let agent = rustix::fs::open(relay.slave_path(), OFlags::RDWR, Mode::empty()).unwrap();
            let mut raw = rustix::termios::tcgetattr(&agent).unwrap();
            raw.make_raw();
            rustix::termios::tcsetattr(&agent, OptionalActions::Now, &raw).unwrap();
            relay.start().unwrap();

            let sent = format!("\x1b]52;c;{}\x07done", b64("rm -rf ~\n"));
            write_all(agent.as_fd(), sent.as_bytes()).unwrap();
            let screen = read_until(&term.master, b"done");
            let want = format!("\x1b]52;c;{}\x07done", b64(expected));
            assert!(
                contains(&screen, want.as_bytes()),
                "filter {filter}: {:?}",
                String::from_utf8_lossy(&screen)
            );
            relay.finish();
        }
    }

    // The relay only reads keyboard input in the terminal's foreground,
    // which a test pty with no controlling process isn't; `pump` is driven
    // directly instead.
    #[test]
    fn keyboard_input_reaches_the_agent() {
        let term = FakeTerminal::new();
        let relay = Relay::open(term.stdio(), true).unwrap().unwrap();
        let agent = rustix::fs::open(relay.slave_path(), OFlags::RDWR, Mode::empty()).unwrap();
        // Raw on both sides, as `start` leaves the user's terminal and a
        // full-screen agent leaves its own.
        for fd in [relay.stdin, agent.as_fd()] {
            let mut raw = rustix::termios::tcgetattr(fd).unwrap();
            raw.make_raw();
            rustix::termios::tcsetattr(fd, OptionalActions::Now, &raw).unwrap();
        }

        let (stop_rx, stop_tx) = rustix::pipe::pipe().unwrap();
        let master = Arc::clone(&relay.master);
        let stdin = relay.stdin;
        let terminal = relay.terminal;
        let thread =
            std::thread::spawn(move || pump(&master, Some(stdin), terminal, &stop_rx, None));

        write_all(term.master.as_fd(), b"typed").unwrap();
        assert!(contains(&read_until(&agent, b"typed"), b"typed"));

        rustix::io::write(&stop_tx, b"x").unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn drain_discards_replies_up_to_the_status_answer() {
        let term = FakeTerminal::new();
        let stdio = term.stdio();
        let mut raw = rustix::termios::tcgetattr(stdio[0]).unwrap();
        raw.make_raw();
        rustix::termios::tcsetattr(stdio[0], OptionalActions::Now, &raw).unwrap();

        // A reply the agent provoked, arriving after it exited, then the
        // answer to the relay's own status query.
        let emulator = std::thread::spawn({
            let master = term.master.try_clone().unwrap();
            move || {
                read_until(&master, STATUS_QUERY);
                write_all(master.as_fd(), b"\x1b]l; rm -rf ~\x1b\\").unwrap();
                write_all(master.as_fd(), STATUS_OK).unwrap();
            }
        });
        drain_replies(stdio[0], stdio[1]);
        emulator.join().unwrap();

        rustix::fs::fcntl_setfl(stdio[0], OFlags::NONBLOCK).unwrap();
        let mut buf = [0u8; 64];
        assert!(
            matches!(
                rustix::io::read(stdio[0], &mut buf),
                Err(rustix::io::Errno::AGAIN)
            ),
            "the reply must not be left for the shell"
        );
    }

    #[test]
    fn drain_gives_up_on_a_terminal_that_never_answers() {
        let term = FakeTerminal::new();
        let stdio = term.stdio();
        let mut raw = rustix::termios::tcgetattr(stdio[0]).unwrap();
        raw.make_raw();
        rustix::termios::tcsetattr(stdio[0], OptionalActions::Now, &raw).unwrap();

        let started = Instant::now();
        drain_replies(stdio[0], stdio[1]);
        let took = started.elapsed();
        assert!(
            took >= DRAIN_TIMEOUT && took < DRAIN_TIMEOUT * 3,
            "{took:?}"
        );
    }
}
