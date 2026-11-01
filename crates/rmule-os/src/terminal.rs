//! What a process does about the terminal it runs on, behind the TUI's stop
//! path (ADR-0118): whether the terminal hung up, what to leave on the
//! standard streams when it did, and stopping as a shell's job.
//!
//! Linux and macOS go through `rustix`'s safe calls. Windows has no hang-up to
//! watch, no streams that spin and no stop: the console's close is a signal
//! there, and [`stop_refused`] says so.

/// Why a run cannot stop as a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoStop {
    /// This system has no job control.
    NoJobControl,
    /// No shell above this run would bring it back.
    NoShell,
}

/// Block until standard input hangs up, and answer `true`. `false` is a
/// terminal this call cannot watch: a device `poll` refuses, or a system with
/// no such call.
///
/// `macOS` reports a hang-up only to a `poll` that also asks for input, so
/// this asks, and a wake on typed bytes rests for `rest` to leave the reader
/// its turn.
#[must_use]
pub fn wait_for_hangup(rest: std::time::Duration) -> bool {
    imp::wait_for_hangup(rest)
}

/// Leave nothing of a lost terminal on the standard streams. Input becomes a
/// pipe nobody writes, so a reader spinning on the dead descriptor blocks on
/// its next read and costs nothing; output and error, where they were the
/// terminal, become the null device, so a late write neither fails nor waits.
pub fn blank_standard_streams() {
    imp::blank_standard_streams();
}

/// Discard what is queued for a terminal that is not reading, so a writer
/// blocked on it can finish.
pub fn discard_pending_output() {
    imp::discard_pending_output();
}

/// Why this run cannot stop as a job, or `None` when it can.
#[must_use]
pub fn stop_refused() -> Option<NoStop> {
    imp::stop_refused()
}

/// Stop this process group as a job, the way Ctrl-Z does on a terminal.
/// Answers once the group has been continued.
pub fn stop_process_group() {
    imp::stop_process_group();
}

/// The signals job control sends: the terminal's stop, then the continue.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[must_use]
pub const fn job_signals() -> (i32, i32) {
    use rustix::process::Signal;
    (Signal::TSTP.as_raw(), Signal::CONT.as_raw())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod imp {
    use std::fs::File;
    use std::io::{IsTerminal, stderr, stdin, stdout};
    use std::os::fd::AsFd;
    use std::time::Duration;

    use rustix::event::{PollFd, PollFlags, poll};
    use rustix::io::Errno;
    use rustix::process::{Signal, getpgrp, getsid, kill_current_process_group};
    use rustix::termios::{QueueSelector, tcflush};

    use super::NoStop;

    pub(super) fn wait_for_hangup(rest: Duration) -> bool {
        let input = stdin();
        loop {
            let mut watched = [PollFd::new(&input, PollFlags::IN)];
            match poll(&mut watched, None) {
                Ok(_) => {
                    let events = watched[0].revents();
                    if events.contains(PollFlags::NVAL) {
                        return false;
                    }
                    if events.intersects(PollFlags::HUP | PollFlags::ERR) {
                        return true;
                    }
                    std::thread::sleep(rest);
                }
                Err(Errno::INTR) => {}
                Err(_) => return false,
            }
        }
    }

    pub(super) fn blank_standard_streams() {
        if let Ok((reader, writer)) = rustix::pipe::pipe() {
            let _ = rustix::stdio::dup2_stdin(reader);
            // Held open for the run: a pipe with no writer reads as an end,
            // and the reader would spin on that as it did on the terminal.
            std::mem::forget(writer);
        }
        let Ok(null) = File::options().write(true).open("/dev/null") else {
            return;
        };
        if stdout().is_terminal() {
            let _ = rustix::stdio::dup2_stdout(&null);
        }
        if stderr().is_terminal() {
            let _ = rustix::stdio::dup2_stderr(&null);
        }
    }

    pub(super) fn discard_pending_output() {
        let _ = tcflush(stdout().as_fd(), QueueSelector::OFlush);
    }

    pub(super) fn stop_refused() -> Option<NoStop> {
        // A group that leads its session has no shell above it to say `fg`:
        // stopped, it would stay stopped.
        match getsid(None) {
            Ok(session) if session != getpgrp() => None,
            _ => Some(NoStop::NoShell),
        }
    }

    pub(super) fn stop_process_group() {
        // SIGSTOP, not SIGTSTP: the run holds a handler for the terminal's
        // stop, the one that called this.
        let _ = kill_current_process_group(Signal::STOP);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use std::time::Duration;

    use super::NoStop;

    pub(super) fn wait_for_hangup(_rest: Duration) -> bool {
        false
    }

    pub(super) fn blank_standard_streams() {}

    pub(super) fn discard_pending_output() {}

    pub(super) fn stop_refused() -> Option<NoStop> {
        Some(NoStop::NoJobControl)
    }

    pub(super) fn stop_process_group() {}
}
