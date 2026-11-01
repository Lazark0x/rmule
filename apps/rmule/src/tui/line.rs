//! The line to the terminal: the one thread that writes to it. A write lasts
//! as long as the terminal does (a stalled ssh, a window nobody reads), so the
//! run never makes one: it hands bytes over here and goes on, and a loop that
//! finds the line busy holds its frame. A failed write is the terminal's
//! loss, told once, and everything sent after it is dropped.

use std::collections::VecDeque;
use std::io::{ErrorKind, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};

/// How long a write that would block waits before it tries again, on a
/// terminal somebody else made non-blocking.
const RETRY: Duration = Duration::from_millis(10);

/// The handle on the writing thread.
#[derive(Clone)]
pub(super) struct Line {
    shared: Arc<Shared>,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Default)]
struct State {
    queue: VecDeque<Vec<u8>>,
    writing: bool,
    lost: bool,
}

impl Line {
    /// Start the thread over `out`. `lost` runs once, on the thread, when a
    /// write fails.
    pub(super) fn open(
        out: impl Write + Send + 'static,
        lost: impl FnOnce() + Send + 'static,
    ) -> std::io::Result<Self> {
        let shared = Arc::new(Shared::default());
        let writer = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("rmule-terminal".into())
            .spawn(move || write_until_lost(&writer, out, lost))?;
        Ok(Self { shared })
    }

    /// Hand `bytes` over. Never blocks; on a lost line it does nothing.
    pub(super) fn send(&self, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let mut state = self.shared.state.lock();
        if !state.lost {
            state.queue.push_back(bytes);
            self.shared.changed.notify_all();
        }
    }

    /// Whether what was sent has not all reached the terminal.
    pub(super) fn busy(&self) -> bool {
        let state = self.shared.state.lock();
        !state.lost && (state.writing || !state.queue.is_empty())
    }

    /// Whether the terminal is gone.
    pub(super) fn lost(&self) -> bool {
        self.shared.state.lock().lost
    }

    /// Wait, at most `bound`, for what was sent to reach the terminal.
    pub(super) fn settle(&self, bound: Duration) -> bool {
        let until = Instant::now() + bound;
        let mut state = self.shared.state.lock();
        while !state.lost && (state.writing || !state.queue.is_empty()) {
            if self
                .shared
                .changed
                .wait_until(&mut state, until)
                .timed_out()
            {
                return false;
            }
        }
        true
    }
}

fn write_until_lost(shared: &Shared, mut out: impl Write, lost: impl FnOnce()) {
    loop {
        let bytes = {
            let mut state = shared.state.lock();
            state.writing = false;
            shared.changed.notify_all();
            while state.queue.is_empty() {
                shared.changed.wait(&mut state);
            }
            state.writing = true;
            state.queue.pop_front()
        };
        let Some(bytes) = bytes else { continue };
        if write_whole(&mut out, &bytes).is_err() {
            let mut state = shared.state.lock();
            state.lost = true;
            state.queue.clear();
            state.writing = false;
            shared.changed.notify_all();
            drop(state);
            lost();
            return;
        }
    }
}

fn write_whole(out: &mut impl Write, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        match out.write(bytes) {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == ErrorKind::WouldBlock => std::thread::sleep(RETRY),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::mpsc;
    use std::time::Duration;

    use super::Line;

    /// A terminal nobody reads: a write lasts until the test lets it go.
    struct Stalled(mpsc::Receiver<()>);

    impl Write for Stalled {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let _ = self.0.recv();
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A closed window.
    struct Closed;

    impl Write for Closed {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from_raw_os_error(5))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_stalled_terminal_holds_nobody_but_the_line() {
        let (release, stall) = mpsc::channel();
        let line = Line::open(Stalled(stall), || {}).expect("thread");

        line.send(b"a frame".to_vec());

        assert!(line.busy(), "the next frame is held");
        assert!(!line.settle(Duration::from_millis(20)), "the wait is bound");

        release.send(()).expect("the line is writing");
        assert!(line.settle(Duration::from_secs(5)), "it drains once read");
        assert!(!line.busy());
    }

    #[test]
    fn a_failed_write_is_the_terminals_loss_told_once() {
        let (told, heard) = mpsc::channel();
        let line = Line::open(Closed, move || told.send(()).expect("the test")).expect("thread");

        line.send(b"a frame".to_vec());
        heard
            .recv_timeout(Duration::from_secs(5))
            .expect("the loss is told");

        assert!(line.lost());
        line.send(b"another".to_vec());
        assert!(!line.busy(), "a lost line takes nothing");
        assert!(line.settle(Duration::from_secs(5)), "and holds nobody");
    }
}
