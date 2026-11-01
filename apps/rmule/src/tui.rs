//! Terminal lifecycle (spec §5 feature floor): raw mode + alternate screen
//! entered by hand, mouse capture, kitty-keyboard enhancement pushed only
//! when the terminal reports support (feature-detected, never assumed), and
//! synchronized output (DEC mode 2026) wrapped around every frame so a big
//! repaint commits atomically. [`leave`] is the one restore: [`Tui`]'s `Drop`,
//! the panic hook and the stop deadline (ADR-0118) all reach it, and only the
//! first does anything. Ratatui's own init is not used, since its hook
//! restores the terminal on a panic of any thread, with the UI still drawing.
//!
//! Every byte goes through the [`Line`], so nothing here waits on the
//! terminal: a frame the line is not ready for is held, a stalled terminal
//! holds nobody, and losing the terminal is told to the [`Stop`] rather than
//! returned as an error. Crossterm's reader spins on a dead descriptor and
//! never returns, so the loss also blanks the standard streams, which parks
//! that reader; the watch on input hangs up the same way when no write is
//! going to fail first.
//!
//! The terminal's title is the operator's: it is taken only when they turn the
//! setting on, the title they had goes on the terminal's stack, and [`leave`]
//! or the setting turned off gives it back. A stop gives it back too, and the
//! re-entry takes it again.
//!
//! [`Surface`] is the one capability `App` needs from this module — draw a
//! frame, the writes beside it, and what a job's stop asks of the terminal —
//! pulled out as a trait
//! so `App`'s loop can be proven against a recorder in a test instead of a
//! real terminal, which only [`Tui::enter`] can open.

use std::io::{Write, stderr, stdout};
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(windows)]
use std::os::windows::io::AsHandle;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::cursor;
use ratatui::crossterm::event::{
    DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use ratatui::crossterm::queue;
use ratatui::crossterm::style::Print;
use ratatui::crossterm::terminal::{
    BeginSynchronizedUpdate, EndSynchronizedUpdate, EnterAlternateScreen, LeaveAlternateScreen,
    SetTitle, disable_raw_mode, enable_raw_mode, supports_keyboard_enhancement,
};
use ratatui::{Frame, Terminal};
pub use rmule_os::terminal::NoStop;

use crate::stop::Stop;
use line::Line;

mod line;

/// How long the terminal's restore may wait on a terminal that is not reading.
const LEAVE_BOUND: Duration = Duration::from_secs(1);
/// How long what was left may take once the queue is discarded.
const DISCARDED_BOUND: Duration = Duration::from_millis(250);
/// How long a run's last words may wait on a stderr that is not reading.
const LAST_WORDS_BOUND: Duration = Duration::from_secs(1);
/// What the hang-up watch rests between two wakes on typed bytes.
const WATCH_REST: Duration = Duration::from_millis(100);

/// The terminal is ours: what [`leave`] gives back, and what a panic on
/// another thread reads to know a frame is up.
static ENTERED: AtomicBool = AtomicBool::new(false);
/// The kitty enhancement is pushed, so [`leave`] pops it.
static KITTY_PUSHED: AtomicBool = AtomicBool::new(false);
/// The terminal answered the kitty probe, so a re-entry pushes it again.
static KITTY_ACCEPTED: AtomicBool = AtomicBool::new(false);
/// The app holds the terminal's title, so [`leave`] gives it back.
static TITLE_HELD: AtomicBool = AtomicBool::new(false);
/// The line, for a [`leave`] from any thread.
static LINE: OnceLock<Line> = OnceLock::new();
/// The terminal's loss has been handled.
static LOST: AtomicBool = AtomicBool::new(false);

/// Save the title on the terminal's stack (XTWINOPS). A terminal without the
/// stack ignores this and the restore, and its empty title reads as its own.
const TITLE_PUSH: &str = "\x1b[22;0t";
/// See [`TITLE_PUSH`].
const TITLE_POP: &str = "\x1b[23;0t";

/// Whether the full-screen UI holds the terminal.
#[must_use]
pub fn entered() -> bool {
    ENTERED.load(Ordering::SeqCst)
}

/// Give the terminal back, exactly what was taken, once: a later call and a
/// call with nothing entered do nothing. Safe on any thread, and bounded: a
/// terminal that does not read loses what was queued for it, and past that
/// the restore is abandoned, not waited for.
pub fn leave() {
    if !ENTERED.swap(false, Ordering::SeqCst) {
        return;
    }
    if let Some(line) = LINE.get() {
        line.send(restore_bytes());
        if !line.settle(LEAVE_BOUND) {
            rmule_os::terminal::discard_pending_output();
            line.settle(DISCARDED_BOUND);
        }
    }
    let _ = disable_raw_mode();
}

/// Say `words` on stderr, however stderr is: a closed one takes nothing and a
/// stalled one is not waited for. For what is said once the terminal is back.
pub fn last_words(words: String) {
    let (said, heard) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = writeln!(stderr(), "{words}");
        let _ = said.send(());
    });
    let _ = heard.recv_timeout(LAST_WORDS_BOUND);
}

/// The terminal is gone. Once: what can be restored on what remains, nothing
/// left on the standard streams to fail or spin, and the stop.
fn lose_terminal(stop: &Stop) {
    if LOST.swap(true, Ordering::SeqCst) {
        return;
    }
    let _ = disable_raw_mode();
    rmule_os::terminal::blank_standard_streams();
    stop.request();
}

/// The bytes that show `title`, taking the title first if the app does not
/// hold it.
fn take_title(title: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    if !TITLE_HELD.swap(true, Ordering::SeqCst) {
        let _ = queue!(bytes, Print(TITLE_PUSH));
    }
    let _ = queue!(bytes, SetTitle(title));
    bytes
}

/// The bytes that give the title back, if the app holds it.
fn release_title() -> Vec<u8> {
    let mut bytes = Vec::new();
    if TITLE_HELD.swap(false, Ordering::SeqCst) {
        let _ = queue!(bytes, SetTitle(""), Print(TITLE_POP));
    }
    bytes
}

/// The bytes that take the screen.
fn enter_bytes() -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = queue!(bytes, EnterAlternateScreen);
    if KITTY_ACCEPTED.load(Ordering::SeqCst) {
        let _ = queue!(
            bytes,
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
        );
        KITTY_PUSHED.store(true, Ordering::SeqCst);
    }
    // Without bracketed paste a paste arrives as keys, and each runs as a
    // command. The legacy Windows console refuses it, which costs only that.
    let _ = queue!(bytes, EnableMouseCapture, EnableBracketedPaste);
    bytes
}

/// The bytes that give the screen back.
fn restore_bytes() -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = queue!(bytes, EndSynchronizedUpdate);
    bytes.extend(release_title());
    if KITTY_PUSHED.swap(false, Ordering::SeqCst) {
        let _ = queue!(bytes, PopKeyboardEnhancementFlags);
    }
    let _ = queue!(
        bytes,
        DisableBracketedPaste,
        DisableMouseCapture,
        LeaveAlternateScreen,
        cursor::Show
    );
    bytes
}

/// The stream ratatui writes a frame to: a buffer, handed to the [`Line`]
/// whole. Its writes cannot fail, so neither can ratatui's.
struct FrameBytes {
    bytes: Vec<u8>,
    line: Line,
}

impl Write for FrameBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.line.send(std::mem::take(&mut self.bytes));
        Ok(())
    }
}

/// The terminal for the run. `Drop` gives it back.
pub struct Tui {
    terminal: Terminal<CrosstermBackend<FrameBytes>>,
    line: Line,
    repaint_owed: bool,
    /// The title in force, for the re-entry after a stop to take again.
    title: Option<String>,
}

impl Tui {
    /// Enter the full-screen UI, its loss told to `stop`. Must run on a real
    /// terminal; the kitty probe runs after raw mode is up (it queries the
    /// device). A failure part way gives back what was taken.
    pub fn enter(stop: &Stop) -> std::io::Result<Self> {
        enable_raw_mode()?;
        ENTERED.store(true, Ordering::SeqCst);
        Self::take_screen(stop).inspect_err(|_| leave())
    }

    fn take_screen(stop: &Stop) -> std::io::Result<Self> {
        #[cfg(unix)]
        let out = std::fs::File::from(stdout().as_fd().try_clone_to_owned()?);
        #[cfg(windows)]
        let out = std::fs::File::from(stdout().as_handle().try_clone_to_owned()?);
        let on_loss = stop.clone();
        let line = Line::open(out, move || lose_terminal(&on_loss))?;
        let _ = LINE.set(line.clone());
        watch_for_hangup(stop.clone());
        KITTY_ACCEPTED.store(
            supports_keyboard_enhancement().unwrap_or(false),
            Ordering::SeqCst,
        );
        line.send(enter_bytes());
        let terminal = Terminal::new(CrosstermBackend::new(FrameBytes {
            bytes: Vec::new(),
            line: line.clone(),
        }))?;
        Ok(Self {
            terminal,
            line,
            repaint_owed: false,
            title: None,
        })
    }
}

/// Watch standard input for the hang-up crossterm's reader would spin on, for
/// the terminal lost with no write to fail: no controlling terminal to send a
/// SIGHUP, nothing new to draw.
fn watch_for_hangup(stop: Stop) {
    let watch = move || {
        if rmule_os::terminal::wait_for_hangup(WATCH_REST) {
            lose_terminal(&stop);
        }
    };
    // Without the watch a loss still arrives with the next failed write.
    let _ = std::thread::Builder::new()
        .name("rmule-hangup".into())
        .spawn(watch);
}

impl Drop for Tui {
    fn drop(&mut self) {
        leave();
    }
}

/// What became of a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drawn {
    /// It is on its way to the terminal.
    Shown,
    /// The terminal cannot take it now: it is behind, stopped or gone. Its
    /// state stays owed, and the terminal keeps the last frame it had.
    Held,
}

/// Where `App` draws a frame. `Tui` is the one production implementation;
/// a test substitutes a recorder to prove a frame was drawn without opening
/// a real terminal. Nothing here fails or waits: a lost terminal is told to
/// the [`Stop`].
pub trait Surface {
    /// Draw one frame.
    fn draw(&mut self, render: impl FnOnce(&mut Frame)) -> Drawn;

    /// Have the next frame drawn whole, over whatever the screen shows now.
    fn repaint(&mut self);

    /// Copy `text` to the system clipboard.
    fn copy_to_clipboard(&mut self, text: &str);

    /// Show `title` as the terminal's title; `None` gives the title back.
    fn set_title(&mut self, title: Option<&str>);

    /// Ring the terminal's bell.
    fn ring_bell(&mut self);

    /// Give the terminal back and stop as a job. Answers once the job
    /// continues, or at once with why it cannot stop.
    ///
    /// # Errors
    ///
    /// This run cannot stop as a job.
    fn suspend(&mut self) -> Result<(), NoStop>;

    /// Take the terminal again after a stop, whoever stopped the run, and
    /// have the next frame drawn whole.
    fn reenter(&mut self);
}

impl Surface for Tui {
    /// Wraps the render in a synchronized-output block (mode 2026 —
    /// additive: terminals without it ignore both escapes).
    fn draw(&mut self, render: impl FnOnce(&mut Frame)) -> Drawn {
        if !entered() || self.line.busy() || self.line.lost() {
            return Drawn::Held;
        }
        let _ = queue!(self.terminal.backend_mut(), BeginSynchronizedUpdate);
        if std::mem::take(&mut self.repaint_owed) {
            let _ = self.terminal.clear();
        }
        // Past the writes, which cannot fail, only asking the terminal for
        // its size can, and that is a terminal going: its frame is held.
        let drawn = self.terminal.draw(render).is_ok();
        let backend = self.terminal.backend_mut();
        let _ = queue!(backend, EndSynchronizedUpdate);
        let _ = backend.flush();
        if drawn { Drawn::Shown } else { Drawn::Held }
    }

    fn repaint(&mut self) {
        self.repaint_owed = true;
    }

    /// Via OSC 52 (additive escape: terminals without clipboard integration
    /// ignore it; Ghostty honors it).
    fn copy_to_clipboard(&mut self, text: &str) {
        let payload = data_encoding::BASE64.encode(text.as_bytes());
        self.line
            .send(format!("\x1b]52;c;{payload}\x07").into_bytes());
    }

    fn set_title(&mut self, title: Option<&str>) {
        self.title = title.map(str::to_owned);
        self.line.send(title.map_or_else(release_title, take_title));
    }

    fn ring_bell(&mut self) {
        self.line.send(b"\x07".to_vec());
    }

    fn suspend(&mut self) -> Result<(), NoStop> {
        if let Some(refused) = rmule_os::terminal::stop_refused() {
            return Err(refused);
        }
        leave();
        rmule_os::terminal::stop_process_group();
        Ok(())
    }

    /// Whatever the shell left: raw mode set anew, since a shell may have put
    /// its own modes back, and a screen taken by a stop from outside given
    /// back first, so nothing is pushed twice. Off a job that was continued
    /// in the background, the first of these stops it again until `fg`.
    fn reenter(&mut self) {
        leave();
        if self.line.lost() {
            return;
        }
        if enable_raw_mode().is_err() {
            return;
        }
        ENTERED.store(true, Ordering::SeqCst);
        self.line.send(enter_bytes());
        if let Some(title) = &self.title {
            self.line.send(take_title(title));
        }
        self.repaint_owed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::{TITLE_POP, TITLE_PUSH, release_title, take_title};

    fn holds(bytes: &[u8], sequence: &str) -> bool {
        bytes
            .windows(sequence.len())
            .any(|window| window == sequence.as_bytes())
    }

    /// The stack takes one push per hold: a stop pops it, and the re-entry
    /// that follows has to push again or the pop at the end gives back nothing.
    #[test]
    fn the_title_is_pushed_once_per_hold_and_again_after_a_release() {
        assert!(holds(&take_title("a"), TITLE_PUSH));
        assert!(!holds(&take_title("b"), TITLE_PUSH));
        assert!(holds(&release_title(), TITLE_POP));
        assert!(release_title().is_empty(), "nothing held, nothing given");
        assert!(holds(&take_title("c"), TITLE_PUSH));
        assert!(holds(&release_title(), TITLE_POP));
    }
}
