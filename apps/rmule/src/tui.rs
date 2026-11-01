//! Terminal lifecycle (spec §5 feature floor): raw mode + alternate screen
//! entered by hand, mouse capture, kitty-keyboard enhancement pushed only
//! when the terminal reports support (feature-detected, never assumed), and
//! synchronized output (DEC mode 2026) wrapped around every frame so a big
//! repaint commits atomically. [`leave`] is the one restore: [`Tui`]'s `Drop`
//! and the panic hook (ADR-0118) both reach it, and only the first does
//! anything. Ratatui's own init is not used, since its hook restores the
//! terminal on a panic of any thread, with the UI still drawing.
//!
//! [`Surface`] is the one capability `App` needs from this module — draw a
//! frame — pulled out as a trait so `App::graceful_quit`'s redraw-on-wait
//! sequence can be proven against a recorder in a test instead
//! of a real terminal, which only [`Tui::enter`] can open.

use std::io::stdout;
use std::sync::atomic::{AtomicBool, Ordering};

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, KeyboardEnhancementFlags, PopKeyboardEnhancementFlags,
    PushKeyboardEnhancementFlags,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    BeginSynchronizedUpdate, EndSynchronizedUpdate, EnterAlternateScreen, LeaveAlternateScreen,
    disable_raw_mode, enable_raw_mode, supports_keyboard_enhancement,
};
use ratatui::{DefaultTerminal, Frame, Terminal};

/// The terminal is ours: what [`leave`] gives back, and what a panic on
/// another thread reads to know a frame is up.
static ENTERED: AtomicBool = AtomicBool::new(false);
/// The kitty enhancement was accepted, so [`leave`] pops it.
static KITTY_PUSHED: AtomicBool = AtomicBool::new(false);

/// Whether the full-screen UI holds the terminal.
#[must_use]
pub fn entered() -> bool {
    ENTERED.load(Ordering::SeqCst)
}

/// Give the terminal back, exactly what was taken, once: a later call and a
/// call with nothing entered do nothing. Safe on any thread.
pub fn leave() {
    if !ENTERED.swap(false, Ordering::SeqCst) {
        return;
    }
    let _ = execute!(stdout(), EndSynchronizedUpdate);
    if KITTY_PUSHED.swap(false, Ordering::SeqCst) {
        let _ = execute!(stdout(), PopKeyboardEnhancementFlags);
    }
    let _ = execute!(stdout(), DisableMouseCapture, LeaveAlternateScreen);
    let _ = disable_raw_mode();
}

/// The terminal for the run. `Drop` gives it back.
pub struct Tui {
    terminal: DefaultTerminal,
}

impl Tui {
    /// Enter the full-screen UI. Must run on a real terminal; the kitty
    /// probe runs after raw mode is up (it queries the device). A failure
    /// part way gives back what was taken.
    pub fn enter() -> std::io::Result<Self> {
        enable_raw_mode()?;
        ENTERED.store(true, Ordering::SeqCst);
        Self::take_screen().inspect_err(|_| leave())
    }

    fn take_screen() -> std::io::Result<Self> {
        execute!(stdout(), EnterAlternateScreen)?;
        let terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
        if supports_keyboard_enhancement().unwrap_or(false) {
            execute!(
                stdout(),
                PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
            )?;
            KITTY_PUSHED.store(true, Ordering::SeqCst);
        }
        execute!(stdout(), EnableMouseCapture)?;
        Ok(Self { terminal })
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        leave();
    }
}

/// Where `App` draws a frame. `Tui` is the one production implementation;
/// a test substitutes a recorder to prove a frame was drawn without opening
/// a real terminal.
pub trait Surface {
    /// Draw one frame.
    fn draw(&mut self, render: impl FnOnce(&mut Frame)) -> std::io::Result<()>;

    /// Copy `text` to the system clipboard.
    fn copy_to_clipboard(&mut self, text: &str) -> std::io::Result<()>;
}

impl Surface for Tui {
    /// Wraps the render in a synchronized-output block (mode 2026 —
    /// additive: terminals without it ignore both escapes).
    fn draw(&mut self, render: impl FnOnce(&mut Frame)) -> std::io::Result<()> {
        execute!(stdout(), BeginSynchronizedUpdate)?;
        let drawn = self.terminal.draw(render).map(|_| ());
        execute!(stdout(), EndSynchronizedUpdate)?;
        drawn
    }

    /// Via OSC 52 (additive escape: terminals without clipboard integration
    /// ignore it; Ghostty honors it).
    fn copy_to_clipboard(&mut self, text: &str) -> std::io::Result<()> {
        let payload = data_encoding::BASE64.encode(text.as_bytes());
        execute!(
            stdout(),
            ratatui::crossterm::style::Print(format!("\x1b]52;c;{payload}\x07"))
        )
    }
}
