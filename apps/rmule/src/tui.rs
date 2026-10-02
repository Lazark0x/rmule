//! Terminal lifecycle (spec §5 feature floor): raw mode + alternate screen
//! via `ratatui::init`, mouse capture, kitty-keyboard enhancement pushed only
//! when the terminal reports support (feature-detected, never assumed), and
//! synchronized output (DEC mode 2026) wrapped around every frame so a big
//! repaint commits atomically. Restore is drop-safe for the extras this
//! module adds; `ratatui::init`'s own panic hook covers raw/altscreen.
//!
//! [`Surface`] is the one capability `App` needs from this module — draw a
//! frame — pulled out as a trait so `App::graceful_quit`'s redraw-on-wait
//! sequence can be proven against a recorder in a test instead
//! of a real terminal, which only [`Tui::enter`] can open.

use std::io::stdout;

use ratatui::crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, KeyboardEnhancementFlags, PopKeyboardEnhancementFlags,
    PushKeyboardEnhancementFlags,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    BeginSynchronizedUpdate, EndSynchronizedUpdate, supports_keyboard_enhancement,
};
use ratatui::{DefaultTerminal, Frame};

/// The terminal for the run, holding whichever enhancements this terminal
/// accepted so `Drop` gives back exactly what was taken.
pub struct Tui {
    terminal: DefaultTerminal,
    kitty_pushed: bool,
}

impl Tui {
    /// Enter the full-screen UI. Must run on a real terminal; the kitty
    /// probe runs after raw mode is up (it queries the device).
    pub fn enter() -> std::io::Result<Self> {
        let terminal = ratatui::init();
        let kitty_pushed = supports_keyboard_enhancement().unwrap_or(false);
        if kitty_pushed {
            execute!(
                stdout(),
                PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
            )?;
        }
        execute!(stdout(), EnableMouseCapture)?;
        Ok(Self {
            terminal,
            kitty_pushed,
        })
    }

    /// Copy `text` to the system clipboard via OSC 52 (additive escape:
    /// terminals without clipboard integration ignore it; Ghostty honors it).
    pub fn copy_to_clipboard(&mut self, text: &str) -> std::io::Result<()> {
        let payload = data_encoding::BASE64.encode(text.as_bytes());
        execute!(
            stdout(),
            ratatui::crossterm::style::Print(format!("\x1b]52;c;{payload}\x07"))
        )
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        if self.kitty_pushed {
            let _ = execute!(stdout(), PopKeyboardEnhancementFlags);
        }
        let _ = execute!(stdout(), DisableMouseCapture);
        ratatui::restore();
    }
}

/// Where `App` draws a frame. `Tui` is the one production implementation;
/// a test substitutes a recorder to prove a frame was drawn without opening
/// a real terminal.
pub trait Surface {
    /// Draw one frame.
    fn draw(&mut self, render: impl FnOnce(&mut Frame)) -> std::io::Result<()>;
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
}
