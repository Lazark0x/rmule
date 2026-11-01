//! The ratatui backend the run draws on: crossterm's, writing to the
//! [`FrameBytes`] buffer, but for one question. Ratatui asks for the cursor
//! before every clear, a resize's among them, and crossterm answers by
//! writing a query to the terminal and waiting up to two seconds on the
//! input it shares with the pump: a loop that waits on nothing cannot ask,
//! and a full frame follows every clear, so the answer is never read.

use std::io::Write;

use ratatui::backend::{Backend, ClearType, CrosstermBackend, WindowSize};
use ratatui::buffer::Cell;
use ratatui::layout::{Position, Size};

use super::line::Line;

/// The stream ratatui writes a frame to: a buffer, handed to the [`Line`]
/// whole. Its writes cannot fail, so neither can ratatui's.
pub(super) struct FrameBytes {
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

/// See the module's doc.
pub(super) struct Screen {
    crossterm: CrosstermBackend<FrameBytes>,
    cursor: Position,
}

impl Screen {
    pub(super) fn new(line: Line) -> Self {
        let bytes = FrameBytes {
            bytes: Vec::new(),
            line,
        };
        Self {
            crossterm: CrosstermBackend::new(bytes),
            cursor: Position::ORIGIN,
        }
    }
}

impl Write for Screen {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.crossterm.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Write::flush(&mut self.crossterm)
    }
}

impl Backend for Screen {
    type Error = std::io::Error;

    fn draw<'a, I>(&mut self, content: I) -> std::io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        self.crossterm.draw(content)
    }

    fn append_lines(&mut self, lines: u16) -> std::io::Result<()> {
        self.crossterm.append_lines(lines)
    }

    fn hide_cursor(&mut self) -> std::io::Result<()> {
        self.crossterm.hide_cursor()
    }

    fn show_cursor(&mut self) -> std::io::Result<()> {
        self.crossterm.show_cursor()
    }

    /// Where the run last put the cursor; the terminal is never asked.
    fn get_cursor_position(&mut self) -> std::io::Result<Position> {
        Ok(self.cursor)
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> std::io::Result<()> {
        self.cursor = position.into();
        self.crossterm.set_cursor_position(self.cursor)
    }

    fn clear(&mut self) -> std::io::Result<()> {
        self.crossterm.clear()
    }

    fn clear_region(&mut self, clear_type: ClearType) -> std::io::Result<()> {
        self.crossterm.clear_region(clear_type)
    }

    fn size(&self) -> std::io::Result<Size> {
        self.crossterm.size()
    }

    fn window_size(&mut self) -> std::io::Result<WindowSize> {
        self.crossterm.window_size()
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Backend::flush(&mut self.crossterm)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use ratatui::Terminal;

    use super::{Line, Screen};

    /// Crossterm's own answer asks a terminal, and a test has none: a clear
    /// that asked would fail here, or wait out its two seconds.
    #[test]
    fn a_clear_asks_the_terminal_nothing() {
        let line = Line::open(std::io::sink(), || {}).expect("thread");
        let viewport = ratatui::TerminalOptions {
            viewport: ratatui::Viewport::Fixed(ratatui::layout::Rect::new(0, 0, 80, 24)),
        };
        let mut terminal = Terminal::with_options(Screen::new(line), viewport).expect("terminal");
        let asked = Instant::now();

        terminal.clear().expect("no question, no failure");

        assert!(asked.elapsed() < Duration::from_secs(1));
    }
}
