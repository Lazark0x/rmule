//! Drawing the Searches view into a test terminal and reading the screen back.

use std::time::Instant;

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;

use super::{GOLDEN_H, GOLDEN_W, theme};
use crate::state::UiState;
use crate::views::searches::SearchesView;

/// Draw `view` over a `width`×`height` terminal and return what is on screen.
pub(crate) fn draw_searches(
    view: &mut SearchesView,
    state: &UiState,
    width: u16,
    height: u16,
) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
    terminal
        .draw(|frame| view.draw(frame, frame.area(), state, &theme(), Instant::now()))
        .expect("draw");
    terminal.backend().buffer().clone()
}

/// [`draw_searches`] at the golden surface.
pub(crate) fn draw_golden(view: &mut SearchesView, state: &UiState) -> Buffer {
    draw_searches(view, state, GOLDEN_W, GOLDEN_H)
}

/// The glyphs of `buffer`, one string per row.
pub(crate) fn screen_lines(buffer: &Buffer) -> Vec<String> {
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer.cell((x, y)).map_or(" ", |cell| cell.symbol()))
                .collect()
        })
        .collect()
}
