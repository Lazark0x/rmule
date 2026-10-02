//! Every table marks its selected row the same way, in either focus.

use std::time::Instant;

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::Modifier;

use crate::fixture::{
    listed_servers, press, served_files, state_with, theme, three_downloads, three_tier_results,
};
use crate::state::{SearchStatus, UiState};
use crate::theme::Theme;
use crate::views::networks::NetworksView;
use crate::views::searches::SearchesView;
use crate::views::shared_files::SharedView;
use crate::views::transfers::TransfersView;

const W: u16 = 120;
const H: u16 = 40;

fn drawn(mut draw: impl FnMut(&mut ratatui::Frame)) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(W, H)).expect("terminal");
    terminal.draw(|frame| draw(frame)).expect("draw");
    terminal.backend().buffer().clone()
}

fn area() -> Rect {
    Rect::new(0, 0, W, H)
}

/// One table (or two, for a view with a pane under it), drawn with the focus
/// on its `n`th pane.
struct Case {
    name: &'static str,
    /// Tables on screen, each with a selected row.
    marked: usize,
    /// How many places the focus can be: the marked tables, and any pane
    /// without a selection (the log, the query input).
    focuses: usize,
    draw: fn(focus: usize, &Theme) -> Buffer,
}

fn transfers(focus: usize, theme: &Theme) -> Buffer {
    let (mut view, state) = (TransfersView::new(), three_downloads());
    let now = Instant::now();
    drawn(|frame| view.draw(frame, area(), &state, theme, now));
    for _ in 0..focus {
        view.handle_key(press(KeyCode::Tab), &state);
    }
    drawn(|frame| view.draw(frame, area(), &state, theme, now))
}

fn shared(focus: usize, theme: &Theme) -> Buffer {
    let (mut view, state) = (SharedView::default(), served_files());
    for _ in 0..focus {
        view.handle_key(press(KeyCode::Tab), &state);
    }
    drawn(|frame| view.draw(frame, area(), &state, theme, Instant::now()))
}

fn searches(focus: usize, theme: &Theme) -> Buffer {
    let state = state_with(three_tier_results(), SearchStatus::Completed { total: 3 });
    let mut view = SearchesView::new().having_sent("ubuntu");
    if focus == 1 {
        view.handle_key(press(KeyCode::Char('/')), &state);
    }
    drawn(|frame| view.draw(frame, area(), &state, theme, Instant::now()))
}

fn networks(focus: usize, theme: &Theme) -> Buffer {
    let (mut view, state): (NetworksView, UiState) = (NetworksView::new(), listed_servers());
    for _ in 0..focus {
        view.handle_key(press(KeyCode::Tab), &state);
    }
    drawn(|frame| view.draw(frame, area(), &state, theme, Instant::now()))
}

/// The cells of every `▸` on screen, top to bottom.
fn markers(buffer: &Buffer) -> Vec<(u16, u16)> {
    (0..H)
        .flat_map(|y| (0..W).map(move |x| (x, y)))
        .filter(|&(x, y)| buffer.cell((x, y)).is_some_and(|c| c.symbol() == "▸"))
        .collect()
}

#[test]
fn every_table_marks_its_selected_row_in_either_focus() {
    let theme = theme();
    let cases = [
        Case {
            name: "transfers",
            marked: 2,
            focuses: 2,
            draw: transfers,
        },
        Case {
            name: "shared files",
            marked: 2,
            focuses: 2,
            draw: shared,
        },
        Case {
            name: "searches",
            marked: 1,
            focuses: 2,
            draw: searches,
        },
        Case {
            name: "networks",
            marked: 1,
            focuses: 2,
            draw: networks,
        },
    ];
    for case in cases {
        for focus in 0..case.focuses {
            let buffer = (case.draw)(focus, &theme);
            let found = markers(&buffer);
            let context = format!("{}, focus {focus}", case.name);
            assert_eq!(found.len(), case.marked, "{context}: a marker per table");
            for (index, &(x, y)) in found.iter().enumerate() {
                let marker = buffer.cell((x, y)).expect("marker cell");
                assert_eq!(marker.style().bg, Some(theme.selection), "{context}");
                // The row's first word, past the gutter.
                let word = (x + 1..W)
                    .map(|x| buffer.cell((x, y)).expect("row cell"))
                    .find(|cell| !matches!(cell.symbol(), " " | "●"))
                    .expect("a selected row says something");
                assert_eq!(word.style().bg, Some(theme.selection), "{context}");
                if index == focus {
                    assert!(word.modifier.contains(Modifier::BOLD), "{context}: bold");
                    assert!(!word.modifier.contains(Modifier::DIM), "{context}");
                } else {
                    assert!(word.modifier.contains(Modifier::DIM), "{context}: dimmed");
                    assert!(!word.modifier.contains(Modifier::BOLD), "{context}");
                }
            }
        }
    }
}
