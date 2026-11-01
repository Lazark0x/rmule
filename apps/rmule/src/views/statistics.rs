//! The Statistics view (spec §6 return): the session's rate history
//! as two oscilloscope graphs over a facts strip — aMule's statistics page
//! (graphs on top, totals tree below) rendered against the facts core actually
//! surfaces.
//!
//! # Where the data comes from
//!
//! Everything here is a fact the 1 Hz data tick already established:
//!
//! - the graphs replay [`UiState::rate_history`], the tiers `apply_snapshot`
//!   adds each tick to — never a rate this view derives at draw time, so a
//!   graph column and the status bar's ▼/▲ can never disagree;
//! - the totals are [`rmule_core::diagnostics::SessionCounters`] — core's
//!   monotonic process-lifetime byte counters (ADR-0077) — read straight
//!   through, not summed from rows that retire;
//! - the activity counts come from the same two lanes the other views read:
//!   the levels lane for upload slots, the edge fold for downloads, queued
//!   peers, shares, the eD2k connection and Kad.
//!
//! Nothing is invented. A run before the first data tick lands shows `—` for every metered figure rather than a zero
//! nobody observed, and the graphs say so instead of drawing a flat line.
//!
//! # Why a sparkline and not a braille chart
//!
//! `Sparkline` maps one history column to one cell with block glyphs, so the
//! render is exact (no interpolation), stable under `TestBackend` — the goldens are
//! readable ASCII — and degrades to the same glyphs in the Indexed-256 theme,
//! where only the tone changes. A braille `Chart` would resample the window
//! onto its canvas, forcing axis furniture and a legend into panes this small
//! and making every golden width-sensitive for no added truth.
//!
//! The view is **display-only**: no selection, no menus, no modal. Its one
//! view state is the window `w` walks.
use std::time::Instant;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Rect};

use crate::state::{RateWindow, UiState};
use crate::theme::Theme;
use crate::views::ViewOutcome;
use facts::draw_facts;
use graph::{Series, draw_graph};

mod facts;
mod graph;

/// Height of the facts strip: six fact rows (either pane, the Session one
/// counting Kad in/out, the Activity one the refused hellos) plus the pane border.
const FACTS_H: u16 = 8;

/// The Statistics tab: which window of the history the graphs show.
#[derive(Debug, Default)]
pub struct StatisticsView {
    window: RateWindow,
}

impl StatisticsView {
    /// `w` walks the window; every other key bubbles to the app loop.
    pub fn handle_key(&mut self, key: KeyEvent) -> ViewOutcome {
        if key.code == KeyCode::Char('w') {
            self.window = self.window.next();
            return ViewOutcome::Redraw;
        }
        ViewOutcome::Ignored
    }

    /// Draw the whole view: the download graph, the upload graph, the facts strip.
    pub fn draw(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
        now: Instant,
    ) {
        let [graphs, facts] =
            Layout::vertical([Constraint::Min(4), Constraint::Length(FACTS_H)]).areas(area);
        // Both graphs get the same height, so neither draws a bar-row fewer; an
        // odd row left over sits between them rather than in one of them.
        let half = graphs.height / 2;
        let down = Rect {
            height: half,
            ..graphs
        };
        let up = Rect {
            y: graphs.bottom() - half,
            height: half,
            ..graphs
        };

        draw_graph(frame, down, state, theme, now, (Series::Down, self.window));
        draw_graph(frame, up, state, theme, now, (Series::Up, self.window));
        draw_facts(frame, facts, state, theme, now);
    }
}
