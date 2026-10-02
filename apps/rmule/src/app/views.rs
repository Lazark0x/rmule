//! The six views the app loop owns, and the dispatch that offers an input to
//! the active one.
//!
//! Every view implements the same small contract, so routing a key or a click
//! is one match rather than six special cases.

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::Rect;

use crate::state::UiState;
use crate::theme::Theme;
use crate::view::ViewId;
use crate::views::ViewOutcome;
use crate::views::networks::NetworksView;
use crate::views::searches::SearchesView;
use crate::views::settings::SettingsView;
use crate::views::shared_files::SharedView;
use crate::views::statistics;
use crate::views::transfers::TransfersView;

/// The persistent view components (selection/scroll/menu state survives across
/// frames and view switches). Dispatch is a match — the views share a
/// signature by convention (views/mod.rs contract), not a trait.
///
/// Statistics has no field: it is display-only, so it holds no view
/// state to persist and its key/click arms are honest `Ignored`s that let the
/// globals through.
#[derive(Default)]
pub(super) struct Views {
    pub(super) transfers: TransfersView,
    pub(super) searches: SearchesView,
    pub(super) networks: NetworksView,
    pub(super) shared: SharedView,
    pub(super) settings: SettingsView,
}

impl Views {
    pub(super) fn handle_key(
        &mut self,
        active: ViewId,
        key: ratatui::crossterm::event::KeyEvent,
        state: &UiState,
    ) -> ViewOutcome {
        match active {
            ViewId::Transfers => self.transfers.handle_key(key, state),
            ViewId::Searches => self.searches.handle_key(key, state),
            ViewId::Networks => self.networks.handle_key(key, state),
            ViewId::SharedFiles => self.shared.handle_key(key, state),
            ViewId::Statistics => ViewOutcome::Ignored,
            ViewId::Settings => self.settings.handle_key(key, state),
        }
    }

    pub(super) fn draw(
        &mut self,
        active: ViewId,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
        now: Instant,
    ) {
        match active {
            ViewId::Transfers => self.transfers.draw(frame, area, state, theme, now),
            ViewId::Searches => self.searches.draw(frame, area, state, theme, now),
            ViewId::Networks => {
                // The one impure stamp in the draw path: the log gutter shows
                // wall-clock event times, derived at draw from `wall − age`.
                // Goldens call the view directly and use its fixed fallback.
                self.networks.wall_now = Some(chrono::Local::now().fixed_offset());
                self.networks.draw(frame, area, state, theme, now);
            }
            ViewId::SharedFiles => self.shared.draw(frame, area, state, theme, now),
            ViewId::Statistics => statistics::draw(frame, area, state, theme, now),
            ViewId::Settings => self.settings.draw(frame, area, state, theme, now),
        }
    }

    pub(super) fn handle_click(
        &mut self,
        active: ViewId,
        column: u16,
        row: u16,
        state: &UiState,
    ) -> ViewOutcome {
        match active {
            ViewId::Transfers => self.transfers.handle_click(column, row, state),
            ViewId::Searches => self.searches.handle_click(column, row, state),
            ViewId::Networks => self.networks.handle_click(column, row, state),
            ViewId::SharedFiles => self.shared.handle_click(column, row, state),
            ViewId::Statistics => ViewOutcome::Ignored,
            ViewId::Settings => self.settings.handle_click(column, row, state),
        }
    }
}
