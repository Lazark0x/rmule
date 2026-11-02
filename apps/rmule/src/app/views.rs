//! The six views the app loop owns, and which one is active.
//!
//! Each view keeps its own state across frames and view switches, and they all
//! answer the one [`View`] contract, so routing an input is picking the view.

use crate::view::ViewId;
use crate::views::View;
use crate::views::networks::NetworksView;
use crate::views::searches::SearchesView;
use crate::views::settings::SettingsView;
use crate::views::shared_files::SharedView;
use crate::views::statistics::StatisticsView;
use crate::views::transfers::TransfersView;

/// The persistent view components.
#[derive(Default)]
pub(super) struct Views {
    pub(super) transfers: TransfersView,
    pub(super) searches: SearchesView,
    pub(super) networks: NetworksView,
    pub(super) shared: SharedView,
    pub(super) statistics: StatisticsView,
    pub(super) settings: SettingsView,
}

impl Views {
    /// The view `active` names.
    pub(super) fn view(&self, active: ViewId) -> &dyn View {
        match active {
            ViewId::Transfers => &self.transfers,
            ViewId::Searches => &self.searches,
            ViewId::Networks => &self.networks,
            ViewId::SharedFiles => &self.shared,
            ViewId::Statistics => &self.statistics,
            ViewId::Settings => &self.settings,
        }
    }

    /// The view `active` names, to offer it an input.
    pub(super) fn view_mut(&mut self, active: ViewId) -> &mut dyn View {
        match active {
            ViewId::Transfers => &mut self.transfers,
            ViewId::Searches => &mut self.searches,
            ViewId::Networks => &mut self.networks,
            ViewId::SharedFiles => &mut self.shared,
            ViewId::Statistics => &mut self.statistics,
            ViewId::Settings => &mut self.settings,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use ratatui::crossterm::event::KeyCode;

    use super::*;
    use crate::fixture::{golden_area, press, served_files, theme};

    #[test]
    fn a_filter_being_typed_keeps_the_terminals_cursor() {
        let state = served_files();
        let mut views = Views::default();
        let shared = ViewId::SharedFiles;
        views
            .view_mut(shared)
            .handle_key(press(KeyCode::Char('/')), &state);

        let mut caret = None;
        crate::golden::render_to_lines(golden_area().width, golden_area().height, |frame| {
            let now = Instant::now();
            caret = views
                .view_mut(shared)
                .draw(frame, golden_area(), &state, &theme(), now);
        });
        assert!(caret.is_some());
    }
}
