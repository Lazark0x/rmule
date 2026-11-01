//! The line under the query that says who a search would ask.
//!
//! There is no method to pick: a started search goes to the server, to the
//! other listed servers and through Kad (ADR-0051 + ADR-0062), each leg that
//! can run. What the operator can use is which of them can run now.

use ratatui::text::{Line, Span};

use super::SearchesView;
use crate::state::UiState;
use crate::theme::Theme;
use crate::words::search as words;
use crate::wrap::wrap_text;

impl SearchesView {
    /// Who a search sent now would ask, from the levels; a Related-Files
    /// entry goes to the connected server alone (ADR-0037).
    pub(super) fn asks_lines(
        &self,
        width: usize,
        state: &UiState,
        theme: &Theme,
    ) -> Vec<Line<'static>> {
        let text = if self.showing_related() {
            words::ASKS_CONNECTED_SERVER
        } else {
            let server = state.connected_server.is_some()
                || state.diagnostics.connected_server.is_some();
            words::asks(server, state.diagnostics.kad.is_some())
        };
        wrap_text(text, width)
            .into_iter()
            .map(|part| Line::from(Span::styled(part, theme.dim_text())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_first_run_is_not_promised_a_walk_of_kad() {
        let view = SearchesView::new();
        let lines = view.asks_lines(70, &UiState::default(), &Theme::default_dark());
        let text: String = lines[0].spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(text, "Asks: nobody yet; a search waits for a server or Kad");
    }
}
