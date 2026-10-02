//! The search-method selector.
//!
//! The two methods are not a choice: a started search fans out to both
//! surfaces at once (ADR-0051 + ADR-0062), so the Kad slot renders
//! greyed-with-reason — not because it is missing, but because it is never
//! *not* running.

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use super::SearchesView;
use super::ViewOutcome;
use crate::action::Action;
use crate::theme::Theme;
use crate::wrap::wrap_text;

/// The visible-deferral method selector (spec §3.3): eD2k
/// server search is the one the operator picks; Kad rides along with it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum SearchMethod {
    #[default]
    Ed2kServer,
    Kad,
}

impl SearchMethod {
    const ALL: [SearchMethod; 2] = [SearchMethod::Ed2kServer, SearchMethod::Kad];

    fn label(self) -> &'static str {
        match self {
            SearchMethod::Ed2kServer => "eD2k server",
            SearchMethod::Kad => "Kad",
        }
    }

    fn available(self) -> bool {
        self.deferral_reason().is_none()
    }

    /// Greyed-with-reason. Kad's reason is not a
    /// missing feature: core fans every `StartSearch` out to the eD2k server,
    /// the global-UDP sweep *and* a Kad keyword walk, merging all three into one
    /// result set (ADR-0051/ADR-0062). There is nothing to pick.
    fn deferral_reason(self) -> Option<crate::words::Sentence> {
        match self {
            SearchMethod::Ed2kServer => None,
            SearchMethod::Kad => Some(crate::words::search::KAD_ALWAYS_ON),
        }
    }
}

impl SearchesView {
    /// Move the method selector to the next method, surfacing *why* when the
    /// target is deferred rather than silently refusing.
    pub(super) fn cycle_method(&mut self) -> ViewOutcome {
        let target = match self.method {
            SearchMethod::Ed2kServer => SearchMethod::Kad,
            SearchMethod::Kad => SearchMethod::Ed2kServer,
        };
        if target.available() {
            self.method = target;
            ViewOutcome::Redraw
        } else if let Some(reason) = target.deferral_reason() {
            ViewOutcome::Emit(Action::Flash(reason))
        } else {
            ViewOutcome::Redraw
        }
    }

    /// The method selector, wrapped so the deferral tag is never cut.
    pub(super) fn method_lines(&self, width: usize, theme: &Theme) -> Vec<Line<'static>> {
        if self.showing_related() {
            // Asked of the connected server alone (ADR-0037): no Kad walk, no
            // sweep, whatever the selector says for typed queries.
            return wrap_text("Method: the connected server only", width)
                .into_iter()
                .map(|part| Line::from(Span::styled(part, theme.dim_text())))
                .collect();
        }
        let mut spans = vec![Span::styled("Method: ", theme.dim_text())];
        for (index, method) in SearchMethod::ALL.iter().enumerate() {
            if index > 0 {
                spans.push(Span::raw("  "));
            }
            let label = format!("{} ▾", method.label());
            if let Some(reason) = method.deferral_reason() {
                // Greyed-with-reason.
                spans.push(Span::styled(label, theme.dim_text()));
                spans.push(Span::styled(format!(" ({reason})"), theme.dim_text()));
            } else if *method == self.method {
                spans.push(Span::styled(
                    label,
                    Style::new().fg(theme.accent).add_modifier(Modifier::BOLD),
                ));
            } else {
                spans.push(Span::styled(label, Style::new().fg(theme.fg)));
            }
        }
        let line = Line::from(spans);
        if line.width() <= width {
            return vec![line];
        }
        // Too narrow for the styled composition: fall back to a wrapped plain
        // rendering rather than clipping the tail off.
        let flat: String = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        wrap_text(&flat, width)
            .into_iter()
            .map(|part| Line::from(Span::styled(part, theme.dim_text())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::state::UiState;
    use ratatui::crossterm::event::KeyCode;

    use super::*;
    use crate::fixture::*;

    #[test]
    fn the_method_toggle_surfaces_the_kad_deferral() {
        let state = UiState::default();
        let mut view = SearchesView::new();
        view.handle_key(press(KeyCode::Char('/')), &state);
        match view.handle_key(press(KeyCode::Right), &state) {
            ViewOutcome::Emit(Action::Flash(text)) => {
                assert_eq!(text, "always on — every search also walks Kad");
            }
            _ => panic!("toggling toward the deferred Kad method flashes its reason"),
        }
        // The only selectable method stays selected (visible deferral).
        assert_eq!(view.method, SearchMethod::Ed2kServer);
        assert!(!SearchMethod::Kad.available());
    }
}
