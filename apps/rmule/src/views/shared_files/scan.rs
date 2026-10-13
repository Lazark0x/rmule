//! The disclosure questions (ADR-0101): the download directory's first
//! share and a directory being added, asked as a modal that names what a yes
//! discloses. Shared Files asks every question; Settings asks the ones its
//! own add raised. Each view remembers what it answered, since the question
//! stays open in the state until core's next edge for the directory.

use std::cell::Cell;
use std::collections::BTreeSet;

use crate::row_selection::viewport::Viewport;
use crate::views::modal::{Modal, scroll_key};
use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use rmule_core::{CoreCommand, ScanCommand};

use super::ViewOutcome;
use crate::action::Action;
use crate::state::{ScanConsent, UiState};
use crate::theme::Theme;
use crate::wrap::{clamp_u16, wrapped_lines};

/// The oldest open question this view has not answered; with `adding_only`,
/// only a directory being added.
pub(crate) fn open_consent<'a>(
    state: &'a UiState,
    answered: &BTreeSet<u64>,
    adding_only: bool,
) -> Option<&'a ScanConsent> {
    state
        .scan_consents
        .iter()
        .find(|consent| !answered.contains(&consent.asked) && (consent.adding || !adding_only))
}

/// `y` shares, `n` keeps the directory private. Every other key is
/// swallowed so nothing behind the question moves, except what the globals
/// claim (a tab switch, quit — which answers nothing). `j` `k` `g` `G`
/// scroll the question in a frame too short for it.
pub(crate) fn consent_key(
    key: KeyEvent,
    consent: &ScanConsent,
    (answered, viewport): (&mut BTreeSet<u64>, &mut Cell<Viewport>),
) -> ViewOutcome {
    let share = match key.code {
        KeyCode::Char('y') => true,
        KeyCode::Char('n') => false,
        KeyCode::Char('j' | 'k' | 'g' | 'G') | KeyCode::Up | KeyCode::Down => {
            scroll_key(viewport, key.code);
            return ViewOutcome::Redraw;
        }
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('m' | 'x') => {
            return ViewOutcome::Redraw;
        }
        _ => return ViewOutcome::Ignored,
    };
    viewport.take();
    answered.insert(consent.asked);
    ViewOutcome::Emit(Action::Command(CoreCommand::Scan(ScanCommand::Answer {
        dir: consent.dir.clone(),
        share,
    })))
}

/// The question, with what a yes discloses.
pub(crate) fn draw_consent(
    frame: &mut Frame,
    area: Rect,
    consent: &ScanConsent,
    theme: &Theme,
    viewport: &Cell<Viewport>,
) {
    let (title, question, consequence) = crate::words::scan::share_confirm(
        &consent.dir,
        consent.offer,
        consent.adding,
        &consent.replaces,
    );
    let width = clamp_u16(64).min(area.width);
    let lines = |width: u16| {
        let text_w = usize::from(width).saturating_sub(4).max(1);
        let mut lines = wrapped_lines(&question, text_w, Style::new().fg(theme.fg));
        lines.push(Line::from(""));
        lines.extend(wrapped_lines(&consequence, text_w, theme.dim_text()));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("y", Style::new().fg(theme.bad).add_modifier(Modifier::BOLD)),
            Span::styled(" share    ", Style::new().fg(theme.fg)),
            Span::styled("n", Style::new().fg(theme.accent)),
            Span::styled(" keep private", Style::new().fg(theme.fg)),
        ]));
        lines
    };
    Modal::new(title, theme)
        .padded()
        .draw_scrolled(frame, area, width, theme, viewport, lines);
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ratatui::crossterm::event::KeyCode;
    use rmule_core::DirectoryOffer;

    use super::*;
    use crate::fixture::press;
    use crate::views::shared_files::SharedView;

    fn asked(dir: &str) -> UiState {
        let mut state = UiState::default();
        crate::state::fold(
            &mut state,
            rmule_core::CoreEvent::Scan(rmule_core::ScanEvent::ConsentRequested {
                dir: PathBuf::from(dir),
                offer: DirectoryOffer {
                    files: 3,
                    bytes: 3_000,
                    unread: 0,
                },
                adding: false,
                replaces: Vec::new(),
            }),
        );
        state
    }

    fn answer_of(outcome: ViewOutcome) -> Option<bool> {
        match outcome {
            ViewOutcome::Emit(Action::Command(CoreCommand::Scan(ScanCommand::Answer {
                share,
                ..
            }))) => Some(share),
            _ => None,
        }
    }

    #[test]
    fn the_question_takes_the_keys_until_answered_then_closes() {
        let state = asked("/dl");
        let mut view = SharedView::default();
        assert!(matches!(
            view.handle_key(press(KeyCode::Char('m')), &state),
            ViewOutcome::Redraw
        ));
        assert_eq!(
            answer_of(view.handle_key(press(KeyCode::Char('y')), &state)),
            Some(true)
        );
        assert!(view.pending_consent(&state).is_none());
    }

    /// Core asks again about a directory whose answer it could not record:
    /// the second question is shown though the first was answered.
    #[test]
    fn a_second_question_about_the_same_directory_is_asked_again() {
        let mut state = asked("/dl");
        let mut view = SharedView::default();
        view.handle_key(press(KeyCode::Char('y')), &state);
        assert!(view.pending_consent(&state).is_none());
        let again = asked("/dl");
        state.scan_consents = again.scan_consents;
        state.scan_consents[0].asked = 2;
        assert!(view.pending_consent(&state).is_some());
    }

    /// Two directories asked about at once are both asked, in turn: an edge
    /// about one does not drop the other's question.
    #[test]
    fn a_question_waits_its_turn_behind_another_directorys() {
        let mut state = asked("/dl");
        crate::state::fold(
            &mut state,
            rmule_core::CoreEvent::Scan(rmule_core::ScanEvent::ConsentRequested {
                dir: PathBuf::from("/media"),
                offer: DirectoryOffer::default(),
                adding: true,
                replaces: Vec::new(),
            }),
        );
        crate::state::fold(
            &mut state,
            rmule_core::CoreEvent::Scan(rmule_core::ScanEvent::WatchRestored {
                dir: PathBuf::from("/elsewhere"),
            }),
        );
        let mut view = SharedView::default();
        assert_eq!(
            view.pending_consent(&state).unwrap().dir,
            PathBuf::from("/dl")
        );
        view.handle_key(press(KeyCode::Char('n')), &state);
        assert_eq!(
            view.pending_consent(&state).unwrap().dir,
            PathBuf::from("/media")
        );
    }

    #[test]
    fn n_keeps_the_directory_private() {
        let state = asked("/dl");
        let mut view = SharedView::default();
        assert_eq!(
            answer_of(view.handle_key(press(KeyCode::Char('n')), &state)),
            Some(false)
        );
    }
}
