//! Downloading a result, and adding a file the operator already knows
//! (ADR-0100, "Adding a marked file"): a new file starts at once; a file
//! downloading already is refused with where it is; a file they have, once
//! had, or once cancelled, is asked about once — naming the mark, for Have
//! the path, for Had the name it last had and the day it left — and a yes
//! starts it, which turns its mark to Downloading. A file whose download
//! failed is asked about the same way, and a yes restarts that download in
//! place (ADR-0094, "Failed").

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use rmule_core::{CoreCommand, DownloadCommand, DownloadId, NameTaken};
use rmule_primitives::{SafeFileName, SearchResult};

use super::{SearchesView, ViewOutcome};
use crate::action::Action;
use crate::row_selection::viewport::Viewport;
use crate::state::{
    KnownFileMark, KnownFileMarks, UiState, download_failure_words, withheld_words,
};
use crate::theme::Theme;
use crate::views::day;
use crate::views::modal::{Modal, scroll_key};
use crate::words::download as download_words;
use crate::wrap::wrapped_lines;

/// The confirm a Have, Withheld, Had, Cancelled or Failed result opens: the
/// result, and the mark it was asked about.
#[derive(Clone, Debug)]
pub(super) struct ReAdd {
    result: SearchResult,
    mark: KnownFileMark,
    /// What part of the question is on screen, in a frame too short for it.
    viewport: std::cell::Cell<Viewport>,
}

impl SearchesView {
    /// The row menu's Download on the selected result.
    pub(super) fn download_selected(&mut self, state: &UiState) -> ViewOutcome {
        let Some(result) = self.selected_result(state).cloned() else {
            return ViewOutcome::Redraw;
        };
        let mark = KnownFileMarks::of(state)
            .get(result.file_hash(), result.file_size())
            .cloned();
        match mark {
            None => start_download(&result, state, false),
            Some(KnownFileMark::Downloading { name }) => {
                ViewOutcome::Emit(Action::Flash(download_words::already_downloading(&name)))
            }
            Some(mark) => {
                self.readd = Some(ReAdd {
                    result,
                    mark,
                    viewport: std::cell::Cell::default(),
                });
                ViewOutcome::Redraw
            }
        }
    }

    /// The confirm is modal: `y` starts the download, `n` / `Esc` / `q` keep
    /// things as they are, anything else is swallowed.
    pub(super) fn handle_readd_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome {
        match key.code {
            KeyCode::Char('y') => match self.readd.take() {
                Some(ReAdd {
                    mark: KnownFileMark::Failed { download_id, .. },
                    ..
                }) => restart_download(download_id, state),
                Some(readd) => start_download(&readd.result, state, true),
                None => ViewOutcome::Redraw,
            },
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('q') => {
                self.readd = None;
                ViewOutcome::Redraw
            }
            code => {
                if let Some(readd) = self.readd.as_mut() {
                    scroll_key(&mut readd.viewport, code);
                }
                ViewOutcome::Redraw
            }
        }
    }

    pub(super) fn draw_readd(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let Some(readd) = &self.readd else {
            return;
        };
        let width = 56u16.min(area.width);
        let (verb, title) = match readd.mark {
            KnownFileMark::Failed { .. } => (" restart it    ", " Restart download? "),
            _ => (" download again    ", " Download again? "),
        };
        let lines = |width: u16| {
            let text_w = usize::from(width).saturating_sub(2).max(1);
            let text = Style::new().fg(theme.fg);
            let mut lines: Vec<Line<'static>> = wrapped_lines(
                &readd.result.primary_name().to_display_string(),
                text_w,
                text,
            );
            match &readd.mark {
                KnownFileMark::Have { path } => {
                    lines.extend(wrapped_lines("You have this file, at", text_w, text));
                    lines.extend(wrapped_lines(
                        &path.display().to_string(),
                        text_w,
                        Style::new().fg(theme.mark_have),
                    ));
                }
                KnownFileMark::Withheld {
                    path,
                    reason,
                    since,
                } => {
                    lines.extend(wrapped_lines("You share this file, at", text_w, text));
                    lines.extend(wrapped_lines(
                        &path.display().to_string(),
                        text_w,
                        Style::new().fg(theme.mark_withheld),
                    ));
                    lines.extend(wrapped_lines(
                        &format!(
                            "rmule cannot read it now ({}) since {}.",
                            withheld_words(*reason),
                            day(*since)
                        ),
                        text_w,
                        text,
                    ));
                }
                KnownFileMark::Had { name, found_gone } => {
                    lines.extend(wrapped_lines("You had this file, as", text_w, text));
                    lines.extend(wrapped_lines(name, text_w, Style::new().fg(theme.mark_had)));
                    lines.extend(wrapped_lines(
                        &format!("rmule found it gone on {}.", day(*found_gone)),
                        text_w,
                        text,
                    ));
                }
                KnownFileMark::Cancelled => lines.extend(wrapped_lines(
                    "You cancelled a download of this file before.",
                    text_w,
                    Style::new().fg(theme.mark_cancelled),
                )),
                KnownFileMark::Failed { name, reason, .. } => {
                    lines.extend(wrapped_lines(
                        "Your download of this file failed, as",
                        text_w,
                        text,
                    ));
                    lines.extend(wrapped_lines(
                        name,
                        text_w,
                        Style::new().fg(theme.mark_failed),
                    ));
                    let why = match reason {
                        Some(reason) => {
                            format!("It failed because {}.", download_failure_words(reason))
                        }
                        // Only a row failed before the store kept reasons (store
                        // version 6) has none.
                        None => format!("Why was {}.", crate::state::FAILURE_NOT_RECORDED),
                    };
                    lines.extend(wrapped_lines(&why, text_w, text));
                    lines.extend(wrapped_lines(
                        "Restarting continues from the parts on disk that still check, or starts over when nothing there can be continued from.",
                        text_w,
                        text,
                    ));
                }
                // Refused before a confirm opens.
                KnownFileMark::Downloading { .. } => {}
            }
            lines.push(Line::raw(""));
            let key = Style::new().fg(theme.accent).add_modifier(Modifier::BOLD);
            lines.push(Line::from(vec![
                Span::styled("y", key),
                Span::styled(verb, text),
                Span::styled("Esc", key),
                Span::styled(" keep", text),
            ]));

            lines
        };
        Modal::new(title, theme).draw_scrolled(frame, area, width, theme, &readd.viewport, lines);
    }
}

/// `StartDownload` for `result`: core places it in its download directory.
/// A re-add (`again`) takes a free name beside a copy already there, so the
/// file on disk is never the one written over. The source hint is
/// [`UiState::active_server`] (live connection first), none at all for a
/// Kad-only operator: core finds the sources over Kad and asks any server
/// session that comes up later.
fn start_download(result: &SearchResult, state: &UiState, again: bool) -> ViewOutcome {
    if state.session.is_none() {
        return ViewOutcome::Emit(Action::Flash(crate::words::app::CORE_NOT_ATTACHED));
    }
    let file = result.to_file_link();
    ViewOutcome::Emit(Action::Command(CoreCommand::Download(
        DownloadCommand::StartDownload {
            name: SafeFileName::of_link(&file),
            file,
            source_hint: state.active_server(),
            if_taken: if again {
                NameTaken::Number
            } else {
                NameTaken::Refuse
            },
        },
    )))
}

/// `ResumeDownload` for a failed download — the one Restart (ADR-0094,
/// "Restart"): the same row, which core continues from what is on disk
/// or starts over in its place; the store would refuse a new one for the file.
fn restart_download(download_id: DownloadId, state: &UiState) -> ViewOutcome {
    if state.session.is_none() {
        return ViewOutcome::Emit(Action::Flash(crate::words::app::CORE_NOT_ATTACHED));
    }
    ViewOutcome::Emit(Action::Command(CoreCommand::Download(
        DownloadCommand::ResumeDownload { download_id },
    )))
}

#[cfg(test)]
mod tests;
