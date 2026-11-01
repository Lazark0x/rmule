//! Downloading a result, and adding a file the operator already knows
//! (ADR-0100, "Adding a marked file"): a new file starts at once; a file
//! downloading already is refused with where it is; a file they have, once
//! had, or once cancelled, is asked about once — naming the mark, for Have
//! the path, for Had the name it last had and the day it left — and a yes
//! starts it, which turns its mark to Downloading. A file whose download
//! failed is asked about the same way, and a yes restarts that download in
//! place (ADR-0094, "Failed").

use ratatui::Frame;
use ratatui::crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Line;

use rmule_core::{CoreCommand, DownloadCommand, DownloadId, NameTaken};
use rmule_primitives::{SafeFileName, SearchResult};

use super::sort::ResultsTable;
use super::{SearchesView, ViewOutcome};
use crate::action::Action;
use crate::row_selection::viewport::Viewport;
use crate::state::{KnownFileMark, KnownFileMarks, UiState};
use crate::table_sort::SortedTable;
use crate::theme::Theme;
use crate::views::day;
use crate::views::modal::{Modal, confirm_key, scroll_key};
use crate::words::download as download_words;
use crate::words::readd::{self as readd_words, Tone};
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
    /// The tagged results, those the operator holds no history with: a marked
    /// file asks its own question, one row at a time, so it is left and said.
    fn download_tagged(&mut self, state: &UiState) -> ViewOutcome {
        let Some(entry) = self.held.current_mut() else {
            return ViewOutcome::Redraw;
        };
        let tagged = entry.tags.targets(None);
        entry.tags.clear();
        let marks = KnownFileMarks::of(state);
        let results = self
            .held
            .current_pane(state)
            .map_or(&[][..], |pane| pane.results.as_slice());
        let (fresh, marked): (Vec<&SearchResult>, Vec<&SearchResult>) = results
            .iter()
            .filter(|result| tagged.contains(&ResultsTable::identity(result)))
            .partition(|result| marks.get(result.file_hash(), result.file_size()).is_none());
        let commands = fresh
            .into_iter()
            .map(|result| start_command(result, state, false))
            .collect();
        let mut actions = vec![Action::Commands(commands)];
        if !marked.is_empty() {
            actions.push(Action::Flash(crate::words::rows::tagged_marked_left(
                marked.len(),
            )));
        }
        ViewOutcome::Emit(Action::Actions(actions))
    }

    /// The row menu's Download on the tagged results, else the selected one.
    pub(super) fn download_selected(&mut self, state: &UiState) -> ViewOutcome {
        if self
            .held
            .current()
            .is_some_and(|entry| !entry.tags.is_empty())
        {
            return self.download_tagged(state);
        }
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
        match confirm_key(key.code) {
            Some(true) => match self.readd.take() {
                Some(ReAdd {
                    mark: KnownFileMark::Failed { download_id, .. },
                    ..
                }) => restart_download(download_id),
                Some(readd) => start_download(&readd.result, state, true),
                None => ViewOutcome::Redraw,
            },
            Some(false) => {
                self.readd = None;
                ViewOutcome::Redraw
            }
            None => {
                if let Some(readd) = self.readd.as_mut() {
                    scroll_key(&mut readd.viewport, key.code);
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
        let title = match readd.mark {
            KnownFileMark::Failed { .. } => crate::words::search::RESTART_TITLE,
            _ => crate::words::search::AGAIN_TITLE,
        };
        let lines = |width: u16| {
            let text_w = usize::from(width).saturating_sub(2).max(1);
            let text = Style::new().fg(theme.fg);
            let mut lines: Vec<Line<'static>> = wrapped_lines(
                &readd.result.primary_name().to_display_string(),
                text_w,
                text,
            );
            let subject = match &readd.mark {
                KnownFileMark::Have { .. } => theme.mark_have,
                KnownFileMark::Withheld { .. } => theme.mark_withheld,
                KnownFileMark::Had { .. } => theme.mark_had,
                KnownFileMark::Cancelled => theme.mark_cancelled,
                KnownFileMark::Failed { .. } | KnownFileMark::Downloading { .. } => {
                    theme.mark_failed
                }
            };
            for said in readd_words::mark_lines(&readd.mark, day) {
                let style = match said.tone {
                    Tone::Plain => text,
                    Tone::Subject => Style::new().fg(subject),
                };
                lines.extend(wrapped_lines(&said.text, text_w, style));
            }
            lines.push(Line::raw(""));
            lines.push(crate::views::modal::answer_line(theme));
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
    ViewOutcome::Emit(Action::Command(start_command(result, state, again)))
}

fn start_command(result: &SearchResult, state: &UiState, again: bool) -> CoreCommand {
    let file = result.to_file_link();
    CoreCommand::Download(DownloadCommand::StartDownload {
        name: SafeFileName::of_link(&file),
        file,
        source_hint: state.active_server(),
        if_taken: if again {
            NameTaken::Number
        } else {
            NameTaken::Refuse
        },
        kad_aich_root: result.kad_aich_root(),
    })
}

/// `ResumeDownload` for a failed download — the one Restart (ADR-0094,
/// "Restart"): the same row, which core continues from what is on disk
/// or starts over in its place; the store would refuse a new one for the file.
fn restart_download(download_id: DownloadId) -> ViewOutcome {
    ViewOutcome::Emit(Action::Command(CoreCommand::Download(
        DownloadCommand::ResumeDownload { download_id },
    )))
}

#[cfg(test)]
mod tests;
