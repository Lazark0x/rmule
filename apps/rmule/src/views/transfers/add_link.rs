//! The Transfers tab's Add-link form (`L`): a pasted `ed2k://|file|…|/` link
//! becomes a download.
//!
//! The link is read by `Ed2kLink::read`, the reader `rmule-cli add` uses, and
//! started by the `StartDownload` the Search tab's Download sends — so the
//! TUI and the CLI accept, skip and refuse exactly the same links. What the
//! form refuses stays on screen under the field with the typing kept; a link
//! refused for want of a download dir also outlives the form, since setting
//! one means leaving it, and `L` brings it back. The fields a link carried
//! that no client reads are said in the status feed once the download is asked
//! for.

use std::cell::Cell;
use std::collections::VecDeque;

use ratatui::Frame;
use ratatui::crossterm::event::KeyEvent;
use ratatui::layout::{Position, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use rmule_core::{CoreCommand, DownloadCommand, NameTaken};
use rmule_primitives::{Ed2kFileLink, Ed2kLink, SafeFileName};

use super::TransfersView;
use crate::action::Action;
use crate::form::{Field, Form, FormKey};
use crate::row_selection::viewport::Viewport;
use crate::state::{KnownFileMark, KnownFileMarks, UiState};
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::views::modal::{Modal, release_form, scroll_form};
use crate::words::download::{self as words, LinkRefusal};
use crate::wrap::clamp_u16;

/// Floor width of the form; a long pasted link wraps inside it.
const FORM_W: u16 = 64;

/// The form's one field and its last refusal.
pub(super) struct AddLink {
    form: Form,
    /// What part of the form is on screen, in a frame too short for it.
    viewport: Cell<Viewport>,
    /// Links of a paste refused and waiting their turn in the field.
    refused: VecDeque<(String, LinkRefusal)>,
    /// The refusal in force names no fault of the link: it needs a download
    /// dir, which is set elsewhere.
    waits_for_dir: bool,
}

impl AddLink {
    fn new() -> Self {
        Self {
            form: Form::new(vec![
                Field::text("Link", "").with_placeholder("ed2k://|file|name|size|hash|/"),
            ]),
            viewport: Cell::default(),
            refused: VecDeque::new(),
            waits_for_dir: false,
        }
    }

    /// Say why the field's link was refused.
    fn refuse(&mut self, refusal: &LinkRefusal) {
        self.waits_for_dir = matches!(refusal, LinkRefusal::NoDownloadDir);
        self.form.error = Some(words::link_refused(refusal));
    }

    /// Put the next refused link in the field with its refusal. Whether there
    /// was one.
    fn next_refused(&mut self) -> bool {
        let Some((line, refusal)) = self.refused.pop_front() else {
            return false;
        };
        self.form.set_focused_text(&line);
        self.refuse(&refusal);
        true
    }
}

/// The download a pasted link asks for, or why it cannot be asked.
fn read_link(text: &str) -> Result<(Ed2kFileLink, Vec<String>), LinkRefusal> {
    let text = text.trim();
    if text.is_empty() {
        return Err(LinkRefusal::Empty);
    }
    let read = Ed2kLink::read(text).map_err(|error| LinkRefusal::of(&error))?;
    match read.link {
        Ed2kLink::File(file) => Ok((file, read.skipped_fields)),
        Ed2kLink::Server(_) | Ed2kLink::ServerList(_) => Err(LinkRefusal::NotAFileLink),
    }
}

/// Whether the link carries a source a running download could take.
fn names_sources(file: &Ed2kFileLink) -> bool {
    !file.sources.peers().is_empty() || !file.ipv6_sources.is_empty()
}

/// The actions a read link asks for: the `StartDownload`, and the note
/// naming any field it skipped. For a file already in Transfers the same
/// command carries the link's sources to the running download (ADR-0089),
/// so a link that names none is refused here.
fn start(
    file: Ed2kFileLink,
    skipped: &[String],
    state: &UiState,
) -> Result<ViewOutcome, LinkRefusal> {
    if let Some(KnownFileMark::Downloading { name }) =
        KnownFileMarks::of(state).get(file.file_hash, file.size)
        && !names_sources(&file)
    {
        return Err(LinkRefusal::AlreadyDownloading { name: name.clone() });
    }
    if state.session.download_dir.is_none() {
        return Err(LinkRefusal::NoDownloadDir);
    }
    let command = Action::Command(CoreCommand::Download(DownloadCommand::StartDownload {
        name: SafeFileName::of_link(&file),
        file,
        source_hint: state.active_server(),
        if_taken: NameTaken::Refuse,
        kad_aich_root: None,
    }));
    Ok(ViewOutcome::Emit(
        match words::link_fields_skipped(skipped) {
            Some(note) => Action::Actions(vec![command, Action::Note(note)]),
            None => command,
        },
    ))
}

impl TransfersView {
    /// A paste into the form: one link goes in the field. Several, one a line,
    /// are each asked for at once, as Enter on each would; those refused come
    /// up in the field in turn with their refusals, so none is lost.
    pub(crate) fn handle_paste(&mut self, text: &str, state: &UiState) -> ViewOutcome {
        let Some(entry) = self.add_link.as_mut() else {
            return ViewOutcome::Ignored;
        };
        release_form(&mut entry.viewport);
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        if lines.len() < 2 {
            entry.form.paste(text);
            return ViewOutcome::Redraw;
        }
        let mut asked = Vec::new();
        for line in lines {
            match read_link(line).and_then(|(file, skipped)| start(file, &skipped, state)) {
                Ok(ViewOutcome::Emit(action)) => asked.push(action),
                Ok(_) => {}
                Err(refusal) => entry.refused.push_back((line.to_string(), refusal)),
            }
        }
        if !entry.next_refused() {
            self.add_link = None;
        }
        ViewOutcome::Emit(Action::Actions(asked))
    }

    /// `L`: open the Add-link form, or the one that waited for a download
    /// dir, its refusal gone once there is one.
    pub(super) fn open_add_link(&mut self, state: &UiState) -> ViewOutcome {
        let mut entry = self.parked_link.take().unwrap_or_else(AddLink::new);
        if state.session.download_dir.is_some() && entry.waits_for_dir {
            entry.waits_for_dir = false;
            entry.form.error = None;
        }
        self.add_link = Some(entry);
        ViewOutcome::Redraw
    }

    /// Every key while the form is up: it is modal, so nothing reaches the
    /// table or the globals underneath — `q` in a pasted name is text.
    pub(super) fn handle_add_link_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome {
        let Some(entry) = self.add_link.as_mut() else {
            return ViewOutcome::Ignored;
        };
        if scroll_form(&mut entry.viewport, key.code) {
            return ViewOutcome::Redraw;
        }
        release_form(&mut entry.viewport);
        match entry.form.handle_key(key) {
            FormKey::Cancel => {
                let left = self.add_link.take();
                self.parked_link = left.filter(|entry| entry.waits_for_dir);
                ViewOutcome::Redraw
            }
            FormKey::Commit => {
                let outcome = read_link(entry.form.text(0))
                    .and_then(|(file, skipped)| start(file, &skipped, state));
                match outcome {
                    Ok(outcome) => {
                        if !entry.next_refused() {
                            self.add_link = None;
                        }
                        outcome
                    }
                    Err(refusal) => {
                        entry.refuse(&refusal);
                        ViewOutcome::Redraw
                    }
                }
            }
            FormKey::Consumed | FormKey::Ignored => ViewOutcome::Redraw,
        }
    }

    /// The form over the view: the field, the last refusal, the key legend.
    /// Returns where its caret is.
    pub(super) fn draw_add_link(
        &self,
        frame: &mut Frame,
        area: Rect,
        theme: &Theme,
    ) -> Option<Position> {
        let entry = self.add_link.as_ref()?;
        let width = clamp_u16(entry.form.natural_width() + 2)
            .max(FORM_W)
            .min(area.width);
        Modal::new(" Add eD2k link ", theme).draw_form(
            frame,
            area,
            width,
            theme,
            &entry.viewport,
            |width| {
                let inner_w = usize::from(width).saturating_sub(2).max(1);
                let legend = Line::from(vec![
                    Span::styled(" Enter", Style::new().fg(theme.accent)),
                    Span::styled(" add    ", Style::new().fg(theme.fg)),
                    Span::styled("Esc", Style::new().fg(theme.accent)),
                    Span::styled(" cancel", Style::new().fg(theme.fg)),
                ]);
                entry.form.render_modal(inner_w, theme, vec![legend])
            },
        )
    }
}

#[cfg(test)]
mod tests;
