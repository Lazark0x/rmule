//! The Transfers tab's Add-link form (`L`): a pasted `ed2k://|file|…|/` link
//! becomes a download.
//!
//! The link is read by `Ed2kLink::read`, the reader `rmule-cli add` uses, and
//! started by the `StartDownload` the Search tab's Download sends — so the
//! TUI and the CLI accept, skip and refuse exactly the same links. What the
//! form refuses stays on screen under the field with the typing kept; the
//! fields a link carried that no client reads are said in the status feed
//! once the download is asked for.

use std::cell::Cell;

use ratatui::Frame;
use ratatui::crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use rmule_core::{CoreCommand, DownloadCommand, NameTaken};
use rmule_primitives::{Ed2kFileLink, Ed2kLink, PrimitiveError, SafeFileName};

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
}

impl AddLink {
    fn new() -> Self {
        Self {
            form: Form::new(vec![
                Field::text("Link", "").with_placeholder("ed2k://|file|name|size|hash|/"),
            ]),
            viewport: Cell::default(),
        }
    }
}

/// The download a pasted link asks for, or why it cannot be asked.
fn read_link(text: &str) -> Result<(Ed2kFileLink, Vec<String>), LinkRefusal> {
    let text = text.trim();
    if text.is_empty() {
        return Err(LinkRefusal::Empty);
    }
    let read = Ed2kLink::read(text).map_err(|error| refusal_of(&error))?;
    match read.link {
        Ed2kLink::File(file) => Ok((file, read.skipped_fields)),
        Ed2kLink::Server(_) | Ed2kLink::ServerList(_) => Err(LinkRefusal::NotAFileLink),
    }
}

/// The refusal code a reader error is: the classes an operator can act on
/// apart, everything else one "not readable".
fn refusal_of(error: &PrimitiveError) -> LinkRefusal {
    match error {
        PrimitiveError::InvalidHashLength { .. }
        | PrimitiveError::InvalidHashEncoding { .. }
        | PrimitiveError::InvalidPartHashSetCount { .. } => LinkRefusal::BadHash,
        PrimitiveError::FileTooLarge { .. } | PrimitiveError::FileSizeAboveLimit { .. } => {
            LinkRefusal::TooLarge
        }
        PrimitiveError::FileSizeZero => LinkRefusal::ZeroSize,
        PrimitiveError::DuplicateLinkField { field } => {
            LinkRefusal::DuplicateField((*field).to_string())
        }
        _ => LinkRefusal::Unreadable,
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
    if state.session.is_none() {
        return Ok(ViewOutcome::Emit(Action::Flash(
            crate::words::app::CORE_NOT_ATTACHED,
        )));
    }
    let command = Action::Command(CoreCommand::Download(DownloadCommand::StartDownload {
        name: SafeFileName::of_link(&file),
        file,
        source_hint: state.active_server(),
        if_taken: NameTaken::Refuse,
    }));
    Ok(ViewOutcome::Emit(
        match words::link_fields_skipped(skipped) {
            Some(note) => Action::Actions(vec![command, Action::Note(note)]),
            None => command,
        },
    ))
}

impl TransfersView {
    /// `L`: open the Add-link form.
    pub(super) fn open_add_link(&mut self) -> ViewOutcome {
        self.add_link = Some(AddLink::new());
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
                self.add_link = None;
                ViewOutcome::Redraw
            }
            FormKey::Commit => {
                let outcome = read_link(entry.form.text(0))
                    .and_then(|(file, skipped)| start(file, &skipped, state));
                match outcome {
                    Ok(outcome) => {
                        self.add_link = None;
                        outcome
                    }
                    Err(refusal) => {
                        entry.form.error = Some(words::link_refused(&refusal).to_string());
                        ViewOutcome::Redraw
                    }
                }
            }
            FormKey::Consumed | FormKey::Ignored => ViewOutcome::Redraw,
        }
    }

    /// The form over the view: the field, the last refusal, the key legend.
    pub(super) fn draw_add_link(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let Some(entry) = self.add_link.as_ref() else {
            return;
        };
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
        );
    }
}

#[cfg(test)]
mod tests;
