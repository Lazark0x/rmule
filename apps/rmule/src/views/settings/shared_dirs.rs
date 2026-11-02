//! Settings' "Shared directories" section (ADR-0101, "Shared Directories"):
//! the list — the download directory first, marked — each entry with its
//! state and what lies under it, and a row to add one. `Enter` on the add row
//! opens it for a path, and `Enter` again sends it: core counts what the
//! directory would offer and asks, and the question is asked here. `x` on a
//! listed directory asks, naming the count, before it stops sharing it.

use std::cell::Cell;
use std::path::PathBuf;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use rmule_core::{CoreCommand, DirectoryRefusal, DirectoryRole, ScanCommand};

use super::{Row, SettingsView};
use crate::action::Action;
use crate::form::Field;
use crate::row_selection::viewport::Viewport;
use crate::state::UiState;
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::views::modal::{Question, confirm_key, draw_question, scroll_key};
use crate::words::Sentence;
use crate::words::app::{self as words, AddDirectoryRefusal};
use crate::words::scan::{remove_confirm, role_words, state_words, under_words};
use crate::words::settings;

/// What a form row stands for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Slot {
    /// A preference row.
    Row(Row),
    /// A listed directory.
    Dir {
        /// The directory, as the list names it.
        dir: PathBuf,
        /// What kind of entry it is.
        role: DirectoryRole,
    },
    /// The row a new directory is typed into.
    AddDir,
}

/// The section's rows: every listed directory, then the add row.
pub(super) fn fields(state: &UiState) -> Vec<(Field, Slot)> {
    let mut rows: Vec<(Field, Slot)> = state
        .diagnostics
        .shared_directories
        .iter()
        .map(|entry| {
            let mut note = String::new();
            if let Some(role) = role_words(entry.role) {
                note.push_str(role);
                note.push_str(" · ");
            }
            note.push_str(&state_words(&entry.state));
            note.push_str(" · ");
            note.push_str(&under_words(state.shared_under(&entry.dir)));
            (
                Field::item(settings::SHARED, entry.dir.display().to_string()).with_note(note),
                Slot::Dir {
                    dir: entry.dir.clone(),
                    role: entry.role,
                },
            )
        })
        .collect();
    rows.push((
        Field::directory(settings::SHARE_A_DIR, String::new())
            .with_placeholder(settings::SHARE_A_DIR_HINT),
        Slot::AddDir,
    ));
    if let Some((field, _)) = rows.first_mut() {
        field.section = Some(settings::SHARED_DIRECTORIES);
    }
    rows
}

impl SettingsView {
    /// The slot under the cursor.
    pub(super) fn focused_slot(&self) -> Option<&Slot> {
        self.slots.get(self.form.focus)
    }

    /// The add row's commit: the typed path, sent for core to guard, count
    /// and ask about.
    pub(super) fn send_add(&mut self, state: &UiState) -> ViewOutcome {
        match directory_to_add(self.form.text(self.form.focus)) {
            Ok(path) => {
                self.editing = false;
                self.form.error = None;
                self.sent_dir = Some((path.clone(), state.directory_refusal.0));
                ViewOutcome::Emit(Action::Command(CoreCommand::Scan(
                    ScanCommand::AddSharedDirectory { path },
                )))
            }
            Err(reason) => {
                self.form.error = Some(reason);
                ViewOutcome::Redraw
            }
        }
    }

    /// Core refused the directory sent: the add row opens again with the
    /// path in it and the reason under it, wherever the cursor went.
    pub(super) fn reopen_refused_add(&mut self, state: &UiState) {
        let Some((sent, before)) = &self.sent_dir else {
            return;
        };
        let (count, Some((dir, reason))) = &state.directory_refusal else {
            return;
        };
        if count == before || dir != sent {
            return;
        }
        let text = sent.display().to_string();
        self.sent_dir = None;
        if let Some(row) = self.slots.iter().position(|slot| *slot == Slot::AddDir) {
            self.form.focus = row;
            self.form.set_focused_text(&text);
            self.form.error = Some(words::shared_directory_refusal(reason));
            self.editing = true;
        }
    }

    /// `x` on a listed directory: the remove confirm, or why it cannot be
    /// removed.
    pub(super) fn ask_remove(&mut self) -> ViewOutcome {
        match self.focused_slot() {
            Some(Slot::Dir {
                role: DirectoryRole::DownloadDirectory,
                ..
            }) => {
                self.form.error = Some(words::shared_directory_refusal(
                    &DirectoryRefusal::DownloadDirectory,
                ));
                ViewOutcome::Redraw
            }
            Some(Slot::Dir {
                dir,
                role: DirectoryRole::Added,
            }) => {
                self.removing = Some(dir.clone());
                self.modal_viewport.take();
                ViewOutcome::Redraw
            }
            _ => ViewOutcome::Ignored,
        }
    }

    /// The remove confirm takes every key: `y` stops sharing, `n` or `Esc`
    /// keeps it.
    pub(super) fn remove_key(&mut self, key: KeyEvent) -> ViewOutcome {
        match (confirm_key(key.code), key.code) {
            (Some(true), _) => {
                let Some(path) = self.removing.take() else {
                    return ViewOutcome::Redraw;
                };
                ViewOutcome::Emit(Action::Command(CoreCommand::Scan(
                    ScanCommand::RemoveSharedDirectory { path },
                )))
            }
            (Some(false), _) => {
                self.removing = None;
                ViewOutcome::Redraw
            }
            (None, code @ (KeyCode::Char('j' | 'k' | 'g' | 'G') | KeyCode::Up | KeyCode::Down)) => {
                scroll_key(&mut self.modal_viewport, code);
                ViewOutcome::Redraw
            }
            (None, KeyCode::Char('x')) => ViewOutcome::Redraw,
            (None, _) => ViewOutcome::Ignored,
        }
    }
}

/// The typed path, if it can be sent: core does every other check.
fn directory_to_add(text: &str) -> Result<PathBuf, Sentence> {
    let text = text.trim();
    if text.is_empty() {
        return Err(words::add_directory_refusal(AddDirectoryRefusal::Empty));
    }
    let path = crate::config::expand_home(text);
    if !path.is_absolute() {
        return Err(words::add_directory_refusal(AddDirectoryRefusal::Relative));
    }
    if !path.is_dir() {
        return Err(words::add_directory_refusal(AddDirectoryRefusal::Missing));
    }
    Ok(path)
}

/// The remove confirm, naming what leaves the offer.
pub(super) fn draw_remove(
    frame: &mut Frame,
    area: Rect,
    (dir, viewport): (&std::path::Path, &Cell<Viewport>),
    state: &UiState,
    theme: &Theme,
) {
    let (asks, does) = remove_confirm(dir, state.shared_under(dir));
    let question = Question {
        title: crate::words::scan::REMOVE_TITLE,
        asks: &asks,
        does: &does,
    };
    draw_question(frame, area, &question, theme, viewport);
}

#[cfg(test)]
mod tests;
