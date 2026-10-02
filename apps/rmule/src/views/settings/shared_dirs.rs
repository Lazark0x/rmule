//! Settings' "Shared directories" section (ADR-0101, "Shared Directories"):
//! the list — the download directory first, marked — each entry with its
//! state and what lies under it, and a row to add one. `Enter` on the add row
//! opens it for a path, and `Enter` again sends it: core counts what the
//! directory would offer and asks, and the question is asked here. `x` on a
//! listed directory asks, naming the count, before it stops sharing it.

use std::path::PathBuf;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use rmule_core::{CoreCommand, DirectoryRefusal, DirectoryRole, ScanCommand};

use super::{Row, SettingsView};
use crate::action::Action;
use crate::form::Field;
use crate::state::UiState;
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::views::modal::Modal;
use crate::words::scan::{refusal, remove_confirm, role_words, state_words, under_words};
use crate::wrap::{clamp_u16, wrapped_lines};

/// The section's heading.
const SECTION: &str = "Shared directories";

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
                Field::item("Shared", entry.dir.display().to_string()).with_note(note),
                Slot::Dir {
                    dir: entry.dir.clone(),
                    role: entry.role,
                },
            )
        })
        .collect();
    rows.push((
        Field::text("Share a dir", String::new())
            .with_placeholder("Enter, type an absolute path, Enter"),
        Slot::AddDir,
    ));
    if let Some((field, _)) = rows.first_mut() {
        field.section = Some(SECTION);
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
    pub(super) fn send_add(&mut self) -> ViewOutcome {
        match directory_to_add(self.form.text(self.form.focus)) {
            Ok(path) => {
                self.editing = false;
                self.form.error = None;
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

    /// `x` on a listed directory: the remove confirm, or why it cannot be
    /// removed.
    pub(super) fn ask_remove(&mut self) -> ViewOutcome {
        match self.focused_slot() {
            Some(Slot::Dir {
                role: DirectoryRole::DownloadDirectory,
                ..
            }) => {
                self.form.error = Some(refusal(&DirectoryRefusal::DownloadDirectory));
                ViewOutcome::Redraw
            }
            Some(Slot::Dir {
                dir,
                role: DirectoryRole::Added,
            }) => {
                self.removing = Some(dir.clone());
                ViewOutcome::Redraw
            }
            _ => ViewOutcome::Ignored,
        }
    }

    /// The remove confirm takes every key: `y` stops sharing, `n` or `Esc`
    /// keeps it.
    pub(super) fn remove_key(&mut self, key: KeyEvent) -> ViewOutcome {
        match key.code {
            KeyCode::Char('y') => {
                let Some(path) = self.removing.take() else {
                    return ViewOutcome::Redraw;
                };
                ViewOutcome::Emit(Action::Command(CoreCommand::Scan(
                    ScanCommand::RemoveSharedDirectory { path },
                )))
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.removing = None;
                ViewOutcome::Redraw
            }
            KeyCode::Char('q') | KeyCode::Char('j' | 'k' | 'g' | 'G' | 'x') => ViewOutcome::Redraw,
            _ => ViewOutcome::Ignored,
        }
    }
}

/// The typed path, if it can be sent: core does every other check.
fn directory_to_add(text: &str) -> Result<PathBuf, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err(crate::words::scan::ADD_EMPTY.to_string());
    }
    let path = PathBuf::from(text);
    if !path.is_absolute() {
        return Err(crate::words::scan::ADD_RELATIVE.to_string());
    }
    Ok(path)
}

/// The remove confirm, naming what leaves the offer.
pub(super) fn draw_remove(
    frame: &mut Frame,
    area: Rect,
    dir: &std::path::Path,
    state: &UiState,
    theme: &Theme,
) {
    let (question, consequence) = remove_confirm(dir, state.shared_under(dir));
    let width = clamp_u16(64).min(area.width);
    let text_w = usize::from(width).saturating_sub(4).max(1);
    let mut lines = wrapped_lines(&question, text_w, Style::new().fg(theme.fg));
    lines.push(Line::from(""));
    lines.extend(wrapped_lines(&consequence, text_w, theme.dim_text()));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("y", Style::new().fg(theme.bad).add_modifier(Modifier::BOLD)),
        Span::styled(" stop sharing    ", Style::new().fg(theme.fg)),
        Span::styled("n", Style::new().fg(theme.accent)),
        Span::styled(" keep it", Style::new().fg(theme.fg)),
    ]));
    Modal::new(crate::words::scan::REMOVE_TITLE, theme)
        .danger(theme)
        .padded()
        .draw(frame, area, width, theme, lines);
}

#[cfg(test)]
mod tests;
