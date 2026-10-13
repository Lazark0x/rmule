//! The row-action menu: which actions a download in a given status offers,
//! and which are greyed with a reason.
//!
//! `Pause`/`Resume`/`Cancel…` emit real download commands. `Resume` needs a
//! core, which a UI-only run lacks, so without one it flashes an honest note
//! instead of emitting. *Search related* asks the connected
//! server about the download's file, dimmed with its reason while it cannot.
//! *Preview* hands the download's file to the operator's player once it is
//! Preview Ready (ADR-0114), dimmed with the first reason it is not.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use rmule_core::{CoreCommand, DownloadCommand, DownloadId};

use super::link::{copy_link_for, copy_link_reason};
use super::{Overlay, TransfersView};
use crate::action::Action;
use crate::state::{DownloadStatus, UiState};
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::views::modal::Modal;
use crate::words::units::short_hash_or_dash;
use crate::wrap::{clamp_u16, labeled_lines};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MenuAction {
    Pause,
    Resume,
    /// The one action of a failed download.
    Restart,
    /// Forget a completed download; its file stays shared.
    Clear,
    Cancel,
    Details,
    /// Hand the file to the operator's player (ADR-0114).
    Preview,
    CopyLink,
    SearchRelated,
    /// A greyed, deferred item: rendered with a reason tag, never actioned
    /// (spec §6 fence). The menu cursor never rests on one.
    Inert,
}

pub(super) struct MenuItem {
    pub(super) label: String,
    pub(super) action: MenuAction,
    /// `Some` ⇒ greyed with this reason tag.
    pub(super) reason: Option<&'static str>,
}

/// The row menu (spec §3.2 plus the degrade set). Order is stable, *Search
/// related* directly under *Copy eD2k link* as in every row menu; `menu_step`
/// skips whatever is greyed.
pub(super) fn menu_items(status: DownloadStatus, id: DownloadId, state: &UiState) -> Vec<MenuItem> {
    let row = state.downloads.get(&id);
    // A failed download holds its place with no run (ADR-0094, "Failed"):
    // what it offers is one Restart, and core picks whether that continues
    // from what is on disk or starts over (ADR-0094, "Restart").
    // A completed download has no run to pause and nothing to cancel: what
    // it offers is to leave the list (ADR-0093, "Clearing a completed
    // download").
    let (first, first_action) = match status {
        DownloadStatus::Paused => ("Resume", MenuAction::Resume),
        DownloadStatus::Failed => ("Restart", MenuAction::Restart),
        DownloadStatus::Completed => ("Clear from list", MenuAction::Clear),
        _ => ("Pause", MenuAction::Pause),
    };
    let cancel_reason =
        (status == DownloadStatus::Completed).then_some("completed: the file is kept and shared");
    let copy_reason = copy_link_reason(row);
    let preview_reason = crate::player::preview_target(state, id)
        .err()
        .map(crate::words::player::block_words);
    // The hash is all the wire needs; a row that has not learned it yet has
    // nothing to ask about.
    let related_reason = match row.and_then(|row| row.file_hash) {
        Some(_) => crate::views::related::unavailable(state),
        None => Some("file hash not known yet"),
    };
    let mut items = vec![MenuItem {
        label: first.to_string(),
        action: first_action,
        reason: None,
    }];
    items.extend([
        MenuItem {
            label: "Cancel…".to_string(),
            action: if cancel_reason.is_none() {
                MenuAction::Cancel
            } else {
                MenuAction::Inert
            },
            reason: cancel_reason,
        },
        MenuItem {
            label: "Show file details".to_string(),
            action: MenuAction::Details,
            reason: None,
        },
        MenuItem {
            label: "Preview".to_string(),
            action: if preview_reason.is_none() {
                MenuAction::Preview
            } else {
                MenuAction::Inert
            },
            reason: preview_reason,
        },
        MenuItem {
            label: "Copy eD2k link".to_string(),
            action: if copy_reason.is_none() {
                MenuAction::CopyLink
            } else {
                MenuAction::Inert
            },
            reason: copy_reason,
        },
        MenuItem {
            label: crate::views::related::LABEL.to_string(),
            action: if related_reason.is_none() {
                MenuAction::SearchRelated
            } else {
                MenuAction::Inert
            },
            reason: related_reason,
        },
        MenuItem {
            label: "Priority ▸".to_string(),
            action: MenuAction::Inert,
            reason: Some("needs core priority model"),
        },
        MenuItem {
            label: "Category ▸".to_string(),
            action: MenuAction::Inert,
            reason: Some("needs core categories"),
        },
    ]);
    items
}

/// The place of the action the cursor names, `None` once the row's status no
/// longer offers it.
pub(super) fn menu_index(items: &[MenuItem], cursor: MenuAction) -> Option<usize> {
    items.iter().position(|item| item.action == cursor)
}

/// Move the menu cursor one enabled step, skipping greyed items and clamping
/// at the ends. The cursor names an action, so a status change under an open
/// menu can never hand Enter another action than the one shown.
pub(super) fn menu_step(items: &[MenuItem], cursor: MenuAction, delta: i32) -> MenuAction {
    let Some(start) = menu_index(items, cursor) else {
        return cursor;
    };
    let len = items.len() as i32;
    let mut probe = start as i32;
    loop {
        let candidate = probe + delta;
        if candidate < 0 || candidate >= len {
            return cursor;
        }
        let item = &items[candidate as usize];
        if item.reason.is_none() {
            return item.action;
        }
        probe = candidate;
    }
}

/// The action a fresh menu rests on: the first item, always enabled.
pub(super) fn first_action(status: DownloadStatus) -> MenuAction {
    match status {
        DownloadStatus::Paused => MenuAction::Resume,
        DownloadStatus::Failed => MenuAction::Restart,
        DownloadStatus::Completed => MenuAction::Clear,
        _ => MenuAction::Pause,
    }
}

/// Pause always emits the real command; resume — of a paused download, or
/// the restart of a failed one — needs a core, and a UI-only run flashes the
/// honest reason.
pub(super) fn pause_toggle_action(
    status: DownloadStatus,
    id: DownloadId,
    state: &UiState,
) -> Action {
    if status == DownloadStatus::Completed {
        return Action::Flash(crate::words::download::NOTHING_TO_PAUSE);
    }
    if matches!(status, DownloadStatus::Paused | DownloadStatus::Failed) {
        match &state.session {
            Some(_) => Action::Command(CoreCommand::Download(DownloadCommand::ResumeDownload {
                download_id: id,
            })),
            None => Action::Flash(crate::words::app::CORE_NOT_ATTACHED),
        }
    } else {
        Action::Command(CoreCommand::Download(DownloadCommand::PauseDownload {
            download_id: id,
        }))
    }
}

impl TransfersView {
    pub(super) fn handle_menu(
        &mut self,
        key: KeyEvent,
        state: &UiState,
        ids: &[DownloadId],
        cursor: MenuAction,
    ) -> ViewOutcome {
        let Some((id, status)) = self.selected_row_status(state, ids) else {
            self.overlay = Overlay::None;
            return ViewOutcome::Redraw;
        };
        let items = menu_items(status, id, state);
        if menu_index(&items, cursor).is_none() {
            self.overlay = Overlay::None;
            return ViewOutcome::Redraw;
        }
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.overlay = Overlay::Menu {
                    cursor: menu_step(&items, cursor, 1),
                };
                ViewOutcome::Redraw
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.overlay = Overlay::Menu {
                    cursor: menu_step(&items, cursor, -1),
                };
                ViewOutcome::Redraw
            }
            KeyCode::Enter => match cursor {
                MenuAction::Pause | MenuAction::Resume | MenuAction::Restart => {
                    self.overlay = Overlay::None;
                    ViewOutcome::Emit(pause_toggle_action(status, id, state))
                }
                MenuAction::Clear => {
                    self.overlay = Overlay::None;
                    ViewOutcome::Emit(Action::Command(CoreCommand::Download(
                        DownloadCommand::ClearDownload { download_id: id },
                    )))
                }
                MenuAction::Cancel => {
                    self.overlay = Overlay::ConfirmCancel;
                    ViewOutcome::Redraw
                }
                MenuAction::Details => {
                    self.overlay = Overlay::Details;
                    ViewOutcome::Redraw
                }
                MenuAction::Preview => {
                    self.overlay = Overlay::None;
                    ViewOutcome::Emit(Action::Preview(id))
                }
                MenuAction::CopyLink => {
                    self.overlay = Overlay::None;
                    match copy_link_for(state.downloads.get(&id)) {
                        Some(link) => ViewOutcome::Emit(Action::CopyLink(link)),
                        // The menu already gates on this; a miss here would
                        // mean the row changed shape between draw and Enter —
                        // an honest no-op, not a fabricated link.
                        None => ViewOutcome::Redraw,
                    }
                }
                MenuAction::SearchRelated => {
                    self.overlay = Overlay::None;
                    let row = state.downloads.get(&id);
                    let name = row
                        .and_then(|row| row.metadata.as_ref())
                        .map(|metadata| &metadata.name);
                    match row
                        .and_then(|row| row.file_hash)
                        .and_then(|hash| crate::views::related::action(state, hash, name))
                    {
                        Some(action) => ViewOutcome::Emit(action),
                        None => ViewOutcome::Redraw,
                    }
                }
                MenuAction::Inert => ViewOutcome::Redraw,
            },
            KeyCode::Esc | KeyCode::Char('q') => {
                self.overlay = Overlay::None;
                ViewOutcome::Redraw
            }
            // A modal is exclusive: swallow everything else.
            _ => ViewOutcome::Redraw,
        }
    }

    pub(super) fn draw_menu(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
        ids: &[DownloadId],
        cursor: MenuAction,
    ) {
        let Some((id, status)) = self.selected_row_status(state, ids) else {
            return;
        };
        let items = menu_items(status, id, state);
        let short = short_hash_or_dash(state.downloads.get(&id).and_then(|r| r.file_hash));
        let title = format!(" Actions — {short} ");
        // Greedy modal width: wide enough for every item whole, clamped to the
        // frame; anything still too long wraps under its marker.
        let natural = items
            .iter()
            .map(|item| {
                2 + item.label.chars().count() + item.reason.map_or(0, |r| r.chars().count() + 2)
            })
            .chain(std::iter::once(title.chars().count()))
            .max()
            .unwrap_or(0)
            + 2;
        let width = clamp_u16(natural.max(52)).min(area.width);
        let at = items
            .iter()
            .position(|item| item.action == cursor)
            .unwrap_or(0);
        let rows = |width: u16| -> Vec<Vec<Line<'static>>> {
            let text_w = usize::from(width).saturating_sub(2 + 2).max(1);
            items
                .iter()
                .map(|item| {
                    let marker = if item.action == cursor { "▸ " } else { "  " };
                    let label_style = if item.reason.is_some() {
                        theme.dim_text()
                    } else {
                        Style::new().fg(theme.fg)
                    };
                    let text = match item.reason {
                        Some(reason) => format!("{}  {reason}", item.label),
                        None => item.label.clone(),
                    };
                    labeled_lines(
                        Span::styled(marker.to_string(), Style::new().fg(theme.accent)),
                        &text,
                        label_style,
                        text_w,
                    )
                })
                .collect()
        };
        Modal::new(title, theme).flash_title(theme).draw_list(
            frame,
            area,
            (width, at),
            theme,
            &self.menu_viewport,
            rows,
        );
    }
}

#[cfg(test)]
mod tests;
