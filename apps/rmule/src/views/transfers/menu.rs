//! The row-action menu: which actions a download in a given status offers,
//! and which are greyed with a reason.
//!
//! `Pause`/`Resume`/`Cancel…` emit real download commands. *Search related*
//! asks the connected server about the download's file, dimmed with its reason while it cannot.
//! *Preview* hands the download's file to the operator's player once it is
//! Preview Ready (ADR-0114), dimmed with the first reason it is not.

use ratatui::Frame;
use ratatui::crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use rmule_core::{CoreCommand, DownloadCommand, DownloadId};

use super::link::{copy_link_for, copy_link_reason};
use super::confirm::download_name;
use super::{Overlay, TransfersView};
use crate::action::Action;
use crate::state::{DownloadStatus, UiState};
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::views::menu::{self, Asked, Item};
use crate::words::labels;

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
    /// Every download on show: pause what runs, or resume what rests.
    PauseAll,
    /// A greyed, deferred item: rendered with a reason tag, never actioned
    /// (spec §6 fence). The menu cursor never rests on one.
    Inert,
}

pub(super) type MenuItem = Item<MenuAction>;

/// The row menu (spec §3.2 plus the degrade set). Order is stable, *Search
/// related* directly under *Copy eD2k link* as in every row menu.
pub(super) fn menu_items(status: DownloadStatus, id: DownloadId, state: &UiState) -> Vec<MenuItem> {
    let row = state.downloads.get(&id);
    // A failed download holds its place with no run (ADR-0094, "Failed"):
    // what it offers is one Restart, and core picks whether that continues
    // from what is on disk or starts over (ADR-0094, labels::RESTART).
    // A completed download has no run to pause and nothing to cancel: what
    // it offers is to leave the list (ADR-0094, "Clearing a completed download").
    let first = match status {
        DownloadStatus::Paused => Item::new(labels::RESUME, MenuAction::Resume).keyed('p'),
        DownloadStatus::Failed => Item::new(labels::RESTART, MenuAction::Restart).keyed('p'),
        DownloadStatus::Completed => Item::new(labels::CLEAR_FROM_LIST, MenuAction::Clear),
        _ => Item::new(labels::PAUSE, MenuAction::Pause).keyed('p'),
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
    let or_inert = |action, reason: Option<&'static str>| {
        if reason.is_none() {
            action
        } else {
            MenuAction::Inert
        }
    };
    vec![
        first,
        Item::new(labels::CANCEL, or_inert(MenuAction::Cancel, cancel_reason))
            .keyed('x')
            .greyed(cancel_reason),
        Item::new(labels::SHOW_DETAILS, MenuAction::Details).keyed('d'),
        Item::new(labels::PREVIEW, or_inert(MenuAction::Preview, preview_reason))
            .keyed('v')
            .greyed(preview_reason),
        Item::new(labels::COPY_LINK, or_inert(MenuAction::CopyLink, copy_reason))
            .greyed(copy_reason),
        Item::new(
            labels::SEARCH_RELATED,
            or_inert(MenuAction::SearchRelated, related_reason),
        )
        .greyed(related_reason),
        Item::new(labels::PAUSE_ALL, MenuAction::PauseAll).keyed('P'),
    ]
}

/// What the menu offers over tagged rows: only what acts on all of them.
pub(super) fn tagged_items(targets: &[DownloadId], state: &UiState) -> Vec<MenuItem> {
    let any = |wanted: fn(DownloadStatus) -> bool| {
        targets
            .iter()
            .filter_map(|id| state.downloads.get(id))
            .any(|row| wanted(row.status))
    };
    let pausable = any(can_pause);
    let resumable = any(can_resume);
    vec![
        Item::new(labels::PAUSE, MenuAction::Pause)
            .keyed('p')
            .greyed((!pausable).then_some(labels::NONE_RUNNING)),
        Item::new(labels::RESUME, MenuAction::Resume)
            .greyed((!resumable).then_some(labels::NONE_RESTING)),
        Item::new(labels::CANCEL, MenuAction::Cancel)
            .keyed('x')
            .greyed(
                cancellable(targets.to_vec(), state)
                    .is_empty()
                    .then_some("completed: the file is kept and shared"),
            ),
    ]
}

const fn can_pause(status: DownloadStatus) -> bool {
    !matches!(
        status,
        DownloadStatus::Paused | DownloadStatus::Failed | DownloadStatus::Completed
    )
}

const fn can_resume(status: DownloadStatus) -> bool {
    matches!(status, DownloadStatus::Paused | DownloadStatus::Failed)
}

/// `targets` a cancel can take: a completed download has nothing to delete.
pub(super) fn cancellable(targets: Vec<DownloadId>, state: &UiState) -> Vec<DownloadId> {
    targets
        .into_iter()
        .filter(|id| {
            state
                .downloads
                .get(id)
                .is_some_and(|row| row.status != DownloadStatus::Completed)
        })
        .collect()
}

/// Pause what of `targets` is running, or, with none running, resume what
/// rests. One press, one meaning for the whole set.
pub(super) fn pause_or_resume(targets: &[DownloadId], state: &UiState) -> Action {
    let of = |wanted: fn(DownloadStatus) -> bool| {
        targets
            .iter()
            .copied()
            .filter(|id| {
                state
                    .downloads
                    .get(id)
                    .is_some_and(|row| wanted(row.status))
            })
            .collect::<Vec<_>>()
    };
    let running = of(can_pause);
    if running.is_empty() {
        resume_all(&of(can_resume))
    } else {
        pause_all(&running)
    }
}

fn pause_all(ids: &[DownloadId]) -> Action {
    Action::Commands(
        ids.iter()
            .map(|id| {
                CoreCommand::Download(DownloadCommand::PauseDownload { download_id: *id })
            })
            .collect(),
    )
}

fn resume_all(ids: &[DownloadId]) -> Action {
    Action::Commands(
        ids.iter()
            .map(|id| {
                CoreCommand::Download(DownloadCommand::ResumeDownload { download_id: *id })
            })
            .collect(),
    )
}

/// The place of the action the cursor names, `None` once the row's status no
/// longer offers it.
pub(super) fn menu_index(items: &[MenuItem], cursor: MenuAction) -> Option<usize> {
    items.iter().position(|item| item.action == cursor)
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

/// Pause, or the resume of a paused download, or the restart of a failed one.
pub(super) fn pause_toggle_action(status: DownloadStatus, id: DownloadId) -> Action {
    if status == DownloadStatus::Completed {
        return Action::Flash(crate::words::download::NOTHING_TO_PAUSE);
    }
    if matches!(status, DownloadStatus::Paused | DownloadStatus::Failed) {
        Action::Command(CoreCommand::Download(DownloadCommand::ResumeDownload {
            download_id: id,
        }))
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
        let items = self.items_now(id, status, state, ids);
        let Some(at) = menu_index(&items, cursor) else {
            self.overlay = Overlay::None;
            return ViewOutcome::Redraw;
        };
        let asked = menu::key(&items, at, key.code);
        self.answer_menu(asked, &items, (id, status), state, ids)
    }

    /// The menu the row and the tags ask for now.
    pub(super) fn items_now(
        &mut self,
        id: DownloadId,
        status: DownloadStatus,
        state: &UiState,
        ids: &[DownloadId],
    ) -> Vec<MenuItem> {
        let targets = self.targets(state, ids);
        if self.tags.is_empty() {
            menu_items(status, id, state)
        } else {
            tagged_items(&targets, state)
        }
    }

    /// A click on the open menu: an item runs, outside closes.
    pub(super) fn click_menu(
        &mut self,
        (column, row): (u16, u16),
        state: &UiState,
        ids: &[DownloadId],
    ) -> ViewOutcome {
        let Some((id, status)) = self.selected_row_status(state, ids) else {
            self.overlay = Overlay::None;
            return ViewOutcome::Redraw;
        };
        let items = self.items_now(id, status, state, ids);
        let asked = self.menu_place.click(&items, column, row);
        self.answer_menu(asked, &items, (id, status), state, ids)
    }

    fn answer_menu(
        &mut self,
        asked: Asked,
        items: &[MenuItem],
        row: (DownloadId, DownloadStatus),
        state: &UiState,
        ids: &[DownloadId],
    ) -> ViewOutcome {
        match asked {
            Asked::Close => self.overlay = Overlay::None,
            Asked::Move(index) => {
                self.overlay = Overlay::Menu {
                    cursor: items[index].action,
                };
            }
            Asked::Nothing => {}
            Asked::Run(index) => return self.run_menu(items[index].action, row, state, ids),
        }
        ViewOutcome::Redraw
    }

    fn run_menu(
        &mut self,
        action: MenuAction,
        (id, status): (DownloadId, DownloadStatus),
        state: &UiState,
        ids: &[DownloadId],
    ) -> ViewOutcome {
        if !self.tags.is_empty() {
            return self.run_tagged(action, state, ids);
        }
        match action {
            MenuAction::Pause | MenuAction::Resume | MenuAction::Restart => {
                self.overlay = Overlay::None;
                ViewOutcome::Emit(pause_toggle_action(status, id))
            }
            MenuAction::PauseAll => {
                self.overlay = Overlay::None;
                ViewOutcome::Emit(pause_or_resume(ids, state))
            }
            MenuAction::Clear => {
                self.overlay = Overlay::None;
                ViewOutcome::Emit(Action::Command(CoreCommand::Download(
                    DownloadCommand::ClearDownload { download_id: id },
                )))
            }
            MenuAction::Cancel => {
                self.ask_cancel(vec![id]);
                ViewOutcome::Redraw
            }
            MenuAction::Details => {
                self.overlay = Overlay::Details;
                self.details_viewport.take();
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
        }
    }

    fn run_tagged(
        &mut self,
        action: MenuAction,
        state: &UiState,
        ids: &[DownloadId],
    ) -> ViewOutcome {
        let targets = self.targets(state, ids);
        self.overlay = Overlay::None;
        let of = |wanted: fn(DownloadStatus) -> bool| -> Vec<DownloadId> {
            targets
                .iter()
                .copied()
                .filter(|id| {
                    state
                        .downloads
                        .get(id)
                        .is_some_and(|row| wanted(row.status))
                })
                .collect()
        };
        match action {
            MenuAction::Pause => ViewOutcome::Emit(pause_all(&of(can_pause))),
            MenuAction::Resume => ViewOutcome::Emit(resume_all(&of(can_resume))),
            MenuAction::Cancel => {
                self.ask_cancel(cancellable(targets.clone(), state));
                ViewOutcome::Redraw
            }
            _ => ViewOutcome::Redraw,
        }
    }

    pub(super) fn draw_menu(
        &mut self,
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
        let items = self.items_now(id, status, state, ids);
        let at = menu_index(&items, cursor).unwrap_or(0);
        let name = if self.tags.is_empty() {
            download_name(state, id)
        } else {
            crate::words::app::tagged(self.tags.len())
        };
        menu::draw(frame, area, (&name, &items, at), theme, &self.menu_place);
    }
}

#[cfg(test)]
mod tests;
