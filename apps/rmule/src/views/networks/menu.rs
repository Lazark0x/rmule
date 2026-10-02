//! The server row-action menu and the remove confirm.
//!
//! An item is either enabled or greyed *with its reason* — the menu never
//! hides an action the operator might look for, and never offers one that
//! would be rejected. Every action emits a `CoreCommand` and waits for the
//! level to move.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};

use rmule_core::{CoreCommand, ServerListCommand};
use rmule_primitives::ServerEndpoint;

use super::NetworksView;
use super::form::{FORM_W, NO_CREDENTIALS, ServerForm};
use super::servers::{next_priority, priority_word, row_name};
use crate::action::Action;
use crate::state::{UiState, server_label};
use crate::theme::Theme;
use crate::views::modal::Modal;
use crate::views::{ViewOutcome, connect_action};
use crate::wrap::{clamp_u16, labeled_lines, wrap_text, wrapped_lines};

/// A row-menu entry. `disabled` carries the greyed reason tag (
/// visible deferral, never silent absence); `None` means enabled.
pub(super) struct MenuItem {
    pub(super) label: String,
    pub(super) action: MenuAction,
    pub(super) disabled: Option<String>,
}

impl MenuItem {
    fn enabled(label: impl Into<String>, action: MenuAction) -> Self {
        Self {
            label: label.into(),
            action,
            disabled: None,
        }
    }

    /// An item whose action exists but cannot run right now, tagged with why.
    fn greyed(label: impl Into<String>, action: MenuAction, reason: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            action,
            disabled: Some(reason.into()),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum MenuAction {
    Connect,
    /// Ends the session and the intent to stay connected; offered in
    /// Connect's place on the row the intent stands on.
    Disconnect,
    CopyLink,
    Remove,
    ToggleStatic,
    /// Priority is a **cycling** item rather than a submenu: the house modal
    /// machine is one level deep, and a three-valued enum reads better as
    /// "Normal → High" on one line than as a nested menu of three.
    CyclePriority,
    AddServer,
    UpdateFromUrl,
}

/// The centered row-action menu (spec §3.4 / §4). The last two items are
/// *list* actions rather than row actions — aMule's server context menu mixes
/// them the same way — and carry their global key in the label.
pub(super) struct Menu {
    pub(super) items: Vec<MenuItem>,
    pub(super) sel: usize,
}

impl Menu {
    /// Move the selection to the next/previous *enabled* item, wrapping —
    /// greyed items are skipped, never landed on.
    fn step(&mut self, forward: bool) {
        let n = self.items.len();
        for k in 1..=n {
            let idx = if forward {
                (self.sel + k) % n
            } else {
                (self.sel + n - k) % n
            };
            if self.items[idx].disabled.is_none() {
                self.sel = idx;
                return;
            }
        }
    }
}

/// The Remove-server confirm modal (one of the spec's exactly-three
/// destructive confirms, §4). Names the server and the consequence.
pub(super) struct Confirm {
    name: String,
    server: ServerEndpoint,
}

pub(super) fn draw_menu(frame: &mut Frame, area: Rect, menu: &Menu, theme: &Theme) {
    // Greedy width: every item whole when the frame allows, wrapped under its
    // own indent when it does not.
    let natural = menu
        .items
        .iter()
        .map(|item| {
            1 + item.label.chars().count()
                + item
                    .disabled
                    .as_ref()
                    .map_or(0, |reason| reason.chars().count() + 1)
        })
        .max()
        .unwrap_or(0)
        + 2;
    let width = clamp_u16(natural.max(48)).min(area.width);
    let inner_w = usize::from(width).saturating_sub(2).max(1);

    let lines: Vec<Line> = menu
        .items
        .iter()
        .enumerate()
        .flat_map(|(i, item)| match item.disabled.as_deref() {
            None => {
                let style = if i == menu.sel {
                    Style::new().fg(theme.bg).bg(theme.accent)
                } else {
                    Style::new().fg(theme.fg)
                };
                // Full-width selection bar: pad each wrapped line out.
                wrap_text(&format!(" {}", item.label), inner_w)
                    .into_iter()
                    .map(|part| Line::styled(format!("{part:<inner_w$}"), style))
                    .collect::<Vec<_>>()
            }
            Some(reason) => labeled_lines(
                Span::styled(format!(" {} ", item.label), theme.dim_text()),
                reason,
                theme.dim_text(),
                inner_w
                    .saturating_sub(item.label.chars().count() + 2)
                    .max(1),
            ),
        })
        .collect();

    Modal::new(" Server actions ", theme).draw(frame, area, width, theme, lines);
}

pub(super) fn draw_confirm(frame: &mut Frame, area: Rect, confirm: &Confirm, theme: &Theme) {
    let width = FORM_W.min(area.width);
    let text_w = usize::from(width).saturating_sub(2).max(1);
    // Both prose lines wrap: a long server name grows the modal.
    let mut lines = wrapped_lines(
        &format!(
            "Remove '{}' ({})?",
            confirm.name,
            server_label(&confirm.server)
        ),
        text_w,
        Style::new().fg(theme.fg),
    );
    // aMule's own posture, which core implements: the list entry goes, the
    // session does not (ADR-0080).
    lines.extend(wrapped_lines(
        "The list entry goes; a session connected to it stays up.",
        text_w,
        theme.dim_text(),
    ));
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("y", Style::new().fg(theme.accent)),
        Span::styled(" confirm    ", Style::new().fg(theme.fg)),
        Span::styled("Esc", Style::new().fg(theme.accent)),
        Span::styled(" abort", Style::new().fg(theme.fg)),
    ]));

    Modal::new(" Remove server ", theme)
        .danger(theme)
        .at_least(6)
        .draw(frame, area, width, theme, lines);
}

impl NetworksView {
    /// Build the row menu against the selected row's actual facts, so every
    /// label states what activating it will do and every greyed item states
    /// why it will not.
    pub(super) fn open_menu(&mut self, state: &UiState) -> ViewOutcome {
        let update = if state.server_list_updating {
            MenuItem::greyed(
                "Update list from URL… (U)",
                MenuAction::UpdateFromUrl,
                "(update in flight)",
            )
        } else {
            MenuItem::enabled("Update list from URL… (U)", MenuAction::UpdateFromUrl)
        };
        let list_items = [
            MenuItem::enabled("Add server… (a)", MenuAction::AddServer),
            update,
        ];

        let Some(row) = self.selected(state) else {
            // No row: only the list-level actions are meaningful, and the row
            // actions say so instead of vanishing.
            let mut items = vec![
                MenuItem::greyed("Connect (c)", MenuAction::Connect, "(no server selected)"),
                MenuItem::greyed(
                    "Copy server link",
                    MenuAction::CopyLink,
                    "(no server selected)",
                ),
            ];
            items.extend(list_items);
            let sel = items
                .iter()
                .position(|item| item.disabled.is_none())
                .unwrap_or(0);
            self.menu = Some(Menu { items, sel });
            return ViewOutcome::Redraw;
        };

        // The row the operator's intent stands on offers Disconnect where the
        // others offer Connect: one place, the action that can act.
        let connect = if crate::views::is_remaking(state, &row.server.endpoint) {
            MenuItem::enabled("Stop reconnecting (c)", MenuAction::Disconnect)
        } else if crate::views::is_ours(state, &row.server.endpoint) {
            MenuItem::enabled("Disconnect (c)", MenuAction::Disconnect)
        } else if state.session.is_none() {
            MenuItem::greyed("Connect (c)", MenuAction::Connect, NO_CREDENTIALS)
        } else {
            MenuItem::enabled("Connect (c)", MenuAction::Connect)
        };
        let static_label = if row.server.is_static {
            "Unpin (currently static)"
        } else {
            "Pin as static"
        };
        let next = next_priority(row.server.priority);
        let priority_label = format!(
            "Priority: {} → {}",
            priority_word(row.server.priority),
            priority_word(next)
        );

        let mut items = vec![
            connect,
            MenuItem::enabled("Copy server link", MenuAction::CopyLink),
            MenuItem::enabled("Remove…", MenuAction::Remove),
            MenuItem::enabled(static_label, MenuAction::ToggleStatic),
            MenuItem::enabled(priority_label, MenuAction::CyclePriority),
        ];
        items.extend(list_items);
        let sel = items
            .iter()
            .position(|item| item.disabled.is_none())
            .unwrap_or(0);
        self.menu = Some(Menu { items, sel });
        ViewOutcome::Redraw
    }

    pub(super) fn handle_menu_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome {
        match key.code {
            KeyCode::Esc => {
                self.menu = None;
                ViewOutcome::Redraw
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if let Some(menu) = self.menu.as_mut() {
                    menu.step(true);
                }
                ViewOutcome::Redraw
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if let Some(menu) = self.menu.as_mut() {
                    menu.step(false);
                }
                ViewOutcome::Redraw
            }
            KeyCode::Enter => self.activate_menu(state),
            // The menu swallows everything else — it is modal.
            _ => ViewOutcome::Redraw,
        }
    }

    fn activate_menu(&mut self, state: &UiState) -> ViewOutcome {
        let Some(menu) = self.menu.as_ref() else {
            return ViewOutcome::Ignored;
        };
        if menu.items[menu.sel].disabled.is_some() {
            return ViewOutcome::Redraw; // `step` never rests here; belt and braces.
        }
        let action = menu.items[menu.sel].action; // Copy; releases the borrow.
        self.menu = None;
        match action {
            MenuAction::AddServer => {
                self.form = Some(ServerForm::add_server());
                return ViewOutcome::Redraw;
            }
            MenuAction::UpdateFromUrl => return self.open_update_form(state),
            _ => {}
        }
        let Some(row) = self.selected(state) else {
            return ViewOutcome::Redraw;
        };
        let server = row.server.endpoint.clone();
        match action {
            MenuAction::Connect => ViewOutcome::Emit(connect_action(state, server)),
            MenuAction::Disconnect => {
                ViewOutcome::Emit(Action::Command(CoreCommand::DisconnectFromServer))
            }
            MenuAction::CopyLink => ViewOutcome::Emit(Action::CopyLink(format!(
                "ed2k://|server|{}|{}|/",
                server.host(),
                server.port()
            ))),
            MenuAction::Remove => {
                self.confirm = Some(Confirm {
                    name: row_name(row),
                    server,
                });
                ViewOutcome::Redraw
            }
            MenuAction::ToggleStatic => ViewOutcome::Emit(Action::Command(
                CoreCommand::ServerList(ServerListCommand::SetServerStatic {
                    server,
                    is_static: !row.server.is_static,
                }),
            )),
            MenuAction::CyclePriority => ViewOutcome::Emit(Action::Command(
                CoreCommand::ServerList(ServerListCommand::SetServerPriority {
                    server,
                    priority: next_priority(row.server.priority),
                }),
            )),
            // Handled above, before the row lookup.
            MenuAction::AddServer | MenuAction::UpdateFromUrl => ViewOutcome::Redraw,
        }
    }

    pub(super) fn handle_confirm_key(&mut self, key: KeyEvent) -> ViewOutcome {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                let Some(confirm) = self.confirm.take() else {
                    return ViewOutcome::Redraw;
                };
                // The row goes when the level says it went — nothing is
                // removed locally and reconciled afterwards.
                ViewOutcome::Emit(Action::Command(CoreCommand::ServerList(
                    ServerListCommand::RemoveServer {
                        server: confirm.server,
                    },
                )))
            }
            KeyCode::Esc | KeyCode::Char('n') => {
                self.confirm = None;
                ViewOutcome::Redraw
            }
            _ => ViewOutcome::Redraw,
        }
    }
}

#[cfg(test)]
mod tests;
