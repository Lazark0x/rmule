//! The server row-action menu and the remove confirm.
//!
//! An item is either enabled or greyed *with its reason* — the menu never
//! hides an action the operator might look for, and never offers one that
//! would be rejected. Every action emits a `CoreCommand` and waits for the
//! level to move.

use std::cell::Cell;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::Style;

use rmule_core::diagnostics::ServerDiagnostics;
use rmule_core::{CoreCommand, ServerListCommand};
use rmule_primitives::{Ed2kLink, Ed2kServerLink, ServerEndpoint};

use super::form::ServerForm;
use super::servers::{next_priority, priority_word, row_name};
use super::{NetworksView, servers};
use crate::action::Action;
use crate::row_selection::viewport::Viewport;
use crate::state::{UiState, server_label};
use crate::theme::Theme;
use crate::views::menu::{self, Asked, Item, Place};
use crate::views::modal::{Modal, Question, confirm_key, draw_question, scroll_key};
use crate::views::{ViewOutcome, connect_action};
use crate::words::{labels, networks, rows};
use crate::wrap::wrapped_lines;

/// The details modal's width, room for a sentence on a line or two.
const DETAILS_W: u16 = 64;

/// A row-menu entry.
pub(super) type MenuItem = Item<MenuAction>;

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
    /// What the server grants, its UDP flags, health and shares.
    Details,
    AddServer,
    UpdateFromUrl,
}

/// The row-action menu (spec §3.4 / §4). The last two items are *list*
/// actions rather than row actions, aMule's server context menu mixes them the
/// same way.
pub(super) struct Menu {
    pub(super) items: Vec<MenuItem>,
    pub(super) sel: usize,
    /// What the title names: the server, or the list with no row selected.
    pub(super) name: String,
    /// Where it is, and what part of it is on screen.
    pub(super) place: Place,
}

/// The Remove-server confirm modal (one of the spec's exactly-three
/// destructive confirms, §4). Names the server and the consequence.
pub(super) struct Confirm {
    /// The row by name, with several none.
    name: Option<String>,
    servers: Vec<ServerEndpoint>,
    /// What part of the question is on screen, in a frame too short for it.
    viewport: std::cell::Cell<Viewport>,
}

pub(super) fn draw_menu(frame: &mut Frame, area: Rect, menu: &Menu, theme: &Theme) {
    let shown = (menu.name.as_str(), menu.items.as_slice(), menu.sel);
    menu::draw(frame, area, shown, theme, &menu.place);
}

/// The selected server's details: every sentence the table has no room for,
/// wrapped, scrolled when the frame is too short for them.
pub(super) fn draw_details(
    frame: &mut Frame,
    area: Rect,
    row: &ServerDiagnostics,
    state: &UiState,
    viewport: &Cell<Viewport>,
    theme: &Theme,
) {
    let sentences = super::servers::detail_sentences(row, state);
    let lines = |width: u16| {
        let text_w = usize::from(width).saturating_sub(2).max(1);
        sentences
            .iter()
            .flat_map(|sentence| wrapped_lines(sentence, text_w, Style::new().fg(theme.fg)))
            .collect::<Vec<_>>()
    };
    let title = format!(" {} ", super::servers::row_name(row));
    Modal::new(title, theme).closes().draw_scrolled(
        frame,
        area,
        DETAILS_W.min(area.width),
        theme,
        viewport,
        lines,
    );
}

pub(super) fn draw_confirm(frame: &mut Frame, area: Rect, confirm: &Confirm, theme: &Theme) {
    let asks = match (&confirm.name, confirm.servers.as_slice()) {
        (Some(name), [server]) => rows::remove_one(name, &server_label(server)),
        (_, many) => rows::remove_many(many.len()),
    };
    let question = Question {
        title: labels::REMOVE_TITLE,
        asks: &asks,
        does: rows::REMOVE_DOES,
    };
    draw_question(frame, area, &question, theme, &confirm.viewport);
}

impl NetworksView {
    /// Open the selected server's details; with no row there is nothing to
    /// open.
    pub(super) fn open_details(&mut self, state: &UiState) -> ViewOutcome {
        if self.selected(state).is_none() {
            return ViewOutcome::Ignored;
        }
        self.details = Some(Cell::default());
        ViewOutcome::Redraw
    }

    pub(super) fn handle_details_key(&mut self, key: KeyEvent) -> ViewOutcome {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q' | 'd') => self.details = None,
            code => {
                if let Some(viewport) = self.details.as_mut() {
                    scroll_key(viewport, code);
                }
            }
        }
        ViewOutcome::Redraw
    }

    /// Build the row menu against the selected row's actual facts, so every
    /// label states what activating it will do and every greyed item states
    /// why it will not.
    pub(super) fn open_menu(&mut self, state: &UiState) -> ViewOutcome {
        let update = Item::new(labels::UPDATE_LIST, MenuAction::UpdateFromUrl)
            .keyed('U')
            .greyed(
                state
                    .server_list_updating
                    .then_some(networks::UPDATE_IN_FLIGHT),
            );
        let list_items = [
            Item::new(labels::ADD_SERVER, MenuAction::AddServer).keyed('a'),
            update,
        ];

        let Some(row) = self.selected(state) else {
            // No row: only the list-level actions are meaningful, and the row
            // actions say so instead of vanishing.
            let none = Some(networks::NO_SERVER_SELECTED);
            let mut items = vec![
                Item::new(labels::CONNECT, MenuAction::Connect)
                    .keyed('c')
                    .greyed(none),
                Item::new(labels::COPY_SERVER_LINK, MenuAction::CopyLink).greyed(none),
            ];
            items.extend(list_items);
            self.show_menu(items, labels::SERVER_LIST.to_string());
            return ViewOutcome::Redraw;
        };

        // The row the operator's intent stands on offers Disconnect where the
        // others offer Connect: one place, the action that can act.
        let connect = if crate::views::is_remaking(state, &row.server.endpoint) {
            Item::new(labels::STOP_RECONNECTING, MenuAction::Disconnect)
        } else if crate::views::is_dialling(state, &row.server.endpoint) {
            Item::new(labels::STOP_CONNECTING, MenuAction::Disconnect)
        } else if crate::views::is_ours(state, &row.server.endpoint) {
            Item::new(labels::DISCONNECT, MenuAction::Disconnect)
        } else {
            Item::new(labels::CONNECT, MenuAction::Connect)
        };
        let static_label = if row.server.is_static {
            labels::UNPIN
        } else {
            labels::PIN
        };
        let next = next_priority(row.server.priority);
        let priority_label =
            networks::priority_step(priority_word(row.server.priority), priority_word(next));

        // Tagged rows take the one action that acts on all of them.
        let one = (!self.tags.is_empty()).then_some(rows::ONE_ROW_ONLY);
        let mut items = vec![
            connect.keyed('c').greyed(one),
            Item::new(labels::COPY_SERVER_LINK, MenuAction::CopyLink).greyed(one),
            Item::new(labels::REMOVE, MenuAction::Remove).keyed('x'),
            Item::new(static_label, MenuAction::ToggleStatic).greyed(one),
            Item::new(priority_label, MenuAction::CyclePriority).greyed(one),
            Item::new(labels::DETAILS, MenuAction::Details)
                .keyed('d')
                .greyed(one),
        ];
        items.extend(list_items);
        let name = if self.tags.is_empty() {
            row_name(row)
        } else {
            rows::tagged(self.tags.len())
        };
        self.show_menu(items, name);
        ViewOutcome::Redraw
    }

    fn show_menu(&mut self, items: Vec<MenuItem>, name: String) {
        self.menu = Some(Menu {
            sel: menu::first_enabled(&items),
            items,
            name,
            place: Place::default(),
        });
    }

    pub(super) fn handle_menu_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome {
        let Some(open) = self.menu.as_ref() else {
            return ViewOutcome::Ignored;
        };
        let asked = menu::key(&open.items, open.sel, key.code);
        self.answer_menu(asked, state)
    }

    /// A click on the open menu: an item runs, outside closes.
    pub(super) fn click_menu(&mut self, column: u16, row: u16, state: &UiState) -> ViewOutcome {
        let Some(open) = self.menu.as_ref() else {
            return ViewOutcome::Ignored;
        };
        let asked = open.place.click(&open.items, column, row);
        self.answer_menu(asked, state)
    }

    fn answer_menu(&mut self, asked: Asked, state: &UiState) -> ViewOutcome {
        match asked {
            Asked::Close => self.menu = None,
            Asked::Move(index) => {
                if let Some(open) = self.menu.as_mut() {
                    open.sel = index;
                }
            }
            Asked::Run(index) => {
                if let Some(open) = self.menu.as_mut() {
                    open.sel = index;
                }
                return self.activate_menu(state);
            }
            Asked::Nothing => {}
        }
        ViewOutcome::Redraw
    }

    fn activate_menu(&mut self, state: &UiState) -> ViewOutcome {
        let Some(menu) = self.menu.as_ref() else {
            return ViewOutcome::Ignored;
        };
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
            MenuAction::Connect => ViewOutcome::Emit(connect_action(server)),
            MenuAction::Disconnect => {
                ViewOutcome::Emit(Action::Command(CoreCommand::DisconnectFromServer))
            }
            MenuAction::CopyLink => ViewOutcome::Emit(Action::CopyLink(
                Ed2kLink::Server(Ed2kServerLink {
                    endpoint: server.clone(),
                })
                .to_string(),
            )),
            MenuAction::Remove => self.ask_remove(state),
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
            MenuAction::Details => self.open_details(state),
            // Handled above, before the row lookup.
            MenuAction::AddServer | MenuAction::UpdateFromUrl => ViewOutcome::Redraw,
        }
    }

    /// Ask before removing the selected server; with no row, nothing to ask.
    pub(super) fn ask_remove(&mut self, state: &UiState) -> ViewOutcome {
        self.tags.keep(|tagged| {
            servers(state)
                .iter()
                .any(|row| row.server.endpoint == *tagged)
        });
        let row = self.selected(state);
        let servers = self
            .tags
            .targets(row.map(|row| row.server.endpoint.clone()));
        if servers.is_empty() {
            return ViewOutcome::Ignored;
        }
        self.confirm = Some(Confirm {
            name: row.filter(|_| self.tags.is_empty()).map(row_name),
            servers,
            viewport: Cell::default(),
        });
        ViewOutcome::Redraw
    }

    pub(super) fn handle_confirm_key(&mut self, key: KeyEvent) -> ViewOutcome {
        match confirm_key(key.code) {
            Some(true) => {
                let Some(confirm) = self.confirm.take() else {
                    return ViewOutcome::Redraw;
                };
                self.tags.clear();
                // The row goes when the level says it went — nothing is
                // removed locally and reconciled afterwards.
                ViewOutcome::Emit(Action::Commands(
                    confirm
                        .servers
                        .into_iter()
                        .map(|server| {
                            CoreCommand::ServerList(ServerListCommand::RemoveServer { server })
                        })
                        .collect(),
                ))
            }
            Some(false) => {
                self.confirm = None;
                ViewOutcome::Redraw
            }
            None => {
                if let Some(confirm) = self.confirm.as_mut() {
                    scroll_key(&mut confirm.viewport, key.code);
                }
                ViewOutcome::Redraw
            }
        }
    }
}

#[cfg(test)]
mod tests;
