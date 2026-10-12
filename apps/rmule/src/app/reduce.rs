//! The action reducer: the one place a bus action becomes a state change, a
//! command to core, or a flow decision.
//!
//! Pure apart from the command queue it appends to — the app loop drains that
//! separately — so the whole reduction tests without a terminal or a live
//! core.

use crate::words::{Sentence, app as app_words};
use std::time::Instant;

use ratatui::crossterm::event::Event;

use super::{App, Flow};
use crate::action::Action;
use crate::input;
use crate::views::ViewOutcome;

impl App {
    /// Route one action into the right state owner. Public shape kept
    /// test-driving-friendly: pure apart from what the action itself does.
    pub(super) fn reduce(&mut self, action: Action, now: Instant) -> Flow {
        match action {
            Action::Input(event) => {
                let mapped = match event {
                    Event::Key(key) => {
                        // View-first routing (views/mod.rs contract): the
                        // active view sees keys before the globals — that is
                        // what lets a focused query input treat `h`/`q` as
                        // text. The help overlay preempts everything.
                        if self.chrome.help_open {
                            input::map_key(&self.chrome, key)
                        } else {
                            match self.views.handle_key(self.chrome.active, key, &self.state) {
                                ViewOutcome::Redraw => {
                                    self.dirty = true;
                                    None
                                }
                                ViewOutcome::Emit(action) => return self.reduce(action, now),
                                ViewOutcome::Ignored => input::map_key(&self.chrome, key),
                            }
                        }
                    }
                    Event::Mouse(mouse) => {
                        // Wheel scrolls the focused table (ADR-0072, Row Selection) by
                        // synthesizing the arrow the view already handles —
                        // one scroll path, no per-view mouse geometry.
                        use ratatui::crossterm::event::{
                            KeyCode, KeyEvent, KeyModifiers, MouseEventKind,
                        };
                        let synthesized = match mouse.kind {
                            MouseEventKind::ScrollUp => Some(KeyCode::Up),
                            MouseEventKind::ScrollDown => Some(KeyCode::Down),
                            _ => None,
                        };
                        if let Some(code) = synthesized {
                            if !self.chrome.help_open {
                                let key = KeyEvent::new(code, KeyModifiers::NONE);
                                match self.views.handle_key(self.chrome.active, key, &self.state) {
                                    ViewOutcome::Redraw => self.dirty = true,
                                    ViewOutcome::Emit(action) => return self.reduce(action, now),
                                    ViewOutcome::Ignored => {}
                                }
                            }
                            None
                        } else if let MouseEventKind::Down(
                            ratatui::crossterm::event::MouseButton::Left,
                        ) = mouse.kind
                        {
                            // Row 0 is the tab bar (global); anything lower
                            // is the active view's click (row select).
                            if mouse.row == 0 || self.chrome.help_open {
                                input::map_mouse(&self.chrome, mouse)
                            } else {
                                match self.views.handle_click(
                                    self.chrome.active,
                                    mouse.column,
                                    mouse.row,
                                    &self.state,
                                ) {
                                    ViewOutcome::Redraw => self.dirty = true,
                                    ViewOutcome::Emit(action) => return self.reduce(action, now),
                                    ViewOutcome::Ignored => {}
                                }
                                None
                            }
                        } else {
                            input::map_mouse(&self.chrome, mouse)
                        }
                    }
                    Event::Resize(_, _) => {
                        self.dirty = true;
                        None
                    }
                    _ => None,
                };
                match mapped {
                    Some(action) => self.reduce(action, now),
                    None => Flow::Continue,
                }
            }
            Action::Quit => Flow::Quit,
            Action::StartKad => {
                self.kad_first_login_owed = false;
                match self.kad_start.as_ref().map(|start| start.send(())) {
                    Some(Ok(())) => Flow::Continue,
                    Some(Err(_)) => {
                        self.tell_kad_join_ended(now);
                        Flow::Continue
                    }
                    None => self.reduce(Action::Flash(app_words::CORE_NOT_ATTACHED), now),
                }
            }
            Action::SearchRelated(query) => self.search_related(query, now),
            Action::Command(command) => {
                if matches!(command, rmule_core::CoreCommand::DisableKad) {
                    // The operator stopped Kad: a later first login must not
                    // start it again behind their back.
                    self.kad_first_login_owed = false;
                }
                if self.client.is_some() {
                    // Queued for the run loop's async flush; outcomes come
                    // back as core events on the bus.
                    self.pending_commands.push(command);
                    Flow::Continue
                } else {
                    // UI-only run: the only honest outcome is saying so.
                    self.reduce(Action::Flash(app_words::CORE_NOT_ATTACHED), now)
                }
            }
            Action::Commands(commands) => {
                let mut flow = Flow::Continue;
                for command in commands {
                    flow = self.reduce(Action::Command(command), now);
                }
                flow
            }
            Action::Actions(actions) => {
                let mut flow = Flow::Continue;
                for action in actions {
                    flow = self.reduce(action, now);
                    if matches!(flow, Flow::Quit) {
                        break;
                    }
                }
                flow
            }
            Action::CopyLink(link) => {
                self.pending_copy = Some(link);
                self.reduce(Action::Flash(app_words::LINK_COPIED), now)
            }
            Action::Preference(edit) => match self.write_preference(edit) {
                Some(flash) => self.reduce(Action::Flash(flash), now),
                None => Flow::Continue,
            },
            Action::ConfirmDownloadDir(dir) => {
                let edit = crate::config::PrefEdit::DownloadDir(dir.clone());
                if let Some(Err(refusal)) = self.config.as_ref().map(|config| config.check(&edit)) {
                    rmule_core::run_log::write(&refusal.record(), self.run_log.get());
                    return self.reduce(
                        Action::Flash(crate::words::store::setting_refused(&refusal)),
                        now,
                    );
                }
                self.views.settings.warn_share(dir);
                self.dirty = true;
                Flow::Continue
            }
            Action::Core(_)
            | Action::Snapshot(_)
            | Action::CoreClosed
            | Action::Note(_)
            | Action::ForgetSearch(_) => {
                // Sequencing, not state: the Kad join rides the run's
                // first eD2k *login* — not startup, not a dial that may still
                // fail, and not the `c` key. Owed once: a reconnect, a server
                // switch or a second login finds it spent, so nothing
                // re-fetches — and neither does a login after the operator's
                // own `K` started or stopped Kad.
                let kad_join_ended = matches!(
                    &action,
                    Action::Core(rmule_core::CoreEvent::ServerConnection(
                        rmule_core::ServerConnectionEvent::Connected { .. },
                    ))
                ) && std::mem::take(&mut self.kad_first_login_owed)
                    && self
                        .kad_start
                        .as_ref()
                        .is_some_and(|start| start.send(()).is_err());
                // The server a connect at start dials is the one the operator
                // last reached (ADR-0095); written quietly, it is not an edit.
                let reached = match &action {
                    Action::Core(rmule_core::CoreEvent::ServerConnection(
                        rmule_core::ServerConnectionEvent::Connected { server, .. },
                    )) if self.config.is_some()
                        && self.state.preferences.last_server.as_ref() != Some(server) =>
                    {
                        Some(server.clone())
                    }
                    _ => None,
                };
                // The File History follows its edges (ADR-0100): an ask goes
                // out only with a core there to answer it.
                if let Action::Core(event) = &action
                    && self.client.is_some()
                    && let Some(ask) = self.history.on_event(event)
                {
                    self.pending_commands.push(ask);
                }
                // Quit's own progress: the step the core
                // is running is the status bar's receipt, as a flash.
                // A restart of a failed download that fails again leaves its
                // row as it was, so the status bar says so at once.
                if let Action::Core(rmule_core::CoreEvent::Download(event)) = &action
                    && let Some(text) = crate::state::restart_failed_again(&self.state, event)
                {
                    self.dirty |= self.chrome.update(&Action::Flash(text), now);
                }
                if let Action::Core(rmule_core::CoreEvent::Quitting { step }) = &action {
                    let flash = Action::Flash(app_words::quit_step(*step));
                    self.dirty |= self.chrome.update(&flash, now);
                    return Flow::Continue;
                }
                self.dirty |= self.state.apply(action, now);
                // After the fold, so a refusal outlasts the connection's own
                // note in the status bar.
                if kad_join_ended {
                    self.tell_kad_join_ended(now);
                }
                if let Some(server) = reached {
                    self.remember_server(server, now);
                }
                Flow::Continue
            }
            chrome_action @ (Action::SwitchView(_)
            | Action::CycleView(_)
            | Action::ToggleHelp
            | Action::DismissOverlay
            | Action::ScrollHelp(_)
            | Action::Flash(_)) => {
                self.dirty |= self.chrome.update(&chrome_action, now);
                Flow::Continue
            }
        }
    }

    /// Say why a start of Kad reached nothing: the join it is sent to has
    /// ended, so no press or login can start Kad until the next run. Told
    /// once, however many starts follow.
    fn tell_kad_join_ended(&mut self, now: Instant) {
        if !std::mem::replace(&mut self.kad_join_ended_told, true) {
            self.dirty |= self
                .state
                .apply(Action::Note(crate::words::kad::JOIN_ENDED), now);
        }
    }

    /// Record the server just reached as the one a connect at start dials.
    /// The write is not an edit, so it says nothing when it lands; when the
    /// store refuses it the operator is told once, since the next start will
    /// dial the server before it.
    fn remember_server(&mut self, server: rmule_primitives::ServerEndpoint, now: Instant) {
        let edit = crate::config::PrefEdit::LastServer(server);
        let Some(config) = &self.config else {
            return;
        };
        if let Err(error) = config.commit(&edit) {
            tracing::warn!(%error, "the last connected server could not be saved");
            if !std::mem::replace(&mut self.last_server_unsaved_told, true) {
                self.dirty |= self.state.apply(
                    Action::Note(crate::words::store::LAST_SERVER_NOT_SAVED),
                    now,
                );
            }
            return;
        }
        self.state.preferences.apply(&edit);
    }

    /// Persist one Settings edit, apply what this app keeps itself, and
    /// return the status-bar receipt — or nothing for a table's sort, whose
    /// receipt is the header arrow already drawn.
    ///
    /// A core key goes through Core Settings, which takes it up in the running
    /// core when it is live and says when it takes effect; the receipt reads
    /// that answer. The write is synchronous on purpose: it is one small store
    /// transaction (a device flush, single-digit milliseconds — ADR-0083), so
    /// there is nothing to queue and nothing to await. A failure is reported
    /// where the operator is looking: why Core Settings refused the value, or
    /// that the store refused the write, never a swallowed one.
    fn write_preference(&mut self, edit: crate::config::PrefEdit) -> Option<Sentence> {
        let sort = matches!(edit, crate::config::PrefEdit::TableSort { .. });
        let effect = match &self.config {
            // A UI-only run keeps nothing across runs; the sort is still the
            // view's for this one, so it is not worth a flash per keypress.
            None if sort => rmule_core::TakesEffect::Now,
            None => return Some(crate::words::store::NO_CONFIG_STORE),
            Some(config) => match config.commit(&edit) {
                Ok(effect) => effect,
                Err(rmule_core::SettingError::Refused(refusal)) => {
                    rmule_core::run_log::write(&refusal.record(), self.run_log.get());
                    return Some(crate::words::store::setting_refused(&refusal));
                }
                Err(error) => {
                    tracing::warn!(%error, "a setting could not be saved");
                    return Some(crate::words::store::NOT_SAVED);
                }
            },
        };
        self.state.preferences.apply(&edit);
        // What this app keeps itself: the palette, the Run Log's level, and
        // the directory its next download is written to.
        match &edit {
            crate::config::PrefEdit::Theme(choice) => {
                self.theme = choice.resolve(self.auto_theme);
            }
            crate::config::PrefEdit::RunLogFull(on) => {
                self.run_log.set(rmule_core::run_log::Level::from_full(*on));
            }
            crate::config::PrefEdit::DownloadDir(dir) => {
                if let Some(session) = &mut self.state.session {
                    session.download_dir = Some(dir.clone());
                }
            }
            _ => {}
        }
        self.dirty = true;
        (!sort).then(|| app_words::receipt(&edit, effect))
    }
}

#[cfg(test)]
mod tests;
