//! The action reducer: the one place a bus action becomes a state change, a
//! command to core, or a flow decision.
//!
//! Pure apart from the command queue it appends to — the app loop drains that
//! separately — so the whole reduction tests without a terminal or a live
//! core.

use crate::words::severity::Severity;
use crate::words::{Sentence, app as app_words};
use std::time::Instant;

use ratatui::crossterm::event::Event;

use super::{App, Flow, TerminalWork};
use crate::action::Action;
use crate::input;
use crate::views::ViewOutcome;

/// A key press of `code` alone, as the gate and the wheel hand one on.
fn key_of(code: ratatui::crossterm::event::KeyCode) -> ratatui::crossterm::event::KeyEvent {
    ratatui::crossterm::event::KeyEvent::new(code, ratatui::crossterm::event::KeyModifiers::NONE)
}

impl App {
    /// Route one action into the right state owner. Public shape kept
    /// test-driving-friendly: pure apart from what the action itself does.
    pub(super) fn reduce(&mut self, action: Action, now: Instant) -> Flow {
        match action {
            Action::Input(event) => {
                let mapped = match event {
                    Event::Key(key) => {
                        let overlay = self.chrome.help_open || self.chrome.quit_open;
                        let text_open = self.chrome.help_open
                            || (!overlay
                                && self.views.view(self.chrome.active).text_open(&self.state));
                        let key = match input::gate(&key, text_open) {
                            input::KeyGate::Pass => key,
                            input::KeyGate::Page(code) => key_of(code),
                            input::KeyGate::Drop => return Flow::Continue,
                            input::KeyGate::Interrupt => {
                                return self.reduce(Action::AskQuit, now);
                            }
                            input::KeyGate::Suspend => {
                                return self.reduce(Action::Suspend, now);
                            }
                            input::KeyGate::Repaint => {
                                return self.reduce(Action::Repaint, now);
                            }
                        };
                        // Under the too-small screen no view is on show, so no
                        // view hears the key: the way out alone answers.
                        if self.too_small && !self.chrome.quit_open {
                            return match key.code {
                                ratatui::crossterm::event::KeyCode::Char('q') => {
                                    self.reduce(Action::AskQuit, now)
                                }
                                _ => Flow::Continue,
                            };
                        }
                        // View-first routing (views/mod.rs contract): the
                        // active view sees keys before the globals — that is
                        // what lets a focused query input treat `h`/`q` as
                        // text. A chrome modal preempts everything.
                        if overlay {
                            input::map_key(&self.chrome, key)
                        } else {
                            match self
                                .views
                                .view_mut(self.chrome.active)
                                .handle_key(key, &self.state)
                            {
                                ViewOutcome::Redraw => {
                                    self.dirty = true;
                                    None
                                }
                                ViewOutcome::Emit(action) => return self.reduce(action, now),
                                ViewOutcome::Ignored => input::map_key(&self.chrome, key),
                            }
                        }
                    }
                    Event::Mouse(_) if self.too_small => None,
                    Event::Mouse(mouse) => {
                        // The wheel scrolls the pane under the pointer (ADR-0072,
                        // Row Selection): each view reads it as the arrow it
                        // already handles, on that pane.
                        use ratatui::crossterm::event::{KeyCode, MouseEventKind};
                        let synthesized = match mouse.kind {
                            MouseEventKind::ScrollUp => Some(KeyCode::Up),
                            MouseEventKind::ScrollDown => Some(KeyCode::Down),
                            _ => None,
                        };
                        if let Some(code) = synthesized {
                            if self.chrome.help_open {
                                let lines = if code == KeyCode::Up { -1 } else { 1 };
                                return self.reduce(Action::ScrollHelp(lines), now);
                            }
                            if !self.chrome.quit_open {
                                let at = (mouse.column, mouse.row);
                                let key = key_of(code);
                                match self.views.view_mut(self.chrome.active).handle_wheel(
                                    at,
                                    key,
                                    &self.state,
                                ) {
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
                            if mouse.row == 0 || self.chrome.help_open || self.chrome.quit_open {
                                input::map_mouse(&self.chrome, mouse)
                            } else {
                                match self.views.view_mut(self.chrome.active).handle_click(
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
                    Event::Paste(text) => {
                        if self.chrome.help_open || self.chrome.quit_open {
                            return Flow::Continue;
                        }
                        match self
                            .views
                            .view_mut(self.chrome.active)
                            .handle_paste(&text, &self.state)
                        {
                            ViewOutcome::Redraw => self.dirty = true,
                            ViewOutcome::Emit(action) => return self.reduce(action, now),
                            ViewOutcome::Ignored => {}
                        }
                        None
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
            Action::Repaint => {
                self.pending_terminal = Some(TerminalWork::Repaint);
                self.dirty = true;
                Flow::Continue
            }
            Action::Suspend => {
                self.pending_terminal = Some(TerminalWork::Suspend);
                Flow::Continue
            }
            Action::Continued => {
                self.pending_terminal = Some(TerminalWork::Reenter);
                self.dirty = true;
                self.reduce(
                    Action::Note(Severity::Info, crate::words::app::CONTINUED),
                    now,
                )
            }
            // A second ask while the confirm is up is its answer: Ctrl-C
            // twice leaves, whatever is running.
            Action::AskQuit if self.chrome.quit_open || self.state.quit_cost().is_idle() => {
                Flow::Quit
            }
            Action::StartKad => {
                self.kad_first_login_owed = false;
                match self.kad_start.as_ref().map(|start| start.send(())) {
                    Some(Ok(())) => Flow::Continue,
                    Some(Err(_)) => {
                        self.tell_kad_join_ended(now);
                        Flow::Continue
                    }
                    None => Flow::Continue,
                }
            }
            Action::Preview(download_id) => self.preview(download_id, now),
            Action::SearchRelated(query) => self.search_related(query, now),
            Action::Command(command) => {
                if matches!(command, rmule_core::CoreCommand::DisableKad) {
                    // The operator stopped Kad: a later first login must not
                    // start it again behind their back.
                    self.kad_first_login_owed = false;
                }
                // Queued for the run loop's async flush; outcomes come back
                // as core events on the bus.
                self.pending_commands.push(command);
                Flow::Continue
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
                let note = app_words::link_sent(&link);
                self.pending_copy = Some(link);
                self.dirty |= self.state.apply(Action::Note(Severity::Info, note), now);
                self.reduce(Action::Flash(app_words::LINK_SENT), now)
            }
            Action::Preference(edit) => match self.write_preference(edit) {
                Ok(Some(flash)) | Err(flash) => self.reduce(Action::Flash(flash), now),
                Ok(None) => Flow::Continue,
            },
            Action::SettingsEdit(edit) => match self.write_preference(edit) {
                Ok(receipt) => {
                    self.views.settings.saved();
                    self.dirty = true;
                    match receipt {
                        Some(flash) => self.reduce(Action::Flash(flash), now),
                        None => Flow::Continue,
                    }
                }
                Err(why) => {
                    self.views.settings.refused(why);
                    self.dirty = true;
                    Flow::Continue
                }
            },
            Action::ConfirmDownloadDir(dir) => {
                let edit = crate::config::PrefEdit::download_dir(dir.clone());
                match self.config.as_ref().map(|config| config.check(&edit)) {
                    Some(Err(rmule_core::SettingError::Refused(refusal))) => {
                        rmule_core::run_log::write(&refusal.record(), self.run_log.get());
                        self.views
                            .settings
                            .refused(crate::words::store::setting_refused(&refusal));
                        self.dirty = true;
                        return Flow::Continue;
                    }
                    Some(Err(error)) => {
                        tracing::warn!(%error, "a setting could not be checked");
                        self.views.settings.refused(crate::words::store::NOT_SAVED);
                        self.dirty = true;
                        return Flow::Continue;
                    }
                    Some(Ok(())) | None => {}
                }
                self.views.settings.warn_share(dir);
                self.dirty = true;
                Flow::Continue
            }
            Action::Core(_)
            | Action::Snapshot(_)
            | Action::CoreClosed
            | Action::Note(..)
            | Action::ForgetSearch(_)
            | Action::RestoreSearch(_) => {
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
                // The one edge the opt-in bell rings for: a restored completed
                // row comes back as a recovery and stays silent.
                if self
                    .state
                    .preferences
                    .flags
                    .is_on(crate::config::AppFlag::CompletionBell)
                    && matches!(
                        &action,
                        Action::Core(rmule_core::CoreEvent::Download(
                            rmule_core::DownloadEvent::DownloadCompleted { .. }
                        ))
                    )
                {
                    self.pending_bell = true;
                }
                if let Action::Core(rmule_core::CoreEvent::Quitting { step }) = &action {
                    let flash = Action::Flash(app_words::quit_step(*step));
                    self.dirty |= self.chrome.update(&flash, now);
                    return Flow::Continue;
                }
                let closed_a_search = matches!(action, Action::ForgetSearch(_));
                // Reader Mode: the data tick's levels wait for news or a key.
                let held = self
                    .state
                    .preferences
                    .flags
                    .is_on(crate::config::AppFlag::ReaderMode)
                    && matches!(action, Action::Snapshot(_));
                self.dirty |= self.state.apply(action, now) && !held;
                if closed_a_search {
                    return self.reduce(Action::Flash(crate::words::search::CLOSED), now);
                }
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
            chrome_action @ (Action::AskQuit
            | Action::SwitchView(_)
            | Action::CycleView(_)
            | Action::ToggleHelp
            | Action::HelpKey(_)
            | Action::DismissOverlay
            | Action::ScrollHelp(_)
            | Action::Flash(_)) => {
                let from = self.chrome.active;
                self.dirty |= self.chrome.update(&chrome_action, now);
                if let Action::Flash(text) = &chrome_action {
                    self.state.log_flash(text.clone(), now);
                }
                // `h` / `l` pass through a tab: only the tab's own digit or
                // click means the operator came to use it.
                if matches!(chrome_action, Action::SwitchView(_))
                    && self.chrome.active == crate::view::ViewId::Searches
                    && from != self.chrome.active
                {
                    self.views.searches.arrive(&self.state);
                }
                if self.chrome.active != from {
                    self.remember_tab(now);
                }
                Flow::Continue
            }
        }
    }

    /// Say why a start of Kad reached nothing: the join it is sent to has
    /// ended, so no press or login can start Kad until the next run. Told
    /// once, however many starts follow.
    fn tell_kad_join_ended(&mut self, now: Instant) {
        if !std::mem::replace(&mut self.kad_join_ended_told, true) {
            self.dirty |= self.state.apply(
                Action::Note(Severity::Warning, crate::words::kad::JOIN_ENDED),
                now,
            );
        }
    }

    /// Record the server just reached as the one a connect at start dials.
    /// When the store refuses it the operator is told once, since the next
    /// start will dial the server before it.
    fn remember_server(&mut self, server: rmule_primitives::ServerEndpoint, now: Instant) {
        let edit = crate::config::PrefEdit::LastServer(server);
        if !self.remember(&edit) && !std::mem::replace(&mut self.last_server_unsaved_told, true) {
            self.dirty |= self.state.apply(
                Action::Note(
                    Severity::Warning,
                    crate::words::store::LAST_SERVER_NOT_SAVED,
                ),
                now,
            );
        }
    }

    /// Record the tab now up as the one the next run opens on, told once when
    /// the store refuses it.
    fn remember_tab(&mut self, now: Instant) {
        let edit = crate::config::PrefEdit::LastTab(self.chrome.active);
        if !self.remember(&edit) && !std::mem::replace(&mut self.last_tab_unsaved_told, true) {
            self.dirty |= self.state.apply(
                Action::Note(Severity::Warning, crate::words::store::LAST_TAB_NOT_SAVED),
                now,
            );
        }
    }

    /// Write what the app keeps for itself. It is not an edit, so it says
    /// nothing when it lands; false when the store refused it.
    fn remember(&mut self, edit: &crate::config::PrefEdit) -> bool {
        let Some(config) = &self.config else {
            return true;
        };
        if let Err(error) = config.commit(edit) {
            tracing::warn!(%error, "a remembered value could not be saved");
            return false;
        }
        self.state.preferences.apply(edit);
        true
    }

    /// Persist one Settings edit, apply what this app keeps itself, and
    /// return the status-bar receipt — nothing for a table's sort, whose
    /// receipt is the header arrow already drawn — or why it was not saved.
    ///
    /// A core key goes through Core Settings, which takes it up in the running
    /// core when it is live and says when it takes effect; the receipt reads
    /// that answer. The write is synchronous on purpose: it is one small store
    /// transaction (a device flush, single-digit milliseconds — ADR-0083), so
    /// there is nothing to queue and nothing to await. A failure is said
    /// to the caller, which reports it where the operator is looking: why Core
    /// Settings refused the value, or that the store refused the write, never
    /// a swallowed one.
    fn write_preference(
        &mut self,
        edit: crate::config::PrefEdit,
    ) -> Result<Option<Sentence>, Sentence> {
        let sort = matches!(edit, crate::config::PrefEdit::TableSort { .. });
        let effect = match &self.config {
            None => rmule_core::TakesEffect::Now,
            Some(config) => match config.commit(&edit) {
                Ok(effect) => effect,
                Err(rmule_core::SettingError::Refused(refusal)) => {
                    rmule_core::run_log::write(&refusal.record(), self.run_log.get());
                    return Err(crate::words::store::setting_refused(&refusal));
                }
                Err(error) => {
                    tracing::warn!(%error, "a setting could not be saved");
                    return Err(crate::words::store::NOT_SAVED);
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
            crate::config::PrefEdit::Flag(crate::config::AppFlag::RunLogFull, on) => {
                self.run_log.set(rmule_core::run_log::Level::from_full(*on));
            }
            crate::config::PrefEdit::Core(rmule_core::Setting::DownloadDir { dir, .. }) => {
                self.state.session.download_dir = Some(dir.clone());
            }
            _ => {}
        }
        self.dirty = true;
        Ok((!sort).then(|| app_words::receipt(&edit, effect)))
    }
}

#[cfg(test)]
mod tests;
