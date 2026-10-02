//! Input mapping (pure) + the blocking input pump.
//!
//! Spec-conflict note: ADR-0069 names crossterm's
//! `EventStream`, but the survey's umbrella-only dependency rule wins — the
//! `event-stream` cargo feature is not reachable through `ratatui`'s
//! re-export, so a poll/read pump thread feeds the same `select!` instead.
//! The dataflow (async input into the one bus) is unchanged.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, MouseButton, MouseEvent, MouseEventKind,
};
use tokio::sync::mpsc;

use crate::action::Action;
use crate::chrome::{self, ChromeState};

/// Map one key press against current chrome state. `None` = the key means
/// nothing here; view-local keys arrive with their views. `c` is among them:
/// the eD2k connect/disconnect toggle belongs to the Networks tab and is
/// unbound everywhere else (ADR-0074). Pure: nothing here mutates or reads a
/// clock.
#[must_use]
pub fn map_key(chrome: &ChromeState, key: KeyEvent) -> Option<Action> {
    // Kitty keyboard may report releases/repeats; only presses act.
    if key.kind == KeyEventKind::Release {
        return None;
    }
    if chrome.help_open {
        let page = i16::try_from(chrome.help_page()).unwrap_or(i16::MAX);
        return match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => Some(Action::DismissOverlay),
            KeyCode::Char('j') | KeyCode::Down => Some(Action::ScrollHelp(1)),
            KeyCode::Char('k') | KeyCode::Up => Some(Action::ScrollHelp(-1)),
            KeyCode::PageDown | KeyCode::Char(' ') => Some(Action::ScrollHelp(page)),
            KeyCode::PageUp => Some(Action::ScrollHelp(-page)),
            KeyCode::Char('g') | KeyCode::Home => Some(Action::ScrollHelp(i16::MIN)),
            KeyCode::Char('G') | KeyCode::End => Some(Action::ScrollHelp(i16::MAX)),
            _ => None,
        };
    }
    match key.code {
        KeyCode::Char(digit @ '1'..='6') => {
            let number = digit.to_digit(10).and_then(|n| u8::try_from(n).ok())?;
            crate::view::ViewId::from_number(number).map(Action::SwitchView)
        }
        // The tabs are reached by the digits and `h` / `l` alone. `[` / `]`
        // are not global: one key, one meaning (ADR-0073, Held Searches) —
        // they move between a tab's own sub-entries, and a tab with none
        // leaves them unbound. A focused query input claims `h` / `l` as text.
        KeyCode::Char('l') => Some(Action::CycleView(1)),
        KeyCode::Char('h') => Some(Action::CycleView(-1)),
        KeyCode::Char('?') => Some(Action::ToggleHelp),
        KeyCode::Char('q') => Some(Action::Quit),
        _ => None,
    }
}

/// Map one mouse event. Only the tab click is global;
/// row clicks and wheel scroll belong to the table views.
#[must_use]
pub fn map_mouse(chrome: &ChromeState, mouse: MouseEvent) -> Option<Action> {
    if chrome.help_open {
        return None;
    }
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) if mouse.row == 0 => {
            chrome::tab_at(chrome, mouse.column).map(Action::SwitchView)
        }
        _ => None,
    }
}

/// Blocking poll/read pump: forwards terminal events onto the action bus
/// until told to stop or the bus closes. 100 ms poll keeps shutdown prompt
/// without busy-waiting.
pub fn spawn_input_pump(
    actions: mpsc::Sender<Action>,
    shutdown: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("rmule-input".into())
        .spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                match ratatui::crossterm::event::poll(Duration::from_millis(100)) {
                    Ok(true) => match ratatui::crossterm::event::read() {
                        Ok(event) => {
                            if actions.blocking_send(Action::Input(event)).is_err() {
                                return; // UI gone
                            }
                        }
                        Err(_) => return,
                    },
                    Ok(false) => {}
                    Err(_) => return,
                }
            }
        })
        .expect("spawn input pump thread")
}

#[cfg(test)]
mod tests {
    use ratatui::crossterm::event::{KeyEventState, KeyModifiers};

    use super::*;
    use crate::fixture::press;
    use crate::view::ViewId;

    fn release(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Release,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn top_level_keys_map_per_spec() {
        let chrome = ChromeState::default();
        assert!(matches!(
            map_key(&chrome, press(KeyCode::Char('1'))),
            Some(Action::SwitchView(ViewId::Networks))
        ));
        assert!(matches!(
            map_key(&chrome, press(KeyCode::Char('3'))),
            Some(Action::SwitchView(ViewId::Transfers))
        ));
        assert!(matches!(
            map_key(&chrome, press(KeyCode::Char('5'))),
            Some(Action::SwitchView(ViewId::Statistics))
        ));
        assert!(matches!(
            map_key(&chrome, press(KeyCode::Char('6'))),
            Some(Action::SwitchView(ViewId::Settings))
        ));
        assert!(
            map_key(&chrome, press(KeyCode::Char('7'))).is_none(),
            "no seventh view"
        );
        assert!(matches!(
            map_key(&chrome, press(KeyCode::Char('l'))),
            Some(Action::CycleView(1))
        ));
        assert!(matches!(
            map_key(&chrome, press(KeyCode::Char('h'))),
            Some(Action::CycleView(-1))
        ));
        assert!(matches!(
            map_key(&chrome, press(KeyCode::Char('?'))),
            Some(Action::ToggleHelp)
        ));
        assert!(matches!(
            map_key(&chrome, press(KeyCode::Char('q'))),
            Some(Action::Quit)
        ));
        assert!(
            map_key(&chrome, press(KeyCode::Esc)).is_none(),
            "Esc is a no-op at top level"
        );
        assert!(map_key(&chrome, press(KeyCode::Char('z'))).is_none());
    }

    #[test]
    fn an_open_help_overlay_captures_dismissal_keys() {
        let mut chrome = ChromeState::default();
        chrome.help_open = true;
        for code in [KeyCode::Esc, KeyCode::Char('q'), KeyCode::Char('?')] {
            assert!(matches!(
                map_key(&chrome, press(code)),
                Some(Action::DismissOverlay)
            ));
        }
        assert!(
            map_key(&chrome, press(KeyCode::Char('2'))).is_none(),
            "views don't switch under a modal"
        );
    }

    #[test]
    fn key_releases_never_act() {
        let chrome = ChromeState::default();
        assert!(map_key(&chrome, release(KeyCode::Char('q'))).is_none());
    }

    #[test]
    fn a_tab_click_switches_and_other_clicks_do_nothing_yet() {
        let chrome = ChromeState::default();
        let click = |column, row| MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        };
        assert!(matches!(
            map_mouse(&chrome, click(15, 0)),
            Some(Action::SwitchView(ViewId::Searches))
        ));
        assert!(
            map_mouse(&chrome, click(15, 5)).is_none(),
            "a content click is the active view's, never the chrome's"
        );
    }
}
