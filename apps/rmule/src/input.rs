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
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use tokio::sync::mpsc;

use crate::action::Action;
use crate::chrome::{self, ChromeState};

/// What the reducer does with a key before anything else reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyGate {
    /// A press the views and the globals may read.
    Pass,
    /// Means nothing: a release, or a Ctrl or Alt chord no surface binds.
    Drop,
    /// Ctrl-C: the quit path, from every surface.
    Interrupt,
}

/// The one reading of a key's kind and modifiers, so no view has to.
///
/// Windows reports a release for every key, and the kitty protocol may; only
/// a press acts. In raw mode Ctrl-C reaches here as `c` with a modifier, so a
/// view that read the code alone would take it for its own `c`. Ctrl with Alt
/// on a character is AltGr on a Windows console, and that is typed text.
#[must_use]
pub fn gate(key: &KeyEvent) -> KeyGate {
    if key.kind == KeyEventKind::Release {
        return KeyGate::Drop;
    }
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    match key.code {
        KeyCode::Char(_) if ctrl && alt => KeyGate::Pass,
        KeyCode::Char('c' | 'C') if ctrl => KeyGate::Interrupt,
        _ if ctrl || alt => KeyGate::Drop,
        _ => KeyGate::Pass,
    }
}

/// Map one key press against current chrome state. `None` = the key means
/// nothing here; view-local keys arrive with their views. `c` is among them:
/// the eD2k connect/disconnect toggle belongs to the Networks tab and is
/// unbound everywhere else (ADR-0074). Pure: nothing here mutates or reads a
/// clock.
#[must_use]
pub fn map_key(chrome: &ChromeState, key: KeyEvent) -> Option<Action> {
    if chrome.quit_open {
        return match crate::views::modal::confirm_key(key.code) {
            Some(true) => Some(Action::Quit),
            Some(false) => Some(Action::DismissOverlay),
            None => None,
        };
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
        KeyCode::Char('q') => Some(Action::AskQuit),
        _ => None,
    }
}

/// Map one mouse event. Only the tab click is global;
/// row clicks and wheel scroll belong to the table views.
#[must_use]
pub fn map_mouse(chrome: &ChromeState, mouse: MouseEvent) -> Option<Action> {
    if chrome.help_open || chrome.quit_open {
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
            pump(actions, shutdown, || {
                if ratatui::crossterm::event::poll(Duration::from_millis(100))? {
                    ratatui::crossterm::event::read().map(Some)
                } else {
                    Ok(None)
                }
            });
        })
        .expect("spawn input pump thread")
}

/// Feed what `next` reads onto the bus until the run's end is asked for. A
/// pump that ends any other way, a read failure or its own panic, leaves the
/// operator no key to quit with, so its end is a Quit (ADR-0118).
fn pump(
    actions: mpsc::Sender<Action>,
    shutdown: Arc<AtomicBool>,
    mut next: impl FnMut() -> std::io::Result<Option<Event>>,
) {
    struct QuitAtEnd {
        actions: mpsc::Sender<Action>,
        shutdown: Arc<AtomicBool>,
    }
    impl Drop for QuitAtEnd {
        fn drop(&mut self) {
            if !self.shutdown.load(Ordering::Relaxed) {
                let _ = self.actions.blocking_send(Action::Quit);
            }
        }
    }
    let end = QuitAtEnd { actions, shutdown };
    while !end.shutdown.load(Ordering::Relaxed) {
        match next() {
            Ok(Some(event)) => {
                if end.actions.blocking_send(Action::Input(event)).is_err() {
                    return; // UI gone
                }
            }
            Ok(None) => {}
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::press;
    use crate::view::ViewId;

    fn a_quit_follows(
        next: impl FnMut() -> std::io::Result<Option<Event>> + Send + 'static,
    ) -> bool {
        let (actions, mut bus) = mpsc::channel(4);
        let shutdown = Arc::new(AtomicBool::new(false));
        let pump = std::thread::spawn(move || pump(actions, shutdown, next));
        let _ = pump.join();
        matches!(bus.try_recv(), Ok(Action::Quit))
    }

    #[test]
    fn a_pump_whose_read_fails_quits_the_run() {
        assert!(a_quit_follows(|| Err(std::io::Error::from(
            std::io::ErrorKind::BrokenPipe
        ))));
    }

    #[test]
    fn a_pump_that_panics_quits_the_run() {
        assert!(a_quit_follows(|| panic!("a defect in the pump")));
    }

    #[test]
    fn a_pump_told_to_stop_says_nothing() {
        let (actions, mut bus) = mpsc::channel(4);
        pump(actions, Arc::new(AtomicBool::new(true)), || Ok(None));
        assert!(bus.try_recv().is_err());
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
            Some(Action::AskQuit)
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
    fn the_gate_reads_kind_and_modifiers_once() {
        let chord = |code, modifiers| KeyEvent::new(code, modifiers);
        let release = KeyEvent::new_with_kind(
            KeyCode::Char('a'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        assert_eq!(gate(&release), KeyGate::Drop);
        assert_eq!(gate(&press(KeyCode::Char('a'))), KeyGate::Pass);
        let shifted = chord(KeyCode::Char('A'), KeyModifiers::SHIFT);
        assert_eq!(gate(&shifted), KeyGate::Pass);
        let ctrl = KeyModifiers::CONTROL;
        assert_eq!(gate(&chord(KeyCode::Char('c'), ctrl)), KeyGate::Interrupt);
        assert_eq!(gate(&chord(KeyCode::Char('p'), ctrl)), KeyGate::Drop);
        assert_eq!(gate(&chord(KeyCode::Left, ctrl)), KeyGate::Drop);
        let alt = KeyModifiers::ALT;
        assert_eq!(gate(&chord(KeyCode::Char('q'), alt)), KeyGate::Drop);
        let alt_gr = KeyModifiers::CONTROL | KeyModifiers::ALT;
        assert_eq!(gate(&chord(KeyCode::Char('@'), alt_gr)), KeyGate::Pass);
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
