//! What a panic costs the UI (ADR-0118). The hook writes the Run Log first,
//! then decides by what the panic costs: a worker's panic in a build that
//! unwinds leaves the frame alone and reaches the status line as a note; a
//! panic of the UI thread, or any panic in a dist build, gives the terminal
//! back and says on the normal screen what happened.

use std::panic::PanicHookInfo;
use std::path::PathBuf;
use std::thread::ThreadId;

use rmule_core::run_log::{self, LevelHandle};
use tokio::sync::mpsc;

use crate::action::Action;
use crate::tui;
use crate::words::app as app_words;

/// What the hook does once the Run Log holds the panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Response {
    /// One task ended behind a live frame: a note, and no byte on the screen.
    Note,
    /// One task ended before the terminal was entered, or after it was given
    /// back: stderr is a screen the operator reads.
    Print,
    /// The run is over: the terminal back, then the words.
    Leave,
}

/// What a panic costs: on the UI thread or in a build that does not unwind
/// the run is over; on a worker the task is, and what the operator sees
/// depends on whether a frame is up.
const fn response(on_ui_thread: bool, unwinds: bool, frame_up: bool) -> Response {
    if on_ui_thread || !unwinds {
        Response::Leave
    } else if frame_up {
        Response::Note
    } else {
        Response::Print
    }
}

/// Install the hook. `run_log` is the log's file, when the run has one.
/// `notes` is weak, so the hook does not hold the action bus open.
pub fn install_hook(
    ui_thread: ThreadId,
    level: LevelHandle,
    notes: mpsc::WeakSender<Action>,
    run_log: Option<PathBuf>,
) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info: &PanicHookInfo<'_>| {
        run_log::panic_record(info, &level);
        let on_ui_thread = std::thread::current().id() == ui_thread;
        match response(on_ui_thread, cfg!(panic = "unwind"), tui::entered()) {
            Response::Note => {
                if let Some(notes) = notes.upgrade() {
                    let _ = notes.try_send(Action::Note(app_words::INTERNAL_FAULT));
                }
            }
            Response::Print => previous(info),
            Response::Leave => {
                tui::leave();
                let (file, line) = info
                    .location()
                    .map_or(("unknown", 0), |site| (site.file(), site.line()));
                eprintln!(
                    "{}",
                    app_words::fault_at(file, line, run_log.as_deref())
                );
            }
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::{Response, response};

    /// Ratatui's own hook restored the terminal here and left the UI drawing
    /// onto the shell's screen.
    #[test]
    fn a_workers_panic_behind_a_frame_touches_no_terminal() {
        assert_eq!(response(false, true, true), Response::Note);
    }

    #[test]
    fn the_ui_threads_panic_gives_the_terminal_back() {
        assert_eq!(response(true, true, true), Response::Leave);
    }

    #[test]
    fn a_dist_builds_panic_ends_the_run_from_any_thread() {
        assert_eq!(response(false, false, true), Response::Leave);
    }

    #[test]
    fn a_panic_with_no_frame_up_is_printed() {
        assert_eq!(response(false, true, false), Response::Print);
    }
}
