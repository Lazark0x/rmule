//! What a run says as it starts. Every note lands in the log, but the status
//! bar shows one at a time, the last, so they go out mildest first and the
//! worst is the one left on the bar.

use crate::words::{Sentence, app, download, kad};

/// What this start found worth saying.
#[derive(Debug, Default)]
pub struct StartFacts {
    /// Why this run has no Run Log.
    pub no_run_log: Option<Sentence>,
    /// The OS refused the stop signals' handlers.
    pub stop_signals_refused: bool,
    /// The OS refused job control's handlers: Ctrl-Z may stop nothing and a
    /// continue will not repaint.
    pub job_control_refused: bool,
    /// The Connection Ceiling the OS held the run under.
    pub ceiling_lowered: Option<Sentence>,
    /// Why the connect at start found nothing to connect to.
    pub cannot_connect: Option<Sentence>,
    /// A download has somewhere to land.
    pub download_dir_set: bool,
}

/// The notes of a start, mildest first.
#[must_use]
pub fn start_notes(facts: StartFacts) -> Vec<Sentence> {
    [
        Some(kad::WAITING_FOR_CONNECT),
        (!facts.download_dir_set).then_some(download::NO_DOWNLOAD_DIR),
        facts.cannot_connect,
        facts.ceiling_lowered,
        facts.stop_signals_refused.then_some(app::NO_STOP_SIGNALS),
        facts.job_control_refused.then_some(app::NO_JOB_CONTROL),
        facts.no_run_log,
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The last note is the one the status bar keeps.
    #[test]
    fn the_worst_note_is_the_one_left_on_the_bar() {
        let first_run = start_notes(StartFacts::default());
        assert_eq!(first_run.last(), Some(&download::NO_DOWNLOAD_DIR));
        let settled = StartFacts {
            download_dir_set: true,
            ..StartFacts::default()
        };
        assert_eq!(start_notes(settled), [kad::WAITING_FOR_CONNECT]);
        let lowered = crate::words::Sentence::for_test("ceiling lowered");
        let notes = start_notes(StartFacts {
            ceiling_lowered: Some(lowered.clone()),
            stop_signals_refused: true,
            ..StartFacts::default()
        });
        assert_eq!(notes.last(), Some(&app::NO_STOP_SIGNALS));
        let notes = start_notes(StartFacts {
            ceiling_lowered: Some(lowered.clone()),
            download_dir_set: true,
            ..StartFacts::default()
        });
        assert_eq!(notes.last(), Some(&lowered));
    }
}
