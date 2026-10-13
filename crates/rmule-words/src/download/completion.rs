//! The operator's words for a download's completion move (ADR-0115): each
//! step the move takes, the line a one-shot download prints as each begins,
//! and the note the status bar shows. Core carries the step and the path; the
//! sentences are here.

use std::path::Path;

use rmule_core::CompletionStep;
use rmule_core::diagnostics::CompletionProgress;

use super::super::Sentence;
use super::super::units::human_size;

/// A figure not known.
const DASH: &str = "—";

/// What a completing download is doing, as a clause.
#[must_use]
pub const fn completion_step_words(step: CompletionStep) -> &'static str {
    match step {
        CompletionStep::Moving => "moving the finished file into place",
        CompletionStep::QueuedForCopy => {
            "waiting its turn to copy the finished file to the disk it goes to"
        }
        CompletionStep::Copying => "copying the finished file to the disk it goes to",
        CompletionStep::WaitingForRelease => "waiting for the file to be released",
        CompletionStep::WaitingForStore => "waiting for rmule's store to record the finished file",
    }
}

/// What a completing download is doing, with the bytes its copy has written
/// of the file's `size` while it copies; a size not known is a dash.
#[must_use]
pub fn completion_progress(step: CompletionStep, copied: u64, size: Option<u64>) -> String {
    match step {
        CompletionStep::Copying => format!(
            "{}: {} of {}",
            completion_step_words(step),
            human_size(copied),
            size.map_or_else(|| DASH.to_string(), human_size)
        ),
        step => completion_step_words(step).to_string(),
    }
}

/// A completing download's status cell (ADR-0115, "What the operator
/// reads"): Completing, with what the move waits for while a program holds
/// the file and the bytes copied while it copies; the row's Size cell says
/// of what. A step not yet published reads Completing.
#[must_use]
pub fn completing_status(progress: Option<CompletionProgress>) -> String {
    match progress.map(|progress| (progress.step, progress.copied)) {
        Some((CompletionStep::WaitingForRelease, _)) => {
            "Completing: waiting for the file to be released".to_string()
        }
        Some((CompletionStep::Copying, copied)) => {
            format!("Completing: {} copied", human_size(copied))
        }
        Some((
            CompletionStep::Moving | CompletionStep::QueuedForCopy | CompletionStep::WaitingForStore,
            _,
        ))
        | None => "Completing".to_string(),
    }
}

/// The status bar's note as a step of the move begins.
#[must_use]
pub fn completing(name: &str, step: CompletionStep) -> Sentence {
    let words = completion_step_words(step);
    Sentence::owned(match step {
        CompletionStep::WaitingForRelease => {
            format!("{name}: {words}; it completes once the program holding it lets go")
        }
        _ => format!("{name}: {words}"),
    })
}

/// The line a one-shot download prints as a step of its move begins: the
/// step, and where the file goes.
#[must_use]
pub fn completing_line(step: CompletionStep, to: &Path) -> String {
    format!(
        "completing: {} ({})",
        completion_step_words(step),
        to.display()
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use rmule_core::CompletionStep;

    use super::{completing_line, completion_progress};

    #[test]
    fn a_copy_reads_its_bytes_and_a_wait_says_what_it_waits_for() {
        assert_eq!(
            completion_progress(CompletionStep::Copying, 1_048_576, Some(4_194_304)),
            "copying the finished file to the disk it goes to: 1.0 MB of 4.0 MB"
        );
        assert_eq!(
            completion_progress(CompletionStep::Copying, 1_048_576, None),
            "copying the finished file to the disk it goes to: 1.0 MB of —",
            "a size not known is a dash, never 0 B"
        );
        assert_eq!(
            completing_line(
                CompletionStep::WaitingForRelease,
                Path::new("/Downloads/Мой фильм (1).mkv")
            ),
            "completing: waiting for the file to be released (/Downloads/Мой фильм (1).mkv)"
        );
    }
}
