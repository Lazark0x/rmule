//! The confirm a result the operator already knows opens (ADR-0100, "Adding a
//! marked file"): what the mark says, line by line, and the question on the
//! download that clears the completed ones.

use rmule_words::download::{FAILURE_NOT_RECORDED, download_failure_words};
use rmule_words::serve::withheld_words;

use crate::state::KnownFileMark;

/// How a line of the confirm is drawn: as plain text, or as the name or path
/// the mark is about, in the mark's own colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// Drawn in the text colour.
    Plain,
    /// Drawn in the mark's colour.
    Subject,
}

/// One line of the confirm, before it is wrapped to the modal's width.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Said {
    /// How the line is drawn.
    pub tone: Tone,
    /// What it says.
    pub text: String,
}

fn plain(text: impl Into<String>) -> Said {
    Said {
        tone: Tone::Plain,
        text: text.into(),
    }
}

fn subject(text: impl Into<String>) -> Said {
    Said {
        tone: Tone::Subject,
        text: text.into(),
    }
}

/// What a mark says of the file, after its name. `day` spells a moment as
/// the calendar day the operator reads.
#[must_use]
pub fn mark_lines(
    mark: &KnownFileMark,
    day: impl Fn(std::time::SystemTime) -> String,
) -> Vec<Said> {
    match mark {
        KnownFileMark::Have { path } => vec![
            plain("You have this file, at"),
            subject(path.display().to_string()),
        ],
        KnownFileMark::Withheld {
            path,
            reason,
            since,
        } => vec![
            plain("You share this file, at"),
            subject(path.display().to_string()),
            plain(format!(
                "rmule cannot read it now ({}) since {}.",
                withheld_words(*reason),
                day(*since)
            )),
        ],
        KnownFileMark::Had { name, found_gone } => vec![
            plain("You had this file, as"),
            subject(name.clone()),
            plain(format!("rmule found it gone on {}.", day(*found_gone))),
        ],
        KnownFileMark::Cancelled => vec![subject("You cancelled a download of this file before.")],
        KnownFileMark::Failed { name, reason, .. } => vec![
            plain("Your download of this file failed, as"),
            subject(name.clone()),
            plain(match reason {
                Some(reason) => format!("It failed because {}.", download_failure_words(reason)),
                // Only a row failed before the store kept reasons (store
                // version 6) has none.
                None => format!("Why was {FAILURE_NOT_RECORDED}."),
            }),
            plain(
                "Restarting continues from the parts on disk that still check, or starts over when nothing there can be continued from.",
            ),
        ],
        // Refused before a confirm opens.
        KnownFileMark::Downloading { .. } => Vec::new(),
    }
}

/// The question that clears `count` completed downloads from the list.
#[must_use]
pub fn clear_question(count: usize) -> String {
    let noun = if count == 1 { "download" } else { "downloads" };
    format!("Clear {count} completed {noun} from the list?")
}

/// What clearing leaves alone.
#[must_use]
pub const fn clear_keeps(count: usize) -> &'static str {
    if count == 1 {
        "The file stays on disk and shared."
    } else {
        "The files stay on disk and shared."
    }
}
