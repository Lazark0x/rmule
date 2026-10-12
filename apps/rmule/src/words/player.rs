//! The words of **Preview** and its **Player Command** (ADR-0114): the unset
//! Settings row, why a typed command is refused, why Preview is greyed, and
//! how a player's launch ended. Each launch note names the download.

use std::io::ErrorKind;
use std::process::ExitStatus;

use super::{Sentence, os};
use crate::player::{PreviewBlock, Unsplittable};

/// What the unset Player Command row reads.
pub const UNSET: &str = "unset — Preview is off";

/// A Preview the player lane could not take: its task has ended.
pub const LANE_ENDED: Sentence = Sentence::fixed("cannot preview: the player launcher has stopped");

/// Why a Player Command does not split, as a clause.
#[must_use]
pub const fn refusal_words(refusal: Unsplittable) -> &'static str {
    match refusal {
        Unsplittable::OpenQuote => "a quote is not closed",
        Unsplittable::NoProgram => "the first word must name the player, not %PARTFILE",
    }
}

/// Why a typed Player Command is refused, as the line under the field.
#[must_use]
pub fn field_refusal(refusal: Unsplittable) -> String {
    format!("player: {}", refusal_words(refusal))
}

/// A Preview whose stored Player Command does not split.
#[must_use]
pub fn unsplittable(refusal: Unsplittable) -> Sentence {
    Sentence::owned(format!(
        "cannot preview: in the player set in Settings, {}",
        refusal_words(refusal)
    ))
}

/// What a saved Player Command reads in the Settings receipt.
#[must_use]
pub fn receipt(command: Option<&str>) -> String {
    format!("player → {}", command.unwrap_or("none"))
}

/// Why Preview is greyed, as the reason beside the menu item.
#[must_use]
pub const fn block_words(block: PreviewBlock) -> &'static str {
    match block {
        PreviewBlock::DetailsUnknown => "details not known yet",
        PreviewBlock::NotPreviewable => "not a video or audio file",
        PreviewBlock::NoPlayer => "set a player in Settings",
        PreviewBlock::NoPartMap => "part map not loaded yet",
        PreviewBlock::HeadNotVerified => "first part not verified yet",
    }
}

/// Why `v` did not start a player, as the flash.
#[must_use]
pub fn blocked(block: PreviewBlock) -> Sentence {
    Sentence::owned(format!("cannot preview: {}", block_words(block)))
}

/// How the player of download `name` ended, or `None` for a clean exit,
/// which says nothing.
#[must_use]
pub fn exit_note(name: &str, status: ExitStatus) -> Option<Sentence> {
    if status.success() {
        return None;
    }
    Some(Sentence::owned(match status.code() {
        Some(code) => format!("preview of {name}: the player ended with status {code}"),
        // Only a Unix process ends with no code: a signal stopped it.
        None => format!("preview of {name}: the player was stopped by a signal"),
    }))
}

/// The player of download `name` could not start.
#[must_use]
pub fn spawn_refused(name: &str, kind: ErrorKind) -> Sentence {
    Sentence::owned(format!(
        "preview of {name}: the player could not start: {}",
        os::kind_words(kind)
    ))
}

/// The player of download `name` started, but how it ended could not be
/// read.
#[must_use]
pub fn unwatched(name: &str, kind: ErrorKind) -> Sentence {
    Sentence::owned(format!(
        "preview of {name}: the player started, but its end could not be read: {}",
        os::kind_words(kind)
    ))
}
