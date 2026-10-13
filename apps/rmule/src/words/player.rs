//! The words of **Preview**, its **Player Command** and its **Default App**
//! (ADR-0114): the unset Settings row, why a typed command is refused, why
//! Preview is greyed, why no Default App starts, and how a player's launch
//! ended. Each launch note names the download.

use std::io::ErrorKind;
use std::process::ExitStatus;

use super::{Sentence, os};
use crate::player::{PreviewBlock, Unsplittable};

/// What the unset Player Command row reads.
pub const UNSET: &str = "unset — Preview opens the default app";

/// A Preview the player lane could not take: its task has ended.
pub const LANE_ENDED: Sentence = Sentence::fixed("cannot preview: the player launcher has stopped");

/// Why a Player Command does not split, as a clause.
#[must_use]
pub const fn refusal_words(refusal: Unsplittable) -> &'static str {
    match refusal {
        Unsplittable::OpenQuote => "a quote is not closed",
        Unsplittable::NoProgram => "the first word must name the player, not %PARTFILE",
        Unsplittable::Folder => "the first word is a folder, not a program",
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
    format!("player → {}", command.unwrap_or("the default app"))
}

/// Why Preview is greyed, as the reason beside the menu item.
#[must_use]
pub const fn block_words(block: PreviewBlock) -> &'static str {
    match block {
        PreviewBlock::DetailsUnknown => "details not known yet",
        PreviewBlock::NotPreviewable => "not a video or audio file",
        PreviewBlock::NoAppForType => "no app for this type",
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
        spawn_cause(kind)
    ))
}

/// Why a player could not start, as a clause. A program the system denies is
/// one it may not run, so the clause says what the operator can change.
const fn spawn_cause(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::PermissionDenied => "the program is not executable",
        kind => os::kind_words(kind),
    }
}

/// No Default App opens files with `extension` here, so a Preview of
/// download `name` needs a player set.
#[must_use]
pub fn no_app(name: &str, extension: &str) -> Sentence {
    Sentence::owned(format!(
        "preview of {name}: no app opens .{extension} files here — set a player in Settings"
    ))
}

/// The Default App for `extension` could not be looked up for a Preview of
/// download `name`.
#[must_use]
pub fn lookup_failed(name: &str, extension: &str, kind: ErrorKind) -> Sentence {
    Sentence::owned(format!(
        "preview of {name}: the app for .{extension} files could not be looked up: {}",
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
