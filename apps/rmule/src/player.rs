//! **Preview** (ADR-0114): the operator's player, handed a download's own
//! file as one argument and through no shell, once the download is Preview
//! Ready.
//!
//! The **Player Command** is split into words by POSIX rules, never run as a
//! shell line: quotes and backslashes are honoured; nothing is expanded,
//! globbed or run as an operator, and a word starting with `#` comments out
//! the rest. The first word is the program, so it may not hold
//! [`PLACEHOLDER`]: the downloaded file is never the program run.
//!
//! What the menu shows and what a launch does are one reading,
//! [`preview_target`], so the two cannot disagree. The launch itself runs on
//! the player lane ([`lane`]).

use std::ffi::OsString;
use std::path::Path;

use rmule_core::diagnostics::PartState;
use rmule_core::{DownloadId, DownloadMetadata};

use crate::state::{DownloadStatus, UiState};

mod launch;

pub use launch::{Launch, PlayerLauncher, PlayerLaunches, lane, play_each};

/// The word the download's path replaces, inside any word — aMule's, so an
/// aMule player string carries over.
pub const PLACEHOLDER: &str = "%PARTFILE";

/// Why a Player Command text does not split into a player's words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsplittable {
    /// A quote is never closed, or the text ends in a lone backslash.
    OpenQuote,
    /// No first word names a program: every word is a comment, or the first
    /// one holds [`PLACEHOLDER`].
    NoProgram,
}

/// Split `text` into the player's words.
///
/// # Errors
/// [`Unsplittable`] when the words do not split or do not start with a
/// program.
pub fn split(text: &str) -> Result<Vec<String>, Unsplittable> {
    let words = shlex::split(text).ok_or(Unsplittable::OpenQuote)?;
    match words.first() {
        Some(program) if !program.contains(PLACEHOLDER) => Ok(words),
        _ => Err(Unsplittable::NoProgram),
    }
}

/// Why Preview cannot start for a download now. The variants are in check
/// order: the first that holds is the one shown (ADR-0114, "The control").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreviewBlock {
    /// Core has not yet named the file or where its bytes lie.
    DetailsUnknown,
    /// Core does not read the name as a video or an audio file.
    NotPreviewable,
    /// No Player Command is set.
    NoPlayer,
    /// The last snapshot holds no diagnostics row for the download.
    NoPartMap,
    /// The download is not complete and its first part is not verified.
    HeadNotVerified,
}

/// A Preview Ready download: what to hand the player and with which command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target<'a> {
    /// Where the download's bytes lie now, as core published it.
    pub path: &'a Path,
    /// The Player Command's text.
    pub command: &'a str,
    /// The download's name and size, so a launch's notes name it.
    pub metadata: &'a DownloadMetadata,
}

/// Whether download `id` is **Preview Ready** (ADR-0114): core calls it
/// Previewable and it is either `Completed` or its first part is verified on
/// its diagnostics row — a resting row counts, so a failed download whose
/// part 0 holds is ready. Read from `state` at each call, never stored.
///
/// # Errors
/// The first [`PreviewBlock`] that holds.
pub fn preview_target(state: &UiState, id: DownloadId) -> Result<Target<'_>, PreviewBlock> {
    let row = state.downloads.get(&id);
    let (Some(row), Some(metadata), Some(path)) = (
        row,
        row.and_then(|row| row.metadata.as_ref()),
        row.and_then(|row| row.file_path.as_deref()),
    ) else {
        return Err(PreviewBlock::DetailsUnknown);
    };
    if !metadata.is_previewable() {
        return Err(PreviewBlock::NotPreviewable);
    }
    let command = state
        .preferences
        .player_command
        .as_deref()
        .ok_or(PreviewBlock::NoPlayer)?;
    let target = Target {
        path,
        command,
        metadata,
    };
    if row.status == DownloadStatus::Completed {
        return Ok(target);
    }
    let parts = &state
        .diagnostics
        .downloads
        .get(&id)
        .ok_or(PreviewBlock::NoPartMap)?
        .parts;
    match parts.first() {
        Some(PartState::Verified) => Ok(target),
        _ => Err(PreviewBlock::HeadNotVerified),
    }
}

/// The player's arguments for `path`: every [`PLACEHOLDER`] inside a word is
/// replaced by the path and the word stays one argument; with no such word
/// the path is appended last. Built as OS strings, so a path whose bytes are
/// not UTF-8 reaches the player unchanged.
#[must_use]
pub fn argv(words: &[String], path: &Path) -> Vec<OsString> {
    let mut placed = false;
    let mut argv: Vec<OsString> = words
        .iter()
        .map(|word| {
            let mut pieces = word.split(PLACEHOLDER);
            let mut arg = OsString::from(pieces.next().unwrap_or_default());
            for piece in pieces {
                placed = true;
                arg.push(path.as_os_str());
                arg.push(piece);
            }
            arg
        })
        .collect();
    if !placed {
        argv.push(path.as_os_str().to_owned());
    }
    argv
}

#[cfg(test)]
mod tests;
