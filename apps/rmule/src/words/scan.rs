//! The TUI's own scan words, beside the shared ones it re-exports: how much
//! of the share set lies under a directory, and the remove confirm that
//! names it — which word the TUI's own tally.

use std::path::Path;

pub use rmule_words::scan::*;

use super::units::human_size;
use crate::state::SharedUnder;

/// How much of the share set lies under a directory.
#[must_use]
pub fn under_words(under: SharedUnder) -> String {
    match (under.files, under.bytes) {
        (0, _) => "no files shared yet".to_string(),
        (count, Some(bytes)) => format!("{}, {}", files(count), human_size(bytes)),
        (count, None) => format!("{}, size still being read", files(count)),
    }
}

/// The remove confirm: its question and what a yes does.
#[must_use]
pub fn remove_confirm(dir: &Path, under: SharedUnder) -> (String, String) {
    (
        format!("Stop sharing {}? {}.", dir.display(), under_words(under)),
        "They leave the offer at once: servers and Kad stop hearing of them, and an \
         upload in progress ends. The files stay on disk, and adding the directory \
         again reads nothing."
            .to_string(),
    )
}
