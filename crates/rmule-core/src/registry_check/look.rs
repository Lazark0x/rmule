//! One look at one registry row: what its path holds now, against what the
//! row says (ADR-0106, "The registry against the disk"). A look reads
//! metadata only, and opens a file without reading it only where the row's
//! readability is the question.

use std::io;

use crate::directory_scan::{DirectorySource, EntryKind, FileStamp};
use crate::registry::SharedFileEntry;

/// What a look found at a row's path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Look {
    /// A file whose stamp matches the row.
    Readable,
    /// A file whose size or modification time differ from the row's.
    Changed,
    /// Nothing, or something other than a file, in a folder that is there.
    Gone,
    /// Nothing, and no folder either: an unmounted volume looks like this.
    FolderMissing,
    /// The path could not be looked at, or its file could not be opened or
    /// read, for this kind of error.
    Unreadable(io::ErrorKind),
}

/// Look at `row`'s path: one `stat`, and one more of its folder when the
/// file is not there. Nothing is opened.
pub(crate) fn look(source: &dyn DirectorySource, row: &SharedFileEntry) -> Look {
    match source.kind(&row.path) {
        Ok(EntryKind::File(stamp)) if matches_row(row, stamp) => Look::Readable,
        Ok(EntryKind::File(_)) => Look::Changed,
        Ok(EntryKind::Directory | EntryKind::Symlink | EntryKind::Other) => Look::Gone,
        Err(error) if error.kind() == io::ErrorKind::NotFound => folder_look(source, row),
        Err(error) => Look::Unreadable(error.kind()),
    }
}

/// Look at `row` and, if its stamp says it is readable, open it: a withheld
/// row is offered again only once it opens.
pub(crate) fn look_and_open(source: &dyn DirectorySource, row: &SharedFileEntry) -> Look {
    match look(source, row) {
        Look::Readable => match source.open(&row.path) {
            Ok(_) => Look::Readable,
            Err(error) => Look::Unreadable(error.kind()),
        },
        other => other,
    }
}

/// Look at `row` after a read of it failed. A path that still looks right is
/// unreadable all the same: the open's error if it will not open, else the
/// failed read's.
pub(crate) fn look_after_failure(source: &dyn DirectorySource, row: &SharedFileEntry) -> Look {
    match look_and_open(source, row) {
        // It opens, so the read failed past the open: an I/O error.
        Look::Readable => Look::Unreadable(io::ErrorKind::Other),
        other => other,
    }
}

fn folder_look(source: &dyn DirectorySource, row: &SharedFileEntry) -> Look {
    let Some(folder) = row.path.parent() else {
        return Look::FolderMissing;
    };
    match source.is_folder(folder) {
        Ok(true) => Look::Gone,
        Ok(false) => Look::FolderMissing,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Look::FolderMissing,
        Err(error) => Look::Unreadable(error.kind()),
    }
}

/// The **Hash Trust Rule** as a look applies it. A row with no recorded time
/// (written before store version 2) is compared on size alone: its time was
/// never known, and the scan re-stamps the rows under its directory.
fn matches_row(row: &SharedFileEntry, stamp: FileStamp) -> bool {
    row.file_size == stamp.size
        && row
            .modified
            .is_none_or(|modified| modified == stamp.modified)
}
