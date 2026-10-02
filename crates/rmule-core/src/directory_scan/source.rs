//! What the scan reads the disk through: the seam [`DirectorySource`] and the
//! facts it reports — a directory entry, a file's stamp, and its
//! path-independent identity where the filesystem keeps one.

use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// What the trust rule compares besides the path: a file's size and its
/// modification time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileStamp {
    /// The file's size in bytes.
    pub size: u64,
    /// The file's modification time.
    pub modified: SystemTime,
}

/// A file's path-independent identity (ADR-0100, "A rename carries its hash
/// when the file's identity proves it"): its device, its inode number and its
/// birth time. A rename within one filesystem keeps all three; a file created
/// in its place after a delete has another birth time. Read only where the
/// filesystem's identities are stable, and never trusted alone: size and
/// modification time must match too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileIdentity {
    /// The device the file lies on.
    pub device: u64,
    /// The file's inode number on that device.
    pub inode: u64,
    /// When the file was created.
    pub born: SystemTime,
}

/// What one directory entry is, as listed — a symlink is reported as itself,
/// never followed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file, with its stamp.
    File(FileStamp),
    /// A directory, walked into.
    Directory,
    /// A symbolic link, skipped whatever it points at.
    Symlink,
    /// Anything else (a socket, a device), skipped.
    Other,
}

/// One entry of a directory listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry's own name, not its path.
    pub name: OsString,
    /// What the entry is.
    pub kind: EntryKind,
}

/// The seam between the scan and the filesystem: list a directory, stamp a
/// file, open one for reading. Everything the pass learns about the disk
/// comes through here.
pub trait DirectorySource: Send + Sync + 'static {
    /// The entries of `dir`, in any order.
    ///
    /// # Errors
    /// The listing's I/O error.
    fn list(&self, dir: &Path) -> io::Result<Vec<DirEntry>>;

    /// What is at `path` now, a symlink reported as itself.
    ///
    /// # Errors
    /// The lookup's I/O error; `NotFound` when nothing is there.
    fn kind(&self, path: &Path) -> io::Result<EntryKind>;

    /// Whether `path` leads to a directory, every symlink on the way and at
    /// its end followed, as they are when a path through it is opened.
    ///
    /// # Errors
    /// The lookup's I/O error; `NotFound` when nothing is there, a dangling
    /// link included.
    fn is_folder(&self, path: &Path) -> io::Result<bool>;

    /// The size and modification time of the file at `path`.
    ///
    /// # Errors
    /// The lookup's I/O error.
    fn stamp(&self, path: &Path) -> io::Result<FileStamp>;

    /// The file at `path`, opened for reading. The trust rule exists so that
    /// an unchanged file never gets here.
    ///
    /// # Errors
    /// The open's I/O error.
    fn open(&self, path: &Path) -> io::Result<Box<dyn io::Read + Send>>;

    /// The [`FileIdentity`] of the regular file at `path`, or `None` when
    /// its filesystem gives no stable one, it has no birth time, or it
    /// cannot be looked at. `None` means the file is read, as it always was.
    fn identity(&self, path: &Path) -> Option<FileIdentity> {
        let _ = path;
        None
    }
}
