//! The filesystem steps of the completion move that the operating system may
//! refuse in ways the move answers differently (ADR-0115): a rename and a
//! delete, each refused because another program holds the file, because the
//! two paths lie on different volumes, or for a reason of its own. A seam,
//! so a test can answer what a second volume or a media player would.

use std::io;
use std::path::Path;

/// Why the operating system refused a rename or a delete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Another program holds the file (Windows `ERROR_SHARING_VIOLATION` 32,
    /// `ERROR_LOCK_VIOLATION` 33): the move waits for it.
    InUse {
        /// The OS's error number.
        os_code: i32,
    },
    /// The two paths lie on different volumes (`EXDEV`, Windows
    /// `ERROR_NOT_SAME_DEVICE`): the move copies.
    CrossesDevices,
    /// Any other refusal, with the OS's error number when it gave one.
    Other {
        /// The OS's error number, when there is one.
        os_code: Option<i32>,
    },
}

impl Refusal {
    /// The OS's error number, when the refusal kept one.
    pub(crate) const fn os_code(self) -> Option<i32> {
        match self {
            Self::InUse { os_code } => Some(os_code),
            Self::Other { os_code } => os_code,
            Self::CrossesDevices => None,
        }
    }

    /// The refusal `error` stands for.
    pub(crate) fn of(error: &io::Error) -> Self {
        if error.kind() == io::ErrorKind::CrossesDevices {
            return Self::CrossesDevices;
        }
        match error.raw_os_error() {
            Some(os_code) if in_use(os_code) => Self::InUse { os_code },
            os_code => Self::Other { os_code },
        }
    }
}

/// Whether `os_code` says another program holds the file.
#[cfg(windows)]
const fn in_use(os_code: i32) -> bool {
    matches!(os_code, 32 | 33)
}

/// Whether `os_code` says another program holds the file: never on a system
/// whose renames and deletes ignore open handles.
#[cfg(not(windows))]
const fn in_use(_os_code: i32) -> bool {
    false
}

/// The rename and the delete the completion move makes. Blocking: the move
/// calls them on the blocking pool.
pub(crate) trait CompletionFs: Send + Sync + 'static {
    /// Rename `from` onto `to`, which the move has found free.
    fn rename(&self, from: &Path, to: &Path) -> Result<(), Refusal>;

    /// Delete `path`; one already gone is no refusal.
    fn remove(&self, path: &Path) -> Result<(), Refusal>;
}

/// The operating system's own.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OsCompletionFs;

impl CompletionFs for OsCompletionFs {
    fn rename(&self, from: &Path, to: &Path) -> Result<(), Refusal> {
        std::fs::rename(from, to).map_err(|error| Refusal::of(&error))
    }

    fn remove(&self, path: &Path) -> Result<(), Refusal> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Refusal::of(&error)),
        }
    }
}
