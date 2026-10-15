//! The filesystem steps of the completion move that the operating system may
//! refuse in ways the move answers differently (ADR-0115): an exclusive
//! rename and a delete, each refused because a file stands at the target,
//! because another program holds the file, because the two paths lie on
//! different volumes, or for a reason of its own. A seam, so a test can
//! answer what a second volume, a media player or a file that came to stand
//! at the destination would.

use std::io;
use std::path::Path;

/// Why the operating system refused a rename or a delete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Something stands at the rename's target (`AlreadyExists`): the move
    /// names the next free name.
    Taken,
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
            Self::Taken | Self::CrossesDevices => None,
        }
    }

    /// The refusal `error` stands for.
    pub(crate) fn of(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::AlreadyExists => return Self::Taken,
            io::ErrorKind::CrossesDevices => return Self::CrossesDevices,
            _ => {}
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
    /// Rename `from` onto `to` unless something stands at `to`, which
    /// answers [`Refusal::Taken`] and leaves both files as they were.
    fn rename_exclusive(&self, from: &Path, to: &Path) -> Result<(), Refusal>;

    /// Delete `path`; one already gone is no refusal.
    fn remove(&self, path: &Path) -> Result<(), Refusal>;
}

/// The operating system's own: the exclusive rename of `rmule-os`, and on a
/// filesystem that refuses its flag a check of the target, then a rename —
/// the window between the two open on that volume alone.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OsCompletionFs;

impl CompletionFs for OsCompletionFs {
    fn rename_exclusive(&self, from: &Path, to: &Path) -> Result<(), Refusal> {
        exclusive_or_checked(rmule_os::fs::rename_exclusive(from, to), from, to)
    }

    fn remove(&self, path: &Path) -> Result<(), Refusal> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Refusal::of(&error)),
        }
    }
}

/// What the exclusive rename `exclusive` answered, or where the filesystem
/// refused its flag, the checked rename: [`Refusal::Taken`] when anything,
/// a dangling link included, stands at `to`, else std's rename.
fn exclusive_or_checked(exclusive: io::Result<()>, from: &Path, to: &Path) -> Result<(), Refusal> {
    match exclusive {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {
            if std::fs::symlink_metadata(to).is_ok() {
                return Err(Refusal::Taken);
            }
            std::fs::rename(from, to).map_err(|error| Refusal::of(&error))
        }
        Err(error) => Err(Refusal::of(&error)),
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::{Refusal, exclusive_or_checked};

    /// A volume that refuses the exclusive flag still never renames onto a
    /// file standing before the call, and renames onto a free name.
    #[test]
    fn where_the_flag_is_refused_the_rename_checks_the_target_first() {
        let dir = tempfile::tempdir().unwrap();
        let (from, to) = (
            dir.path().join("film.mkv.part"),
            dir.path().join("film.mkv"),
        );
        std::fs::write(&from, b"finished").unwrap();
        std::fs::write(&to, b"the operator's own").unwrap();
        let unsupported = || Err(io::Error::from(io::ErrorKind::Unsupported));

        assert_eq!(
            exclusive_or_checked(unsupported(), &from, &to),
            Err(Refusal::Taken)
        );
        assert_eq!(std::fs::read(&to).unwrap(), b"the operator's own");

        std::fs::remove_file(&to).unwrap();
        assert_eq!(exclusive_or_checked(unsupported(), &from, &to), Ok(()));
        assert!(!from.exists());
        assert_eq!(std::fs::read(&to).unwrap(), b"finished");
    }
}
