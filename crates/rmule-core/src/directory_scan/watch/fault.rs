//! Why a watch over a directory, or over one path under it, does not hold — as
//! a code with its data, so a front end words it. The watch library's
//! own sentence is never carried: what it said is traced where it happened.

use std::io;

/// Why a watch does not hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchFault {
    /// The system's limit on watched files is reached (on Linux,
    /// `fs.inotify.max_user_watches`).
    Limit,
    /// The path to watch does not exist.
    PathNotFound,
    /// The operating system refused: its error kind, and its error number
    /// when it gave one.
    Io {
        /// The kind of the OS error.
        kind: io::ErrorKind,
        /// The OS's error number, when there is one.
        os_code: Option<i32>,
    },
    /// The watch's stream of change notices ended.
    Stopped,
    /// The watch library reported a fault of its own, with no OS error behind
    /// it.
    Backend,
    /// The shared file registry could not be read, so there is nothing to
    /// hold the watch's notices against.
    RegistryUnreadable,
}

impl WatchFault {
    /// The code for an OS error.
    #[must_use]
    pub fn io(error: &io::Error) -> Self {
        Self::Io {
            kind: error.kind(),
            os_code: error.raw_os_error(),
        }
    }
}

impl From<&notify::Error> for WatchFault {
    fn from(error: &notify::Error) -> Self {
        match &error.kind {
            notify::ErrorKind::MaxFilesWatch => Self::Limit,
            notify::ErrorKind::PathNotFound => Self::PathNotFound,
            notify::ErrorKind::Io(io) => Self::io(io),
            notify::ErrorKind::Generic(_)
            | notify::ErrorKind::WatchNotFound
            | notify::ErrorKind::InvalidConfig(_) => Self::Backend,
        }
    }
}
