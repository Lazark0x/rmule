//! The **Default App** (ADR-0114, "The Default App"): the app the system
//! opens a download's real type with, which Preview starts when no Player
//! Command is set. It is looked up by the extension of the download's name,
//! never of the file on disk, and named when it is started, so no
//! association launcher picks a handler by `.part`. macOS and Windows answer
//! through `rmule-os`; the freedesktop systems through [`freedesktop`],
//! which reads their files and is built everywhere, so its reading is tested
//! on every platform.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

pub mod freedesktop;
#[cfg(test)]
mod tests;

/// A Default App the system named, by the way its system starts it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DefaultApp {
    /// A macOS application bundle, opened through LaunchServices with the app
    /// named.
    Bundle(PathBuf),
    /// A Windows executable, run with the file as its one argument.
    Program(PathBuf),
    /// A freedesktop desktop entry, started by GLib's `gio launch`, which
    /// runs its `Exec` line by the Desktop Entry spec.
    DesktopEntry(PathBuf),
}

impl DefaultApp {
    /// The arguments that start this app on `file`, program first; no shell
    /// on any road.
    #[must_use]
    pub fn argv(&self, file: &Path) -> Vec<OsString> {
        let file = file.as_os_str().to_owned();
        match self {
            Self::Bundle(app) => vec![
                super::OPEN.into(),
                "-a".into(),
                app.as_os_str().to_owned(),
                file,
            ],
            Self::Program(program) => vec![program.as_os_str().to_owned(), file],
            Self::DesktopEntry(entry) => vec![
                "gio".into(),
                "launch".into(),
                entry.as_os_str().to_owned(),
                file,
            ],
        }
    }
}

/// The app this system opens files with `extension` with, `None` when it has
/// none. A short read of the system's own answer: the player lane runs it
/// off the runtime's workers.
///
/// # Errors
/// The system's error when the lookup itself fails.
pub fn lookup(extension: &str) -> io::Result<Option<DefaultApp>> {
    #[cfg(target_os = "macos")]
    let app = rmule_os::default_app::for_extension(extension)?.map(DefaultApp::Bundle);
    #[cfg(windows)]
    let app = rmule_os::default_app::for_extension(extension)?.map(DefaultApp::Program);
    #[cfg(all(unix, not(target_os = "macos")))]
    let app = freedesktop::lookup(&freedesktop::Dirs::from_env(), extension)?
        .map(DefaultApp::DesktopEntry);
    Ok(app)
}
