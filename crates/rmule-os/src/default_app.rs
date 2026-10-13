//! The **Default app lookup** (ADR-0114, "The Default App"): which app the
//! system opens a file-name extension with — LaunchServices on macOS, the
//! shell's association on Windows. The extension is the caller's to read
//! from a name, and what to start the app on, and how, is the TUI's. Linux
//! has no such call: the TUI reads the freedesktop files itself, so this
//! module is macOS's and Windows's alone.

use std::io;
use std::path::PathBuf;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(test)]
mod tests;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
use macos::for_extension as ask_the_system;
#[cfg(windows)]
use windows::for_extension as ask_the_system;

/// The app the system opens files named `*.<extension>` with — the
/// extension without its dot, in any case: on macOS the application
/// bundle's path, on Windows the executable's. `None` when the system has no
/// app for the type, and for an empty extension or one holding a NUL, which
/// names no type.
///
/// # Errors
/// The system's error when the lookup itself fails.
pub fn for_extension(extension: &str) -> io::Result<Option<PathBuf>> {
    if extension.is_empty() || extension.contains('\0') {
        return Ok(None);
    }
    ask_the_system(extension)
}
