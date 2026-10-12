//! A tool's output path as core takes it: core places every download in the
//! download directory its Core Settings name, and a start names the file
//! only (ADR-0069). A tool that is told where a file lands sets the folder
//! as its core's download directory and starts the download by name.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rmule_core::{CoreCommand, DownloadCommand, NameTaken};
use rmule_primitives::{Ed2kFileLink, FileHash, SafeFileName, ServerEndpoint};

/// The one folder every path in `outputs` lands in, made absolute against
/// the working directory: it becomes the core's download directory.
///
/// # Errors
/// When the paths name no file, or more than one folder.
pub(crate) fn download_dir(outputs: &[PathBuf]) -> Result<PathBuf> {
    let mut dirs = outputs.iter().map(|path| folder_of(path));
    let first = dirs.next().context("no output path")??;
    for dir in dirs {
        let dir = dir?;
        anyhow::ensure!(
            dir == first,
            "every output must land in one folder: {} and {}",
            first.display(),
            dir.display()
        );
    }
    Ok(first)
}

/// The `StartDownload` that lands `file` at `output`, inside the folder
/// [`download_dir`] named, refused when the name is taken there.
///
/// # Errors
/// When `output` names no file.
pub(crate) fn start(
    file: Ed2kFileLink,
    source_hint: Option<ServerEndpoint>,
    output: &Path,
) -> Result<CoreCommand> {
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{} names no file", output.display()))?;
    let cleaned = SafeFileName::clean(name, &FileHash::from_bytes([0; FileHash::BYTE_LEN]));
    anyhow::ensure!(
        cleaned.as_str() == name,
        "{} is not a name core keeps as it is",
        output.display()
    );
    Ok(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint,
        name: cleaned,
        if_taken: NameTaken::Refuse,
    }))
}

fn folder_of(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)
        .with_context(|| format!("resolve output path {}", path.display()))?;
    absolute
        .parent()
        .map(Path::to_path_buf)
        .with_context(|| format!("{} names no file", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outputs_in_one_folder_name_it_and_two_folders_are_refused() {
        let path = rmule_testkit::absolute_path;
        let one = [path("srv/dl/a.bin"), path("srv/dl/b.bin")];
        assert_eq!(download_dir(&one).unwrap(), path("srv/dl"));
        let two = [path("srv/dl/a.bin"), path("srv/other/b.bin")];
        assert!(download_dir(&two).is_err());
    }

    /// The file would land under another name than the one asked for.
    #[test]
    fn a_name_core_would_clean_differently_is_refused() {
        let rmule_primitives::Ed2kLink::File(file) = rmule_primitives::Ed2kLink::parse(
            "ed2k://|file|x.bin|1|0123456789ABCDEF0123456789ABCDEF|/",
        )
        .unwrap() else {
            panic!("a file link");
        };
        assert!(start(file.clone(), None, Path::new("/srv/dl/a.bin")).is_ok());
        assert!(start(file, None, Path::new("/srv/dl/a:b.bin")).is_err());
    }
}
