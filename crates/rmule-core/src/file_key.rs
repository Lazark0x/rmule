//! Which file a path or an open handle names, as the operating system keys
//! it: the volume the file lies on and the file's number there. On Unix that
//! is the device and inode `stat` and `fstat` report. On Windows it is the
//! volume serial number and file index `GetFileInformationByHandle` reports,
//! read through `winapi-util` because the workspace forbids `unsafe`; a path
//! is opened for it the way std's own `metadata` opens one, asking for no
//! access and sharing read, write and delete, with backup semantics so a
//! directory opens too. The **Held Part File** compares keys to see that the
//! path still names the file it holds; the shared-directory guards compare
//! volumes to see a mount point.

use std::io;
use std::path::Path;

/// The volume a file lies on and its number there. Two keys are equal when
/// they name the same file; what each file system guarantees beyond that is
/// in the Held Part File's module (`content/held.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileKey {
    /// The device (Unix) or volume serial number (Windows).
    pub(crate) volume: u64,
    /// The inode (Unix) or file index (Windows).
    pub(crate) file: u64,
}

#[cfg(unix)]
impl FileKey {
    fn of_metadata(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            volume: meta.dev(),
            file: meta.ino(),
        }
    }

    /// The key of the file or directory at `path`, following a final link.
    /// `NotFound` when nothing is there.
    pub(crate) fn at(path: &Path) -> io::Result<Self> {
        std::fs::metadata(path).map(|meta| Self::of_metadata(&meta))
    }

    /// [`Self::at`], off the runtime's threads.
    pub(crate) async fn at_async(path: &Path) -> io::Result<Self> {
        tokio::fs::metadata(path)
            .await
            .map(|meta| Self::of_metadata(&meta))
    }

    /// The key of the file `file` holds open.
    pub(crate) async fn of_open(file: &tokio::fs::File) -> io::Result<Self> {
        file.metadata().await.map(|meta| Self::of_metadata(&meta))
    }
}

#[cfg(windows)]
impl FileKey {
    fn of_handle(file: &std::fs::File) -> io::Result<Self> {
        let info = winapi_util::file::information(file)?;
        Ok(Self {
            volume: info.volume_serial_number(),
            file: info.file_index(),
        })
    }

    /// The key of the file or directory at `path`, following a final link.
    /// `NotFound` when nothing is there.
    pub(crate) fn at(path: &Path) -> io::Result<Self> {
        use std::os::windows::fs::OpenOptionsExt;
        // `FILE_FLAG_BACKUP_SEMANTICS` (`winbase.h`): lets the open take a
        // directory.
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let file = std::fs::OpenOptions::new()
            .access_mode(0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        Self::of_handle(&file)
    }

    /// [`Self::at`], off the runtime's threads.
    pub(crate) async fn at_async(path: &Path) -> io::Result<Self> {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || Self::at(&path))
            .await
            .map_err(io::Error::other)?
    }

    /// The key of the file `file` holds open, read through a second handle
    /// to it.
    pub(crate) async fn of_open(file: &tokio::fs::File) -> io::Result<Self> {
        let file = file.try_clone().await?.into_std().await;
        tokio::task::spawn_blocking(move || Self::of_handle(&file))
            .await
            .map_err(io::Error::other)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_path_and_a_handle_on_it_key_the_same_file_and_another_file_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("held.bin");
        let other = dir.path().join("other.bin");
        std::fs::write(&path, b"held").unwrap();
        std::fs::write(&other, b"other").unwrap();
        let open = tokio::fs::File::open(&path).await.unwrap();

        let held = FileKey::of_open(&open).await.unwrap();
        assert_eq!(FileKey::at(&path).unwrap(), held);
        assert_eq!(FileKey::at_async(&path).await.unwrap(), held);
        let another = FileKey::at(&other).unwrap();
        assert_ne!(another, held);
        assert_eq!(another.volume, held.volume, "one directory, one volume");

        std::fs::rename(&other, &path).unwrap();
        assert_eq!(FileKey::at(&path).unwrap(), another);
        assert_eq!(FileKey::of_open(&open).await.unwrap(), held);
    }

    #[test]
    fn a_directory_keys_on_the_volume_of_the_files_in_it() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("inside.bin");
        std::fs::write(&file, b"x").unwrap();
        let key = FileKey::at(dir.path()).unwrap();
        assert_eq!(key.volume, FileKey::at(&file).unwrap().volume);
        assert_ne!(key.file, FileKey::at(&file).unwrap().file);
    }

    #[test]
    fn nothing_at_the_path_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let error = FileKey::at(&dir.path().join("absent")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
