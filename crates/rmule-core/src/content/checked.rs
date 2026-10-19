//! A read of a **Served Download**'s bytes (ADR-0113 §"Reading a part
//! file"): the file is opened, the opened handle's key — and its length and
//! modification time while no run writes it — compared with the entry's
//! **Part File Identity**, and only then read, through that same handle, so
//! no byte of a file that is not the one the Verified Range was read from is
//! ever sent. A path that names nothing gives way to the download's other
//! path once: the completion move keeps the bytes at one of the two at every
//! instant (ADR-0115).

use std::fs::File;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};
use std::path::Path;

use super::{ContentFileStore, on_pool};
use crate::file_key::FileKey;
use crate::served_downloads::ReadCheck;

/// Why a checked read sent nothing.
#[derive(Debug)]
pub(crate) enum CheckedReadError {
    /// The file opened is not the one the identity names, or its identity
    /// could not be read.
    Changed,
    /// Neither path could be opened, or the read through the handle failed.
    Unreadable(io::Error),
}

impl ContentFileStore {
    /// Read exactly `len` bytes at `offset` from the file at `path` — or,
    /// when nothing is there, at `check.other` — once its handle is proven
    /// to be the file `check.identity` names. An entry holding no identity
    /// reads nothing, and a `len` over three blocks is refused before
    /// anything is opened or allocated (ADR-0031).
    pub(crate) async fn read_checked(
        path: &Path,
        check: &ReadCheck,
        offset: u64,
        len: u64,
    ) -> Result<Vec<u8>, CheckedReadError> {
        let len = super::read_len(len).map_err(CheckedReadError::Unreadable)?;
        let (path, check) = (path.to_path_buf(), check.clone());
        on_pool(move || read_checked_blocking(&path, &check, offset, len)).await
    }
}

fn read_checked_blocking(
    path: &Path,
    check: &ReadCheck,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, CheckedReadError> {
    let mut file = open_either(path, &check.other).map_err(CheckedReadError::Unreadable)?;
    let opened = FileKey::of_open(&file).and_then(|key| Ok((key, file.metadata()?)));
    let Ok((key, meta)) = opened else {
        return Err(CheckedReadError::Changed);
    };
    if !check
        .identity
        .is_some_and(|identity| identity.holds(key, &meta))
    {
        return Err(CheckedReadError::Changed);
    }
    let mut bytes = vec![0; len];
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(&mut bytes))
        .map_err(CheckedReadError::Unreadable)?;
    Ok(bytes)
}

/// The file at `path`, or at `other` when `path` names nothing.
fn open_either(path: &Path, other: &Path) -> io::Result<File> {
    match File::open(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => File::open(other),
        opened => opened,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::served_downloads::PartFileIdentity;

    fn identity_of(path: &Path, at_rest: bool) -> PartFileIdentity {
        let file = File::open(path).unwrap();
        let key = FileKey::of_open(&file).unwrap();
        if at_rest {
            PartFileIdentity::at_rest(key, &file.metadata().unwrap()).unwrap()
        } else {
            PartFileIdentity::while_written(key)
        }
    }

    fn check(identity: PartFileIdentity, other: &Path) -> ReadCheck {
        ReadCheck {
            identity: Some(identity),
            other: other.to_path_buf(),
        }
    }

    #[tokio::test]
    async fn a_file_moved_to_the_other_path_is_read_from_there() {
        let dir = tempfile::tempdir().unwrap();
        let (part, done) = (dir.path().join("a.part"), dir.path().join("a.bin"));
        std::fs::write(&part, b"verified bytes").unwrap();
        let check = check(identity_of(&part, true), &done);
        std::fs::rename(&part, &done).unwrap();

        let read = ContentFileStore::read_checked(&part, &check, 9, 5).await;
        assert_eq!(read.unwrap(), b"bytes");
    }

    #[tokio::test]
    async fn a_read_over_three_blocks_is_refused_though_the_file_holds_it() {
        let dir = tempfile::tempdir().unwrap();
        let (part, done) = (dir.path().join("a.part"), dir.path().join("a.bin"));
        let cap = rmule_peer::MAX_REQUESTED_RANGE;
        File::create(&part).unwrap().set_len(2 * cap).unwrap();
        let check = check(identity_of(&part, true), &done);

        let read = ContentFileStore::read_checked(&part, &check, 0, cap).await;
        assert_eq!(read.unwrap().len() as u64, cap);
        let read = ContentFileStore::read_checked(&part, &check, 0, cap + 1).await;
        assert!(matches!(
            read,
            Err(CheckedReadError::Unreadable(error)) if error.kind() == ErrorKind::InvalidInput
        ));
    }

    #[tokio::test]
    async fn another_file_at_the_path_reads_nothing_and_no_file_at_either_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let (part, done) = (dir.path().join("a.part"), dir.path().join("a.bin"));
        std::fs::write(&part, b"verified bytes").unwrap();
        let check = check(identity_of(&part, false), &done);
        let replacement = dir.path().join("b.part");
        std::fs::write(&replacement, b"other bytes!!!").unwrap();
        std::fs::rename(&replacement, &part).unwrap();

        let read = ContentFileStore::read_checked(&part, &check, 0, 5).await;
        assert!(matches!(read, Err(CheckedReadError::Changed)));

        std::fs::remove_file(&part).unwrap();
        let read = ContentFileStore::read_checked(&part, &check, 0, 5).await;
        assert!(matches!(
            read,
            Err(CheckedReadError::Unreadable(error)) if error.kind() == ErrorKind::NotFound
        ));
    }
}
