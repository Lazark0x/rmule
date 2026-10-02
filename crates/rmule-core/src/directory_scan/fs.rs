//! The one [`DirectorySource`] that touches the real filesystem: a thin
//! adapter with no decisions in it, save which filesystems give a stable
//! [`FileIdentity`].

use std::fs;
use std::io;
use std::path::Path;

use super::{DirEntry, DirectorySource, EntryKind, FileIdentity, FileStamp};

/// [`DirectorySource`] over `std::fs`. A listing reports a symlink as
/// [`EntryKind::Symlink`] and never follows it.
#[derive(Clone, Copy, Debug, Default)]
pub struct FsDirectorySource;

impl DirectorySource for FsDirectorySource {
    fn list(&self, dir: &Path) -> io::Result<Vec<DirEntry>> {
        let mut listing = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            // `DirEntry::file_type` does not follow a symlink.
            if let Some(listed) = listed(entry.file_name(), entry.file_type(), || entry.metadata())?
            {
                listing.push(listed);
            }
        }
        Ok(listing)
    }

    fn kind(&self, path: &Path) -> io::Result<EntryKind> {
        let meta = fs::symlink_metadata(path)?;
        kind_of(meta.file_type(), || Ok(meta.clone()))
    }

    fn is_folder(&self, path: &Path) -> io::Result<bool> {
        Ok(fs::metadata(path)?.is_dir())
    }

    fn stamp(&self, path: &Path) -> io::Result<FileStamp> {
        stamp_of(&fs::symlink_metadata(path)?)
    }

    fn open(&self, path: &Path) -> io::Result<Box<dyn io::Read + Send>> {
        Ok(Box::new(fs::File::open(path)?))
    }

    fn identity(&self, path: &Path) -> Option<FileIdentity> {
        identity_of(path)
    }
}

/// One entry of a listing, `None` when it was removed between the listing
/// and the look at it: a file renamed away meanwhile is not a failed listing.
fn listed(
    name: std::ffi::OsString,
    file_type: io::Result<fs::FileType>,
    meta: impl FnOnce() -> io::Result<fs::Metadata>,
) -> io::Result<Option<DirEntry>> {
    match file_type.and_then(|file_type| kind_of(file_type, meta)) {
        Ok(kind) => Ok(Some(DirEntry { name, kind })),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// What an entry is, from its type; `meta` is asked only of a regular file.
fn kind_of(
    file_type: fs::FileType,
    meta: impl FnOnce() -> io::Result<fs::Metadata>,
) -> io::Result<EntryKind> {
    Ok(if file_type.is_symlink() {
        EntryKind::Symlink
    } else if file_type.is_dir() {
        EntryKind::Directory
    } else if file_type.is_file() {
        EntryKind::File(stamp_of(&meta()?)?)
    } else {
        EntryKind::Other
    })
}

fn stamp_of(meta: &fs::Metadata) -> io::Result<FileStamp> {
    Ok(FileStamp {
        size: meta.len(),
        modified: meta.modified()?,
    })
}

/// The identity of the regular file at `path`: its device, inode and birth
/// time, on a filesystem [`stable_identities`] vouches for. `created()` is
/// the birth time; it fails where there is none (ext2 and ext3, 128-byte ext4
/// inodes, a kernel without `statx`), and then nothing is carried.
#[cfg(unix)]
fn identity_of(path: &Path) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || !stable_identities(path) {
        return None;
    }
    Some(FileIdentity {
        device: meta.dev(),
        inode: meta.ino(),
        born: meta.created().ok()?,
    })
}

#[cfg(not(unix))]
fn identity_of(_path: &Path) -> Option<FileIdentity> {
    None
}

/// Whether the filesystem `path` lies on keeps a file's inode across a
/// rename and gives it a birth time: APFS and HFS+ on macOS.
#[cfg(target_os = "macos")]
fn stable_identities(path: &Path) -> bool {
    let Ok(stat) = rustix::fs::statfs(path) else {
        return false;
    };
    let name: Vec<u8> = stat
        .f_fstypename
        .iter()
        .take_while(|&&byte| byte != 0)
        .map(|&byte| byte.to_ne_bytes()[0])
        .collect();
    matches!(name.as_slice(), b"apfs" | b"hfs")
}

/// Whether the filesystem `path` lies on keeps a file's inode across a
/// rename and gives it a birth time: ext4, btrfs and XFS on Linux, by their
/// superblock magic. ext2 and ext3 share ext4's magic and have no birth
/// time, which `created()` then refuses.
#[cfg(target_os = "linux")]
fn stable_identities(path: &Path) -> bool {
    const EXT4: u64 = 0xEF53;
    const BTRFS: u64 = 0x9123_683E;
    const XFS: u64 = 0x5846_5342;
    rustix::fs::statfs(path).is_ok_and(|stat| {
        #[allow(clippy::cast_sign_loss, clippy::unnecessary_cast)]
        let magic = (stat.f_type as u64) & 0xFFFF_FFFF;
        matches!(magic, EXT4 | BTRFS | XFS)
    })
}

/// Other platforms give no filesystem rmule has verified.
#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn stable_identities(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;

    use super::listed;

    #[test]
    fn an_entry_removed_while_its_folder_is_listed_is_skipped_and_nothing_else_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("partial.tmp");
        fs::write(&path, b"x").unwrap();
        let file_type = || Ok(fs::symlink_metadata(&path).unwrap().file_type());
        let removed = listed("partial.tmp".into(), file_type(), || {
            Err(io::ErrorKind::NotFound.into())
        });
        assert!(matches!(removed, Ok(None)));
        let untyped = listed(
            "partial.tmp".into(),
            Err(io::ErrorKind::NotFound.into()),
            || unreachable!("no type, no stamp"),
        );
        assert!(matches!(untyped, Ok(None)));
        let refused = listed("partial.tmp".into(), file_type(), || {
            Err(io::ErrorKind::PermissionDenied.into())
        });
        assert_eq!(
            refused.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
            "any other error still fails the listing"
        );
    }
}
