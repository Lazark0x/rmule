//! Where a new download lands: the download directory the Core Settings name,
//! judged by the share guards at the start, under the name the command gives,
//! with its part file `<name>.part` in the Temp Directory (ADR-0115). A
//! command names no folder (ADR-0069), so a file can finish only where core's
//! own rule for sharing it holds (ADR-0101), and fills only where nothing is
//! shared.
//!
//! A name is taken by what stands on the disk and by what any live row holds,
//! compared as the strictest volume folds: a path comes from a peer's name, so
//! two rows can spell one file, and the second's run would open the first's.

use std::collections::HashSet;
use std::path::Path;

use rmule_primitives::{Ed2kFileLink, OLD_MAX_FILE_SIZE, SafeFileName, fold_as_a_volume};

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::service::{CoreCommandRejectReason, NameTaken};
use crate::storage::DownloadRepository;
use crate::{DownloadPaths, DurableDownloadRecord};

use super::super::CoreActor;

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// The paths the download of `file` named `name` writes, in the download
    /// directory and the Temp Directory as they stand now, or why it has
    /// none: no download directory, one the guards refuse where its path
    /// leads now, a file those volumes cannot hold, or a name taken when the
    /// command refuses one. A core with no Temp Directory places the part
    /// file beside its final path.
    pub(super) fn place_download(
        &self,
        file: &Ed2kFileLink,
        name: &SafeFileName,
        if_taken: NameTaken,
    ) -> Result<DownloadPaths, CoreCommandRejectReason> {
        let dir = self
            .directories
            .download_dir
            .as_deref()
            .ok_or(CoreCommandRejectReason::NoDownloadDir)?;
        self.directories
            .guard_in_place(dir)
            .map_err(CoreCommandRejectReason::DownloadDirRefused)?;
        let parts = self.directories.temp_dir.as_deref().unwrap_or(dir);
        if file.size > OLD_MAX_FILE_SIZE && [dir, parts].into_iter().any(lies_on_fat) {
            return Err(CoreCommandRejectReason::FileTooLargeForVolume);
        }
        let live = self
            .wiring
            .store
            .live_downloads()
            .map_err(|_| CoreCommandRejectReason::DownloadStoreFailed)?;
        // A row for this very file is the store's to refuse by its identity.
        let others: Vec<&DurableDownloadRecord> = live
            .iter()
            .filter(|row| row.file_hash() != file.file_hash || row.file_size() != file.size)
            .collect();
        let rows = HeldNames::of(others.iter().map(|row| row.paths()));
        match if_taken {
            NameTaken::Refuse => {
                let paths = placed(dir, parts, name.as_str());
                if crate::free_name::stands_at(paths.part_path()) || rows.hold(&paths) {
                    return Err(CoreCommandRejectReason::DownloadPathConflict);
                }
                Ok(paths)
            }
            NameTaken::Number => Ok(free_paths(dir, parts, name, &rows)),
        }
    }
}

/// Whether `dir` lies on FAT. A volume that cannot say is no proof, and the
/// download's write says what is wrong.
fn lies_on_fat(dir: &Path) -> bool {
    rmule_os::volume::is_fat(dir).unwrap_or(false)
}

/// The paths the live rows hold, as the strictest volume folds them.
struct HeldNames(HashSet<String>);

impl HeldNames {
    fn of<'a>(rows: impl Iterator<Item = &'a DownloadPaths>) -> Self {
        let folded_paths =
            rows.flat_map(|paths| [folded(paths.final_path()), folded(paths.part_path())]);
        Self(folded_paths.collect())
    }

    /// Whether a row holds the final path or the part path of `paths`.
    fn hold(&self, paths: &DownloadPaths) -> bool {
        self.0.contains(&folded(paths.final_path())) || self.0.contains(&folded(paths.part_path()))
    }
}

/// `path` as the strictest volume compares it.
fn folded(path: &Path) -> String {
    fold_as_a_volume(&path.to_string_lossy())
}

/// `dir/name`, with its part file `parts/name.part`.
fn placed(dir: &Path, parts: &Path, name: &str) -> DownloadPaths {
    DownloadPaths::new(dir.join(name), parts.join(format!("{name}.part")))
}

/// [`placed`] under `name`, or under the first free `stem (n).ext`
/// ([`crate::free_name`]) for which neither the file nor its part file
/// exists and no row holds either, keeping `name` as the Download Name the
/// completion move numbers from.
fn free_paths(dir: &Path, parts: &Path, name: &SafeFileName, rows: &HeldNames) -> DownloadPaths {
    let free = |paths: &DownloadPaths| {
        !crate::free_name::stands_at(paths.final_path())
            && !crate::free_name::stands_at(paths.part_path())
            && !rows.hold(paths)
    };
    let name = name.as_str();
    let plain = placed(dir, parts, name);
    if free(&plain) {
        return plain;
    }
    (1..)
        .map(|n| placed(dir, parts, &crate::free_name::numbered(name, n)).named(name))
        .find(free)
        .expect("an unbounded range finds a free name")
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::symlink;

    use rmule_primitives::{FileHash, SafeFileName};

    use super::{HeldNames, free_paths, placed};

    /// A dangling link stands at its name, at either path: the move's
    /// exclusive rename would refuse it, so a placement passes it by.
    #[test]
    fn a_dangling_link_at_either_path_takes_the_next_number() {
        let dir = tempfile::tempdir().unwrap();
        let name = SafeFileName::clean("film.mkv", &FileHash::from_bytes([1; FileHash::BYTE_LEN]));
        symlink(dir.path().join("gone"), dir.path().join("film.mkv")).unwrap();
        symlink(
            dir.path().join("gone"),
            dir.path().join("film (1).mkv.part"),
        )
        .unwrap();

        let paths = free_paths(
            dir.path(),
            dir.path(),
            &name,
            &HeldNames::of(std::iter::empty()),
        );

        assert_eq!(paths.final_path(), dir.path().join("film (2).mkv"));
        assert_eq!(paths.part_path(), dir.path().join("film (2).mkv.part"));
    }

    /// exFAT folds a name on disk itself, whatever the rows say.
    #[test]
    #[ignore = "by hand, RMULE_TEST_VOLUME on an exFAT volume"]
    fn a_part_file_the_volume_folds_onto_the_name_takes_the_next_number() {
        let volume = std::env::var_os("RMULE_TEST_VOLUME").expect("RMULE_TEST_VOLUME");
        let dir = tempfile::tempdir_in(volume).unwrap();
        let hash = FileHash::from_bytes([1; FileHash::BYTE_LEN]);
        let name = SafeFileName::clean("film.mkv", &hash);
        std::fs::write(dir.path().join("FILM.MKV.part"), b"held").unwrap();

        let paths = free_paths(
            dir.path(),
            dir.path(),
            &name,
            &HeldNames::of(std::iter::empty()),
        );

        assert_eq!(paths.part_path(), dir.path().join("film (1).mkv.part"));
    }

    /// A row with no file yet holds its name as well as a file does, and two
    /// spellings the volume folds onto one are that name.
    #[test]
    fn a_row_that_folds_onto_the_name_takes_the_next_number() {
        let dir = tempfile::tempdir().unwrap();
        let hash = FileHash::from_bytes([1; FileHash::BYTE_LEN]);
        let name = SafeFileName::clean("film.mkv", &hash);
        let row = placed(dir.path(), dir.path(), "FILM.MKV");
        let rows = HeldNames::of(std::iter::once(&row));

        let paths = free_paths(dir.path(), dir.path(), &name, &rows);

        assert_eq!(paths.final_path(), dir.path().join("film (1).mkv"));
    }
}
