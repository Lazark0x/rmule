//! Where a new download lands: the download directory the Core Settings name,
//! judged by the share guards at the start, under the name the command gives.
//! A command names no folder (ADR-0069), so a file can finish only where
//! core's own rule for sharing it holds (ADR-0101).

use std::path::{Path, PathBuf};

use rmule_primitives::SafeFileName;

use crate::DownloadPaths;
use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::directory_scan::guard_in_place;
use crate::service::{CoreCommandRejectReason, NameTaken};

use super::super::CoreActor;

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// The paths a download named `name` writes, in the download directory
    /// as it stands now, or why it has none: no download directory, or one
    /// the guards refuse where its path leads now.
    pub(super) fn place_download(
        &self,
        name: &SafeFileName,
        if_taken: NameTaken,
    ) -> Result<DownloadPaths, CoreCommandRejectReason> {
        let dir = self
            .directories
            .download_dir
            .as_deref()
            .ok_or(CoreCommandRejectReason::NoDownloadDir)?;
        guard_in_place(dir, &self.directories.guards)
            .map_err(CoreCommandRejectReason::DownloadDirRefused)?;
        Ok(DownloadPaths::from_final_path(match if_taken {
            NameTaken::Refuse => name.path_in(dir),
            NameTaken::Number => free_path(dir, name),
        }))
    }
}

/// `dir/name`, or the first `dir/stem (n).ext` for which neither the file nor
/// its `.part` exists. The numbered form adds only a space, parentheses and
/// digits to a cleaned name, so it stays one component inside `dir`.
fn free_path(dir: &Path, name: &SafeFileName) -> PathBuf {
    let taken = |path: &Path| {
        path.exists()
            || DownloadPaths::from_final_path(path.to_path_buf())
                .part_path()
                .exists()
    };
    let plain = name.path_in(dir);
    if !taken(&plain) {
        return plain;
    }
    let name = name.as_str();
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, Some(ext)),
        _ => (name, None),
    };
    (1..)
        .map(|n| {
            dir.join(match ext {
                Some(ext) => format!("{stem} ({n}).{ext}"),
                None => format!("{stem} ({n})"),
            })
        })
        .find(|path| !taken(path))
        .expect("an unbounded range finds a free name")
}
