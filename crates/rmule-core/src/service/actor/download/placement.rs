//! Where a new download lands: the download directory the Core Settings name,
//! judged by the share guards at the start, under the name the command gives,
//! with its part file `<name>.part` in the Temp Directory (ADR-0115). A
//! command names no folder (ADR-0069), so a file can finish only where core's
//! own rule for sharing it holds (ADR-0101), and fills only where nothing is
//! shared.

use std::path::Path;

use rmule_primitives::SafeFileName;

use crate::DownloadPaths;
use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
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
    /// and the Temp Directory as they stand now, or why it has none: no
    /// download directory, or one the guards refuse where its path leads
    /// now. A core with no Temp Directory places the part file beside its
    /// final path.
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
        self.directories
            .guard_in_place(dir)
            .map_err(CoreCommandRejectReason::DownloadDirRefused)?;
        let parts = self.directories.temp_dir.as_deref().unwrap_or(dir);
        Ok(match if_taken {
            NameTaken::Refuse => placed(dir, parts, name.as_str()),
            NameTaken::Number => free_paths(dir, parts, name),
        })
    }
}

/// `dir/name`, with its part file `parts/name.part`.
fn placed(dir: &Path, parts: &Path, name: &str) -> DownloadPaths {
    DownloadPaths::new(dir.join(name), parts.join(format!("{name}.part")))
}

/// [`placed`] under `name`, or under the first free `stem (n).ext`
/// ([`crate::free_name`]) for which neither the file nor its part file
/// exists.
fn free_paths(dir: &Path, parts: &Path, name: &SafeFileName) -> DownloadPaths {
    let free = |paths: &DownloadPaths| !paths.final_path().exists() && !paths.part_path().exists();
    let name = name.as_str();
    let plain = placed(dir, parts, name);
    if free(&plain) {
        return plain;
    }
    (1..)
        .map(|n| placed(dir, parts, &crate::free_name::numbered(name, n)))
        .find(free)
        .expect("an unbounded range finds a free name")
}
