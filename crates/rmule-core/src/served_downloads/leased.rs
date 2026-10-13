//! A Served Download installed and leased to a run: the setup the serve and
//! Kad tests that read a Partial Share start from.

use std::path::PathBuf;
use std::sync::Arc;

use rmule_primitives::{ED2K_PART_SIZE, Ed2kFileLink, Ed2kText, FileHash, PartHash};

use super::{RunLease, ServedDownloads};
use crate::download::RunNumber;
use crate::storage::DownloadRepository;
use crate::store::download::DurableDownloadRepository;
use crate::{DownloadPaths, DurableDownloadRecord, DurableStore, SharedFileEntry};

/// The size of a [`leased`] download: two whole parts and five bytes, so
/// three parts and three hashes.
pub(crate) const SIZE: u64 = 2 * ED2K_PART_SIZE + 5;

/// What [`leased`] built.
pub(crate) struct Leased {
    /// The in-memory Durable Store the download's row lives in.
    pub(crate) store: Arc<DurableStore>,
    /// The download's row.
    pub(crate) record: DurableDownloadRecord,
    /// The cell holding its entry.
    pub(crate) cell: ServedDownloads,
    /// Run 1's lease on the entry.
    pub(crate) lease: RunLease,
    /// Its whole part hash set, part `i`'s hash sixteen bytes of `i`.
    pub(crate) set: Vec<PartHash>,
}

/// A [`SIZE`]-byte download of `file_hash` whose destination is
/// `final_path`, named after it, installed with its whole set and handed to
/// run 1. Its range is empty; nothing is written to disk.
pub(crate) fn leased(file_hash: FileHash, final_path: PathBuf) -> Leased {
    let set: Vec<PartHash> = (0..3)
        .map(|part| PartHash::from_bytes([part; 16]))
        .collect();
    let store = rmule_testkit::memory_store();
    let link = Ed2kFileLink {
        name: Ed2kText::from_utf8(SharedFileEntry::name_of(&final_path)),
        size: SIZE,
        file_hash,
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let paths = DownloadPaths::from_final_path(final_path);
    let record = DurableDownloadRepository::new(store.clone())
        .create_download(&link, None, &paths)
        .unwrap();
    let cell = ServedDownloads::default();
    assert!(cell.install(&record, &set));
    let lease = cell.hand_to_run(file_hash, RunNumber::new(1)).unwrap();
    Leased {
        store,
        record,
        cell,
        lease,
        set,
    }
}
