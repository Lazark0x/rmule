//! The Shared File Registry: what this session offers the network, whether an
//! operator shared it explicitly or a completed download auto-shared itself
//! (ADR-0031). [`SharedFileRegistry`] is the store seam; the auto-share path
//! here is the join point where the download and serve halves of a session meet.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rmule_primitives::{FileHash, PartHash};
use tokio::sync::mpsc;

use crate::registry_check::{WithheldReason, WithheldRows};
use crate::service::{CoreEvent, DownloadId, ServeEvent};
use crate::storage::DownloadRepository;
use crate::{CoreError, DownloadLifecycle, DurableDownloadRecord};

/// How a file came to be shared. Distinguishes a row a lone-file share wrote
/// before the **Shared Directory List** from a download that auto-registered
/// on completion and a file a directory's scan found.
// Durable: the store's `shared_file` record carries it as it stands
// (ADR-0083), rather than a mirror enum in the store seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ShareSource {
    /// A lone-file share named the path. Nothing writes it now (a file is
    /// shared by sharing its directory, ADR-0101); a stored row keeps it.
    Explicit,
    /// A download finished and registered its own output. Unsharing it does not
    /// delete the file.
    CompletedDownload,
    /// The **Download Directory Scan** found the file under the download
    /// directory and hashed it (ADR-0102).
    DownloadDirectory,
}

/// One row of the **Shared File Registry**: a file we serve, identified by
/// its **ED2K File Hash**.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedFileEntry {
    /// The row's key — the file's ED2K content identity. Sharing the same
    /// content twice upserts rather than duplicating.
    pub file_hash: FileHash,
    /// The file's exact size in bytes; with the hash it forms the eD2k identity
    /// a peer matches against.
    pub file_size: u64,
    /// Where the bytes are read from when a peer is served. The file must stay
    /// there for the share to work.
    pub path: PathBuf,
    /// The name announced to servers and peers, taken from the path's file
    /// name.
    pub name: String,
    /// Whether an operator shared it or a completed download registered itself.
    pub source: ShareSource,
    /// The file's ED2K part hash set, answered verbatim to a peer's
    /// `OP_HASHSETREQUEST`. Empty for files below one part — they have
    /// no part hash set, only a file hash.
    pub part_hashes: Vec<PartHash>,
    /// The file's modification time when it was hashed — with the path and
    /// the size, what the **Hash Trust Rule** compares (ADR-0102). `None` on
    /// a row older than the field, which the rule never trusts.
    pub modified: Option<SystemTime>,
}

impl SharedFileEntry {
    /// The name a row whose file is at `path` is announced under: the path's
    /// file name, empty for a path that has none.
    pub(crate) fn name_of(path: &Path) -> String {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Build a registry entry from a download whose finished file is in place
    /// at `path`, the destination its completion move chose (ADR-0115). The
    /// record already carries the verified file hash, size and part hash
    /// set, so nothing is read but the file's modification time.
    pub(crate) fn from_completed_download(
        record: &DurableDownloadRecord,
        path: &Path,
        part_hashes: Vec<PartHash>,
    ) -> Self {
        Self {
            file_hash: record.file_hash(),
            file_size: record.file_size(),
            path: path.to_path_buf(),
            name: Self::name_of(path),
            source: ShareSource::CompletedDownload,
            part_hashes,
            modified: modified_time(path),
        }
    }
}

/// The file's modification time as the share reads it, or `None` when it
/// cannot be read — a row the Hash Trust Rule then re-hashes rather than one
/// it trusts wrongly.
pub(crate) fn modified_time(path: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
}

/// What became of a completing download's file: its registry row is
/// written, and either offered or withheld.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AutoShared {
    /// The row is offered.
    Offered(FileHash),
    /// The row lies under a shared directory the guards refuse (ADR-0101),
    /// the download directory among them: it is withheld as refused and
    /// never offered while the refusal stands.
    Refused(FileHash),
}

/// Auto-share a download whose finished file is in place into the **Shared
/// File Registry** (ADR-0031), the join point where the download and serve
/// halves meet: the completion move's in-place step (ADR-0115) registers the
/// file at `path` from the download record, so the serve side answers probes
/// for it. A load miss or any lifecycle but `Completing` is a no-op returning
/// `None`.
///
/// A file whose path `refuses` names lies under a refused entry: its row is
/// withheld as refused in `withheld` before the row is written, so no offer
/// read between the two ever holds it, and `FileWithheld` is said in place of
/// `FileShared`.
///
/// The per-part hash authority the auto-shared file answers hash-set probes
/// with is resolved behind the repository seam by
/// [`DownloadRepository::hash_authority`] — link > provisional >
/// none — so no storage-model knowledge leaks into the actor. Returns what
/// became of the row, so the caller fires the serve-activity and
/// Kad-publisher share-set triggers — and mirrors an offered row into the
/// file-known predicate — exactly once per successful auto-share.
pub(crate) async fn auto_share_completed_download<R, G>(
    download_id: DownloadId,
    path: &Path,
    store: &R,
    registry: &G,
    refuses: impl FnOnce(&Path) -> bool,
    withheld: &WithheldRows,
    evt_tx: &mpsc::Sender<CoreEvent>,
) -> Option<AutoShared>
where
    R: DownloadRepository,
    G: SharedFileRegistry,
{
    // The record already holds the verified file hash and size, so beyond
    // the completion gate this needs no re-read.
    let record = match store.load_download(download_id) {
        Ok(record) if record.lifecycle() == DownloadLifecycle::Completing => record,
        _ => return None,
    };
    // Ask the seam one question — the effective per-part authority — and map its
    // answer to the hashes the auto-shared file replies to hash-set probes with.
    let part_hashes = match store.hash_authority(download_id) {
        Ok(authority) => authority.into_part_hashes(),
        Err(error) => {
            tracing::warn!(
                download_id = download_id.as_u64(),
                %error,
                "resolving hash authority for auto-share failed; \
                 auto-shared file will answer an empty set",
            );
            Vec::new()
        }
    };
    let entry = SharedFileEntry::from_completed_download(&record, path, part_hashes);
    let file_hash = entry.file_hash;
    let refused = refuses(&entry.path).then(|| {
        let (was, since) = (withheld.get(file_hash), SystemTime::now());
        withheld.withhold(file_hash, WithheldReason::Refused, since);
        (was, since)
    });
    match registry.share(entry) {
        Ok(()) => {
            let (event, shared) = match refused {
                None => {
                    tracing::info!(
                        download_id = download_id.as_u64(),
                        file_hash = %file_hash.to_hex_upper(),
                        "completed download auto-shared",
                    );
                    (
                        ServeEvent::FileShared { file_hash },
                        AutoShared::Offered(file_hash),
                    )
                }
                Some((_, since)) => {
                    tracing::info!(
                        download_id = download_id.as_u64(),
                        file_hash = %file_hash.to_hex_upper(),
                        "completed download withheld: its folder is refused",
                    );
                    let event = ServeEvent::FileWithheld {
                        file_hash,
                        reason: WithheldReason::Refused,
                        since,
                    };
                    (event, AutoShared::Refused(file_hash))
                }
            };
            let _ = evt_tx.send(event.into()).await;
            Some(shared)
        }
        // No command issuer to reject to on auto-share, but a durable registry
        // can fail mid-write; surface it in diagnostics rather than dropping it
        // silently. No row was written, so the mark goes back to what it was.
        Err(error) => {
            if let Some((was, _)) = refused {
                withheld.restore(file_hash, was);
            }
            tracing::warn!(
                download_id = download_id.as_u64(),
                file_hash = %file_hash.to_hex_upper(),
                %error,
                "failed to auto-share completed download",
            );
            None
        }
    }
}

/// The durable serve source of truth (ADR-0031). A new abstraction, not a
/// widening of `DownloadRepository`. Keyed by content identity, so sharing
/// the same file twice upserts.
pub trait SharedFileRegistry: Send + Sync + 'static {
    /// Add or replace the row for `entry`'s file hash. An upsert, so re-sharing
    /// a file with a new path just moves it. The content is on disk again, so
    /// its hash leaves the **Had Set** in the same step.
    fn share(&self, entry: SharedFileEntry) -> Result<(), CoreError>;

    /// Stop serving `file_hash`; returns whether a row was removed. The file
    /// is still on disk, or changed: its hash does not join the **Had Set**.
    fn unshare(&self, file_hash: FileHash) -> Result<bool, CoreError>;

    /// The file behind `file_hash`'s row is gone from `path`: the row leaves
    /// and its hash joins the **Had Set**, in one step (ADR-0100, "The Had
    /// Set"). Only a row still at `path` leaves; one that moved meanwhile is
    /// left alone. Returns whether a row was removed.
    fn gone(&self, file_hash: FileHash, path: &Path) -> Result<bool, CoreError>;

    /// The row for `file_hash`, or `None` when we do not share it — which is
    /// what turns a peer's file request into `OP_FILENOTFOUND`. A row that is
    /// there is whole: its `part_hashes` is the file's stored set.
    fn get(&self, file_hash: FileHash) -> Result<Option<SharedFileEntry>, CoreError>;

    /// Every shared row, each whole as [`get`](Self::get)'s is. This is what
    /// an `OP_OFFERFILES` announce is built from, so its size is the
    /// announce's file count — and what the serve side snapshots, so a row
    /// listed after a restart answers a hash-set probe with the set it was
    /// shared with.
    fn list(&self) -> Result<Vec<SharedFileEntry>, CoreError>;

    /// The stored ED2K part hash set for `file_hash`, or `None` if not
    /// shared — the projection of [`get`](Self::get) for a caller that wants
    /// only the set. An empty `Vec` means a shared file below one part (no
    /// set).
    fn hash_set(&self, file_hash: FileHash) -> Result<Option<Vec<PartHash>>, CoreError>;
}

#[cfg(test)]
mod tests {
    use super::{SharedFileRegistry, auto_share_completed_download};
    use crate::registry_check::WithheldRows;
    use crate::storage::DownloadRepository;
    use crate::store::download::DurableDownloadRepository;
    use crate::store::registry::DurableSharedFileRegistry;
    use crate::{DownloadId, DownloadLifecycle, DownloadPaths};
    use rmule_primitives::{
        ED2K_PART_SIZE, Ed2kFileLink, Ed2kText, FileHash, FileHashSummary, PartHash, ServerEndpoint,
    };
    use std::path::Path;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn server() -> ServerEndpoint {
        ServerEndpoint::new("127.0.0.1", 4661).unwrap()
    }

    /// Drive one download to `Completing` — its finished file in place,
    /// its row not yet written — and return its id.
    fn complete(
        store: &DurableDownloadRepository,
        link: &Ed2kFileLink,
        dir: &Path,
        name: &str,
    ) -> DownloadId {
        let id = DownloadRepository::create_download(
            store,
            link,
            Some(&server()),
            &DownloadPaths::from_final_path(dir.join(name)),
            None,
        )
        .unwrap()
        .id();
        store.set_lifecycle(id, DownloadLifecycle::Active).unwrap();
        store
            .set_lifecycle(id, DownloadLifecycle::Completing)
            .unwrap();
        id
    }

    #[tokio::test]
    async fn auto_share_registers_the_link_authority_part_hash_set() {
        // Two parts, so the link carries a real `p=` set — the authority a
        // completed link download answers hash-set probes with.
        let mut bytes = vec![0xAB; ED2K_PART_SIZE as usize];
        bytes.extend_from_slice(b"tail");
        let summary = FileHashSummary::digest_bytes(&bytes);
        let link = Ed2kFileLink {
            name: Ed2kText::from_utf8("autoshare-link.bin"),
            size: summary.file_size(),
            file_hash: summary.file_hash(),
            part_hash_set: summary.part_hash_set().cloned(),
            aich_root: None,
            ipv6_sources: Vec::new(),
            sources: Default::default(),
        };
        let expected = link.part_hash_set.as_ref().unwrap().hashes().to_vec();

        let dir = tempfile::tempdir().unwrap();
        let handle = rmule_testkit::memory_store();
        let store = DurableDownloadRepository::new(handle.clone());
        let id = complete(&store, &link, dir.path(), "autoshare-link.bin");
        let store = Arc::new(store);
        let registry = DurableSharedFileRegistry::new(handle);
        let observed = registry.clone();
        let registry = Arc::new(registry);
        let (evt_tx, _evt_rx) = mpsc::channel(4);

        assert!(
            auto_share_completed_download(
                id,
                store.load_download(id).unwrap().paths().final_path(),
                &*store,
                &*registry,
                |_| false,
                &WithheldRows::default(),
                &evt_tx
            )
            .await
            .is_some()
        );
        // The link's `p=` set — not an empty provisional set — is what the
        // auto-shared file answers hash-set probes with.
        assert_eq!(observed.hash_set(link.file_hash).unwrap(), Some(expected));
    }

    #[tokio::test]
    async fn auto_share_registers_the_provisional_authority_part_hashes() {
        // A hashless link carries no `p=` set, so the peer hashes recorded after
        // the fact are the authority the completed download shares.
        let peer_hashes = vec![
            PartHash::from_bytes([0x11; PartHash::BYTE_LEN]),
            PartHash::from_bytes([0x22; PartHash::BYTE_LEN]),
        ];
        let link = Ed2kFileLink {
            name: Ed2kText::from_utf8("autoshare-provisional.bin"),
            size: ED2K_PART_SIZE + 4,
            file_hash: FileHash::from_bytes([0x33; FileHash::BYTE_LEN]),
            part_hash_set: None,
            aich_root: None,
            ipv6_sources: Vec::new(),
            sources: Default::default(),
        };

        let dir = tempfile::tempdir().unwrap();
        let handle = rmule_testkit::memory_store();
        let store = DurableDownloadRepository::new(handle.clone());
        let id = DownloadRepository::create_download(
            &store,
            &link,
            Some(&server()),
            &DownloadPaths::from_final_path(dir.path().join("autoshare-provisional.bin")),
            None,
        )
        .unwrap()
        .id();
        store
            .record_provisional_part_hashes(id, &peer_hashes)
            .unwrap();
        store.set_lifecycle(id, DownloadLifecycle::Active).unwrap();
        store
            .set_lifecycle(id, DownloadLifecycle::Completing)
            .unwrap();
        let store = Arc::new(store);
        let registry = DurableSharedFileRegistry::new(handle);
        let observed = registry.clone();
        let registry = Arc::new(registry);
        let (evt_tx, _evt_rx) = mpsc::channel(4);

        assert!(
            auto_share_completed_download(
                id,
                store.load_download(id).unwrap().paths().final_path(),
                &*store,
                &*registry,
                |_| false,
                &WithheldRows::default(),
                &evt_tx
            )
            .await
            .is_some()
        );
        assert_eq!(
            observed.hash_set(link.file_hash).unwrap(),
            Some(peer_hashes)
        );
    }
}
