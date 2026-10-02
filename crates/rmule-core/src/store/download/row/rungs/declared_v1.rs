//! The download seam as store versions 1 to 5 declared it — the row shape
//! with both of its indexes, as a store written before any rung holds them —
//! and a writer of one download in that shape, with a row in every child
//! table, for a test that climbs such a store.

use rmule_primitives::{Ed2kFileLink, Ed2kLink, PartHash, ServerEndpoint, UserHash};
use rmule_store::{Indexed, MultimapIndex, Schema, StoreError, UniqueIndex, WriteTransaction};

use super::DownloadRowV1;
use super::row_enums::{DownloadLifecycleV1, DownloadMetadataOriginV1, VerificationAuthorityV1};
use crate::store::download::row::{
    DISTRUSTED_PEERS, DOWNLOAD_IDS, DistrustedPeerRow, PROVISIONAL_HASHES, ProvisionalPartHashRow,
    VERIFIED_PARTS, VerifiedPartRow,
};
use crate::{DownloadPaths, VerifiedPartRecord};

static PART_PATH_V1: UniqueIndex<&'static str, u64, DownloadRowV1> =
    UniqueIndex::new("download.part_path", |row| row.part_path.as_str());

static IDENTITY_V1: MultimapIndex<([u8; 16], u64), u64, DownloadRowV1> =
    MultimapIndex::new("download.identity", |row| {
        (*row.file_hash.as_bytes(), row.file_size)
    });

static DOWNLOADS_V1_DECLARED: Indexed<u64, DownloadRowV1> =
    Indexed::new("download", &[&PART_PATH_V1, &IDENTITY_V1]);

/// The download seam's tables as store versions 1 to 5 declared them, for a
/// test that builds an older store.
pub(crate) fn schema_v1() -> Schema {
    Schema::new()
        .indexed(&DOWNLOADS_V1_DECLARED)
        .children(&VERIFIED_PARTS)
        .children(&PROVISIONAL_HASHES)
        .children(&DISTRUSTED_PEERS)
}

/// Write `file` as a version-1 store kept a running download verified by a
/// peer's hash set: its row and both index entries, its first part verified,
/// the peer's hashes, and one distrusted peer. Returns the id it was minted.
///
/// # Errors
/// The store's.
pub(crate) fn seed_v1(
    txn: &WriteTransaction,
    file: &Ed2kFileLink,
    server: &ServerEndpoint,
    paths: &DownloadPaths,
    part: VerifiedPartRecord,
    peer_hashes: &[PartHash],
    distrusted: UserHash,
) -> Result<u64, StoreError> {
    let key = DOWNLOAD_IDS.next(txn)?;
    DOWNLOADS_V1_DECLARED.insert(
        txn,
        &key,
        &DownloadRowV1 {
            file_hash: file.file_hash,
            file_size: file.size,
            canonical_link: Ed2kLink::File(file.clone()).to_string(),
            server: server.clone(),
            final_path: paths.final_path().to_string_lossy().into_owned(),
            part_path: paths.part_path().to_string_lossy().into_owned(),
            lifecycle: DownloadLifecycleV1::Active,
            verification_authority: Some(VerificationAuthorityV1::PeerHashSet),
            file_name: file.name.clone(),
            metadata_origin: DownloadMetadataOriginV1::Link,
        },
    )?;
    VERIFIED_PARTS.put(
        txn,
        key,
        part.part_index,
        &VerifiedPartRow::from_record(part),
    )?;
    PROVISIONAL_HASHES.replace(txn, key, peer_hashes.iter().map(ProvisionalPartHashRow::of))?;
    DISTRUSTED_PEERS.replace(
        txn,
        key,
        [DistrustedPeerRow {
            user_hash: *distrusted.as_bytes(),
        }],
    )?;
    Ok(key)
}
