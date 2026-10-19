//! The download row table as store versions 9 to 14 declared it — record
//! version 5 with both of its indexes — and a writer of one row in that
//! shape, for a test that climbs such a store.

use rmule_primitives::{Ed2kFileLink, Ed2kLink};
use rmule_store::{Indexed, MultimapIndex, Schema, StoreError, UniqueIndex, WriteTransaction};

use super::DownloadRowV5;
use super::row_enums::{DownloadLifecycleV5, DownloadMetadataOriginV1};
use crate::DownloadPaths;
use crate::store::download::row::DOWNLOAD_IDS;

static PART_PATH_V5: UniqueIndex<&'static str, u64, DownloadRowV5> =
    UniqueIndex::new("download.part_path", |row| row.part_path.as_str());

static IDENTITY_V5: MultimapIndex<([u8; 16], u64), u64, DownloadRowV5> =
    MultimapIndex::new("download.identity", |row| {
        (*row.file_hash.as_bytes(), row.file_size)
    });

static DOWNLOADS_V5_DECLARED: Indexed<u64, DownloadRowV5> =
    Indexed::new("download", &[&PART_PATH_V5, &IDENTITY_V5]);

/// The download row table as store versions 9 to 14 declared it.
pub(crate) fn schema_v5_rows() -> Schema {
    Schema::new().indexed(&DOWNLOADS_V5_DECLARED)
}

/// Write `file` as a version-14 store kept a queued download at `paths`,
/// with no source hint. Returns the id it was minted.
///
/// # Errors
/// The store's.
pub(crate) fn seed_v5(
    txn: &WriteTransaction,
    file: &Ed2kFileLink,
    paths: &DownloadPaths,
) -> Result<u64, StoreError> {
    let key = DOWNLOAD_IDS.next(txn)?;
    DOWNLOADS_V5_DECLARED.insert(
        txn,
        &key,
        &DownloadRowV5 {
            file_hash: file.file_hash,
            file_size: file.size,
            canonical_link: Ed2kLink::File(file.clone()).to_string(),
            source_hint: None,
            final_path: paths.final_path().to_string_lossy().into_owned(),
            part_path: paths.part_path().to_string_lossy().into_owned(),
            lifecycle: DownloadLifecycleV5::Queued,
            verification_authority: None,
            file_name: file.name.clone(),
            metadata_origin: DownloadMetadataOriginV1::Link,
            failure: None,
        },
    )?;
    Ok(key)
}
