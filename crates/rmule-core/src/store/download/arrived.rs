//! The **Arrived Checkpoint** in the store (ADR-0117 §4): one row per part in
//! flight, keyed by `(download id, part index)`, its Arrived Ranges and the
//! writers of each cell. A row claims bytes the part file already holds on
//! disk: the run syncs the file before it asks for this write. A row lives
//! beside an unverified part of a row that still holds its place: the record
//! of a verified part removes it, and a write for a part already recorded or a
//! finished row writes nothing.

use std::net::IpAddr;

use rmule_peer::PartIndex;
use rmule_primitives::{Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, UserHash};
use rmule_store::{Children, Record, StoreError, WriteTransaction};
use serde::{Deserialize, Serialize};

use super::row::VERIFIED_PARTS;
use super::{DurableDownloadRepository, read_row};
use crate::assembly::{ArrivedPart, ArrivedWriter};
use crate::{CoreError, DownloadId};

/// One writer of a part as the store holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ArrivedWriterRow {
    ip: IpAddr,
    port: u16,
    user_hash: Option<[u8; UserHash::BYTE_LEN]>,
}

/// One part in flight, keyed by `(download id, part index)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ArrivedPartRow {
    /// The Arrived Ranges, in the file's offsets.
    ranges: Vec<(u64, u64)>,
    /// The part's writers.
    writers: Vec<ArrivedWriterRow>,
    /// Per cell, the positions in `writers` of those that wrote into it.
    cells: Vec<Vec<u16>>,
}

impl Record for ArrivedPartRow {
    const NAME: &'static str = "download.arrived_part";
    const VERSION: u32 = 1;
}

pub(super) static ARRIVED_PARTS: Children<u64, ArrivedPartRow> =
    Children::new("download.arrived_part");

/// Drop `key`'s rows: the cascade a row's completion, cancel, clear or start
/// over owes.
pub(super) fn forget(txn: &WriteTransaction, key: u64) -> Result<(), StoreError> {
    ARRIVED_PARTS.clear(txn, key)
}

/// Remove `part_index`'s row, in the transaction that records the part.
pub(super) fn settle(txn: &WriteTransaction, key: u64, part_index: u32) -> Result<(), StoreError> {
    ARRIVED_PARTS.table().remove(txn, &(key, part_index))?;
    Ok(())
}

impl ArrivedPartRow {
    fn of(part: &ArrivedPart) -> Self {
        Self {
            ranges: part.ranges.clone(),
            writers: part
                .writers
                .iter()
                .map(|writer| ArrivedWriterRow {
                    ip: writer.endpoint.ip(),
                    port: writer.endpoint.port(),
                    user_hash: writer.user_hash.map(|hash| *hash.as_bytes()),
                })
                .collect(),
            cells: part.cells.clone(),
        }
    }

    fn part(self, index: u32) -> ArrivedPart {
        ArrivedPart {
            part_index: PartIndex::new(index),
            ranges: self.ranges,
            writers: self
                .writers
                .into_iter()
                .map(|writer| ArrivedWriter {
                    endpoint: match writer.ip {
                        IpAddr::V4(ip) => PeerEndpoint::V4(Ipv4Endpoint::new(ip, writer.port)),
                        IpAddr::V6(ip) => PeerEndpoint::V6(Ipv6Endpoint::new(ip, writer.port)),
                    },
                    user_hash: writer.user_hash.map(UserHash::from_bytes),
                })
                .collect(),
            cells: self.cells,
        }
    }
}

impl DurableDownloadRepository {
    /// Commit `parts`, the parts that moved since the last checkpoint, at the
    /// store's own durability. The part file must already be synced: this is
    /// the claim that its bytes are there. A part with no range left loses its
    /// row, a part already recorded never takes one, and a row that no longer
    /// holds its place takes none.
    ///
    /// # Errors
    /// [`CoreError::UnknownDownload`] when the row is gone, or
    /// [`CoreError::Repository`].
    pub(crate) fn record_arrived(
        &self,
        id: DownloadId,
        parts: Vec<ArrivedPart>,
    ) -> Result<(), CoreError> {
        self.store.write(|txn| {
            if !read_row(txn, id)?.is_live() {
                return Ok(());
            }
            let key = id.as_u64();
            let recorded = VERIFIED_PARTS.list(txn, key)?;
            for part in &parts {
                let index = part.part_index.value();
                let done = recorded.iter().any(|&(verified, _)| verified == index);
                if part.ranges.is_empty() || done {
                    settle(txn, key, index)?;
                } else {
                    ARRIVED_PARTS.put(txn, key, index, &ArrivedPartRow::of(part))?;
                }
            }
            Ok(())
        })
    }

    /// The download's Arrived Checkpoint, in part order: what every run starts
    /// from, whatever ended the last.
    ///
    /// # Errors
    /// [`CoreError::Repository`].
    pub(crate) fn arrived_parts(&self, id: DownloadId) -> Result<Vec<ArrivedPart>, CoreError> {
        self.store.read(|txn| {
            Ok(ARRIVED_PARTS
                .list(txn, id.as_u64())?
                .into_iter()
                .map(|(index, row)| row.part(index))
                .collect())
        })
    }

    /// Drop the download's checkpoint: the file it claims bytes of is gone.
    ///
    /// # Errors
    /// [`CoreError::Repository`].
    pub(crate) fn forget_arrived(&self, id: DownloadId) -> Result<(), CoreError> {
        self.store.write(|txn| Ok(forget(txn, id.as_u64())?))
    }
}
