//! A download's **Source Seeds** in the store (ADR-0109, "Source Seeds"): one
//! set per download, keyed by the row's id and held in rank order (the ordinal
//! is the rank; an endpoint is in a set at most once). Each seed carries the
//! time its set was written, which is what ages it out.
//!
//! A set lives beside a row that still holds its place: a write for a
//! completed or cancelled row writes nothing, and the lifecycle move that
//! completes or cancels a row deletes its set in the same transaction.

use std::net::IpAddr;
use std::time::SystemTime;

use rmule_primitives::{Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, SourceCryptOptions, UserHash};
use rmule_store::{Children, Record, StoreError, UpgradeStep, WriteTransaction};
use serde::{Deserialize, Serialize};

use super::{DurableDownloadRepository, read_row};
use crate::download::source_seeds::{SEED_LIFETIME, SeedRank, SourceSeed, crypt_options};
use crate::server_list::unix_seconds;
use crate::{CoreError, DownloadId};

/// One seed as the store holds it, keyed by `(download id, rank ordinal)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SourceSeedRow {
    ip: IpAddr,
    port: u16,
    user_hash: Option<[u8; UserHash::BYTE_LEN]>,
    /// The peer's crypt stance as the source-exchange v4 options byte,
    /// `None` when nothing stated one.
    crypt: Option<u8>,
    rank: SeedRank,
    /// When the set was written, in Unix seconds.
    written_at: u64,
}

impl Record for SourceSeedRow {
    const NAME: &'static str = "download.source_seed";
    const VERSION: u32 = 1;
}

pub(super) static SOURCE_SEEDS: Children<u64, SourceSeedRow> =
    Children::new("download.source_seed");

/// Store version 12 → 13: the seeds table appears, empty. A version-12 build
/// must refuse the file afterwards: a cancel there would leave a download's
/// seeds behind.
pub(crate) const UPGRADE_FROM_V12: UpgradeStep = UpgradeStep {
    from: 12,
    run: |txn| SOURCE_SEEDS.table().create(txn),
};

/// Drop `key`'s seeds — the cascade a row's completion, cancel or clear owes.
pub(super) fn forget(txn: &WriteTransaction, key: u64) -> Result<(), StoreError> {
    SOURCE_SEEDS.clear(txn, key)
}

impl SourceSeedRow {
    fn of(seed: &SourceSeed, written_at: u64) -> Self {
        Self {
            ip: seed.endpoint.ip(),
            port: seed.endpoint.port(),
            user_hash: seed.user_hash.map(|hash| *hash.as_bytes()),
            crypt: crypt_options(seed.crypt).map(SourceCryptOptions::as_byte),
            rank: seed.rank,
            written_at,
        }
    }

    fn seed(self) -> SourceSeed {
        let endpoint = match self.ip {
            IpAddr::V4(ip) => PeerEndpoint::V4(Ipv4Endpoint::new(ip, self.port)),
            IpAddr::V6(ip) => PeerEndpoint::V6(Ipv6Endpoint::new(ip, self.port)),
        };
        SourceSeed {
            endpoint,
            user_hash: self.user_hash.map(UserHash::from_bytes),
            crypt: self
                .crypt
                .map(|byte| SourceCryptOptions::from_byte(byte).crypt_stance()),
            rank: self.rank,
        }
    }

    fn fresh_at(self, now: u64) -> bool {
        self.written_at.saturating_add(SEED_LIFETIME.as_secs()) >= now
    }
}

/// What attach reads of one download's seeds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoadedSeeds {
    /// The seeds written within the last 24 hours, in rank order.
    pub fresh: Vec<SourceSeed>,
    /// How many older ones the load deleted.
    pub expired: usize,
}

impl DurableDownloadRepository {
    /// Replace the download's seeds with `seeds`, in the order given, as
    /// written at `written_at`. Writes nothing — and says so with `false` —
    /// when `seeds` is empty, so the last set stands until it ages out, and
    /// when the row no longer holds its place.
    ///
    /// # Errors
    /// [`CoreError::UnknownDownload`] when there is no such row, or
    /// [`CoreError::Repository`].
    pub fn write_source_seeds(
        &self,
        id: DownloadId,
        seeds: &[SourceSeed],
        written_at: SystemTime,
    ) -> Result<bool, CoreError> {
        if seeds.is_empty() {
            return Ok(false);
        }
        let written_at = unix_seconds(written_at);
        self.store.write(|txn| {
            if !read_row(txn, id)?.is_live() {
                return Ok(false);
            }
            SOURCE_SEEDS.replace(
                txn,
                id.as_u64(),
                seeds.iter().map(|seed| SourceSeedRow::of(seed, written_at)),
            )?;
            Ok(true)
        })
    }

    /// The download's seeds in rank order, whatever their age.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store read fails.
    pub fn source_seeds(&self, id: DownloadId) -> Result<Vec<SourceSeed>, CoreError> {
        self.store.read(|txn| {
            Ok(SOURCE_SEEDS
                .list(txn, id.as_u64())?
                .into_iter()
                .map(|(_, row)| row.seed())
                .collect())
        })
    }

    /// The download's seeds written within 24 hours of `now`, the
    /// older ones deleted in the same transaction.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store fails.
    pub fn load_source_seeds(
        &self,
        id: DownloadId,
        now: SystemTime,
    ) -> Result<LoadedSeeds, CoreError> {
        let now = unix_seconds(now);
        self.store.write(|txn| {
            let held = SOURCE_SEEDS.list(txn, id.as_u64())?;
            let (fresh, expired): (Vec<_>, Vec<_>) = held
                .into_iter()
                .map(|(_, row)| row)
                .partition(|row| row.fresh_at(now));
            if !expired.is_empty() {
                SOURCE_SEEDS.replace(txn, id.as_u64(), fresh.iter().copied())?;
            }
            Ok(LoadedSeeds {
                fresh: fresh.into_iter().map(SourceSeedRow::seed).collect(),
                expired: expired.len(),
            })
        })
    }
}

#[cfg(test)]
mod tests;
