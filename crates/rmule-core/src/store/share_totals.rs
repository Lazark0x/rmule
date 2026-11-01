//! **Share Totals** on the Durable Store: what the serve activity has
//! done for each file across every run — upload requests drawn, slots
//! granted, bytes served — aMule's all-time `CFileStatistic` figures, which it
//! keeps in `known.met` (`FT_ATREQUESTED`, `FT_ATACCEPTED`,
//! `FT_ATTRANSFERRED`/`HI`, `amule-2.3.3/src/KnownFile.cpp:580-594`,
//! `:737-753`).
//!
//! Keyed by the file's content identity, as the **Shared File Registry** keys
//! its rows, but beside the row rather than inside it: aMule's known list
//! keeps a file's statistic after the file stops being shared, and a file
//! hashed again under another name or date takes over the known record's
//! figures (`KnownFileList.cpp:283-305`). So an unshare, a rename or a file
//! that left and came back keeps its totals here, and a share of the same
//! content picks them up by its hash.
//!
//! Written as absolute values, never as increments: a flush states what the
//! totals are now, so a flush repeated after a failure cannot count twice.

use std::collections::BTreeMap;
use std::sync::Arc;

use rmule_primitives::FileHash;
use rmule_store::{Indexed, Record, Store};
use serde::{Deserialize, Serialize};

use crate::CoreError;
use crate::diagnostics::ShareTotals;
use crate::store::Schema;

/// A file's key: its ED2K File Hash's bytes, as the registry keys its rows.
type FileKey = [u8; FileHash::BYTE_LEN];

/// One file's all-time totals.
#[derive(Debug, Serialize, Deserialize)]
struct TotalsRow {
    /// [`ShareTotals::requests`].
    requests: u64,
    /// [`ShareTotals::accepted`].
    accepted: u64,
    /// [`ShareTotals::transferred`].
    transferred: u64,
}

impl Record for TotalsRow {
    const NAME: &'static str = "shared_file_totals";
    const VERSION: u32 = 1;
}

static SHARE_TOTALS: Indexed<FileKey, TotalsRow> = Indexed::new(TotalsRow::NAME, &[]);

/// The table this seam owns, merged into the store's schema.
#[must_use]
pub(crate) fn schema() -> Schema {
    Schema::new().indexed(&SHARE_TOTALS)
}

/// The **Share Totals** seam. A clone shares the store; each call is one
/// transaction.
#[derive(Clone, Debug)]
pub struct DurableShareTotals {
    store: Arc<Store>,
}

impl DurableShareTotals {
    /// Bind the seam to the store all seams share.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    /// Every file's totals.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store read fails.
    pub fn load(&self) -> Result<BTreeMap<FileHash, ShareTotals>, CoreError> {
        self.store.read(|txn| {
            Ok(crate::store::readable(&SHARE_TOTALS, txn)?
                .into_iter()
                .map(|(key, row)| {
                    let totals = ShareTotals {
                        requests: row.requests,
                        accepted: row.accepted,
                        transferred: row.transferred,
                    };
                    (FileHash::from_bytes(key), totals)
                })
                .collect())
        })
    }

    /// Write `totals` as each file's totals now, in one transaction.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store write fails; nothing is
    /// written then.
    pub fn record(&self, totals: &[(FileHash, ShareTotals)]) -> Result<(), CoreError> {
        if totals.is_empty() {
            return Ok(());
        }
        self.store.write(|txn| {
            for (file_hash, totals) in totals {
                let row = TotalsRow {
                    requests: totals.requests,
                    accepted: totals.accepted,
                    transferred: totals.transferred,
                };
                SHARE_TOTALS.set(txn, file_hash.as_bytes(), &row)?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::open_durable_store;

    #[test]
    fn a_totals_row_keeps_its_bytes() {
        let row = TotalsRow {
            requests: 1,
            accepted: 2,
            transferred: 300,
        };
        crate::store::assert_pinned(&row, "0102ac02");
    }

    fn totals(requests: u64, accepted: u64, transferred: u64) -> ShareTotals {
        ShareTotals {
            requests,
            accepted,
            transferred,
        }
    }

    #[test]
    fn totals_survive_a_store_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let film = FileHash::from_bytes([1; 16]);
        {
            let seam = DurableShareTotals::new(open_durable_store(dir.path()).unwrap());
            seam.record(&[(film, totals(3, 1, 9_728_000))]).unwrap();
            // A later flush states the totals again, grown: it replaces.
            seam.record(&[(film, totals(5, 2, 19_456_000))]).unwrap();
        }
        let reopened = DurableShareTotals::new(open_durable_store(dir.path()).unwrap());
        assert_eq!(
            reopened.load().unwrap(),
            BTreeMap::from([(film, totals(5, 2, 19_456_000))])
        );
    }
}
