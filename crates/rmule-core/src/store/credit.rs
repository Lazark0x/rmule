//! The credit ring's durable half on the [`Durable Store`](rmule_store::Store):
//! one record kind, `peer_credit`, keyed by the peer's User Hash bytes, holding
//! the lifetime totals and the bound SUI public key together — so adopting a key
//! and accruing bytes touch one row instead of two tables. No secondary index:
//! every question the seam asks is "what does this peer's row say", which the
//! primary key already answers.

use std::sync::Arc;

use rmule_primitives::UserHash;
use rmule_store::{Indexed, Record, Store};
use serde::{Deserialize, Serialize};

use super::Schema;
use crate::CoreError;
use crate::credit::{CreditStore, CreditTotals, KeyBinding, PeerCredit};

/// The `peer_credit` record's shape version. Bumped with every field change,
/// together with a ladder step (ADR-0083).
pub const PEER_CREDIT_RECORD_VERSION: u32 = 1;

/// One peer's ring row as the store holds it. The `UserHash` is the primary
/// key, not a field. `public_key` is `None` on an unsecured record; a bound key
/// makes the peer a Secured Identity (ADR-0041).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct PeerCreditRow {
    uploaded: u64,
    downloaded: u64,
    public_key: Option<Vec<u8>>,
}

impl Record for PeerCreditRow {
    const NAME: &'static str = "peer_credit";
    const VERSION: u32 = PEER_CREDIT_RECORD_VERSION;
}

static PEER_CREDIT: Indexed<[u8; UserHash::BYTE_LEN], PeerCreditRow> =
    Indexed::new("peer_credit", &[]);

/// The tables this seam owns, for the store-wide [`Schema`] core assembles
/// before [`Store::open`].
#[must_use]
pub(crate) fn schema() -> Schema {
    Schema::new().indexed(&PEER_CREDIT)
}

/// The durable [`CreditStore`]: the credit ring's per-peer totals and identity
/// bindings in the shared store, so a peer's earned standing survives a restart
/// exactly as aMule's `clients.met` makes it survive one.
///
/// Every method takes `&self` and commits its own write transaction, so a
/// handle is shared, not locked, and a clone reaches the same store. Accrual
/// commits without a device flush and is made durable by
/// [`CreditStore::checkpoint`]; a key binding, which a caller acts on, is
/// flushed where it is written.
#[derive(Clone, Debug)]
pub struct DurableCreditStore {
    store: Arc<Store>,
}

impl DurableCreditStore {
    /// A ledger over the already-open store. Nothing is read until a call
    /// asks for it; the tables were created by [`Store::open`] against
    /// this module's schema.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    /// Add `bytes` to the total `direction` names, creating the row when the
    /// peer is new. Saturating: a lifetime counter has no meaningful wrap.
    ///
    /// One call per transferred block, so it commits without a device flush
    /// and [`CreditStore::checkpoint`] is what makes the accrual durable.
    fn accrue(
        &self,
        peer: UserHash,
        bytes: u64,
        direction: fn(&mut PeerCreditRow) -> &mut u64,
    ) -> Result<(), CoreError> {
        self.store.write_deferred(|txn| {
            let key = *peer.as_bytes();
            let mut row = PEER_CREDIT.get(txn, &key)?.unwrap_or_default();
            let total = direction(&mut row);
            *total = total.saturating_add(bytes);
            Ok(PEER_CREDIT.set(txn, &key, &row)?)
        })
    }

    fn row(&self, peer: UserHash) -> Result<Option<PeerCreditRow>, CoreError> {
        self.store
            .read(|txn| Ok(PEER_CREDIT.get(txn, peer.as_bytes())?))
    }
}

impl CreditStore for DurableCreditStore {
    fn record_upload(&self, peer: UserHash, bytes: u64) -> Result<(), CoreError> {
        self.accrue(peer, bytes, |row| &mut row.uploaded)
    }

    fn record_download(&self, peer: UserHash, bytes: u64) -> Result<(), CoreError> {
        self.accrue(peer, bytes, |row| &mut row.downloaded)
    }

    fn totals(&self, peer: UserHash) -> Result<CreditTotals, CoreError> {
        Ok(self
            .row(peer)?
            .map_or_else(CreditTotals::default, |row| CreditTotals {
                uploaded: row.uploaded,
                downloaded: row.downloaded,
            }))
    }

    /// The read and the write share one transaction, so the compare-and-set
    /// cannot interleave — and it flushes where it is written, because the
    /// caller acts on the answer.
    fn bind_public_key(&self, peer: UserHash, key: &[u8]) -> Result<KeyBinding, CoreError> {
        self.store.write(|txn| {
            let primary = *peer.as_bytes();
            let mut row = PEER_CREDIT.get(txn, &primary)?.unwrap_or_default();
            if let Some(bound) = &row.public_key {
                return Ok(if bound.as_slice() == key {
                    KeyBinding::AlreadyBound
                } else {
                    KeyBinding::Mismatch
                });
            }
            row.public_key = Some(key.to_vec());
            PEER_CREDIT.put(txn, &primary, &row)?;
            Ok(KeyBinding::Adopted)
        })
    }

    fn public_key(&self, peer: UserHash) -> Result<Option<Vec<u8>>, CoreError> {
        Ok(self.row(peer)?.and_then(|row| row.public_key))
    }

    /// The store's own flush: the engine settles every deferred commit before
    /// it, so the ring needs no write of its own to reach the disk.
    fn checkpoint(&self) -> Result<(), CoreError> {
        Ok(self.store.flush()?)
    }

    fn snapshot(&self) -> Result<Vec<PeerCredit>, CoreError> {
        let rows = self.store.read(|txn| PEER_CREDIT.iter(txn))?;
        Ok(rows
            .into_iter()
            .map(|(key, row)| PeerCredit {
                key: UserHash::from_bytes(key),
                totals: CreditTotals {
                    uploaded: row.uploaded,
                    downloaded: row.downloaded,
                },
                public_key: row.public_key,
            })
            .collect())
    }
}
