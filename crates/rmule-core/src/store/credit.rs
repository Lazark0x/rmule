//! The credit ring's durable half on the [`Durable Store`](rmule_store::Store):
//! one record kind, `peer_credit`, keyed by the peer's User Hash bytes, holding
//! the lifetime totals and the bound SUI public key together — so adopting a key
//! and accruing bytes touch one row instead of two tables. No secondary index:
//! every question the seam asks is "what does this peer's row say", which the
//! primary key already answers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rmule_primitives::UserHash;
use rmule_store::{Indexed, Record, Store, StoreError};
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
/// The totals live in memory, as aMule's do, loaded whole here: a block's
/// accrual and a waiter's rank are read and written once per block and once
/// per input by loops that must not wait on the store (ADR-0031). What moved
/// reaches the store at [`CreditStore::checkpoint`] and when the last handle
/// goes. A key binding, which a caller acts on, is written and flushed where it
/// is made. A clone shares the ring; a second `new` over one store does not.
#[derive(Clone, Debug)]
pub struct DurableCreditStore {
    ring: Arc<Ring>,
}

/// The store and the totals over it.
#[derive(Debug)]
struct Ring {
    store: Arc<Store>,
    books: Mutex<Books>,
}

/// The ring in memory. Every lock of it is a few map steps, never an I/O.
#[derive(Debug, Default)]
struct Books {
    totals: HashMap<UserHash, CreditTotals>,
    /// What moved since the store last heard, added to its rows at the next
    /// write, so a key bound meanwhile is not written over.
    moved: HashMap<UserHash, CreditTotals>,
}

impl Books {
    fn accrue(&mut self, peer: UserHash, moved: CreditTotals) {
        add(self.totals.entry(peer).or_default(), moved);
        add(self.moved.entry(peer).or_default(), moved);
    }
}

/// Saturating: a lifetime counter has no meaningful wrap.
const fn add(totals: &mut CreditTotals, moved: CreditTotals) {
    totals.uploaded = totals.uploaded.saturating_add(moved.uploaded);
    totals.downloaded = totals.downloaded.saturating_add(moved.downloaded);
}

impl DurableCreditStore {
    /// A ledger over the already-open store, its totals read now. A store that
    /// will not be read leaves a ring of strangers for this run: its rows are
    /// not written over, because what this run moves is added to them.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        let rows: Result<_, StoreError> = store.read(|txn| PEER_CREDIT.iter(txn));
        let totals = rows
            .inspect_err(|error| {
                tracing::warn!(%error, "credit ring unreadable; peers start unknown this run");
            })
            .unwrap_or_default()
            .into_iter()
            .map(|(key, row)| {
                let totals = CreditTotals {
                    uploaded: row.uploaded,
                    downloaded: row.downloaded,
                };
                (UserHash::from_bytes(key), totals)
            })
            .collect();
        let books = Mutex::new(Books {
            totals,
            moved: HashMap::new(),
        });
        Self {
            ring: Arc::new(Ring { store, books }),
        }
    }
}

impl Ring {
    fn books(&self) -> MutexGuard<'_, Books> {
        self.books.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Add what moved to the store's rows in one flushed transaction. What the
    /// store would not take stays owed.
    fn persist(&self) -> Result<(), CoreError> {
        let moved = std::mem::take(&mut self.books().moved);
        if moved.is_empty() {
            return Ok(());
        }
        let written = self.store.write(|txn| {
            for (peer, by) in &moved {
                let key = *peer.as_bytes();
                let mut row = PEER_CREDIT.get(txn, &key)?.unwrap_or_default();
                row.uploaded = row.uploaded.saturating_add(by.uploaded);
                row.downloaded = row.downloaded.saturating_add(by.downloaded);
                PEER_CREDIT.put(txn, &key, &row)?;
            }
            Ok(())
        });
        if written.is_err() {
            let mut books = self.books();
            for (peer, by) in moved {
                add(books.moved.entry(peer).or_default(), by);
            }
        }
        written
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        if let Err(error) = self.persist() {
            tracing::warn!(%error, "credit accrual not written; the last of it is lost");
        }
    }
}

impl CreditStore for DurableCreditStore {
    fn record_upload(&self, peer: UserHash, bytes: u64) -> Result<(), CoreError> {
        let moved = CreditTotals {
            uploaded: bytes,
            downloaded: 0,
        };
        self.ring.books().accrue(peer, moved);
        Ok(())
    }

    fn record_download(&self, peer: UserHash, bytes: u64) -> Result<(), CoreError> {
        let moved = CreditTotals {
            uploaded: 0,
            downloaded: bytes,
        };
        self.ring.books().accrue(peer, moved);
        Ok(())
    }

    fn totals(&self, peer: UserHash) -> Result<CreditTotals, CoreError> {
        Ok(self
            .ring
            .books()
            .totals
            .get(&peer)
            .copied()
            .unwrap_or_default())
    }

    /// The read and the write share one transaction, so the compare-and-set
    /// cannot interleave — and it flushes where it is written, because the
    /// caller acts on the answer.
    fn bind_public_key(&self, peer: UserHash, key: &[u8]) -> Result<KeyBinding, CoreError> {
        self.ring.store.write(|txn| {
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
        let row = self
            .ring
            .store
            .read(|txn| Ok::<_, CoreError>(PEER_CREDIT.get(txn, peer.as_bytes())?))?;
        Ok(row.and_then(|row| row.public_key))
    }

    /// Writes what moved in one flushed transaction, and nothing when nothing
    /// did. Called once a minute and at shutdown.
    fn checkpoint(&self) -> Result<(), CoreError> {
        self.ring.persist()
    }

    fn snapshot(&self) -> Result<Vec<PeerCredit>, CoreError> {
        self.ring.persist()?;
        let rows = self.ring.store.read(|txn| PEER_CREDIT.iter(txn))?;
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
