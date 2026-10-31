//! The credit ring's durable half on the [`Durable Store`](rmule_store::Store):
//! one record kind, `peer_credit`, keyed by the peer's User Hash bytes, holding
//! the lifetime totals and the bound SUI public key together — so adopting a key
//! and accruing bytes touch one row instead of two tables. No secondary index:
//! every question the seam asks is "what does this peer's row say", which the
//! primary key already answers.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use rmule_primitives::UserHash;
use rmule_store::redb::TableDefinition;
use rmule_store::{Indexed, Packed, Record, Store, StoreError, UpgradeStep};
use serde::{Deserialize, Serialize};

use super::Schema;
use crate::CoreError;
use crate::credit::{CreditProof, CreditStore, CreditTotals, KeyBinding, PeerCredit};

/// The `peer_credit` record's shape version. Bumped with every field change,
/// together with a ladder step (ADR-0083).
pub const PEER_CREDIT_RECORD_VERSION: u32 = 2;

/// How long a row outlives its peer's last sign of life: aMule's 150 days
/// (`ClientCreditsList.cpp:142`).
pub const CREDIT_EXPIRY_SECS: u64 = 12_960_000;

/// One peer's ring row as the store holds it. The `UserHash` is the primary
/// key, not a field. `public_key` is `None` on an unsecured record; a bound key
/// makes the peer a Secured Identity (ADR-0041).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct PeerCreditRow {
    uploaded: u64,
    downloaded: u64,
    public_key: Option<Vec<u8>>,
    /// When the peer last accrued or proved its key, in Unix seconds: what the
    /// row ages from.
    last_seen: u64,
}

impl Record for PeerCreditRow {
    const NAME: &'static str = "peer_credit";
    const VERSION: u32 = PEER_CREDIT_RECORD_VERSION;
}

static PEER_CREDIT: Indexed<[u8; UserHash::BYTE_LEN], PeerCreditRow> =
    Indexed::new("peer_credit", &[]);

/// The row as record version 1 wrote it, before it kept when it was last seen.
/// Compiled only for the rung.
#[derive(Debug, Serialize, Deserialize)]
struct PeerCreditRowV1 {
    uploaded: u64,
    downloaded: u64,
    public_key: Option<Vec<u8>>,
}

impl Record for PeerCreditRowV1 {
    const NAME: &'static str = "peer_credit";
    const VERSION: u32 = 1;
}

static PEER_CREDIT_V1: Indexed<[u8; UserHash::BYTE_LEN], PeerCreditRowV1> =
    Indexed::new("peer_credit", &[]);

/// The tables this seam owns, for the store-wide [`Schema`] core assembles
/// before [`Store::open`].
#[must_use]
pub(crate) fn schema() -> Schema {
    Schema::new().indexed(&PEER_CREDIT)
}

/// The tables as store version 1 declared them.
#[cfg(test)]
pub(crate) fn schema_v1() -> Schema {
    Schema::new().indexed(&PEER_CREDIT_V1)
}

/// A row as store version 1 held it, for the ladder's own test.
#[cfg(test)]
pub(crate) fn row_v1(
    txn: &rmule_store::WriteTransaction,
    peer: UserHash,
    downloaded: u64,
) -> Result<(), StoreError> {
    let row = PeerCreditRowV1 {
        uploaded: 0,
        downloaded,
        public_key: None,
    };
    PEER_CREDIT_V1.set(txn, peer.as_bytes(), &row)
}

/// Store version 15 → 16: every row keeps when it was last seen. Nothing says
/// when an old row last was, so it ages from the climb. A version-15 build
/// refuses the store: it could not read the row.
pub(crate) const UPGRADE_FROM_V15: UpgradeStep = UpgradeStep {
    from: 15,
    run: |txn| {
        let old = PEER_CREDIT_V1.iter(txn)?;
        txn.delete_table(TableDefinition::<
            [u8; UserHash::BYTE_LEN],
            Packed<PeerCreditRowV1>,
        >::new("peer_credit"))?;
        PEER_CREDIT.create(txn)?;
        let last_seen = unix_now();
        for (key, row) in old {
            let grown = PeerCreditRow {
                uploaded: row.uploaded,
                downloaded: row.downloaded,
                public_key: row.public_key,
                last_seen,
            };
            PEER_CREDIT.set(txn, &key, &grown)?;
        }
        Ok(())
    },
};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
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
    /// The peers that proved their key since the store last heard, whose rows
    /// are seen at the next write though no byte moved.
    seen: HashSet<UserHash>,
    /// The rows holding a key, which pay only on proof (ADR-0041).
    keyed: HashSet<UserHash>,
    /// Where each key was last proved this run, one address per family
    /// because a dual-stack client holds one in each (ADR-0107): aMule's
    /// `m_identAddress`.
    proved: HashMap<(UserHash, bool), IpAddr>,
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
        Self::opened_at(store, unix_now())
    }

    /// [`Self::new`] at `now` in Unix seconds: a row unseen for 150 days
    /// leaves the ring, as aMule drops it at load
    /// (`ClientCreditsList.cpp:142`, `:169`). A row that will not leave the
    /// store this time is gone from this run and tried at the next.
    #[must_use]
    pub fn opened_at(store: Arc<Store>, now: u64) -> Self {
        let rows: Result<_, StoreError> = store.read(|txn| PEER_CREDIT.iter(txn));
        let rows = rows
            .inspect_err(|error| {
                tracing::warn!(%error, "credit ring unreadable; peers start unknown this run");
            })
            .unwrap_or_default();
        let expired_before = now.saturating_sub(CREDIT_EXPIRY_SECS);
        let (rows, expired): (Vec<_>, Vec<_>) = rows
            .into_iter()
            .partition(|(_, row)| row.last_seen >= expired_before);
        if !expired.is_empty() {
            let removed: Result<(), StoreError> = store.write(|txn| {
                for (key, _) in &expired {
                    PEER_CREDIT.remove(txn, key)?;
                }
                Ok(())
            });
            if let Err(error) = removed {
                tracing::warn!(%error, "expired credit rows stay until the next start");
            }
        }
        let mut books = Books::default();
        for (key, row) in rows {
            let peer = UserHash::from_bytes(key);
            let totals = CreditTotals {
                uploaded: row.uploaded,
                downloaded: row.downloaded,
            };
            books.totals.insert(peer, totals);
            if row.public_key.is_some() {
                books.keyed.insert(peer);
            }
        }
        let books = Mutex::new(books);
        Self {
            ring: Arc::new(Ring { store, books }),
        }
    }
}

impl DurableCreditStore {
    /// [`CreditStore::checkpoint`] at `now` in Unix seconds.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store will not commit.
    pub fn checkpoint_at(&self, now: u64) -> Result<(), CoreError> {
        self.ring.persist(now)
    }
}

impl Ring {
    fn books(&self) -> MutexGuard<'_, Books> {
        self.books.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Add what moved to the store's rows in one flushed transaction, each
    /// row touched seen at `now`. What the store would not take stays owed.
    fn persist(&self, now: u64) -> Result<(), CoreError> {
        let (moved, seen) = {
            let mut books = self.books();
            (
                std::mem::take(&mut books.moved),
                std::mem::take(&mut books.seen),
            )
        };
        if moved.is_empty() && seen.is_empty() {
            return Ok(());
        }
        let written = self.store.write(|txn| {
            for (peer, by) in &moved {
                let key = *peer.as_bytes();
                let mut row = PEER_CREDIT.get(txn, &key)?.unwrap_or_default();
                row.uploaded = row.uploaded.saturating_add(by.uploaded);
                row.downloaded = row.downloaded.saturating_add(by.downloaded);
                row.last_seen = now;
                PEER_CREDIT.put(txn, &key, &row)?;
            }
            for peer in seen.iter().filter(|peer| !moved.contains_key(peer)) {
                let key = *peer.as_bytes();
                if let Some(mut row) = PEER_CREDIT.get(txn, &key)? {
                    row.last_seen = now;
                    PEER_CREDIT.put(txn, &key, &row)?;
                }
            }
            Ok(())
        });
        if written.is_err() {
            let mut books = self.books();
            for (peer, by) in moved {
                add(books.moved.entry(peer).or_default(), by);
            }
            books.seen.extend(seen);
        }
        written
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        if let Err(error) = self.persist(unix_now()) {
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

    fn proof(&self, peer: UserHash, at: IpAddr) -> CreditProof {
        let at = at.to_canonical();
        let books = self.ring.books();
        match books.proved.get(&(peer, at.is_ipv6())) {
            Some(proved) if *proved == at => CreditProof::Proved,
            Some(_) => CreditProof::Elsewhere,
            None if books.keyed.contains(&peer) => CreditProof::Owed,
            None => CreditProof::Open,
        }
    }

    fn prove(&self, peer: UserHash, at: IpAddr) {
        let at = at.to_canonical();
        let mut books = self.ring.books();
        books.proved.insert((peer, at.is_ipv6()), at);
        books.seen.insert(peer);
    }

    /// The read and the write share one transaction, so the compare-and-set
    /// cannot interleave — and it flushes where it is written, because the
    /// caller acts on the answer. A first key over a row with bytes received
    /// leaves both totals at one: the prover has not shown it earned them
    /// (`ClientCredits.cpp:235-241`).
    fn bind_public_key(&self, peer: UserHash, key: &[u8]) -> Result<KeyBinding, CoreError> {
        let wipe = self.totals(peer)?.downloaded > 0;
        let binding: KeyBinding = self.ring.store.write(|txn| {
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
            row.last_seen = unix_now();
            if wipe {
                row.uploaded = 1;
                row.downloaded = 1;
            }
            PEER_CREDIT.put(txn, &primary, &row)?;
            Ok::<_, CoreError>(KeyBinding::Adopted)
        })?;
        if binding == KeyBinding::Adopted {
            let mut books = self.ring.books();
            books.keyed.insert(peer);
            if wipe {
                let left = CreditTotals {
                    uploaded: 1,
                    downloaded: 1,
                };
                books.totals.insert(peer, left);
                books.moved.remove(&peer);
            }
        }
        Ok(binding)
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
        self.checkpoint_at(unix_now())
    }

    fn snapshot(&self) -> Result<Vec<PeerCredit>, CoreError> {
        self.ring.persist(unix_now())?;
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
                last_seen: row.last_seen,
            })
            .collect())
    }
}
