//! The **pending-callback table** (ADR-0039, ADR-0107): which download a
//! called-back Low-ID peer's connection belongs to.
//!
//! One key — `(server, low_id)` — can be awaited by several members of the
//! **Download Set** at once: one Low-ID peer holding two files we fetch. A
//! callback opens one connection, and aMule opens no second one while the
//! first lives (`ServerSocket.cpp:582-605`, `TryToConnect` on a known client),
//! so the table keeps an ordered list per key with one entry per download: the
//! oldest takes the connection, the others stay pending to their own
//! deadlines, and only an entry's owner — the runner whose `adopt_tx`
//! registered it — removes it.

use std::collections::HashMap;

use rmule_peer::PartBitmap;
use rmule_primitives::Ed2kFileLink;
use tokio::sync::mpsc;

use super::CallbackKey;
use crate::adapters::peer_transfer::PeerWorker;

/// Where an adopted worker is handed back, tagged with the key it settles. Its
/// channel identity is the entry's owner.
pub(crate) type AdoptSender = mpsc::Sender<(CallbackKey, PeerWorker)>;

/// One pending callback the inbound accept-router can adopt (ADR-0039). The
/// requesting download's runner registers it; the triage consumes it on a
/// matching inbound hello and drives the adopted worker, handing it back over
/// `adopt_tx`.
pub(crate) struct PendingCallbackEntry {
    /// The file the adopted worker downloads — the triage knows only the key.
    pub(crate) file: Ed2kFileLink,
    /// What the download held when it asked for the callback — the adopted
    /// worker's connect-time name ask carries it.
    pub(crate) own_status: PartBitmap,
    /// Whether the adopted worker's connect-time request asks for sources —
    /// the download's decision when it registered (ADR-0108).
    pub(crate) want_sources: bool,
    /// Back to the registering runner, tagged with the matched callback key (the
    /// adopted worker's real socket cannot yield the server-assigned id; the key's
    /// server lets the runner route a per-server global adoption from a connected one).
    pub(crate) adopt_tx: AdoptSender,
}

/// Every pending callback, per key in registration order.
#[derive(Default)]
pub(crate) struct PendingCallbacks {
    entries: HashMap<CallbackKey, Vec<PendingCallbackEntry>>,
}

impl PendingCallbacks {
    /// Hold `key`'s next inbound connection for `entry`'s download. The same
    /// download registering again replaces its own entry in place, keeping its
    /// turn; another download's entry is never touched.
    pub(crate) fn register(&mut self, key: CallbackKey, entry: PendingCallbackEntry) {
        let waiting = self.entries.entry(key).or_default();
        match waiting
            .iter_mut()
            .find(|held| held.adopt_tx.same_channel(&entry.adopt_tx))
        {
            Some(own) => *own = entry,
            None => waiting.push(entry),
        }
    }

    /// Spend the oldest entry on `key`: a called-back peer arrived.
    pub(crate) fn adopt(&mut self, key: &CallbackKey) -> Option<PendingCallbackEntry> {
        let waiting = self.entries.get_mut(key)?;
        let oldest = waiting.remove(0);
        if waiting.is_empty() {
            self.entries.remove(key);
        }
        Some(oldest)
    }

    /// Drop `owner`'s entry on `key` — its callback ended. Idempotent.
    pub(crate) fn retract(&mut self, key: &CallbackKey, owner: &AdoptSender) {
        if let Some(waiting) = self.entries.get_mut(key) {
            waiting.retain(|held| !held.adopt_tx.same_channel(owner));
            if waiting.is_empty() {
                self.entries.remove(key);
            }
        }
    }

    /// Drop every entry `owner` holds — its download ended.
    pub(crate) fn release_owner(&mut self, owner: &AdoptSender) {
        self.entries.retain(|_, waiting| {
            waiting.retain(|held| !held.adopt_tx.same_channel(owner));
            !waiting.is_empty()
        });
    }

    /// How many callbacks are pending, across every key and download.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }

    /// Whether no callback is pending.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_primitives::{ClientId, Ed2kText, FileHash, Ipv4Endpoint};

    use super::*;

    fn entry(adopt_tx: &AdoptSender, file_seed: u8) -> PendingCallbackEntry {
        let mut hash = [0u8; FileHash::BYTE_LEN];
        for (index, byte) in hash.iter_mut().enumerate() {
            *byte = file_seed ^ u8::try_from(index * 37 % 251).expect("fits");
        }
        PendingCallbackEntry {
            file: Ed2kFileLink {
                name: Ed2kText::from_utf8("callback"),
                size: 9_728_001,
                file_hash: FileHash::from_bytes(hash),
                part_hash_set: None,
                aich_root: None,
                ipv6_sources: Vec::new(),
                sources: Default::default(),
            },
            own_status: PartBitmap::downloader_empty(9_728_001),
            want_sources: true,
            adopt_tx: adopt_tx.clone(),
        }
    }

    fn key() -> CallbackKey {
        CallbackKey {
            server: Some(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 9), 4661)),
            low_id: ClientId::from_u32(0x0012_3456),
        }
    }

    /// Two downloads wait on one Low-ID peer: neither overwrites the other,
    /// the older takes the first connection, and the younger still waits for
    /// the next — until its own callback ends it.
    #[test]
    fn two_downloads_waiting_on_one_low_id_peer_keep_both_entries() {
        let (first_tx, _first_rx) = mpsc::channel(1);
        let (second_tx, _second_rx) = mpsc::channel(1);
        let mut table = PendingCallbacks::default();
        table.register(key(), entry(&first_tx, 0x71));
        table.register(key(), entry(&second_tx, 0x9E));
        assert_eq!(table.len(), 2);

        let adopted = table.adopt(&key()).expect("the first connection");
        assert!(adopted.adopt_tx.same_channel(&first_tx));
        // The first download's end cannot take the second one's entry.
        table.retract(&key(), &first_tx);
        table.release_owner(&first_tx);
        let next = table
            .adopt(&key())
            .expect("the second download still waits");
        assert!(next.adopt_tx.same_channel(&second_tx));
        assert!(table.is_empty());
    }

    /// A download re-registering its own callback keeps its place in line.
    #[test]
    fn a_download_re_registering_keeps_its_turn() {
        let (first_tx, _first_rx) = mpsc::channel(1);
        let (second_tx, _second_rx) = mpsc::channel(1);
        let mut table = PendingCallbacks::default();
        table.register(key(), entry(&first_tx, 0x71));
        table.register(key(), entry(&second_tx, 0x9E));
        table.register(key(), entry(&first_tx, 0x72));
        assert_eq!(table.len(), 2);
        let adopted = table.adopt(&key()).expect("the older download");
        assert!(adopted.adopt_tx.same_channel(&first_tx));
        assert_eq!(adopted.file.file_hash.as_bytes()[0], 0x72);
    }
}
