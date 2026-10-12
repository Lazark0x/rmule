//! The **Source Book**'s run tier: facts kept for the whole run apart from any
//! record, because a channel stated them about an address or a peer rather
//! than about one connection (ADR-0090 "Attachments"), or because the record
//! that held them stopped answering to the name (ADR-0108). Each is folded into
//! a record sighted later. The ask facts kept under a name last until aMule's
//! client-list cleanup would have forgotten the client: the first pass that
//! finds no record answering to the name.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use rmule_primitives::{Ipv4Endpoint, PeerCrypt, PeerEndpoint, UserHash};

use super::asks::AskName;
use crate::download::source_ask_clock::AskFacts;

/// aMule `CLIENTLIST_CLEANUP_TIME` (stock 2.3.3
/// `include/protocol/ed2k/Constants.h:74`): how often aMule's client list
/// deletes every client that is no source, no upload and holds no socket any
/// more (`ClientList.cpp:975-1003`), and with it what it knew of the peer.
pub(crate) const CLIENT_LIST_CLEANUP: Duration = Duration::from_secs(34 * 60);

/// The record-stated crypt by endpoint and the hello-named buddy by User Hash.
#[derive(Debug, Default)]
pub(super) struct RunTier {
    /// The crypt side a record stated for an endpoint — a server's `0x44`, a
    /// source exchange, a Kad row's `TAG_ENCRYPTION` — folded newest first
    /// (ADR-0049). A peer's own hello outranks it while its worker lives.
    record_crypts: HashMap<PeerEndpoint, PeerCrypt>,
    /// The serving buddy a source's own hello named, by the source's User
    /// Hash: the one name that survives its address changing under a NAT, and
    /// the key the buddy road cannot run without (ADR-0061).
    hello_buddies: HashMap<UserHash, Ipv4Endpoint>,
    /// The ask facts a name kept when its record stopped answering to it —
    /// a worker's hello hash at its end, an endpoint or key the record
    /// dropped, every name of a record that left the book (ADR-0108).
    asks: HashMap<AskName, AskFacts>,
    /// When the last client-list cleanup ran; `None` until the first instant
    /// starts the clock.
    cleaned_at: Option<Instant>,
}

impl RunTier {
    /// Fold what a record stated about `endpoint` into what earlier records
    /// said ([`PeerCrypt::fold_newer`]): the newer statement wins, silence keeps
    /// the stated stance, and a record naming another User Hash replaces the
    /// record whole.
    pub(super) fn note_crypt(&mut self, endpoint: PeerEndpoint, crypt: PeerCrypt) {
        if crypt.is_unknown() {
            return;
        }
        let held = self
            .record_crypts
            .get(&endpoint)
            .copied()
            .unwrap_or_default();
        self.record_crypts.insert(endpoint, held.fold_newer(crypt));
    }

    /// What records stated about `endpoint`.
    pub(super) fn record_crypt(&self, endpoint: PeerEndpoint) -> Option<PeerCrypt> {
        self.record_crypts.get(&endpoint).copied()
    }

    /// Remember the buddy `user_hash`'s own hello named.
    pub(super) fn note_hello_buddy(&mut self, user_hash: UserHash, buddy_udp: Ipv4Endpoint) {
        self.hello_buddies.insert(user_hash, buddy_udp);
    }

    /// The buddy `user_hash`'s own hello named this run.
    pub(super) fn hello_buddy(&self, user_hash: UserHash) -> Option<Ipv4Endpoint> {
        self.hello_buddies.get(&user_hash).copied()
    }

    /// Keep `facts` under `name` for the run, merged with what it held.
    pub(super) fn keep_asks(&mut self, name: AskName, facts: AskFacts) {
        let kept = self.asks.entry(name).or_default();
        *kept = kept.merge(facts);
    }

    /// The ask facts `name` kept, if any.
    pub(super) fn kept_asks(&self, name: AskName) -> Option<AskFacts> {
        self.asks.get(&name).copied()
    }

    /// Whether a client-list cleanup falls due at `now`. The first instant
    /// only starts the clock.
    pub(super) fn cleanup_due(&mut self, now: Instant) -> bool {
        match self.cleaned_at {
            None => {
                self.cleaned_at = Some(now);
                false
            }
            Some(at) => now.saturating_duration_since(at) >= CLIENT_LIST_CLEANUP,
        }
    }

    /// The cleanup at `now`: forget the facts of every name `claimed` does not
    /// hold.
    pub(super) fn clean_up_asks(&mut self, now: Instant, claimed: &HashSet<AskName>) {
        self.asks.retain(|name, _| claimed.contains(name));
        self.cleaned_at = Some(now);
    }

    /// When the next cleanup falls due, while any facts wait on one.
    pub(super) fn next_asks_cleanup(&self) -> Option<Instant> {
        self.cleaned_at
            .filter(|_| !self.asks.is_empty())
            .map(|at| at + CLIENT_LIST_CLEANUP)
    }
}
