//! The **Source Ask Clock**'s facts in the **Source Book** (ADR-0108): a peer's
//! [`AskFacts`] ride its record, and its **Ask Names** are the record's aliases
//! — its endpoints and its `CallbackKey` — plus the User Hashes the record
//! knows. A stamp lands on the record. A read merges what every live record
//! sharing one of its User Hashes holds and what the run tier kept under each
//! of its names, so a name a record stops answering to — its worker's hello
//! hash, a dropped endpoint or key, every name of a record that left — keeps
//! its facts, as aMule's one client object per peer does
//! (`FindMatchingClient`, stock 2.3.3 `ClientList.cpp:264-297`), until aMule's
//! client-list cleanup would have deleted that object: the first pass that
//! finds no record answering to the name. A low id is a
//! name only beside the server that assigned it: aMule matches one by id only
//! when the client's server IP and port are known and equal
//! (`ClientList.cpp:283-297`), so a candidate minted with no server known is
//! never a Low-ID name, and its facts never reach another record by its id.

use std::time::Instant;

use rmule_peer::{PeerIdentity, SourceExchangeSupport};
use rmule_primitives::{PeerEndpoint, UserHash};

use super::SourceBook;
use super::record::{Record, RecordId};
use crate::adapters::CallbackKey;
use crate::download::source_ask_clock::AskFacts;
use crate::download::state::LowIdCandidate;

/// One of the names a peer's ask facts are known by (ADR-0108, "Ask Name").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum AskName {
    /// The peer's TCP endpoint: a High-ID source's dial target, or the remote
    /// end of any connection.
    Endpoint(PeerEndpoint),
    /// A Low-ID callback's routing key, as the book holds it: an eD2k low id
    /// with the server that assigned it, or a Kad row's observed address and
    /// Kad UDP port.
    LowId(CallbackKey),
    /// The peer's User Hash, from a candidate's record, a record-stated crypt
    /// or a hello.
    User(UserHash),
}

impl From<PeerEndpoint> for AskName {
    fn from(endpoint: PeerEndpoint) -> Self {
        Self::Endpoint(endpoint)
    }
}

impl SourceBook {
    /// Whether a connection to the source at `endpoint` carries a source ask
    /// at `now`: aMule's `IsSourceRequestAllowed`, the peer-side half left to
    /// the session's hello. A source the book does not hold is a stranger.
    pub(crate) fn wants_sources_at(&self, endpoint: PeerEndpoint, now: Instant) -> bool {
        let facts = self
            .aliases
            .endpoint(endpoint)
            .map_or_else(AskFacts::default, |id| self.asks_of(id));
        facts.wants(self.file_asks, now, self.counts())
    }

    /// Whether the connection `key`'s callback brings carries a source ask at
    /// `now`, decided before the peer connects by the names its record holds.
    pub(crate) fn wants_sources_for(&self, key: CallbackKey, now: Instant) -> bool {
        let facts = self
            .aliases
            .key(key)
            .map_or_else(AskFacts::default, |id| self.asks_of(id));
        facts.wants(self.file_asks, now, self.counts())
    }

    /// Whether `id`'s whole source-ask gate is open at `now`: its hello allows
    /// the ask and the clock wants it. The reask sweep reads it to leave a due
    /// ask to the TCP full ask, which can carry it.
    pub(super) fn source_ask_due(&self, id: RecordId, now: Instant) -> bool {
        self.asks_of(id).due(self.file_asks, now, self.counts())
    }

    /// The connection at `endpoint` carried a source ask at `now`: the peer is
    /// asked, and the file reads "answered `SOURCECLIENTREASKS` less two
    /// latencies ago".
    pub(crate) fn asked(&mut self, endpoint: PeerEndpoint, now: Instant) {
        self.stamp(endpoint, |facts| facts.asked(now));
        self.file_asks.asked(now);
    }

    /// The peer at `endpoint` answered with its sources at `now`, empty or
    /// not: both clocks read now.
    pub(crate) fn answered(&mut self, endpoint: PeerEndpoint, now: Instant) {
        self.stamp(endpoint, |facts| facts.answered(now));
        self.file_asks.answered(now);
    }

    /// The peer at `endpoint`'s hello said `support` about source exchange.
    pub(crate) fn learned(&mut self, endpoint: PeerEndpoint, support: SourceExchangeSupport) {
        self.stamp(endpoint, |facts| facts.learned(support));
    }

    /// The peer at `endpoint` advertised its part status at `now`: complete or
    /// not.
    pub(crate) fn advertised(&mut self, endpoint: PeerEndpoint, complete: bool, now: Instant) {
        self.stamp(endpoint, |facts| facts.advertised(complete, now));
    }

    /// Land one stamp on the record `endpoint` names, or, when none does,
    /// under the endpoint in the run tier.
    fn stamp(&mut self, endpoint: PeerEndpoint, apply: impl FnOnce(&mut AskFacts)) {
        match self
            .aliases
            .endpoint(endpoint)
            .and_then(|id| self.records.get_mut(&id))
        {
            Some(record) => apply(&mut record.asks),
            None => {
                let mut stamped = AskFacts::default();
                apply(&mut stamped);
                self.run.keep_asks(AskName::Endpoint(endpoint), stamped);
            }
        }
    }

    /// The facts the gate reads for `id`: its own, every live record's that
    /// shares one of its User Hashes, and what the run kept under its names.
    pub(super) fn asks_of(&self, id: RecordId) -> AskFacts {
        let Some(record) = self.records.get(&id) else {
            return AskFacts::default();
        };
        let hashes = self.user_hashes(record);
        let kept = self
            .ask_names(record, &hashes)
            .into_iter()
            .filter_map(|name| self.run.kept_asks(name))
            .fold(record.asks, AskFacts::merge);
        self.records
            .iter()
            .filter(|&(&other, held)| {
                other != id
                    && self
                        .user_hashes(held)
                        .iter()
                        .any(|hash| hashes.contains(hash))
            })
            .fold(kept, |facts, (_, held)| facts.merge(held.asks))
    }

    /// Keep `id`'s facts under every name it answers to now, for the run: the
    /// record is about to drop one of them, or leave the book.
    pub(super) fn keep_asks(&mut self, id: RecordId) {
        let Some(record) = self.records.get(&id) else {
            return;
        };
        let facts = record.asks;
        if facts == AskFacts::default() {
            return;
        }
        let hashes = self.user_hashes(record);
        for name in self.ask_names(record, &hashes) {
            self.run.keep_asks(name, facts);
        }
    }

    /// aMule's client-list cleanup at `now` (`CClientList::CleanUpClientList`,
    /// stock 2.3.3 `ClientList.cpp:975-1003`): once a [`CLIENT_LIST_CLEANUP`]
    /// has passed since the last pass, the facts kept under every name no
    /// record answers to now are forgotten, as aMule deletes the client that is
    /// no source any more. A name some record answers to keeps its facts until
    /// a pass finds it unclaimed.
    ///
    /// [`CLIENT_LIST_CLEANUP`]: super::run_tier::CLIENT_LIST_CLEANUP
    pub(crate) fn clean_up_asks(&mut self, now: Instant) {
        if !self.run.cleanup_due(now) {
            return;
        }
        let claimed = self
            .records
            .values()
            .flat_map(|record| self.ask_names(record, &self.user_hashes(record)))
            .collect();
        self.run.clean_up_asks(now, &claimed);
    }

    /// When the next client-list cleanup falls due, while the run keeps any
    /// facts for one to forget.
    pub(crate) fn next_asks_cleanup(&self) -> Option<Instant> {
        self.run.next_asks_cleanup()
    }

    /// Every name `record` is known by: its endpoints, its `CallbackKey` when
    /// that names the peer beyond this record, and `hashes`.
    pub(super) fn ask_names(&self, record: &Record, hashes: &[UserHash]) -> Vec<AskName> {
        record
            .endpoints
            .iter()
            .map(|&endpoint| AskName::Endpoint(endpoint))
            .chain(record.candidate.as_ref().and_then(low_id_name))
            .chain(hashes.iter().map(|&hash| AskName::User(hash)))
            .collect()
    }

    /// The User Hashes `record` knows: its live worker's identity's, the one
    /// the hello its standing kept named (ADR-0049), its candidate's, and the
    /// one a record stated with its crypt at any of its endpoints.
    pub(super) fn user_hashes(&self, record: &Record) -> Vec<UserHash> {
        let mut hashes = Vec::new();
        let identified = record.stage.identity().map(PeerIdentity::user_hash);
        let queued_under = record
            .standing
            .and_then(|standing| standing.crypt())
            .map(|crypt| crypt.user_hash);
        let stated = record.endpoints.iter().map(|&endpoint| {
            self.run
                .record_crypt(endpoint)
                .and_then(|crypt| crypt.user_hash())
        });
        let candidate = record
            .candidate
            .as_ref()
            .and_then(|candidate| candidate.user_hash);
        let named = std::iter::once(identified)
            .chain(std::iter::once(queued_under))
            .chain(stated)
            .chain(std::iter::once(candidate));
        for hash in named.flatten() {
            if !hashes.contains(&hash) {
                hashes.push(hash);
            }
        }
        hashes
    }
}

/// `candidate`'s key as an Ask Name, when it names the peer beyond its record:
/// a Kad row's, or a low id beside the server that assigned it. One minted with
/// no server known is read against whichever server we are on, so it names
/// nobody past its record.
pub(super) fn low_id_name(candidate: &LowIdCandidate) -> Option<AskName> {
    (candidate.from_kad || candidate.source_server.is_some())
        .then(|| AskName::LowId(candidate.key()))
}
