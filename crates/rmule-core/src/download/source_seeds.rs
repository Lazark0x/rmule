//! **Source Seeds** (ADR-0109, "Source Seeds"): the peers one download keeps in
//! the store so a restart can dial them before asking anyone — aMule's `.seeds`
//! file (`PartFile.cpp:939-1121`), kept for every running download.
//!
//! This module holds the vocabulary — a seed, its rank class, the operator's
//! count, the two clocks — and the [`SeedLedger`], the run's record of who
//! earned which class. The brain ranks from the ledger, the runner publishes
//! the ranking, the core actor writes it, and the store keeps it beside the
//! download's row.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroU8;
use std::time::Duration;

use rmule_primitives::{
    CryptStance, ExchangedSource, PeerEndpoint, PeerSource, SourceCryptOptions, UserHash,
};
use serde::{Deserialize, Serialize};

/// How old a written seed may be when attach loads it; an older one is
/// dropped without a dial. aMule allows two hours (`PartFile.cpp:1092`).
pub(crate) const SEED_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// How often the core actor writes every running download's seeds, beside
/// the write at **Quit**.
pub(crate) const SEED_WRITE_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// The most seeds one ranking carries: the largest count the operator can
/// ask for.
pub(crate) const MOST_SEEDS: usize = u8::MAX as usize;

/// What a seed earned this run, best first. The declaration order is the
/// ranking and the store's encoding: a new class goes at the end and bumps
/// the row's version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SeedRank {
    /// Sent this run at least one block of the file.
    Received,
    /// Granted this run a queue rank or an upload slot.
    Ranked,
    /// Held by an owner when the ranking was taken — pooled, worked or
    /// remote-queued — and not spent by a failed dial.
    Known,
}

/// One peer a download remembers: where to dial it, who it said it was, and
/// what it earned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSeed {
    /// The endpoint rmule dialed or pooled for its own dial, either family.
    pub endpoint: PeerEndpoint,
    /// The peer's User Hash, when its hello or its record named one.
    pub user_hash: Option<UserHash>,
    /// The peer's crypt stance, when its hello or its record stated one: a
    /// `required` policy refuses a dial whose stance is unknown (ADR-0049).
    pub crypt: Option<CryptStance>,
    /// The class it reached.
    pub rank: SeedRank,
}

impl SourceSeed {
    /// The seed as the candidate record a source of the run's first snapshot
    /// is made of, carrying its hash the way a `0x44` row does.
    pub(crate) const fn as_source(self) -> ExchangedSource {
        let source = match self.endpoint {
            PeerEndpoint::V4(endpoint) => PeerSource::HighId(endpoint),
            PeerEndpoint::V6(endpoint) => PeerSource::Ipv6(endpoint),
        };
        ExchangedSource::new(source, self.user_hash, crypt_options(self.crypt))
    }
}

/// A stance as the crypt-options byte a source-exchange v4 entry carries,
/// `(requires << 2) | (requests << 1) | supports` — the byte aMule writes
/// for each seed (`PartFile.cpp:1009-1013`).
pub(crate) const fn crypt_options(stance: Option<CryptStance>) -> Option<SourceCryptOptions> {
    match stance {
        Some(stance) => Some(SourceCryptOptions::from_byte(
            ((stance.requires() as u8) << 2)
                | ((stance.requests() as u8) << 1)
                | stance.supports() as u8,
        )),
        None => None,
    }
}

/// The operator's `Remember peers`: how many seeds each download keeps, 1 to
/// 255 (aMule's fixed `MAX_SAVED_SOURCES`, `PartFile.cpp:941`, is the
/// default).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RememberPeers(NonZeroU8);

impl RememberPeers {
    /// aMule's ten.
    pub const DEFAULT: Self = Self(NonZeroU8::new(10).expect("ten is not zero"));

    /// The count `peers` names.
    #[must_use]
    pub const fn new(peers: NonZeroU8) -> Self {
        Self(peers)
    }

    /// The count as stored text reads, or the default when unset or not a
    /// whole number from 1 to 255.
    #[must_use]
    pub fn parse(text: Option<&str>) -> Self {
        text.and_then(|text| text.trim().parse::<NonZeroU8>().ok())
            .map_or(Self::DEFAULT, Self)
    }

    /// How many seeds a download keeps.
    #[must_use]
    pub const fn get(self) -> NonZeroU8 {
        self.0
    }
}

impl Default for RememberPeers {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What one peer's hello named: its User Hash and the crypt stance it
/// stated, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SeedHello {
    pub(crate) user_hash: UserHash,
    pub(crate) crypt: Option<CryptStance>,
}

/// The best class an endpoint earned by a fact, and that fact's turn in the
/// ledger's sequence.
#[derive(Clone, Copy, Debug)]
struct Earned {
    rank: SeedRank,
    turn: u64,
}

/// The run's record of each dialable peer's best class and when it last
/// earned anything. Clock-free: "newest" is the ledger's own sequence.
#[derive(Debug, Default)]
pub(crate) struct SeedLedger {
    /// Every endpoint rmule pooled for its own dial or dialed: the only
    /// endpoints a seed may name.
    dialable: HashSet<PeerEndpoint>,
    /// The best class each endpoint earned by a fact, and that fact's turn.
    earned: HashMap<PeerEndpoint, Earned>,
    /// When each endpoint was last pooled or dialed.
    sighted: HashMap<PeerEndpoint, u64>,
    /// The User Hash and crypt stance each endpoint's hello named, kept for
    /// the run: a worker's end prunes the brain's own copy, and a seed still
    /// wants them.
    hellos: HashMap<PeerEndpoint, SeedHello>,
    turn: u64,
    /// Whether who is a seed, its class or its hello moved since the last
    /// [`Self::take_moved`] — what makes the ranking worth publishing now
    /// rather than at the next sweep.
    moved: bool,
}

impl SeedLedger {
    /// `peer` was pooled for rmule's own dial, or dialed.
    pub(crate) fn dialable(&mut self, peer: PeerEndpoint) {
        self.turn += 1;
        self.moved |= self.dialable.insert(peer);
        self.sighted.insert(peer, self.turn);
    }

    /// `peer`'s hello named `hello`.
    pub(crate) fn named(&mut self, peer: PeerEndpoint, hello: SeedHello) {
        self.moved |= self.hellos.insert(peer, hello) != Some(hello);
    }

    /// The User Hash and crypt stance `peer`'s hello named this run, if one
    /// did.
    pub(crate) fn hello(&self, peer: PeerEndpoint) -> Option<SeedHello> {
        self.hellos.get(&peer).copied()
    }

    /// `peer` earned `rank` just now: it keeps the best class it ever
    /// reached, and any fact makes it the newest.
    pub(crate) fn earned(&mut self, peer: PeerEndpoint, rank: SeedRank) {
        self.turn += 1;
        let turn = self.turn;
        let before = self.earned.get(&peer).map(|held| held.rank);
        let held = self
            .earned
            .entry(peer)
            .and_modify(|held| {
                *held = Earned {
                    rank: held.rank.min(rank),
                    turn,
                };
            })
            .or_insert(Earned { rank, turn });
        self.moved |= before != Some(held.rank);
    }

    /// Whether the seeds moved since the last call, clearing it.
    pub(crate) fn take_moved(&mut self) -> bool {
        std::mem::take(&mut self.moved)
    }

    /// Every dialable endpoint with the class it reached and its newest turn,
    /// best first and newest first within a class, up to [`MOST_SEEDS`].
    /// `known` says whether an endpoint that earned nothing is still held.
    pub(crate) fn ranking(
        &self,
        known: impl Fn(PeerEndpoint) -> bool,
    ) -> Vec<(PeerEndpoint, SeedRank)> {
        let mut ranked: Vec<(PeerEndpoint, Earned)> = self
            .dialable
            .iter()
            .filter_map(|&peer| match self.earned.get(&peer) {
                Some(&earned) => Some((peer, earned)),
                None if known(peer) => Some((
                    peer,
                    Earned {
                        rank: SeedRank::Known,
                        turn: self.sighted[&peer],
                    },
                )),
                None => None,
            })
            .collect();
        ranked.sort_by(|(_, a), (_, b)| a.rank.cmp(&b.rank).then(b.turn.cmp(&a.turn)));
        ranked.truncate(MOST_SEEDS);
        ranked
            .into_iter()
            .map(|(peer, earned)| (peer, earned.rank))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_primitives::Ipv4Endpoint;

    use super::*;

    fn peer(last: u8) -> PeerEndpoint {
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(192, 0, 2, last), 4662))
    }

    #[test]
    fn received_outranks_ranked_outranks_known_and_newest_leads_each_class() {
        let mut ledger = SeedLedger::default();
        for last in 1..=6 {
            ledger.dialable(peer(last));
        }
        ledger.earned(peer(1), SeedRank::Ranked);
        ledger.earned(peer(2), SeedRank::Received);
        ledger.earned(peer(3), SeedRank::Ranked);
        ledger.earned(peer(4), SeedRank::Received);
        // A rank after bytes keeps the bytes' class and is its newest fact.
        ledger.earned(peer(2), SeedRank::Ranked);
        assert_eq!(
            ledger.ranking(|_| true),
            [
                (peer(2), SeedRank::Received),
                (peer(4), SeedRank::Received),
                (peer(3), SeedRank::Ranked),
                (peer(1), SeedRank::Ranked),
                (peer(6), SeedRank::Known),
                (peer(5), SeedRank::Known),
            ]
        );
    }

    #[test]
    fn a_peer_that_earned_nothing_and_is_no_longer_held_is_not_a_seed() {
        let mut ledger = SeedLedger::default();
        ledger.dialable(peer(7));
        ledger.dialable(peer(8));
        ledger.earned(peer(9), SeedRank::Received);
        assert_eq!(
            ledger.ranking(|held| held == peer(8)),
            [(peer(8), SeedRank::Known)],
            "a peer never pooled for our own dial is no seed, whatever it sent"
        );
    }

    #[test]
    fn remember_peers_reads_one_to_255_and_defaults_otherwise() {
        assert_eq!(RememberPeers::parse(Some("25")).get().get(), 25);
        assert_eq!(RememberPeers::parse(Some("255")).get().get(), 255);
        for refused in [None, Some("0"), Some("256"), Some("ten")] {
            assert_eq!(RememberPeers::parse(refused), RememberPeers::DEFAULT);
        }
    }
}
