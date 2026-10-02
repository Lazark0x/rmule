//! The **Source Ask Clock** (ADR-0055 requester cadence, ADR-0108): whether a
//! download asks a peer for its sources on this connection.
//!
//! aMule decides with `IsSourceRequestAllowed` (stock 2.3.3
//! `DownloadClient.cpp:179-212`).
//! The peer-side conjuncts — the extended protocol, SourceExchange2 or an SX1
//! nibble above 1 — are read off the peer's hello by the peer session; this
//! clock holds the rest: the file's need for sources and the timing, kept per
//! (peer, download) because rmule runs one conversation per pair where aMule
//! runs one per peer with one requested file. A peer is known by every
//! **Ask Name** it has — endpoint, Low-ID callback key, User Hash — so a
//! Low-ID peer reached twice is the same peer to the gate.
//!
//! The peer's last advertisement — complete or not, aMule's
//! `m_bCompleteSource` — is kept here per (peer, download) for the run, so a
//! complete source is asked on the common cadence even on a later connection.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rmule_peer::SourceExchangeSupport;
use rmule_primitives::{PeerEndpoint, UserHash};

use crate::adapters::CallbackKey;

/// aMule's soft per-file source cap at its default `MaxSourcesPerFile` of 300:
/// `min(300 × 0.9, 1000)` (stock 2.3.3 `Preferences.h:270-273`, `Preferences.cpp:1027`).
/// A file with this many sources asks nobody for more.
pub(crate) const SOURCE_ASK_SOFT_CAP: u32 = 270;

/// aMule `CONNECTION_LATENCY` (stock 2.3.3 `Constants.h:70`): added to every elapsed time.
const CONNECTION_LATENCY: Duration = Duration::from_millis(22_050);

/// aMule `SOURCECLIENTREASKS` (stock 2.3.3 `include/protocol/ed2k/Constants.h:38`; eMule
/// `Opcodes.h:68`, the same 40 minutes): how long a peer that answered sources is left alone.
/// aMule runs it from the peer's last answer (`DownloadClient.cpp:184`), eMule from its last
/// ask (`DownloadClient.cpp:220`); rmule follows aMule (ADR-0108). Not `MIN_REQUESTTIME`,
/// which spaces file requests and TCP reasks, never the source ask.
const CLIENT_REASK: Duration = Duration::from_secs(40 * 60);

/// aMule `SOURCECLIENTREASKF` (stock 2.3.3 `Constants.h:39`): how long after any peer
/// answered for the file the next peer may be asked.
const FILE_REASK: Duration = Duration::from_secs(5 * 60);

/// aMule `MINCOMMONPENALTY` (stock 2.3.3 `Constants.h:43`): the common file's multiplier.
const COMMON_PENALTY: u32 = 4;

/// aMule `RARE_FILE` (stock 2.3.3 `Constants.h:66`).
const RARE_FILE: u32 = 50;

/// One of the names a download's **Source Ask Clock** knows a peer by
/// (ADR-0108, "Ask Name"). aMule finds its one client object again by IP and
/// port, by `(low id, server)` for a Low-ID client, or by User Hash last
/// (stock 2.3.3 `ClientList.cpp:264-297`, `:334-343`); rmule keeps the same
/// facts under each name instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum AskName {
    /// The peer's TCP endpoint: a High-ID source's dial target, or the remote
    /// end of any connection.
    Endpoint(PeerEndpoint),
    /// A Low-ID callback's routing key, its server resolved — known before
    /// the peer connects.
    LowId(CallbackKey),
    /// The peer's User Hash, from a candidate's record or a hello.
    User(UserHash),
}

/// What this download knows of one name: when it last asked, when the peer
/// last answered, what its hello said about source exchange, and its last
/// complete-or-not advertisement.
#[derive(Clone, Copy, Debug, Default)]
struct PeerClock {
    asked: Option<Instant>,
    answered: Option<Instant>,
    /// `None` until a worker read the peer's hello.
    support: Option<SourceExchangeSupport>,
    /// aMule `m_bCompleteSource`, with when it was advertised: the latest
    /// advertisement across a peer's names is the one that counts.
    complete: Option<(Instant, bool)>,
}

impl PeerClock {
    /// Two names' facts read as one peer's: the latest of each stamp.
    fn merge(self, other: Self) -> Self {
        Self {
            asked: self.asked.max(other.asked),
            answered: self.answered.max(other.answered),
            support: other.support.or(self.support),
            complete: match (self.complete, other.complete) {
                (Some(a), Some(b)) => Some(if b.0 > a.0 { b } else { a }),
                (a, b) => a.or(b),
            },
        }
    }
}

/// A file's source counts as aMule's source-ask rule reads them: every
/// source the run knows, and the `valid` ones among them — queued,
/// downloading or connected (aMule `GetValidSourcesCount`, stock 2.3.3
/// `PartFile.cpp:3467-3496`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SourceCounts {
    pub(crate) known: u32,
    pub(crate) valid: u32,
}

/// One download's source-ask clocks: per Ask Name, and the file's own.
#[derive(Debug, Default)]
pub(crate) struct SourceAskClock {
    peers: HashMap<AskName, PeerClock>,
    /// The other names a live connection's endpoint is known by: its callback
    /// key from adoption, its User Hash from its hello. A binding ends with
    /// its worker; what was stamped stays under every name for the run.
    bound: HashMap<PeerEndpoint, Vec<AskName>>,
    /// aMule `m_ClientSrcAnswered`: when any peer last answered for the file,
    /// or the instant an ask pretended it did. `None` is aMule's `0` — long
    /// ago.
    file_answered: Option<Instant>,
}

impl SourceAskClock {
    /// Whether a connection to the peer known by `names` at `now` carries a
    /// source ask, for a file with source `counts`. A peer none of whose
    /// names was ever asked reads as never asked.
    pub(crate) fn wants(&self, names: &[AskName], now: Instant, counts: SourceCounts) -> bool {
        let SourceCounts {
            known: sources,
            valid,
        } = counts;
        let clock = self.read(names.iter().copied());
        let passed = |at: Option<Instant>| {
            at.map_or(Duration::MAX, |at| {
                now.saturating_duration_since(at) + CONNECTION_LATENCY
            })
        };
        let client = passed(clock.answered);
        let file = passed(self.file_answered);
        let never_asked = clock.asked.is_none();
        let complete = clock.complete.is_some_and(|(_, complete)| complete);
        let client_due = never_asked || client > CLIENT_REASK;
        let very_rare = !complete && client_due && sources <= RARE_FILE / 5;
        let rare = !complete
            && client_due
            && (sources <= RARE_FILE || sources.saturating_sub(valid) <= RARE_FILE / 2)
            && file > FILE_REASK;
        let common = (never_asked || client > CLIENT_REASK * COMMON_PENALTY)
            && file > FILE_REASK * COMMON_PENALTY;
        sources < SOURCE_ASK_SOFT_CAP && (very_rare || rare || common)
    }

    /// aMule's whole `IsSourceRequestAllowed` for the peer at `peer` at `now`
    /// (stock 2.3.3 `DownloadClient.cpp:179-212`): the peer-side half off its
    /// hello, then [`Self::wants`]. A peer whose hello this run never read is
    /// not due — aMule reads an unknown client's extended protocol as absent.
    /// The reask sweep reads it: a due ask sends a pooled source's reask over
    /// TCP, where the ask can ride (`DownloadClient.cpp:1269-1273`).
    pub(crate) fn due(&self, peer: PeerEndpoint, now: Instant, counts: SourceCounts) -> bool {
        let names = self.names_of(peer);
        self.read(names.iter().copied())
            .support
            .is_some_and(SourceExchangeSupport::askable)
            && self.wants(&names, now, counts)
    }

    /// The connection at `peer` is also known as `name` — its callback key at
    /// adoption, its User Hash at its hello — until [`Self::unbind`]. The
    /// connection's source-exchange facts are carried onto `name` now: the
    /// router may hand them up before the hello's name is bound (ADR-0108).
    pub(crate) fn bind(&mut self, peer: PeerEndpoint, name: AskName) {
        let support = self.read(self.names_of(peer).into_iter()).support;
        let names = self.bound.entry(peer).or_default();
        if !names.contains(&name) {
            names.push(name);
        }
        if let Some(support) = support {
            self.peers.entry(name).or_default().support = Some(support);
        }
    }

    /// The worker at `peer` ended: its endpoint is no longer bound to its
    /// other names. What was stamped stays under each.
    pub(crate) fn unbind(&mut self, peer: PeerEndpoint) {
        self.bound.remove(&peer);
    }

    /// `peer` advertised its part status for this file at `now`: complete or
    /// not (ADR-0108). The last advertisement stands for the run.
    pub(crate) fn advertised(&mut self, peer: PeerEndpoint, complete: bool, now: Instant) {
        self.stamp(peer, |clock| clock.complete = Some((now, complete)));
    }

    /// `peer`'s hello said `support` about source exchange.
    pub(crate) fn learned(&mut self, peer: PeerEndpoint, support: SourceExchangeSupport) {
        self.stamp(peer, |clock| clock.support = Some(support));
    }

    /// The connection at `peer` carried a source ask: stamp the peer asked,
    /// and the file's clock to "answered `SOURCECLIENTREASKS` less two
    /// latencies ago" (aMule `SetLastAnsweredTimeTimeout`, stock 2.3.3
    /// `PartFile.cpp:2520-2523`).
    pub(crate) fn asked(&mut self, peer: PeerEndpoint, now: Instant) {
        self.stamp(peer, |clock| clock.asked = Some(now));
        self.file_answered = now.checked_sub(CLIENT_REASK - CONNECTION_LATENCY * 2);
    }

    /// `peer` answered with its sources: both clocks read now (stock 2.3.3
    /// `ClientTCPSocket.cpp:1513-1515`).
    pub(crate) fn answered(&mut self, peer: PeerEndpoint, now: Instant) {
        self.stamp(peer, |clock| clock.answered = Some(now));
        self.file_answered = Some(now);
    }

    /// Every name the connection at `peer` is known by, its endpoint first.
    fn names_of(&self, peer: PeerEndpoint) -> Vec<AskName> {
        std::iter::once(AskName::Endpoint(peer))
            .chain(self.bound.get(&peer).into_iter().flatten().copied())
            .collect()
    }

    /// One peer's facts, merged across `names`.
    fn read(&self, names: impl Iterator<Item = AskName>) -> PeerClock {
        names
            .filter_map(|name| self.peers.get(&name).copied())
            .fold(PeerClock::default(), PeerClock::merge)
    }

    /// Apply one stamp under every name the connection at `peer` is known by.
    fn stamp(&mut self, peer: PeerEndpoint, apply: impl Fn(&mut PeerClock)) {
        for name in self.names_of(peer) {
            apply(self.peers.entry(name).or_default());
        }
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

    /// The one name a High-ID peer at `peer(last)` is decided by.
    fn at(last: u8) -> [AskName; 1] {
        [AskName::Endpoint(peer(last))]
    }

    /// A far-enough origin that every `now - duration` below stays in range.
    fn counts(known: u32, valid: u32) -> SourceCounts {
        SourceCounts { known, valid }
    }

    fn origin() -> Instant {
        Instant::now() + Duration::from_secs(24 * 3600)
    }

    #[test]
    fn a_file_at_the_soft_cap_asks_nobody() {
        let clock = SourceAskClock::default();
        assert!(!clock.wants(&at(1), origin(), counts(SOURCE_ASK_SOFT_CAP, 0)));
        assert!(clock.wants(&at(1), origin(), counts(SOURCE_ASK_SOFT_CAP - 1, 0)));
    }

    /// A very rare file (≤ 10 sources) asks every peer it never asked, and a
    /// peer that answered only after 40 minutes.
    #[test]
    fn a_very_rare_file_reasks_a_peer_after_forty_minutes() {
        let mut clock = SourceAskClock::default();
        let now = origin();
        assert!(clock.wants(&at(1), now, counts(4, 1)));
        clock.asked(peer(1), now);
        clock.answered(peer(1), now);
        assert!(!clock.wants(&at(1), now + Duration::from_secs(30 * 60), counts(4, 1)));
        // 38 minutes plus the 22 s latency is short of 40; 40 is past it.
        assert!(!clock.wants(&at(1), now + Duration::from_secs(38 * 60), counts(4, 1)));
        assert!(clock.wants(&at(1), now + Duration::from_secs(40 * 60), counts(4, 1)));
        // Another peer, never asked, may be asked at once.
        assert!(clock.wants(&at(2), now, counts(4, 1)));
    }

    /// A rare file (≤ 50 sources) also waits five minutes after any peer
    /// answered before asking the next.
    #[test]
    fn a_rare_file_waits_five_minutes_after_any_answer() {
        let mut clock = SourceAskClock::default();
        let now = origin();
        clock.asked(peer(1), now);
        clock.answered(peer(1), now);
        assert!(!clock.wants(&at(2), now + Duration::from_secs(4 * 60), counts(30, 20)));
        assert!(clock.wants(&at(2), now + Duration::from_secs(5 * 60), counts(30, 20)));
    }

    /// A common file (many valid sources) asks a new peer only 20 minutes after
    /// the last answer, and the same peer only after 160.
    #[test]
    fn a_common_file_carries_the_fourfold_penalty() {
        let mut clock = SourceAskClock::default();
        let now = origin();
        clock.asked(peer(1), now);
        clock.answered(peer(1), now);
        let common = counts(200, 100);
        assert!(!clock.wants(&at(2), now + Duration::from_secs(19 * 60), common));
        assert!(clock.wants(&at(2), now + Duration::from_secs(20 * 60), common));
        assert!(!clock.wants(&at(1), now + Duration::from_secs(150 * 60), common));
        assert!(clock.wants(&at(1), now + Duration::from_secs(160 * 60), common));
    }

    /// An ask that is never answered sets the file's clock to "answered
    /// 40 minutes less 44.1 s ago", so a common file's next peer is not held
    /// for 20 minutes by a silence, and a rare file's is asked at once.
    #[test]
    fn an_unanswered_ask_leaves_the_file_clock_just_short_of_forty_minutes() {
        let mut clock = SourceAskClock::default();
        let now = origin();
        clock.asked(peer(1), now);
        assert!(clock.wants(&at(2), now, counts(30, 20)));
        assert!(clock.wants(&at(2), now, counts(200, 100)));
        // aMule's client clock runs from the peer's last answer, not its last
        // ask: a peer that asked-and-stayed-silent is due again.
        assert!(clock.wants(&at(1), now, counts(30, 20)));
    }

    /// The reask sweep's gate is the whole of aMule's: a peer whose hello the
    /// run never read, or one that cannot be asked, is never due; an askable
    /// one is due exactly while the clock wants it.
    #[test]
    fn a_source_ask_is_due_only_for_a_peer_whose_hello_allows_it() {
        let mut clock = SourceAskClock::default();
        let now = origin();
        assert!(!clock.due(peer(1), now, counts(4, 1)), "no hello read");
        clock.learned(peer(1), SourceExchangeSupport::new(true, 1, false));
        assert!(!clock.due(peer(1), now, counts(4, 1)), "SX1 nibble 1");
        clock.learned(peer(2), SourceExchangeSupport::new(true, 0, true));
        assert!(clock.due(peer(2), now, counts(4, 1)), "SourceExchange2");
        clock.asked(peer(2), now);
        clock.answered(peer(2), now);
        assert!(!clock.due(peer(2), now + Duration::from_secs(60), counts(4, 1)));
    }

    /// A source that advertised the whole file is asked only on the common
    /// cadence (aMule `m_bCompleteSource`, ADR-0108): a very rare file re-asks
    /// a partial source after 40 minutes, a complete one only after 160 — and
    /// its next advertisement is the one that counts.
    #[test]
    fn a_complete_source_waits_for_the_common_cadence() {
        let mut clock = SourceAskClock::default();
        let asked_at = origin();
        clock.asked(peer(3), asked_at);
        clock.answered(peer(3), asked_at);
        let later = asked_at + Duration::from_secs(45 * 60);
        assert!(clock.wants(&at(3), later, counts(4, 1)));
        clock.advertised(peer(3), true, later);
        assert!(!clock.wants(&at(3), later, counts(4, 1)));
        assert!(clock.wants(
            &at(3),
            asked_at + Duration::from_secs(160 * 60),
            counts(4, 1)
        ));
        clock.advertised(peer(3), false, later + Duration::from_secs(1));
        assert!(clock.wants(&at(3), later, counts(4, 1)));
    }

    /// A Low-ID peer has no endpoint before it connects, so its callback is
    /// decided by the names it does have (ADR-0108, aMule
    /// `FindMatchingClient`): the `(server, low_id)` of its callback while that
    /// id holds, its User Hash after. A peer asked on one callback connection is
    /// the same peer to the next callback, and a stranger is still never asked.
    #[test]
    fn a_low_id_peer_called_back_again_is_the_peer_already_asked() {
        let server = Some(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 23), 4661));
        let first_id = CallbackKey {
            server,
            low_id: rmule_primitives::ClientId::from_u32(0x0003_1A2B),
        };
        let next_id = CallbackKey {
            server,
            low_id: rmule_primitives::ClientId::from_u32(0x0004_77C1),
        };
        let hash = UserHash::from_bytes([
            0xE4, 0x1B, 0x72, 0x09, 0xAD, 0x35, 0xC8, 0x60, 0x1F, 0x94, 0x2E, 0xB7, 0x58, 0x03,
            0xDA, 0x6C,
        ]);
        let connection = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 7), 51_234));
        let mut clock = SourceAskClock::default();
        let now = origin();
        assert!(clock.wants(&[AskName::LowId(first_id)], now, counts(4, 1)));

        clock.bind(connection, AskName::LowId(first_id));
        clock.bind(connection, AskName::User(hash));
        clock.asked(connection, now);
        clock.answered(connection, now);
        clock.unbind(connection);

        let later = now + Duration::from_secs(10 * 60);
        assert!(!clock.wants(&[AskName::LowId(first_id)], later, counts(4, 1)));
        assert!(!clock.wants(
            &[AskName::LowId(next_id), AskName::User(hash)],
            later,
            counts(4, 1)
        ));
        assert!(clock.wants(&[AskName::LowId(next_id)], later, counts(4, 1)));
    }

    /// The router can hand up a connection's source-exchange facts before the
    /// worker's `Identified` binds the peer's User Hash (ADR-0108): the binding
    /// carries them onto the hash, so the same peer on its next connection —
    /// another ephemeral endpoint, found by hash — is still known askable.
    #[test]
    fn facts_learned_before_the_hash_is_bound_reach_the_hash() {
        let hash = UserHash::from_bytes([
            0x5B, 0xC2, 0x0E, 0x97, 0x31, 0xD8, 0x6A, 0x14, 0xF3, 0x88, 0x27, 0xBD, 0x40, 0x9E,
            0x65, 0x0C,
        ]);
        let first = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 9), 50_117));
        let next = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 9), 50_342));
        let mut clock = SourceAskClock::default();
        let now = origin();
        clock.learned(first, SourceExchangeSupport::new(true, 3, false));
        clock.bind(first, AskName::User(hash));
        clock.unbind(first);

        assert!(
            !clock.due(next, now, counts(4, 1)),
            "a stranger's facts are unknown"
        );
        clock.bind(next, AskName::User(hash));
        assert!(clock.due(next, now, counts(4, 1)));
    }
}
