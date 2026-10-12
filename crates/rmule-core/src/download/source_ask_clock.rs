//! The **Source Ask Clock**'s rule (ADR-0055 requester cadence, ADR-0108):
//! whether a download asks a peer for its sources on this connection.
//!
//! aMule decides with `IsSourceRequestAllowed` (stock 2.3.3
//! `DownloadClient.cpp:179-212`).
//! The peer-side conjuncts — the extended protocol, SourceExchange2 or an SX1
//! nibble above 1 — are read off the peer's hello by the peer session; this
//! rule holds the rest: the file's need for sources and the timing, kept per
//! (peer, download) because rmule runs one conversation per pair where aMule
//! runs one per peer with one requested file. The per-peer [`AskFacts`] ride
//! the peer's **Source Book** record, read under every **Ask Name** it has —
//! endpoint, Low-ID callback key, User Hash — so a Low-ID peer reached twice
//! is the same peer to the gate.
//!
//! The peer's last advertisement — complete or not, aMule's
//! `m_bCompleteSource` — is one of those facts, kept for the run, so a
//! complete source is asked on the common cadence even on a later connection.

use std::time::{Duration, Instant};

use rmule_peer::SourceExchangeSupport;

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

/// What this download knows of one peer: when it last asked, when the peer
/// last answered, what its hello said about source exchange, and its last
/// complete-or-not advertisement. It rides the peer's **Source Book** record
/// (ADR-0108), and the book keeps it under each name the record stops
/// answering to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AskFacts {
    asked: Option<Instant>,
    answered: Option<Instant>,
    /// `None` until a worker read the peer's hello.
    support: Option<SourceExchangeSupport>,
    /// aMule `m_bCompleteSource`, with when it was advertised: the latest
    /// advertisement across a peer's names is the one that counts.
    complete: Option<(Instant, bool)>,
}

impl AskFacts {
    /// Two names' facts read as one peer's: the latest of each stamp.
    pub(crate) fn merge(self, other: Self) -> Self {
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

    /// The connection carried a source ask at `now`.
    pub(crate) fn asked(&mut self, now: Instant) {
        self.asked = Some(now);
    }

    /// The peer answered with its sources at `now`, empty or not.
    pub(crate) fn answered(&mut self, now: Instant) {
        self.answered = Some(now);
    }

    /// The peer's hello said `support` about source exchange.
    pub(crate) fn learned(&mut self, support: SourceExchangeSupport) {
        self.support = Some(support);
    }

    /// The peer advertised its part status for this file at `now`: complete
    /// or not. The last advertisement stands for the run.
    pub(crate) fn advertised(&mut self, complete: bool, now: Instant) {
        self.complete = Some((now, complete));
    }

    /// Whether a connection to this peer at `now` carries a source ask, for a
    /// file whose own clock is `file` and whose source counts are `counts`. A
    /// peer never asked reads as never asked.
    pub(crate) fn wants(self, file: FileAskClock, now: Instant, counts: SourceCounts) -> bool {
        let SourceCounts {
            known: sources,
            valid,
        } = counts;
        let passed = |at: Option<Instant>| {
            at.map_or(Duration::MAX, |at| {
                now.saturating_duration_since(at) + CONNECTION_LATENCY
            })
        };
        let client = passed(self.answered);
        let file = passed(file.answered);
        let never_asked = self.asked.is_none();
        let complete = self.complete.is_some_and(|(_, complete)| complete);
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

    /// aMule's whole `IsSourceRequestAllowed` for this peer at `now` (stock
    /// 2.3.3 `DownloadClient.cpp:179-212`): the peer-side half off its hello,
    /// then [`Self::wants`]. A peer whose hello this run never read is not due
    /// — aMule reads an unknown client's extended protocol as absent. The
    /// reask sweep reads it: a due ask sends a pooled source's reask over TCP,
    /// where the ask can ride (`DownloadClient.cpp:1269-1273`).
    pub(crate) fn due(self, file: FileAskClock, now: Instant, counts: SourceCounts) -> bool {
        self.support.is_some_and(SourceExchangeSupport::askable) && self.wants(file, now, counts)
    }
}

/// The file's own source-ask clock: aMule `m_ClientSrcAnswered`, when any
/// peer last answered for the file, or the instant an ask pretended it did.
/// `None` is aMule's `0` — long ago.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FileAskClock {
    answered: Option<Instant>,
}

impl FileAskClock {
    /// A connection carried a source ask at `now`: the file reads "answered
    /// `SOURCECLIENTREASKS` less two latencies ago" (aMule
    /// `SetLastAnsweredTimeTimeout`, stock 2.3.3 `PartFile.cpp:2520-2523`).
    pub(crate) fn asked(&mut self, now: Instant) {
        self.answered = now.checked_sub(CLIENT_REASK - CONNECTION_LATENCY * 2);
    }

    /// A peer answered with its sources at `now` (stock 2.3.3
    /// `ClientTCPSocket.cpp:1513-1515`).
    pub(crate) fn answered(&mut self, now: Instant) {
        self.answered = Some(now);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer this download knows nothing of.
    fn stranger() -> AskFacts {
        AskFacts::default()
    }

    /// A peer asked and answering at `at`.
    fn answered_at(at: Instant) -> AskFacts {
        let mut facts = AskFacts::default();
        facts.asked(at);
        facts.answered(at);
        facts
    }

    /// The file's clock after an answer at `at`.
    fn file_answered_at(at: Instant) -> FileAskClock {
        let mut file = FileAskClock::default();
        file.answered(at);
        file
    }

    fn counts(known: u32, valid: u32) -> SourceCounts {
        SourceCounts { known, valid }
    }

    /// A far-enough origin that every `now - duration` below stays in range.
    fn origin() -> Instant {
        Instant::now() + Duration::from_secs(24 * 3600)
    }

    #[test]
    fn a_file_at_the_soft_cap_asks_nobody() {
        let file = FileAskClock::default();
        assert!(!stranger().wants(file, origin(), counts(SOURCE_ASK_SOFT_CAP, 0)));
        assert!(stranger().wants(file, origin(), counts(SOURCE_ASK_SOFT_CAP - 1, 0)));
    }

    /// A very rare file (≤ 10 sources) asks every peer it never asked, and a
    /// peer that answered only after 40 minutes.
    #[test]
    fn a_very_rare_file_reasks_a_peer_after_forty_minutes() {
        let now = origin();
        let file = file_answered_at(now);
        let peer = answered_at(now);
        assert!(!peer.wants(file, now + Duration::from_secs(30 * 60), counts(4, 1)));
        // 38 minutes plus the 22 s latency is short of 40; 40 is past it.
        assert!(!peer.wants(file, now + Duration::from_secs(38 * 60), counts(4, 1)));
        assert!(peer.wants(file, now + Duration::from_secs(40 * 60), counts(4, 1)));
        // Another peer, never asked, may be asked at once.
        assert!(stranger().wants(file, now, counts(4, 1)));
    }

    /// A rare file (≤ 50 sources) also waits five minutes after any peer
    /// answered before asking the next.
    #[test]
    fn a_rare_file_waits_five_minutes_after_any_answer() {
        let now = origin();
        let file = file_answered_at(now);
        assert!(!stranger().wants(file, now + Duration::from_secs(4 * 60), counts(30, 20)));
        assert!(stranger().wants(file, now + Duration::from_secs(5 * 60), counts(30, 20)));
    }

    /// A common file (many valid sources) asks a new peer only 20 minutes after
    /// the last answer, and the same peer only after 160.
    #[test]
    fn a_common_file_carries_the_fourfold_penalty() {
        let now = origin();
        let file = file_answered_at(now);
        let peer = answered_at(now);
        let common = counts(200, 100);
        assert!(!stranger().wants(file, now + Duration::from_secs(19 * 60), common));
        assert!(stranger().wants(file, now + Duration::from_secs(20 * 60), common));
        assert!(!peer.wants(file, now + Duration::from_secs(150 * 60), common));
        assert!(peer.wants(file, now + Duration::from_secs(160 * 60), common));
    }

    /// An ask that is never answered sets the file's clock to "answered
    /// 40 minutes less 44.1 s ago", so a common file's next peer is not held
    /// for 20 minutes by a silence, and a rare file's is asked at once.
    #[test]
    fn an_unanswered_ask_leaves_the_file_clock_just_short_of_forty_minutes() {
        let now = origin();
        let mut file = FileAskClock::default();
        let mut silent = AskFacts::default();
        silent.asked(now);
        file.asked(now);
        assert!(stranger().wants(file, now, counts(30, 20)));
        assert!(stranger().wants(file, now, counts(200, 100)));
        // aMule's client clock runs from the peer's last answer, not its last
        // ask: a peer that asked-and-stayed-silent is due again.
        assert!(silent.wants(file, now, counts(30, 20)));
    }

    /// The reask sweep's gate is the whole of aMule's: a peer whose hello the
    /// run never read, or one that cannot be asked, is never due; an askable
    /// one is due exactly while the clock wants it.
    #[test]
    fn a_source_ask_is_due_only_for_a_peer_whose_hello_allows_it() {
        let now = origin();
        let file = FileAskClock::default();
        assert!(!stranger().due(file, now, counts(4, 1)), "no hello read");
        let mut sx1 = AskFacts::default();
        sx1.learned(SourceExchangeSupport::new(true, 1, false));
        assert!(!sx1.due(file, now, counts(4, 1)), "SX1 nibble 1");
        let mut sx2 = AskFacts::default();
        sx2.learned(SourceExchangeSupport::new(true, 0, true));
        assert!(sx2.due(file, now, counts(4, 1)), "SourceExchange2");
        sx2.asked(now);
        sx2.answered(now);
        assert!(!sx2.due(file, now + Duration::from_secs(60), counts(4, 1)));
    }

    /// A source that advertised the whole file is asked only on the common
    /// cadence (aMule `m_bCompleteSource`, ADR-0108): a very rare file re-asks
    /// a partial source after 40 minutes, a complete one only after 160 — and
    /// its next advertisement is the one that counts.
    #[test]
    fn a_complete_source_waits_for_the_common_cadence() {
        let asked_at = origin();
        let file = file_answered_at(asked_at);
        let mut peer = answered_at(asked_at);
        let later = asked_at + Duration::from_secs(45 * 60);
        assert!(peer.wants(file, later, counts(4, 1)));
        peer.advertised(true, later);
        assert!(!peer.wants(file, later, counts(4, 1)));
        assert!(peer.wants(file, asked_at + Duration::from_secs(160 * 60), counts(4, 1)));
        peer.advertised(false, later + Duration::from_secs(1));
        assert!(peer.wants(file, later, counts(4, 1)));
    }
}
