//! The **Source Book** (ADR-0090): the one place a download's sources live and
//! where it is decided who owns each. One record per source, known by its
//! aliases — up to two endpoints and a `CallbackKey` — through one index, and
//! carrying exactly one stage, so one owner holds a source by construction.
//!
//! The book takes every **Source Sighting** through one entry and merges a held
//! source rather than pooling it twice; two records merge only on wire proof.
//! It holds the blocks (spent endpoints, distrusted peers) that outlive its
//! records, the run-tier facts that are folded into a record sighted later,
//! the lanes a fill drains, and each peer's source-ask facts (ADR-0108). It answers in its own typed outcomes and never
//! sees a `Decision`: the **Download State** maps each to the decisions it
//! means, and keeps the slots' diagnostics numbers and the part scheduler.

mod aliases;
mod asks;
mod blocks;
mod exchange;
mod frequency;
mod gate;
mod grant;
mod lanes;
mod purge;
mod record;
mod road;
mod run_tier;
mod sighting;
mod stages;
mod standing;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use rmule_peer::PeerIdentity;
use rmule_primitives::{Ipv4Endpoint, PeerCrypt, PeerEndpoint, UserHash};

use self::aliases::Aliases;
use self::blocks::Blocks;
use self::frequency::PartFrequency;
pub(crate) use self::gate::Gate;
use self::lanes::Lanes;
#[cfg(test)]
pub(crate) use self::purge::{
    LOW_TO_LOW_PURGE_SPACING, NO_NEEDED_PARTS_PURGE_SPACING, QUEUE_FULL_PURGE_SPACING,
    SOURCE_PURGE_AT,
};
pub(crate) use self::purge::{PurgeKind, Purged};
pub(crate) use self::record::Lane;
use self::record::{DialRoad, Record, RecordId, Stage, stated_crypt};
pub(crate) use self::road::Deadline;
#[cfg(test)]
pub(crate) use self::run_tier::CLIENT_LIST_CLEANUP;
use self::run_tier::RunTier;
pub(crate) use self::standing::{Answer, Reask, ReaskGates, UDP_REASK_LEAD};
#[cfg(test)]
pub(crate) use self::standing::{FILE_REASK_TIME, NO_NEEDED_PARTS_MULTIPLIER, REASK_RECHECK};
use crate::adapters::CallbackKey;
use crate::download::source_ask_clock::{FileAskClock, SourceCounts};
use crate::download::state::{LowIdCandidate, LowIdRoad};

/// What one sighting did to the book.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sighted {
    /// A new record was pooled — at this endpoint, when it is dialable.
    Pooled(Option<PeerEndpoint>),
    /// The sighting's facts folded into a record the book already held. When
    /// it proved two held records one peer, the one that gave way may have
    /// had a worker or a callback in flight, which ends.
    Merged(Option<MergeEnd>),
    /// Nothing was pooled.
    Blocked(Blocked),
}

/// Why a sighting pooled nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Blocked {
    /// Every address it named lies in a Reserved Range its Informant cannot
    /// vouch for (ADR-0085; aMule `IsGoodIP`).
    Reserved,
    /// The IP filter refuses every address it named (aMule
    /// `CPartFile::AddSources`).
    IpFiltered,
    /// Its only address is IPv6 and this node holds no IPv6 to dial it from
    /// (ADR-0087).
    FamilyUnreachable,
    /// It named a distrusted User Hash (ADR-0090 invariant 4).
    Distrusted,
    /// Every endpoint it named is spent (invariant 3).
    Spent,
    /// It names no road at all: no address, and no Low ID or Kad callback.
    Unreachable,
}

/// The road a record that gave way in a merge still had in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MergeEnd {
    /// Its worker at this endpoint ends, unspent: the peer is alive.
    Worker(PeerEndpoint),
    /// Its callback ends; its facts live on in the record that kept them.
    Callback(CallbackKey),
}

/// The next dial a free slot takes, chosen in lane order and already moved to
/// its stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NextDial {
    /// Put a worker on this endpoint: a High ID or a rung-0 IPv6 half.
    Worker(PeerEndpoint),
    /// Open this Low-ID road for the candidate.
    Callback {
        /// The candidate, as every channel named it.
        candidate: LowIdCandidate,
        /// The road the admission rule picked.
        road: LowIdRoad,
    },
}

/// How a worker's end left its record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkerEnd {
    /// The dial ended short of a handshake.
    Dial(DialEnd),
    /// The worker had reached the peer, or dialed nothing.
    Release(Release),
}

/// A failed dial's end: its endpoint is spent, and the record takes whatever
/// road it has left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DialEnd {
    /// No road is left: the record leaves the book.
    Spent,
    /// The same peer's other half goes first in the High-ID lane.
    FellToOtherHalf(PeerEndpoint),
    /// A Low-ID candidate goes first in its lane, for its callback roads.
    ToCallbackRoad,
}

/// A worker's or a callback's end that spends nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Release {
    /// The record waits in a lane again.
    BackToLane,
    /// Its queue standing keeps it in the RemoteQueued stage.
    RemoteQueued,
    /// The record leaves the book.
    Gone,
}

/// What an adopted callback became.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Adopted {
    /// The record's worker is dialing in on the endpoint.
    Worker,
    /// A worker already holds that endpoint: the callback's record joined it
    /// and holds no slot of its own.
    Joined,
}

/// One download's sources. See the module docs.
#[derive(Debug)]
pub(crate) struct SourceBook {
    records: HashMap<RecordId, Record>,
    minted: u64,
    aliases: Aliases,
    lanes: Lanes,
    blocks: Blocks,
    run: RunTier,
    /// The file's own source-ask clock (ADR-0108).
    file_asks: FileAskClock,
    /// The server we are logged into, when known by address: which Low-ID
    /// lane a candidate waits in.
    own_server: Option<Ipv4Endpoint>,
    /// When a purge last let a source go, or the run started: `None` before
    /// the first tick.
    purged_at: Option<Instant>,
    /// Part Frequency over the records' Advertised Parts (ADR-0112).
    frequency: PartFrequency,
}

impl SourceBook {
    /// The empty book a run starts with, holding the distrust the download's
    /// record carries, for a file of `part_count` parts. Every source reaches
    /// it as a sighting.
    pub(crate) fn new(distrusted: HashSet<UserHash>, part_count: u32) -> Self {
        Self {
            records: HashMap::new(),
            minted: 0,
            aliases: Aliases::default(),
            lanes: Lanes::default(),
            blocks: Blocks::new(distrusted),
            run: RunTier::default(),
            file_asks: FileAskClock::default(),
            own_server: None,
            purged_at: None,
            frequency: PartFrequency::new(part_count),
        }
    }

    /// We are logged into `server` now: a pooled Low-ID candidate it
    /// assigned waits in the connected lane, one another server assigned —
    /// our former server included — in the global lane, each keeping its
    /// order.
    pub(crate) fn logged_into(&mut self, server: Option<Ipv4Endpoint>) {
        if server == self.own_server {
            return;
        }
        self.own_server = server;
        for from in [Lane::LowIdConnected, Lane::LowIdGlobal] {
            let moving: Vec<(RecordId, Lane)> = self
                .lanes
                .iter(from)
                .filter_map(|id| {
                    let candidate = self.records.get(&id)?.candidate.as_ref()?;
                    let lane = Lane::of(candidate, server);
                    (lane != from).then_some((id, lane))
                })
                .collect();
            for (id, lane) in moving {
                self.lanes.remove(from, id);
                self.lanes.push_back(lane, id);
                if let Some(record) = self.records.get_mut(&id) {
                    record.stage = Stage::Pooled(lane);
                }
            }
        }
    }

    /// Mark the record pooled at `endpoint` as restored from a **Source Seed**
    /// there (ADR-0109).
    pub(crate) fn remember(&mut self, endpoint: PeerEndpoint) {
        if let Some(id) = self.aliases.endpoint(endpoint)
            && let Some(record) = self.records.get_mut(&id)
        {
            record.seed = Some(endpoint);
        }
    }

    /// Whether `endpoint` is held for a dial: first in the High-ID lane, a
    /// worker's, or holding a queue standing.
    pub(crate) fn holds(&self, endpoint: PeerEndpoint) -> bool {
        self.record_at(endpoint)
            .is_some_and(|record| match record.stage {
                Stage::RemoteQueued(at) => at == endpoint,
                _ => Self::pooled_or_live_at(record, endpoint),
            })
    }

    /// Whether `endpoint` is first in the High-ID lane or a worker's.
    pub(crate) fn is_pooled_or_live(&self, endpoint: PeerEndpoint) -> bool {
        self.record_at(endpoint)
            .is_some_and(|record| Self::pooled_or_live_at(record, endpoint))
    }

    fn pooled_or_live_at(record: &Record, endpoint: PeerEndpoint) -> bool {
        match record.stage {
            Stage::Pooled(Lane::HighId) => record.endpoints.first() == Some(&endpoint),
            _ => record.live_at(endpoint).is_some(),
        }
    }

    /// Whether `endpoint` sits out a re-ask period (ADR-0090 invariant 3).
    pub(crate) fn is_spent(&self, endpoint: PeerEndpoint) -> bool {
        self.blocks.is_spent(endpoint)
    }

    /// Whether a source named by `user_hash` is distrusted.
    pub(crate) fn distrusts(&self, user_hash: Option<UserHash>) -> bool {
        self.blocks.distrusts(user_hash)
    }

    /// The brain's tick at `now`: once a `FILEREASKTIME` period has passed,
    /// endpoints spent two periods ago may be dialed again when next sighted.
    /// Nothing is re-pooled here. The first instant starts the period.
    pub(crate) fn turn_spent(&mut self, now: Instant) {
        self.blocks.turn_at(now);
    }

    /// When the spent endpoints' generations next turn.
    pub(crate) fn next_spent_turn(&self) -> Option<Instant> {
        self.blocks.next_turn()
    }

    /// Whether `endpoint`'s record came from a seed at that endpoint.
    pub(crate) fn is_remembered(&self, endpoint: PeerEndpoint) -> bool {
        self.record_at(endpoint)
            .is_some_and(|record| record.seed == Some(endpoint))
    }

    /// The crypt side `endpoint` stated — its stance and User Hash — by the
    /// ADR-0049 precedence: the live worker's own hello, else what a record
    /// stated, else, for a dial at a Low-ID candidate's half, the candidate's,
    /// else nothing stated.
    pub(crate) fn peer_crypt(&self, endpoint: PeerEndpoint) -> PeerCrypt {
        let record = self.record_at(endpoint);
        self.identity(endpoint)
            .map(stated_crypt)
            .or_else(|| self.run.record_crypt(endpoint))
            .or_else(|| {
                let record = record?;
                let live = record.live_at(endpoint)?;
                (live.road == DialRoad::Rung0)
                    .then(|| record.candidate.as_ref().map(LowIdCandidate::peer_crypt))
                    .flatten()
            })
            .unwrap_or_default()
    }

    /// The identity the live worker at `endpoint` holds, once its peer
    /// identified (ADR-0049): gone with that worker.
    pub(crate) fn identity(&self, endpoint: PeerEndpoint) -> Option<&PeerIdentity> {
        let record = self.record_at(endpoint)?;
        record.live_at(endpoint)?;
        record.stage.identity()
    }

    /// The counts the source-ask rule reads (aMule's): every source the book
    /// holds, and those on queue, downloading or connected
    /// (`GetValidSourcesCount`, stock 2.3.3 `PartFile.cpp:3467-3496`) — each
    /// once, because each is one record.
    pub(crate) fn counts(&self) -> SourceCounts {
        let valid = self
            .records
            .values()
            .filter(|record| {
                record.stage.live().is_some() || matches!(record.stage, Stage::RemoteQueued(_))
            })
            .count();
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        SourceCounts {
            known: count(self.records.len()),
            valid: count(valid),
        }
    }

    /// How many worker slots the stages hold: every dial, worker and callback
    /// in flight.
    pub(crate) fn slots_in_use(&self) -> usize {
        self.records
            .values()
            .filter(|record| record.stage.holds_slot())
            .count()
    }

    fn record_at(&self, endpoint: PeerEndpoint) -> Option<&Record> {
        self.records.get(&self.aliases.endpoint(endpoint)?)
    }

    fn record_at_mut(&mut self, endpoint: PeerEndpoint) -> Option<&mut Record> {
        self.records.get_mut(&self.aliases.endpoint(endpoint)?)
    }

    /// The record whose live worker is at `endpoint`.
    fn live_record_mut(&mut self, endpoint: PeerEndpoint) -> Option<&mut Record> {
        self.record_at_mut(endpoint)
            .filter(|record| record.live_at(endpoint).is_some())
    }

    /// File `record` under a new id, binding every alias it names.
    fn insert(&mut self, record: Record) -> RecordId {
        let id = RecordId(self.minted);
        self.minted += 1;
        for &endpoint in &record.endpoints {
            self.aliases.bind_endpoint(endpoint, id);
        }
        if let Some(candidate) = &record.candidate {
            self.aliases.bind_key(candidate.key(), id);
        }
        self.records.insert(id, record);
        id
    }

    /// Take `id` out of the book: its aliases, its lane, the record, and its
    /// Advertised Parts out of Part Frequency. What its source asks stamped
    /// stays under its names for the run.
    fn remove(&mut self, id: RecordId) -> Option<Record> {
        self.keep_asks(id);
        let record = self.records.remove(&id)?;
        if let Some(parts) = &record.advertised {
            self.frequency.subtract(parts);
        }
        for &endpoint in &record.endpoints {
            self.aliases.unbind_endpoint(endpoint, id);
        }
        if let Some(candidate) = &record.candidate {
            self.aliases.unbind_key(candidate.key(), id);
        }
        if let Stage::Pooled(lane) = record.stage {
            self.lanes.remove(lane, id);
        }
        Some(record)
    }

    /// Spend `id` under every **Ask Name** it holds — its endpoints, its
    /// Low-ID key, the User Hashes it knows, the one its standing keeps from
    /// the hello it queued under among them — and take it out of the book: its
    /// source said it lacks the file (ADR-0090). A sighting under any of those
    /// names is refused for the spent period.
    fn spend_lacking(&mut self, id: RecordId) {
        let Some(record) = self.records.get(&id) else {
            return;
        };
        let mut hashes = self.user_hashes(record);
        if let Some(queued_under) = record.standing.and_then(|standing| standing.crypt())
            && !hashes.contains(&queued_under.user_hash)
        {
            hashes.push(queued_under.user_hash);
        }
        for name in self.ask_names(record, &hashes) {
            self.blocks.spend(name);
        }
        self.remove(id);
    }

    /// Bind `endpoint` to `id`, if the record has room and nothing else
    /// answers to it.
    fn add_endpoint(&mut self, id: RecordId, endpoint: PeerEndpoint) {
        if self.aliases.endpoint(endpoint).is_some() {
            return;
        }
        let Some(record) = self.records.get_mut(&id) else {
            return;
        };
        if record.endpoints.len() < 2 {
            record.endpoints.push(endpoint);
            self.aliases.bind_endpoint(endpoint, id);
        }
    }

    /// Unbind every endpoint of `id` but `keep`.
    fn keep_only_endpoint(&mut self, id: RecordId, keep: Option<PeerEndpoint>) {
        self.keep_asks(id);
        let Some(record) = self.records.get_mut(&id) else {
            return;
        };
        for endpoint in std::mem::take(&mut record.endpoints) {
            if Some(endpoint) == keep {
                record.endpoints.push(endpoint);
            } else {
                self.aliases.unbind_endpoint(endpoint, id);
            }
        }
    }

    /// Drop `id`'s Low-ID candidate and its key: its road is done.
    fn drop_candidate(&mut self, id: RecordId) {
        self.keep_asks(id);
        let Some(record) = self.records.get_mut(&id) else {
            return;
        };
        if let Some(candidate) = record.candidate.take() {
            self.aliases.unbind_key(candidate.key(), id);
        }
    }
}
