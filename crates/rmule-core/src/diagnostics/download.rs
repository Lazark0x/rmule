//! Per-download and per-upload diagnostics rows: worker slots and phases, the positional part map with its derived tallies, and the upload rows the serve task keeps.

use std::collections::BTreeMap;
use std::time::Instant;

use super::{
    ClientSoftware, DownloadId, DownloadMetadata, FileHash, PeerEndpoint, PeerRetirementReason,
};
use crate::content::HoleVerdict;
use crate::service::{CompletionStep, DialEnd};

/// Stable identifier for one peer worker slot inside one download.
/// Slot index is `0..peer_concurrency_per_download` and is assigned at
/// worker construction time; the peer the slot is bound to may change as
/// peers are retired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkerSlot(usize);

impl WorkerSlot {
    /// Wrap a raw slot index. Not validated against a download's concurrency —
    /// an out-of-range value simply names a slot no row will ever hold.
    #[must_use]
    pub const fn from_usize(slot: usize) -> Self {
        Self(slot)
    }

    /// The raw index, for ordering slots or printing them.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0
    }
}

/// Currently observed orchestration state of one worker slot.
///
/// Mixes connection-level facts (`Connecting`, `AskingFile`) with
/// orchestration facts (`WaitingForSlot`, `VerifyingPart`, `Retired`)
/// because hang investigation needs both in one place (ADR-0028). Every
/// phase has a writer at the transition it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerPhase {
    /// The slot holds no peer yet: its row as it is built, before its first
    /// phase is written.
    Idle,
    /// Dialing the peer and reading its hello.
    Connecting,
    /// The hello is done and the file asked; the worker waits for the probe's
    /// answer, which asks its slot or the hash set, or retires it (ADR-0112).
    AskingFile,
    /// Asked for the part hash set; its slot ask waits on the answer or the
    /// **Hash-Set Deadline** (ADR-0026).
    RequestingHashSet,
    /// The slot ask is out and the peer is queueing us. The longest phase by
    /// far on a busy source, and the one `slot_wait_timeout` bounds.
    WaitingForSlot {
        /// Our place in the peer's upload queue, once an `OP_QUEUERANKING`
        /// gives one; refreshed by each.
        rank: Option<u16>,
    },
    /// A part was handed at a grant and its first block has not arrived.
    RequestingPart {
        /// The zero-based part index asked for.
        part_index: u32,
    },
    /// Blocks are arriving. A slot stuck here with a flat `bytes_received` is a
    /// stalled source rather than a queued one.
    ReceivingPart {
        /// The zero-based part index being streamed.
        part_index: u32,
        /// Bytes of that part delivered so far by this worker; other workers may
        /// be filling the same part.
        bytes_received: u64,
    },
    /// The part's bytes are complete and its hash is being checked.
    VerifyingPart {
        /// The zero-based part index being checked.
        part_index: u32,
    },
    /// The worker left the fleet; the row stays, until the slot dials again,
    /// so the reason is visible after the fact.
    Retired {
        /// Why it left.
        reason: PeerRetirementReason,
    },
    /// The whole download stopped, so the worker was wound down rather than
    /// retired for a peer-specific reason.
    ShutDown,
}

/// Per-slot diagnostics row. One worker is its slot's only writer.
#[derive(Clone, Debug)]
pub struct WorkerEntry {
    slot: WorkerSlot,
    peer_endpoint: Option<PeerEndpoint>,
    phase: WorkerPhase,
    since: Instant,
    transition_count: u32,
    software: Option<ClientSoftware>,
    remembered: bool,
}

impl WorkerEntry {
    /// An empty row for `slot`: no peer attached and phase [`WorkerPhase::Idle`],
    /// timed from now.
    #[must_use]
    pub fn new(slot: WorkerSlot) -> Self {
        Self {
            slot,
            peer_endpoint: None,
            phase: WorkerPhase::Idle,
            since: Instant::now(),
            transition_count: 0,
            software: None,
            remembered: false,
        }
    }

    /// The slot this row belongs to; stable for the row's life.
    #[must_use]
    pub const fn slot(&self) -> WorkerSlot {
        self.slot
    }

    /// The peer currently in the slot, or `None` before one is attached. It
    /// changes over the download's life as peers are retired and backfilled.
    #[must_use]
    pub const fn peer_endpoint(&self) -> Option<PeerEndpoint> {
        self.peer_endpoint
    }

    /// What the worker is doing right now.
    #[must_use]
    pub const fn phase(&self) -> &WorkerPhase {
        &self.phase
    }

    /// When the current phase was entered — differenced against now, this is
    /// the dwell time that exposes a hang.
    #[must_use]
    pub const fn since(&self) -> Instant {
        self.since
    }

    /// How many phase changes this row has seen. A slot that churns without
    /// receiving bytes shows up here rather than in the phase alone. Saturates
    /// rather than wrapping.
    #[must_use]
    pub const fn transition_count(&self) -> u32 {
        self.transition_count
    }

    /// Which client the slot's peer runs, from its hello; `None` until the
    /// hello completes.
    #[must_use]
    pub const fn software(&self) -> Option<&ClientSoftware> {
        self.software.as_ref()
    }

    /// Bind the slot to the peer it is now working. Overwrites any previous
    /// peer — a backfilled slot names its new one, and forgets the old one's
    /// software until the new hello names its own.
    pub fn attach_peer(&mut self, peer: PeerEndpoint) {
        self.peer_endpoint = Some(peer);
        self.software = None;
        self.remembered = false;
    }

    /// Whether the slot's peer was dialed from the download's **Source
    /// Seeds** (ADR-0109): a peer the last run knew, dialed before anyone was
    /// asked.
    #[must_use]
    pub const fn remembered(&self) -> bool {
        self.remembered
    }

    /// Mark the slot's peer as dialed from a seed.
    pub fn mark_remembered(&mut self) {
        self.remembered = true;
    }

    /// Record the client the slot's peer named in its hello.
    pub fn identify(&mut self, software: ClientSoftware) {
        self.software = Some(software);
    }

    /// Move to a new phase, restarting the dwell clock and bumping the
    /// transition count. Called by the slot's single writer only.
    pub fn transition(&mut self, new: WorkerPhase) {
        self.phase = new;
        self.since = Instant::now();
        self.transition_count = self.transition_count.saturating_add(1);
    }
}

/// Where one ED2K part of a download stands (ADR-0079). The scheduler
/// partitions every part into exactly one of these, so the three are total
/// and mutually exclusive.
///
/// The scheduler's own vocabulary is *pending* / *racing* / gone (completion
/// is by absence); this is that partition in consumer words.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PartState {
    /// Hash-checked and persisted. Nothing will be fetched for it again.
    Verified,
    /// Assigned to at least one peer right now (ADR-0026's racing rule allows
    /// several) and not yet verified.
    InFlight,
    /// Not held and not assigned: still to be fetched.
    Missing,
}

/// The three part tallies, counted in one pass over
/// [`DownloadDiagnostics::parts`] (ADR-0079). They always sum to the vector's
/// length — they are a reading of it, not a second record of the same fact.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PartCounts {
    /// Parts hash-checked and persisted.
    pub verified: u32,
    /// Parts assigned to at least one worker right now.
    pub in_flight: u32,
    /// Parts neither held nor assigned.
    pub missing: u32,
}

impl PartCounts {
    /// Total parts counted — the length of the vector these came from, and
    /// `0` while the row has no part map yet.
    #[must_use]
    pub const fn total(self) -> u32 {
        self.verified + self.in_flight + self.missing
    }
}

/// Per-download diagnostics row. While a run exists, its part map is
/// populated by the per-download task at the same points where the scheduler
/// mutates, so the snapshot reflects live scheduler shape without duplicating
/// state. Without a run (paused, failed, waiting, restored) the row is at
/// rest: its part map is the durable picture — held and missing, nothing in
/// flight — and it has no workers (ADR-0094). Only a cancel removes it.
#[derive(Clone, Debug)]
pub struct DownloadDiagnostics {
    /// The download this row is for — the same id its events carry.
    pub download_id: DownloadId,
    /// The file's content identity.
    pub file_hash: FileHash,
    /// The download's stored name + exact byte size (ADR-0078), copied from
    /// its durable record when the row is opened. Immutable for the row's
    /// life, so a snapshot consumer reads it without joining the event
    /// stream.
    pub metadata: DownloadMetadata,
    /// When the current or last run started — not when the download was first
    /// queued: a resume restarts the clock on the row it finds at rest.
    pub started_at: Instant,
    /// Status of every part of the file, indexed by part number (ADR-0079):
    /// `parts[i]` is part `i`. Republished whole by the download runner's
    /// single writer whenever the scheduler settles, so it is a level, not a
    /// diff a consumer has to replay.
    ///
    /// A row at rest carries the durable picture instead: `Verified` where a
    /// part is held, `Missing` elsewhere, never `InFlight` (ADR-0094).
    ///
    /// A freshly opened row (the window between `StartDownload` and the
    /// first drain) holds every part `Missing`: the vector's length is the
    /// file's part count from the row's first snapshot on.
    pub parts: Vec<PartState>,
    /// How many workers have left the fleet over the row's life. Monotonic —
    /// the rows themselves are reused, so this is the only trace of churn.
    pub retired_peers: u32,
    /// The live slot rows, keyed by slot so the map's order is the slot order a
    /// renderer draws.
    pub workers: BTreeMap<WorkerSlot, WorkerEntry>,
    /// Payload bytes this download has taken off the wire since core opened
    /// its row, over every run of this process, summed over every worker
    /// (ADR-0077). Monotonic: it counts what
    /// peers *delivered*, so a block a later hash check discards still counts,
    /// and a duplicate range delivered by a second peer counts twice. It is a
    /// transfer fact, not a progress measure — the part map is progress.
    pub received_bytes: u64,
    /// Sources this run knows now — aMule's source count: the peers in a
    /// worker slot, the callbacks awaited, and the dial pools not yet tried.
    /// A level, republished with the part map at every settle; a source that
    /// failed and was retired has left it.
    pub known_sources: u32,
    /// Dials that ended before the peer's hello over the row's life —
    /// refused by policy, never dialed, or lost before the peer identified.
    /// Monotonic.
    pub dials_ended: u32,
    /// Reask replies routed to this download that changed nothing over the
    /// row's life (ADR-0057). Monotonic.
    pub reask_replies_ignored: u32,
    /// Each source whose last dial this run ended before its hello, by peer
    /// (ADR-0110, "The cause is the source's, not the slot's"). An entry
    /// leaves when a slot dials its peer again; it outlives the slot's next
    /// peer and the run's end, is cleared when a run starts, and at most
    /// [`DIAL_ENDS_KEPT`] are kept, the oldest leaving first.
    pub dial_ends: BTreeMap<PeerEndpoint, SourceDialEnd>,
    /// **Allocated Bytes**: what the filesystem reserved for the `.part`,
    /// read on the run's held handle when it holds the file and after each
    /// part written (ADR-0111). A storage reading, not a counter: it falls
    /// when a gap is punched and may exceed the file's length; core computes
    /// no ratio from it. `None` when not read, or when the last reading
    /// failed. The row keeps the last reading after the run ends; the next
    /// run's first reading replaces it.
    pub allocated_bytes: Option<u64>,
    /// The run's **Hole Verdict**: whether the disk under the `.part` holds
    /// holes, as the run's Hole Probe measured (ADR-0111). `None` from a run's
    /// start until its probe answers; the row keeps it after the run.
    pub hole_verdict: Option<HoleVerdict>,
    /// Where the run's completion move stands (ADR-0115): `None` until the
    /// move begins, and again once its run has ended.
    pub completion: Option<CompletionProgress>,
}

/// A completion move's step and the bytes its copy has written, as levels
/// the run publishes as each step begins and after each part it copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletionProgress {
    /// What the move is doing.
    pub step: CompletionStep,
    /// Bytes the Completion Copy has written: 0 until a copy begins, and kept
    /// through the steps that follow it.
    pub copied: u64,
}

/// The most [`DownloadDiagnostics::dial_ends`] a row keeps.
pub const DIAL_ENDS_KEPT: usize = 64;

/// Why a source's dial ended before its hello, and when (ADR-0110).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceDialEnd {
    /// Why the dial ended.
    pub cause: DialEnd,
    /// When it ended.
    pub at: Instant,
    /// The peer was dialed from the download's **Source Seeds**.
    pub remembered: bool,
}

impl DownloadDiagnostics {
    /// Tally [`Self::parts`] in one pass (ADR-0079). O(parts); a consumer
    /// wanting several of the three reads them from one call.
    #[must_use]
    pub fn part_counts(&self) -> PartCounts {
        let mut counts = PartCounts::default();
        for part in &self.parts {
            let bucket = match part {
                PartState::Verified => &mut counts.verified,
                PartState::InFlight => &mut counts.in_flight,
                PartState::Missing => &mut counts.missing,
            };
            *bucket += 1;
        }
        counts
    }

    /// Parts hash-checked and persisted — the download's progress.
    #[must_use]
    pub fn verified_parts(&self) -> u32 {
        self.part_counts().verified
    }

    /// Parts currently assigned to at least one peer.
    #[must_use]
    pub fn in_flight_parts(&self) -> u32 {
        self.part_counts().in_flight
    }

    /// Parts neither held nor assigned.
    #[must_use]
    pub fn missing_parts(&self) -> u32 {
        self.part_counts().missing
    }
}

/// Per-upload diagnostics row: what the serve activity has handed to one
/// peer holding an upload slot (ADR-0077). The serve task is the row's only
/// writer.
///
/// Keyed by peer, not by file, mirroring aMule's per-client
/// `m_nTransferredUp`: a slot holder is served one file at a time, and a
/// re-grant for a different file keeps accumulating against the same peer.
/// The row lives between the slot grant and its release — a finished upload
/// leaves the map, and only [`SessionCounters::up_bytes_total`](super::SessionCounters::up_bytes_total) remembers it.
#[derive(Clone, Debug)]
pub struct UploadDiagnostics {
    /// The slot holder being served — this row's key.
    pub peer: PeerEndpoint,
    /// The file whose blocks are currently being served to this peer.
    pub file_hash: FileHash,
    /// When the slot was granted.
    pub started_at: Instant,
    /// Payload bytes handed to this peer's connection writer since the row
    /// opened. Monotonic.
    pub bytes_sent: u64,
}
