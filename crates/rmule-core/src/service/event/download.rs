//! The download activity's event vocabulary (ADR-0030): what a download's run,
//! its sources and its part file did, one fact per event.

use std::path::PathBuf;

use rmule_primitives::FileHash;

use crate::{DownloadFailure, DownloadLifecycle, DownloadMetadata, StorageIntegrityFault};

use super::super::{DownloadId, PartReleaseReason, PeerRetirementReason, VerificationAuthority};

/// The download activity's event vocabulary. Wrapped by
/// [`CoreEvent::Download`](super::CoreEvent::Download); its serve-side sibling `ServeEvent` carries no
/// `DownloadId` on its variants.
#[derive(Clone, Debug)]
pub enum DownloadEvent {
    /// Core accepted a `StartDownload` and minted the activity: the first fact
    /// about this download, and the only place its id is introduced.
    DownloadQueued {
        /// The id every later event, command and diagnostics row for this
        /// download carries; it is also what the store persists.
        download_id: DownloadId,
        /// The ED2K file hash the download is pinned to — its content identity
        /// on every wire surface.
        file_hash: FileHash,
        /// The name + exact size core just recorded for this download
        /// (ADR-0078). Carried on the edge so a consumer that folds events
        /// into its own row has the file's identity in one message, without
        /// waiting for a diagnostics snapshot to join against.
        metadata: DownloadMetadata,
        /// Where the download's bytes lie now: its `.part` (ADR-0114).
        file_path: PathBuf,
    },
    /// A download the store held from an earlier run was re-admitted at
    /// startup. No task is running for it yet; `state` says what it was doing.
    DownloadRecovered {
        /// The id the store persisted, reused unchanged — ids survive restarts.
        download_id: DownloadId,
        /// Where the download stood when the last run ended.
        state: DownloadLifecycle,
        /// Why the last run failed, for a `Failed` download whose store row
        /// kept it (ADR-0094, "Failed"); `None` otherwise, and for a row
        /// failed before the store kept reasons.
        failure: Option<DownloadFailure>,
        /// The file's ED2K content identity, as the store recorded it.
        /// Carried with the name and size so a consumer folding events has
        /// the file's identity in this one message; the resting diagnostics
        /// row opened just before it carries the same facts.
        file_hash: FileHash,
        /// The name and exact size the store recorded for it.
        metadata: DownloadMetadata,
        /// Where the download's bytes lie now (ADR-0114): the finished file
        /// of a `Completed` download, the `.part` of any other.
        file_path: PathBuf,
    },
    /// Verified on-disk progress was read back for a recovered download, so a
    /// consumer can show it as partly complete before a single peer is dialed.
    DownloadProgressRestored {
        /// The recovered download the progress belongs to.
        download_id: DownloadId,
        /// How many parts passed their hash check in an earlier run and are
        /// never re-fetched.
        verified_parts: usize,
        /// The bytes those parts account for — the part size times the count,
        /// with the file's short tail part counted at its real length.
        verified_bytes: u64,
    },
    /// A resume found verified parts that no longer hold on disk and dropped
    /// their records, so the run fetches them again (ADR-0093, "Damaged
    /// parts"). Sent before the `DownloadProgressRestored` that counts what
    /// did hold.
    DamagedPartsDropped {
        /// The download whose parts were dropped.
        download_id: DownloadId,
        /// Each dropped part and what its check found, lowest part first.
        damaged: Vec<crate::PartFault>,
    },
    /// The run found that the file at its part file's path is not the file it
    /// holds, or no longer all of it (ADR-0094, "The run holds its part
    /// file"): removed, replaced or cut short. The verified parts it cost
    /// are dropped and are to be fetched again; a removed or replaced file
    /// fails the download (`PartFileMissing`) rather than being recreated, and
    /// a file cut short keeps its run going. Told even when the store cannot
    /// say which parts were lost; the download then fails as a store failure.
    PartFileLost {
        /// The download whose part file changed.
        download_id: DownloadId,
        /// What the run found.
        found: crate::PartFileChange,
        /// What that cost in verified parts.
        lost: PartsLost,
    },
    /// The finished file did not hash to the file's hash and no part could be
    /// named (ADR-0094, "Finalize with lost parts"): every recorded part, and
    /// the hash set a peer supplied, are dropped and fetched again. The run
    /// goes on; the download is not failed.
    FinishedFileRejected {
        /// The download whose finished file was rejected.
        download_id: DownloadId,
        /// How many recorded parts were dropped.
        parts_dropped: u32,
        /// How many bytes they held.
        bytes_dropped: u64,
    },
    /// The operator restarted a failed download (ADR-0094, "Restart"), and
    /// rmule chose how: it continued from what is on disk, or found nothing
    /// there to continue from and started over. Sent before the run's
    /// [`DownloadResumed`](Self::DownloadResumed).
    DownloadRestarted {
        /// The download restarted.
        download_id: DownloadId,
        /// Which of the two it did, and what that cost.
        outcome: RestartOutcome,
    },
    /// The server login this download rode completed; its assigned id decides
    /// whether the download can be called back (ADR-0039).
    ServerLoginAccepted {
        /// The download whose run performed the login.
        download_id: DownloadId,
        /// The id the server assigned: High-ID (a routable address) or Low-ID
        /// (< `0x00FFFFFF`, reachable only through server-relayed callbacks).
        client_id: rmule_primitives::ClientId,
    },
    /// The single server source lookup answered (`OP_FOUNDSOURCES`). One event
    /// per lookup, not per source.
    SourcesFound {
        /// The download the lookup was for.
        download_id: DownloadId,
        /// Every source the server named, Low-ID ones included.
        total: usize,
        /// The subset with a dialable endpoint — the candidate pool's size. The
        /// difference from `total` is the Low-ID tail, usable only with
        /// Callback Capability.
        usable_high_id: usize,
    },
    /// A connected source answered this download's source-exchange ask
    /// (`OP_ANSWERSOURCES` / `OP_ANSWERSOURCES2`, ADR-0055) — the
    /// download-side mirror of [`ServeEvent::SourcesServed`](super::ServeEvent::SourcesServed). One event per
    /// decoded answer.
    SourcesExchanged {
        /// The download the answer was for.
        download_id: DownloadId,
        /// The source that answered.
        peer: rmule_primitives::PeerEndpoint,
        /// How many sources the answer carried.
        received: usize,
        /// How many of them passed the ingest gate (IP filter, dial family).
        admitted: usize,
    },
    /// A second link for a file this download already runs for named sources,
    /// and they joined the run's candidate pool instead of a second download
    /// being made (ADR-0089's amendment; aMule `DownloadQueue.cpp:1461-1500`,
    /// eMule `DownloadQueue.cpp:271-295`). The `StartDownload` that carried the
    /// link mints nothing else.
    LinkSourcesAdded {
        /// The running download the sources joined.
        download_id: DownloadId,
        /// How many sources the link named that still stood — unexpired, and
        /// a named host only once it resolved.
        named: usize,
        /// How many of them passed the ingest gate (IP filter, dial family).
        admitted: usize,
        /// How many of the admitted the run did not already know, and so
        /// joined its pool: zero when the link repeats sources it holds.
        new: usize,
    },
    /// Attach read the **Source Seeds** of the downloads it restores
    /// (ADR-0109): once per attach, for all of them, before the first run
    /// starts. Each run then dials its own ([`Self::SeedsDialled`]).
    SeedsLoaded {
        /// How many restored downloads had a seed under a day old.
        downloads: usize,
        /// How many such seeds they hold together, to be dialed first.
        seeds: usize,
        /// How many older seeds the load dropped without a dial.
        expired: usize,
    },
    /// A run's **Source Seeds**, put ahead of every other source and dialled
    /// before any lookup, have all answered or ended — or the run ended
    /// first (ADR-0109). Said once per run that started with seeds.
    SeedsDialled {
        /// The download.
        download_id: DownloadId,
        /// How many seeds the last run wrote that were under a day old.
        written: usize,
        /// How many of them passed the ingest gate (IP filter, dial family)
        /// and entered the candidate pool.
        dialled: usize,
        /// How many of those the run reached and read a hello from.
        answered: usize,
    },
    /// A candidate was taken from the pool and a worker is being put on the
    /// wire for it. Precedes any connection outcome.
    PeerSelected {
        /// The download whose fleet the peer joins.
        download_id: DownloadId,
        /// The candidate being dialed.
        peer: rmule_primitives::PeerEndpoint,
    },
    /// The peer is holding us in its upload queue at position `rank`
    /// (`OP_QUEUERANKING`). Emitted on first observation and again each
    /// time the rank changes, so the caller sees queue progress instead
    /// of apparent silence while waiting for a slot.
    PeerQueued {
        /// The download waiting for the slot.
        download_id: DownloadId,
        /// The source holding us in its queue.
        peer: rmule_primitives::PeerEndpoint,
        /// Our position in that peer's upload queue, as it reported it.
        rank: u16,
    },
    /// The peer granted an upload slot (`OP_ACCEPTUPLOADREQ`); part bytes
    /// follow. Marks the queued→downloading transition for the caller.
    PeerSlotGranted {
        /// The download the slot was granted to.
        download_id: DownloadId,
        /// The source that granted it.
        peer: rmule_primitives::PeerEndpoint,
    },
    /// The worker waited `slot_wait_timeout` for a slot without a grant
    /// and gave up; the peer is retired and its part released for retry.
    PeerSlotTimeout {
        /// The download whose worker gave up waiting.
        download_id: DownloadId,
        /// The source that never granted a slot.
        peer: rmule_primitives::PeerEndpoint,
    },
    /// A source that queued us hung up and entered the **Remote-Queued Pool**
    /// (ADR-0057): its earned queue standing is now kept without a socket, on the
    /// `FILEREASKTIME` reask heartbeat, instead of being forfeited. `rank` is the
    /// last position we learned before disconnecting.
    SourceRemoteQueued {
        /// The download the pooled source still owes bytes to.
        download_id: DownloadId,
        /// The source that hung up while queueing us.
        peer: rmule_primitives::PeerEndpoint,
        /// The last rank learned before the disconnect; the reask cycle
        /// refreshes it.
        rank: u16,
    },
    /// A pooled source answered our UDP reask ping with `OP_REASKACK` (`0x91`):
    /// the fresh `rank` was recorded and its standing refreshed (ADR-0057).
    SourceReaskAcked {
        /// The download the refreshed standing belongs to.
        download_id: DownloadId,
        /// The pooled source that answered.
        peer: rmule_primitives::PeerEndpoint,
        /// The position it reported this cycle — lower is closer to a slot.
        rank: u16,
    },
    /// A pooled source answered `OP_QUEUEFULL` (`0x93`): its queue is (near) full,
    /// so its rank is cleared; it is reasked on the same cadence, and is the
    /// first let go when the file nears its source limit (ADR-0057).
    SourceReaskQueueFull {
        /// The download the deprioritized source belongs to.
        download_id: DownloadId,
        /// The source whose queue is (near) full.
        peer: rmule_primitives::PeerEndpoint,
    },
    /// A pooled source's `FILEREASKTIME` came with no answer to its ping, or no
    /// ping could reach it: its standing is re-asked by the **TCP full ask**
    /// (ADR-0057), and it leaves the pool for the road that first reached it —
    /// a dial at its endpoint, or a called-back source's callback road.
    SourceReaskedOverTcp {
        /// The download re-asking the source.
        download_id: DownloadId,
        /// The endpoint the source stood at.
        peer: rmule_primitives::PeerEndpoint,
    },
    /// A source was let go to make room: the file holds as many sources as
    /// aMule purges at, and one source goes at a time, on one clock per file
    /// (ADR-0057).
    SourcePurged {
        /// The download that let the source go.
        download_id: DownloadId,
        /// Which source went.
        source: super::PurgedSource,
        /// Why it was the one let go.
        reason: super::SourcePurgeReason,
    },
    /// A pooled source answered `OP_FILENOTFOUND` (`0x92`): it no longer shares
    /// the file, so it was dropped from the pool (ADR-0057 dead-source).
    SourceReaskDropped {
        /// The download that lost the source.
        download_id: DownloadId,
        /// The source that no longer shares the file.
        peer: rmule_primitives::PeerEndpoint,
    },
    /// A reask reply from `peer`'s client-UDP endpoint reached this download
    /// and changed nothing (ADR-0057): the standing it would have refreshed
    /// falls to the TCP full ask at the end of the 20 s lead.
    ReaskReplyIgnored {
        /// The download whose ping the reply was routed to.
        download_id: DownloadId,
        /// The client-UDP endpoint the reply came from.
        peer: rmule_primitives::PeerEndpoint,
        /// Why it was not taken.
        reason: super::IgnoredReaskReply,
    },
    /// A dial to `peer` ended before the peer's hello: refused by policy
    /// before any socket, never dialed, or lost before it identified. The
    /// source's slot is backfilled as for any lost worker.
    DialEnded {
        /// The download that dialed.
        download_id: DownloadId,
        /// The source that was dialed.
        peer: rmule_primitives::PeerEndpoint,
        /// Why the dial ended.
        cause: super::DialEnd,
    },
    /// The part hash set the run verifies against is settled — from the link,
    /// from a peer, or from the store. Every later `PartVerified` is checked
    /// against it.
    HashSetReceived {
        /// The download the hash set governs.
        download_id: DownloadId,
        /// How many parts the file has under it.
        part_count: usize,
        /// Where the hashes came from, which is what a part verification is
        /// worth: a link-borne set is authoritative, a peer-supplied one is
        /// provisional until the whole file's hash confirms it.
        authority: VerificationAuthority,
    },
    /// A worker was handed its next part to fetch. Assignment happens on the
    /// worker's `Connected` event, so a failed handshake never strands a part.
    PartAssigned {
        /// The download the part belongs to.
        download_id: DownloadId,
        /// The worker that will fetch it.
        peer: rmule_primitives::PeerEndpoint,
        /// The zero-based part index within the file.
        part_index: u32,
    },
    /// A part went back to the unassigned pool for another worker to take.
    PartReleased {
        /// The download the part belongs to.
        download_id: DownloadId,
        /// The worker that was holding it.
        peer: rmule_primitives::PeerEndpoint,
        /// The zero-based part index within the file.
        part_index: u32,
        /// What put it back — which decides whether its partial bytes are kept.
        reason: PartReleaseReason,
    },
    /// A worker left the fleet. Its slot is free, so the pool may backfill.
    PeerRetired {
        /// The download whose fleet shrank.
        download_id: DownloadId,
        /// The worker that left.
        peer: rmule_primitives::PeerEndpoint,
        /// Why it left — which decides whether the peer may be re-dialed.
        reason: PeerRetirementReason,
    },
    /// A part's bytes matched its hash and were written to the file. The one
    /// fact that advances durable progress.
    PartVerified {
        /// The download that gained a part.
        download_id: DownloadId,
        /// The zero-based part index within the file.
        part_index: u32,
    },
    /// Every part verified and the file was finalized on disk. Terminal.
    DownloadCompleted {
        /// The download that finished.
        download_id: DownloadId,
        /// Where the finished file now lies: the path core resolved in the
        /// download directory when the download started, the `.part` renamed
        /// onto it.
        final_path: PathBuf,
    },
    /// A `CancelDownload` was honoured: the run stopped and the store row is
    /// gone. Terminal.
    DownloadCancelled {
        /// The download that was cancelled.
        download_id: DownloadId,
    },
    /// A completed download's record was forgotten on a `ClearDownload` or
    /// `ClearCompletedDownloads`. Its file stays on disk and in the **Shared
    /// File Registry**; only the download is gone. Terminal.
    DownloadCleared {
        /// The download that was cleared.
        download_id: DownloadId,
    },
    /// A `PauseDownload` was honoured: the fleet is down but the parts on disk
    /// and the store row stay, so a resume picks up where this left off.
    DownloadPaused {
        /// The download that stopped.
        download_id: DownloadId,
    },
    /// A paused download started a fresh run.
    DownloadResumed {
        /// The download that restarted.
        download_id: DownloadId,
    },
    /// The run ended without the file. Terminal for this run; whether a retry
    /// is possible depends on `reason`.
    DownloadFailed {
        /// The download that failed.
        download_id: DownloadId,
        /// What ended it.
        reason: DownloadFailure,
    },
    /// The store could not record the [`DownloadFailed`](Self::DownloadFailed)
    /// just told: the row keeps the lifecycle it had, so the next start shows
    /// the download as it was before this failure, and one left running is
    /// started again.
    FailureNotRecorded {
        /// The download whose failure was not recorded.
        download_id: DownloadId,
    },
    /// No usable source right now, but a discovery channel is armed — the
    /// server-UDP global sweep (ADR-0051) or Kad (ADR-0043) — so the download
    /// waits for one to backfill rather than failing. Distinct from
    /// `DownloadFailed { NoUsableSources }`. Told again whenever `reason`
    /// changes while the run still waits: a server session ending or
    /// arriving, Kad starting or stopping.
    WaitingForSources {
        /// The download that is parked rather than failed.
        download_id: DownloadId,
        /// Who can still find it a source.
        reason: SourceWait,
    },
    /// The run's server login found no connection — the server unreachable,
    /// or the session gone before it answered — and Kad is not running, so
    /// nothing can be asked for sources (ADR-0093, "Waiting for a
    /// connection"). Not a failure: the run waits, and asks again once a
    /// server session or Kad exists. A later `SourcesFound` says it asked.
    WaitingForConnection {
        /// The download that waits.
        download_id: DownloadId,
    },
}

/// Why a download with no source to try waits, rather than fails: which
/// discovery channel can still find it one (ADR-0051's amendment, ADR-0097).
/// The global sweep stays armed while its server list is non-empty, but asks
/// only while a server session is up, so a run with no session waits on that
/// session — or on Kad — before anyone asks for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceWait {
    /// A server session is up: the global sweep asks for it, and Kad too
    /// while it runs.
    Asking,
    /// No server session; Kad runs and asks alone. The server's sources and
    /// the global sweep wait for a session.
    KadAlone,
    /// No server session and Kad off: every source it held was tried and
    /// nothing asks for more until a session comes up or Kad starts.
    NoSession,
}

/// What a restart of a failed download did (ADR-0094, "Restart"). The operator
/// asks for one action; rmule picks between these two by what is on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestartOutcome {
    /// The part file still backs what was recorded, or nothing was recorded:
    /// the run continues from the parts that hold. Damaged parts, if any, were
    /// dropped and are fetched again
    /// ([`DamagedPartsDropped`](DownloadEvent::DamagedPartsDropped) names them).
    Continued {
        /// Verified parts that still hold, kept.
        kept_parts: u32,
        /// The bytes they hold.
        kept_bytes: u64,
        /// Verified parts that no longer hold, dropped.
        dropped_parts: u32,
        /// The bytes those held.
        dropped_bytes: u64,
    },
    /// Nothing on disk to continue from — the part file is gone, or no
    /// recorded part matches it. What was recorded is discarded, the part file
    /// the row names is removed, and the run starts from nothing.
    StartedOver {
        /// Why nothing could be continued from.
        fault: StorageIntegrityFault,
        /// Verified parts recorded before, all dropped.
        dropped_parts: u32,
        /// The bytes they held.
        dropped_bytes: u64,
    },
}

/// What a changed part file cost in verified parts
/// ([`PartFileLost`](DownloadEvent::PartFileLost)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartsLost {
    /// The store named the parts the change cost and dropped their records.
    Counted {
        /// How many verified parts were lost.
        parts: u32,
        /// How many bytes those parts held.
        bytes: u64,
    },
    /// The store could not say which parts were lost, so no count is told;
    /// the download fails as a store failure.
    NotCounted,
}
