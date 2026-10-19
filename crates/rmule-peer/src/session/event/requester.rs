//! The **Requester** group of [`PeerEvent`](super::PeerEvent): our pull from
//! the peer (ADR-0025) — what our probes, hash-set, slot, part, source and
//! AICH asks drew, and the comment an uploader sends about the file we pull.

use rmule_primitives::{AichRootHash, Ed2kText, FileHash, PartHash, SourceSighting};

use crate::compress::InflateFailed;
use crate::source_exchange::AnswerSourcesSkip;

use super::{FileProbeStatus, SlotReleaseReason};

/// What the Requester Capability heard back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequesterEvent {
    /// A file request (`RequestFile`) is on the wire (ADR-0108), and whether
    /// it carried a source ask. The one place the ask is decided, so a
    /// download stamps its ask here — what went out, not what it expected to
    /// go out. The source-exchange facts it was framed under are the
    /// identity's.
    FileRequestSent {
        /// The file asked for.
        file_hash: FileHash,
        /// Whether the request carried `OP_REQUESTSOURCES` / `OP_REQUESTSOURCES2`.
        sources_asked: bool,
    },
    /// What asking the peer about a file established.
    FileProbed {
        /// The file that was asked about.
        file_hash: FileHash,
        /// Whether it has it, and with what.
        status: FileProbeStatus,
    },
    /// The peer sent a file's part-hash set (its `OP_HASHSETANSWER`).
    HashSetReceived {
        /// The file the set belongs to.
        file_hash: FileHash,
        /// One hash per part, in part order: the verification material for
        /// every block that follows.
        part_hashes: Vec<PartHash>,
    },
    /// Our `OP_STARTUPLOADREQ` for the file left: the uploader queues us, as
    /// aMule sets `DS_ONQUEUE` when it sends one (stock 2.3.3
    /// `DownloadClient.cpp:163-169`), whether or not a rank follows.
    SlotAsked {
        /// The file the upload was asked for.
        file_hash: FileHash,
    },
    /// Initial queue rank observation for a file. Subsequent improvements
    /// emit `QueueProgress` instead.
    QueueRanked {
        /// The file we are queued for.
        file_hash: FileHash,
        /// Places ahead of us, as the peer counted them.
        rank: u16,
    },
    /// Rank moved up (towards 0). `new_rank < previous_rank`.
    QueueProgress {
        /// The file whose queue moved.
        file_hash: FileHash,
        /// The rank last reported.
        previous_rank: u16,
        /// The rank now — always nearer 0.
        new_rank: u16,
    },
    /// The uploader ended our granted slot with `OP_OUTOFPARTREQS` and put us
    /// back on its queue (ADR-0025): the flow is queued again on the same
    /// link, the blocks we asked for are dropped, and the `OP_QUEUERANKING`
    /// that follows ranks it afresh. Not terminal: a later
    /// `OP_ACCEPTUPLOADREQ` grants it again.
    Requeued {
        /// The file whose transfer ended.
        file_hash: FileHash,
    },
    /// The peer sent `OP_ACCEPTUPLOADREQ` on a link where no slot was asked:
    /// an uploader promoting us by dial-back, or on a link it held, from its
    /// queue (ADR-0057). It names no file; the link's owner hands it to the
    /// download it is for, or gives it back with `DeclineSlot`.
    SlotOffered,
    /// Peer granted an upload slot via `OP_ACCEPTUPLOADREQ`.
    SlotGranted {
        /// The file the slot is for.
        file_hash: FileHash,
    },
    /// One frame of a part arrived. Application accumulates bytes,
    /// verifies against `HashSetReceived.part_hashes` per ADR-0026.
    PartReceived {
        /// The file the bytes belong to.
        file_hash: FileHash,
        /// Absolute offset of the first byte within the file.
        offset: u64,
        /// The block, already inflated if it arrived compressed.
        bytes: Vec<u8>,
    },
    /// A compressed part block could not be inflated (corrupt zlib stream or
    /// over the size ceiling). Non-terminal, mirroring rmule-ed2k's
    /// `CompressedFrameSkipped`: the session stays open, and the requester
    /// takes the block as lost and gives its slot back (ADR-0029 "A lost
    /// block ends the stream").
    CompressedPartSkipped {
        /// The file the block was for.
        file_hash: FileHash,
        /// Where the block would have landed.
        offset: u64,
        /// Why inflation failed.
        reason: InflateFailed,
    },
    /// Active slot context terminated. Per ADR-0025 only one slot
    /// context is live at a time; this clears the connection-level
    /// `active_slot` so a new `RequestParts` may proceed.
    SlotReleased {
        /// The file the slot served.
        file_hash: FileHash,
        /// Which terminal transition ended it.
        reason: SlotReleaseReason,
    },
    /// A peer answered our `OP_REQUESTSOURCES` with sources for `file_hash`
    /// (ADR-0055). The runner dedups + High-ID-filters these into the
    /// candidate pool. May be empty (the peer knew no sources).
    SourcesReceived {
        /// The file the sources are for.
        file_hash: FileHash,
        /// The rows as the peer sent them: not deduped, not filtered.
        sources: Vec<SourceSighting>,
    },
    /// A peer's `OP_ANSWERSOURCES` (`0x82`) or `OP_ANSWERSOURCES2` (`0x84`)
    /// failed to decode — truncated, or geometry that did not reconcile with
    /// the declared/advertised source-exchange version. Non-terminal: aMule's
    /// `AddClientSources` silently `return`s on exactly this for both wire
    /// forms (`PartFile.cpp` @4e8f2b3c), ignoring the bad source list while the
    /// connection stays open, so rmule drops the answer and emits this
    /// diagnostic instead of closing an otherwise-healthy link.
    SourceExchangeAnswerSkipped {
        /// What made the answer undecodable.
        reason: AnswerSourcesSkip,
    },
    /// A peer answered our `OP_AICHREQUEST` with the AICH recovery data for
    /// `part` (ADR-0038). `recovery_data` is the opaque tree branch; core
    /// verifies it against the trusted `root` with
    /// `rmule_primitives::AichHashSet::verify_part` to localize corrupt blocks.
    AichAnswerReceived {
        /// The file being recovered.
        file_hash: FileHash,
        /// Which part the branch covers.
        part: u16,
        /// The master hash the peer says the branch descends from.
        root: AichRootHash,
        /// The opaque tree branch. Verifying it is core's job, against a
        /// root it already trusts rather than the one quoted here.
        recovery_data: Vec<u8>,
    },
    /// A peer answered our `OP_AICHFILEHASHREQ` with its AICH master `root` for
    /// the requested file (ADR-0038). The runner counts it as a trusted-set root
    /// proposal from this peer. The wire carries no file hash (the file is the
    /// connection's requested file), so the worker tags it with its download.
    AichFileHashReceived {
        /// The master hash the peer proposes for this connection's file.
        root: AichRootHash,
    },
    /// Surface-as-event (ADR-0068): an inbound file rating/comment
    /// (`OP_FILEDESC`), already capped to aMule's 50-char limit. rmule has no
    /// ratings/comments store; this is display metadata only.
    FileCommentReceived {
        /// The rating byte as the peer sent it.
        rating: u8,
        /// The comment, already capped at aMule's 50 characters.
        comment: Ed2kText,
    },
}
