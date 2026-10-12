//! The **Server** group of [`PeerEvent`](super::PeerEvent): the peer's pull
//! from us (ADR-0031) — every ask the Server Capability reports for core to
//! answer, and the peer's cancel of the slot we granted (ADR-0056).

use rmule_primitives::{AichRootHash, FileHash};

use crate::file_request::PartStatusTail;
use crate::multipacket::{BundleCut, BundledAsk};
use crate::parts::PartRanges;

/// What the peer asked of us. Core answers with
/// [`ServerCommand`](crate::ServerCommand)s, or with nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerEvent {
    /// The remote peer asked for `file_hash`'s name
    /// (a standalone `OP_REQUESTFILENAME`). Core answers with
    /// `AnswerFileName` or nothing.
    FileRequested {
        /// The file whose name was asked for.
        file_hash: FileHash,
        /// The bytes after the hash, unread: the asker's part status is
        /// sized by the asked file, which only core knows. The serve side
        /// keeps it for the source-exchange answer's needed-part filter
        /// (ADR-0055 §Serving).
        status: PartStatusTail,
    },
    /// The remote peer asked about `file_hash` in one
    /// bundle (`OP_MULTIPACKET` / `OP_MULTIPACKET_EXT`, ADR-0054). Core gates
    /// the whole bundle on the file — one `AnswerFileNotFound`, or each ask
    /// answered in turn — as aMule does before its sub-opcode loop (stock
    /// 2.3.3 `4e8f2b3c` `ClientTCPSocket.cpp:1061-1085`).
    FileBundleRequested {
        /// The file every ask is about.
        file_hash: FileHash,
        /// The size an `OP_MULTIPACKET_EXT` names; a bundle naming another
        /// size than the file's is answered not-found.
        file_size: Option<u64>,
        /// The asks, in wire order, up to where the walk stopped.
        asks: Vec<BundledAsk>,
        /// Where the walk ran out of bytes inside a sub-ask: aMule's reader
        /// throws there, once the bundle passed its file gate.
        cut: Option<BundleCut>,
    },
    /// The remote peer set the current file
    /// (`OP_SETREQFILEID`); core answers its bitmap with `AnswerFileStatus`.
    FileIdSet {
        /// The file the peer is talking about from here on.
        file_hash: FileHash,
    },
    /// The remote peer requested the part-hash set
    /// (`OP_HASHSETREQUEST`); core answers with `AnswerHashSet`.
    HashSetRequested {
        /// The file whose part hashes were asked for.
        file_hash: FileHash,
    },
    /// The remote peer requested an upload slot
    /// (`OP_STARTUPLOADREQ`). Core admits it to the upload queue and
    /// replies `GrantSlot`, `SetQueueRank`, or nothing.
    SlotRequested {
        /// The file the peer wants to download.
        file_hash: FileHash,
    },
    /// The remote peer requested part ranges on its
    /// granted slot (`OP_REQUESTPARTS`). Core reads the bytes
    /// (`read_range`) and pushes them with `SendBlock`.
    PartsRequested {
        /// The file the ranges fall in.
        file_hash: FileHash,
        /// What to read, already checked against the wire form.
        ranges: PartRanges,
    },
    /// The remote peer requested parts without holding a granted serve slot
    /// for `file_hash`. Reported, not closed (close the flow, not the
    /// process); nothing is framed for it.
    PartsWithoutSlot {
        /// The file the parts were requested from.
        file_hash: FileHash,
    },
    /// The remote peer canceled its held upload slot
    /// (`OP_CANCELTRANSFER`, ADR-0056). Surfaced only when the peer actually
    /// held `served_slot`; a slotless cancel is a benign no-op (mirrors
    /// aMule's `RemoveFromUploadQueue`, which silently returns `false`). Core
    /// runs the release/promote batch on receipt — the connection stays
    /// open and the canceller is not re-queued.
    TransferCancelled {
        /// The file whose slot was given up.
        file_hash: FileHash,
    },
    /// The remote peer asked us for more sources of `file_hash`
    /// (`OP_REQUESTSOURCES` / `OP_REQUESTSOURCES2`, ADR-0055). The session has
    /// already picked the wire form the answer goes out in from the asker's
    /// advertised source-exchange capability and keeps it; core applies its
    /// pools, filters and per-peer throttle and answers with `AnswerSources`,
    /// or with nothing when throttled or the pool is empty.
    SourcesRequested {
        /// The file sources were asked for.
        file_hash: FileHash,
    },
    /// Our answer to a source-exchange ask went out carrying `count` sources.
    /// The session reports it because only the session knows how many the
    /// negotiated wire form could carry: a classic answer omits an IPv6-only
    /// source (ADR-0087). An answer left empty by that sends nothing and
    /// reports nothing.
    SourcesAnswered {
        /// The file the sources are for.
        file_hash: FileHash,
        /// How many sources the framed answer carries.
        count: usize,
    },
    /// The remote peer asked for `file_hash` part `part`'s
    /// AICH recovery data (`OP_AICHREQUEST`), quoting the `root` it trusts. Core
    /// builds the file's `AichHashSet` and answers with the recovery data
    /// (ADR-0038, phase 4 serve side).
    AichRequested {
        /// The file the peer is recovering.
        file_hash: FileHash,
        /// The part it wants a branch for.
        part: u16,
        /// The master hash it quotes as trusted.
        root: AichRootHash,
    },
    /// The peer asked for `file_hash`'s AICH master hash
    /// (`OP_AICHFILEHASHREQ`); core answers with `AnswerAichFileHash` from the
    /// shared file's tree (ADR-0038).
    AichFileHashRequested {
        /// The file whose master hash was asked for.
        file_hash: FileHash,
    },
}
