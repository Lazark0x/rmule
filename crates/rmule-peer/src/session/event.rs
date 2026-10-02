//! What a peer session reports to its driver: the [`PeerEvent`] vocabulary
//! and the opcode-to-event mapping capture tooling reads. The human-readable
//! rendering the TUI and harness log lines share lives in `display`.

mod display;

use rmule_primitives::{
    AichRootHash, ClientId, Ed2kText, ExchangedSource, FileHash, PacketProtocol, PartHash, UserHash,
};

use super::SourceExchangeSupport;
use super::{PeerCloseReason, PeerError, SecureIdentFailure};
use crate::compress::InflateFailed;
use crate::compressed_frame::CompressedFrameSkipReason;
use crate::file::PartBitmap;
use crate::file_request::PartStatusTail;
use crate::identity::PeerIdentity;
use crate::multipacket::{BundleCut, BundledAsk};
use crate::packet::PeerPacket;
use crate::parts::PartRanges;
use crate::software::ClientSoftware;
use crate::source_exchange::{AnswerSourcesSkip, ServedSourcesVersion};

/// What a session reports to its owner. Every variant is a fact already
/// established — nothing here asks a question, and the owner is free to act
/// on it or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerEvent {
    /// Our `OP_HELLO` is on the wire; the peer has said nothing back yet.
    PeerHelloSent,
    /// The peer answered the handshake and named itself — the first point at
    /// which anything about it is known.
    PeerIdentified {
        /// Everything its hello carried: user hash, client, ports, capabilities.
        identity: PeerIdentity,
    },
    /// An identified peer's `OP_EMULEINFO` / `OP_EMULEINFOANSWER` changed what
    /// its software reads as — a pre-0.42 mule's version arrives only there.
    PeerSoftwareRevised {
        /// Which client it runs, the hello and the block read together.
        software: ClientSoftware,
    },
    /// An identified peer's `OP_EMULEINFO` named a client-UDP reask contact
    /// its hello did not: the port to reask it at and its peer-UDP
    /// version, as the hello's `CT_EMULE_UDPPORTS` would have given them.
    PeerReaskContactRevised {
        /// Its client-UDP port.
        udp_port: u16,
        /// Its peer-UDP protocol version.
        udp_version: u8,
    },
    /// An identified peer's `OP_EMULEINFO` / `OP_EMULEINFOANSWER` changed
    /// what it says about source exchange (ADR-0108) — a pre-0.42 mule
    /// states its SX version only there. Comes off the same stream as
    /// [`Self::FileRequestSent`], so the later of the two is the current one.
    PeerSourceExchangeRevised {
        /// Its source-exchange facts, hello and block read together.
        support: SourceExchangeSupport,
    },
    /// A file request (`RequestFile`) is on the wire (ADR-0108): the
    /// source-exchange facts it was framed under, and whether it carried a
    /// source ask. The one place the ask is decided, so a download stamps
    /// its ask here — what went out, not what it expected to go out.
    FileRequestSent {
        /// The file asked for.
        file_hash: FileHash,
        /// The peer's source-exchange facts when the request was framed.
        support: SourceExchangeSupport,
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
    /// Peer refused the slot via `OP_OUTOFPARTREQS` (TCP) or
    /// equivalent terminal signal. Slot context clears.
    QueueRejected {
        /// The file the queue was for.
        file_hash: FileHash,
    },
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
    /// A peer answered our `OP_REQUESTSOURCES` with sources for `file_hash`
    /// (ADR-0055). The runner dedups + High-ID-filters these into the
    /// candidate pool. May be empty (the peer knew no sources).
    SourcesReceived {
        /// The file the sources are for.
        file_hash: FileHash,
        /// The rows as the peer sent them: not deduped, not filtered.
        sources: Vec<ExchangedSource>,
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
    /// A compressed part block could not be inflated (corrupt zlib stream or
    /// over the size ceiling). Non-terminal: the session stays open and core
    /// re-requests the block, mirroring rmule-ed2k's `CompressedFrameSkipped`.
    CompressedPartSkipped {
        /// The file the block was for.
        file_hash: FileHash,
        /// Where the block would have landed.
        offset: u64,
        /// Why inflation failed.
        reason: InflateFailed,
    },
    /// An inbound packed (`0xD4`) frame's payload could not be inflated
    /// (corrupt zlib or over the [`crate::PEER_COMPRESSED_FRAME_LIMIT`]
    /// ceiling). Non-terminal: the session stays open, mirroring
    /// `rmule-ed2k`'s `CompressedFrameSkipped` (ADR-0053). Distinct from
    /// `CompressedPartSkipped`: this is the frame-level `0xD4` codec: any
    /// packed opcode, not only `OP_COMPRESSEDPART` transfer blocks.
    CompressedFrameSkipped {
        /// The inner opcode, which framing established before the payload
        /// was lost.
        opcode: u8,
        /// Compressed size as framed.
        compressed_len: usize,
        /// Why inflation failed.
        reason: CompressedFrameSkipReason,
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
    /// Session refused to act on an application command (e.g. a second
    /// `RequestParts` while a slot context is active). Carries the
    /// typed `PeerError` per ADR-0010.
    CommandRejected {
        /// Why the session refused.
        reason: PeerError,
    },
    /// A well-formed frame this crate does not model. Reported as shape
    /// only; the bytes stay with the packet, which is kept rather than
    /// ending the conversation (ADR-0018).
    UnknownPeerPacket {
        /// Which framing byte carried it.
        protocol: PacketProtocol,
        /// The opcode nothing claimed.
        opcode: u8,
        /// Payload size, so a diagnostic can say how much went unread.
        payload_len: usize,
    },
    /// A bundled `OP_MULTIPACKET`/`OP_MULTIPACKET_EXT`/`OP_MULTIPACKETANSWER`
    /// (ADR-0054) walk met a sub-opcode it does not model and stopped; the
    /// already-decoded prefix still fanned in normally. Non-terminal — the
    /// session stays open, mirroring [`Self::UnknownPeerPacket`] but scoped to
    /// one sub-item inside the bundle rather than a whole wire frame.
    MultiPacketUnknownSub {
        /// The file the bundle was about.
        file_hash: FileHash,
        /// The sub-opcode the walk stopped at.
        opcode: u8,
        /// Bytes left unwalked behind it.
        remaining: usize,
    },
    /// `OP_KAD_FWTCPCHECK_ACK` (`0xA8`) arrived on this link — a peer we asked to
    /// firewall-check us dialed our TCP port and acked (ADR-0058 requester). The
    /// session stays Kad-ignorant; its owner bridges this to the KadNode's
    /// window-guarded ack consume, keyed on this peer's IP, which counts it
    /// toward the ≥2-ack reachability verdict.
    KadFirewallCheckAck,
    /// `OP_FWCHECKUDPREQ` (`0xA7`) arrived on this link — the peer asks us to
    /// prove its Kad UDP port reachable (ADR-0058, UDP Firewall Helper). The
    /// session stays Kad-ignorant; its owner bridges the opaque body, keyed on
    /// this peer's IP, to the Kad node, which answers `KADEMLIA2_FIREWALLUDP`.
    KadUdpFirewallCheckRequested {
        /// The request body as it arrived.
        request: Vec<u8>,
    },
    /// `OP_CHANGE_CLIENT_IP` (`0xAC`) arrived: the peer's Known IPv6 changed
    /// mid-session (ADR-0087). Wire-silent — its owner re-points the candidate
    /// entry so the next dial goes to the address the peer now holds rather
    /// than the one its hello named. The address has already passed
    /// `IsUsableTagIdentity`.
    PeerIpv6Changed {
        /// The address the peer now holds.
        address: std::net::Ipv6Addr,
    },
    /// `OP_BUDDYPING` (`0x9F`) arrived on this link — our firewalled buddy's
    /// keepalive over the buddy TCP link (ADR-0061). The session stays
    /// Kad-ignorant; its owner routes this to the core buddy service's
    /// `on_buddy_ping`, which pongs (`SendBuddyPong`) and refreshes the link only
    /// when the sender is our registered buddy, refusing a stranger.
    BuddyPingReceived,
    /// `OP_CALLBACK` (`0x99`) arrived on this link — our own buddy relayed a
    /// Kad `0x52` and is asking us to dial the requester back (ADR-0061
    /// firewalled-node consume). Wire-silent: the session stays Kad-ignorant,
    /// and its owner runs the buddy-ID XOR check, the Kad-running and
    /// file-known gates, and the dial.
    BuddyCallbackReceived {
        /// The relay as it arrived — the echoed buddy-ID and file hash, and
        /// the requester endpoint the buddy injected.
        callback: crate::buddy::Callback,
    },
    /// `OP_REASKCALLBACKTCP` (`0x9A`) arrived on this link — our own buddy
    /// relayed a peer-UDP `0x94` (ADR-0061), or, when the forwarded tail
    /// carries the `OP_RENDEZVOUS` marker, a rendezvous aimed at us
    /// (ADR-0091's acting path). Wire-silent for the same reason: the answer
    /// leaves by the client-UDP socket, which this session does not own.
    BuddyReaskCallbackReceived {
        /// The injected requester endpoint and the forwarded tail, verbatim.
        relay: crate::buddy::ReaskCallbackTcp,
    },
    /// The peer's hello was refused under a named code (ADR-0050). Emitted
    /// immediately before the `Disconnected` its protocol-violation close
    /// raises; the refusal carries the name and mod the peer wrote before its
    /// frame went wrong.
    HelloRefused {
        /// Why, and what the peer said of itself.
        refusal: crate::hello::HelloRefusal,
    },
    /// The last word about this session. Emitted exactly once, immediately
    /// before the close it explains (ADR-0044).
    Disconnected {
        /// What ended it.
        reason: PeerCloseReason,
    },
    /// Server Capability — the remote peer asked for `file_hash`'s name
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
    /// Server Capability — the remote peer asked about `file_hash` in one
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
    /// Server Capability — the remote peer set the current file
    /// (`OP_SETREQFILEID`); core answers its bitmap with `AnswerFileStatus`.
    FileIdSet {
        /// The file the peer is talking about from here on.
        file_hash: FileHash,
    },
    /// Server Capability — the remote peer requested the part-hash set
    /// (`OP_HASHSETREQUEST`); core answers with `AnswerHashSet`.
    HashSetRequested {
        /// The file whose part hashes were asked for.
        file_hash: FileHash,
    },
    /// Server Capability — the remote peer requested an upload slot
    /// (`OP_STARTUPLOADREQ`). Core admits it to the upload queue and
    /// replies `GrantSlot`, `SetQueueRank`, or nothing.
    SlotRequested {
        /// The file the peer wants to download.
        file_hash: FileHash,
    },
    /// Server Capability — the remote peer requested part ranges on its
    /// granted slot (`OP_REQUESTPARTS`). Core reads the bytes
    /// (`read_range`) and pushes them with `SendBlock`.
    PartsRequested {
        /// The file the ranges fall in.
        file_hash: FileHash,
        /// What to read, already checked against the wire form.
        ranges: PartRanges,
    },
    /// Server Capability — the remote peer asked us for more sources of
    /// `file_hash` (`OP_REQUESTSOURCES` / `OP_REQUESTSOURCES2`, or a bundled
    /// `Sources` / `Sources2` sub — ADR-0055). `version` is the
    /// aMule-exact serve wire form the session already picked from the
    /// requester's advertised SX capability; core applies its pools / filters /
    /// per-peer throttle and answers with `AnswerSources` (or, when throttled
    /// or the pool is empty, nothing).
    SourcesRequested {
        /// The file sources were asked for.
        file_hash: FileHash,
        /// The serve wire form picked from the requester's advertised
        version: ServedSourcesVersion,
    },
    /// Server Capability — the remote peer requested parts without holding
    /// a granted serve slot for `file_hash`. Reported, not closed (design
    /// §5: close the flow, not the process); core decides whether to grant,
    /// queue, or ignore.
    ServePartsWithoutSlot {
        /// The file the parts were requested from.
        file_hash: FileHash,
    },
    /// Server Capability — the remote peer canceled its held upload slot
    /// (`OP_CANCELTRANSFER`, ADR-0056). Surfaced only when the peer actually
    /// held `served_slot`; a slotless cancel is a benign no-op (mirrors
    /// aMule's `RemoveFromUploadQueue`, which silently returns `false`). Core
    /// runs the release/promote batch on receipt — the connection stays
    /// open and the canceller is not re-queued.
    TransferCancelled {
        /// The file whose slot was given up.
        file_hash: FileHash,
    },
    /// Server Capability — the remote peer asked for `file_hash` part `part`'s
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
    /// Server Capability — the peer asked for `file_hash`'s AICH master hash
    /// (`OP_AICHFILEHASHREQ`); core answers with `AnswerAichFileHash` from the
    /// shared file's tree (ADR-0038).
    AichFileHashRequested {
        /// The file whose master hash was asked for.
        file_hash: FileHash,
    },
    /// Secure User Identification proved the peer owns the **User Hash** it
    /// claimed; `public_key` is its RSA public key DER (ADR-0041). Core binds
    /// this as a **Secured Identity** so credit cannot be spoofed. Non-terminal.
    PeerIdentityVerified {
        /// The hash now proven to belong to this peer.
        user_hash: UserHash,
        /// Its RSA public key, DER-encoded — what core keeps to recognise it.
        public_key: Vec<u8>,
    },
    /// A Secure User Identification exchange failed (bad public key or a
    /// signature that did not verify). Non-terminal — the session stays open and
    /// the peer keeps only unsecured credit (ADR-0041).
    PeerSecureIdentFailed {
        /// Which step of the proof failed.
        reason: SecureIdentFailure,
    },
    /// Respond-by-parity (ADR-0068): a browse request
    /// (`OP_ASKSHAREDFILES`/`OP_ASKSHAREDDIRS`/`OP_ASKSHAREDFILESDIR`) was
    /// answered `OP_ASKSHAREDDENIEDANS` — the classification counter for the
    /// `browse-denied` gate. rmule has no browse feature; every browse
    /// request gets this same unconditional refusal.
    BrowseDenied,
    /// Drop-with-counter (ADR-0068): an unsolicited browse answer arrived
    /// (`OP_ASKSHAREDFILESANSWER`/`OP_ASKSHAREDDIRSANS`/
    /// `OP_ASKSHAREDFILESDIRANS`/a denied answer rmule never asked for) —
    /// rmule never browses, so any of these is unsolicited. Parsed, counted,
    /// dropped.
    UnsolicitedBrowseAnswerDropped,
    /// Respond-by-parity (ADR-0068): `OP_PUBLICIP_REQ` was answered
    /// `OP_PUBLICIP_ANSWER` with the peer's own observed IPv4 — ungated in
    /// aMule, no privacy preference silences it.
    PublicIpAnswered,
    /// Drop-with-counter (ADR-0085): `OP_PUBLICIP_REQ` from an IPv6 peer —
    /// the answer is a 32-bit field, so there is nothing true to reply.
    PublicIpRequestUnanswerable,
    /// Drop-with-counter (ADR-0068): an unsolicited `OP_PUBLICIP_ANSWER`
    /// arrived (rmule never asks — the server's IDCHANGE serves that need,
    /// ADR-0047). Parsed, counted, dropped.
    UnsolicitedPublicIpAnswerDropped,
    /// Surface-as-event (ADR-0068): inbound chat text (`OP_MESSAGE`),
    /// already capped to aMule's 450-char limit. No reply, no state, no spam
    /// gate — rmule has no chat feature.
    ChatMessageReceived {
        /// The message, already capped at aMule's 450 characters.
        text: Ed2kText,
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
    /// Surface-as-event (ADR-0068): the peer's ID (and, when Low-ID, its
    /// server) changed (`OP_CHANGE_CLIENT_ID`). Wire-silent either way — core
    /// applies it to the matching candidate-pool entry, the way aMule updates
    /// `UserIDHybrid`/server.
    ClientIdChanged {
        /// The id the peer now answers to; High or Low decides whether it
        /// can be dialed at all.
        new_id: ClientId,
        /// The server it named alongside that id.
        new_server_ip: std::net::Ipv4Addr,
    },
    /// Drop-with-counter (ADR-0068): an inbound chat-captcha challenge or
    /// answer (`OP_CHATCAPTCHAREQ`/`RES`). Rides on outbound chat, which
    /// rmule never sends, so any inbound instance is unsolicited. Parsed,
    /// counted, dropped.
    ChatCaptchaDropped,
}

impl PeerEvent {
    /// Project the *state-independent* peer packets onto their event.
    ///
    /// Returns `None` for packets whose emitted event depends on session
    /// state (handshake, probe accumulation, slot/queue progress) — those
    /// stay in `PeerSession::dispatch`. Lossy by design, mirroring
    /// `rmule_ed2k::Ed2kEvent::from_server_packet` (plain reference, not an
    /// intra-doc link — `rmule-peer` does not depend on `rmule-ed2k`); the
    /// raw packet stays available for diagnostics or replay. `AnswerSources`
    /// is state-*dependent* (its sanity filter, Low-ID
    /// routing, and per-file cap all read session context) and is handled in
    /// `PeerSession::dispatch` instead of here.
    #[must_use]
    pub fn from_peer_packet(packet: &PeerPacket) -> Option<Self> {
        match packet {
            PeerPacket::SendingPart(sp) => Some(Self::PartReceived {
                file_hash: sp.file_hash,
                offset: sp.start,
                bytes: sp.data.clone(),
            }),
            PeerPacket::AichAnswer(a) => Some(Self::AichAnswerReceived {
                file_hash: a.file_hash,
                part: a.part,
                root: a.root,
                recovery_data: a.recovery_data.clone(),
            }),
            PeerPacket::AichFileHashAns(a) => Some(Self::AichFileHashReceived { root: a.root }),
            PeerPacket::HashSetAnswer(a) => Some(Self::HashSetReceived {
                file_hash: a.file_hash,
                part_hashes: a.part_hashes.clone(),
            }),
            PeerPacket::FileReqAnsNoFil(n) => Some(Self::FileProbed {
                file_hash: n.file_hash,
                status: FileProbeStatus::NotAvailable,
            }),
            PeerPacket::KadFirewallAck => Some(Self::KadFirewallCheckAck),
            PeerPacket::KadUdpFirewallRequest(request) => {
                Some(Self::KadUdpFirewallCheckRequested {
                    request: request.clone(),
                })
            }
            PeerPacket::ChangeClientIpV6(c) => Some(Self::PeerIpv6Changed {
                address: c.address(),
            }),
            PeerPacket::BuddyPing => Some(Self::BuddyPingReceived),
            PeerPacket::BuddyCallback(c) => Some(Self::BuddyCallbackReceived {
                callback: c.clone(),
            }),
            PeerPacket::BuddyReaskCallback(r) => {
                Some(Self::BuddyReaskCallbackReceived { relay: r.clone() })
            }
            PeerPacket::Unknown {
                protocol,
                opcode,
                payload,
            } => Some(Self::UnknownPeerPacket {
                protocol: *protocol,
                opcode: *opcode,
                payload_len: payload.len(),
            }),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// What a file probe established about the peer's copy.
pub enum FileProbeStatus {
    /// The peer has the file.
    Available {
        /// The name it calls the file by.
        file_name: Ed2kText,
        /// Which parts of it the peer holds — aMule's part-count-0 sentinel
        /// already expanded to every part.
        bitmap: PartBitmap,
        /// Whether the peer said it holds the whole file (aMule
        /// `m_bCompleteSource`, ADR-0108): the part-count-0 sentinel, or the
        /// name answer for a one-part file. A spelled-out bitmap with every
        /// part set is not complete — a part file whose last part arrived.
        complete: bool,
    },
    /// The peer does not have it.
    NotAvailable,
}

/// Terminal transitions out of an active slot context per ADR-0025.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SlotReleaseReason {
    /// All requested parts arrived and verified.
    DownloadComplete,
    /// Peer refused the slot (`OP_OUTOFPARTREQS` or queue terminal).
    QueueRejected,
    /// Peer closed the connection mid-slot.
    PeerClosed,
    /// Wire-level protocol violation forced session into terminal
    /// slot state.
    ProtocolViolation,
    /// Driver-owned slot-stale timeout fired (`signal_slot_stale`).
    Stale,
    /// Local-reason teardown sent `OP_CANCELTRANSFER` before releasing
    /// (`CancelTransfer`, ADR-0056): `CancelDownload`, `PauseDownload`, or
    /// complete-overshoot while the slot was held.
    Cancelled,
}
