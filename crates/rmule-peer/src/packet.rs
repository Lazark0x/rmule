//! The umbrella decoder: one inbound peer frame in, one typed
//! [`PeerPacket`] out.
//!
//! Dispatch is keyed by `(protocol, opcode)` (ADR-0025) — the same byte means
//! different packets under the eDonkey and eMule protocols. A well-formed
//! frame rmule has no model for keeps its bytes under `Unknown` with its
//! routing attribution intact (ADR-0018), and a packed frame that fails to
//! inflate surfaces as a skip rather than a close (ADR-0053).

use rmule_primitives::{Packet, PacketProtocol};

use crate::aich::{AichAnswer, AichFileHashAns, AichFileHashReq, AichRequest};
use crate::buddy::{Callback, ReaskCallbackTcp};
use crate::capability::MiscOptions1;
use crate::compressed_frame::CompressedFrameSkipReason;
use crate::emule_info::{EmuleInfo, OP_EMULEINFO, OP_EMULEINFOANSWER};
use crate::error::PeerPacketDecodeError;
use crate::file_request::{
    ExtendedRequests, FileReqAnsNoFil, FileStatus, ReqFileNameAnswer, RequestFileName, SetReqFileId,
};
use crate::hash_set::{HashSetAnswer, HashSetRequest};
use crate::hello::{Hello, HelloAnswer};
use crate::human_layer::{self, ChangeClientId, FileDesc, Message, PublicIpAnswer};
use crate::ipv6::ChangeClientIpV6;
use crate::multipacket::{MultiPacketAnswer, MultiPacketRequest};
use crate::opcode::PeerOpcode;
use crate::parts::PartOffsetWidth;
use crate::parts::{CompressedPart, RequestParts, SendingPart};
use crate::secure_ident::{PublicKeyPacket, SecIdentStatePacket, SignaturePacket};
use crate::slot::{AcceptUploadReq, CancelTransfer, OutOfPartReqs, QueueRanking, StartUploadReq};
use crate::source_exchange::{
    AnswerSources, AnswerSources2, RequestSources, RequestSources2, SourceExchangeClaim,
    SourceExchangeEntry, SourceExchangeVersion,
};

fn narrowest_width_for_ranges(req: &RequestParts) -> PartOffsetWidth {
    let max_offset = req
        .ranges
        .as_array()
        .iter()
        .flat_map(|(s, e)| [*s, *e])
        .max()
        .unwrap_or(0);
    PartOffsetWidth::for_file_size(max_offset)
}

/// The narrowest [`SourceExchangeVersion`] that round-trips every field a
/// decoded [`AnswerSources`] actually carries: v4 iff any source has crypt
/// options, else v2 iff any source has a user hash, else v1. Mirrors
/// `narrowest_width_for_ranges`'s spirit — the umbrella-wide `encode()` picks
/// a sufficient variant from the data rather than assuming a fixed one; a
/// caller wanting a specific wire version (v3's hybrid id order in
/// particular, which this can never pick since nothing in `SourceClaim`
/// distinguishes "v2" from "v3") should call
/// `AnswerSources::encode_packet(version)` directly.
fn narrowest_version_for_sources(sources: &[SourceExchangeEntry]) -> SourceExchangeVersion {
    if sources.iter().any(|s| s.crypt_options().is_some()) {
        SourceExchangeVersion::V4
    } else if sources.iter().any(|s| s.user_hash().is_some()) {
        SourceExchangeVersion::V2
    } else {
        SourceExchangeVersion::V1
    }
}

/// Umbrella for every peer-to-peer eD2k packet rmule decodes.
///
/// Dispatch is keyed by `(PacketProtocol, opcode)` per ADR-0025's
/// design — opcode `0x60` means `OP_ASKSHAREDFILESDIRANS` over
/// `OP_EDONKEYPROT` and `OP_QUEUERANKING` over `OP_EMULEPROT`, and
/// future extended-protocol opcodes share the same pattern. Unknown
/// well-formed frames preserve their bytes under `Unknown` per
/// ADR-0018; the `protocol` field is part of the preserved routing
/// attribution so replay tools and the inspector can tell where the
/// packet came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerPacket {
    /// `OP_HELLO` (`0x01`): the dialer's opening, naming itself and what it can do.
    Hello(Hello),
    /// `OP_HELLOANSWER` (`0x4C`): the same shape back, from the side that was dialed.
    HelloAnswer(HelloAnswer),
    /// `OP_REQUESTFILENAME` (`0x58`): what do you call this file?
    RequestFileName(RequestFileName),
    /// `OP_REQFILENAMEANSWER` (`0x59`): the name, which means the peer has it.
    ReqFileNameAnswer(ReqFileNameAnswer),
    /// `OP_FILEREQANSNOFIL` (`0x48`): the peer does not have the file.
    FileReqAnsNoFil(FileReqAnsNoFil),
    /// `OP_SETREQFILEID` (`0x4F`): every later request on this link is about this file.
    SetReqFileId(SetReqFileId),
    /// `OP_FILESTATUS` (`0x50`): which parts of it the peer holds.
    FileStatus(FileStatus),
    /// `OP_HASHSETREQUEST` (`0x51`): send the part hashes for the current file.
    HashSetRequest(HashSetRequest),
    /// `OP_HASHSETANSWER` (`0x52`): the part hashes, in part order.
    HashSetAnswer(HashSetAnswer),
    /// `OP_STARTUPLOADREQ` (`0x54`): put me in the queue for this file.
    StartUploadReq(StartUploadReq),
    /// `OP_ACCEPTUPLOADREQ` (`0x55`): the slot is yours — part requests may start.
    AcceptUploadReq(AcceptUploadReq),
    /// `OP_CANCELTRANSFER` (`0x56`, ADR-0056): "stop sending, I no longer
    /// want this transfer." Symmetric — either capability may receive it.
    CancelTransfer(CancelTransfer),
    /// `OP_OUTOFPARTREQS` (`0x57`): the granted transfer is over; back to the
    /// queue.
    OutOfPartReqs(OutOfPartReqs),
    /// `OP_QUEUERANKING` (`0x60` under Emule): how far from the front the queued peer stands.
    QueueRanking(QueueRanking),
    /// `OP_REQUESTPARTS` (`0x47`, or `0xA3` for 64-bit offsets): up to three byte ranges.
    RequestParts(RequestParts),
    /// `OP_SENDINGPART` (`0x46`, or `0xA2`): one block, uncompressed.
    SendingPart(SendingPart),
    /// `OP_COMPRESSEDPART` (`0x40`, or `0xA1`): one zlib slice of a block, reassembled by the session.
    CompressedPart(CompressedPart),
    /// `OP_REQUESTSOURCES` (`0x81`) — a peer asking *us* for sources of its
    /// file (ADR-0055 serve side). Dispatched to the serve callback;
    /// the requester ask rmule sends is framed directly, never round-tripped
    /// through the umbrella.
    RequestSources(RequestSources),
    /// `OP_REQUESTSOURCES2` (`0x83`) — the SX2 form of the serve request. Its
    /// `version`/`options` feed the aMule-exact serve-version pick.
    RequestSources2(RequestSources2),
    /// `OP_ANSWERSOURCES` (`0x82`): a peer's source list for our `0x81` ask.
    AnswerSources(AnswerSources),
    /// `OP_ANSWERSOURCES2` (`0x84`) — a peer's SX2 source list answering *our*
    /// `0x83` ask (ADR-0055 requester consume). Fans in through the same
    /// session sanity/provenance/cap core as [`Self::AnswerSources`].
    AnswerSources2(AnswerSources2),
    /// `OP_AICHREQUEST` (`0x9B`): the recovery branch for one part, against a quoted root.
    AichRequest(AichRequest),
    /// `OP_AICHANSWER` (`0x9C`): that branch.
    AichAnswer(AichAnswer),
    /// `OP_AICHFILEHASHREQ` (`0x9E`): the file's AICH master root.
    AichFileHashReq(AichFileHashReq),
    /// `OP_AICHFILEHASHANS` (`0x9D`): that root. The wire names no file — it is the link's current one.
    AichFileHashAns(AichFileHashAns),
    /// `OP_SECIDENTSTATE` (`0x87`): which half of the identity proof the peer wants next (ADR-0041).
    SecIdentState(SecIdentStatePacket),
    /// `OP_PUBLICKEY` (`0x85`): the peer's RSA public key.
    PublicKey(PublicKeyPacket),
    /// `OP_SIGNATURE` (`0x86`): its signature over the challenge, which is what actually proves the key is its own.
    Signature(SignaturePacket),
    /// `OP_MULTIPACKET` (`0x92`) or `OP_MULTIPACKET_EXT` (`0xA4`): several asks about one file in a single frame (ADR-0054).
    MultiPacketRequest(MultiPacketRequest),
    /// `OP_MULTIPACKETANSWER` (`0x93`): the answers to those asks, in one frame.
    MultiPacketAnswer(MultiPacketAnswer),
    /// `OP_KAD_FWTCPCHECK_ACK` (`0xA8`): the empty-body ack a peer sends over the
    /// TCP link it dialed back on, proving one leg of *our* Kad firewall
    /// self-check (ADR-0058 requester). The session stays Kad-ignorant — it
    /// surfaces the ack as an event, and core bridges it (with this peer's IP) to
    /// the KadNode's window guard.
    KadFirewallAck,
    /// `OP_FWCHECKUDPREQ` (`0xA7`): a Kad node asks us, over this link, to
    /// send `KADEMLIA2_FIREWALLUDP` to its Kad UDP port(s) (ADR-0058, UDP
    /// Firewall Helper). The body — `<intern port 2><extern port 2><sender key
    /// 4>` — stays opaque: the session is Kad-ignorant, the Kad node decodes it.
    KadUdpFirewallRequest(Vec<u8>),
    /// `OP_BUDDYPING` (`0x9F`): the empty-body keepalive our buddy sends over its
    /// TCP link (ADR-0061). The session surfaces it so the core buddy
    /// service can pong and extend the link; a ping from a non-buddy is refused
    /// there.
    BuddyPing,
    /// `OP_BUDDYPONG` (`0xA0`): the empty-body answer to an `OP_BUDDYPING`. rmule
    /// emits it for its buddy; it also decodes (a buddy we ping answers one).
    BuddyPong,
    /// `OP_CALLBACK` (`0x99`): the Kad `0x52`→`0x99` relay our **own** buddy
    /// forwards to us over its TCP link, asking us to dial a requester that
    /// cannot reach us (ADR-0061 firewalled-node consume). rmule also *emits*
    /// this packet as somebody's open-node buddy, but that side frames
    /// [`Callback`] directly; this arm is the inbound read.
    BuddyCallback(Callback),
    /// `OP_REASKCALLBACKTCP` (`0x9A`): the peer-UDP `0x94`→`0x9A` relay our own
    /// buddy forwards to us — a reask whose answer we send straight back to the
    /// injected requester over UDP (ADR-0057's reply matrix), or, when its
    /// forwarded tail carries the `OP_RENDEZVOUS` marker, the acting path's
    /// inlet (ADR-0091). Emit-side twin of [`Self::BuddyCallback`].
    BuddyReaskCallback(ReaskCallbackTcp),
    // ADR-0068 human-layer catalog, Private-Citizen Parity: rmule
    // behaves byte-exact as an aMule 2.3.3 client at its most private setting.
    /// `OP_ASKSHAREDFILES` (`0x4A`): browse request. Answered `AskSharedDeniedAns`
    /// unconditionally — no browse feature (`CanSeeShares == nobody`).
    AskSharedFiles,
    /// `OP_ASKSHAREDDIRS` (`0x5D`): browse request, same treatment as
    /// [`Self::AskSharedFiles`].
    AskSharedDirs,
    /// `OP_ASKSHAREDFILESDIR` (`0x5E`): browse request for one named directory's
    /// files. Same unconditional denial; the directory name is not inspected,
    /// since the answer never depends on it.
    AskSharedFilesDir,
    /// `OP_ASKSHAREDDENIEDANS` (`0x61` under Edonkey): rmule's browse-denied
    /// reply (emitted for every one of the three requests above), and also the
    /// shape an unsolicited copy takes (rmule never browses, so any inbound
    /// instance not preceded by our own request is dropped). Collides with
    /// `OP_FILEDESC` (`0x61` under Emule) — see `human_layer`.
    AskSharedDeniedAns,
    /// Unsolicited browse answers rmule never asked for (`OP_ASKSHAREDFILESANSWER
    /// 0x4B`, `OP_ASKSHAREDDIRSANS 0x5F`, `OP_ASKSHAREDFILESDIRANS 0x60` under
    /// Edonkey) — rmule never browses, so any inbound instance is dropped.
    /// `0x60` collides with `OP_QUEUERANKING` (Emule) — see `human_layer`.
    AskSharedFilesAnswer,
    /// `OP_ASKSHAREDDIRSANS` (`0x5F`): likewise unsolicited, likewise dropped.
    AskSharedDirsAns,
    /// `OP_ASKSHAREDFILESDIRANS` (`0x60` under Edonkey): likewise. The opcode collides with `OP_QUEUERANKING` under Emule — see `human_layer`.
    AskSharedFilesDirAns,
    /// `OP_PUBLICIP_REQ` (`0x97`): answered unconditionally with
    /// `OP_PUBLICIP_ANSWER` — ungated in aMule, no privacy preference silences
    /// it.
    PublicIpReq,
    /// `OP_PUBLICIP_ANSWER` (`0x98`): rmule never asks (the server's IDCHANGE
    /// serves that need, ADR-0047), so an inbound one is unsolicited and
    /// dropped.
    PublicIpAnswer(PublicIpAnswer),
    /// `OP_MESSAGE` (`0x4E`): inbound chat text, surfaced as an event. No
    /// reply, no state, no spam gate (rmule has no chat feature).
    Message(Message),
    /// `OP_FILEDESC` (`0x61` under Emule): inbound file rating/comment,
    /// surfaced as an event. Collides with `OP_ASKSHAREDDENIEDANS` (`0x61`
    /// under Edonkey) — see [`Self::AskSharedDeniedAns`].
    FileDesc(FileDesc),
    /// `OP_EMULEINFO` / `OP_EMULEINFOANSWER` (`0x01`/`0x02` under Emule): the
    /// pre-0.42 capability block. `0x01` is `OP_HELLO` under Edonkey, so it
    /// resolves ahead of the registry, as `OP_FILEDESC` does.
    EmuleInfo {
        /// `OP_EMULEINFOANSWER` rather than `OP_EMULEINFO`.
        answer: bool,
        /// The block as read.
        info: EmuleInfo,
        /// The payload as it arrived, so a re-encode is the peer's bytes.
        payload: Vec<u8>,
    },
    /// `OP_CHANGE_CLIENT_ID` (`0x4D`): a peer's ID (and, when Low-ID, its
    /// server) changed, surfaced as an event; core applies it to the matching
    /// candidate-pool entry. Wire-silent either way — aMule marks it "Unused
    /// for sending" and rmule never emits it.
    ChangeClientId(ChangeClientId),
    /// `OP_CHANGE_CLIENT_IP` (`0xAC`, ADR-0087): the peer's Known IPv6
    /// changed mid-session. Sixteen raw bytes under the eDonkey protocol, so a
    /// stock client reads an unknown opcode and ignores it.
    ChangeClientIpV6(ChangeClientIpV6),
    /// `OP_CHATCAPTCHAREQ` (`0xA5`): rides on outbound chat, which rmule never
    /// sends, so any inbound instance is unsolicited and dropped.
    ChatCaptchaReq,
    /// `OP_CHATCAPTCHARES` (`0xA6`): same treatment as [`Self::ChatCaptchaReq`].
    ChatCaptchaRes,
    /// A well-formed frame no opcode in this crate claims. Kept whole
    /// (ADR-0018): the bytes stay, so a replay or an inspector can still
    /// account for them.
    Unknown {
        /// The framing byte it arrived under, which is half of what identifies an opcode.
        protocol: PacketProtocol,
        /// The opcode itself.
        opcode: u8,
        /// The payload, untouched.
        payload: Vec<u8>,
    },
}

/// Result of decoding one inbound peer packet frame. Plain frames decode to
/// a [`PeerPacket`]; inbound packed `0xD4` frames whose payload fails to
/// inflate (bad zlib or oversize) surface as a non-terminal skip the session
/// reports as [`crate::NoticeEvent::CompressedFrameSkipped`] rather than
/// closing (ADR-0053). Mirrors
/// `rmule_ed2k::server_packet::DecodedServerFrame` (plain reference, not an
/// intra-doc link — `rmule-peer` does not depend on `rmule-ed2k`).
#[derive(Debug)]
pub(crate) enum DecodedPeerFrame {
    Packet(PeerPacket),
    CompressedFrameSkipped {
        opcode: u8,
        compressed_len: usize,
        reason: CompressedFrameSkipReason,
    },
}

impl PeerPacket {
    /// Decode a packet using rmule's own advertised source-exchange nibble as
    /// the `OP_ANSWERSOURCES` cross-check version — a faithful stand-in for
    /// callers with no session context (offline fixture decode, tests) — and
    /// no extended-requests level, the level before any peer identified.
    /// `Self::decode_frame` (the live session's entry point) uses
    /// `Self::decode_for_peer` instead, threading the *tracked peer's own*
    /// claimed nibble (ADR-0055).
    pub fn decode(packet: &Packet) -> Result<Self, PeerPacketDecodeError> {
        Self::decode_for_peer(
            packet,
            SourceExchangeClaim {
                sx1_nibble: MiscOptions1::rmule_advertised().source_exchange_version(),
                ext_sx: false,
            },
            ExtendedRequests::NONE,
        )
    }

    /// Decode a packet, resolving `OP_ANSWERSOURCES`'s geometry cross-check
    /// against the [`SourceExchangeClaim`] — the answering peer's own
    /// claimed SX1 nibble, not rmule's (see
    /// [`AnswerSources::decode_packet`]'s doc comment). [`Self::decode`]
    /// supplies rmule's own nibble as a stand-in; [`Self::decode_frame`]
    /// threads the session's tracked peer capability through to this instead.
    fn decode_for_peer(
        packet: &Packet,
        claim: SourceExchangeClaim,
        level: ExtendedRequests,
    ) -> Result<Self, PeerPacketDecodeError> {
        // `0x60`/`0x61` carry a second meaning under the opposite protocol byte
        // that the shared `PeerOpcode` registry cannot also claim (ADR-0025,
        // ADR-0068): `0x60` is `OP_QUEUERANKING` (`PeerOpcode::QueueRanking`)
        // under Emule but `OP_ASKSHAREDFILESDIRANS` under Edonkey; `0x61` is
        // `OP_FILEDESC` under Emule but `OP_ASKSHAREDDENIEDANS` under Edonkey.
        // Both resolve here, ahead of the registry — see `human_layer`'s
        // module doc for why they cannot join it as ordinary variants.
        match (packet.protocol(), packet.opcode()) {
            (PacketProtocol::Edonkey, human_layer::OP_ASKSHAREDFILESDIRANS) => {
                return Ok(Self::AskSharedFilesDirAns);
            }
            (PacketProtocol::Edonkey, human_layer::OP_ASKSHAREDDENIEDANS) => {
                return Ok(Self::AskSharedDeniedAns);
            }
            (PacketProtocol::Emule, human_layer::OP_FILEDESC) => {
                return FileDesc::decode_packet(packet)
                    .map(Self::FileDesc)
                    .map_err(|source| PeerPacketDecodeError::HumanLayer { source });
            }
            (PacketProtocol::Emule, OP_EMULEINFO | OP_EMULEINFOANSWER) => {
                return EmuleInfo::decode_packet(packet)
                    .map(|info| Self::EmuleInfo {
                        answer: packet.opcode() == OP_EMULEINFOANSWER,
                        info,
                        payload: packet.payload().to_vec(),
                    })
                    .map_err(|source| PeerPacketDecodeError::EmuleInfo { source });
            }
            _ => {}
        }
        let opcode = match PeerOpcode::try_from_u8(packet.opcode()) {
            Some(op) if op.protocol() == packet.protocol() => op,
            _ => {
                return Ok(Self::Unknown {
                    protocol: packet.protocol(),
                    opcode: packet.opcode(),
                    payload: packet.payload().to_vec(),
                });
            }
        };
        match opcode {
            PeerOpcode::Hello => Hello::decode_packet(packet)
                .map(Self::Hello)
                .map_err(|source| PeerPacketDecodeError::Hello { source }),
            PeerOpcode::HelloAnswer => HelloAnswer::decode_packet(packet)
                .map(Self::HelloAnswer)
                .map_err(|source| PeerPacketDecodeError::HelloAnswer { source }),
            PeerOpcode::RequestFileName => RequestFileName::decode_packet(packet)
                .map(Self::RequestFileName)
                .map_err(|source| PeerPacketDecodeError::FileRequest { source }),
            PeerOpcode::ReqFileNameAnswer => ReqFileNameAnswer::decode_packet(packet)
                .map(Self::ReqFileNameAnswer)
                .map_err(|source| PeerPacketDecodeError::FileRequest { source }),
            PeerOpcode::FileReqAnsNoFil => FileReqAnsNoFil::decode_packet(packet)
                .map(Self::FileReqAnsNoFil)
                .map_err(|source| PeerPacketDecodeError::FileRequest { source }),
            PeerOpcode::SetReqFileId => SetReqFileId::decode_packet(packet)
                .map(Self::SetReqFileId)
                .map_err(|source| PeerPacketDecodeError::FileRequest { source }),
            PeerOpcode::FileStatus => FileStatus::decode_packet(packet)
                .map(Self::FileStatus)
                .map_err(|source| PeerPacketDecodeError::FileRequest { source }),
            PeerOpcode::HashSetRequest => HashSetRequest::decode_packet(packet)
                .map(Self::HashSetRequest)
                .map_err(|source| PeerPacketDecodeError::HashSet { source }),
            PeerOpcode::HashSetAnswer => HashSetAnswer::decode_packet(packet)
                .map(Self::HashSetAnswer)
                .map_err(|source| PeerPacketDecodeError::HashSet { source }),
            PeerOpcode::StartUploadReq => StartUploadReq::decode_packet(packet)
                .map(Self::StartUploadReq)
                .map_err(|source| PeerPacketDecodeError::Slot { source }),
            PeerOpcode::AcceptUploadReq => AcceptUploadReq::decode_packet(packet)
                .map(Self::AcceptUploadReq)
                .map_err(|source| PeerPacketDecodeError::Slot { source }),
            // aMule acts on a cancel whatever rides after the opcode, reading
            // none of it (stock 2.3.3 `4e8f2b3c` `ClientTCPSocket.cpp:673-678`):
            // a body is ignored, never a reason to close.
            PeerOpcode::CancelTransfer => Ok(Self::CancelTransfer(CancelTransfer)),
            PeerOpcode::OutOfPartReqs => OutOfPartReqs::decode_packet(packet)
                .map(Self::OutOfPartReqs)
                .map_err(|source| PeerPacketDecodeError::Slot { source }),
            PeerOpcode::QueueRanking => QueueRanking::decode_packet(packet)
                .map(Self::QueueRanking)
                .map_err(|source| PeerPacketDecodeError::Slot { source }),
            PeerOpcode::RequestParts | PeerOpcode::RequestPartsI64 => {
                RequestParts::decode_packet(packet)
                    .map(Self::RequestParts)
                    .map_err(|source| PeerPacketDecodeError::Parts { source })
            }
            PeerOpcode::SendingPart | PeerOpcode::SendingPartI64 => {
                SendingPart::decode_packet(packet)
                    .map(Self::SendingPart)
                    .map_err(|source| PeerPacketDecodeError::Parts { source })
            }
            PeerOpcode::CompressedPart | PeerOpcode::CompressedPartI64 => {
                CompressedPart::decode_packet(packet)
                    .map(Self::CompressedPart)
                    .map_err(|source| PeerPacketDecodeError::Parts { source })
            }
            PeerOpcode::AnswerSources => {
                // An ExtSX claimant's answer is a record list, so its reader is
                // chosen by the claim rather than by geometry — a
                // variable-length record has no stride to check (ADR-0087).
                // Otherwise aMule's own cross-check reads the *answering
                // peer's* claimed SX1 nibble (`ClientTCPSocket.cpp` @4e8f2b3c).
                if claim.ext_sx {
                    AnswerSources::decode_ext_packet(packet)
                } else {
                    AnswerSources::decode_packet(packet, claim.sx1_nibble)
                }
                .map(Self::AnswerSources)
                .map_err(|source| PeerPacketDecodeError::SourceExchange { source })
            }
            // Inbound serve requests dispatch to the serve callback
            // (ADR-0055): `OP_REQUESTSOURCES` (a bare file hash) and
            // `OP_REQUESTSOURCES2` (the SX2 `<ver><opts><hash>` triple; rmule
            // accepts its correct 19-byte shape rather than replicating aMule
            // 2.3.3's `size != 16` disconnect defect — ADR-0055).
            PeerOpcode::RequestSources => RequestSources::decode_packet(packet)
                .map(Self::RequestSources)
                .map_err(|source| PeerPacketDecodeError::SourceExchangeRequest { source }),
            PeerOpcode::RequestSources2 => RequestSources2::decode_packet(packet)
                .map(Self::RequestSources2)
                .map_err(|source| PeerPacketDecodeError::SourceExchangeRequest2 { source }),
            // `OP_ANSWERSOURCES2` (`0x84`) — a peer's SX2 answer to our own
            // `0x83` ask (ADR-0055 requester consume). Unlike `0x82`, the entry
            // version travels on the wire, so decode is self-contained (no
            // peer-nibble cross-check); the session routes the result through
            // the same sanity/provenance/cap core `0x82` uses. A malformed one
            // is a non-terminal drop, mapped like `0x82`'s `SourceExchange`.
            PeerOpcode::AnswerSources2 => if claim.ext_sx {
                AnswerSources2::decode_ext_packet(packet)
            } else {
                AnswerSources2::decode_packet(packet)
            }
            .map(Self::AnswerSources2)
            .map_err(|source| PeerPacketDecodeError::SourceExchange2 { source }),
            PeerOpcode::AichRequest => AichRequest::decode_packet(packet)
                .map(Self::AichRequest)
                .map_err(|source| PeerPacketDecodeError::Aich { source }),
            PeerOpcode::AichAnswer => AichAnswer::decode_packet(packet)
                .map(Self::AichAnswer)
                .map_err(|source| PeerPacketDecodeError::Aich { source }),
            PeerOpcode::AichFileHashReq => AichFileHashReq::decode_packet(packet)
                .map(Self::AichFileHashReq)
                .map_err(|source| PeerPacketDecodeError::Aich { source }),
            PeerOpcode::AichFileHashAns => AichFileHashAns::decode_packet(packet)
                .map(Self::AichFileHashAns)
                .map_err(|source| PeerPacketDecodeError::Aich { source }),
            PeerOpcode::SecIdentState => SecIdentStatePacket::decode_packet(packet)
                .map(Self::SecIdentState)
                .map_err(|source| PeerPacketDecodeError::Sui { source }),
            PeerOpcode::PublicKey => PublicKeyPacket::decode_packet(packet)
                .map(Self::PublicKey)
                .map_err(|source| PeerPacketDecodeError::Sui { source }),
            PeerOpcode::Signature => SignaturePacket::decode_packet(packet)
                .map(Self::Signature)
                .map_err(|source| PeerPacketDecodeError::Sui { source }),
            // OP_MULTIPACKET (0x92) and OP_MULTIPACKET_EXT (0xA4) both decode
            // through `MultiPacketRequest::decode_packet`, which tells the two
            // apart by opcode (the `size8` field is EXT-only) — the same
            // pattern `RequestParts | RequestPartsI64` uses above (ADR-0054).
            PeerOpcode::MultiPacket | PeerOpcode::MultiPacketExt => {
                MultiPacketRequest::decode_packet(packet, level)
                    .map(Self::MultiPacketRequest)
                    .map_err(|source| PeerPacketDecodeError::MultiPacket { source })
            }
            PeerOpcode::MultiPacketAnswer => MultiPacketAnswer::decode_packet(packet)
                .map(Self::MultiPacketAnswer)
                .map_err(|source| PeerPacketDecodeError::MultiPacket { source }),
            // OP_KAD_FWTCPCHECK_ACK acks *our own* firewall check over the
            // dial-back's TCP link (ADR-0058 requester). aMule's ack is a null
            // packet; any trailing bytes are tolerated (ADR-0018 liberal
            // receive) — the ack's meaning is entirely its arrival on this link.
            PeerOpcode::KadFwTcpCheckAck => Ok(Self::KadFirewallAck),
            PeerOpcode::FwCheckUdpReq => Ok(Self::KadUdpFirewallRequest(packet.payload().to_vec())),
            // Empty-body buddy keepalive (ADR-0061): the meaning is the
            // opcode's arrival on the buddy link; any trailing bytes are
            // tolerated (ADR-0018 liberal receive), as with the firewall ack.
            PeerOpcode::BuddyPing => Ok(Self::BuddyPing),
            PeerOpcode::BuddyPong => Ok(Self::BuddyPong),
            // `OP_CALLBACK` (0x99) / `OP_REASKCALLBACKTCP` (0x9A): the buddy
            // relay outputs. rmule *emits* both as somebody's open-node buddy
            // — framed directly from `crate::buddy`, never round-tripped
            // through this umbrella — and *consumes* both as a firewalled node
            // whose own buddy forwards them. The consume is the
            // reason they decode here: the session surfaces the parsed relay
            // and its owner routes it, exactly as it does the buddy ping.
            //
            // A malformed relay is **not** a protocol violation: the gates
            // that matter (it arrived on our buddy's link, the buddy-ID XOR
            // check, the file we serve) are core's, and tearing the buddy link
            // down over one bad frame would cost every relay behind it. It
            // parks as `Unknown`, ADR-0018's liberal receive.
            PeerOpcode::Callback => Ok(Callback::decode_packet(packet)
                .map_or_else(|_| Self::unknown_from(packet), Self::BuddyCallback)),
            PeerOpcode::ReaskCallbackTcp => Ok(ReaskCallbackTcp::decode_packet(packet)
                .map_or_else(|_| Self::unknown_from(packet), Self::BuddyReaskCallback)),
            // ADR-0068 human-layer catalog. The browse requests and
            // the payload-less drop rows carry no fields worth decoding — the
            // response (or lack of one) never depends on their content — so
            // they tolerate any payload, mirroring `BuddyPing`/`BuddyPong`
            // above.
            PeerOpcode::AskSharedFiles => Ok(Self::AskSharedFiles),
            PeerOpcode::AskSharedDirs => Ok(Self::AskSharedDirs),
            PeerOpcode::AskSharedFilesDir => Ok(Self::AskSharedFilesDir),
            PeerOpcode::AskSharedFilesAnswer => Ok(Self::AskSharedFilesAnswer),
            PeerOpcode::AskSharedDirsAns => Ok(Self::AskSharedDirsAns),
            PeerOpcode::PublicIpReq => Ok(Self::PublicIpReq),
            PeerOpcode::ChatCaptchaReq => Ok(Self::ChatCaptchaReq),
            PeerOpcode::ChatCaptchaRes => Ok(Self::ChatCaptchaRes),
            PeerOpcode::PublicIpAnswer => PublicIpAnswer::decode_packet(packet)
                .map(Self::PublicIpAnswer)
                .map_err(|source| PeerPacketDecodeError::HumanLayer { source }),
            PeerOpcode::Message => Message::decode_packet(packet)
                .map(Self::Message)
                .map_err(|source| PeerPacketDecodeError::HumanLayer { source }),
            PeerOpcode::ChangeClientId => ChangeClientId::decode_packet(packet)
                .map(Self::ChangeClientId)
                .map_err(|source| PeerPacketDecodeError::HumanLayer { source }),
            PeerOpcode::ChangeClientIpV6 => ChangeClientIpV6::decode_packet(packet)
                .map(Self::ChangeClientIpV6)
                .map_err(|source| PeerPacketDecodeError::Ipv6 { source }),
        }
    }

    /// Dispatch-layer entry point used by [`crate::PeerSession`]: maps one
    /// raw [`Packet`] either to a decoded [`PeerPacket`] or to a
    /// non-terminal compressed-frame skip, so failed inbound inflation does
    /// not close the session. Packed (`0xD4`) frames are inflated with the
    /// peer surface's cap and re-attributed to [`PacketProtocol::Emule`]
    /// before normal decode (ADR-0053). Callers that don't need the skip
    /// signal should use [`Self::decode`].
    ///
    /// `claim` is the session's tracked peer capability (the answerer's
    /// source-exchange nibble, `0` before it identified, plus its ExtSX claim)
    /// — the live counterpart to [`Self::decode`]'s stand-in default
    /// (ADR-0055, ADR-0087). `level` is the session's negotiated
    /// extended-requests level, which alone frames a bundle's `0x58` sub.
    pub(crate) fn decode_frame(
        packet: &Packet,
        claim: SourceExchangeClaim,
        level: ExtendedRequests,
    ) -> Result<DecodedPeerFrame, PeerPacketDecodeError> {
        if packet.protocol() == PacketProtocol::PackedEd2k {
            return match crate::compressed_frame::inflate_peer_packet(packet) {
                Ok(inflated) => {
                    Self::decode_for_peer(&inflated, claim, level).map(DecodedPeerFrame::Packet)
                }
                Err(reason) => Ok(DecodedPeerFrame::CompressedFrameSkipped {
                    opcode: packet.opcode(),
                    compressed_len: packet.payload().len(),
                    reason,
                }),
            };
        }
        Self::decode_for_peer(packet, claim, level).map(DecodedPeerFrame::Packet)
    }

    /// Preserve `packet` verbatim as [`Self::Unknown`] — ADR-0018's liberal
    /// receive for a frame whose own decoder refused it but whose opcode must
    /// not close the session.
    fn unknown_from(packet: &Packet) -> Self {
        Self::Unknown {
            protocol: packet.protocol(),
            opcode: packet.opcode(),
            payload: packet.payload().to_vec(),
        }
    }

    #[must_use]
    /// Frame this packet back onto the wire.
    pub fn encode(&self) -> Packet {
        match self {
            Self::Hello(h) => h.encode_packet(),
            Self::HelloAnswer(h) => h.encode_packet(),
            Self::RequestFileName(r) => r.encode_packet(),
            Self::ReqFileNameAnswer(r) => r.encode_packet(),
            Self::FileReqAnsNoFil(r) => r.encode_packet(),
            Self::SetReqFileId(r) => r.encode_packet(),
            Self::FileStatus(r) => r.encode_packet(),
            Self::HashSetRequest(r) => r.encode_packet(),
            Self::HashSetAnswer(r) => r.encode_packet(),
            Self::StartUploadReq(r) => r.encode_packet(),
            Self::AcceptUploadReq(r) => r.encode_packet(),
            Self::CancelTransfer(r) => r.encode_packet(),
            Self::OutOfPartReqs(r) => r.encode_packet(),
            Self::QueueRanking(r) => r.encode_packet(),
            Self::RequestParts(r) => {
                // Pick the narrowest width that fits the actual offsets;
                // round-trips through the umbrella may choose a different
                // opcode than the original wire frame if all offsets fit
                // u32. For wire-faithful round-trip, call
                // `RequestParts::encode_packet(width)` directly.
                let width = narrowest_width_for_ranges(r);
                r.encode_packet(width)
                    .expect("narrowest width always satisfies its own range check")
            }
            Self::SendingPart(sp) => {
                let width = PartOffsetWidth::for_file_size(sp.end.max(sp.start));
                sp.encode_packet(width)
                    .expect("narrowest width always satisfies its own range check")
            }
            Self::CompressedPart(cp) => {
                let width = PartOffsetWidth::for_file_size(cp.start);
                cp.encode_packet(width)
                    .expect("narrowest width always satisfies its own range check")
            }
            Self::RequestSources(r) => r.encode_packet(),
            Self::RequestSources2(r) => r.encode_packet(),
            Self::AnswerSources(a) => a.encode_packet(narrowest_version_for_sources(&a.sources)),
            Self::AnswerSources2(a) => a.encode_packet(),
            Self::AichRequest(r) => r.encode_packet(),
            Self::AichAnswer(a) => a.encode_packet(),
            Self::AichFileHashReq(r) => r.encode_packet(),
            Self::AichFileHashAns(a) => a.encode_packet(),
            Self::SecIdentState(p) => p.encode_packet(),
            Self::PublicKey(p) => p.encode_packet(),
            Self::Signature(p) => p.encode_packet(),
            Self::MultiPacketRequest(r) => r.encode_packet(),
            Self::MultiPacketAnswer(a) => a.encode_packet(),
            // aMule sends a null (empty-body) OP_KAD_FWTCPCHECK_ACK on the eMule
            // extension protocol.
            Self::KadFirewallAck => Packet::new(
                PacketProtocol::Emule,
                PeerOpcode::KadFwTcpCheckAck.as_u8(),
                Vec::new(),
            ),
            Self::KadUdpFirewallRequest(request) => Packet::new(
                PacketProtocol::Emule,
                PeerOpcode::FwCheckUdpReq.as_u8(),
                request.clone(),
            ),
            // Null (empty-body) buddy keepalive over the eMule extension protocol.
            Self::BuddyPing => Packet::new(
                PacketProtocol::Emule,
                PeerOpcode::BuddyPing.as_u8(),
                Vec::new(),
            ),
            Self::BuddyPong => Packet::new(
                PacketProtocol::Emule,
                PeerOpcode::BuddyPong.as_u8(),
                Vec::new(),
            ),
            Self::BuddyCallback(c) => c.encode_packet(),
            Self::BuddyReaskCallback(r) => r.encode_packet(),
            // ADR-0068 human-layer catalog.
            Self::AskSharedFiles => Packet::new(
                PeerOpcode::AskSharedFiles.protocol(),
                PeerOpcode::AskSharedFiles.as_u8(),
                Vec::new(),
            ),
            Self::AskSharedDirs => Packet::new(
                PeerOpcode::AskSharedDirs.protocol(),
                PeerOpcode::AskSharedDirs.as_u8(),
                Vec::new(),
            ),
            Self::AskSharedFilesDir => Packet::new(
                PeerOpcode::AskSharedFilesDir.protocol(),
                PeerOpcode::AskSharedFilesDir.as_u8(),
                Vec::new(),
            ),
            // `0x61` under Edonkey — rmule's only ever-empty emit of the two
            // meanings this byte carries (see `human_layer`).
            Self::AskSharedDeniedAns => Packet::new(
                PacketProtocol::Edonkey,
                human_layer::OP_ASKSHAREDDENIEDANS,
                Vec::new(),
            ),
            Self::AskSharedFilesAnswer => Packet::new(
                PeerOpcode::AskSharedFilesAnswer.protocol(),
                PeerOpcode::AskSharedFilesAnswer.as_u8(),
                Vec::new(),
            ),
            Self::AskSharedDirsAns => Packet::new(
                PeerOpcode::AskSharedDirsAns.protocol(),
                PeerOpcode::AskSharedDirsAns.as_u8(),
                Vec::new(),
            ),
            // `0x60` under Edonkey — the other collision byte (see
            // `human_layer`).
            Self::AskSharedFilesDirAns => Packet::new(
                PacketProtocol::Edonkey,
                human_layer::OP_ASKSHAREDFILESDIRANS,
                Vec::new(),
            ),
            Self::PublicIpReq => Packet::new(
                PeerOpcode::PublicIpReq.protocol(),
                PeerOpcode::PublicIpReq.as_u8(),
                Vec::new(),
            ),
            Self::PublicIpAnswer(p) => p.encode_packet(),
            Self::Message(m) => m.encode_packet(),
            Self::FileDesc(d) => d.encode_packet(),
            Self::EmuleInfo {
                answer, payload, ..
            } => Packet::new(
                PacketProtocol::Emule,
                if *answer {
                    OP_EMULEINFOANSWER
                } else {
                    OP_EMULEINFO
                },
                payload.clone(),
            ),
            Self::ChangeClientId(c) => c.encode_packet(),
            Self::ChangeClientIpV6(c) => c.encode_packet(),
            Self::ChatCaptchaReq => Packet::new(
                PeerOpcode::ChatCaptchaReq.protocol(),
                PeerOpcode::ChatCaptchaReq.as_u8(),
                Vec::new(),
            ),
            Self::ChatCaptchaRes => Packet::new(
                PeerOpcode::ChatCaptchaRes.protocol(),
                PeerOpcode::ChatCaptchaRes.as_u8(),
                Vec::new(),
            ),
            Self::Unknown {
                protocol,
                opcode,
                payload,
            } => Packet::new(*protocol, *opcode, payload.clone()),
        }
    }
}
