//! The umbrella for every packet a server pushes at rmule: one typed variant
//! per inbound opcode, plus the decode outcome the session's dispatch loop
//! reads.
//!
//! A packed `0xD4` frame that fails to inflate surfaces as a non-terminal
//! skip rather than a close, and an unknown well-formed opcode keeps its
//! bytes (ADR-0018).

use rmule_primitives::{Packet, PacketProtocol};

use crate::{
    CallbackFailed, CompressedFrameSkipReason, Ed2kError, FoundSources, FoundSourcesObfu,
    HolepunchFail, HolepunchInfo, IdChange, Opcode, PeerCallback, PeerCallbackIpv6, Reject, Result,
    SearchResultSkipReason, SearchResults, ServerIdent, ServerList, ServerMessage, ServerStatus,
};

/// Result of decoding one inbound eD2k server **Packet Frame** in the
/// session's dispatch loop. Plain frames decode to a [`ServerPacket`];
/// inbound packed `0xD4` frames whose payload fails to inflate (bad zlib
/// or oversize) surface as a non-terminal skip the session reports as
/// [`crate::Ed2kEvent::CompressedFrameSkipped`] rather than closing.
#[derive(Debug)]
pub(crate) enum DecodedServerFrame {
    Packet(ServerPacket),
    CompressedFrameSkipped {
        opcode: u8,
        compressed_len: usize,
        reason: CompressedFrameSkipReason,
    },
    SearchResultSkipped {
        reason: SearchResultSkipReason,
    },
}

/// Umbrella for every server-pushed packet rmule decodes. Unknown well-formed
/// frames land in `Unknown { opcode, payload }` per ADR-0018 so the service
/// layer can ignore them without losing the bytes for diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerPacket {
    /// The server assigned (or re-assigned) our client id.
    IdChange(IdChange),
    /// The server refused the last thing we asked for.
    Reject(Reject),
    /// Free text for the user: a banner, rule or notice.
    ServerMessage(ServerMessage),
    /// The server's user and file counts.
    ServerStatus(ServerStatus),
    /// Other servers it knows about.
    ServerList(ServerList),
    /// The server describing itself.
    ServerIdent(ServerIdent),
    /// Sources for a file we asked about.
    FoundSources(FoundSources),
    /// Sources in the obfuscation-aware form, carrying each source's crypt
    /// stance and user hash.
    FoundSourcesObfu(FoundSourcesObfu),
    /// A batch of search results.
    SearchResults(SearchResults),
    /// A firewalled peer asking us, through the server, to dial it back.
    PeerCallback(PeerCallback),
    /// The same request naming an IPv6 requester (`0x26`, ADR-0087 §4.5).
    PeerCallbackIpv6(PeerCallbackIpv6),
    /// The server could not route a callback we requested.
    CallbackFailed(CallbackFailed),
    /// `OP_LOWID_HOLEPUNCH_INFO` (`0x61`): ed2k-server introducing us to a
    /// LowID peer — sent to both sides of a punch, asked for or not
    /// (ADR-0091).
    HolepunchInfo(HolepunchInfo),
    /// `OP_LOWID_HOLEPUNCH_FAIL` (`0x62`): the server would not introduce us
    /// to the target our `0x60` named.
    HolepunchFail(HolepunchFail),
    /// A well-formed frame whose opcode this build has no model for, kept
    /// whole rather than dropped (ADR-0018).
    Unknown {
        /// The unmodelled opcode.
        opcode: u8,
        /// Its payload, byte-for-byte as it arrived.
        payload: Vec<u8>,
    },
}

impl ServerPacket {
    /// Dispatch-layer entry point used by [`crate::Ed2kSession`]: maps
    /// one raw [`Packet`] either to a decoded [`ServerPacket`] or to a
    /// non-terminal compressed-frame skip, so failed inbound inflation
    /// does not close the session. Callers that don't need the skip
    /// signal should use [`Self::decode`].
    pub(crate) fn decode_frame(packet: &Packet) -> Result<DecodedServerFrame> {
        if packet.protocol() == PacketProtocol::PackedEd2k {
            return match crate::compressed_frame::inflate_server_packet(packet) {
                Ok(inflated) => Self::decode_edonkey_frame(&inflated),
                Err(reason) => Ok(DecodedServerFrame::CompressedFrameSkipped {
                    opcode: packet.opcode(),
                    compressed_len: packet.payload().len(),
                    reason,
                }),
            };
        }
        Self::decode_edonkey_frame(packet)
    }

    /// Decode any inbound server [`Packet`] into a logical [`ServerPacket`].
    ///
    /// Inflates packed `0xD4` frames before dispatching the inflated
    /// opcode. Inflation failure is reported as
    /// [`Ed2kError::InvalidPayload`]; the session uses `decode_frame`
    /// instead so it can treat the same failure as a non-terminal event.
    pub fn decode(packet: &Packet) -> Result<Self> {
        match Self::decode_frame(packet)? {
            DecodedServerFrame::Packet(server_packet) => Ok(server_packet),
            DecodedServerFrame::CompressedFrameSkipped { opcode, .. } => {
                Err(Ed2kError::InvalidPayload {
                    opcode,
                    reason: "compressed server frame skipped",
                })
            }
            DecodedServerFrame::SearchResultSkipped { reason } => Err(Ed2kError::InvalidPayload {
                opcode: Opcode::SearchResult.as_u8(),
                reason: reason.as_static_str(),
            }),
        }
    }

    fn decode_edonkey_frame(packet: &Packet) -> Result<DecodedServerFrame> {
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode: packet.opcode(),
                reason: "unsupported packet protocol",
            });
        }
        if packet.opcode() == Opcode::SearchResult.as_u8() {
            return Ok(match SearchResults::try_decode_packet(packet) {
                Ok(results) => DecodedServerFrame::Packet(Self::SearchResults(results)),
                Err(reason) => DecodedServerFrame::SearchResultSkipped { reason },
            });
        }
        Self::decode_edonkey(packet).map(DecodedServerFrame::Packet)
    }

    /// Decode a plain (non-packed) eDonkey-protocol [`Packet`] into a
    /// logical [`ServerPacket`]. Centralises the opcode-dispatch table
    /// shared by [`Self::decode`] and [`Self::decode_frame`]; rejecting
    /// any other protocol byte here keeps the inflate path structurally
    /// non-recursive.
    fn decode_edonkey(packet: &Packet) -> Result<Self> {
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode: packet.opcode(),
                reason: "unsupported packet protocol",
            });
        }
        let opcode = packet.opcode();
        if opcode == Opcode::IdChange.as_u8() {
            Ok(Self::IdChange(IdChange::decode_packet(packet)?))
        } else if opcode == Opcode::Reject.as_u8() {
            Ok(Self::Reject(Reject::decode_packet(packet)?))
        } else if opcode == Opcode::ServerMessage.as_u8() {
            Ok(Self::ServerMessage(ServerMessage::decode_packet(packet)?))
        } else if opcode == Opcode::ServerStatus.as_u8() {
            Ok(Self::ServerStatus(ServerStatus::decode_packet(packet)?))
        } else if opcode == Opcode::ServerList.as_u8() {
            Ok(Self::ServerList(ServerList::decode_packet(packet)?))
        } else if opcode == Opcode::ServerIdent.as_u8() {
            Ok(Self::ServerIdent(ServerIdent::decode_packet(packet)?))
        } else if opcode == Opcode::FoundSources.as_u8() {
            Ok(Self::FoundSources(FoundSources::decode_packet(packet)?))
        } else if opcode == Opcode::FoundSourcesObfu.as_u8() {
            Ok(Self::FoundSourcesObfu(FoundSourcesObfu::decode_packet(
                packet,
            )?))
        } else if opcode == Opcode::PeerCallback.as_u8() {
            Ok(Self::PeerCallback(PeerCallback::decode_packet(packet)?))
        } else if opcode == Opcode::PeerCallbackIpv6.as_u8() {
            Ok(Self::PeerCallbackIpv6(PeerCallbackIpv6::decode_packet(
                packet,
            )?))
        } else if opcode == Opcode::CallbackFail.as_u8() {
            Ok(Self::CallbackFailed(CallbackFailed::decode_packet(packet)?))
        } else if opcode == Opcode::LowIdHolepunchInfo.as_u8() {
            Ok(Self::HolepunchInfo(HolepunchInfo::decode_packet(packet)?))
        } else if opcode == Opcode::LowIdHolepunchFail.as_u8() {
            Ok(Self::HolepunchFail(HolepunchFail::decode_packet(packet)?))
        } else {
            Ok(Self::Unknown {
                opcode,
                payload: packet.payload().to_vec(),
            })
        }
    }

    /// Re-encode the packet. An [`Unknown`](Self::Unknown) frame re-emits its
    /// kept bytes, so a decode/encode round trip is byte-exact even for
    /// opcodes rmule has no model for.
    #[must_use]
    pub fn encode(&self) -> Packet {
        match self {
            Self::IdChange(p) => p.encode_packet(),
            Self::Reject(p) => p.encode_packet(),
            Self::ServerMessage(p) => p.encode_packet(),
            Self::ServerStatus(p) => p.encode_packet(),
            Self::ServerList(p) => p.encode_packet(),
            Self::ServerIdent(p) => p.encode_packet(),
            Self::FoundSources(p) => p.encode_packet(),
            Self::FoundSourcesObfu(p) => p.encode_packet(),
            Self::SearchResults(p) => p.encode_packet(),
            Self::PeerCallback(p) => p.encode_packet(),
            Self::PeerCallbackIpv6(p) => p.encode_packet(),
            Self::CallbackFailed(p) => p.encode_packet(),
            Self::HolepunchInfo(p) => p.encode_packet(),
            Self::HolepunchFail(p) => p.encode_packet(),
            Self::Unknown { opcode, payload } => {
                Packet::new(PacketProtocol::Edonkey, *opcode, payload.clone())
            }
        }
    }
}
