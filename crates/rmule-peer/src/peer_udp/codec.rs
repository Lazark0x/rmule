//! The client-UDP codec: the frames the peer-UDP surface carries, each
//! encoded and decoded whole, with no rule about when to send or how to answer
//! one (the [`responder`](super::responder) and [`requester`](super::requester)
//! own those).
//!
//! Client-UDP opcodes per `src/include/protocol/ed2k/Client2Client/UDP.h` and
//! the framing in `src/ClientUDPSocket.cpp` / `src/DownloadClient.cpp` at aMule
//! `4e8f2b3c`, cite-and-rewritten (ADR-0004). All travel under `OP_EMULEPROT`
//! (`0xC5`) as a bare UDP datagram — `[protocol][opcode][body]`, no length
//! prefix — on the shared client-UDP socket (ADR-0057):
//!
//! ```text
//! OP_REASKFILEPING = 0x90  <HASH 16>[part-status][complete-source-count]
//! OP_REASKACK      = 0x91  [part-status]<rank u16>
//! OP_FILENOTFOUND  = 0x92  empty
//! OP_QUEUEFULL     = 0x93  empty
//! ```
//!
//! **Part status** is aMule's `WritePartStatus`: `<part_count u16><ceil(n/8)
//! bytes>`, the same bitfield [`PartBitmap`] already models for
//! `OP_FILESTATUS`. Which optional fields a frame carries is the sender's UDP
//! version's business; the codec takes the version it is told.
//!
//! Beside the reask quartet sit the frames that share its header: `0x94`
//! [`ReaskCallbackUdp`] (the buddy relay input) and `0x95`
//! [`DirectCallbackReq`] (ADR-0061 route 2).

use rmule_primitives::{FileHash, PacketProtocol, UserHash, WireReader, WireTruncated};
use thiserror::Error;

use crate::file::{PartBitmap, PartBitmapDecodeError};

/// The client-UDP opcode space (all under `OP_EMULEPROT`), distinct from the
/// TCP [`PeerOpcode`](crate::opcode::PeerOpcode). The reask quartet plus the
/// two callback opcodes the ADR-0057 demux front leaves as named plug-in
/// points for LowID connectivity (ADR-0061) — modelled here so the demux
/// can name them rather than lump them into "unknown".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientUdpOpcode {
    /// `OP_REASKFILEPING`: downloader → uploader reask heartbeat.
    ReaskFilePing = 0x90,
    /// `OP_REASKACK`: uploader → downloader, carries the queue rank.
    ReaskAck = 0x91,
    /// `OP_FILENOTFOUND`: uploader → downloader, the hash is not shared.
    FileNotFound = 0x92,
    /// `OP_QUEUEFULL`: uploader → downloader, the queue is (near) full.
    QueueFull = 0x93,
    /// `OP_REASKCALLBACKUDP`: a downloader's reask relayed through a firewalled
    /// uploader's buddy — the open-node relay input ([`ReaskCallbackUdp`]).
    ReaskCallbackUdp = 0x94,
    /// `OP_DIRECTCALLBACKREQ`: UDP direct-callback request — rmule emits it;
    /// consuming one is the firewalled-node role.
    DirectCallbackReq = 0x95,
    /// `OP_RENDEZVOUS`: eMuleAI's NAT-T introduction (ADR-0091) — standalone
    /// here, and more often embedded in a `0x94`/`0x9A` relay
    /// ([`RendezvousBody`](crate::natt::RendezvousBody)).
    Rendezvous = 0xA0,
    /// `OP_HOLEPUNCH`: the empty-bodied punch.
    Holepunch = 0xA1,
    /// `OP_NATT_ENDPOINT_HINT`: a serving buddy's answer naming the target's
    /// live endpoint ([`EndpointHint`](crate::natt::EndpointHint)).
    NattEndpointHint = 0xAA,
}

impl ClientUdpOpcode {
    #[must_use]
    /// The opcode's wire byte.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    #[must_use]
    /// The opcode this byte names, or `None` when rmule models none.
    pub const fn try_from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x90 => Some(Self::ReaskFilePing),
            0x91 => Some(Self::ReaskAck),
            0x92 => Some(Self::FileNotFound),
            0x93 => Some(Self::QueueFull),
            0x94 => Some(Self::ReaskCallbackUdp),
            0x95 => Some(Self::DirectCallbackReq),
            0xA0 => Some(Self::Rendezvous),
            0xA1 => Some(Self::Holepunch),
            0xAA => Some(Self::NattEndpointHint),
            _ => None,
        }
    }
}

/// `OP_REASKFILEPING` (`0x90`) — the downloader's UDP reask. `part_status` is
/// present iff the sender's UDP version is `> 3`, `complete_sources` iff `> 2`
/// (aMule `CUpDownClient::UDPReaskForDownload`); the two are monotonic (a `> 3`
/// sender carries both).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaskFilePing {
    /// The file the ping is about.
    pub file_hash: FileHash,
    /// The pinger's own availability for the file (its `WritePartStatus`).
    pub part_status: Option<PartBitmap>,
    /// The pinger's complete-source count (`m_nCompleteSourcesCount`).
    pub complete_sources: Option<u16>,
}

/// `OP_REASKACK` (`0x91`) — the uploader's answer. `part_status` (our
/// availability) is present iff the *waiter's* UDP version is `> 3`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaskAck {
    /// Our availability for the file, sent only when the waiter's version can read it.
    pub part_status: Option<PartBitmap>,
    /// The waiter's 1-based queue position (`GetUploadQueueWaitingPosition`).
    pub rank: u16,
}

impl ReaskFilePing {
    #[must_use]
    /// Frame the ping, including only the fields this sender's version carries.
    pub fn encode_udp(&self) -> Vec<u8> {
        let mut datagram = udp_header(ClientUdpOpcode::ReaskFilePing);
        datagram.extend_from_slice(self.file_hash.as_bytes());
        if let Some(status) = &self.part_status {
            write_part_status(&mut datagram, status);
        }
        if let Some(count) = self.complete_sources {
            datagram.extend_from_slice(&count.to_le_bytes());
        }
        datagram
    }

    /// Decode a full `[0xC5][0x90][body]` datagram, reading the version-gated
    /// fields as the stored client's `udp_version` dictates — the downloader
    /// knows the peer's version from its hello, so this stays a
    /// parameter.
    pub fn decode_udp(datagram: &[u8], udp_version: u8) -> Result<Self, ReaskDecodeError> {
        let body = strip_header(datagram, ClientUdpOpcode::ReaskFilePing)?;
        let mut reader = WireReader::new(body);
        let file_hash = reader.read_file_hash("file hash")?;
        let part_status = (udp_version > 3)
            .then(|| read_part_status(&mut reader))
            .transpose()?;
        let complete_sources = (udp_version > 2)
            .then(|| reader.read_u16_le("complete source count"))
            .transpose()?;
        ensure_consumed(&reader)?;
        Ok(Self {
            file_hash,
            part_status,
            complete_sources,
        })
    }
}

impl ReaskAck {
    #[must_use]
    /// Frame the answer, including our availability only when the waiter can read it.
    pub fn encode_udp(&self) -> Vec<u8> {
        let mut datagram = udp_header(ClientUdpOpcode::ReaskAck);
        if let Some(status) = &self.part_status {
            write_part_status(&mut datagram, status);
        }
        datagram.extend_from_slice(&self.rank.to_le_bytes());
        datagram
    }

    /// Decode a full `[0xC5][0x91][body]` datagram. `udp_version` is *our*
    /// advertised version to the answering uploader: the part status rides
    /// iff it saw us as `> 3` (the reason the downloader keys the parse on
    /// the same version it advertised).
    pub fn decode_udp(datagram: &[u8], udp_version: u8) -> Result<Self, ReaskDecodeError> {
        let body = strip_header(datagram, ClientUdpOpcode::ReaskAck)?;
        let mut reader = WireReader::new(body);
        let part_status = (udp_version > 3)
            .then(|| read_part_status(&mut reader))
            .transpose()?;
        let rank = reader.read_u16_le("queue rank")?;
        ensure_consumed(&reader)?;
        Ok(Self { part_status, rank })
    }
}

/// The empty-body `0x92` datagram — the uploader does not share the hash.
#[must_use]
pub fn file_not_found_datagram() -> Vec<u8> {
    udp_header(ClientUdpOpcode::FileNotFound)
}

/// The empty-body `0x93` datagram — the uploader's queue is (near) full.
#[must_use]
pub fn queue_full_datagram() -> Vec<u8> {
    udp_header(ClientUdpOpcode::QueueFull)
}

/// `OP_DIRECTCALLBACKREQ` (`0x95`) — the **direct UDP callback** request
/// (ADR-0061 route 2, the emit side). rmule, reaching a firewalled peer that
/// advertises `SupportsDirectUDPCallback` while our own UDP surface is open,
/// asks it over UDP to connect *back* to us instead of a relay. aMule sends it
/// to the target's **Kad** UDP port (`BaseClient.cpp`), plaintext — aMule does
/// not obfuscate callback requests, an own limitation the ADR keeps.
///
/// Body `<our TCP port u16 LE><our user hash 16><connect options u8>`: the port
/// and hash are where and how the target connects back; the connect-options byte
/// is *our* crypt stance (bits 0-2, the [`SourceCryptOptions`] layout) so the
/// target may obfuscate that connect-back. The inbound consume — rate-limit,
/// firewalled-only gate, and dial-back — is the firewalled-node role;
/// this is only the emit wire.
///
/// [`SourceCryptOptions`]: rmule_primitives::SourceCryptOptions
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectCallbackReq {
    /// Our advertised TCP listen port — where the target dials back.
    pub our_tcp_port: u16,
    /// Our user hash — the key basis for the target's obfuscated connect-back.
    pub our_user_hash: UserHash,
    /// Our connect options: the crypt-stance bits (0-2) the target reads to
    /// decide whether to obfuscate its dial-back (bit 3, direct-callback
    /// support, is `0` here — we are the requester, not being called back).
    pub connect_options: u8,
}

impl DirectCallbackReq {
    #[must_use]
    /// Frame the request.
    pub fn encode_udp(&self) -> Vec<u8> {
        let mut datagram = udp_header(ClientUdpOpcode::DirectCallbackReq);
        datagram.extend_from_slice(&self.our_tcp_port.to_le_bytes());
        datagram.extend_from_slice(self.our_user_hash.as_bytes());
        datagram.push(self.connect_options);
        datagram
    }

    /// Decode a full `[0xC5][0x95][body]` datagram — the firewalled-node
    /// consume reads it, and the emit round-trips through it.
    pub fn decode_udp(datagram: &[u8]) -> Result<Self, ReaskDecodeError> {
        let body = strip_header(datagram, ClientUdpOpcode::DirectCallbackReq)?;
        let mut reader = WireReader::new(body);
        let our_tcp_port = reader.read_u16_le("callback TCP port")?;
        let our_user_hash = UserHash::from_bytes(reader.read_array("callback user hash")?);
        let connect_options = reader.read_u8("connect options")?;
        ensure_consumed(&reader)?;
        Ok(Self {
            our_tcp_port,
            our_user_hash,
            connect_options,
        })
    }
}

/// The 16-byte buddy-ID a `0x94` (and its `0x9A` TCP relay) is keyed on — the
/// prefix a buddy verifies against its registered buddy before relaying.
pub const BUDDY_ID_LEN: usize = 16;

/// `OP_REASKCALLBACKUDP` (`0x94`) — a downloader's queue reask relayed toward a
/// firewalled uploader through *its buddy* (us), when the downloader cannot
/// reach the uploader directly (ADR-0061 open-node relay). aMule sends it to the
/// buddy's UDP port
/// ([`ClientUDPSocket.cpp`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientUDPSocket.cpp#L143));
/// the buddy verifies the leading buddy-ID against its registered buddy
/// (`md4cmp(packet, buddy->GetBuddyID())`) and relays over the buddy's TCP link
/// as `OP_REASKCALLBACKTCP` (`0x9A`, the `buddy` module), injecting the requester's
/// endpoint.
///
/// Body `<buddyID 16><forwarded…>`: the leading 16 bytes are the buddy-ID rmule
/// verifies (the relay tightening's anchor); the rest is the reask context the
/// buddy forwards verbatim to its firewalled client — opaque to the relay, so
/// its exact fields belong to the firewalled-node consume (kept opaque here
/// rather than guessed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaskCallbackUdp {
    /// The buddy-ID the requester addressed — verified against the registered
    /// buddy before relaying.
    pub buddy_id: [u8; BUDDY_ID_LEN],
    /// The forwarded callback payload after the buddy-ID (opaque to the relay).
    pub forwarded: Vec<u8>,
}

impl ReaskCallbackUdp {
    #[must_use]
    /// Frame the relay, buddy-ID first.
    pub fn encode_udp(&self) -> Vec<u8> {
        let mut datagram = udp_header(ClientUdpOpcode::ReaskCallbackUdp);
        datagram.extend_from_slice(&self.buddy_id);
        datagram.extend_from_slice(&self.forwarded);
        datagram
    }

    /// Decode a full `[0xC5][0x94][body]` datagram into the verified buddy-ID and
    /// the forwarded tail. A body shorter than the 16-byte buddy-ID is truncated.
    pub fn decode_udp(datagram: &[u8]) -> Result<Self, ReaskDecodeError> {
        let body = strip_header(datagram, ClientUdpOpcode::ReaskCallbackUdp)?;
        let mut reader = WireReader::new(body);
        let buddy_id = reader.read_array::<BUDDY_ID_LEN>("buddy id")?;
        Ok(Self {
            buddy_id,
            forwarded: reader.remaining_bytes().to_vec(),
        })
    }
}

pub(super) fn udp_header(opcode: ClientUdpOpcode) -> Vec<u8> {
    vec![PacketProtocol::Emule.as_byte(), opcode.as_u8()]
}

/// Verify the `[protocol][opcode]` header and return the body slice.
pub(super) fn strip_header(
    datagram: &[u8],
    expect: ClientUdpOpcode,
) -> Result<&[u8], ReaskDecodeError> {
    let mut reader = WireReader::new(datagram);
    let [protocol, opcode] = reader.read_array("frame header")?;
    if protocol != PacketProtocol::Emule.as_byte() {
        return Err(ReaskDecodeError::WrongProtocol { protocol });
    }
    if opcode != expect.as_u8() {
        return Err(ReaskDecodeError::WrongOpcode { opcode });
    }
    Ok(reader.remaining_bytes())
}

/// aMule `WritePartStatus`: `<part_count u16><ceil(n/8) status bytes>`.
fn write_part_status(out: &mut Vec<u8>, status: &PartBitmap) {
    out.extend_from_slice(&(status.part_count() as u16).to_le_bytes());
    out.extend_from_slice(&status.encode());
}

fn read_part_status(reader: &mut WireReader<'_>) -> Result<PartBitmap, ReaskDecodeError> {
    let part_count = u32::from(reader.read_u16_le("part count")?);
    let status = reader.take((part_count as usize).div_ceil(8), "part status")?;
    Ok(PartBitmap::decode(part_count, status)?)
}

fn ensure_consumed(reader: &WireReader<'_>) -> Result<(), ReaskDecodeError> {
    if reader.is_exhausted() {
        Ok(())
    } else {
        Err(ReaskDecodeError::TrailingBytes {
            trailing: reader.remaining(),
        })
    }
}

impl From<WireTruncated> for ReaskDecodeError {
    fn from(truncated: WireTruncated) -> Self {
        Self::Truncated {
            needed: truncated.needed,
            actual: truncated.available,
        }
    }
}

/// Why a client-UDP datagram could not be read.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ReaskDecodeError {
    /// The datagram did not open with the eMule protocol byte.
    #[error("reask datagram not OP_EMULEPROT-framed: 0x{protocol:02X}")]
    WrongProtocol {
        /// The byte that opened it.
        protocol: u8,
    },

    /// The decoder was handed a datagram of some other opcode.
    #[error("wrong opcode for reask variant: 0x{opcode:02X}")]
    WrongOpcode {
        /// The opcode that arrived.
        opcode: u8,
    },

    /// The datagram ended inside a field the shape requires.
    #[error("reask datagram truncated: needed {needed} bytes, had {actual}")]
    Truncated {
        /// Bytes required at that point.
        needed: usize,
        /// Bytes present.
        actual: usize,
    },

    /// The part bitmap inside it did not decode.
    #[error("reask part-status decode failed: {0}")]
    PartStatus(#[from] PartBitmapDecodeError),

    /// Bytes remain after the shape ends — the optional fields are decided
    /// by the sender's version, so a tail means that version was misread.
    #[error("reask datagram has {trailing} trailing bytes after its body")]
    TrailingBytes {
        /// How many are left over.
        trailing: usize,
    },
}

#[cfg(test)]
mod tests;
