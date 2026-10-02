//! Peer-UDP source-reask packets — the `0x90`–`0x93` quartet (ADR-0057).
//!
//! Client-UDP opcodes per `src/include/protocol/ed2k/Client2Client/UDP.h` and
//! the framing in `src/ClientUDPSocket.cpp` / `src/DownloadClient.cpp` at aMule
//! `4e8f2b3c`, cite-and-rewritten (ADR-0004). All four travel under
//! `OP_EMULEPROT` (`0xC5`) as a bare UDP datagram — `[protocol][opcode][body]`,
//! no length prefix — carried on the shared client-UDP socket the ADR-0057
//! demux front owns:
//!
//! ```text
//! OP_REASKFILEPING = 0x90  <HASH 16>[part-status][complete-source-count]
//! OP_REASKACK      = 0x91  [part-status]<rank u16>
//! OP_FILENOTFOUND  = 0x92  empty
//! OP_QUEUEFULL     = 0x93  empty
//! ```
//!
//! The downloader emits `0x90` to hold a remote queue position without a TCP
//! session; the uploader answers `0x91` (rank), `0x92` (we do not share it),
//! or `0x93` (queue near full) — the reply matrix lives serve-side, this is
//! only the wire (ADR-0057).
//!
//! **Part status** is aMule's `WritePartStatus`: `<part_count u16><ceil(n/8)
//! bytes>`, the same bitfield [`PartBitmap`] already
//! models for `OP_FILESTATUS`. It rides `0x90` when the pinger's UDP version
//! is `> 3` (its own availability) and `0x91` when the *waiter's* is `> 3`
//! (our availability); the complete-source count rides `0x90` when `> 2`.
//!
//! The one non-reask member of this client-UDP opcode space, `0x95`
//! [`DirectCallbackReq`], is the plug-in point the demux front names
//! (ADR-0061 route 2): the outbound direct-UDP callback request rmule
//! emits to reach a firewalled peer. It shares the framing and header codec of
//! the quartet, so it lives beside them.

use rmule_primitives::{FileHash, PacketProtocol, UserHash};
use thiserror::Error;

use crate::file::{PartBitmap, PartBitmapDecodeError};
use crate::file_request::{FileSizedStatus, read_file_sized_status};

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
        let mut cursor = 0;
        let file_hash = read_file_hash(body, &mut cursor)?;
        let part_status = (udp_version > 3)
            .then(|| read_part_status(body, &mut cursor))
            .transpose()?;
        let complete_sources = (udp_version > 2)
            .then(|| read_u16(body, &mut cursor))
            .transpose()?;
        ensure_consumed(body, cursor)?;
        Ok(Self {
            file_hash,
            part_status,
            complete_sources,
        })
    }

    /// The leading 16-byte file hash of a `0x90` datagram, or `None` when the
    /// datagram is malformed or the wrong opcode. The uploader's reply-matrix
    /// read (ADR-0057): a reask is routed by hash + UDP source alone, and an
    /// unknown pinger's UDP version is unknown, so the version-gated tail is
    /// never parsed on the consume path.
    #[must_use]
    pub fn file_hash_of(datagram: &[u8]) -> Option<FileHash> {
        let body = strip_header(datagram, ClientUdpOpcode::ReaskFilePing).ok()?;
        let mut cursor = 0;
        read_file_hash(body, &mut cursor).ok()
    }

    /// Whether a UDPv3 waiter's `0x90` holds the complete-source count its
    /// reader takes right after the hash, whatever the waiter's
    /// extended-requests claim (stock 2.3.3 `4e8f2b3c`
    /// `ClientUDPSocket.cpp:204-205`). A ping that is the hash alone makes
    /// that read throw, and the dispatcher's catch only logs (`:131-134`):
    /// the ping is malformed and goes unanswered. Bytes past the count are
    /// ignored.
    #[must_use]
    pub fn carries_complete_count(datagram: &[u8]) -> bool {
        strip_header(datagram, ClientUdpOpcode::ReaskFilePing)
            .is_ok_and(|body| body.len() >= FileHash::BYTE_LEN + 2)
    }

    /// What the uploader takes from a UDPv4 waiter's ping for the shared file
    /// of `file_size` bytes, read as aMule's `ProcessExtendedInfo` reads it
    /// (stock 2.3.3 `4e8f2b3c` `UploadClient.cpp:397-456`, reached from
    /// `ClientUDPSocket.cpp:202-203` and the buddy relay's
    /// `ClientTCPSocket.cpp:1735-1736`), `extended_requests` being the
    /// pinger's hello claim. The bitmap is sized by the **file's** part count,
    /// not the wire's; the complete-source count is read only for a claim
    /// above `1`; bytes past what the claim reads are ignored.
    #[must_use]
    pub fn read_status(datagram: &[u8], file_size: u64, extended_requests: u8) -> PingStatus {
        let Some(tail) = strip_header(datagram, ClientUdpOpcode::ReaskFilePing)
            .ok()
            .and_then(|body| body.get(FileHash::BYTE_LEN..))
        else {
            return PingStatus::Malformed(None);
        };
        // A claim of `0` is cleared before anything is read
        // (`UploadClient.cpp:400-406`).
        if extended_requests == 0 {
            return PingStatus::Read(None);
        }
        // The count, the bitmap sized by the file, and a count other than
        // the file's clearing the status are the name ask's reader too
        // (`:408-446`, `read_file_sized_status`).
        match read_file_sized_status(tail, file_size) {
            FileSizedStatus::Cut(status) => PingStatus::Malformed(status),
            FileSizedStatus::Cleared => PingStatus::Read(None),
            // The complete-source count follows a real status for a claim
            // above `1` (`:448-455`); its absence throws after the status is
            // set. Count `0` reads nothing more (`:415-416`).
            FileSizedStatus::Read { status, end }
                if extended_requests > 1 && status.part_count() != 0 && tail.len() < end + 2 =>
            {
                PingStatus::Malformed(Some(status))
            }
            FileSizedStatus::Read { status, .. } => PingStatus::Read(Some(status)),
        }
    }
}

/// What a UDPv4 waiter's `0x90` says of its own parts, as
/// [`ReaskFilePing::read_status`] reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PingStatus {
    /// Read to the end the claim asks for: the pinger's status in its wire
    /// shape (count `0` is a complete copy's), or `None` where aMule clears it
    /// without reading — a claim of `0`, or a count that is not the file's.
    Read(Option<PartBitmap>),
    /// Cut short where aMule's reader throws: its dispatcher only logs, so
    /// the ping goes unanswered. Carries the status as far as it was read
    /// before the throw, `None` when not even the count arrived.
    Malformed(Option<PartBitmap>),
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
        let mut cursor = 0;
        let part_status = (udp_version > 3)
            .then(|| read_part_status(body, &mut cursor))
            .transpose()?;
        let rank = read_u16(body, &mut cursor)?;
        ensure_consumed(body, cursor)?;
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
        let mut cursor = 0;
        let our_tcp_port = read_u16(body, &mut cursor)?;
        let our_user_hash = read_user_hash(body, &mut cursor)?;
        let connect_options = read_u8(body, &mut cursor)?;
        ensure_consumed(body, cursor)?;
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
        if body.len() < BUDDY_ID_LEN {
            return Err(ReaskDecodeError::Truncated {
                needed: BUDDY_ID_LEN,
                actual: body.len(),
            });
        }
        let mut buddy_id = [0u8; BUDDY_ID_LEN];
        buddy_id.copy_from_slice(&body[..BUDDY_ID_LEN]);
        Ok(Self {
            buddy_id,
            forwarded: body[BUDDY_ID_LEN..].to_vec(),
        })
    }
}

fn udp_header(opcode: ClientUdpOpcode) -> Vec<u8> {
    vec![PacketProtocol::Emule.as_byte(), opcode.as_u8()]
}

/// Verify the `[protocol][opcode]` header and return the body slice.
fn strip_header(datagram: &[u8], expect: ClientUdpOpcode) -> Result<&[u8], ReaskDecodeError> {
    if datagram.len() < 2 {
        return Err(ReaskDecodeError::Truncated {
            needed: 2,
            actual: datagram.len(),
        });
    }
    if datagram[0] != PacketProtocol::Emule.as_byte() {
        return Err(ReaskDecodeError::WrongProtocol {
            protocol: datagram[0],
        });
    }
    if datagram[1] != expect.as_u8() {
        return Err(ReaskDecodeError::WrongOpcode {
            opcode: datagram[1],
        });
    }
    Ok(&datagram[2..])
}

fn read_file_hash(body: &[u8], cursor: &mut usize) -> Result<FileHash, ReaskDecodeError> {
    let end = *cursor + FileHash::BYTE_LEN;
    if body.len() < end {
        return Err(ReaskDecodeError::Truncated {
            needed: end,
            actual: body.len(),
        });
    }
    let mut buf = [0u8; FileHash::BYTE_LEN];
    buf.copy_from_slice(&body[*cursor..end]);
    *cursor = end;
    Ok(FileHash::from_bytes(buf))
}

fn read_u16(body: &[u8], cursor: &mut usize) -> Result<u16, ReaskDecodeError> {
    let end = *cursor + 2;
    if body.len() < end {
        return Err(ReaskDecodeError::Truncated {
            needed: end,
            actual: body.len(),
        });
    }
    let value = u16::from_le_bytes([body[*cursor], body[*cursor + 1]]);
    *cursor = end;
    Ok(value)
}

fn read_u8(body: &[u8], cursor: &mut usize) -> Result<u8, ReaskDecodeError> {
    let end = *cursor + 1;
    if body.len() < end {
        return Err(ReaskDecodeError::Truncated {
            needed: end,
            actual: body.len(),
        });
    }
    let value = body[*cursor];
    *cursor = end;
    Ok(value)
}

fn read_user_hash(body: &[u8], cursor: &mut usize) -> Result<UserHash, ReaskDecodeError> {
    let end = *cursor + UserHash::BYTE_LEN;
    if body.len() < end {
        return Err(ReaskDecodeError::Truncated {
            needed: end,
            actual: body.len(),
        });
    }
    let mut buf = [0u8; UserHash::BYTE_LEN];
    buf.copy_from_slice(&body[*cursor..end]);
    *cursor = end;
    Ok(UserHash::from_bytes(buf))
}

/// aMule `WritePartStatus`: `<part_count u16><ceil(n/8) status bytes>`.
fn write_part_status(out: &mut Vec<u8>, status: &PartBitmap) {
    out.extend_from_slice(&(status.part_count() as u16).to_le_bytes());
    out.extend_from_slice(&status.encode());
}

fn read_part_status(body: &[u8], cursor: &mut usize) -> Result<PartBitmap, ReaskDecodeError> {
    let part_count = u32::from(read_u16(body, cursor)?);
    let byte_len = (part_count as usize).div_ceil(8);
    let end = *cursor + byte_len;
    if body.len() < end {
        return Err(ReaskDecodeError::Truncated {
            needed: end,
            actual: body.len(),
        });
    }
    let status = PartBitmap::decode(part_count, &body[*cursor..end])?;
    *cursor = end;
    Ok(status)
}

fn ensure_consumed(body: &[u8], cursor: usize) -> Result<(), ReaskDecodeError> {
    if cursor == body.len() {
        Ok(())
    } else {
        Err(ReaskDecodeError::TrailingBytes {
            trailing: body.len() - cursor,
        })
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
mod tests {
    use super::*;

    fn hash() -> FileHash {
        FileHash::from_bytes([0xAB; FileHash::BYTE_LEN])
    }

    /// A complete two-part file's `WritePartStatus`: count 2, one all-present
    /// byte (`0b0000_0011`).
    fn full_two_parts() -> PartBitmap {
        PartBitmap::decode(2, &[0b0000_0011]).unwrap()
    }

    #[test]
    fn reask_ping_golden_bytes_across_udp_versions() {
        // v4 (> 3): hash + WritePartStatus + complete-source count.
        let v4 = ReaskFilePing {
            file_hash: hash(),
            part_status: Some(full_two_parts()),
            complete_sources: Some(5),
        };
        let mut expected = vec![0xC5, 0x90];
        expected.extend_from_slice(&[0xAB; 16]);
        expected.extend_from_slice(&[0x02, 0x00, 0x03]); // <count=2><status 0x03>
        expected.extend_from_slice(&[0x05, 0x00]); // complete sources
        assert_eq!(v4.encode_udp(), expected);
        assert_eq!(ReaskFilePing::decode_udp(&expected, 4), Ok(v4));

        // v3 (> 2, not > 3): hash + complete-source count only.
        let v3 = ReaskFilePing {
            file_hash: hash(),
            part_status: None,
            complete_sources: Some(5),
        };
        let mut expected = vec![0xC5, 0x90];
        expected.extend_from_slice(&[0xAB; 16]);
        expected.extend_from_slice(&[0x05, 0x00]);
        assert_eq!(v3.encode_udp(), expected);
        assert_eq!(ReaskFilePing::decode_udp(&expected, 3), Ok(v3));

        // v2 (not > 2): the bare hash.
        let v2 = ReaskFilePing {
            file_hash: hash(),
            part_status: None,
            complete_sources: None,
        };
        let mut expected = vec![0xC5, 0x90];
        expected.extend_from_slice(&[0xAB; 16]);
        assert_eq!(v2.encode_udp(), expected);
        assert_eq!(ReaskFilePing::decode_udp(&expected, 2), Ok(v2));
    }

    #[test]
    fn reask_ping_large_file_golden_spans_a_multi_byte_part_status() {
        // The "large form": a file whose part count needs a multi-byte
        // `WritePartStatus` bitfield, proving the 0x90 body carries the full
        // `ceil(parts/8)`-byte status verbatim (aMule `CPartFile::WritePartStatus`
        // loops the whole part count) — the two-part golden above only exercises
        // a single status byte. Twenty parts: 0–15 present (two 0xFF bytes),
        // 16–19 missing (a trailing 0x00 byte the ceil rounding still emits), and
        // a complete-source count large enough to prove its LE u16 (258 = 0x0102).
        let status = PartBitmap::decode(20, &[0xFF, 0xFF, 0x00]).unwrap();
        let large = ReaskFilePing {
            file_hash: hash(),
            part_status: Some(status),
            complete_sources: Some(258),
        };
        let mut expected = vec![0xC5, 0x90];
        expected.extend_from_slice(&[0xAB; 16]);
        expected.extend_from_slice(&[0x14, 0x00]); // <part count = 20>
        expected.extend_from_slice(&[0xFF, 0xFF, 0x00]); // ceil(20/8) = 3 status bytes
        expected.extend_from_slice(&[0x02, 0x01]); // <complete sources = 258>
        assert_eq!(large.encode_udp(), expected);
        assert_eq!(ReaskFilePing::decode_udp(&expected, 4), Ok(large));
    }

    /// The uploader's read of a UDPv4 ping, shape by shape, as
    /// aMule's `ProcessExtendedInfo` reads it (stock 2.3.3 `4e8f2b3c`
    /// `UploadClient.cpp:397-456`).
    #[test]
    fn a_pings_status_is_read_by_the_files_part_count_and_the_senders_claim() {
        use rmule_primitives::ED2K_PART_SIZE;

        let ping = |tail: &[u8]| [&[0xC5, 0x90][..], &[0xAB; 16], tail].concat();
        let bitmap = |count, bytes: &[u8]| PartBitmap::decode(count, bytes).unwrap();

        // Twenty parts: a three-byte status, then the complete-source count.
        let size = 19 * ED2K_PART_SIZE + 1;
        let read = |tail: &[u8], claim| ReaskFilePing::read_status(&ping(tail), size, claim);
        let whole = [0x14, 0x00, 0xFF, 0x0F, 0x03, 0x07, 0x00];
        let status = bitmap(20, &[0xFF, 0x0F, 0x03]);
        assert_eq!(read(&whole, 2), PingStatus::Read(Some(status.clone())));
        // Without the count: malformed for a claim of 2, whole for a claim of 1.
        assert_eq!(
            read(&whole[..5], 2),
            PingStatus::Malformed(Some(status.clone()))
        );
        assert_eq!(read(&whole[..5], 1), PingStatus::Read(Some(status)));
        // A status cut short keeps the bits read before the throw.
        assert_eq!(
            read(&whole[..3], 1),
            PingStatus::Malformed(Some(bitmap(20, &[0xFF, 0x00, 0x00]))),
        );
        // The hash alone, or a count cut short: nothing set.
        assert_eq!(read(&[], 1), PingStatus::Malformed(None));
        assert_eq!(read(&whole[..1], 1), PingStatus::Malformed(None));
        // A claim of 0 is never read; a count not the file's clears unread.
        assert_eq!(read(&[], 0), PingStatus::Read(None));
        assert_eq!(read(&[0x13, 0x00], 2), PingStatus::Read(None));
        // Count 0 reads nothing more, not even the complete-source count.
        assert_eq!(
            read(&[0x00, 0x00], 2),
            PingStatus::Read(Some(bitmap(0, &[])))
        );

        // Sixteen whole parts: the wire counts seventeen (a phantom part),
        // but the reader takes the file's two bytes and the count right after.
        let size = 16 * ED2K_PART_SIZE;
        let read = |tail: &[u8]| ReaskFilePing::read_status(&ping(tail), size, 2);
        assert_eq!(
            read(&[0x11, 0x00, 0xFF, 0xFF, 0x05, 0x00]),
            PingStatus::Read(Some(bitmap(17, &[0xFF, 0xFF, 0x00]))),
        );
        assert_eq!(
            read(&[0x11, 0x00, 0xFF, 0xFF, 0x01]),
            PingStatus::Malformed(Some(bitmap(17, &[0xFF, 0xFF, 0x00]))),
        );
    }

    #[test]
    fn reask_ack_golden_bytes_gate_part_status_on_the_waiters_version() {
        // Waiter UDP v4: our part status rides ahead of the rank.
        let v4 = ReaskAck {
            part_status: Some(full_two_parts()),
            rank: 7,
        };
        let expected = vec![0xC5, 0x91, 0x02, 0x00, 0x03, 0x07, 0x00];
        assert_eq!(v4.encode_udp(), expected);
        assert_eq!(ReaskAck::decode_udp(&expected, 4), Ok(v4));

        // Waiter UDP v3: rank only.
        let v3 = ReaskAck {
            part_status: None,
            rank: 7,
        };
        let expected = vec![0xC5, 0x91, 0x07, 0x00];
        assert_eq!(v3.encode_udp(), expected);
        assert_eq!(ReaskAck::decode_udp(&expected, 3), Ok(v3));
    }

    #[test]
    fn empty_body_replies_are_two_byte_datagrams() {
        assert_eq!(file_not_found_datagram(), vec![0xC5, 0x92]);
        assert_eq!(queue_full_datagram(), vec![0xC5, 0x93]);
    }

    #[test]
    fn file_hash_of_reads_the_hash_regardless_of_the_version_tail() {
        // A v4 ping carries a tail the consume path never parses; the hash is
        // still recovered.
        let ping = ReaskFilePing {
            file_hash: hash(),
            part_status: Some(full_two_parts()),
            complete_sources: Some(9),
        };
        assert_eq!(
            ReaskFilePing::file_hash_of(&ping.encode_udp()),
            Some(hash())
        );
        // A datagram too short to carry a hash yields nothing rather than
        // panicking (an unknown pinger's junk).
        assert_eq!(ReaskFilePing::file_hash_of(&[0xC5, 0x90, 0x00]), None);
        // Wrong opcode is not a ping.
        assert_eq!(ReaskFilePing::file_hash_of(&queue_full_datagram()), None);
    }

    #[test]
    fn decode_rejects_wrong_frame_and_trailing_bytes() {
        let ping = ReaskFilePing {
            file_hash: hash(),
            part_status: None,
            complete_sources: None,
        };
        // Wrong protocol byte (a server-UDP `0xE3`, never on this socket).
        let mut wrong_proto = ping.encode_udp();
        wrong_proto[0] = 0xE3;
        assert_eq!(
            ReaskFilePing::decode_udp(&wrong_proto, 2),
            Err(ReaskDecodeError::WrongProtocol { protocol: 0xE3 }),
        );
        // Wrong opcode.
        assert_eq!(
            ReaskAck::decode_udp(&ping.encode_udp(), 2),
            Err(ReaskDecodeError::WrongOpcode { opcode: 0x90 }),
        );
        // Trailing bytes past the declared body (a v2 ping with junk appended).
        let mut trailing = ping.encode_udp();
        trailing.push(0xFF);
        assert_eq!(
            ReaskFilePing::decode_udp(&trailing, 2),
            Err(ReaskDecodeError::TrailingBytes { trailing: 1 }),
        );
    }

    #[test]
    fn direct_callback_req_golden_bytes_and_round_trip() {
        // ADR-0061 route 2 emit: `[0xC5][0x95]<our TCP port LE><our user hash
        // 16><connect options>`. 0x4CE2 = 19_682, our advertised TCP port;
        // connect options 0x03 = supports+requests crypt (bits 0,1).
        let req = DirectCallbackReq {
            our_tcp_port: 0x4CE2,
            our_user_hash: UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]),
            connect_options: 0x03,
        };
        let mut expected = vec![0xC5, 0x95, 0xE2, 0x4C];
        expected.extend_from_slice(&[0x5A; 16]);
        expected.push(0x03);
        assert_eq!(req.encode_udp(), expected);
        assert_eq!(DirectCallbackReq::decode_udp(&expected), Ok(req));
        // The body is fixed-width — 2 + 16 + 1 = 19 bytes under the 2-byte
        // header — so a short datagram is truncated, not silently accepted.
        assert_eq!(
            DirectCallbackReq::decode_udp(&expected[..expected.len() - 1]),
            Err(ReaskDecodeError::Truncated {
                needed: 19,
                actual: 18
            }),
        );
        // Trailing bytes past the fixed body are rejected (an over-long junk
        // datagram is not a callback request).
        let mut trailing = expected.clone();
        trailing.push(0xFF);
        assert_eq!(
            DirectCallbackReq::decode_udp(&trailing),
            Err(ReaskDecodeError::TrailingBytes { trailing: 1 }),
        );
        // A reask opcode is not a direct-callback request.
        assert_eq!(
            DirectCallbackReq::decode_udp(&queue_full_datagram()),
            Err(ReaskDecodeError::WrongOpcode { opcode: 0x93 }),
        );
    }

    #[test]
    fn reask_callback_udp_splits_the_verified_buddy_id_from_the_forwarded_tail() {
        // The 0x94 relay input: `[0xC5][0x94]<buddyID 16><forwarded…>`. The
        // leading 16 bytes are the buddy-ID the open node verifies against its
        // registered buddy; the rest is forwarded opaquely to the firewalled
        // client (aMule's `packet + 16, size - 16`).
        let msg = ReaskCallbackUdp {
            buddy_id: [0x7A; BUDDY_ID_LEN],
            forwarded: vec![0x01, 0x02, 0x03, 0x04],
        };
        let mut expected = vec![0xC5, 0x94];
        expected.extend_from_slice(&[0x7A; 16]);
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(msg.encode_udp(), expected);
        assert_eq!(ReaskCallbackUdp::decode_udp(&expected), Ok(msg));

        // An exactly-16-byte body is a valid relay with an empty forwarded tail.
        assert_eq!(
            ReaskCallbackUdp::decode_udp(&[vec![0xC5, 0x94], vec![0x11; 16]].concat()),
            Ok(ReaskCallbackUdp {
                buddy_id: [0x11; 16],
                forwarded: Vec::new(),
            })
        );
        // A body shorter than the 16-byte buddy-ID is truncated, never a partial id.
        assert_eq!(
            ReaskCallbackUdp::decode_udp(&[vec![0xC5, 0x94], vec![0x00; 15]].concat()),
            Err(ReaskDecodeError::Truncated {
                needed: 16,
                actual: 15
            }),
        );
        // A different opcode is not a reask-callback.
        assert_eq!(
            ReaskCallbackUdp::decode_udp(&queue_full_datagram()),
            Err(ReaskDecodeError::WrongOpcode { opcode: 0x93 }),
        );
    }

    #[test]
    fn opcode_round_trips_including_the_callback_seams() {
        for (byte, opcode) in [
            (0x90, ClientUdpOpcode::ReaskFilePing),
            (0x91, ClientUdpOpcode::ReaskAck),
            (0x92, ClientUdpOpcode::FileNotFound),
            (0x93, ClientUdpOpcode::QueueFull),
            (0x94, ClientUdpOpcode::ReaskCallbackUdp),
            (0x95, ClientUdpOpcode::DirectCallbackReq),
        ] {
            assert_eq!(ClientUdpOpcode::try_from_u8(byte), Some(opcode));
            assert_eq!(opcode.as_u8(), byte);
        }
        assert_eq!(ClientUdpOpcode::try_from_u8(0x60), None);
    }
}
