//! The **Reask Requester** — the downloader half of the peer-UDP reask
//! (ADR-0057), sans-I/O and stateless.
//!
//! [`ping`] frames the `OP_REASKFILEPING` a pooled source is due, and
//! [`read_reply`] reads what came back into a [`HeardReply`]. Both negotiate
//! the lower of the two advertised UDP versions themselves: the uploader reads
//! our ping by the version we advertised and writes its status only to a
//! UDPv4 pinger (stock 2.3.3 `4e8f2b3c` `ClientUDPSocket.cpp:213-219`), and
//! aMule's pinger frames its extras and reads a status by the uploader's
//! (`CUpDownClient::UDPReaskForDownload`, `ClientUDPSocket.cpp:258-259`). The
//! per-source standing, its clock and the one-ping-in-flight latch are the
//! runtime's.

use rmule_primitives::FileHash;

use super::codec::{ClientUdpOpcode, ReaskAck, ReaskFilePing};
use crate::file::PartBitmap;

/// Frame the `0x90` for `file_hash` to a source that advertised UDP version
/// `theirs`, ours being `ours`. Our part status rides above version 3 and is
/// only built then; the complete-source count rides above version 2 and is
/// `0`, because rmule counts no complete sources.
#[must_use]
pub fn ping(
    file_hash: FileHash,
    ours: u8,
    theirs: u8,
    our_status: impl FnOnce() -> PartBitmap,
) -> Vec<u8> {
    let version = ours.min(theirs);
    ReaskFilePing {
        file_hash,
        part_status: (version > 3).then(our_status),
        complete_sources: (version > 2).then_some(0),
    }
    .encode_udp()
}

/// What a reask reply said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeardReply {
    /// `OP_REASKACK`: our queue rank, with the uploader's part status when
    /// both ends are UDPv4.
    Rank {
        /// The 1-based queue position.
        rank: u16,
        /// The uploader's availability for the file.
        part_status: Option<PartBitmap>,
    },
    /// `OP_QUEUEFULL`: the uploader's queue is (near) full.
    QueueFull,
    /// `OP_FILENOTFOUND`: the uploader no longer shares the file.
    FileNotFound,
    /// The datagram changed nothing, for this reason.
    Ignored(IgnoredReply),
}

/// Why a reply changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IgnoredReply {
    /// Shorter than the two-byte header.
    Runt,
    /// Not `0x91`, `0x92` or `0x93`.
    UnexpectedOpcode,
    /// No source we reask sits at the endpoint it came from.
    UnknownSource,
    /// Its body did not read as the shape both ends' versions call for.
    Misframed,
}

/// Read a reply datagram. `ours` is the UDP version our hello advertised;
/// `source_version` is the advertised version of the source at the reply's
/// endpoint, `None` when no source we reask sits there (aMule matches the
/// reply by `FindClientByIP_UDP`). The body of `0x92`/`0x93` is not read.
#[must_use]
pub fn read_reply(datagram: &[u8], ours: u8, source_version: Option<u8>) -> HeardReply {
    let Some(&opcode) = datagram.get(1) else {
        return HeardReply::Ignored(IgnoredReply::Runt);
    };
    let opcode = match ClientUdpOpcode::try_from_u8(opcode) {
        Some(
            opcode @ (ClientUdpOpcode::ReaskAck
            | ClientUdpOpcode::QueueFull
            | ClientUdpOpcode::FileNotFound),
        ) => opcode,
        _ => return HeardReply::Ignored(IgnoredReply::UnexpectedOpcode),
    };
    let Some(theirs) = source_version else {
        return HeardReply::Ignored(IgnoredReply::UnknownSource);
    };
    match opcode {
        ClientUdpOpcode::QueueFull => HeardReply::QueueFull,
        ClientUdpOpcode::FileNotFound => HeardReply::FileNotFound,
        _ => match ReaskAck::decode_udp(datagram, ours.min(theirs)) {
            Ok(ack) => HeardReply::Rank {
                rank: ack.rank,
                part_status: ack.part_status,
            },
            Err(_) => HeardReply::Ignored(IgnoredReply::Misframed),
        },
    }
}
