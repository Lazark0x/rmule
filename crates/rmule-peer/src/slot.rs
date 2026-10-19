//! Slot-queue packets.
//!
//! Opcodes per `src/include/protocol/ed2k/Client2Client/TCP.h` at amule
//! `377ec8d9`:
//!   OP_STARTUPLOADREQ  = 0x54 (OP_EDONKEYPROT) <HASH 16>
//!   OP_ACCEPTUPLOADREQ = 0x55 (OP_EDONKEYPROT) empty
//!   OP_CANCELTRANSFER  = 0x56 (OP_EDONKEYPROT) empty — "stop sending, I no
//!                        longer want this transfer" (ADR-0056)
//!   OP_OUTOFPARTREQS   = 0x57 (OP_EDONKEYPROT) empty — TCP "back to queue"
//!   OP_QUEUERANKING    = 0x60 (OP_EMULEPROT)   12 bytes: u16 rank + 10 zero pad
//!
//! `OP_OUTOFPARTREQS` is the uploader ending a granted transfer and queueing
//! the downloader again: aMule sends it when the session's time or bytes are
//! up while someone waits, then ranks the downloader on the same socket
//! (`UploadClient.cpp:643-660`). Its receiver goes back to queued
//! (`ClientTCPSocket.cpp:755-762`), and the session does the same (ADR-0025).
//! `OP_QUEUEFULL = 0x93` is a UDP-only opcode and this session has no UDP
//! surface.
//!
//! `OP_QUEUERANKING`'s 10-byte trailing pad is "purpose unknown" per
//! eMule spec §6.5.4; aMule sender writes zeros (`UploadClient.cpp:585-589`)
//! and receiver requires exactly 12 bytes via `PeekUInt16` on the head
//! (`ClientTCPSocket.cpp:1331-1349`). Legacy `OP_QUEUERANK = 0x5C` (u32,
//! standard protocol) has never been sent by any aMule version (git
//! search returns zero hits) and falls through to `PeerPacket::Unknown`.

use rmule_primitives::{FileHash, Packet, WireReader, empty_body_codec};
use thiserror::Error;

use crate::opcode::PeerOpcode;

const QUEUE_RANKING_PAYLOAD_LEN: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq)]
/// `OP_STARTUPLOADREQ` (`0x54`) — queue me for this file.
pub struct StartUploadReq {
    /// The file wanted.
    pub file_hash: FileHash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// `OP_QUEUERANKING` (`0x60` under Emule) — how far from the front the
/// queued peer stands. Names no file: a link has at most one queued
/// context, so there is nothing to disambiguate.
pub struct QueueRanking {
    /// Places ahead of the peer.
    pub rank: u16,
}

impl StartUploadReq {
    /// Read the request.
    pub fn decode_packet(packet: &Packet) -> Result<Self, SlotDecodeError> {
        let payload = packet.payload();
        if payload.len() != FileHash::BYTE_LEN {
            return Err(SlotDecodeError::WrongPayloadLen {
                expected: FileHash::BYTE_LEN,
                actual: payload.len(),
            });
        }
        let mut buf = [0u8; FileHash::BYTE_LEN];
        buf.copy_from_slice(payload);
        Ok(Self {
            file_hash: FileHash::from_bytes(buf),
        })
    }

    #[must_use]
    /// Frame the request.
    pub fn encode_packet(&self) -> Packet {
        Packet::new(
            PeerOpcode::StartUploadReq.protocol(),
            PeerOpcode::StartUploadReq.as_u8(),
            self.file_hash.as_bytes().to_vec(),
        )
    }
}

empty_body_codec! {
    /// `OP_ACCEPTUPLOADREQ` (`0x55`) — the slot is granted; part requests
    /// may start.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    AcceptUploadReq, SlotDecodeError,
    protocol: PeerOpcode::AcceptUploadReq.protocol(),
    opcode: PeerOpcode::AcceptUploadReq.as_u8()
}

empty_body_codec! {
    /// `OP_OUTOFPARTREQS` (`0x57`) — the granted transfer is over; back to
    /// the queue.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    OutOfPartReqs, SlotDecodeError,
    protocol: PeerOpcode::OutOfPartReqs.protocol(),
    opcode: PeerOpcode::OutOfPartReqs.as_u8()
}

empty_body_codec! {
    /// `OP_CANCELTRANSFER` (ADR-0056): "stop sending, I no longer want this
    /// transfer." The downloader emits it; the uploader ends the upload
    /// relationship on receipt but keeps the connection open (no disconnect).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    CancelTransfer, SlotDecodeError,
    protocol: PeerOpcode::CancelTransfer.protocol(),
    opcode: PeerOpcode::CancelTransfer.as_u8()
}

impl QueueRanking {
    /// Read the ranking, which is fixed-size and padded.
    pub fn decode_packet(packet: &Packet) -> Result<Self, SlotDecodeError> {
        let payload = packet.payload();
        if payload.len() != QUEUE_RANKING_PAYLOAD_LEN {
            return Err(SlotDecodeError::WrongPayloadLen {
                expected: QUEUE_RANKING_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        let rank = WireReader::new(payload)
            .read_u16_le("queue rank")
            .map_err(|truncated| SlotDecodeError::WrongPayloadLen {
                expected: QUEUE_RANKING_PAYLOAD_LEN,
                actual: truncated.available,
            })?;
        Ok(Self { rank })
    }

    #[must_use]
    /// Frame the ranking, zero-padding to the fixed size.
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(QUEUE_RANKING_PAYLOAD_LEN);
        payload.extend_from_slice(&self.rank.to_le_bytes());
        payload.extend_from_slice(&[0u8; QUEUE_RANKING_PAYLOAD_LEN - 2]);
        Packet::new(
            PeerOpcode::QueueRanking.protocol(),
            PeerOpcode::QueueRanking.as_u8(),
            payload,
        )
    }
}

/// Why a slot or queue packet could not be read.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SlotDecodeError {
    #[error("slot-queue packet payload wrong size: expected {expected} bytes, had {actual}")]
    /// The body was not the fixed size this packet's shape requires —
    /// including the empty-body packets, where anything at all is wrong.
    WrongPayloadLen {
        /// The size this packet's shape requires.
        expected: usize,
        /// The size that arrived.
        actual: usize,
    },
}
