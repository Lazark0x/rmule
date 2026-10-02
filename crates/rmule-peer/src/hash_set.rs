//! Hash-set packet pair.
//!
//! Opcodes per `src/include/protocol/ed2k/Client2Client/TCP.h` at amule
//! `377ec8d9`:
//!   OP_HASHSETREQUEST = 0x51 — client requests the part-hash set for a file
//!   OP_HASHSETANSWER  = 0x52 — peer answers with the part-hash array
//!
//! TCP.h comment for OP_HASHSETANSWER is `<count 2><HASH[count] 16*count>`
//! but the actual handler `DownloadClient.cpp::ProcessHashSet` opens with
//! `md4cmp(packet, m_reqfile->GetFileHash().GetHash())` — the leading 16
//! bytes are the file hash. Real wire is `<HASH 16><u16 count><PartHash[count]>`.
//!
//! A zero part-count is well-formed, not malformed: some real peers answer
//! with `<HASH 16><u16 0>` (no hash array) for a single-chunk file, whose only
//! part hash is the whole-file MD4 itself. aMule 2.3.3 may instead not answer a
//! hashset request for a sub-part shared file at all, so the requester state
//! machine must not require `OP_HASHSETANSWER` before requesting a slot when
//! the whole-file hash is already sufficient. Per ADR-0018 an empty answer is
//! still preserved as an empty `part_hashes`.

use rmule_primitives::{FileHash, Packet, PartHash};
use thiserror::Error;

use crate::opcode::PeerOpcode;

const COUNT_LEN: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
/// `OP_HASHSETREQUEST` (`0x51`) — send me this file's part hashes.
pub struct HashSetRequest {
    /// The file whose hashes are wanted.
    pub file_hash: FileHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// `OP_HASHSETANSWER` (`0x52`) — the part hashes themselves.
pub struct HashSetAnswer {
    /// The file they belong to.
    pub file_hash: FileHash,
    /// One hash per part. Position is the only thing binding a hash to its part, so the order is the contract.
    pub part_hashes: Vec<PartHash>,
}

impl HashSetRequest {
    /// Read the request.
    pub fn decode_packet(packet: &Packet) -> Result<Self, HashSetDecodeError> {
        let payload = packet.payload();
        if payload.len() != FileHash::BYTE_LEN {
            return Err(HashSetDecodeError::Truncated {
                needed: FileHash::BYTE_LEN,
                actual: payload.len(),
            });
        }
        Ok(Self {
            file_hash: read_file_hash(payload),
        })
    }

    #[must_use]
    /// Frame the request.
    pub fn encode_packet(&self) -> Packet {
        Packet::new(
            PeerOpcode::HashSetRequest.protocol(),
            PeerOpcode::HashSetRequest.as_u8(),
            self.file_hash.as_bytes().to_vec(),
        )
    }
}

impl HashSetAnswer {
    /// Read the answer, checking the declared count against the bytes that follow it.
    pub fn decode_packet(packet: &Packet) -> Result<Self, HashSetDecodeError> {
        let payload = packet.payload();
        let header_len = FileHash::BYTE_LEN + COUNT_LEN;
        if payload.len() < header_len {
            return Err(HashSetDecodeError::Truncated {
                needed: header_len,
                actual: payload.len(),
            });
        }
        let file_hash = read_file_hash(&payload[..FileHash::BYTE_LEN]);
        let declared_count =
            u16::from_le_bytes([payload[FileHash::BYTE_LEN], payload[FileHash::BYTE_LEN + 1]])
                as usize;
        let body = &payload[header_len..];
        let expected_body = declared_count.checked_mul(PartHash::BYTE_LEN).ok_or(
            HashSetDecodeError::CountOverflow {
                count: declared_count,
            },
        )?;
        if body.len() != expected_body {
            return Err(HashSetDecodeError::CountPayloadMismatch {
                declared: declared_count,
                got_bytes: body.len(),
            });
        }
        let mut part_hashes = Vec::with_capacity(declared_count);
        for chunk in body.chunks_exact(PartHash::BYTE_LEN) {
            let mut buf = [0u8; PartHash::BYTE_LEN];
            buf.copy_from_slice(chunk);
            part_hashes.push(PartHash::from_bytes(buf));
        }
        Ok(Self {
            file_hash,
            part_hashes,
        })
    }

    #[must_use]
    /// Frame the answer.
    pub fn encode_packet(&self) -> Packet {
        let count = u16::try_from(self.part_hashes.len())
            .expect("part_hashes count exceeds u16 — wire encoding does not support that");
        let mut payload = Vec::with_capacity(
            FileHash::BYTE_LEN + COUNT_LEN + self.part_hashes.len() * PartHash::BYTE_LEN,
        );
        payload.extend_from_slice(self.file_hash.as_bytes());
        payload.extend_from_slice(&count.to_le_bytes());
        for h in &self.part_hashes {
            payload.extend_from_slice(h.as_bytes());
        }
        Packet::new(
            PeerOpcode::HashSetAnswer.protocol(),
            PeerOpcode::HashSetAnswer.as_u8(),
            payload,
        )
    }
}

fn read_file_hash(bytes: &[u8]) -> FileHash {
    let mut buf = [0u8; FileHash::BYTE_LEN];
    buf.copy_from_slice(&bytes[..FileHash::BYTE_LEN]);
    FileHash::from_bytes(buf)
}

/// Why a hash-set packet could not be read.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HashSetDecodeError {
    #[error("hash-set packet payload truncated: needed {needed} bytes, had {actual}")]
    /// The payload ended before the header or the declared hashes did.
    Truncated {
        /// Bytes the declared count requires.
        needed: usize,
        /// Bytes present.
        actual: usize,
    },

    #[error("hash-set answer declared {declared} hashes but body has {got_bytes} bytes")]
    /// The declared hash count and the bytes after it disagree.
    CountPayloadMismatch {
        /// Hashes the header declared.
        declared: usize,
        /// Bytes that actually followed it.
        got_bytes: usize,
    },

    #[error("hash-set answer declared part count {count} overflows usize multiplication")]
    /// The declared count cannot be held by this platform's `usize`,
    /// rejected before it sizes any allocation.
    CountOverflow {
        /// The count the header declared.
        count: usize,
    },
}
