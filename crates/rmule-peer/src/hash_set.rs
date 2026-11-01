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

use rmule_primitives::{FileHash, Packet, PartHash, PartHashList, WireReader};

use crate::error::WireFault;

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
    pub part_hashes: PartHashList,
}

impl HashSetRequest {
    /// Read the request.
    pub fn decode_packet(packet: &Packet) -> Result<Self, WireFault> {
        let payload = packet.payload();
        if payload.len() != FileHash::BYTE_LEN {
            return Err(WireFault::Truncated {
                needed: FileHash::BYTE_LEN,
                actual: payload.len(),
            });
        }
        Ok(Self {
            file_hash: WireReader::new(payload).read_file_hash("file hash")?,
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
    pub fn decode_packet(packet: &Packet) -> Result<Self, WireFault> {
        let payload = packet.payload();
        let header_len = FileHash::BYTE_LEN + COUNT_LEN;
        if payload.len() < header_len {
            return Err(WireFault::Truncated {
                needed: header_len,
                actual: payload.len(),
            });
        }
        let mut reader = WireReader::new(payload);
        let file_hash = reader.read_file_hash("file hash")?;
        let declared_count = usize::from(reader.read_u16_le("part hash count")?);
        let body = reader.remaining_bytes();
        let expected_body =
            declared_count
                .checked_mul(PartHash::BYTE_LEN)
                .ok_or(WireFault::CountOverflow {
                    count: declared_count,
                })?;
        if body.len() != expected_body {
            return Err(WireFault::LengthMismatch {
                declared: declared_count,
                actual: body.len(),
            });
        }
        let mut part_hashes = Vec::with_capacity(declared_count);
        for chunk in body.chunks_exact(PartHash::BYTE_LEN) {
            let mut buf = [0u8; PartHash::BYTE_LEN];
            buf.copy_from_slice(chunk);
            part_hashes.push(PartHash::from_bytes(buf));
        }
        let part_hashes = PartHashList::new(part_hashes).map_err(|_| WireFault::CountOverflow {
            count: declared_count,
        })?;
        Ok(Self {
            file_hash,
            part_hashes,
        })
    }

    #[must_use]
    /// Frame the answer.
    pub fn encode_packet(&self) -> Packet {
        let hashes = self.part_hashes.hashes();
        let mut payload =
            Vec::with_capacity(FileHash::BYTE_LEN + COUNT_LEN + hashes.len() * PartHash::BYTE_LEN);
        payload.extend_from_slice(self.file_hash.as_bytes());
        payload.extend_from_slice(&self.part_hashes.count().to_le_bytes());
        for h in hashes {
            payload.extend_from_slice(h.as_bytes());
        }
        Packet::new(
            PeerOpcode::HashSetAnswer.protocol(),
            PeerOpcode::HashSetAnswer.as_u8(),
            payload,
        )
    }
}
