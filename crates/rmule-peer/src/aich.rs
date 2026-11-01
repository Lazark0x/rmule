//! AICH client-to-client packets (ADR-0038).
//!
//! `OP_AICHREQUEST` (`0x9B`) / `OP_AICHANSWER` (`0x9C`) under `OP_EMULEPROT`,
//! per `src/include/protocol/ed2k/Client2Client/TCP.h` @ aMule `377ec8d9`. The
//! wire skeleton is pinned from `DownloadClient.cpp` (`SendAICHRequest` /
//! `ProcessAICHAnswer` / `ProcessAICHRequest`):
//!
//! - request `0x9B` = `[file_hash 16][part u16][master_hash 20]`
//! - answer  `0x9C` = `[file_hash 16][part u16][master_hash 20][recovery_data…]`
//!
//! `recovery_data` is the serialized AICH tree branch; it is carried opaquely
//! here and parsed/built by `rmule_primitives::AichHashSet`. The file-hash
//! discovery pair (`0x9D`/`0x9E`) lands with the trusted-set work.

use rmule_primitives::{AichRootHash, FileHash, Packet, WireReader};

use crate::error::WireFault;

use crate::opcode::PeerOpcode;

/// Fixed header shared by both packets: file hash + part number + master hash.
pub(crate) const HEADER_LEN: usize = FileHash::BYTE_LEN + 2 + AichRootHash::BYTE_LEN;

/// The fixed header both packets open with.
fn read_header(reader: &mut WireReader<'_>) -> Result<(FileHash, u16, AichRootHash), WireFault> {
    Ok((
        reader.read_file_hash("file hash")?,
        reader.read_u16_le("part")?,
        read_root(reader)?,
    ))
}

fn read_root(reader: &mut WireReader<'_>) -> Result<AichRootHash, WireFault> {
    Ok(AichRootHash::from_bytes(reader.read_array("master hash")?))
}

/// `OP_AICHREQUEST` — ask a peer for the AICH recovery data of one part,
/// quoting the master hash we trust so the peer can confirm the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AichRequest {
    /// The file being recovered.
    pub file_hash: FileHash,
    /// The part the branch is wanted for.
    pub part: u16,
    /// The master hash we trust, quoted so the peer answers against the same tree.
    pub root: AichRootHash,
}

impl AichRequest {
    /// Read a request, which is a fixed size.
    pub fn decode_packet(packet: &Packet) -> Result<Self, WireFault> {
        let payload = packet.payload();
        if payload.len() != HEADER_LEN {
            return Err(WireFault::WrongSize {
                expected: HEADER_LEN,
                actual: payload.len(),
            });
        }
        let (file_hash, part, root) = read_header(&mut WireReader::new(payload))?;
        Ok(Self {
            file_hash,
            part,
            root,
        })
    }

    #[must_use]
    /// Frame the request.
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(HEADER_LEN);
        payload.extend_from_slice(self.file_hash.as_bytes());
        payload.extend_from_slice(&self.part.to_le_bytes());
        payload.extend_from_slice(self.root.as_bytes());
        Packet::new(
            PeerOpcode::AichRequest.protocol(),
            PeerOpcode::AichRequest.as_u8(),
            payload,
        )
    }
}

/// `OP_AICHANSWER` — a peer's AICH recovery data for one part, echoing the
/// master hash. `recovery_data` is the opaque tree branch consumed by
/// `AichHashSet::verify_part`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AichAnswer {
    /// The file being recovered.
    pub file_hash: FileHash,
    /// The part this branch covers.
    pub part: u16,
    /// The master hash the peer echoes back.
    pub root: AichRootHash,
    /// The branch itself, opaque here — verifying it is the caller's, against a root it already trusts.
    pub recovery_data: Vec<u8>,
}

impl AichAnswer {
    /// Read an answer; anything past the fixed header is the branch.
    pub fn decode_packet(packet: &Packet) -> Result<Self, WireFault> {
        let payload = packet.payload();
        if payload.len() < HEADER_LEN {
            return Err(WireFault::Truncated {
                needed: HEADER_LEN,
                actual: payload.len(),
            });
        }
        let mut reader = WireReader::new(payload);
        let (file_hash, part, root) = read_header(&mut reader)?;
        Ok(Self {
            file_hash,
            part,
            root,
            recovery_data: reader.remaining_bytes().to_vec(),
        })
    }

    #[must_use]
    /// Frame the answer.
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(HEADER_LEN + self.recovery_data.len());
        payload.extend_from_slice(self.file_hash.as_bytes());
        payload.extend_from_slice(&self.part.to_le_bytes());
        payload.extend_from_slice(self.root.as_bytes());
        payload.extend_from_slice(&self.recovery_data);
        Packet::new(
            PeerOpcode::AichAnswer.protocol(),
            PeerOpcode::AichAnswer.as_u8(),
            payload,
        )
    }
}

/// `OP_AICHANSWER` carrying the file hash alone — the peer has no recovery data
/// for the ask (aMule `DownloadClient.cpp:1691-1695`; ADR-0038) — or less, which
/// the asker reads as the same failed ask (`DownloadClient.cpp:1611-1614`).
/// Nothing else about the ask is named: a link has one AICH ask out per file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AichRefused {
    /// The file the ask was about; `None` for an answer too short to say.
    pub file_hash: Option<FileHash>,
}

impl AichRefused {
    /// Whether `packet`'s payload is this form of `OP_AICHANSWER`.
    #[must_use]
    pub fn is_form_of(packet: &Packet) -> bool {
        packet.payload().len() <= FileHash::BYTE_LEN
    }

    /// Read the refusal; its payload names the file or nothing.
    #[must_use]
    pub fn decode_packet(packet: &Packet) -> Self {
        Self {
            file_hash: WireReader::new(packet.payload())
                .read_file_hash("file hash")
                .ok(),
        }
    }

    #[must_use]
    /// Frame the refusal.
    pub fn encode_packet(&self) -> Packet {
        Packet::new(
            PeerOpcode::AichAnswer.protocol(),
            PeerOpcode::AichAnswer.as_u8(),
            self.file_hash
                .map_or_else(Vec::new, |file_hash| file_hash.as_bytes().to_vec()),
        )
    }
}

/// `OP_AICHFILEHASHREQ` — ask a peer for a file's AICH master hash, to collect
/// trusted-set root proposals when the link carried no `h=` (ADR-0038). Payload
/// is just `[file_hash 16]` (aMule `SendFileRequest`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AichFileHashReq {
    /// The file whose master hash is wanted.
    pub file_hash: FileHash,
}

impl AichFileHashReq {
    /// Read the request.
    pub fn decode_packet(packet: &Packet) -> Result<Self, WireFault> {
        let payload = packet.payload();
        // aMule reads the hash and looks no further
        // (`ClientTCPSocket.cpp:1672-1686`).
        if payload.len() < FileHash::BYTE_LEN {
            return Err(WireFault::WrongSize {
                expected: FileHash::BYTE_LEN,
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
            PeerOpcode::AichFileHashReq.protocol(),
            PeerOpcode::AichFileHashReq.as_u8(),
            self.file_hash.as_bytes().to_vec(),
        )
    }
}

/// `OP_AICHFILEHASHANS` — a peer's AICH master hash for a file (ADR-0038). The
/// **standalone** packet's payload is `[file_hash 16][master_hash 20]`: aMule's
/// non-bundled reader (`ClientTCPSocket.cpp` `OP_AICHFILEHASHANS` →
/// `ProcessAICHFileHash` with a null file) reads the file hash *before* the
/// root, and its standalone sender writes both (`data_out.WriteHash(hash);
/// GetMasterHash().Write()`). A root-only frame under-runs that parse and gets
/// the source dropped. The *bundled* form inside
/// `OP_MULTIPACKETANSWER` omits the hash — that path is
/// [`crate::multipacket::AnswerItem::AichRoot`], not this packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AichFileHashAns {
    /// The file the root belongs to. The standalone form carries it; the bundled form does not.
    pub file_hash: FileHash,
    /// The peer's master hash for that file.
    pub root: AichRootHash,
}

impl AichFileHashAns {
    const PAYLOAD_LEN: usize = FileHash::BYTE_LEN + AichRootHash::BYTE_LEN;

    /// Read the standalone answer's two hashes; aMule reads no more
    /// (`DownloadClient.cpp:1698-1706`).
    pub fn decode_packet(packet: &Packet) -> Result<Self, WireFault> {
        let payload = packet.payload();
        if payload.len() < Self::PAYLOAD_LEN {
            return Err(WireFault::WrongSize {
                expected: Self::PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        let mut reader = WireReader::new(payload);
        Ok(Self {
            file_hash: reader.read_file_hash("file hash")?,
            root: read_root(&mut reader)?,
        })
    }

    #[must_use]
    /// Frame the standalone answer.
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(Self::PAYLOAD_LEN);
        payload.extend_from_slice(self.file_hash.as_bytes());
        payload.extend_from_slice(self.root.as_bytes());
        Packet::new(
            PeerOpcode::AichFileHashAns.protocol(),
            PeerOpcode::AichFileHashAns.as_u8(),
            payload,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_hash() -> FileHash {
        FileHash::from_bytes([0x11; FileHash::BYTE_LEN])
    }

    fn root() -> AichRootHash {
        AichRootHash::from_bytes([0x22; AichRootHash::BYTE_LEN])
    }

    #[test]
    fn aich_request_round_trips_through_the_wire() {
        let req = AichRequest {
            file_hash: file_hash(),
            part: 7,
            root: root(),
        };
        let packet = req.encode_packet();
        // [file_hash 16][part u16][master 20] = 38 bytes, under OP_EMULEPROT.
        assert_eq!(packet.payload().len(), HEADER_LEN);
        assert_eq!(AichRequest::decode_packet(&packet).unwrap(), req);
    }

    #[test]
    fn aich_answer_round_trips_with_opaque_recovery_data() {
        let answer = AichAnswer {
            file_hash: file_hash(),
            part: 3,
            root: root(),
            recovery_data: vec![0xAB; 70], // an opaque branch blob
        };
        let packet = answer.encode_packet();
        let decoded = AichAnswer::decode_packet(&packet).unwrap();
        assert_eq!(decoded, answer);
        assert_eq!(decoded.recovery_data.len(), 70);
    }

    #[test]
    fn aich_answer_with_no_recovery_data_decodes_to_an_empty_blob() {
        // A header-only answer (a peer with nothing to recover) is well-formed;
        // the recovery data is simply empty.
        let answer = AichAnswer {
            file_hash: file_hash(),
            part: 0,
            root: root(),
            recovery_data: Vec::new(),
        };
        let decoded = AichAnswer::decode_packet(&answer.encode_packet()).unwrap();
        assert_eq!(decoded, answer);
    }

    #[test]
    fn file_hash_answer_is_the_file_hash_then_the_root_standalone() {
        // The standalone OP_AICHFILEHASHANS wire form leads with the 16-byte
        // file hash, then the 20-byte root: aMule's non-bundled
        // reader consumes the hash first, so a root-only frame drops the source.
        let ans = AichFileHashAns {
            file_hash: file_hash(),
            root: root(),
        };
        let packet = ans.encode_packet();
        let payload = packet.payload();
        assert_eq!(payload.len(), FileHash::BYTE_LEN + AichRootHash::BYTE_LEN);
        assert_eq!(&payload[..FileHash::BYTE_LEN], file_hash().as_bytes());
        assert_eq!(&payload[FileHash::BYTE_LEN..], root().as_bytes());
        assert_eq!(AichFileHashAns::decode_packet(&packet).unwrap(), ans);
    }

    #[test]
    fn truncated_answer_header_is_rejected() {
        let packet = Packet::new(
            PeerOpcode::AichAnswer.protocol(),
            PeerOpcode::AichAnswer.as_u8(),
            vec![0u8; HEADER_LEN - 1],
        );
        assert!(matches!(
            AichAnswer::decode_packet(&packet),
            Err(WireFault::Truncated { .. })
        ));
    }
}
