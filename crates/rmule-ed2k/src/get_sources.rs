//! `OP_GETSOURCES` (0x19) and its obfuscated form (0x23): asking a server
//! which peers hold a file.
//!
//! Three body widths ride the same opcode — hash only, hash plus 32-bit size,
//! and hash plus the 64-bit escape a file past 4 GiB needs — so the width a
//! server accepts is a capability fact, not a guess.

use rmule_primitives::{FileHash, Packet, PacketProtocol, SourceLookupTarget};

use crate::{Ed2kError, Opcode, Result};

const LEGACY_LEN: usize = FileHash::BYTE_LEN;
const NORMAL_LEN: usize = FileHash::BYTE_LEN + 4;
const LARGE_LEN: usize = FileHash::BYTE_LEN + 4 + 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// `OP_GETSOURCES` in the three forms a client may send, distinguished by
/// body length alone.
///
/// Which form is legal depends on what the server advertised: the size-bearing
/// forms exist because a server cannot answer for a large file without knowing
/// its size.
pub enum GetSourcesRequest {
    /// Hash only — the oldest form, no size, so large files are unanswerable.
    Legacy {
        /// The file being looked up.
        file_hash: FileHash,
    },
    /// Hash plus a 4-byte size.
    Normal {
        /// The file being looked up, hash and size.
        target: SourceLookupTarget,
    },
    /// Hash plus a zero 4-byte size and an 8-byte size — the large-file form.
    Large {
        /// The file being looked up, hash and size.
        target: SourceLookupTarget,
    },
}

impl GetSourcesRequest {
    /// Decode this packet's payload.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte, the opcode, or the
    /// body layout is not this packet's.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let opcode = Opcode::GetSources.as_u8();
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        // `OP_GETSOURCES` (`0x19`) and `OP_GETSOURCES_OBFU` (`0x23`) carry a
        // byte-identical body; the obfu opcode only asks the server to answer
        // with the obfuscation-aware `0x44` reply (ADR-0046). Accept both.
        if packet.opcode() != opcode && packet.opcode() != Opcode::GetSourcesObfu.as_u8() {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_GETSOURCES",
            });
        }
        let payload = packet.payload();
        let mut hash_bytes = [0u8; FileHash::BYTE_LEN];
        match payload.len() {
            LEGACY_LEN => {
                hash_bytes.copy_from_slice(payload);
                Ok(Self::Legacy {
                    file_hash: FileHash::from_bytes(hash_bytes),
                })
            }
            NORMAL_LEN => {
                hash_bytes.copy_from_slice(&payload[..FileHash::BYTE_LEN]);
                let size = u32::from_le_bytes(
                    payload[FileHash::BYTE_LEN..NORMAL_LEN]
                        .try_into()
                        .expect("validated normal slice"),
                );
                Ok(Self::Normal {
                    target: SourceLookupTarget::new(
                        FileHash::from_bytes(hash_bytes),
                        u64::from(size),
                    ),
                })
            }
            LARGE_LEN => {
                hash_bytes.copy_from_slice(&payload[..FileHash::BYTE_LEN]);
                let sentinel: [u8; 4] = payload[FileHash::BYTE_LEN..FileHash::BYTE_LEN + 4]
                    .try_into()
                    .expect("validated large sentinel slice");
                if sentinel != [0; 4] {
                    return Err(Ed2kError::InvalidPayload {
                        opcode,
                        reason: "OP_GETSOURCES large form requires zero u32 sentinel before u64 size",
                    });
                }
                let size = u64::from_le_bytes(
                    payload[FileHash::BYTE_LEN + 4..LARGE_LEN]
                        .try_into()
                        .expect("validated large size slice"),
                );
                Ok(Self::Large {
                    target: SourceLookupTarget::new(FileHash::from_bytes(hash_bytes), size),
                })
            }
            _ => Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_GETSOURCES payload must be 16, 20, or 28 bytes",
            }),
        }
    }

    /// Encode as plain `OP_GETSOURCES` (`0x19`).
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        self.encode_with_opcode(Opcode::GetSources.as_u8())
    }

    /// Encode as `OP_GETSOURCES_OBFU` (`0x23`) — the same body under the
    /// obfuscation-aware opcode, emitted when the connected server advertises
    /// `SRV_TCPFLG_TCPOBFUSCATION` and rmule's crypt stance supports it, so the
    /// server answers with `OP_FOUNDSOURCES_OBFU` (`0x44`) instead of `0x42`
    /// (aMule `CDownloadQueue::SendLocalSrcRequest`, ADR-0046).
    #[must_use]
    pub fn encode_obfu_packet(&self) -> Packet {
        self.encode_with_opcode(Opcode::GetSourcesObfu.as_u8())
    }

    fn encode_with_opcode(&self, opcode: u8) -> Packet {
        let payload = match self {
            Self::Legacy { file_hash } => file_hash.as_bytes().to_vec(),
            Self::Normal { target } => {
                let mut bytes = Vec::with_capacity(NORMAL_LEN);
                bytes.extend_from_slice(target.file_hash().as_bytes());
                let size = u32::try_from(target.file_size())
                    .expect("GetSourcesRequest::Normal requires file_size <= u32::MAX");
                bytes.extend_from_slice(&size.to_le_bytes());
                bytes
            }
            Self::Large { target } => {
                let mut bytes = Vec::with_capacity(LARGE_LEN);
                bytes.extend_from_slice(target.file_hash().as_bytes());
                bytes.extend_from_slice(&[0u8; 4]);
                bytes.extend_from_slice(&target.file_size().to_le_bytes());
                bytes
            }
        };
        Packet::new(PacketProtocol::Edonkey, opcode, payload)
    }
}
