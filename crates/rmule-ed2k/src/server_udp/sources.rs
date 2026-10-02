//! Global source discovery over server UDP (ADR-0051):
//! `OP_GLOBGETSOURCES` (0x9A) and its `OP_GLOBGETSOURCES2` (0x94) large-file
//! form on the way out, `OP_GLOBFOUNDSOURCES` (0x9B) — the same body as the
//! TCP `OP_FOUNDSOURCES`, packed several files to a datagram — on the way
//! back.

use rmule_primitives::{
    FileHash, Packet, PacketProtocol, PeerSource, SourceListTail, SourceLookupTarget,
};

use crate::source_record;
use crate::{Ed2kError, Opcode, Result};

/// `OP_GLOBGETSOURCES` (0x9A): a UDP source query carrying one or more file
/// hashes (aMule packs up to `MAX_FILES_PER_UDP_PACKET` = 31 per datagram).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobGetSources {
    hashes: Vec<FileHash>,
}

impl GlobGetSources {
    /// A query for these files. The caller does the packing — one datagram
    /// holds at most 31 hashes.
    #[must_use]
    pub fn new(hashes: Vec<FileHash>) -> Self {
        Self { hashes }
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(self.hashes.len() * FileHash::BYTE_LEN);
        for hash in &self.hashes {
            payload.extend_from_slice(hash.as_bytes());
        }
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::GlobGetSources.as_u8(),
            payload,
        )
    }
}

/// `OP_GLOBGETSOURCES2` (0x94): the size-extended source query a server
/// advertising `SRV_UDPFLG_EXT_GETSOURCES2` accepts (ADR-0052 — the `0x97`
/// reply's flags gate the upgrade; legacy [`GlobGetSources`] stays the
/// fallback). Each entry is the 16-byte hash **plus the file size** (aMule
/// `DownloadQueue.cpp` `SendNextUDPPacket`): `[size u32 LE]` for a file
/// within `u32`, or the large-file form `[0 u32][size u64 LE]` — the zero
/// `u32` is the escape marker. The size unlocks source discovery for files
/// past 4 GiB, which the bare-hash `0x9A` cannot request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobGetSources2 {
    targets: Vec<SourceLookupTarget>,
}

impl GlobGetSources2 {
    /// A query for these files, each with its size, so large files resolve.
    #[must_use]
    pub fn new(targets: Vec<SourceLookupTarget>) -> Self {
        Self { targets }
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::new();
        for target in &self.targets {
            payload.extend_from_slice(target.file_hash().as_bytes());
            match u32::try_from(target.file_size()) {
                Ok(size) => payload.extend_from_slice(&size.to_le_bytes()),
                Err(_) => {
                    payload.extend_from_slice(&0_u32.to_le_bytes());
                    payload.extend_from_slice(&target.file_size().to_le_bytes());
                }
            }
        }
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::GlobGetSources2.as_u8(),
            payload,
        )
    }
}

/// `OP_GLOBFOUNDSOURCES` (0x9B): one file's sources, server → client over UDP.
/// Body is identical to the TCP `OP_FOUNDSOURCES`: `[hash 16][count u8]` then
/// `count × ([ip u32 LE][port u16 LE])` — a **Sentinel Source** record with its
/// sixteen address bytes inline after its port (ADR-0085) — but the UDP frame
/// has no length prefix. A
/// datagram may carry several of these packets; the caller advances by each
/// [`Self::decode_udp`]'s consumed length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobFoundSources {
    file_hash: FileHash,
    sources: Vec<PeerSource>,
    tail: SourceListTail,
}

impl GlobFoundSources {
    /// The file these sources are for.
    #[must_use]
    pub fn file_hash(&self) -> FileHash {
        self.file_hash
    }

    /// The sources this datagram carried. A **Sentinel Source** whose inline
    /// address is not a usable identity is absent, and so is every record from
    /// the first sentinel on in a malformed list (ADR-0085).
    #[must_use]
    pub fn sources(&self) -> &[PeerSource] {
        &self.sources
    }

    /// How this packet's records measured (ADR-0085).
    #[must_use]
    pub fn tail(&self) -> SourceListTail {
        self.tail
    }

    /// Decode the first `OP_GLOBFOUNDSOURCES` packet from a UDP datagram, returning
    /// it and the byte count it consumed (a server may pack several, one per file;
    /// the caller advances by the returned length and decodes the next). The UDP
    /// frame is `[protocol 0xE3][opcode 0x9B]` then the body `[hash 16][count u8]`
    /// then `count × ([ip u32 LE][port u16 LE])`, a sentinel's address inline — no
    /// length prefix (the body's count delimits it). A list cut short once a
    /// sentinel was met ends the datagram. Cite-and-rewrite only (ADR-0004).
    pub fn decode_udp(bytes: &[u8]) -> Result<(Self, usize)> {
        let opcode = Opcode::GlobFoundSources.as_u8();
        let [protocol, op, body @ ..] = bytes else {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_GLOBFOUNDSOURCES datagram missing header",
            });
        };
        if *protocol != PacketProtocol::Edonkey.as_byte() {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if *op != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_GLOBFOUNDSOURCES",
            });
        }
        if body.len() < FileHash::BYTE_LEN + 1 {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_GLOBFOUNDSOURCES payload missing file hash or count byte",
            });
        }
        let mut hash_bytes = [0u8; FileHash::BYTE_LEN];
        hash_bytes.copy_from_slice(&body[..FileHash::BYTE_LEN]);
        let count = usize::from(body[FileHash::BYTE_LEN]);
        let header_len = FileHash::BYTE_LEN + 1;
        let records = source_record::read_prefix(&body[header_len..], count).ok_or(
            Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_GLOBFOUNDSOURCES declared count exceeds the datagram",
            },
        )?;
        Ok((
            Self {
                file_hash: FileHash::from_bytes(hash_bytes),
                sources: records.records.iter().filter_map(|r| r.source).collect(),
                tail: records.tail,
            },
            2 + header_len + records.consumed,
        ))
    }
}

#[cfg(test)]
/// One `OP_GLOBFOUNDSOURCES` UDP datagram (`[0xE3][0x9B][hash][count][sources]`)
/// answering `file_hash` with a single High-ID source. Shared with the
/// search tests, where it stands in for a datagram that is not a search reply.
pub(super) fn glob_found_sources_datagram(file_hash: u8) -> Vec<u8> {
    let mut out = vec![
        PacketProtocol::Edonkey.as_byte(),
        Opcode::GlobFoundSources.as_u8(),
    ];
    out.extend_from_slice(&[file_hash; FileHash::BYTE_LEN]);
    out.push(1); // count
    out.extend_from_slice(&0x0100_007F_u32.to_le_bytes()); // High-ID (ip-as-u32)
    out.extend_from_slice(&4662u16.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_get_sources_encodes_a_no_length_udp_datagram() {
        let datagram = GlobGetSources::new(vec![
            FileHash::from_bytes([0x11; FileHash::BYTE_LEN]),
            FileHash::from_bytes([0x22; FileHash::BYTE_LEN]),
        ])
        .encode_packet()
        .encode_udp();

        let mut expected = vec![0xE3, Opcode::GlobGetSources.as_u8()];
        expected.extend_from_slice(&[0x11; FileHash::BYTE_LEN]);
        expected.extend_from_slice(&[0x22; FileHash::BYTE_LEN]);
        assert_eq!(datagram, expected);
    }

    #[test]
    fn glob_get_sources2_encodes_sizes_with_the_large_file_escape() {
        let datagram = GlobGetSources2::new(vec![
            SourceLookupTarget::new(FileHash::from_bytes([0x11; FileHash::BYTE_LEN]), 4096),
            // 5 GiB: past u32 — the large-file form [0 u32][size u64].
            SourceLookupTarget::new(
                FileHash::from_bytes([0x22; FileHash::BYTE_LEN]),
                5 * 1024 * 1024 * 1024,
            ),
        ])
        .encode_packet()
        .encode_udp();

        let mut expected = vec![0xE3, 0x94];
        expected.extend_from_slice(&[0x11; FileHash::BYTE_LEN]);
        expected.extend_from_slice(&4096_u32.to_le_bytes());
        expected.extend_from_slice(&[0x22; FileHash::BYTE_LEN]);
        expected.extend_from_slice(&0_u32.to_le_bytes());
        expected.extend_from_slice(&(5_u64 * 1024 * 1024 * 1024).to_le_bytes());
        assert_eq!(datagram, expected);

        // The u32 boundary itself still fits the small form.
        let boundary = GlobGetSources2::new(vec![SourceLookupTarget::new(
            FileHash::from_bytes([0x33; FileHash::BYTE_LEN]),
            u64::from(u32::MAX),
        )])
        .encode_packet()
        .encode_udp();
        assert_eq!(boundary.len(), 2 + FileHash::BYTE_LEN + 4);
        assert_eq!(&boundary[2 + FileHash::BYTE_LEN..], &u32::MAX.to_le_bytes());
    }

    #[test]
    fn glob_found_sources_decodes_one_files_high_id_source() {
        let datagram = glob_found_sources_datagram(0xAB);
        let consumed_expected = datagram.len();
        let (decoded, consumed) = GlobFoundSources::decode_udp(&datagram).expect("decodes");
        assert_eq!(consumed, consumed_expected);
        assert_eq!(
            decoded.file_hash(),
            FileHash::from_bytes([0xAB; FileHash::BYTE_LEN])
        );
        assert_eq!(decoded.sources().len(), 1);
        assert_eq!(decoded.sources()[0].wire_id(), 0x0100_007F);
        assert!(
            decoded.sources()[0].as_peer_endpoint().is_some(),
            "a High-ID global source is dialable"
        );
    }

    #[test]
    fn glob_found_sources_advances_through_a_multi_packet_datagram() {
        // A server may pack several files' sources in one datagram (no length
        // prefix); decoding the first by its consumed length must land on the second.
        let mut datagram = glob_found_sources_datagram(0xAA);
        datagram.extend_from_slice(&glob_found_sources_datagram(0xBB));

        let (first, consumed) = GlobFoundSources::decode_udp(&datagram).expect("first");
        assert_eq!(
            first.file_hash(),
            FileHash::from_bytes([0xAA; FileHash::BYTE_LEN])
        );
        let (second, _) = GlobFoundSources::decode_udp(&datagram[consumed..]).expect("second");
        assert_eq!(
            second.file_hash(),
            FileHash::from_bytes([0xBB; FileHash::BYTE_LEN])
        );
    }
}
