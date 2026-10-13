//! Part-transfer packets — both wire variants.
//!
//! Opcodes per `src/include/protocol/ed2k/Client2Client/TCP.h` at amule
//! `377ec8d9`:
//!
//! ```text
//! OP_REQUESTPARTS     = 0x47 (OP_EDONKEYPROT) <HASH 16><start[3] u32x3><end[3] u32x3>
//! OP_REQUESTPARTS_I64 = 0xA3 (OP_EMULEPROT)   <HASH 16><start[3] u64x3><end[3] u64x3>
//! OP_SENDINGPART      = 0x46 (OP_EDONKEYPROT) <HASH 16><start u32><end u32><data>
//! OP_SENDINGPART_I64  = 0xA2 (OP_EMULEPROT)   <HASH 16><start u64><end u64><data>
//! ```
//!
//! `RequestParts` always carries exactly 3 (start, end) pairs; unused
//! slots are zero-padded. aMule's sender (`DownloadClient.cpp::SendBlockRequests`)
//! and receiver (`UploadClient.cpp::ProcessRequestPartsPacket`) both
//! treat 3 as a hard wire constant.
//!
//! Range layout in the payload is [start0 start1 start2 end0 end1 end2]
//! — all starts first, then all ends — per the TCP.h schema and
//! confirmed by aMule's two separate for-loops in the sender.

use rmule_primitives::{FileHash, Packet, WireReader, WireTruncated};
use thiserror::Error;

use crate::opcode::PeerOpcode;

const RANGE_COUNT: usize = 3;

/// Maximum byte length of a single `OP_REQUESTPARTS` block, matching
/// eMule/aMule's `EMBLOCKSIZE`. A real peer grants the upload slot but
/// sends no `OP_SENDINGPART` for a request whose range spans more than
/// one block, so a downloader must split each part into `<= EMBLOCKSIZE`
/// blocks and request them in sequence. Confirmed live during the
/// core-peer CLI audit: a whole-part request stalled, a 184320-byte
/// block request streamed immediately.
pub const EMBLOCKSIZE: u64 = 184_320;

/// Selector for the part-transfer wire variant. aMule picks it per block, on
/// the block's own offsets: the `_I64` opcodes once an offset passes
/// `0xFFFFFFFF` (`UploadClient.cpp:307`, `:361`; `DownloadClient.cpp:745`),
/// never on `IsLargeFile`, so the blocks of a large file below 4 GiB still
/// ride the 32-bit opcodes. [`Self::for_file_size`] fed a block's highest
/// offset is that rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PartOffsetWidth {
    /// The original opcodes, offsets as `u32`.
    U32,
    /// The eMule-protocol `_I64` opcodes, offsets as `u64`.
    U64,
}

impl PartOffsetWidth {
    /// The narrowest width that can address every byte up to `file_size` —
    /// a block's highest offset, for aMule's per-block choice.
    #[must_use]
    pub const fn for_file_size(file_size: u64) -> Self {
        if file_size <= u32::MAX as u64 {
            Self::U32
        } else {
            Self::U64
        }
    }
}

/// Fixed-size triple of `(start, end)` part ranges. Unused slots are
/// the `(0, 0)` sentinel per aMule's send convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PartRanges {
    ranges: [(u64, u64); RANGE_COUNT],
}

impl PartRanges {
    /// Build the triple, rejecting any pair whose start is past its end.
    /// The `(0, 0)` padding sentinel passes, not being inverted.
    pub fn new(ranges: [(u64, u64); RANGE_COUNT]) -> Result<Self, PartRangesError> {
        for (start, end) in ranges {
            if start > end {
                return Err(PartRangesError::StartAfterEnd { start, end });
            }
        }
        Ok(Self { ranges })
    }

    /// The three pairs as stored, padding included — a caller wanting only
    /// the live ones filters the sentinel itself.
    #[must_use]
    pub fn as_array(&self) -> &[(u64, u64); RANGE_COUNT] {
        &self.ranges
    }
}

/// `OP_REQUESTPARTS` / `OP_REQUESTPARTS_I64` — ask a peer holding our slot
/// for up to three byte ranges of one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestParts {
    /// The file the ranges fall in.
    pub file_hash: FileHash,
    /// The three ranges, unused slots zero-padded.
    pub ranges: PartRanges,
}

/// `OP_SENDINGPART` / `OP_SENDINGPART_I64` — one uncompressed block of a
/// part, sized by its own range rather than by any declared length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendingPart {
    /// The file the bytes belong to.
    pub file_hash: FileHash,
    /// Absolute offset of the first byte.
    pub start: u64,
    /// Absolute offset one past the last byte; the payload must be exactly
    /// that long.
    pub end: u64,
    /// The block itself.
    pub data: Vec<u8>,
}

impl RequestParts {
    /// Read a request at whichever width its opcode names.
    pub fn decode_packet(packet: &Packet) -> Result<Self, PartsDecodeError> {
        let width = match PeerOpcode::try_from_u8(packet.opcode()) {
            Some(op @ PeerOpcode::RequestParts) if op.protocol() == packet.protocol() => {
                PartOffsetWidth::U32
            }
            Some(op @ PeerOpcode::RequestPartsI64) if op.protocol() == packet.protocol() => {
                PartOffsetWidth::U64
            }
            _ => unreachable!("dispatch routes only matching (protocol, opcode) here"),
        };
        let payload = packet.payload();
        let offset_size = match width {
            PartOffsetWidth::U32 => 4,
            PartOffsetWidth::U64 => 8,
        };
        let expected = FileHash::BYTE_LEN + RANGE_COUNT * 2 * offset_size;
        if payload.len() != expected {
            return Err(PartsDecodeError::WrongPayloadLen {
                expected,
                actual: payload.len(),
            });
        }
        let mut reader = WireReader::new(payload);
        let file_hash = reader.read_file_hash("file hash")?;
        let mut starts = [0u64; RANGE_COUNT];
        for slot in starts.iter_mut() {
            *slot = read_offset(&mut reader, width, "range start")?;
        }
        let mut ranges = [(0u64, 0u64); RANGE_COUNT];
        for i in 0..RANGE_COUNT {
            let end = read_offset(&mut reader, width, "range end")?;
            ranges[i] = (starts[i], end);
        }
        Ok(Self {
            file_hash,
            ranges: PartRanges::new(ranges).map_err(PartsDecodeError::Ranges)?,
        })
    }

    /// Frame this request at `width`; an offset that does not fit it is an error, never a truncation.
    pub fn encode_packet(&self, width: PartOffsetWidth) -> Result<Packet, PartsEncodeError> {
        let (protocol, opcode, offset_size) = match width {
            PartOffsetWidth::U32 => (
                PeerOpcode::RequestParts.protocol(),
                PeerOpcode::RequestParts.as_u8(),
                4,
            ),
            PartOffsetWidth::U64 => (
                PeerOpcode::RequestPartsI64.protocol(),
                PeerOpcode::RequestPartsI64.as_u8(),
                8,
            ),
        };
        if matches!(width, PartOffsetWidth::U32) {
            for (start, end) in *self.ranges.as_array() {
                if start > u32::MAX as u64 || end > u32::MAX as u64 {
                    return Err(PartsEncodeError::OffsetExceedsU32 { start, end });
                }
            }
        }
        let mut payload = Vec::with_capacity(FileHash::BYTE_LEN + RANGE_COUNT * 2 * offset_size);
        payload.extend_from_slice(self.file_hash.as_bytes());
        for (start, _) in *self.ranges.as_array() {
            write_offset(&mut payload, start, width);
        }
        for (_, end) in *self.ranges.as_array() {
            write_offset(&mut payload, end, width);
        }
        Ok(Packet::new(protocol, opcode, payload))
    }
}

impl SendingPart {
    /// Read a block at whichever width its opcode names.
    pub fn decode_packet(packet: &Packet) -> Result<Self, PartsDecodeError> {
        let width = match PeerOpcode::try_from_u8(packet.opcode()) {
            Some(op @ PeerOpcode::SendingPart) if op.protocol() == packet.protocol() => {
                PartOffsetWidth::U32
            }
            Some(op @ PeerOpcode::SendingPartI64) if op.protocol() == packet.protocol() => {
                PartOffsetWidth::U64
            }
            _ => unreachable!("dispatch routes only matching (protocol, opcode) here"),
        };
        let offset_size = match width {
            PartOffsetWidth::U32 => 4,
            PartOffsetWidth::U64 => 8,
        };
        let header = FileHash::BYTE_LEN + 2 * offset_size;
        let payload = packet.payload();
        if payload.len() < header {
            return Err(PartsDecodeError::Truncated {
                needed: header,
                actual: payload.len(),
            });
        }
        let mut reader = WireReader::new(payload);
        let file_hash = reader.read_file_hash("file hash")?;
        let start = read_offset(&mut reader, width, "block start")?;
        let end = read_offset(&mut reader, width, "block end")?;
        if end < start {
            return Err(PartsDecodeError::EndBeforeStart { start, end });
        }
        let declared_data_len = (end - start) as usize;
        let actual_data_len = payload.len() - header;
        if declared_data_len != actual_data_len {
            return Err(PartsDecodeError::DataLenMismatch {
                declared: declared_data_len,
                actual: actual_data_len,
            });
        }
        Ok(Self {
            file_hash,
            start,
            end,
            data: reader.remaining_bytes().to_vec(),
        })
    }

    /// Frame this block at `width`; an offset that does not fit it is an error, never a truncation.
    pub fn encode_packet(&self, width: PartOffsetWidth) -> Result<Packet, PartsEncodeError> {
        let (protocol, opcode, offset_size) = match width {
            PartOffsetWidth::U32 => (
                PeerOpcode::SendingPart.protocol(),
                PeerOpcode::SendingPart.as_u8(),
                4,
            ),
            PartOffsetWidth::U64 => (
                PeerOpcode::SendingPartI64.protocol(),
                PeerOpcode::SendingPartI64.as_u8(),
                8,
            ),
        };
        if matches!(width, PartOffsetWidth::U32)
            && (self.start > u32::MAX as u64 || self.end > u32::MAX as u64)
        {
            return Err(PartsEncodeError::OffsetExceedsU32 {
                start: self.start,
                end: self.end,
            });
        }
        let mut payload =
            Vec::with_capacity(FileHash::BYTE_LEN + 2 * offset_size + self.data.len());
        payload.extend_from_slice(self.file_hash.as_bytes());
        write_offset(&mut payload, self.start, width);
        write_offset(&mut payload, self.end, width);
        payload.extend_from_slice(&self.data);
        Ok(Packet::new(protocol, opcode, payload))
    }
}

/// `OP_COMPRESSEDPART` (`0x40`) / `OP_COMPRESSEDPART_I64` (`0xA1`,
/// OP_EMULEPROT) — a zlib-compressed slice of a part block. Payload pinned
/// verbatim from aMule `DownloadClient.cpp::ProcessBlockPacket` @ `377ec8d9`:
///
///   `[HASH 16][start u32|u64][nBlockSize u32][compressed chunk to end]`
///
/// `nBlockSize` is the block's *total* compressed length (chunks accumulate
/// across packets), and stays `u32` even in the I64 variant — only `start`
/// widens to `u64`. Distinct from `OP_PACKEDPROT` (`0xD4`) whole-frame
/// compression. Reassembly + inflate live in the session, not the codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedPart {
    /// The file the block belongs to.
    pub file_hash: FileHash,
    /// Absolute offset of the block's first *uncompressed* byte.
    pub start: u64,
    /// `nBlockSize`: total compressed length of the block across packets.
    pub compressed_block_len: u32,
    /// This packet's slice of the block's compressed (zlib) bytes.
    pub compressed_chunk: Vec<u8>,
}

impl CompressedPart {
    /// Read a compressed slice at whichever width its opcode names.
    pub fn decode_packet(packet: &Packet) -> Result<Self, PartsDecodeError> {
        let width = match PeerOpcode::try_from_u8(packet.opcode()) {
            Some(op @ PeerOpcode::CompressedPart) if op.protocol() == packet.protocol() => {
                PartOffsetWidth::U32
            }
            Some(op @ PeerOpcode::CompressedPartI64) if op.protocol() == packet.protocol() => {
                PartOffsetWidth::U64
            }
            _ => unreachable!("dispatch routes only matching (protocol, opcode) here"),
        };
        let offset_size = match width {
            PartOffsetWidth::U32 => 4,
            PartOffsetWidth::U64 => 8,
        };
        // nBlockSize is u32 regardless of the start-offset width.
        let header = FileHash::BYTE_LEN + offset_size + 4;
        let payload = packet.payload();
        if payload.len() < header {
            return Err(PartsDecodeError::Truncated {
                needed: header,
                actual: payload.len(),
            });
        }
        let mut reader = WireReader::new(payload);
        let file_hash = reader.read_file_hash("file hash")?;
        let start = read_offset(&mut reader, width, "block start")?;
        let compressed_block_len = reader.read_u32_le("compressed block length")?;
        Ok(Self {
            file_hash,
            start,
            compressed_block_len,
            compressed_chunk: reader.remaining_bytes().to_vec(),
        })
    }

    /// Frame this slice at `width`; an offset that does not fit it is an error, never a truncation.
    pub fn encode_packet(&self, width: PartOffsetWidth) -> Result<Packet, PartsEncodeError> {
        let (protocol, opcode, offset_size) = match width {
            PartOffsetWidth::U32 => (
                PeerOpcode::CompressedPart.protocol(),
                PeerOpcode::CompressedPart.as_u8(),
                4,
            ),
            PartOffsetWidth::U64 => (
                PeerOpcode::CompressedPartI64.protocol(),
                PeerOpcode::CompressedPartI64.as_u8(),
                8,
            ),
        };
        if matches!(width, PartOffsetWidth::U32) && self.start > u32::MAX as u64 {
            return Err(PartsEncodeError::OffsetExceedsU32 {
                start: self.start,
                end: self.start,
            });
        }
        let mut payload =
            Vec::with_capacity(FileHash::BYTE_LEN + offset_size + 4 + self.compressed_chunk.len());
        payload.extend_from_slice(self.file_hash.as_bytes());
        write_offset(&mut payload, self.start, width);
        // nBlockSize is u32 regardless of offset width.
        payload.extend_from_slice(&self.compressed_block_len.to_le_bytes());
        payload.extend_from_slice(&self.compressed_chunk);
        Ok(Packet::new(protocol, opcode, payload))
    }
}

fn read_offset(
    reader: &mut WireReader<'_>,
    width: PartOffsetWidth,
    field: &'static str,
) -> Result<u64, PartsDecodeError> {
    Ok(match width {
        PartOffsetWidth::U32 => u64::from(reader.read_u32_le(field)?),
        PartOffsetWidth::U64 => reader.read_u64_le(field)?,
    })
}

fn write_offset(payload: &mut Vec<u8>, value: u64, width: PartOffsetWidth) {
    match width {
        PartOffsetWidth::U32 => payload.extend_from_slice(&(value as u32).to_le_bytes()),
        PartOffsetWidth::U64 => payload.extend_from_slice(&value.to_le_bytes()),
    }
}

/// Why a range triple was refused.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PartRangesError {
    /// A pair runs backwards.
    #[error("part range start {start} > end {end}")]
    StartAfterEnd {
        /// The start offered.
        start: u64,
        /// The end offered.
        end: u64,
    },
}

/// Why a part-transfer frame could not be read.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PartsDecodeError {
    /// A request's payload was not the exact fixed size its width requires.
    #[error("part packet payload wrong size: expected {expected} bytes, had {actual}")]
    WrongPayloadLen {
        /// The size that width requires.
        expected: usize,
        /// The size that arrived.
        actual: usize,
    },

    /// The payload ended inside the header.
    #[error("part packet payload truncated: needed {needed} bytes, had {actual}")]
    Truncated {
        /// Bytes the header requires.
        needed: usize,
        /// Bytes present.
        actual: usize,
    },

    /// A block's range runs backwards, so it names no bytes.
    #[error("part packet end {end} before start {start}")]
    EndBeforeStart {
        /// The declared start.
        start: u64,
        /// The declared end.
        end: u64,
    },

    /// The block's range and its payload disagree about its length.
    #[error("part packet declared {declared} data bytes but payload has {actual}")]
    DataLenMismatch {
        /// What the range implies.
        declared: usize,
        /// What followed it.
        actual: usize,
    },

    /// A request's three ranges did not hold up.
    #[error("part packet ranges invalid: {0}")]
    Ranges(#[from] PartRangesError),
}

impl From<WireTruncated> for PartsDecodeError {
    fn from(truncated: WireTruncated) -> Self {
        Self::Truncated {
            needed: truncated.needed,
            actual: truncated.available,
        }
    }
}

/// Why a part-transfer frame could not be written.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PartsEncodeError {
    /// An offset needs the 64-bit opcodes but the 32-bit ones were asked
    /// for. Truncating would name different bytes, so it fails instead.
    #[error("part offset(s) exceed u32 for u32 wire variant: start={start} end={end}")]
    OffsetExceedsU32 {
        /// The start that does not fit.
        start: u64,
        /// The end that does not fit.
        end: u64,
    },
}
