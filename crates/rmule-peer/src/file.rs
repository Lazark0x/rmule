//! ED2K part index + per-file part availability bitmap.
//!
//! `PartBitmap` mirrors aMule's `OP_FILESTATUS` decoding semantics
//! (`DownloadClient.cpp::ProcessFileStatus` at amule 377ec8d9): bits
//! within a byte are little-endian (bit 0 = part `n*8`, bit 7 = part
//! `n*8 + 7`), and bits beyond `part_count` in the final byte are
//! tolerated on decode but always written as zero on encode.
//!
//! Lives in `rmule-peer` per ADR-0025: promotion to `rmule-primitives`
//! waits for a second consumer (Kad, an orchestrator) — the same rule that
//! keeps `PeerIdentity` here.

use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// A part's position in a file, counted from 0. A newtype so a part number and a byte offset cannot be swapped.
pub struct PartIndex(u32);

impl PartIndex {
    #[must_use]
    /// Wrap a raw index.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    /// The index as a number.
    pub const fn value(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Which parts of a file a peer holds, as the wire carries it: one bit
/// per part, LSB first, padded to whole bytes.
pub struct PartBitmap {
    part_count: u32,
    bytes: Vec<u8>,
}

impl PartBitmap {
    /// Read a bitmap for a file of `part_count` parts; the byte length must be exactly what that count implies.
    pub fn decode(part_count: u32, bytes: &[u8]) -> Result<Self, PartBitmapDecodeError> {
        let expected = expected_byte_len(part_count);
        if bytes.len() != expected {
            return Err(PartBitmapDecodeError::LengthMismatch {
                expected,
                actual: bytes.len(),
            });
        }
        // Normalise trailing bits in the final byte to zero so the stored
        // form is canonical. aMule never reads bits past `part_count`
        // (`DownloadClient.cpp::ProcessFileStatus` breaks at `done ==
        // m_nPartCount`), so dropping the garbage is loss-free.
        let mut bytes = bytes.to_vec();
        if let Some(last) = bytes.last_mut() {
            let used_bits = part_count % 8;
            if used_bits != 0 {
                *last &= (1u8 << used_bits) - 1;
            }
        }
        Ok(Self { part_count, bytes })
    }

    #[must_use]
    /// A one-part file, held whole: what aMule records for a one-part source
    /// whose name answer arrived (`ProcessFileInfo`, `GetPartCount() == 1`),
    /// since it neither asks nor awaits an `OP_FILESTATUS` for such a file.
    pub fn one_part_complete() -> Self {
        Self {
            part_count: 1,
            bytes: vec![0x01],
        }
    }

    #[must_use]
    /// Every part of a `part_count`-part file, held whole: the reader-side
    /// expansion of aMule's `nED2KPartCount == 0` "complete source" sentinel
    /// (`ProcessFileStatus`, `DownloadClient.cpp:388-458`, kno `ab483654`) —
    /// `m_nPartCount = m_reqfile->GetPartCount(); m_downPartStatus.setsize(
    /// m_nPartCount, 1)`, every bit set to the file's own part count, not a
    /// genuinely 0-part bitmap.
    pub fn all_present(part_count: u32) -> Self {
        let mut bytes = vec![0xFFu8; expected_byte_len(part_count)];
        if let Some(last) = bytes.last_mut() {
            let used_bits = part_count % 8;
            if used_bits != 0 {
                *last &= (1u8 << used_bits) - 1;
            }
        }
        Self { part_count, bytes }
    }

    #[must_use]
    /// aMule's writer-side "complete source" sentinel: a literal part count
    /// of zero and no bitmap bytes at all, the shape `SendFileRequest`
    /// writes for a fully-owned shared file (`ClientTCPSocket.cpp`
    /// `OP_SETREQFILEID`, kno `ab483654`: `IsPartFile() ?  WritePartStatus()
    /// : data.WriteUInt16(0)` — a complete file is never a `CPartFile`, so
    /// there is no bitmap to spell out).
    pub fn complete_source_sentinel() -> Self {
        Self {
            part_count: 0,
            bytes: Vec::new(),
        }
    }

    #[must_use]
    /// A downloader's own availability, as aMule's `CPartFile::WritePartStatus`
    /// writes it (stock 2.3.3 `PartFile.cpp:1338`) into a name ask, a UDP
    /// reask or a status answer: `size / PARTSIZE + 1` parts
    /// (`m_iED2KPartCount`, `KnownFile.cpp:422`) — one more than the file has
    /// when its size is an exact multiple of the part size, and that phantom
    /// part always reads held (`GapList.cpp:291`). The count matters: aMule's
    /// uploader drops the whole status on any other count (`UploadClient.cpp`
    /// `ProcessExtendedInfo`), and inside a bundle it then reads the unread
    /// bitmap bytes as sub-opcodes. `held` answers for the file's real parts.
    pub fn downloader(file_size: u64, held: impl Fn(PartIndex) -> bool) -> Self {
        let real = rmule_primitives::part_count(file_size);
        let counted = rmule_primitives::ed2k_status_part_count(file_size);
        let mut bytes = vec![0u8; expected_byte_len(counted)];
        for part in 0..counted {
            if part >= real || held(PartIndex::new(part)) {
                bytes[(part / 8) as usize] |= 1 << (part % 8);
            }
        }
        Self {
            part_count: counted,
            bytes,
        }
    }

    #[must_use]
    /// The **Advertised Parts** a peer's wire status states for a
    /// `file_size`-byte file: one bit per real part, `0..part_count(size)`.
    /// The one reader every status goes through, as aMule's
    /// `ProcessFileStatus` reads one (stock 2.3.3 `DownloadClient.cpp:404-449`):
    /// a count of `0` is a complete source and holds every part; a count of
    /// [`rmule_primitives::ed2k_status_part_count`] gives its first
    /// `part_count(size)` bits, so the phantom part of an exact multiple is
    /// never read; any other count is `None`, refused whole (aMule throws).
    pub fn advertised_parts(&self, file_size: u64) -> Option<Self> {
        let real = rmule_primitives::part_count(file_size);
        if self.part_count == 0 {
            return Some(Self::all_present(real));
        }
        if self.part_count != rmule_primitives::ed2k_status_part_count(file_size) {
            return None;
        }
        let mut bytes = self.bytes[..expected_byte_len(real)].to_vec();
        if let Some(last) = bytes.last_mut() {
            let used_bits = real % 8;
            if used_bits != 0 {
                *last &= (1u8 << used_bits) - 1;
            }
        }
        Some(Self {
            part_count: real,
            bytes,
        })
    }

    #[must_use]
    /// [`Self::downloader`] for a download that holds nothing yet.
    pub fn downloader_empty(file_size: u64) -> Self {
        Self::downloader(file_size, |_| false)
    }

    #[must_use]
    /// Whether every part is present — the shape aMule's writer collapses to
    /// [`Self::complete_source_sentinel`] instead of spelling out bit by bit.
    pub fn is_complete(&self) -> bool {
        self.part_count > 0 && self.iter_present().count() as u32 == self.part_count
    }

    #[must_use]
    /// The bitmap's wire bytes, padding included.
    pub fn encode(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[must_use]
    /// How many parts the file has — the padding bits past this are not parts.
    pub const fn part_count(&self) -> u32 {
        self.part_count
    }

    #[must_use]
    /// Whether the peer holds this part. An index past the end is `false`, not a panic.
    pub fn has(&self, index: PartIndex) -> bool {
        let i = index.value();
        if i >= self.part_count {
            return false;
        }
        let byte = self.bytes[(i / 8) as usize];
        (byte >> (i % 8)) & 1 == 1
    }

    /// Every part the peer holds, in ascending order.
    pub fn iter_present(&self) -> impl Iterator<Item = PartIndex> + '_ {
        (0..self.part_count)
            .map(PartIndex::new)
            .filter(|i| self.has(*i))
    }

    /// Fold a later status's bits into this one, OR-ing them in place.
    /// A peer only ever reports parts it holds, so a later status can only
    /// add availability, never take it away (aMule `ProcessFileStatus`
    /// updates the part status of an already-known file; it never un-knows
    /// it). `other` must describe the same file, so its part count matches.
    pub fn merge_from(&mut self, other: &Self) {
        debug_assert_eq!(
            self.part_count, other.part_count,
            "merge_from: bitmaps for the same file must share a part count"
        );
        for (byte, addition) in self.bytes.iter_mut().zip(other.bytes.iter()) {
            *byte |= addition;
        }
    }
}

const fn expected_byte_len(part_count: u32) -> usize {
    (part_count as usize).div_ceil(8)
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
/// Why a part bitmap could not be read.
pub enum PartBitmapDecodeError {
    #[error("part bitmap length mismatch: expected {expected} bytes, had {actual}")]
    /// The byte count does not match the part count the file has, so the
    /// bitmap describes some other file.
    LengthMismatch {
        /// Bytes that part count implies.
        expected: usize,
        /// Bytes present.
        actual: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_present_sets_every_bit_and_zeroes_the_trailing_pad() {
        let bitmap = PartBitmap::all_present(10);
        assert_eq!(bitmap.part_count(), 10);
        assert_eq!(bitmap.encode(), vec![0xFF, 0b0000_0011]);
        assert_eq!(bitmap.iter_present().count(), 10);
    }

    #[test]
    fn complete_source_sentinel_is_the_zero_part_empty_bitmap() {
        let sentinel = PartBitmap::complete_source_sentinel();
        assert_eq!(sentinel.part_count(), 0);
        assert_eq!(sentinel.encode(), Vec::<u8>::new());
    }

    #[test]
    fn a_downloader_counts_parts_the_way_amules_writer_does() {
        use rmule_primitives::ED2K_PART_SIZE;
        // 2.5 parts, part 1 held: three parts, one bit.
        let partial = PartBitmap::downloader(ED2K_PART_SIZE * 5 / 2, |i| i.value() == 1);
        assert_eq!((partial.part_count(), partial.encode()), (3, vec![0b010]));
        // Exactly two parts, nothing held: aMule counts three and reads the
        // phantom third as held (`GapList.cpp:291`).
        let exact = PartBitmap::downloader_empty(ED2K_PART_SIZE * 2);
        assert_eq!((exact.part_count(), exact.encode()), (3, vec![0b100]));
        // Sixteen parts exactly: the phantom spills into a third byte.
        let spill = PartBitmap::downloader(ED2K_PART_SIZE * 16, |_| true);
        assert_eq!(spill.encode(), vec![0xFF, 0xFF, 0x01]);
    }

    #[test]
    fn is_complete_requires_every_part_present_and_at_least_one_part() {
        assert!(PartBitmap::all_present(5).is_complete());
        assert!(!PartBitmap::decode(5, &[0b0_1111]).unwrap().is_complete());
        assert!(!PartBitmap::complete_source_sentinel().is_complete());
    }
}
