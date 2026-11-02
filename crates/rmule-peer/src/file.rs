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
/// Which parts of a file a peer holds: one bit per part, LSB first, padded
/// to whole bytes. What a peer states reaches it only through
/// [`WireStatus::advertised_parts`](crate::WireStatus::advertised_parts).
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

    /// A `part_count`-part bitmap holding the parts `held` names.
    pub(crate) fn from_fn(part_count: u32, held: impl Fn(PartIndex) -> bool) -> Self {
        let mut bytes = vec![0u8; expected_byte_len(part_count)];
        for part in 0..part_count {
            if held(PartIndex::new(part)) {
                bytes[(part / 8) as usize] |= 1 << (part % 8);
            }
        }
        Self { part_count, bytes }
    }

    /// The first `part_count` parts of this bitmap, which must hold as many.
    pub(crate) fn first(&self, part_count: u32) -> Self {
        Self::from_fn(part_count, |part| self.has(part))
    }

    #[must_use]
    /// Whether every part is present.
    pub fn is_complete(&self) -> bool {
        self.part_count > 0 && self.iter_present().count() as u32 == self.part_count
    }

    #[must_use]
    /// The bitmap's wire bytes, padding included.
    pub fn encode(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// The bitmap's bytes, padding included.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
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
    fn is_complete_requires_every_part_present_and_at_least_one_part() {
        assert!(PartBitmap::all_present(5).is_complete());
        assert!(!PartBitmap::decode(5, &[0b0_1111]).unwrap().is_complete());
    }
}
