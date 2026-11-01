//! A part status as the wire states it, which is not yet a statement about
//! a file's parts: `WritePartStatus`'s `<u16 count><bitmap>`, where the count
//! is `size / PARTSIZE + 1` (one more than the file has on an exact multiple)
//! or `0` for a complete source. [`WireStatus::advertised_parts`] is the only
//! way from it to a [`PartBitmap`], so nothing reads a phantom part or a
//! sentinel as parts.

use crate::file::{PartBitmap, PartBitmapDecodeError, PartIndex};

/// The two fields of a part status, as read or as about to be written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireStatus {
    count: u16,
    bytes: Vec<u8>,
}

impl WireStatus {
    /// Read a status of `count`; the byte length must be exactly what that
    /// count implies.
    ///
    /// # Errors
    /// [`PartBitmapDecodeError::LengthMismatch`] on any other length.
    pub fn decode(count: u16, bytes: &[u8]) -> Result<Self, PartBitmapDecodeError> {
        Ok(Self {
            count,
            bytes: PartBitmap::decode(u32::from(count), bytes)?.into_bytes(),
        })
    }

    /// A status of `count` from the bytes that arrived: a bit past them reads
    /// as not held, so a status cut short keeps what it did state.
    pub(crate) fn padded(count: u16, bytes: &[u8]) -> Self {
        Self {
            count,
            bytes: PartBitmap::from_fn(u32::from(count), |part| {
                let index = part.value();
                bytes
                    .get((index / 8) as usize)
                    .is_some_and(|byte| byte >> (index % 8) & 1 == 1)
            })
            .into_bytes(),
        }
    }

    #[must_use]
    /// aMule's writer-side "complete source" sentinel: a literal part count
    /// of zero and no bitmap bytes at all, the shape `SendFileRequest`
    /// writes for a fully-owned shared file (`ClientTCPSocket.cpp`
    /// `OP_SETREQFILEID`, kno `ab483654`: `IsPartFile() ?  WritePartStatus()
    /// : data.WriteUInt16(0)` — a complete file is never a `CPartFile`, so
    /// there is no bitmap to spell out).
    pub fn complete_source() -> Self {
        Self {
            count: 0,
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
        let count = count_of(file_size);
        Self {
            count,
            bytes: PartBitmap::from_fn(u32::from(count), |part| part.value() >= real || held(part))
                .into_bytes(),
        }
    }

    #[must_use]
    /// [`Self::downloader`] for a download that holds nothing yet.
    pub fn downloader_empty(file_size: u64) -> Self {
        Self::downloader(file_size, |_| false)
    }

    #[must_use]
    /// [`Self::downloader`] for a file held whole.
    pub fn whole(file_size: u64) -> Self {
        Self::downloader(file_size, |_| true)
    }

    #[must_use]
    /// The **Advertised Parts** this status states for a `file_size`-byte
    /// file: one bit per real part, `0..part_count(size)`. The one reader
    /// every status goes through, as aMule's `ProcessFileStatus` reads one
    /// (stock 2.3.3 `DownloadClient.cpp:404-449`): a count of `0` is a
    /// complete source and holds every part; a count of
    /// [`rmule_primitives::ed2k_status_part_count`] gives its first
    /// `part_count(size)` bits, so the phantom part of an exact multiple is
    /// never read; any other count is `None`, refused whole (aMule throws).
    pub fn advertised_parts(&self, file_size: u64) -> Option<PartBitmap> {
        let real = rmule_primitives::part_count(file_size);
        if self.count == 0 {
            return Some(PartBitmap::all_present(real));
        }
        if u32::from(self.count) != rmule_primitives::ed2k_status_part_count(file_size) {
            return None;
        }
        Some(self.bits().first(real))
    }

    #[must_use]
    /// The count as the wire carries it.
    pub const fn count(&self) -> u16 {
        self.count
    }

    #[must_use]
    /// Whether this is the complete-source sentinel.
    pub const fn is_complete_source(&self) -> bool {
        self.count == 0
    }

    #[must_use]
    /// Whether every counted part is held — the shape aMule's writer
    /// collapses to [`Self::complete_source`] instead of spelling out bit by
    /// bit.
    pub fn is_complete(&self) -> bool {
        self.bits().is_complete()
    }

    #[must_use]
    /// The bitmap's wire bytes, padding included.
    pub fn encode(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Append `<u16 count><bitmap>`, the shape of aMule's `WritePartStatus`.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.count.to_le_bytes());
        out.extend_from_slice(&self.bytes);
    }

    /// The counted bits, phantom part included: this module's alone.
    fn bits(&self) -> PartBitmap {
        PartBitmap::from_fn(u32::from(self.count), |part| {
            let index = part.value();
            self.bytes[(index / 8) as usize] >> (index % 8) & 1 == 1
        })
    }
}

/// The count a `file_size`-byte file's status carries. Every size eD2k
/// addresses counts well below `u16::MAX`; one past it saturates to a status
/// a peer refuses, never to a frame of the wrong length.
fn count_of(file_size: u64) -> u16 {
    u16::try_from(rmule_primitives::ed2k_status_part_count(file_size)).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_source_sentinel_is_the_zero_part_empty_bitmap() {
        let sentinel = WireStatus::complete_source();
        assert_eq!(sentinel.count(), 0);
        assert_eq!(sentinel.encode(), Vec::<u8>::new());
    }

    #[test]
    fn a_downloader_counts_parts_the_way_amules_writer_does() {
        use rmule_primitives::ED2K_PART_SIZE;
        // 2.5 parts, part 1 held: three parts, one bit.
        let partial = WireStatus::downloader(ED2K_PART_SIZE * 5 / 2, |i| i.value() == 1);
        assert_eq!((partial.count(), partial.encode()), (3, vec![0b010]));
        // Exactly two parts, nothing held: aMule counts three and reads the
        // phantom third as held (`GapList.cpp:291`).
        let exact = WireStatus::downloader_empty(ED2K_PART_SIZE * 2);
        assert_eq!((exact.count(), exact.encode()), (3, vec![0b100]));
        // Sixteen parts exactly: the phantom spills into a third byte.
        let spill = WireStatus::downloader(ED2K_PART_SIZE * 16, |_| true);
        assert_eq!(spill.encode(), vec![0xFF, 0xFF, 0x01]);
    }
}
