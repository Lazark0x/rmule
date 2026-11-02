//! A served block as aMule's uploader writes it (ADR-0031): its payload cut
//! into packets of about 10 KiB, plain or compressed, each framed straight
//! from its slice of the one block buffer. A stock downloader restarts its
//! download timeout only on a whole packet (`DownloadClient.cpp:848`), so the
//! cut is what lets a slow link finish a block.

use std::ops::Range;

use rmule_primitives::{FileHash, Packet};

use super::{CompressedPart, PartOffsetWidth, SendingPart, write_offset};
use crate::opcode::PeerOpcode;

/// aMule's uploader cuts a block's payload into packets of about this many
/// bytes (`UploadClient.cpp:290-291`, `:349-350`).
const UPLOAD_PACKET_LEN: usize = 10_240;

/// The ranges aMule's uploader cuts a `len`-byte payload into: packets of
/// `len / (len / 10240)` bytes, the last taking what is left once less than
/// two packets' worth remains, and a payload of at most 10,240 bytes whole
/// (`UploadClient.cpp:290-299`, `:349-358`). An empty payload is no packet.
fn upload_cuts(len: usize) -> impl Iterator<Item = Range<usize>> {
    let size = if len > UPLOAD_PACKET_LEN {
        len / (len / UPLOAD_PACKET_LEN)
    } else {
        len
    };
    let mut at = 0;
    std::iter::from_fn(move || {
        let left = len - at;
        if left == 0 {
            return None;
        }
        let take = if left < 2 * size { left } else { size };
        at += take;
        Some(at - take..at)
    })
}

impl SendingPart {
    /// The TCP frames that serve `data`, the plain block at `start`, as
    /// aMule's uploader writes it: packets of about 10 KiB whose ranges tile
    /// the block in order, each at the width its own offsets need
    /// (`UploadClient.cpp:285-330`).
    pub(crate) fn block_frames(
        file_hash: FileHash,
        start: u64,
        data: &[u8],
    ) -> impl Iterator<Item = Vec<u8>> + '_ {
        upload_cuts(data.len()).map(move |cut| {
            let first = start + cut.start as u64;
            let last = start + cut.end as u64;
            let width = PartOffsetWidth::for_file_size(last);
            let opcode = match width {
                PartOffsetWidth::U32 => PeerOpcode::SendingPart,
                PartOffsetWidth::U64 => PeerOpcode::SendingPartI64,
            };
            let chunk = &data[cut];
            let payload_len = FileHash::BYTE_LEN + 2 * width.offset_len() + chunk.len();
            Packet::encode_with(opcode.protocol(), opcode.as_u8(), payload_len, |frame| {
                frame.extend_from_slice(file_hash.as_bytes());
                write_offset(frame, first, width);
                write_offset(frame, last, width);
                frame.extend_from_slice(chunk);
            })
        })
    }
}

impl CompressedPart {
    /// The TCP frames that serve `stream`, the zlib stream of the block
    /// `start..end`, as aMule's uploader writes it: packets of about 10 KiB,
    /// every one naming the block's start and the stream's whole length as
    /// `nBlockSize`, at the width the block's offsets need
    /// (`UploadClient.cpp:333-394`).
    ///
    /// # Panics
    /// If `stream` is longer than `nBlockSize`'s `u32` can name; the serve
    /// session sends such a block plain.
    pub(crate) fn block_frames(
        file_hash: FileHash,
        start: u64,
        end: u64,
        stream: &[u8],
    ) -> impl Iterator<Item = Vec<u8>> + '_ {
        let total = u32::try_from(stream.len()).expect("a compressed block's length fits a u32");
        let width = PartOffsetWidth::for_file_size(end.max(start));
        let opcode = match width {
            PartOffsetWidth::U32 => PeerOpcode::CompressedPart,
            PartOffsetWidth::U64 => PeerOpcode::CompressedPartI64,
        };
        upload_cuts(stream.len()).map(move |cut| {
            let chunk = &stream[cut];
            let payload_len = FileHash::BYTE_LEN + width.offset_len() + 4 + chunk.len();
            Packet::encode_with(opcode.protocol(), opcode.as_u8(), payload_len, |frame| {
                frame.extend_from_slice(file_hash.as_bytes());
                write_offset(frame, start, width);
                frame.extend_from_slice(&total.to_le_bytes());
                frame.extend_from_slice(chunk);
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::upload_cuts;

    fn lens(len: usize) -> Vec<usize> {
        upload_cuts(len).map(|cut| cut.len()).collect()
    }

    /// The short and odd payloads a file's last block and a zlib stream
    /// produce, cut as aMule cuts them.
    #[test]
    fn a_payload_is_cut_as_amule_cuts_it() {
        assert_eq!(lens(0), Vec::<usize>::new());
        assert_eq!(lens(4), [4]);
        assert_eq!(lens(10_240), [10_240]);
        assert_eq!(lens(10_241), [10_241]);
        assert_eq!(lens(20_479), [20_479]);
        assert_eq!(lens(20_480), [10_240, 10_240]);
        assert_eq!(lens(30_719), [15_359, 15_360]);
        assert_eq!(lens(184_320), [10_240; 18]);
        assert_eq!(lens(184_319), [[10_842; 16].as_slice(), &[10_847]].concat());
    }
}
