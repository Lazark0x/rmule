//! Trailing-bit policy: aMule tolerates non-zero bits past `part_count`
//! in the final byte. `DownloadClient.cpp::CUpDownClient::ProcessFileStatus`
//! at amule 377ec8d9 reads 8 bits per byte and `break`s when `done ==
//! m_nPartCount`, never validating the unused bits. rmule mirrors:
//! `decode` ignores trailing bits, `encode` always writes them as zero.

use rmule_peer::file::{PartBitmap, PartBitmapDecodeError, PartIndex};

#[test]
fn decode_reads_each_bit_lsb_first_within_byte() {
    // part_count = 10, two bytes: 0b1010_1010, 0b00_0000_11
    // bits (LSB first): byte0 → indices 0..8 = 0,1,0,1,0,1,0,1
    //                   byte1 → indices 8..10 = 1,1
    let bitmap = PartBitmap::decode(10, &[0b1010_1010, 0b0000_0011]).unwrap();
    let expected = [
        false, true, false, true, false, true, false, true, true, true,
    ];
    for (i, want) in expected.iter().enumerate() {
        assert_eq!(bitmap.has(PartIndex::new(i as u32)), *want, "bit {i}");
    }
}

#[test]
fn iter_present_yields_ascending_set_indices() {
    let bitmap = PartBitmap::decode(10, &[0b1010_1010, 0b0000_0011]).unwrap();
    let present: Vec<u32> = bitmap.iter_present().map(PartIndex::value).collect();
    assert_eq!(present, vec![1, 3, 5, 7, 8, 9]);
}

#[test]
fn decode_rejects_length_mismatch() {
    // part_count = 10 → expects ceil(10/8) = 2 bytes.
    let too_short = PartBitmap::decode(10, &[0xFF]).unwrap_err();
    assert_eq!(
        too_short,
        PartBitmapDecodeError::LengthMismatch {
            expected: 2,
            actual: 1
        }
    );

    let too_long = PartBitmap::decode(10, &[0xFF, 0xFF, 0xFF]).unwrap_err();
    assert_eq!(
        too_long,
        PartBitmapDecodeError::LengthMismatch {
            expected: 2,
            actual: 3
        }
    );
}

#[test]
fn decode_tolerates_trailing_nonzero_bits_in_final_byte() {
    // part_count = 10 means bits 10..16 in byte 1 are undefined;
    // aMule never reads them. We tolerate any value there.
    let bitmap = PartBitmap::decode(10, &[0x00, 0b1111_1111]).unwrap();
    // Bits 0..8 are clear, bits 8 and 9 are set (the meaningful tail of 0xFF).
    let present: Vec<u32> = bitmap.iter_present().map(PartIndex::value).collect();
    assert_eq!(present, vec![8, 9]);
}

#[test]
fn encode_zeros_trailing_bits_in_final_byte() {
    // Construct via decode, then re-encode: trailing bits must be 0
    // even if input had nonzero garbage there.
    let bitmap = PartBitmap::decode(10, &[0xFF, 0b1111_1111]).unwrap();
    let bytes = bitmap.encode();
    // Bits 0..8 set (0xFF), bits 8..10 set (0b0000_0011); bits 10..16 zero.
    assert_eq!(bytes, vec![0xFF, 0b0000_0011]);
}

#[test]
fn round_trip_across_byte_boundary_part_counts() {
    for &part_count in &[1u32, 7, 8, 9, 64, 65] {
        let byte_len = part_count.div_ceil(8) as usize;
        // Pattern: every other bit set, masked to the meaningful range.
        let raw: Vec<u8> = (0..byte_len)
            .map(|i| if i % 2 == 0 { 0b0101_0101 } else { 0b1010_1010 })
            .collect();
        let bitmap = PartBitmap::decode(part_count, &raw).unwrap();
        let encoded = bitmap.encode();
        let re_decoded = PartBitmap::decode(part_count, &encoded).unwrap();
        assert_eq!(bitmap, re_decoded, "round-trip part_count={part_count}");
        // Re-encoded length matches the formula.
        assert_eq!(encoded.len(), byte_len);
    }
}

#[test]
fn empty_bitmap_for_zero_parts() {
    // Wire-level: part_count = 0 carries zero bitmap bytes.
    // Session layer interprets this separately as "peer reports complete file";
    // PartBitmap itself just round-trips an empty bitmap.
    let bitmap = PartBitmap::decode(0, &[]).unwrap();
    assert_eq!(bitmap.part_count(), 0);
    assert_eq!(bitmap.iter_present().count(), 0);
    assert_eq!(bitmap.encode(), Vec::<u8>::new());
}
