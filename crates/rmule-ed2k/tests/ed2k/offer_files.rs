//! `OP_OFFERFILES` as a packet: the zero-count keepalive, the tags a small
//! file's announcement carries, and the u32-low/u16-high split a file above
//! 4 GiB needs.

use rmule_ed2k::{OfferFiles, OfferedFile, Opcode};
use rmule_primitives::{ClientId, Ed2kText, FileHash, Packet, PacketProtocol};

fn file_hash() -> FileHash {
    FileHash::from_bytes([0x11; FileHash::BYTE_LEN])
}

fn announce(size: u64) -> OfferFiles {
    OfferFiles::announce(
        ClientId::from_u32(0x0403_0201),
        4662,
        &[OfferedFile::new(
            file_hash(),
            size,
            Ed2kText::from_utf8("ab"),
        )],
    )
}

#[test]
fn offerfiles_opcode_byte() {
    assert_eq!(Opcode::OfferFiles.as_u8(), 0x15);
}

#[test]
fn empty_announce_is_a_zero_count_keepalive() {
    let packet = OfferFiles::announce(ClientId::from_u32(7), 4662, &[]).encode_packet();
    assert_eq!(packet.protocol(), PacketProtocol::Edonkey);
    assert_eq!(packet.opcode(), 0x15);
    assert_eq!(packet.payload(), &[0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn small_file_announce_emits_filename_and_u32_size_tags() {
    let expected: &[u8] = &[
        0x01, 0x00, 0x00, 0x00, // file_count = 1
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // file_hash
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x01, 0x02, 0x03,
        0x04, // client_id (0x04030201) LE
        0x36, 0x12, // client_port (4662) LE
        0x02, 0x00, 0x00, 0x00, // tag_count = 2
        0x82, 0x01, 0x02, 0x00, b'a', b'b', // FT_FILENAME "ab"
        0x83, 0x02, 0x2A, 0x00, 0x00, 0x00, // FT_FILESIZE = 42 (u32)
    ];
    let packet = announce(42).encode_packet();
    assert_eq!(packet.payload(), expected);
}

#[test]
fn large_file_announce_splits_size_into_u32_low_and_u16_high() {
    let expected: &[u8] = &[
        0x01, 0x00, 0x00, 0x00, // file_count = 1
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // file_hash
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x01, 0x02, 0x03,
        0x04, // client_id LE
        0x36, 0x12, // client_port LE
        0x03, 0x00, 0x00, 0x00, // tag_count = 3
        0x82, 0x01, 0x02, 0x00, b'a', b'b', // FT_FILENAME "ab"
        0x83, 0x02, 0x00, 0x00, 0x00, 0x00, // FT_FILESIZE low 32 bits = 0
        0x88, 0x3A, 0x01, 0x00, // FT_FILESIZE_HI high bits = 1
    ];
    // u32::MAX + 1 = 0x1_0000_0000: low 32 = 0, high = 1.
    let packet = announce(u64::from(u32::MAX) + 1).encode_packet();
    assert_eq!(packet.payload(), expected);
}

#[test]
fn announce_round_trips_through_decode() {
    let original = announce(42);
    let packet = original.encode_packet();
    let decoded = OfferFiles::decode_packet(&packet).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn decode_rejects_wrong_opcode() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x14, vec![0x00, 0x00, 0x00, 0x00]);
    assert!(OfferFiles::decode_packet(&packet).is_err());
}

#[test]
fn decode_rejects_truncated_entry() {
    // Claims 1 file but stops mid-hash.
    let packet = Packet::new(
        PacketProtocol::Edonkey,
        0x15,
        vec![0x01, 0x00, 0x00, 0x00, 0x11],
    );
    assert!(OfferFiles::decode_packet(&packet).is_err());
}

#[test]
fn decode_rejects_wrong_protocol() {
    // Correct opcode byte, but Emule protocol — OP_OFFERFILES is Edonkey-only.
    let packet = Packet::new(PacketProtocol::Emule, 0x15, vec![0x00, 0x00, 0x00, 0x00]);
    assert!(OfferFiles::decode_packet(&packet).is_err());
}
