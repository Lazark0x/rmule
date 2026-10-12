//! `OP_OFFERFILES` as a packet: the zero-count keepalive, the tags a small
//! file's announcement carries, and the u32-low/u16-high split a file above
//! 4 GiB needs.

use rmule_ed2k::{
    COMPLETE_FILE_ID, COMPLETE_FILE_PORT, FileCompleteness, INCOMPLETE_FILE_ID,
    INCOMPLETE_FILE_PORT, OfferFiles, OfferedFile, Opcode, ServerGrants,
};
use rmule_primitives::{ClientId, Ed2kText, FileHash, Packet, PacketProtocol};

fn file_hash() -> FileHash {
    FileHash::from_bytes([0x11; FileHash::BYTE_LEN])
}

fn announce(size: u64) -> OfferFiles {
    OfferFiles::announce(
        ServerGrants::default(),
        ClientId::from_u32(0x0403_0201),
        ClientId::from_u32(0x0403_0201),
        4662,
        &[OfferedFile::new(
            file_hash(),
            size,
            Ed2kText::from_utf8("ab"),
        )],
    )
}

fn compression_grants() -> ServerGrants {
    ServerGrants {
        compression: true,
        ..ServerGrants::default()
    }
}

fn offer_to(grants: ServerGrants, id: u32, completeness: FileCompleteness) -> OfferFiles {
    OfferFiles::announce(
        grants,
        ClientId::from_u32(id),
        ClientId::from_u32(id),
        4662,
        &[OfferedFile::new(file_hash(), 42, Ed2kText::from_utf8("ab"))
            .with_completeness(completeness)],
    )
}

#[test]
fn offerfiles_opcode_byte() {
    assert_eq!(Opcode::OfferFiles.as_u8(), 0x15);
}

#[test]
fn empty_announce_is_a_zero_count_keepalive() {
    let packet = OfferFiles::announce(
        ServerGrants::default(),
        ClientId::from_u32(7),
        ClientId::from_u32(7),
        4662,
        &[],
    )
    .encode_packet();
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

/// A compression-flag server reads completeness off the entry's ID and port:
/// `251.251.251.251:0xFBFB` complete, `252.252.252.252:0xFCFC` incomplete,
/// whatever ID we hold (`KnownFile.cpp:1097-1107`).
#[test]
fn a_compression_server_gets_the_completeness_markers_for_any_id() {
    let complete_bytes: &[u8] = &[0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB];
    let incomplete_bytes: &[u8] = &[0xFC, 0xFC, 0xFC, 0xFC, 0xFC, 0xFC];
    for id in [0x0403_0201, 7, 0] {
        let complete = offer_to(compression_grants(), id, FileCompleteness::Complete);
        let payload = complete.encode_packet().payload().to_vec();
        assert_eq!(&payload[20..26], complete_bytes, "id {id:#x}");
        let incomplete = offer_to(compression_grants(), id, FileCompleteness::Incomplete);
        let payload = incomplete.encode_packet().payload().to_vec();
        assert_eq!(&payload[20..26], incomplete_bytes, "id {id:#x}");
    }
    let entry = offer_to(compression_grants(), 7, FileCompleteness::Incomplete);
    assert_eq!(entry.entries()[0].client_id().as_u32(), INCOMPLETE_FILE_ID);
    assert_eq!(entry.entries()[0].client_port(), INCOMPLETE_FILE_PORT);
    let entry = offer_to(compression_grants(), 7, FileCompleteness::Complete);
    assert_eq!(entry.entries()[0].client_id().as_u32(), COMPLETE_FILE_ID);
    assert_eq!(entry.entries()[0].client_port(), COMPLETE_FILE_PORT);
}

/// Any other server gets the ID and port only while the ID is High, and
/// `0:0` for a Low ID — an incomplete file is no different there
/// (`KnownFile.cpp:1108-1112`).
#[test]
fn a_plain_server_gets_the_id_and_port_only_for_a_high_id() {
    let high = offer_to(
        ServerGrants::default(),
        0x0403_0201,
        FileCompleteness::Incomplete,
    );
    assert_eq!(
        &high.encode_packet().payload()[20..26],
        &[0x01, 0x02, 0x03, 0x04, 0x36, 0x12]
    );
    let low = offer_to(ServerGrants::default(), 4242, FileCompleteness::Complete);
    assert_eq!(&low.encode_packet().payload()[20..26], &[0; 6]);
}

/// aMule gates on the eD2k ID but writes the Presented Client ID
/// (`KnownFile.cpp:1113-1115`): a High eD2k ID with a Kad-derived presented
/// one carries the presented bytes; a Low eD2k ID carries `0:0` whatever is
/// presented.
#[test]
fn the_gate_reads_the_ed2k_id_and_the_bytes_carry_the_presented_one() {
    let file = [OfferedFile::new(file_hash(), 42, Ed2kText::from_utf8("ab"))];
    let presented = ClientId::from_u32(0x0A0B_0C0D);
    let high = OfferFiles::announce(
        ServerGrants::default(),
        ClientId::from_u32(0x0403_0201),
        presented,
        4662,
        &file,
    );
    assert_eq!(
        &high.encode_packet().payload()[20..26],
        &[0x0D, 0x0C, 0x0B, 0x0A, 0x36, 0x12]
    );
    let low = OfferFiles::announce(
        ServerGrants::default(),
        ClientId::from_u32(4242),
        presented,
        4662,
        &file,
    );
    assert_eq!(&low.encode_packet().payload()[20..26], &[0; 6]);
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
