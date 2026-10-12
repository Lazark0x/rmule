//! Offering files through the session: rejected before login, written with our
//! own id and port after it, and split into the wide size form only when the
//! server advertised large-file support.

use rmule_ed2k::{
    CommandRejectReason, Ed2kCommand, Ed2kCommandKind, Ed2kEvent, FileCompleteness, OfferFiles,
    OfferedFile, Output, ServerCapability, ServerTcpFlags,
};
use rmule_primitives::{ClientId, Ed2kText, FileHash, Packet, PacketProtocol};

fn offered(size: u64) -> OfferedFile {
    OfferedFile::new(
        FileHash::from_bytes([0x11; FileHash::BYTE_LEN]),
        size,
        Ed2kText::from_utf8("ab"),
    )
}

#[test]
fn offer_files_before_login_emits_command_rejection() {
    let mut session = crate::fixture::started_session(0x42);

    session.handle_command(Ed2kCommand::OfferFiles {
        presented_id: None,
        files: vec![offered(42)],
    });

    assert!(matches!(
        session.poll_output(),
        Some(Output::Event(Ed2kEvent::CommandRejected {
            command: Ed2kCommandKind::OfferFiles,
            reason: CommandRejectReason::NotLoggedIn,
        }))
    ));
}

#[test]
fn offer_files_after_a_high_id_login_writes_our_id_and_port() {
    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_as(&mut session, 0x0403_0201, None);

    session.handle_command(Ed2kCommand::OfferFiles {
        presented_id: None,
        files: vec![offered(42)],
    });

    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("expected an OP_OFFERFILES write");
    };
    let packet = Packet::decode_exact(&bytes).unwrap();
    let offer = OfferFiles::decode_packet(&packet).unwrap();
    let entries = offer.entries();
    assert_eq!(entries.len(), 1);
    // Complete-source hint = our login-assigned id + identity port.
    assert_eq!(entries[0].client_id(), ClientId::from_u32(0x0403_0201));
    assert_eq!(entries[0].client_port(), 4662);
    assert_eq!(
        entries[0].file_hash(),
        FileHash::from_bytes([0x11; FileHash::BYTE_LEN])
    );
}

/// The session gates on the id its server assigned and writes the presented
/// id the command names, not its own.
#[test]
fn a_high_id_session_writes_the_presented_id_the_command_names() {
    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_as(&mut session, 0x0403_0201, None);

    session.handle_command(Ed2kCommand::OfferFiles {
        presented_id: Some(ClientId::from_u32(0x0A0B_0C0D)),
        files: vec![offered(42)],
    });

    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("expected an OP_OFFERFILES write");
    };
    let offer = OfferFiles::decode_packet(&Packet::decode_exact(&bytes).unwrap()).unwrap();
    assert_eq!(
        offer.entries()[0].client_id(),
        ClientId::from_u32(0x0A0B_0C0D)
    );
    assert_eq!(offer.entries()[0].client_port(), 4662);
}

#[test]
fn offer_files_after_a_low_id_login_writes_zero_id_and_port() {
    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(&mut session, None);

    session.handle_command(Ed2kCommand::OfferFiles {
        presented_id: None,
        files: vec![offered(42)],
    });

    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("expected an OP_OFFERFILES write");
    };
    let offer = OfferFiles::decode_packet(&Packet::decode_exact(&bytes).unwrap()).unwrap();
    assert_eq!(offer.entries()[0].client_id(), ClientId::from_u32(0));
    assert_eq!(offer.entries()[0].client_port(), 0);
}

/// The session reads the compression flag once at login and marks a part-file
/// `0xFCFCFCFC:0xFCFC` and a whole one `0xFBFBFBFB:0xFBFB`.
#[test]
fn a_compression_server_session_marks_each_file_by_completeness() {
    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(
        &mut session,
        Some(ServerTcpFlags::from_bits(ServerTcpFlags::COMPRESSION)),
    );

    session.handle_command(Ed2kCommand::OfferFiles {
        presented_id: None,
        files: vec![
            offered(42),
            offered(43).with_completeness(FileCompleteness::Incomplete),
        ],
    });

    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("expected an OP_OFFERFILES write");
    };
    let packet = Packet::decode_exact(&bytes).unwrap();
    let packet = if packet.protocol() == PacketProtocol::PackedEd2k {
        rmule_primitives::inflate(&packet, 250_000, PacketProtocol::Edonkey).expect("inflates")
    } else {
        packet
    };
    let offer = OfferFiles::decode_packet(&packet).unwrap();
    let marks: Vec<_> = offer
        .entries()
        .iter()
        .map(|e| (e.client_id().as_u32(), e.client_port()))
        .collect();
    assert_eq!(marks, [(0xFBFB_FBFB, 0xFBFB), (0xFCFC_FCFC, 0xFCFC)]);
}

#[test]
fn empty_offer_files_after_login_writes_zero_count_keepalive() {
    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(&mut session, None);

    session.handle_command(Ed2kCommand::OfferFiles {
        presented_id: None,
        files: vec![],
    });

    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("expected an OP_OFFERFILES write");
    };
    let packet = Packet::decode_exact(&bytes).unwrap();
    assert_eq!(packet.payload(), &[0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn large_offer_without_capability_is_rejected() {
    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(&mut session, None);

    session.handle_command(Ed2kCommand::OfferFiles {
        presented_id: None,
        files: vec![offered(u64::from(u32::MAX) + 1)],
    });

    assert!(matches!(
        session.poll_output(),
        Some(Output::Event(Ed2kEvent::CommandRejected {
            command: Ed2kCommandKind::OfferFiles,
            reason: CommandRejectReason::UnsupportedServerCapability {
                capability: ServerCapability::LargeFiles,
            },
        }))
    ));
}

#[test]
fn large_offer_with_capability_writes_split_size() {
    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(
        &mut session,
        Some(ServerTcpFlags::from_bits(ServerTcpFlags::LARGE_FILES)),
    );

    session.handle_command(Ed2kCommand::OfferFiles {
        presented_id: None,
        files: vec![offered(u64::from(u32::MAX) + 1)],
    });

    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("expected an OP_OFFERFILES write");
    };
    let packet = Packet::decode_exact(&bytes).unwrap();
    let offer = OfferFiles::decode_packet(&packet).unwrap();
    // FT_FILENAME + FT_FILESIZE + FT_FILESIZE_HI = 3 tags for a >4 GiB file.
    assert_eq!(offer.entries()[0].tags().len(), 3);
}

#[test]
fn offer_files_without_compression_flag_emits_plain() {
    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(&mut session, None);

    session.handle_command(Ed2kCommand::OfferFiles {
        presented_id: None,
        files: vec![offered(42)],
    });

    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("expected an OP_OFFERFILES write");
    };
    let packet = Packet::decode_exact(&bytes).unwrap();
    assert_eq!(
        packet.protocol(),
        PacketProtocol::Edonkey,
        "without compression flag, OfferFiles emits plain (Edonkey)"
    );
}

#[test]
fn offer_files_with_compression_flag_attempts_pack_when_payload_compressible() {
    use rmule_primitives::inflate;

    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(
        &mut session,
        Some(ServerTcpFlags::from_bits(ServerTcpFlags::COMPRESSION)),
    );

    // Announce a highly compressible file: repeated bytes compress well.
    let compressible_file = OfferedFile::new(
        FileHash::from_bytes([0xAA; FileHash::BYTE_LEN]),
        100_000,
        Ed2kText::from_utf8("x".repeat(1000)),
    );
    session.handle_command(Ed2kCommand::OfferFiles {
        presented_id: None,
        files: vec![compressible_file],
    });

    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("expected an OP_OFFERFILES write");
    };
    let packet = Packet::decode_exact(&bytes).unwrap();
    assert_eq!(
        packet.protocol(),
        PacketProtocol::PackedEd2k,
        "with compression flag and compressible payload, OfferFiles emits packed"
    );

    // Verify the packed frame round-trips through inflate.
    let inflated =
        inflate(&packet, 250_000, PacketProtocol::Edonkey).expect("packed payload should inflate");
    let offer = OfferFiles::decode_packet(&inflated).expect("inflated packet should decode");
    let entries = offer.entries();
    assert_eq!(entries.len(), 1);
}

#[test]
fn offer_files_emitted_size_is_smaller_with_compression_flag_on_compressible_data() {
    let highly_compressible = OfferedFile::new(
        FileHash::from_bytes([0xAA; FileHash::BYTE_LEN]),
        100_000,
        Ed2kText::from_utf8("x".repeat(1000)),
    );

    // Emit without compression flag
    let mut session_no_compression = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(&mut session_no_compression, None);
    session_no_compression.handle_command(Ed2kCommand::OfferFiles {
        presented_id: None,
        files: vec![highly_compressible.clone()],
    });
    let Some(Output::Write(plain_bytes)) = session_no_compression.poll_output() else {
        panic!("expected plain OP_OFFERFILES write");
    };

    // Emit with compression flag
    let mut session_with_compression = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(
        &mut session_with_compression,
        Some(ServerTcpFlags::from_bits(ServerTcpFlags::COMPRESSION)),
    );
    session_with_compression.handle_command(Ed2kCommand::OfferFiles {
        presented_id: None,
        files: vec![highly_compressible],
    });
    let Some(Output::Write(packed_bytes)) = session_with_compression.poll_output() else {
        panic!("expected packed OP_OFFERFILES write");
    };

    // Highly compressible payload should result in smaller wire bytes with compression.
    assert!(
        packed_bytes.len() < plain_bytes.len(),
        "compressed OfferFiles should be smaller than plain for compressible data"
    );
}
