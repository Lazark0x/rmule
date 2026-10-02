//! Receiving parts: 64-bit offsets, compressed-block reassembly, and the
//! refusals that keep a hostile peer from buying unbounded buffer — corrupt
//! inflate, an oversized declared length, and the session-wide in-flight
//! cap.

use rmule_peer::{InflateFailed, PartRanges, PeerCommand, PeerEvent, PeerOutput, PeerSession};
use rmule_primitives::session::drain;
use rmule_primitives::{PartHash, UserHash};
use rmule_testkit::peer_session::*;

#[test]
fn sendingpart_i64_decodes_offset_above_4gb() {
    let h = file_hash(0x99);
    let mut session = identified_session();
    let big: u64 = 5_000_000_000;
    let len: u64 = 16;
    let ranges = PartRanges::new([(big, big + len), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h,
        file_size: 10_000_000_000,
        ranges,
    });
    session.handle_bytes(&reqfilename_answer(h, "big"));
    session.handle_bytes(&file_status(h, 1029, &[0xFF; 129]));
    session.handle_bytes(&hashset_answer(h, &[PartHash::from_bytes([0; 16])]));
    session.handle_bytes(&acceptuploadreq());
    let _ = drain(|| session.poll_output());

    let data: Vec<u8> = (0..len as u8).collect();
    session.handle_bytes(&sendingpart_i64(h, big, &data));
    let out = drain(|| session.poll_output());
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::PartReceived { offset, bytes, .. } if *offset == big && bytes == &data
    )));
}

#[test]
fn compressed_part_inflates_to_part_received() {
    let h = file_hash(0x8C);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 64), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    });
    session.handle_bytes(&reqfilename_answer(h, "z"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    session.handle_bytes(&hashset_answer(h, &[PartHash::from_bytes([0; 16])]));
    session.handle_bytes(&acceptuploadreq());
    let _ = drain(|| session.poll_output());

    // The peer sends the block compressed; the session inflates it and
    // surfaces the SAME PartReceived event a raw OP_SENDINGPART would, so
    // core's block assembly is unchanged.
    let plain: Vec<u8> = b"compressible data ".repeat(8);
    session.handle_bytes(&compressedpart(h, 0, &plain));
    let out = drain(|| session.poll_output());
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::PartReceived { file_hash, offset: 0, bytes }
            if *file_hash == h && bytes == &plain
    )));
}

#[test]
fn corrupt_compressed_part_is_skipped_and_keeps_session_open() {
    let h = file_hash(0x8D);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 64), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    });
    session.handle_bytes(&reqfilename_answer(h, "z"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    session.handle_bytes(&hashset_answer(h, &[PartHash::from_bytes([0; 16])]));
    session.handle_bytes(&acceptuploadreq());
    let _ = drain(|| session.poll_output());

    // A corrupt compressed block must NOT crash the session: it surfaces a
    // non-terminal CompressedPartSkipped, no PartReceived, and stays open.
    session.handle_bytes(&corrupt_compressedpart(
        h,
        0,
        b"definitely not a zlib stream",
    ));
    let out = drain(|| session.poll_output());
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::CompressedPartSkipped { file_hash, offset: 0, .. } if *file_hash == h
    )));
    assert!(
        !events(&out)
            .iter()
            .any(|e| matches!(e, PeerEvent::PartReceived { .. }))
    );
    assert!(!out.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

#[test]
fn oversized_declared_compressed_len_is_refused_before_buffering() {
    let h = file_hash(0x8E);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 64), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    });
    session.handle_bytes(&reqfilename_answer(h, "z"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    session.handle_bytes(&hashset_answer(h, &[PartHash::from_bytes([0; 16])]));
    session.handle_bytes(&acceptuploadreq());
    let _ = drain(|| session.poll_output());

    // A hostile peer declares a ~4 GiB block. The session must refuse the
    // chunk up front — skip event, nothing buffered — instead of silently
    // accumulating toward a length no legal block can reach.
    session.handle_bytes(&compressedpart_chunk(h, 0, u32::MAX, &[0xAB; 1024]));
    let out = drain(|| session.poll_output());
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::CompressedPartSkipped {
            file_hash,
            offset: 0,
            reason: InflateFailed::DeclaredTooLarge { .. },
        } if *file_hash == h
    )));
    // Non-terminal: the session stays open, like any other skipped block.
    assert!(!out.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

#[test]
fn inflight_compressed_blocks_are_capped_session_wide() {
    let h = file_hash(0x8F);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 64), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    });
    session.handle_bytes(&reqfilename_answer(h, "z"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    session.handle_bytes(&hashset_answer(h, &[PartHash::from_bytes([0; 16])]));
    session.handle_bytes(&acceptuploadreq());
    let _ = drain(|| session.poll_output());

    // Fill the in-flight budget: 8 distinct starts, each declaring a small
    // block and delivering less than it, so none ever completes.
    for i in 0..8u32 {
        session.handle_bytes(&compressedpart_chunk(h, i * 100_000, 1_000, &[0x11; 10]));
    }
    let out = drain(|| session.poll_output());
    assert!(
        !events(&out)
            .iter()
            .any(|e| matches!(e, PeerEvent::CompressedPartSkipped { .. })),
        "8 in-flight blocks are within budget"
    );

    // The 9th never-completing start is refused — and the cap is session-wide:
    // a second file we probed (so its flow exists) is refused just the same.
    let h2 = file_hash(0x90);
    session.handle_command(PeerCommand::ProbeFile {
        file_hash: h2,
        file_size: 20_000_000,
        own_status: rmule_peer::PartBitmap::downloader_empty(20_000_000),
    });
    let _ = drain(|| session.poll_output());
    session.handle_bytes(&compressedpart_chunk(h, 900_000, 1_000, &[0x11; 10]));
    session.handle_bytes(&compressedpart_chunk(h2, 0, 1_000, &[0x11; 10]));
    let out = drain(|| session.poll_output());
    let refused = events(&out)
        .iter()
        .filter(|e| {
            matches!(
                e,
                PeerEvent::CompressedPartSkipped {
                    reason: InflateFailed::TooManyInFlight,
                    ..
                }
            )
        })
        .count();
    assert_eq!(refused, 2, "9th start and cross-file start both refused");

    // Completing an in-flight block frees its slot: junk bytes reaching the
    // declared length inflate-fail, the entry is dropped, and the same start
    // that was just refused is buffered again without a skip.
    session.handle_bytes(&compressedpart_chunk(h, 0, 1_000, &[0x11; 990]));
    let out = drain(|| session.poll_output());
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::CompressedPartSkipped {
            reason: InflateFailed::Corrupt,
            ..
        }
    )));
    session.handle_bytes(&compressedpart_chunk(h, 900_000, 1_000, &[0x11; 10]));
    let out = drain(|| session.poll_output());
    assert!(
        !events(&out)
            .iter()
            .any(|e| matches!(e, PeerEvent::CompressedPartSkipped { .. })),
        "freed capacity admits a new in-flight block"
    );
}

#[test]
fn served_compressed_block_round_trips_into_a_requester() {
    // Cycle 7 loopback: a serving rmule session's REAL OP_COMPRESSEDPART wire
    // bytes are consumed by a separate requesting rmule session and inflate
    // back to the original block — proving serve-encode ↔ requester-decode
    // are wire-compatible end to end.
    use rmule_peer::{Hello, MiscOptions1};

    let fh = file_hash(0xA1);
    let plain: Vec<u8> = b"loopback compressible payload ".repeat(40);

    // Server: an inbound rmule session whose peer advertised compression.
    let mut server = PeerSession::new_inbound(peer(), ctx());
    let mut peer_hello = answer_body(UserHash::from_bytes([0x55; 16]));
    peer_hello
        .tags
        .push(MiscOptions1::rmule_advertised().to_tag());
    server.handle_bytes(&Hello::new(peer_hello).encode_packet().encode());
    let _ = drain(|| server.poll_output());
    server.handle_command(PeerCommand::GrantSlot { file_hash: fh });
    let _ = drain(|| server.poll_output());
    server.handle_command(PeerCommand::SendBlock {
        file_hash: fh,
        start: 0,
        end: plain.len() as u64,
        bytes: plain.clone(),
    });
    let compressed_wire = last_write_bytes(&drain(|| server.poll_output()));

    // Requester: a separate rmule session driven to Downloading for `fh`.
    let mut client = identified_session();
    let ranges = PartRanges::new([(0, plain.len() as u64), (0, 0), (0, 0)]).unwrap();
    client.handle_command(PeerCommand::RequestParts {
        file_hash: fh,
        file_size: 1_000_000,
        ranges,
    });
    client.handle_bytes(&reqfilename_answer(fh, "x"));
    client.handle_bytes(&file_status(fh, 1, &[0x01]));
    client.handle_bytes(&hashset_answer(fh, &[PartHash::from_bytes([0; 16])]));
    client.handle_bytes(&acceptuploadreq());
    let _ = drain(|| client.poll_output());

    client.handle_bytes(&compressed_wire);
    let out = drain(|| client.poll_output());
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::PartReceived { file_hash, offset: 0, bytes }
            if *file_hash == fh && bytes == &plain
    )));
}
