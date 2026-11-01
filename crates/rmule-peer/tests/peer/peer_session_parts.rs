//! Receiving parts: 64-bit offsets, compressed-block reassembly, and the
//! refusals that keep a hostile peer from buying unbounded buffer — corrupt
//! inflate, an oversized declared length, and the session-wide in-flight
//! cap.

use rmule_peer::{
    FileProbeStatus, HelloAnswer, InflateFailed, PartRanges, PeerCommand, PeerEvent, PeerOutput,
    PeerSession, RequesterCommand, RequesterEvent,
};
use rmule_primitives::UserHash;
use rmule_primitives::session::drain;
use rmule_testkit::peer_session::*;

/// A session whose peer's hello carries no `MiscOptions2` at all, as a
/// client from before large files would.
fn no_large_files_session() -> PeerSession {
    let mut session = PeerSession::new_outbound(peer(), ctx());
    session.start();
    let _ = drain(|| session.poll_output());
    let mut body = answer_body(UserHash::from_bytes([0x98; 16]));
    body.tags.retain(|tag| tag.name().id() != Some(0xFE));
    session.handle_bytes(&HelloAnswer::new(body).encode_packet().encode());
    let _ = drain(|| session.poll_output());
    session
}

#[test]
fn sendingpart_i64_decodes_offset_above_4gb() {
    let h = file_hash(0x99);
    let mut session = identified_session();
    let big: u64 = 5_000_000_000;
    let len: u64 = 16;
    let ranges = PartRanges::new([(big, big + len), (0, 0), (0, 0)]);
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: h,
        file_size: 10_000_000_000,
        ranges,
    }));
    session.handle_bytes(&reqfilename_answer(h, "big"));
    session.handle_bytes(&file_status(h, 1028, &[0xFF; 129]));
    session.handle_bytes(&acceptuploadreq());
    let _ = drain(|| session.poll_output());

    let data: Vec<u8> = (0..len as u8).collect();
    session.handle_bytes(&sendingpart_i64(h, big, &data));
    let out = drain(|| session.poll_output());
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::Requester(RequesterEvent::PartReceived { offset, bytes, .. }) if *offset == big && bytes == &data
    )));
}

/// A block's own offsets pick the form, never the file's size
/// (`DownloadClient.cpp:745`): the blocks of an 8 GiB file below 4 GiB ride
/// `OP_REQUESTPARTS`, and one over the line takes the whole request to `_I64`.
#[test]
fn a_request_is_as_wide_as_its_highest_offset_not_as_its_file() {
    let h = file_hash(0x9A);
    let mut session = identified_session();
    let file_size = 8_000_000_000;
    let request = |session: &mut PeerSession, ranges: [(u64, u64); 3]| {
        session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
            file_hash: h,
            file_size,
            ranges: PartRanges::new(ranges),
        }));
    };
    let block = rmule_primitives::EMBLOCKSIZE;
    request(&mut session, [(0, block), (0, 0), (0, 0)]);
    session.handle_bytes(&reqfilename_answer(h, "big"));
    session.handle_bytes(&file_status(h, 823, &[0xFF; 103]));
    let _ = drain(|| session.poll_output());
    session.handle_bytes(&acceptuploadreq());
    let opcodes =
        |out: &[PeerOutput]| -> Vec<u8> { writes(out).iter().map(|p| p.opcode()).collect() };
    assert_eq!(opcodes(&drain(|| session.poll_output())), vec![0x47]);

    let past: u64 = 1 << 32;
    request(&mut session, [(past - block, past - 1), (0, 0), (0, 0)]);
    assert_eq!(opcodes(&drain(|| session.poll_output())), vec![0x47]);
    request(&mut session, [(past - 1, past + block), (0, 0), (0, 0)]);
    assert_eq!(opcodes(&drain(|| session.poll_output())), vec![0xA3]);
}

/// A peer whose hello claims no large files is asked nothing of one, and the
/// run reads it as a peer without the file, as a stock peer's answer would
/// have it (`ClientTCPSocket.cpp:1070`).
#[test]
fn a_peer_without_the_large_files_bit_is_asked_nothing() {
    let h = file_hash(0x9B);
    let big: u64 = rmule_primitives::OLD_MAX_FILE_SIZE + 1;
    let mut session = no_large_files_session();
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestFile {
        file_hash: h,
        file_size: big,
        want_sources: true,
        want_aich_root: false,
        own_status: rmule_peer::WireStatus::downloader_empty(big),
    }));
    let out = drain(|| session.poll_output());
    assert!(writes(&out).is_empty());
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::Requester(RequesterEvent::FileProbed {
            status: FileProbeStatus::NotAvailable,
            ..
        })
    )));
}

/// A grant on a large file such a peer never should have: the request goes
/// out as `OP_CANCELTRANSFER`, as stock's does past 4 GiB
/// (`DownloadClient.cpp:748-757`), and no block is asked.
#[test]
fn a_block_of_a_large_file_is_never_asked_of_a_peer_without_the_bit() {
    let h = file_hash(0x9C);
    let mut session = no_large_files_session();
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: h,
        file_size: 8_000_000_000,
        ranges: PartRanges::new([(5_000_000_000, 5_000_000_016), (0, 0), (0, 0)]),
    }));
    let out = drain(|| session.poll_output());
    let sent: Vec<u8> = writes(&out).iter().map(|p| p.opcode()).collect();
    assert_eq!(sent, vec![0x56]);
}

#[test]
fn compressed_part_inflates_to_part_received() {
    let h = file_hash(0x8C);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 64), (0, 0), (0, 0)]);
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    }));
    session.handle_bytes(&reqfilename_answer(h, "z"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
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
        PeerEvent::Requester(RequesterEvent::PartReceived { file_hash, offset: 0, bytes })
            if *file_hash == h && bytes == &plain
    )));
}

#[test]
fn corrupt_compressed_part_is_skipped_and_keeps_session_open() {
    let h = file_hash(0x8D);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 64), (0, 0), (0, 0)]);
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    }));
    session.handle_bytes(&reqfilename_answer(h, "z"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
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
        PeerEvent::Requester(RequesterEvent::CompressedPartSkipped { file_hash, offset: 0, .. }) if *file_hash == h
    )));
    assert!(
        !events(&out)
            .iter()
            .any(|e| matches!(e, PeerEvent::Requester(RequesterEvent::PartReceived { .. })))
    );
    assert!(!out.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

#[test]
fn oversized_declared_compressed_len_is_refused_before_buffering() {
    let h = file_hash(0x8E);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 64), (0, 0), (0, 0)]);
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    }));
    session.handle_bytes(&reqfilename_answer(h, "z"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    session.handle_bytes(&acceptuploadreq());
    let _ = drain(|| session.poll_output());

    // A hostile peer declares a ~4 GiB block. The session must refuse the
    // chunk up front — skip event, nothing buffered — instead of silently
    // accumulating toward a length no legal block can reach.
    session.handle_bytes(&compressedpart_chunk(h, 0, u32::MAX, &[0xAB; 1024]));
    let out = drain(|| session.poll_output());
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::Requester(RequesterEvent::CompressedPartSkipped {
            file_hash,
            offset: 0,
            reason: InflateFailed::DeclaredTooLarge { .. },
        }) if *file_hash == h
    )));
    // Non-terminal: the session stays open, like any other skipped block.
    assert!(!out.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

#[test]
fn inflight_compressed_blocks_are_capped_session_wide() {
    let h = file_hash(0x8F);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 64), (0, 0), (0, 0)]);
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    }));
    session.handle_bytes(&reqfilename_answer(h, "z"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    session.handle_bytes(&acceptuploadreq());
    let _ = drain(|| session.poll_output());

    // Fill the in-flight budget: 8 distinct starts, each declaring a small
    // block and delivering less than it, so none ever completes.
    for i in 0..8u32 {
        session.handle_bytes(&compressedpart_chunk(h, i * 100_000, 1_000, &[0x11; 10]));
    }
    let out = drain(|| session.poll_output());
    assert!(
        !events(&out).iter().any(|e| matches!(
            e,
            PeerEvent::Requester(RequesterEvent::CompressedPartSkipped { .. })
        )),
        "8 in-flight blocks are within budget"
    );

    // The 9th never-completing start is refused.
    session.handle_bytes(&compressedpart_chunk(h, 900_000, 1_000, &[0x11; 10]));
    let out = drain(|| session.poll_output());
    let refused = events(&out)
        .iter()
        .filter(|e| {
            matches!(
                e,
                PeerEvent::Requester(RequesterEvent::CompressedPartSkipped {
                    reason: InflateFailed::TooManyInFlight,
                    ..
                })
            )
        })
        .count();
    assert_eq!(refused, 1, "the 9th start is refused");

    // Completing an in-flight block frees its slot: junk bytes reaching the
    // declared length inflate-fail, the entry is dropped, and the same start
    // that was just refused is buffered again without a skip.
    session.handle_bytes(&compressedpart_chunk(h, 0, 1_000, &[0x11; 990]));
    let out = drain(|| session.poll_output());
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::Requester(RequesterEvent::CompressedPartSkipped {
            reason: InflateFailed::Corrupt,
            ..
        })
    )));
    session.handle_bytes(&compressedpart_chunk(h, 900_000, 1_000, &[0x11; 10]));
    let out = drain(|| session.poll_output());
    assert!(
        !events(&out).iter().any(|e| matches!(
            e,
            PeerEvent::Requester(RequesterEvent::CompressedPartSkipped { .. })
        )),
        "freed capacity admits a new in-flight block"
    );
}

/// A compressed block cut short by the slot's end goes with the slot: a chunk
/// still in flight after the end opens nothing, and the same block asked in
/// the next slot starts a fresh stream. aMule drops its pending blocks' zlib
/// streams when it leaves `DS_DOWNLOADING` (`DownloadClient.cpp:541-543`,
/// `BaseClient.cpp:1209-1245`) and reads no block outside it (`:836-838`).
#[test]
fn a_compressed_block_cut_by_the_slot_end_leaves_nothing_for_the_next_slot() {
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;

    let h = file_hash(0x8F);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 4096), (0, 0), (0, 0)]);
    let request = || {
        PeerCommand::Requester(RequesterCommand::RequestParts {
            file_hash: h,
            file_size: 1_000_000,
            ranges,
        })
    };
    session.handle_command(request());
    session.handle_bytes(&reqfilename_answer(h, "z"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    session.handle_bytes(&acceptuploadreq());
    let _ = drain(|| session.poll_output());

    let plain: Vec<u8> = b"compressible data ".repeat(64);
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&plain).unwrap();
    let zipped = encoder.finish().unwrap();
    let declared = zipped.len() as u32;
    let third = zipped.len() / 3;
    let chunks = [
        &zipped[..third],
        &zipped[third..2 * third],
        &zipped[2 * third..],
    ];

    // The uploader ends the slot one chunk into the block; the second chunk
    // was already on the wire.
    session.handle_bytes(&compressedpart_chunk(h, 0, declared, chunks[0]));
    session.handle_bytes(&outofpartreqs());
    session.handle_bytes(&compressedpart_chunk(h, 0, declared, chunks[1]));
    // The next grant: the block is asked again and sent whole.
    session.handle_command(request());
    session.handle_bytes(&acceptuploadreq());
    let _ = drain(|| session.poll_output());
    for chunk in chunks {
        session.handle_bytes(&compressedpart_chunk(h, 0, declared, chunk));
    }
    let out = drain(|| session.poll_output());

    let blocks: Vec<&PeerEvent> = events(&out)
        .into_iter()
        .filter(|event| {
            matches!(
                event,
                PeerEvent::Requester(
                    RequesterEvent::PartReceived { .. }
                        | RequesterEvent::CompressedPartSkipped { .. }
                )
            )
        })
        .collect();
    assert!(
        matches!(
            blocks.as_slice(),
            [PeerEvent::Requester(RequesterEvent::PartReceived { offset: 0, bytes, .. })]
                if *bytes == plain
        ),
        "the block inflates whole in the next slot: {blocks:?}"
    );
}
