//! Receiving parts: 64-bit offsets, compressed-block reassembly, and the
//! refusals that keep a hostile peer from buying unbounded buffer — corrupt
//! inflate, an oversized declared length, and the session-wide in-flight
//! cap.

use rmule_peer::{
    InflateFailed, PartRanges, PeerCommand, PeerEvent, PeerOutput, RequesterCommand, RequesterEvent,
};
use rmule_primitives::PartHash;
use rmule_primitives::session::drain;
use rmule_testkit::peer_session::*;

#[test]
fn sendingpart_i64_decodes_offset_above_4gb() {
    let h = file_hash(0x99);
    let mut session = identified_session();
    let big: u64 = 5_000_000_000;
    let len: u64 = 16;
    let ranges = PartRanges::new([(big, big + len), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: h,
        file_size: 10_000_000_000,
        ranges,
    }));
    session.handle_bytes(&reqfilename_answer(h, "big"));
    session.handle_bytes(&file_status(h, 1028, &[0xFF; 129]));
    session.handle_bytes(&hashset_answer(h, &[PartHash::from_bytes([0; 16])]));
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

#[test]
fn compressed_part_inflates_to_part_received() {
    let h = file_hash(0x8C);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 64), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    }));
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
        PeerEvent::Requester(RequesterEvent::PartReceived { file_hash, offset: 0, bytes })
            if *file_hash == h && bytes == &plain
    )));
}

#[test]
fn corrupt_compressed_part_is_skipped_and_keeps_session_open() {
    let h = file_hash(0x8D);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 64), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    }));
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
    let ranges = PartRanges::new([(0, 64), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    }));
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
    let ranges = PartRanges::new([(0, 64), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    }));
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
        !events(&out).iter().any(|e| matches!(
            e,
            PeerEvent::Requester(RequesterEvent::CompressedPartSkipped { .. })
        )),
        "8 in-flight blocks are within budget"
    );

    // The 9th never-completing start is refused. A second file we probed (so
    // its flow exists) holds no granted slot, so its chunk opens nothing.
    let h2 = file_hash(0x90);
    session.handle_command(PeerCommand::Requester(RequesterCommand::ProbeFile {
        file_hash: h2,
        file_size: 20_000_000,
        own_status: rmule_peer::PartBitmap::downloader_empty(20_000_000),
    }));
    let _ = drain(|| session.poll_output());
    session.handle_bytes(&compressedpart_chunk(h, 900_000, 1_000, &[0x11; 10]));
    session.handle_bytes(&compressedpart_chunk(h2, 0, 1_000, &[0x11; 10]));
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
    assert_eq!(
        events(&out).len(),
        1,
        "the other file's chunk is dropped unread"
    );

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
    let ranges = PartRanges::new([(0, 4096), (0, 0), (0, 0)]).unwrap();
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
    session.handle_bytes(&hashset_answer(h, &[PartHash::from_bytes([0; 16])]));
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
