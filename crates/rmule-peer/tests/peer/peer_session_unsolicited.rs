//! Answers nobody asked for. An unsolicited probe answer, no-file, hash
//! set, source list or compressed block is diagnosed and discarded: hearsay
//! never seeds state, never poisons a later request, and never holds
//! in-flight budget.

use rmule_peer::{
    FileProbeStatus, NoticeEvent, PartRanges, PeerCommand, PeerEvent, RequesterCommand,
    RequesterEvent,
};
use rmule_primitives::session::drain;
use rmule_primitives::{ED2K_PART_SIZE, PartHash};
use rmule_testkit::peer_session::*;

#[test]
fn unsolicited_probe_answers_do_not_seed_state_or_emit_probed() {
    let h = file_hash(0x91);
    let mut session = identified_session();
    // Answers for a hash rmule never probed or requested must be dropped,
    // not assembled into a FileProbed event.
    session.handle_bytes(&reqfilename_answer(h, "planted"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    let out = drain(|| session.poll_output());
    assert!(
        !events(&out)
            .iter()
            .any(|e| matches!(e, PeerEvent::Requester(RequesterEvent::FileProbed { .. }))),
        "unsolicited answers must not probe: {out:?}"
    );
    // A real probe afterwards starts from scratch and completes.
    session.handle_command(PeerCommand::Requester(RequesterCommand::ProbeFile {
        file_hash: h,
        file_size: 20_000_000,
        own_status: rmule_peer::PartBitmap::downloader_empty(20_000_000),
    }));
    let out = drain(|| session.poll_output());
    assert!(writes(&out).iter().any(|p| p.opcode() == 0x58));
    session.handle_bytes(&reqfilename_answer(h, "real"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    let out = drain(|| session.poll_output());
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::Requester(RequesterEvent::FileProbed {
            file_hash,
            status: FileProbeStatus::Available { .. },
        }) if *file_hash == h
    )));
}

#[test]
fn unsolicited_nofil_does_not_poison_a_later_request() {
    let h = file_hash(0x92);
    let mut session = identified_session();
    // A planted FILEREQANSNOFIL for a file rmule never asked about.
    session.handle_bytes(&filereqansnofil(h));
    let _ = drain(|| session.poll_output());

    // A later legitimate request must not be vetoed by it.
    let ranges = PartRanges::new([(0, 64), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    }));
    let out = drain(|| session.poll_output());
    assert!(
        !events(&out)
            .iter()
            .any(|e| matches!(e, PeerEvent::Notice(NoticeEvent::CommandRejected { .. }))),
        "planted NOFIL must not veto the request: {out:?}"
    );
    assert!(
        writes(&out).iter().any(|p| p.opcode() == 0x58),
        "the probe is issued fresh"
    );
}

#[test]
fn unsolicited_compressed_parts_hold_no_inflight_budget() {
    let mut session = identified_session();
    // 8 never-completing blocks for hashes rmule never engaged: dropped
    // without creating state or consuming in-flight budget.
    for i in 0..8u8 {
        session.handle_bytes(&compressedpart_chunk(
            file_hash(0xA0 + i),
            0,
            1_000,
            &[0x22; 10],
        ));
    }
    let _ = drain(|| session.poll_output());

    // A legitimate transfer afterwards still has its full budget.
    let h = file_hash(0x93);
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

    let plain: Vec<u8> = b"still compressible ".repeat(8);
    session.handle_bytes(&compressedpart(h, 0, &plain));
    let out = drain(|| session.poll_output());
    assert!(
        events(&out).iter().any(|e| matches!(
            e,
            PeerEvent::Requester(RequesterEvent::PartReceived { file_hash, offset: 0, bytes })
                if *file_hash == h && bytes == &plain
        )),
        "legit block inflates despite the earlier junk: {out:?}"
    );
    assert!(!events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::Requester(RequesterEvent::CompressedPartSkipped { .. })
    )));
}

#[test]
fn unsolicited_answer_sources_is_dropped() {
    let h = file_hash(0x94);
    let mut session = identified_session();
    let source = (u32::from_le_bytes([9, 8, 7, 6]), 4662u16);
    // Sources for a file rmule never requested are dropped.
    session.handle_bytes(&answer_sources_wire(h, &[source]));
    let out = drain(|| session.poll_output());
    assert!(
        !events(&out).iter().any(|e| matches!(
            e,
            PeerEvent::Requester(RequesterEvent::SourcesReceived { .. })
        )),
        "unsolicited sources dropped: {out:?}"
    );
    // Once the file's flow is open, its sources are taken. The flow is opened
    // by the name ask: an SX1 nibble-1 peer is never asked for sources
    // (ADR-0108), and this test's subject is the flow gate.
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestFile {
        file_hash: h,
        file_size: 4096,
        own_status: rmule_peer::PartBitmap::downloader_empty(4096),
        want_sources: false,
        want_aich_root: false,
    }));
    let _ = drain(|| session.poll_output());
    session.handle_bytes(&answer_sources_wire(h, &[source]));
    let out = drain(|| session.poll_output());
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::Requester(RequesterEvent::SourcesReceived { .. })
    )));
}

#[test]
fn unsolicited_hashset_answer_does_not_precache() {
    let h = file_hash(0x95);
    let mut session = identified_session();
    // A planted hash-set answer for a file rmule never requested.
    session.handle_bytes(&hashset_answer(h, &[PartHash::from_bytes([0; 16])]));
    let _ = drain(|| session.poll_output());

    // A real multi-part download afterwards must still fetch the hash set
    // instead of trusting the planted "cache".
    let ranges = PartRanges::new([(0, 64), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: h,
        file_size: ED2K_PART_SIZE + 1,
        ranges,
    }));
    let out = drain(|| session.poll_output());
    assert!(
        writes(&out).iter().any(|p| p.opcode() == 0x51),
        "hash set requested despite the planted answer: {out:?}"
    );
}
