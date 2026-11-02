//! Answers nobody asked for that stock lets pass. A no-file, a source list or
//! a compressed block outside a slot is diagnosed and discarded: hearsay never
//! seeds state, never poisons a later request, and never holds in-flight
//! budget. The ones stock's readers throw on are `peer_frame_legs`' rows.

use rmule_peer::{
    NoticeEvent, PartRanges, PeerCommand, PeerEvent, RequesterCommand, RequesterEvent,
};
use rmule_primitives::session::drain;
use rmule_testkit::peer_session::*;

#[test]
fn unsolicited_nofil_does_not_poison_a_later_request() {
    let h = file_hash(0x92);
    let mut session = identified_session();
    // A planted FILEREQANSNOFIL for a file rmule never asked about.
    session.handle_bytes(&filereqansnofil(h));
    let _ = drain(|| session.poll_output());

    // A later legitimate request must not be vetoed by it.
    let ranges = PartRanges::new([(0, 64), (0, 0), (0, 0)]);
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
        own_status: rmule_peer::WireStatus::downloader_empty(4096),
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
fn a_frame_declared_past_the_peer_ceiling_closes_at_its_header() {
    let mut session = identified_session();
    let declared = 1_048_577_u32;
    let mut header = vec![0xE3];
    header.extend_from_slice(&declared.to_le_bytes());

    session.handle_bytes(&header);

    let out = drain(|| session.poll_output());
    assert!(
        out.iter()
            .any(|output| matches!(output, rmule_peer::PeerOutput::Close(_))),
        "{out:?}"
    );
}
