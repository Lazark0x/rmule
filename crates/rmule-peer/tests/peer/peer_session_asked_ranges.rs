//! The link's Asked Ranges (ADR-0107 "How a grant hands over"): a grant after
//! a silent release to another file names every range the link asked, and
//! a `0x56` we send or a `0x57` we read forgets them, as aMule's
//! `RemoveFromUploadQueue` clears its done list (`UploadQueue.cpp:540-541`).

use rmule_peer::{
    AskedRanges, PartRanges, PeerCommand, PeerEvent, PeerSession, RequesterCommand, RequesterEvent,
};
use rmule_primitives::FileHash;
use rmule_primitives::session::drain;
use rmule_testkit::peer_session::*;

const BLOCK: u64 = rmule_peer::EMBLOCKSIZE;
/// One part: the name answer alone settles its probe.
const SIZE: u64 = 1_000_000;

fn first_blocks() -> [(u64, u64); 3] {
    [(0, BLOCK), (BLOCK, 2 * BLOCK), (2 * BLOCK, 3 * BLOCK)]
}

/// `file` asks its first three blocks, is granted and sends them.
fn granted_and_asked(session: &mut PeerSession, file: FileHash) {
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: file,
        file_size: SIZE,
        ranges: PartRanges::new(first_blocks()).unwrap(),
    }));
    session.handle_bytes(&reqfilename_answer(file, "first.bin"));
    session.handle_bytes(&acceptuploadreq());
    let _ = drain(|| session.poll_output());
}

/// The ranges the next grant of `file`'s slot names.
fn asked_at_grant(session: &mut PeerSession, file: FileHash) -> AskedRanges {
    session.handle_command(PeerCommand::Requester(RequesterCommand::AskSlot {
        file_hash: file,
    }));
    session.handle_bytes(&acceptuploadreq());
    let out = drain(|| session.poll_output());
    events(&out)
        .into_iter()
        .find_map(|event| match event {
            PeerEvent::Requester(RequesterEvent::SlotGranted { file_hash, asked })
                if *file_hash == file =>
            {
                Some(asked.clone())
            }
            _ => None,
        })
        .expect("the ask is granted")
}

#[test]
fn a_grant_after_a_silent_release_names_the_ranges_the_link_asked() {
    let (first, second) = (file_hash(0x31), file_hash(0x32));
    let mut session = identified_session();
    granted_and_asked(&mut session, first);
    session.handle_command(PeerCommand::Requester(RequesterCommand::ReleaseSlot {
        file_hash: first,
    }));
    let asked = asked_at_grant(&mut session, second);
    for (start, end) in first_blocks() {
        assert!(
            asked.contains(start, end),
            "{start}..{end} is held: {asked:?}"
        );
    }
}

#[test]
fn a_cancel_we_send_forgets_the_asked_ranges() {
    let (first, second) = (file_hash(0x33), file_hash(0x34));
    let mut session = identified_session();
    granted_and_asked(&mut session, first);
    session.handle_command(PeerCommand::Requester(RequesterCommand::CancelTransfer {
        file_hash: first,
    }));
    assert!(asked_at_grant(&mut session, second).is_empty());
}

#[test]
fn an_out_of_part_reqs_forgets_the_asked_ranges() {
    let file = file_hash(0x35);
    let mut session = identified_session();
    granted_and_asked(&mut session, file);
    session.handle_bytes(&outofpartreqs());
    session.handle_bytes(&acceptuploadreq());
    let out = drain(|| session.poll_output());
    assert!(events(&out).iter().any(|event| matches!(
        event,
        PeerEvent::Requester(RequesterEvent::SlotGranted { file_hash, asked })
            if *file_hash == file && asked.is_empty()
    )));
}
