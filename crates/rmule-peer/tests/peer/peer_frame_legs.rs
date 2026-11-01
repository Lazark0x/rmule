//! Every malformed-frame leg of the peer link, as a table: which frames cost
//! the link and which it keeps, read from stock 2.3.3's whole handler
//! (`ClientTCPSocket.cpp` `ProcessPacket`, `ProcessExtPacket`,
//! `PacketReceived`'s catch at `:2018-2047`) and the `CUpDownClient` readers
//! they call. A thrown read closes; a logged return does not, and
//! `ProcessBlockPacket`'s own `catch (CEOFException)`
//! (`DownloadClient.cpp:1039`) makes a cut block a logged return. Each row
//! drives the session by bytes and reads its outputs.

use crate::fixture::{identified_session, plain_hello_body};
use rmule_peer::{
    Hello, NoticeEvent, PartRanges, PeerCloseReason, PeerCommand, PeerEvent, PeerOutput,
    PeerSession, PeerViolation, RequesterCommand, ServerEvent, WireStatus,
};
use rmule_primitives::session::drain;
use rmule_primitives::{FileHash, Packet, PacketProtocol, UserHash};
use rmule_testkit::peer_session::{ctx, peer};

use PacketProtocol::{Edonkey, Emule};

const FILE: [u8; 16] = [0xAB; 16];
const OTHER: [u8; 16] = [0xCD; 16];
const FILE_SIZE: u64 = 3 * 9_728_000 + 10;

fn hash(bytes: [u8; 16]) -> FileHash {
    FileHash::from_bytes(bytes)
}

/// What a frame cost the link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cost {
    Keeps,
    Closes(PeerViolation),
}
use Cost::{Closes, Keeps};

const MALFORMED: Cost = Closes(PeerViolation::MalformedFrame);

fn cost_of(session: &mut PeerSession, frame: &Packet) -> Cost {
    session.handle_bytes(&frame.encode());
    let outputs = drain(|| session.poll_output());
    match outputs.last() {
        Some(PeerOutput::Close(PeerCloseReason::ProtocolViolation(violation))) => {
            Closes(*violation)
        }
        Some(PeerOutput::Close(other)) => panic!("closed for {other:?}"),
        _ => Keeps,
    }
}

fn frame(protocol: PacketProtocol, opcode: u8, body: &[u8]) -> Packet {
    Packet::new(protocol, opcode, body.to_vec())
}

fn with_file(tail: &[u8]) -> Vec<u8> {
    let mut body = FILE.to_vec();
    body.extend_from_slice(tail);
    body
}

fn of_other_file(tail: &[u8]) -> Vec<u8> {
    let mut body = OTHER.to_vec();
    body.extend_from_slice(tail);
    body
}

/// An identified link with `FILE` asked: a flow exists for it.
fn asking_session() -> PeerSession {
    let mut session = identified_session();
    session.handle_command(PeerCommand::Requester(RequesterCommand::ProbeFile {
        file_hash: hash(FILE),
        file_size: FILE_SIZE,
        own_status: WireStatus::downloader_empty(FILE_SIZE),
    }));
    let _ = drain(|| session.poll_output());
    session
}

/// An identified link holding a granted slot for `FILE`.
fn downloading_session() -> PeerSession {
    let mut session = identified_session();
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: hash(FILE),
        file_size: FILE_SIZE,
        ranges: PartRanges::new([(0, 10), (0, 0), (0, 0)]),
    }));
    session.handle_bytes(&frame(Edonkey, 0x59, &with_file(&[1, 0, b'n'])).encode());
    session.handle_bytes(&frame(Edonkey, 0x50, &with_file(&[0, 0])).encode());
    session.handle_bytes(&frame(Edonkey, 0x55, &[]).encode());
    let _ = drain(|| session.poll_output());
    session
}

fn dialed_session() -> PeerSession {
    let mut session = PeerSession::new_outbound(peer(), ctx());
    session.start();
    let _ = drain(|| session.poll_output());
    session
}

fn dialing_session() -> PeerSession {
    PeerSession::new_inbound(peer(), ctx())
}

/// `ClientTCPSocket.cpp:307-308`, `:1027-1029`: before a hello there is no
/// client, and every frame but `OP_HELLO` throws, under either protocol.
#[test]
fn before_the_hello_only_the_hello_is_read() {
    let hello = Hello::new(plain_hello_body(UserHash::from_bytes([7; 16]))).encode_packet();
    assert_eq!(cost_of(&mut dialing_session(), &hello), Keeps);
    for early in [
        frame(Edonkey, 0x58, &with_file(&[])),
        frame(Edonkey, 0x4C, &[]),
        frame(Edonkey, 0x77, &[1]),
        frame(Emule, 0x9F, &[]),
        frame(Emule, 0x77, &[1]),
    ] {
        assert_eq!(
            cost_of(&mut dialing_session(), &early),
            Closes(PeerViolation::BeforeHello),
            "{early:?}"
        );
    }
}

/// A packed frame that does not inflate is skipped before any of that
/// (`:1985-1988`); one that does is an eMule frame like any other.
#[test]
fn a_packed_frame_before_the_hello_costs_the_link_only_once_it_inflates() {
    let junk = frame(PacketProtocol::PackedEd2k, 0x9F, &[1, 2, 3]);
    assert_eq!(cost_of(&mut dialing_session(), &junk), Keeps);
    let packed = rmule_primitives::pack_if_smaller(frame(Emule, 0x9F, &[0; 400]));
    assert_eq!(packed.protocol(), PacketProtocol::PackedEd2k);
    assert_eq!(
        cost_of(&mut dialing_session(), &packed),
        Closes(PeerViolation::BeforeHello)
    );
}

/// `CheckHandshakeFinished` throws on these while our hello is unanswered, and
/// on no other opcode (`:1053`, `:1208`, `:1301`, `:1330`, `:1342`, `:1360`,
/// `:1421`, `:1442`, `:1504`, `:1528`, `:1554`).
#[test]
fn before_the_hello_answer_the_handshake_gated_frames_close() {
    for opcode in [
        0x92, 0xA4, 0x93, 0x87, 0x85, 0x86, 0x40, 0xA1, 0xA2, 0x60, 0x81, 0x83, 0x82, 0x84, 0x61,
    ] {
        assert_eq!(
            cost_of(&mut dialed_session(), &frame(Emule, opcode, &[])),
            Closes(PeerViolation::HandshakeUnfinished),
            "0x{opcode:02X}"
        );
    }
    for (protocol, opcode, body) in [
        (Edonkey, 0x58, with_file(&[])),
        (Edonkey, 0x46, vec![0; 3]),
        (Edonkey, 0x54, with_file(&[])),
        (Emule, 0x9F, vec![]),
        (Emule, 0xA3, vec![0; 64]),
    ] {
        assert_eq!(
            cost_of(&mut dialed_session(), &frame(protocol, opcode, &body)),
            Keeps,
            "0x{opcode:02X}"
        );
    }
}

/// The rows the review named, and their shorter neighbours where stock's read
/// throws.
#[test]
fn a_frame_stock_reads_no_further_keeps_the_link() {
    let key = |len: u8, body: usize| {
        let mut bytes = vec![len];
        bytes.extend(std::iter::repeat_n(0u8, body));
        bytes
    };
    let rows: Vec<(PacketProtocol, u8, Vec<u8>)> = vec![
        // No size check: `:637-667`, `:755-762`.
        (Edonkey, 0x55, vec![1, 2]),
        (Edonkey, 0x57, vec![1, 2]),
        // Reads eight, `:774-775`.
        (Edonkey, 0x4D, vec![0; 11]),
        // `ProcessPublicKeyPacket`, `BaseClient.cpp:2128-2150`: returns.
        (Emule, 0x85, key(9, 3)),
        (Emule, 0x85, vec![]),
        (Emule, 0x85, key(255, 255)),
        // `ProcessSignaturePacket`, `BaseClient.cpp:2164-2190`: returns.
        (Emule, 0x86, vec![]),
        (Emule, 0x86, key(255, 255)),
        (Emule, 0x86, key(9, 3)),
        // `ProcessSecIdentStatePacket`, `BaseClient.cpp:2252-2271`: returns.
        (Emule, 0x87, vec![1, 2]),
        (Emule, 0x87, vec![9, 0, 0, 0, 0]),
        // Reads the hash, `:1672-1686`, and the root after it.
        (Emule, 0x9E, with_file(&[1, 2])),
        (Emule, 0x9D, with_file(&[0; 22])),
        // Reads the hash and six offsets, `UploadClient.cpp:839-861`.
        (Edonkey, 0x47, with_file(&[0; 26])),
        (Emule, 0xA3, with_file(&[0; 50])),
        // An opcode stock does not know, `:1001-1004`.
        (Edonkey, 0xAC, vec![1, 2, 3]),
        (Edonkey, 0x5B, vec![1]),
    ];
    for (protocol, opcode, body) in rows {
        assert_eq!(
            cost_of(&mut identified_session(), &frame(protocol, opcode, &body)),
            Keeps,
            "0x{opcode:02X} {body:?}"
        );
    }
}

/// Stock's read throws here, so the link goes; rmule read past these before.
#[test]
fn a_frame_stock_cannot_read_closes_the_link() {
    let rows: Vec<(PacketProtocol, u8, Vec<u8>)> = vec![
        // `ClientTCPSocket.cpp:649-652`: four bytes of rank.
        (Edonkey, 0x5C, vec![1, 2, 3]),
        // The directory string is read first, `:923`, `:963`.
        (Edonkey, 0x5E, vec![5, 0, b'a']),
        (Edonkey, 0x60, vec![5, 0, b'a']),
        // Eight bytes of change, `:774-775`.
        (Edonkey, 0x4D, vec![0; 7]),
        // The hash, and the root, `:1646`, `:1683`.
        (Emule, 0x9D, with_file(&[0; 19])),
        (Emule, 0x9E, vec![0; 15]),
        (Edonkey, 0x47, with_file(&[0; 23])),
        (Emule, 0xA3, with_file(&[0; 47])),
        // A source answer's hash, `:1508`, `:1532-1533`.
        (Emule, 0x82, vec![0; 15]),
        (Emule, 0x84, vec![1; 16]),
    ];
    for (protocol, opcode, body) in rows {
        assert_eq!(
            cost_of(&mut identified_session(), &frame(protocol, opcode, &body)),
            MALFORMED,
            "0x{opcode:02X} {body:?}"
        );
    }
}

/// `ProcessFileInfo`, `ProcessFileStatus`, `ProcessHashSet` and the bundle's
/// walk all throw on a file this client was not asked about
/// (`DownloadClient.cpp:339-348`, `:390-396`, `:573-578`,
/// `ClientTCPSocket.cpp:1213-1224`); the comment reader on no asked file at
/// all (`BaseClient.cpp:1178-1183`).
#[test]
fn an_answer_about_a_file_never_asked_closes_the_link() {
    let rows = [
        frame(Edonkey, 0x59, &with_file(&[1, 0, b'n'])),
        frame(Edonkey, 0x50, &with_file(&[0, 0])),
        frame(Edonkey, 0x52, &with_file(&[0, 0])),
        frame(Emule, 0x93, &with_file(&[])),
        frame(Emule, 0x93, &with_file(&[0x77])),
        frame(Emule, 0x61, &[1, 0, 0, 0, 0]),
    ];
    for answer in rows {
        assert_eq!(
            cost_of(&mut identified_session(), &answer),
            Closes(PeerViolation::WrongFile),
            "{answer:?}"
        );
    }
    let mut asked = asking_session();
    assert_eq!(
        cost_of(&mut asked, &frame(Edonkey, 0x59, &of_other_file(&[0, 0]))),
        Closes(PeerViolation::WrongFile)
    );
}

/// Bytes after what the readers take are never looked at.
#[test]
fn an_answer_about_the_asked_file_reads_only_what_it_takes() {
    for answer in [
        frame(Edonkey, 0x59, &with_file(&[1, 0, b'n', 9, 9])),
        frame(Edonkey, 0x50, &with_file(&[0, 0, 9, 9])),
        frame(Edonkey, 0x50, &with_file(&[4, 0, 0b1111, 9, 9])),
    ] {
        assert_eq!(cost_of(&mut asking_session(), &answer), Keeps, "{answer:?}");
    }
    assert_eq!(
        cost_of(
            &mut asking_session(),
            &frame(Edonkey, 0x50, &with_file(&[4, 0]))
        ),
        MALFORMED,
        "the bitmap is read part by part and throws at its end"
    );
}

/// `ProcessHashSet`, `DownloadClient.cpp:576-578`: only a set this client is
/// waiting for is read, so a second one closes too.
#[test]
fn an_unasked_hash_set_closes_and_an_asked_one_reads_past_its_hashes() {
    let answer = frame(Edonkey, 0x52, &with_file(&[0, 0, 9, 9]));
    assert_eq!(
        cost_of(&mut asking_session(), &answer),
        Closes(PeerViolation::Unsolicited)
    );
    let mut session = asking_session();
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestHashSet {
        file_hash: hash(FILE),
    }));
    let _ = drain(|| session.poll_output());
    assert_eq!(cost_of(&mut session, &answer), Keeps);
    assert_eq!(
        cost_of(&mut session, &answer),
        Closes(PeerViolation::Unsolicited)
    );
}

/// `ProcessAICHAnswer`, `DownloadClient.cpp:1606-1608`: an answer to no ask
/// closes, whatever its shape; a cut one past the ask's own file is a
/// refusal, since the root is read only for the file asked (`:1625-1626`).
#[test]
fn an_aich_answer_is_read_only_after_an_ask() {
    let asked = |part| {
        let mut session = identified_session();
        session.handle_command(PeerCommand::Requester(RequesterCommand::RequestAich {
            file_hash: hash(FILE),
            part,
            root: rmule_primitives::AichRootHash::from_bytes([3; 20]),
        }));
        let _ = drain(|| session.poll_output());
        session
    };
    for unasked in [
        frame(Emule, 0x9C, &with_file(&[])),
        frame(Emule, 0x9C, &with_file(&[1, 0])),
    ] {
        assert_eq!(
            cost_of(&mut identified_session(), &unasked),
            Closes(PeerViolation::Unsolicited)
        );
    }
    assert_eq!(
        cost_of(&mut asked(1), &frame(Emule, 0x9C, &with_file(&[]))),
        Keeps
    );
    assert_eq!(
        cost_of(&mut asked(1), &frame(Emule, 0x9C, &with_file(&[2, 0, 7]))),
        Keeps,
        "another part's root is never read"
    );
    assert_eq!(
        cost_of(&mut asked(1), &frame(Emule, 0x9C, &with_file(&[1, 0, 7]))),
        MALFORMED,
        "the asked part's root is read and throws"
    );
    assert_eq!(
        cost_of(&mut asked(1), &frame(Emule, 0x9C, &with_file(&[1]))),
        MALFORMED,
        "the part is read before anything is compared"
    );
}

/// `ProcessBlockPacket`: no block is read outside a slot (`:836-838`); inside,
/// a cut header is a logged return (`:1039-1046`), and a wrong file or a range
/// the bytes deny throws past that catch (`:856-858`, `:885-887`).
#[test]
fn a_block_costs_the_link_only_inside_a_slot_and_never_for_being_cut() {
    let cut = with_file(&[1, 2]);
    let wrong_range = with_file(&[0, 0, 0, 0, 9, 0, 0, 0, 1, 2]);
    let empty = with_file(&[5, 0, 0, 0, 5, 0, 0, 0]);
    let empty_packed = with_file(&[5, 0, 0, 0, 5, 0, 0, 0]);
    for (protocol, opcode, body) in [
        (Edonkey, 0x46, &cut),
        (Edonkey, 0x46, &wrong_range),
        (Emule, 0x40, &cut),
        (Emule, 0x40, &empty_packed),
        (Emule, 0xA2, &cut),
    ] {
        assert_eq!(
            cost_of(&mut identified_session(), &frame(protocol, opcode, body)),
            Keeps,
            "outside a slot 0x{opcode:02X}"
        );
    }
    for (protocol, opcode, body) in [
        (Edonkey, 0x46, vec![0; 3]),
        (Edonkey, 0x46, cut.clone()),
        (Emule, 0x40, cut.clone()),
        (Emule, 0xA2, cut.clone()),
        (Emule, 0xA1, cut.clone()),
    ] {
        assert_eq!(
            cost_of(&mut downloading_session(), &frame(protocol, opcode, &body)),
            Keeps,
            "cut in a slot 0x{opcode:02X}"
        );
    }
    for (body, cost) in [
        (wrong_range, MALFORMED),
        (empty, MALFORMED),
        (
            of_other_file(&[0, 0, 0, 0, 2, 0, 0, 0, 1, 2]),
            Closes(PeerViolation::WrongFile),
        ),
        (of_other_file(&[1, 2]), Closes(PeerViolation::WrongFile)),
    ] {
        assert_eq!(
            cost_of(&mut downloading_session(), &frame(Edonkey, 0x46, &body)),
            cost,
            "{body:?}"
        );
    }
    assert_eq!(
        cost_of(
            &mut downloading_session(),
            &frame(Emule, 0x40, &with_file(&[5, 0, 0, 0, 5, 0, 0, 0]))
        ),
        MALFORMED,
        "a compressed slice with no bytes ends where it starts"
    );
}

/// `ProcessExtPacket` `:1447-1458`: under a peer that claims no source
/// exchange a plain ask reads nothing, and an SX2 ask its trailer. A claimant's
/// is size-checked: sixteen passes, and nineteen stays the named exception
/// (ADR-0055).
#[test]
fn a_source_ask_is_sized_by_what_the_peer_claims() {
    let mut plain = identified_session();
    assert_eq!(
        cost_of(&mut plain, &frame(Emule, 0x81, &[1, 2, 3])),
        Keeps,
        "no claim, no read"
    );
    assert_eq!(
        cost_of(&mut identified_session(), &frame(Emule, 0x83, &[0, 0])),
        MALFORMED,
        "the trailer is read first"
    );
    assert_eq!(
        cost_of(&mut identified_session(), &frame(Emule, 0x83, &[0; 7])),
        Keeps,
        "version 0, no claim"
    );
    let mut sixteen = vec![1u8];
    sixteen.extend_from_slice(&[0; 15]);
    assert_eq!(
        cost_of(&mut identified_session(), &frame(Emule, 0x83, &sixteen)),
        Keeps,
        "sixteen passes stock's check, and names no file"
    );
    assert_eq!(
        cost_of(&mut identified_session(), &frame(Emule, 0x83, &[1; 7])),
        MALFORMED,
        "a claimed version sizes the frame"
    );
    assert_eq!(
        cost_of(
            &mut crate::fixture::identified_session_claiming_sx1(),
            &frame(Emule, 0x81, &[1; 3])
        ),
        MALFORMED,
        "a claimant's ask is sixteen bytes"
    );
}

/// The walk has no `default:` (`:1085-1200`, `:1227-1262`): a byte no case
/// takes is passed over and the next one read as a sub-opcode.
#[test]
fn a_bundle_walk_passes_over_a_byte_it_does_not_know() {
    let mut session = identified_session();
    session.handle_bytes(&frame(Emule, 0x92, &with_file(&[0x77, 0x4F])).encode());
    let outputs = drain(|| session.poll_output());
    let asks = outputs
        .iter()
        .find_map(|output| match output {
            PeerOutput::Event(PeerEvent::Server(ServerEvent::FileBundleRequested {
                asks, ..
            })) => Some(asks.len()),
            _ => None,
        })
        .expect("the bundle reaches core");
    assert_eq!(asks, 1);
    assert!(outputs.iter().any(|output| matches!(
        output,
        PeerOutput::Event(PeerEvent::Notice(NoticeEvent::MultiPacketUnknownSub {
            opcode: 0x77,
            ..
        }))
    )));
}

/// A size no file has is a size no shared file matches: not-found, not a
/// close (`:1072-1085`).
#[test]
fn a_bundle_naming_an_impossible_size_is_a_mismatch_and_keeps_the_link() {
    let mut body = FILE.to_vec();
    body.extend_from_slice(&u64::MAX.to_le_bytes());
    body.push(0x4F);
    let mut session = identified_session();
    session.handle_bytes(&frame(Emule, 0xA4, &body).encode());
    let outputs = drain(|| session.poll_output());
    assert!(outputs.iter().any(|output| matches!(
        output,
        PeerOutput::Event(PeerEvent::Server(ServerEvent::FileBundleRequested {
            file_size: Some(u64::MAX),
            ..
        }))
    )));
    assert!(!outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

/// `CheckForAggressive` runs before the size is looked at (`:601-606`): a
/// slot ask of the wrong size still counts as an ask.
#[test]
fn a_malformed_slot_ask_keeps_the_link_and_still_counts_as_an_ask() {
    let mut session = identified_session();
    session.handle_bytes(&frame(Edonkey, 0x54, &[1, 2, 3]).encode());
    let outputs = drain(|| session.poll_output());
    assert!(outputs.iter().any(|output| matches!(
        output,
        PeerOutput::Event(PeerEvent::Server(ServerEvent::MalformedSlotAsk))
    )));
    assert!(!outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}
