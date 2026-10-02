//! The AICH legs on a live session (ADR-0045): a requester asking for a
//! part's recovery hash, a server answering one, and both round trips
//! between two real sessions.

use rmule_peer::{PeerCommand, PeerEvent};
use rmule_primitives::session::drain;
use rmule_primitives::{AichRootHash, PacketProtocol};
use rmule_testkit::peer_session::*;

#[test]
fn request_aich_frames_op_aichrequest_and_answer_projects_aich_answer_received() {
    let h = file_hash(0xA1);
    let root = AichRootHash::from_bytes([0x5A; AichRootHash::BYTE_LEN]);
    let mut session = identified_session();

    session.handle_command(PeerCommand::RequestAich {
        file_hash: h,
        part: 4,
        root,
    });
    let out = drain(|| session.poll_output());
    assert!(
        writes(&out).iter().any(|p| p.opcode() == 0x9B
            && p.protocol() == PacketProtocol::Emule
            && p.payload().len() == 16 + 2 + AichRootHash::BYTE_LEN),
        "OP_AICHREQUEST framed for the part"
    );

    // The peer answers with opaque recovery data; the receive side projects it.
    session.handle_bytes(&aich_answer_wire(h, 4, root, &[9, 9, 9]));
    let out2 = drain(|| session.poll_output());
    assert!(events(&out2).iter().any(|e| matches!(
        e,
        PeerEvent::AichAnswerReceived { file_hash, part, root: r, recovery_data }
            if *file_hash == h && *part == 4 && *r == root && recovery_data == &[9u8, 9, 9]
    )));
}

#[test]
fn inbound_aich_request_projects_aich_requested_serve_event() {
    let h = file_hash(0xA2);
    let root = AichRootHash::from_bytes([0x6B; AichRootHash::BYTE_LEN]);
    let mut session = identified_session();

    session.handle_bytes(&aich_request_wire(h, 7, root));
    let out = drain(|| session.poll_output());
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::AichRequested { file_hash, part, root: r }
            if *file_hash == h && *part == 7 && *r == root
    )));
}

#[test]
fn aich_request_and_answer_round_trip_between_two_sessions() {
    // End-to-end AICH C2C exchange through two real sessions: the client's
    // RequestAich frames OP_AICHREQUEST, the server projects AichRequested and
    // answers with AnswerAich (OP_AICHANSWER), and the client projects
    // AichAnswerReceived carrying the recovery data byte-intact (ADR-0038).
    let h = file_hash(0xC1);
    let root = AichRootHash::from_bytes([0x7C; AichRootHash::BYTE_LEN]);
    let recovery = vec![0x11u8; 70];

    let mut client = identified_session();
    let mut server = identified_session();

    client.handle_command(PeerCommand::RequestAich {
        file_hash: h,
        part: 5,
        root,
    });
    let req_bytes = last_write_bytes(&drain(|| client.poll_output()));
    server.handle_bytes(&req_bytes);
    let server_out = drain(|| server.poll_output());
    assert!(
        events(&server_out).iter().any(|e| matches!(
            e,
            PeerEvent::AichRequested { file_hash, part, root: r }
                if *file_hash == h && *part == 5 && *r == root
        )),
        "the server surfaces a serve-side AichRequested: {server_out:?}"
    );

    server.handle_command(PeerCommand::AnswerAich {
        file_hash: h,
        part: 5,
        root,
        recovery_data: recovery.clone(),
    });
    let ans_bytes = last_write_bytes(&drain(|| server.poll_output()));
    client.handle_bytes(&ans_bytes);
    let client_out = drain(|| client.poll_output());
    assert!(
        events(&client_out).iter().any(|e| matches!(
            e,
            PeerEvent::AichAnswerReceived { file_hash, part, root: r, recovery_data }
                if *file_hash == h && *part == 5 && *r == root && *recovery_data == recovery
        )),
        "the client receives the server's recovery data intact: {client_out:?}"
    );
}

#[test]
fn aich_file_hash_request_and_answer_round_trip_between_two_sessions() {
    // Trusted-set root discovery (ADR-0038): the client asks for a file's AICH
    // master hash (OP_AICHFILEHASHREQ), the server surfaces AichFileHashRequested
    // and answers OP_AICHFILEHASHANS with its root, and the client surfaces a
    // root proposal (AichFileHashReceived). The standalone 0x9D answer leads with
    // the file hash then the root, which the client decodes back.
    let h = file_hash(0xC2);
    let root = AichRootHash::from_bytes([0x8D; AichRootHash::BYTE_LEN]);

    let mut client = identified_session();
    let mut server = identified_session();

    client.handle_command(PeerCommand::RequestAichFileHash { file_hash: h });
    let req = last_write_bytes(&drain(|| client.poll_output()));
    server.handle_bytes(&req);
    let server_out = drain(|| server.poll_output());
    assert!(
        events(&server_out).iter().any(|e| matches!(
            e,
            PeerEvent::AichFileHashRequested { file_hash } if *file_hash == h
        )),
        "the server surfaces AichFileHashRequested: {server_out:?}"
    );

    server.handle_command(PeerCommand::AnswerAichFileHash { root });
    let ans = last_write_bytes(&drain(|| server.poll_output()));
    client.handle_bytes(&ans);
    let client_out = drain(|| client.poll_output());
    assert!(
        events(&client_out)
            .iter()
            .any(|e| matches!(e, PeerEvent::AichFileHashReceived { root: r } if *r == root)),
        "the client surfaces the server's root proposal: {client_out:?}"
    );
}
