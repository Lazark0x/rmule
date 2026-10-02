//! The login handshake as the session drives it: what `start` owes, what each
//! kind of `OP_IDCHANGE` transitions to, and what a rejection or a malformed
//! frame closes with.

use rmule_ed2k::{CloseReason, Ed2kEvent, Ed2kSession, LoginRequest, Output, SessionError};
use rmule_primitives::session::drain;
use rmule_primitives::{Capabilities, ClientId, CryptStance};

#[test]
fn start_emits_connection_started_then_login_request_write() {
    let endpoint = crate::fixture::endpoint();
    let identity = crate::fixture::identity(0);
    let mut session = Ed2kSession::new(endpoint.clone(), identity.clone());

    session.start();

    let Some(Output::Event(Ed2kEvent::LoginRequested { endpoint: emitted })) =
        session.poll_output()
    else {
        panic!("first output: expected Event(LoginRequested)");
    };
    assert_eq!(emitted, endpoint);

    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("second output: expected Write(login bytes)");
    };
    let expected =
        LoginRequest::from_identity(&identity, &Capabilities::shipped(CryptStance::disabled()))
            .encode_packet()
            .encode();
    assert_eq!(&bytes[..], expected.as_slice());

    assert!(session.poll_output().is_none());
}

#[test]
fn start_is_idempotent_no_extra_outputs_on_repeat_calls() {
    let endpoint = crate::fixture::endpoint();
    let mut session = Ed2kSession::new(endpoint, crate::fixture::identity(0));

    session.start();
    drain(|| session.poll_output());

    session.start();
    assert!(
        session.poll_output().is_none(),
        "second start() must not re-emit LoginRequested or re-send LoginRequest"
    );
}

#[test]
fn id_change_response_emits_login_accepted_with_decoded_client_id() {
    let mut session = crate::fixture::started_session(0);

    session.handle_bytes(&crate::fixture::bytes("login/id_change_with_tcp_flags.bin"));

    let Some(Output::Event(Ed2kEvent::LoginAccepted {
        client_id,
        tcp_flags,
        facts,
    })) = session.poll_output()
    else {
        panic!("expected Event(LoginAccepted)");
    };
    assert_ne!(client_id, ClientId::from_u32(0), "client id was decoded");
    assert!(tcp_flags.is_some(), "fixture is the with-flags variant");
    // The 8-byte form carries no extension, so it offers no ports. It does
    // still establish our own address, because the fixture's id is High and a
    // High id *is* that address — the short-form case that left every
    // UDP crypt send gate shut while rmule read the extension alone.
    assert_eq!(
        facts,
        rmule_ed2k::ServerAssignedFacts {
            public_ip: Some(std::net::Ipv4Addr::new(120, 86, 52, 18)),
            standard_tcp_port: None,
            obfuscation_tcp_port: None,
        }
    );
    assert!(session.poll_output().is_none());
}

#[test]
fn session_accepts_lugdunum_extended_id_change() {
    let mut session = crate::fixture::started_session(0);

    session.handle_bytes(&crate::fixture::bytes(
        "login/id_change_lugdunum_extended.bin",
    ));

    let outputs = drain(|| session.poll_output());

    let accepted = outputs
        .iter()
        .find_map(|o| match o {
            Output::Event(Ed2kEvent::LoginAccepted {
                client_id,
                tcp_flags,
                facts,
            }) => Some((*client_id, *tcp_flags, *facts)),
            _ => None,
        })
        .expect("LoginAccepted should be emitted for an extended OP_IDCHANGE");
    assert_eq!(accepted.0.as_u32(), 936);
    assert_eq!(accepted.1.map(|f| f.bits()), Some(0x05DD));
    // The captured 20-byte extension, projected (ADR-0047): standard port
    // 936, server-reported public IP 171.25.158.106 (HighID-valued → kept),
    // obfuscation TCP port 4661.
    assert_eq!(
        accepted.2,
        rmule_ed2k::ServerAssignedFacts {
            public_ip: Some(std::net::Ipv4Addr::new(171, 25, 158, 106)),
            standard_tcp_port: Some(936),
            obfuscation_tcp_port: Some(4661),
        }
    );
    assert!(
        !outputs.iter().any(|o| matches!(o, Output::Close(_))),
        "extended OP_IDCHANGE must not close the session"
    );
}

#[test]
fn zero_id_change_applies_facts_without_login_transition() {
    // aMule's smart-id bookkeeping case (`ServerSocket.cpp`): a zero id
    // still applies flags and extension ports, but assigns no id and
    // triggers no connected transition — so no LoginAccepted either.
    let mut session = crate::fixture::started_session(0);

    let mut payload = 0_u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&0x100_u32.to_le_bytes()); // LARGEFILES
    payload.extend_from_slice(&4661_u32.to_le_bytes()); // standard port
    payload.extend_from_slice(&[171, 25, 158, 106]); // public ip
    payload.extend_from_slice(&4671_u32.to_le_bytes()); // obfuscation port
    let frame =
        rmule_primitives::Packet::new(rmule_primitives::PacketProtocol::Edonkey, 0x40, payload)
            .encode();
    session.handle_bytes(&frame);

    assert!(
        session.poll_output().is_none(),
        "a zero id emits nothing — no LoginAccepted, no close"
    );
    assert_eq!(
        session.server_facts(),
        rmule_ed2k::ServerAssignedFacts {
            public_ip: Some(std::net::Ipv4Addr::new(171, 25, 158, 106)),
            standard_tcp_port: Some(4661),
            obfuscation_tcp_port: Some(4671),
        },
        "the extension facts still applied"
    );

    // Still not logged in: a follow-up IDCHANGE with a real id completes
    // login normally.
    session.handle_bytes(&crate::fixture::bytes("login/id_change_with_tcp_flags.bin"));
    assert!(matches!(
        session.poll_output(),
        Some(Output::Event(Ed2kEvent::LoginAccepted { .. }))
    ));
}

#[test]
fn reject_response_emits_login_rejected_event_then_closes_session() {
    let mut session = crate::fixture::started_session(0);

    session.handle_bytes(&crate::fixture::bytes("login/op_reject.bin"));

    // First the typed event so the consumer knows the server explicitly
    // refused login (vs. a silent FIN).
    let Some(Output::Event(Ed2kEvent::LoginRejected)) = session.poll_output() else {
        panic!("expected Event(LoginRejected)");
    };
    // Then the paired terminal Disconnected + Close(LoginRejected): the
    // session emits the Disconnected itself on every close path. Treating
    // Reject as terminal matches aMule (`ServerSocket.cpp:289-291`) and
    // stops a subsequent RequestServerList from writing OP_GETSERVERLIST to
    // a server that just refused us.
    let Some(Output::Event(Ed2kEvent::Disconnected {
        reason: CloseReason::LoginRejected,
    })) = session.poll_output()
    else {
        panic!("expected Event(Disconnected{{LoginRejected}}) after the typed event");
    };
    let Some(Output::Close(CloseReason::LoginRejected)) = session.poll_output() else {
        panic!("expected Close(LoginRejected) after Disconnected");
    };
    assert!(session.poll_output().is_none());
}

#[test]
fn malformed_frame_closes_session_with_frame_decode_violation() {
    let mut session = crate::fixture::started_session(0);

    // 0xFF is not a known protocol byte; Packet::decode rejects with
    // UnsupportedProtocolByte at the frame layer.
    session.handle_bytes(&[0xFF, 0x01, 0x00, 0x00, 0x00, 0x00]);

    let Some(Output::Event(Ed2kEvent::Disconnected {
        reason: CloseReason::ProtocolViolation(SessionError::Frame(_)),
    })) = session.poll_output()
    else {
        panic!("first output: expected Event(Disconnected{{ProtocolViolation(Frame)}})");
    };
    let Some(Output::Close(CloseReason::ProtocolViolation(SessionError::Frame(_)))) =
        session.poll_output()
    else {
        panic!("expected Close(ProtocolViolation(SessionError::Frame))");
    };
    assert!(session.poll_output().is_none());

    // Bytes after Close are silently dropped — no panic.
    session.handle_bytes(&crate::fixture::bytes("login/id_change_with_tcp_flags.bin"));
    assert!(session.poll_output().is_none());
}

#[test]
fn partial_frame_buffered_until_more_bytes_arrive() {
    let mut session = crate::fixture::started_session(0);

    let frame = crate::fixture::bytes("login/id_change_with_tcp_flags.bin");
    let (first, second) = frame.split_at(frame.len() - 3);
    session.handle_bytes(first);
    assert!(
        session.poll_output().is_none(),
        "truncated frame must not produce output"
    );

    session.handle_bytes(second);
    let Some(Output::Event(Ed2kEvent::LoginAccepted { .. })) = session.poll_output() else {
        panic!("expected LoginAccepted after second chunk completes the frame");
    };
}

#[test]
fn server_message_before_id_change_is_accepted_per_live_wire_evidence() {
    // Lugdunum servers push ERROR/WARNING messages before OP_IDCHANGE
    // (see captured/welcome-burst-<date>/s2c.bin from Task 13). aMule
    // enforces no welcome-burst ordering. The session must therefore
    // process OP_SERVERMESSAGE while AwaitingIdChange rather than treat
    // it as a protocol violation.
    let mut session = crate::fixture::started_session(0);

    session.handle_bytes(&crate::fixture::bytes("server/server_message.bin"));

    let Some(Output::Event(Ed2kEvent::ServerMessageReceived { .. })) = session.poll_output() else {
        panic!("expected Event(ServerMessageReceived) before IdChange");
    };
    assert!(session.poll_output().is_none(), "no further outputs");
}
