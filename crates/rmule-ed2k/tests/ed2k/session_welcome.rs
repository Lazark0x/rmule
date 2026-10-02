//! The welcome burst: the packets a server sends straight after login
//! dispatch in arrival order, and an unknown-but-well-formed opcode surfaces
//! as an event rather than closing the session.

use rmule_ed2k::{Ed2kCommand, Ed2kEvent, Ed2kSession, GetServerList, Output};
use rmule_primitives::session::drain;
use rmule_primitives::{Packet, PacketProtocol};

fn next_event(session: &mut Ed2kSession) -> Ed2kEvent {
    match session.poll_output() {
        Some(Output::Event(event)) => event,
        other => panic!("expected Event, got {other:?}"),
    }
}

#[test]
fn logged_in_dispatches_welcome_burst_in_arrival_order() {
    let mut session = crate::fixture::logged_in_session(0);

    // Server pushes the four typed welcome packets back-to-back.
    let mut burst = Vec::new();
    burst.extend_from_slice(&crate::fixture::bytes("server/server_message.bin"));
    burst.extend_from_slice(&crate::fixture::bytes("server/server_status.bin"));
    burst.extend_from_slice(&crate::fixture::bytes("server/server_ident.bin"));
    burst.extend_from_slice(&crate::fixture::bytes("server/server_list.bin"));
    session.handle_bytes(&burst);

    // The four typed welcome events arrive in order, and nothing follows —
    // the drained output sequence is exactly these four events.
    assert!(matches!(
        drain(|| session.poll_output()).as_slice(),
        [
            Output::Event(Ed2kEvent::ServerMessageReceived { .. }),
            Output::Event(Ed2kEvent::ServerStatusReceived { .. }),
            Output::Event(Ed2kEvent::ServerIdentified { .. }),
            Output::Event(Ed2kEvent::ServerListReceived { .. }),
        ]
    ));
}

#[test]
fn well_formed_unknown_opcode_surfaces_as_unknown_server_packet_event() {
    let mut session = crate::fixture::logged_in_session(0);

    // Use a real well-formed Packet with an opcode rmule does not type.
    // Frame layer accepts it; ServerPacket::decode falls into Unknown; session emits
    // UnknownServerPacket with the right payload length.
    let payload = vec![0xAA, 0xBB, 0xCC];
    let payload_len = payload.len();
    let packet = Packet::new(PacketProtocol::Edonkey, 0x7f, payload).encode();

    session.handle_bytes(&packet);

    match next_event(&mut session) {
        Ed2kEvent::UnknownServerPacket {
            opcode,
            payload_len: emitted,
        } => {
            assert_eq!(opcode, 0x7f);
            assert_eq!(emitted, payload_len);
        }
        other => panic!("expected UnknownServerPacket, got {other:?}"),
    }
}

#[test]
fn request_server_list_command_writes_get_server_list_packet() {
    let mut session = crate::fixture::logged_in_session(0);

    session.handle_command(Ed2kCommand::RequestServerList);

    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("expected Write(GetServerList bytes)");
    };
    assert_eq!(
        &bytes[..],
        GetServerList.encode_packet().encode().as_slice()
    );
    assert!(session.poll_output().is_none());
}
