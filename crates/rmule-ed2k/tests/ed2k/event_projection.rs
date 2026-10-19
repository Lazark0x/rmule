//! What a decoded server packet projects to on the event surface a front-end
//! reads: text stays byte-lossless, an unknown packet reports its length and
//! not its bytes, and a callback threads its crypt extension through.

use std::net::Ipv4Addr;

use rmule_ed2k::{
    Ed2kEvent, FoundSources, PeerCallback, PeerCallbackCrypt, ServerMessage, ServerPacket,
};
use rmule_primitives::{
    ClientId, Ed2kText, FileHash, Ipv4Endpoint, PeerEndpoint, PeerSource, SourceClaim,
    SourceCryptOptions, UserHash,
};

#[test]
fn server_message_projects_text_losslessly_including_non_utf8() {
    let raw = vec![0xff, 0xfe, b'h', b'i'];
    let packet =
        ServerPacket::ServerMessage(ServerMessage::new(Ed2kText::from_bytes(raw.clone())).unwrap());
    let event = Ed2kEvent::from_server_packet(&packet);
    match event {
        Ed2kEvent::ServerMessageReceived { text } => assert_eq!(text.as_bytes(), raw.as_slice()),
        other => panic!("expected ServerMessageReceived, got {other:?}"),
    }
}

#[test]
fn unknown_packet_projects_to_payload_length_not_payload_bytes() {
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01];
    let packet = ServerPacket::Unknown {
        opcode: 0xCC,
        payload: payload.clone(),
    };
    match Ed2kEvent::from_server_packet(&packet) {
        Ed2kEvent::UnknownServerPacket {
            opcode,
            payload_len,
        } => {
            assert_eq!(opcode, 0xCC);
            assert_eq!(payload_len, payload.len());
        }
        other => panic!("expected UnknownServerPacket, got {other:?}"),
    }
}

#[test]
fn found_sources_packet_projects_to_hash_keyed_event() {
    let file_hash = FileHash::from_bytes([0x99; FileHash::BYTE_LEN]);
    let source = PeerSource::new(ClientId::from_u32(ClientId::LOW_ID_THRESHOLD), 4662);
    let packet = ServerPacket::FoundSources(FoundSources::new(file_hash, vec![source]).unwrap());

    match Ed2kEvent::from_server_packet(&packet) {
        Ed2kEvent::SourcesFound {
            file_hash: h,
            sources,
            ..
        } => {
            assert_eq!(h, file_hash);
            // A plain `0x42` source projects as plaintext-only provenance.
            assert_eq!(sources, vec![SourceClaim::plain(source)]);
        }
        other => panic!("expected SourcesFound, got {other:?}"),
    }
}

#[test]
fn peer_callback_projects_to_event() {
    let endpoint = Ipv4Endpoint::new(Ipv4Addr::new(192, 168, 1, 1), 4242);
    let cb = PeerCallback::new(endpoint);

    match Ed2kEvent::from_server_packet(&ServerPacket::PeerCallback(cb)) {
        Ed2kEvent::PeerCallbackRequested { peer, crypt } => {
            assert_eq!(peer, PeerEndpoint::V4(endpoint));
            assert_eq!(crypt, None, "a base 6-byte callback carries no provenance");
        }
        other => panic!("expected PeerCallbackRequested, got {other:?}"),
    }
}

/// `0x26` is the same role one family over: it projects onto the same event,
/// so every consumer dials the peer it is handed without asking which opcode
/// produced it (ADR-0087 §4.5).
#[test]
fn the_ipv6_callback_projects_onto_the_same_event_with_a_v6_peer() {
    let endpoint = rmule_primitives::Ipv6Endpoint::new("2a01:4f8::1".parse().unwrap(), 4662);
    let cb = rmule_ed2k::PeerCallbackIpv6::new(endpoint);

    match Ed2kEvent::from_server_packet(&ServerPacket::PeerCallbackIpv6(cb)) {
        Ed2kEvent::PeerCallbackRequested { peer, crypt } => {
            assert_eq!(peer, PeerEndpoint::V6(endpoint));
            assert_eq!(
                crypt, None,
                "`0x26` defines no crypt extension, so the dial-back is plaintext"
            );
        }
        other => panic!("expected PeerCallbackRequested, got {other:?}"),
    }
}

#[test]
fn peer_callback_crypt_extension_threads_into_the_event() {
    // The 0x35 crypt extension (ADR-0061) reaches the projected event so the
    // dial-back can obfuscate the connect-back.
    let endpoint = Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 5), 4662);
    let provenance = PeerCallbackCrypt {
        connect_options: SourceCryptOptions::from_byte(0x01),
        user_hash: UserHash::from_bytes([0x42; UserHash::BYTE_LEN]),
    };
    let cb = PeerCallback::with_crypt(endpoint, provenance);

    match Ed2kEvent::from_server_packet(&ServerPacket::PeerCallback(cb)) {
        Ed2kEvent::PeerCallbackRequested { peer, crypt } => {
            assert_eq!(peer, PeerEndpoint::V4(endpoint));
            assert_eq!(crypt, Some(provenance));
        }
        other => panic!("expected PeerCallbackRequested, got {other:?}"),
    }
}
