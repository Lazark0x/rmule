//! `OP_CALLBACKREQUESTED` as the server relays it: the dial-back endpoint
//! decodes, the extended form's trailing bytes are tolerated, and a malformed
//! one is rejected.

use std::net::Ipv4Addr;

use rmule_ed2k::PeerCallback;
use rmule_primitives::{Ipv4Endpoint, Packet, PacketProtocol};

const OP_CALLBACKREQUESTED: u8 = 0x35;

fn callback_packet(payload: Vec<u8>) -> Packet {
    Packet::new(PacketProtocol::Edonkey, OP_CALLBACKREQUESTED, payload)
}

#[test]
fn peer_callback_decodes_ipv4_and_port() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[10, 0, 0, 7]);
    payload.extend_from_slice(&4662u16.to_le_bytes());

    let cb = PeerCallback::decode_packet(&callback_packet(payload)).expect("decode");
    assert_eq!(cb.peer, Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 7), 4662));
}

#[test]
fn peer_callback_tolerates_extended_form_trailing_bytes() {
    // aMule's handler reads optional crypt-options + user-hash when
    // size >= 23; the frame must decode rather than be rejected, or live
    // captures from modern lugdunum servers would close the session.
    let mut payload = Vec::new();
    payload.extend_from_slice(&[10, 0, 0, 7]);
    payload.extend_from_slice(&4662u16.to_le_bytes());
    payload.push(0x00); // crypt_options
    payload.extend_from_slice(&[0xAB; 16]); // user_hash

    let cb = PeerCallback::decode_packet(&callback_packet(payload)).expect("extended form decodes");
    assert_eq!(cb.peer.port, 4662);
}

#[test]
fn malformed_peer_callback_rejects() {
    assert!(PeerCallback::decode_packet(&callback_packet(vec![0; 5])).is_err());
}
