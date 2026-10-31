//! A server link's body decoders over every opcode, and the session they feed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rmule_ed2k::{Ed2kSession, ServerPacket};
use rmule_primitives::session::drain;
use rmule_primitives::{Packet, PacketProtocol, ServerEndpoint};
use rmule_testkit::test_identity;

fuzz_target!(|data: &[u8]| {
    if let [opcode, payload @ ..] = data {
        let packet = Packet::new(PacketProtocol::Edonkey, *opcode, payload.to_vec());
        let _ = ServerPacket::decode(&packet);
    }
    let endpoint = ServerEndpoint::new("198.51.100.1".to_owned(), 4661).expect("valid endpoint");
    let mut session = Ed2kSession::new(endpoint, test_identity(0, "rmule-fuzz", 4662));
    session.start();
    session.handle_bytes(data);
    let _ = drain(|| session.poll_output());
});
