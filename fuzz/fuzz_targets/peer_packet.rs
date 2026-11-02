//! `PeerPacket::decode` over every opcode and marker: no panic in a body decoder.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rmule_peer::PeerPacket;
use rmule_primitives::{Packet, PacketProtocol};

fuzz_target!(|data: &[u8]| {
    let [marker, opcode, payload @ ..] = data else {
        return;
    };
    let protocol = match marker % 3 {
        0 => PacketProtocol::Edonkey,
        1 => PacketProtocol::Emule,
        _ => PacketProtocol::PackedEd2k,
    };
    if let Ok(packet) = PeerPacket::decode(&Packet::new(protocol, *opcode, payload.to_vec())) {
        let _ = packet.encode();
    }
});
