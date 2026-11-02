//! `Packet::decode`, the first thing a peer's or a server's bytes meet: no panic,
//! and what decodes writes back as the bytes it consumed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rmule_primitives::Packet;

fuzz_target!(|data: &[u8]| {
    if let Ok((packet, consumed)) = Packet::decode(data) {
        assert_eq!(packet.encode(), data[..consumed]);
    }
});
