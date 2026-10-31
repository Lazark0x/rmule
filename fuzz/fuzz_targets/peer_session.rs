//! A live peer link after the hello: any bytes, in any cut, through framing, the
//! decoders, the dispatch and the encoders of what it answers. This is
//! `PeerPacket::decode_frame` as a stranger reaches it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rmule_primitives::session::drain;
use rmule_testkit::peer_session::identified_session;

fuzz_target!(|data: &[u8]| {
    let mut session = identified_session();
    for chunk in data.chunks(1 + usize::from(data.first().copied().unwrap_or(0))) {
        session.handle_bytes(chunk);
        let _ = drain(|| session.poll_output());
    }
});
