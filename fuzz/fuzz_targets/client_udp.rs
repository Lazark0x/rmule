//! The client-UDP envelopes: every reask, callback and ack a stranger can send to
//! the one socket.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rmule_peer::{DirectCallbackReq, ReaskAck, ReaskCallbackUdp, ReaskFilePing};

fuzz_target!(|data: &[u8]| {
    let Some((version, datagram)) = data.split_first() else {
        return;
    };
    let _ = ReaskFilePing::decode_udp(datagram, *version);
    let _ = ReaskAck::decode_udp(datagram, *version);
    let _ = ReaskCallbackUdp::decode_udp(datagram);
    let _ = DirectCallbackReq::decode_udp(datagram);
});
