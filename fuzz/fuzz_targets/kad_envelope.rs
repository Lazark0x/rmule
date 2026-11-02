//! A Kad datagram: the envelope, its inflation, and the message inside it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rmule_kad::{Kad2Message, KadDecoded, decode_exact};

fuzz_target!(|data: &[u8]| {
    if let Ok(KadDecoded::Plain(envelope) | KadDecoded::Packed(envelope)) = decode_exact(data) {
        if let Ok(message) = Kad2Message::decode(&envelope) {
            let _ = message.encode();
        }
    }
});
