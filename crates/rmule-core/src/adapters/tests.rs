//! Fixtures the seam tests share: the handshake context a dialed
//! connection identifies with, an IP filter that blocks loopback, and a
//! firewalled slot holding a buddy ([`held_buddy`]), and a hello read back
//! off the wire against a node whose every advert is live ([`hello_wire`]).

pub(crate) mod held_buddy;
pub(crate) mod hello_wire;

use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, UserHash};

pub(crate) fn dialed_serve_ctx() -> PeerHandshakeContext {
    PeerHandshakeContext {
        identity: ClientIdentity::new(
            UserHash::from_bytes([0x09; UserHash::BYTE_LEN]),
            Ed2kText::from_utf8("rmule-dialed-serve"),
            4662,
            60,
        ),
        client_id: ClientId::from_u32(0x0100_007F),
        connected_server: None,
    }
}

/// A loopback-blocking IP filter for the two gate tests below:
/// 127.0.0.0/24 at level 0, both gates on.
pub(crate) fn loopback_blocking_ip_filter() -> crate::ip_filter::IpFilter {
    let (filter, _) = crate::ip_filter::IpFilter::from_texts(
        &[b"127.0.0.0-127.0.0.255,0,loopback\n".as_slice()],
        127,
        true,
        true,
    );
    filter
}
