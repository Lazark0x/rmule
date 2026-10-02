//! What more than one leg here needs. Anything a second crate reaches for
//! belongs in `rmule-testkit` instead — which is where the peer endpoints,
//! handshake contexts, output drains and peer-sent wire frames live.

use rmule_peer::{ClientVersion, HelloAnswer, PeerHelloBody, PeerSession};
use rmule_primitives::session::drain;
use rmule_primitives::{ClientId, Ed2kText, Ipv4Endpoint, Tag, TagName, TagValue, UserHash};
use rmule_testkit::peer_session::{ctx, peer_at};
use std::net::Ipv4Addr;

// --- Hello tag ids -----------------------------------------------------

/// `CT_NAME`: the client's name.
pub const CT_NAME: u8 = 0x01;
/// `CT_VERSION`: the eDonkey protocol version it speaks.
pub const CT_VERSION: u8 = 0x11;
/// `CT_EMULE_UDPPORTS`: Kad UDP port in the high 16 bits, client UDP port in
/// the low 16 (aMule `ProcessHelloTypePacket`).
pub const CT_EMULE_UDPPORTS: u8 = 0xF9;
/// `CT_EMULE_MISCOPTIONS1`: the packed capability nibbles — source exchange,
/// AICH, compression and the rest.
pub const CT_EMULE_MISCOPTIONS1: u8 = 0xFA;

// --- The peer-UDP reask capture run ------------------------------------

/// rmule's own identity this run (`rmule-tools`' default user hash). aMule
/// keys the send on the *recipient's* user hash, so this is half the decrypt
/// key.
pub const RMULE_USER_HASH: [u8; 16] = [0x42; 16];

/// The sender's IP, the other half of the key. It is aMule's own container
/// address — see `meta.toml`: with no public-IP extension in the eserver's
/// `OP_IDCHANGE`, aMule's `GetPublicIP()` fell back to `m_localip`, and this
/// decrypt succeeding is that fallback observed rather than assumed.
pub const AMULE_SENDER_IP: [u8; 4] = [172, 18, 0, 5];

/// The synthetic 40 MiB file both sides shared over the reask capture runs.
pub const FILE_HASH: [u8; 16] = [
    0xC7, 0xC8, 0x96, 0x90, 0x03, 0x5A, 0x1E, 0xA3, 0x2D, 0xC9, 0x7C, 0x6C, 0xD5, 0x3D, 0x68, 0xE5,
];

/// One captured datagram or frame, read out of `tests/fixtures/<dir>` — the
/// aMule-authored bytes a capture leg decodes.
pub fn load(dir: &str, name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(dir)
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

/// A counterparty's hello body — its `OP_HELLO` and its `OP_HELLOANSWER` carry
/// the same shape — with the given tags and no server.
pub fn hello_body(user_hash: UserHash, client_id: u32, tags: Vec<Tag>) -> PeerHelloBody {
    PeerHelloBody {
        user_hash,
        client_id: ClientId::from_u32(client_id),
        tcp_port: 4662,
        tags,
        connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    }
}

/// A counterparty's hello body advertising nothing but its name.
///
/// Deliberately plainer than `rmule_testkit::peer_session::answer_body`, which
/// also claims `CT_EMULE_MISCOPTIONS1`: the legs here assert what a session
/// does for a peer that advertises no capabilities at all.
pub fn plain_hello_body(user_hash: UserHash) -> PeerHelloBody {
    hello_body(
        user_hash,
        0x20000002,
        vec![Tag::new(
            TagName::length_prefixed_id(0x01),
            TagValue::String(Ed2kText::from_utf8("remote")),
        )],
    )
}

/// The version a client's mule tag names.
pub const fn client_version(major: u32, minor: u32, update: u32) -> Option<ClientVersion> {
    Some(ClientVersion {
        major,
        minor,
        update,
    })
}

/// An outbound session driven through the hello exchange with a peer that
/// advertises no capabilities — `Identified`, the state a live link is in when
/// relays, pongs and human-layer frames flow.
pub fn identified_session() -> PeerSession {
    let mut session = PeerSession::new_outbound(peer_at(55), ctx());
    session.start();
    let _ = drain(|| session.poll_output());
    let answer = HelloAnswer::new(plain_hello_body(UserHash::from_bytes([0x99; 16])))
        .encode_packet()
        .encode();
    session.handle_bytes(&answer);
    let _ = drain(|| session.poll_output());
    session
}
