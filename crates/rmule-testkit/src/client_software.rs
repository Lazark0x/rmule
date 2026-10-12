//! The clients a mule hello names, read by the peer codec as core reads a
//! live hello: the captured aMule 2.3.3 and emule-qt, and any
//! `CT_EMULE_VERSION` word with or without a mod. Shared by the front ends'
//! tests, which assert how a client reads to the operator.

use std::net::Ipv4Addr;

use rmule_peer::{ClientSoftware, PeerHelloBody};
use rmule_primitives::{ClientId, Ed2kText, Ipv4Endpoint, Tag, TagName, TagValue, UserHash};

/// The client a mule hello names: its `CT_EMULE_VERSION` word and, when it
/// sent one, its mod — read by the peer codec, as core reads a live hello.
#[must_use]
pub fn client_software(word: u32, client_mod: Option<&str>) -> ClientSoftware {
    let mut hash = [0x42; UserHash::BYTE_LEN];
    // eMule's user-hash mark, as every mule writes it.
    hash[5] = 14;
    hash[14] = 111;
    let mut tags = vec![
        Tag::new(
            TagName::compact_id(0x01),
            TagValue::String(Ed2kText::from_utf8("peer")),
        ),
        Tag::new(TagName::compact_id(0xFB), TagValue::U32(word)),
    ];
    if let Some(text) = client_mod {
        tags.push(Tag::new(
            TagName::compact_id(0x55),
            TagValue::String(Ed2kText::from_utf8(text)),
        ));
    }
    ClientSoftware::from_hello_body(&PeerHelloBody {
        user_hash: UserHash::from_bytes(hash),
        client_id: ClientId::from_u32(0),
        tcp_port: 4662,
        tags,
        connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    })
}

/// aMule 2.3.3, as its captured hellos name it.
#[must_use]
pub fn amule_233() -> ClientSoftware {
    client_software(0x0304_0D80, None)
}

/// emule-qt, as its captured hello names it.
#[must_use]
pub fn emule_qt() -> ClientSoftware {
    client_software(0x0001_1880, Some("eMule Qt 0.4.2"))
}
