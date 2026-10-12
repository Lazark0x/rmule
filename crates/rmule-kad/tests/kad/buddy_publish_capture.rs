//! The buddy source row, from the publisher's own bytes:
//! a firewalled stock aMule 2.3.3, holding rmule as its recruited buddy,
//! publishing a source for the file it shares (interop flow M
//! `kad-core-buddy --publish-source`, run `1790097388`).
//!
//! This is the capture ADR-0061's "Kad buddy source row" section waited on.
//! Until it existed the row's tag order, integer widths and — above all —
//! `TAG_BUDDYHASH`'s byte order were read from three reference trees that do
//! not agree with each other. Every assertion below is against the bytes; the
//! provenance, the five gates the publish had to clear and the one reading the
//! capture cannot settle are in `meta.toml` beside the frame.

const FIXTURE_DIR: &str = "fixtures/buddy/captured/amule-233-publish-source-req-20260922/";

use rmule_kad::KadNodeStart;
use rmule_kad::{Kad2Message, KadId, KadPublishedSource};
use rmule_primitives::{Ipv4Endpoint, kad_wire_id};

use crate::fixture::{AMULE_TCP_PORT, KAD_PROTO};

/// `KADEMLIA2_PUBLISH_SOURCE_REQ`.
const OP_PUBLISH_SOURCE_REQ: u8 = 0x44;

/// The counterparty's harness-pinned Kad ID, in the order both sides write a
/// 128-bit ID on the wire. Asymmetric per 32-bit word on purpose: the buddy
/// relationship ID is its complement, and a palindromic one would hide which
/// way round the hash tag is written.
const AMULE_KAD_ID: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
];
/// rmule's pinned Kad ID — `~AMULE_KAD_ID`, so it *is* the FindBuddy target
/// and the buddy this row names.
pub(super) const RMULE_KAD_ID: [u8; 16] = [
    0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
];
/// rmule's Kad UDP port in the flow-M swarm — what the row's `TAG_SERVERPORT`
/// must carry, the buddy's **UDP** port and not its TCP one.
const RMULE_KAD_UDP_PORT: u16 = 4679;
/// rmule's fake-public address in the flow-M swarm.
const RMULE_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(203, 0, 113, 3);

pub(super) fn frame() -> Vec<u8> {
    crate::fixture::captured(FIXTURE_DIR, "publish_source_req_0x44.bin")
}

fn decoded() -> Kad2Message {
    let rmule_kad::KadDecoded::Plain(envelope) =
        rmule_kad::decode_exact(&frame()).expect("a well-formed publish")
    else {
        panic!("the counterparty published in the clear");
    };
    Kad2Message::decode(&envelope).expect("rmule's codec reads aMule's publish")
}

/// The whole row, through the widened reader, field by field against the
/// bytes. `TAG_SOURCEUPORT` is absent — `CPrefs::m_useExternKadPort` starts
/// `true`, so a stock publisher never writes it and the storer is left to index
/// the port it observed.
#[test]
fn the_captured_publish_decodes_to_the_firewalled_buddy_row() {
    let f = frame();
    assert_eq!(f[0], KAD_PROTO);
    assert_eq!(f[1], OP_PUBLISH_SOURCE_REQ);

    let Kad2Message::PublishSourceReq {
        file,
        source_id,
        source,
    } = decoded()
    else {
        panic!("0x44 decodes to a publish");
    };

    assert_eq!(
        file.as_bytes()[..],
        f[2..18],
        "the published key is the file's Kad target, verbatim from the header",
    );
    assert_eq!(
        source_id[..],
        f[18..34],
        "the row's source ID is the publisher's User Hash in Kad wire order",
    );
    assert_eq!(f[34], 7, "seven tags: no SOURCEIP and no SOURCEUPORT");

    assert_eq!(
        source,
        KadPublishedSource {
            source_type: Some(3),
            tcp_port: Some(AMULE_TCP_PORT),
            udp_port_tag: None,
            file_size: Some(65_536),
            encryption: Some(0),
            ipv6: None,
            buddy: Some(rmule_kad::KadBuddyContact {
                buddy_id: KadId::from_bytes(RMULE_KAD_ID),
                buddy_udp: Some(Ipv4Endpoint::new(RMULE_IP, RMULE_KAD_UDP_PORT)),
                buddy_ipv6: None,
                buddy_udp_ipv6: None,
            }),
        },
        "every tag the firewalled publisher wrote, as the widened reader sees it",
    );
}

/// Tag order and widths, off the bytes rather than off the projection: the
/// publisher's order is `SOURCETYPE, SERVERIP, SERVERPORT, BUDDYHASH,
/// SOURCEPORT, FILESIZE, ENCRYPTION`, and `ENCRYPTION` rides last — the one
/// tag `CSearch::StorePacket` appends after the firewalled/direct branch.
#[test]
fn the_publisher_writes_its_tags_in_one_order_at_pinned_widths() {
    let f = frame();
    // `[type][namelen LE16][name][value]`, walked from the tag count.
    let mut at = 35;
    let mut seen = Vec::new();
    for _ in 0..f[34] {
        let (tag_type, name) = (f[at], f[at + 3]);
        let value_len = match tag_type {
            0x02 => 2 + usize::from(crate::fixture::le_u16(&f[at + 4..at + 6])),
            0x03 => 4,
            0x08 => 2,
            0x09 => 1,
            other => panic!("unmodelled tag type {other:#04x}"),
        };
        seen.push((name, tag_type));
        at += 4 + value_len;
    }
    assert_eq!(at, f.len(), "the tag list accounts for the whole datagram");
    assert_eq!(
        seen,
        vec![
            (0xFF, 0x09), // SOURCETYPE, UINT8
            (0xFB, 0x03), // SERVERIP,   UINT32
            (0xFA, 0x08), // SERVERPORT, UINT16
            (0xF8, 0x02), // BUDDYHASH,  STRING
            (0xFD, 0x08), // SOURCEPORT, UINT16
            (0x02, 0x03), // FILESIZE,   UINT32
            (0xF3, 0x09), // ENCRYPTION, UINT8
        ],
    );
}

/// The trap the three reference trees disagreed on. aMule encodes
/// `TAG_BUDDYHASH` from `CUInt128::ToByteArray` — big-endian, which is the
/// per-32-bit-word byte swap of the order the same ID travels in everywhere
/// else on the Kad wire — and in **upper-case** hex (`CMD4Hash::Encode`).
/// eMule 0.70b and eMuleAI encode it from `GetData()` and would have written
/// the other string; the asymmetric pin is what makes the two distinguishable.
#[test]
fn the_buddy_hash_is_upper_case_big_endian_not_the_wire_order() {
    let f = frame();
    let tag = f
        .windows(4)
        .position(|w| w == [0x02, 0x01, 0x00, 0xF8])
        .expect("the row carries TAG_BUDDYHASH as a string tag");
    assert_eq!(
        crate::fixture::le_u16(&f[tag + 4..tag + 6]),
        32,
        "32 hex characters, the MD4-hash string form",
    );
    let text = std::str::from_utf8(&f[tag + 6..tag + 38]).expect("hex is ascii");

    let big_endian: String = RMULE_KAD_ID
        .chunks_exact(4)
        .flat_map(|word| word.iter().rev())
        .map(|byte| format!("{byte:02X}"))
        .collect();
    assert_eq!(
        text, big_endian,
        "ToByteArray's big-endian bytes, upper case — not GetData's word order",
    );
    let wire_order: String = RMULE_KAD_ID.iter().map(|b| format!("{b:02X}")).collect();
    assert_ne!(
        text, wire_order,
        "the pin is asymmetric, so the two encodings are distinguishable",
    );
}

/// The captured row's buddy ID in both of its spellings. The
/// primary is the aMule reading this capture pins, unchanged; the fallback is
/// the eMule 0.70b / eMuleAI `GetData()` reading of the same 32 characters,
/// exactly one per-32-bit-word byte swap away. Against this aMule row the
/// fallback names nobody — it exists for the other family's rows.
#[test]
fn the_captured_buddy_hash_keeps_its_primary_and_offers_the_word_swapped_fallback() {
    let Kad2Message::PublishSourceReq { source, .. } = decoded() else {
        panic!("0x44 decodes to a publish");
    };
    let buddy = source.buddy.expect("a type-3 row names a buddy");
    assert_eq!(
        buddy.buddy_id,
        KadId::from_bytes(RMULE_KAD_ID),
        "the primary"
    );
    assert_eq!(
        buddy.fallback_buddy_id(),
        Some(KadId::from_bytes(kad_wire_id(RMULE_KAD_ID))),
        "the fallback: the primary with each four-byte word reversed",
    );
}

/// The relationship the hash states, checked the way aMule itself checks it:
/// the buddy ID is the publisher's own Kad ID complemented, which is why a
/// requester can walk to it without being told the buddy's address.
#[test]
fn the_named_buddy_is_the_publishers_own_inverted_kad_id() {
    let Kad2Message::PublishSourceReq { source, .. } = decoded() else {
        panic!("0x44 decodes to a publish");
    };
    let buddy = source.buddy.expect("a type-3 row names a buddy");
    let complement: Vec<u8> = buddy.buddy_id.as_bytes().iter().map(|b| !b).collect();
    assert_eq!(complement, AMULE_KAD_ID);
}

/// The row is only reachable because the storer will pair it with what it
/// observed. The publisher names no IP of its own — no `TAG_SOURCEIP` — and
/// the only address in the datagram is the buddy's.
#[test]
fn the_publisher_names_no_address_of_its_own() {
    let f = frame();
    assert!(
        !f[34..].windows(4).any(|w| w == [0x03, 0x01, 0x00, 0xFE]),
        "TAG_SOURCEIP is the storer's to synthesise from the sender it saw",
    );
    let Kad2Message::PublishSourceReq { source, .. } = decoded() else {
        panic!("0x44 decodes to a publish");
    };
    assert_eq!(
        source
            .buddy
            .and_then(|buddy| buddy.buddy_udp)
            .map(|udp| udp.ip),
        Some(RMULE_IP),
    );
}

/// rmule's own **publisher** against the same bytes — the node's writer, not
/// just the codec: a node standing where the counterparty stood (its User
/// Hash, its TCP port, the buddy it held) and told the connect options a
/// crypt-less aMule publisher holds, publishing the same file, fans out this
/// exact datagram.
///
/// The told byte is the honest input, not a patch-up: the counterparty ran
/// with no crypt layer, no verified-open UDP (it was firewalled behind a
/// buddy) and no NAT-T — aMule's `CPrefs::GetMyConnectOptions`
/// (`src/kademlia/kademlia/Prefs.cpp:214-233`, Fork Pin `ab483654`) lights
/// nothing for that, and the capture's `0x00` says so. Core's composer
/// derives the same byte from the same three facts.
#[test]
fn rmules_publisher_reproduces_the_captured_datagram() {
    use rmule_kad::{KadCommand, KadInstant, KadNode, KadNodeConfig, KadNodeEndpoint};

    let f = frame();
    let Kad2Message::PublishSourceReq {
        file,
        source_id,
        source,
    } = decoded()
    else {
        panic!("0x44 decodes to a publish");
    };
    // The row's source ID is the User Hash word-swapped, and so is the file
    // key from the file hash: the swap is self-inverse, so undoing it is
    // applying it again.
    let now = KadInstant::EPOCH;
    let mut node = KadNode::new(KadNodeStart::new(
        KadNodeConfig {
            id: KadId::from_bytes(AMULE_KAD_ID),
            tcp_port: AMULE_TCP_PORT,
            udp_port: 4672,
            user_hash: rmule_primitives::UserHash::from_bytes(kad_wire_id(source_id)),
        },
        KadInstant::EPOCH,
    ));
    node.handle_command(
        now,
        KadCommand::SetPublishPosture {
            posture: rmule_kad::KadPublishPosture::Firewalled {
                buddy: source.buddy,
            },
        },
    );
    node.handle_command(
        now,
        KadCommand::SetPublishConnectOptions {
            options: Some(0x00),
        },
    );
    let storer = KadNodeEndpoint::new(std::net::Ipv4Addr::new(203, 0, 113, 6), 4690);
    let mut near = *file.as_bytes();
    near[15] ^= 0x01;
    node.handle_datagram(
        now,
        storer,
        &rmule_testkit::kad_node::hello_req_from(KadId::from_bytes(near), storer),
    );
    let _ = rmule_testkit::drain_split(&mut node);
    node.handle_command(
        now,
        KadCommand::PublishSource {
            request: rmule_kad::KadPublishRequest::new(rmule_primitives::SourceLookupTarget::new(
                rmule_primitives::FileHash::from_bytes(kad_wire_id(*file.as_bytes())),
                source.file_size.expect("the captured row carries its size"),
            )),
        },
    );
    let _ = rmule_testkit::drain_split(&mut node);
    node.handle_datagram(
        now,
        storer,
        &rmule_testkit::kad_node::lookup_res_bytes(file, &[]),
    );
    let (datagrams, _) = rmule_testkit::drain_split(&mut node);

    let published: Vec<_> = datagrams
        .iter()
        .filter(|(_, bytes)| bytes.get(1) == Some(&OP_PUBLISH_SOURCE_REQ))
        .collect();
    assert_eq!(published.len(), 1, "one storer, one publish");
    assert_eq!(
        published[0].1, f,
        "byte-for-byte, the counterparty's own datagram"
    );
}

/// The `0x52 KADEMLIA_CALLBACK_REQ` a downloader sends toward this row's buddy
/// (ADR-0061 route 4), built from the captured row and proven
/// against the same bytes rather than a reading of `WriteUInt128`:
///
/// - its buddy ID is the relationship ID the row named — the ID rmule, the
///   buddy in this run, answered the publisher's recruitment under;
/// - its file field is the file key the publisher itself wrote, because aMule
///   writes both through `WriteUInt128` (`BaseClient.cpp:2136-2138`,
///   `CSearch::PreparePacketForTags`), so a raw MD4 hash that a source lookup
///   turns into this key must turn into this field too;
/// - it goes out **plaintext**, whatever the node could encrypt under — aMule:
///   "we don't know which kadversion the buddy has, so we need to send
///   unencrypted" (`BaseClient.cpp:2141-2149`).
#[test]
fn a_callback_request_toward_the_captured_buddy_speaks_the_publishers_byte_order() {
    let f = frame();
    let Kad2Message::PublishSourceReq { file, source, .. } = decoded() else {
        panic!("0x44 decodes to a publish");
    };
    let buddy = source.buddy.expect("a firewalled row names its buddy");
    let buddy_udp = buddy
        .buddy_udp
        .expect("the row carried the buddy's endpoint");

    // The Synthetic File's raw ED2K hash, anchored to the captured key by the
    // source-lookup transform every Kad search already rides.
    let raw = rmule_primitives::FileHash::from_bytes([
        0x8E, 0x30, 0x2D, 0xB5, 0xB8, 0x06, 0xA2, 0x5C, 0x93, 0x85, 0xFC, 0x23, 0xF2, 0x10, 0x62,
        0xD2,
    ]);
    assert_eq!(
        rmule_kad::KadSourceLookupRequest::new(rmule_primitives::SourceLookupTarget::new(
            raw, 65_536
        ))
        .kad_target(),
        file,
        "the raw hash is the one the publisher keyed its row by"
    );

    let mut node = rmule_testkit::kad_node::node();
    let to = rmule_kad::KadNodeEndpoint::new(buddy_udp.ip, buddy_udp.port);
    node.handle_command(
        rmule_testkit::kad_node::T0,
        rmule_kad::KadCommand::RequestBuddyCallback {
            buddy: to,
            buddy_id: buddy.buddy_id,
            file_hash: raw,
            tcp_port: 4662,
        },
    );
    let sent = rmule_testkit::kad_node::datagrams(&rmule_primitives::session::drain(|| {
        node.poll_output()
    }));
    let [(dest, bytes)] = sent.as_slice() else {
        panic!("exactly one datagram: {sent:?}");
    };
    assert_eq!(*dest, to, "addressed to the buddy's UDP endpoint");
    assert_eq!(
        bytes[..2],
        [KAD_PROTO, 0x52],
        "a plain KADEMLIA_CALLBACK_REQ"
    );
    assert_eq!(bytes[2..18], RMULE_KAD_ID, "the buddy's relationship ID");
    assert_eq!(
        bytes[18..34],
        f[2..18],
        "the file key, as the publisher wrote it"
    );
    assert_eq!(
        bytes[34..],
        4662u16.to_le_bytes(),
        "our TCP port, and nothing after"
    );
}
