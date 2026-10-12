//! The buddy source row, both directions: a firewalled rmule with
//! a held buddy publishes aMule's type-3/5 row, an rmule storer indexes and
//! re-serves it, and rmule's widened reader recovers every rung-1 fact it
//! carries — user hash, connect options, Kad UDP endpoint, buddy contact.
//! Beside it, the row that needs no buddy: a publisher that can
//! be called back by direct UDP publishes aMule's type 6, which comes back as
//! a direct-UDP-callable candidate.
//!
//! The layout under test is pinned to a firewalled aMule publisher's own
//! `0x44` — `buddy_publish_capture` is that capture, byte for byte. These
//! legs are the ring the capture cannot show: rmule's writer feeding rmule's
//! storer feeding rmule's reader, over sizes and slot states no single
//! captured datagram carries.

use rmule_kad::KadNodeStart;
use std::net::Ipv4Addr;

use rmule_kad::{
    Kad2Message, KadBuddyContact, KadCommand, KadId, KadInstant, KadNode, KadNodeConfig,
    KadNodeEndpoint, KadPublishPosture, KadSourceDiagnostic, KadSourceRowFacts,
};
use rmule_primitives::{Ipv4Endpoint, UserHash};
use rmule_testkit::drain_split;
use rmule_testkit::kad_node::{hello_req_from, lookup_res_bytes};
use rmule_testkit::kad_source::{
    contact_endpoint, far_storer, id_near_key, key, lan_publisher, publish_request,
    rows_answered_to, search_datagram, searcher,
};

/// The firewalled publisher's User Hash — what the row's source ID carries,
/// word-swapped.
const PUBLISHER_USER_HASH: [u8; 16] = [
    0x51, 0x52, 0x53, 0x54, 0x61, 0x62, 0x63, 0x64, 0x71, 0x72, 0x73, 0x74, 0x81, 0x82, 0x83, 0x84,
];

/// The buddy relationship ID a firewalled publisher advertises: `~ownKadID`
/// (aMule `CUInt128 buddyID(true); buddyID ^= GetKadID()`,
/// `src/kademlia/kademlia/Search.cpp:841-842`).
fn buddy_id() -> KadId {
    let mut bytes = [0u8; 16];
    for (slot, byte) in bytes.iter_mut().zip([0x0Fu8; 16]) {
        *slot = !byte;
    }
    KadId::from_bytes(bytes)
}

fn buddy_udp() -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000)
}

fn held_buddy() -> KadBuddyContact {
    KadBuddyContact {
        buddy_id: buddy_id(),
        buddy_udp: Some(buddy_udp()),
        buddy_ipv6: None,
        buddy_udp_ipv6: None,
    }
}

/// A publisher that has recruited a buddy and walked to three contacts near
/// the key, ready to fan its `0x44`.
fn firewalled_publisher(now: KadInstant, file_size: u64) -> (KadNode, [KadNodeEndpoint; 3]) {
    publisher_with(now, file_size, firewalled(Some(held_buddy())), None)
}

/// Core's firewalled posture over the slot's `buddy`.
fn firewalled(buddy: Option<KadBuddyContact>) -> KadPublishPosture {
    KadPublishPosture::Firewalled { buddy }
}

/// The same publisher with core's posture and the connect-options byte it
/// states left to the caller.
fn publisher_with(
    now: KadInstant,
    file_size: u64,
    posture: KadPublishPosture,
    connect_options: Option<u8>,
) -> (KadNode, [KadNodeEndpoint; 3]) {
    let mut node = KadNode::new(KadNodeStart::new(
        KadNodeConfig {
            id: KadId::from_bytes([0x0F; 16]),
            tcp_port: 4662,
            udp_port: 4672,
            user_hash: UserHash::from_bytes(PUBLISHER_USER_HASH),
        },
        KadInstant::EPOCH,
    ));
    node.handle_command(now, KadCommand::SetPublishPosture { posture });
    node.handle_command(
        now,
        KadCommand::SetPublishConnectOptions {
            options: connect_options,
        },
    );
    for d in [10, 20, 30] {
        node.handle_datagram(
            now,
            contact_endpoint(d),
            &hello_req_from(id_near_key(d), contact_endpoint(d)),
        );
    }
    let _ = drain_split(&mut node);
    node.handle_command(
        now,
        KadCommand::PublishSource {
            request: publish_request(file_size),
        },
    );
    let _ = drain_split(&mut node);
    for d in [10, 20, 30] {
        node.handle_datagram(now, contact_endpoint(d), &lookup_res_bytes(key(), &[]));
    }
    (
        node,
        [
            contact_endpoint(10),
            contact_endpoint(20),
            contact_endpoint(30),
        ],
    )
}

/// The publish half: a held buddy turns the row firewalled. The source type
/// is 3 (5 above the u32 size range) and the buddy trio rides along —
/// aMule `src/kademlia/kademlia/Search.cpp:841-862`.
#[test]
fn a_held_buddy_publishes_the_firewalled_row_instead_of_the_direct_one() {
    for (file_size, expected_type) in [(65_536u64, 3u8), (u64::from(u32::MAX) + 1, 5)] {
        let now = KadInstant::EPOCH;
        let (mut node, fan) = firewalled_publisher(now, file_size);
        let (datagrams, _) = drain_split(&mut node);

        let Kad2Message::PublishSourceReq { source, .. } = decode_publish(&datagrams[0].1) else {
            panic!("the fan carries a 0x44");
        };
        assert_eq!(datagrams.len(), fan.len());
        assert_eq!(
            source.source_type,
            Some(expected_type),
            "a firewalled publisher's row is type 3, or 5 above the u32 size range"
        );
        assert_eq!(
            source.buddy,
            Some(held_buddy()),
            "the buddy trio round-trips through the publish codec"
        );
    }
}

/// Aligned with aMule (`Search.cpp:626-628`, `4e8f2b3c`): a
/// firewalled publisher that lost its buddy stops publishing
/// (`PrepareToStop`) — its direct row would send every asker to a port
/// nobody can dial. A reachable one publishes the direct row.
#[test]
fn a_firewalled_publisher_with_no_buddy_publishes_no_row() {
    let now = KadInstant::EPOCH;
    let (mut node, _) = publisher_with(now, 65_536, firewalled(None), None);
    let (datagrams, _) = drain_split(&mut node);
    assert!(datagrams.is_empty(), "no 0x44 for an undialable node");

    let (mut node, _) = publisher_with(now, 65_536, KadPublishPosture::Reachable, None);
    let (datagrams, _) = drain_split(&mut node);
    let Kad2Message::PublishSourceReq { source, .. } = decode_publish(&datagrams[0].1) else {
        panic!("the fan carries a 0x44");
    };
    assert_eq!(source.source_type, Some(1));
    assert_eq!(source.buddy, None);
}

/// **KAT**: a buddy whose IPv6 core's slot stated closes the
/// firewalled row with `bi6` — the 40-byte string tag, 32 **upper-case** hex
/// characters, after `ENCRYPTION` (eMuleAI `Search.cpp:914-923`, `a2f05dc8`,
/// writes it there and in that case; kno reads it at `Search.cpp:1205`,
/// `ab483654`). The buddy trio before it is unchanged.
#[test]
fn a_held_buddy_with_an_ipv6_closes_the_firewalled_row_with_bi6() {
    let now = KadInstant::EPOCH;
    let buddy = KadBuddyContact {
        buddy_ipv6: Some("3fff:ed2:1::8".parse().unwrap()),
        buddy_udp_ipv6: None,
        ..held_buddy()
    };
    let (mut node, _) = publisher_with(now, 65_536, firewalled(Some(buddy)), None);
    let (datagrams, _) = drain_split(&mut node);
    let bytes = &datagrams[0].1;

    let mut bi6 = vec![0x02, 0x03, 0x00, b'b', b'i', b'6', 0x20, 0x00];
    bi6.extend_from_slice(b"3FFF0ED2000100000000000000000008");
    assert_eq!(&bytes[bytes.len() - 40..], bi6.as_slice());

    let Kad2Message::PublishSourceReq { source, .. } = decode_publish(bytes) else {
        panic!("the fan carries a 0x44");
    };
    assert_eq!(source.source_type, Some(3));
    // The reader pairs `bi6` with `TAG_SERVERPORT`, as eMuleAI's does
    // (`DownloadQueue.cpp:5005-5008`); the writer never sets that pairing.
    let read_back = KadBuddyContact {
        buddy_udp_ipv6: Some(rmule_primitives::Ipv6Endpoint::new(
            "3fff:ed2:1::8".parse().unwrap(),
            buddy_udp().port,
        )),
        ..buddy
    };
    assert_eq!(
        source.buddy,
        Some(read_back),
        "bi6 folds back into the contact"
    );
    assert_eq!(
        source.ipv6, None,
        "the buddy's address is not the publisher's"
    );
}

/// The whole ring: rmule's own writer → an rmule storer → rmule's widened
/// reader. The answered row is a buddy candidate — not the `BuddyCallback`
/// diagnostic it used to be — and it names every rung-1 fact.
#[test]
fn a_published_buddy_row_comes_back_through_the_storer_as_a_buddy_candidate() {
    let now = KadInstant::EPOCH;
    let (mut publisher, _) = firewalled_publisher(now, 65_536);
    let (published, _) = drain_split(&mut publisher);
    let publish_bytes = published[0].1.clone();

    // The publisher never names its own IP — the storer substitutes the
    // address it observed the datagram arrive from. The *buddy's* address, by
    // contrast, is the publisher's to state, and does travel.
    let mut storer = far_storer();
    storer.handle_datagram(now, lan_publisher(7), &publish_bytes);
    let _ = drain_split(&mut storer);

    storer.handle_datagram(now, searcher(), &search_datagram(key(), 0, 65_536));
    let (datagrams, _) = drain_split(&mut storer);

    let rows = rows_answered_to(&datagrams, searcher());
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].refusal(),
        None,
        "a buddy row with a usable contact is a candidate, not a refusal"
    );
    assert_eq!(
        rows[0].peer_source(),
        None,
        "a firewalled source is still not dialable"
    );
    assert_eq!(rows[0].buddy(), Some(held_buddy()));
    assert_eq!(
        rows[0].facts(),
        Some(KadSourceRowFacts {
            user_hash: UserHash::from_bytes(PUBLISHER_USER_HASH),
            source_type: 3,
            tcp_port: 4662,
            // The storer's observation of the publish sender, port included:
            // no publisher emits `TAG_SOURCEUPORT`, so the observed endpoint
            // is the whole of it.
            kad_udp: Some(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 7), 4007)),
            connect_options: None,
            buddy: Some(held_buddy()),
            ipv6: None,
        }),
        "every rung-1 fact the row carries survives the ring"
    );
}

/// A publisher that states its connect options — rmule's NAT-T
/// front runs on the socket its Kad node rides, so the uTP bit is a fact —
/// writes them into `TAG_ENCRYPTION`, and the storer re-serves them: the
/// reader's row is punchable. Stated nothing, the tag stays absent (above).
#[test]
fn a_stated_connect_options_byte_rides_the_row_through_the_storer() {
    let now = KadInstant::EPOCH;
    let (mut publisher, _) =
        publisher_with(now, 65_536, firewalled(Some(held_buddy())), Some(0x80));
    let (published, _) = drain_split(&mut publisher);
    let Kad2Message::PublishSourceReq { source, .. } = decode_publish(&published[0].1) else {
        panic!("the fan carries a 0x44");
    };
    assert_eq!(source.encryption, Some(0x80));

    let mut storer = far_storer();
    storer.handle_datagram(now, lan_publisher(7), &published[0].1);
    let _ = drain_split(&mut storer);
    storer.handle_datagram(now, searcher(), &search_datagram(key(), 0, 65_536));
    let (datagrams, _) = drain_split(&mut storer);
    let rows = rows_answered_to(&datagrams, searcher());
    let options = rows[0]
        .facts()
        .and_then(|facts| facts.connect_options)
        .expect("the storer re-serves TAG_ENCRYPTION");
    assert!(options.supports_natt_utp());
    assert!(!options.supports_crypt());
}

/// A type-3 row whose buddy tags are missing has nowhere to address a
/// callback, so it stays the refusal it always was — the widening never
/// invents a route.
#[test]
fn a_buddy_row_without_buddy_tags_is_still_a_refusal() {
    let now = KadInstant::EPOCH;
    let mut storer = far_storer();
    storer.handle_datagram(
        now,
        lan_publisher(8),
        &rmule_testkit::kad_source::publish_datagram(
            key(),
            [0xC1; 16],
            rmule_kad::KadPublishedSource {
                source_type: Some(3),
                tcp_port: Some(4662),
                udp_port_tag: Some(4672),
                file_size: Some(65_536),
                encryption: Some(0x8B),
                ..rmule_kad::KadPublishedSource::default()
            },
        ),
    );
    let _ = drain_split(&mut storer);

    storer.handle_datagram(now, searcher(), &search_datagram(key(), 0, 65_536));
    let (datagrams, _) = drain_split(&mut storer);
    let rows = rows_answered_to(&datagrams, searcher());

    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].refusal(),
        Some(KadSourceDiagnostic::BuddyCallback),
        "no buddy contact, no candidate"
    );
    // The connect-options byte is still read: eMuleAI publishes its NAT-T bits
    // here (bit 7 = uTP), which is the one thing that could make this source
    // punchable once it names a buddy.
    let facts = rows[0].facts().expect("a decoded row always has facts");
    let options = facts.connect_options.expect("TAG_ENCRYPTION was published");
    assert_eq!(options.as_byte(), 0x8B);
    assert!(options.supports_natt_utp());
    assert!(options.supports_direct_udp_callback());
    assert!(options.supports_crypt());
}

/// The row a firewalled publisher with a **direct UDP callback** publishes
/// Stated bit 3 of the connect options, no buddy needed, and
/// the row is aMule's type 6 — pinned tag by tag, width by width, against the
/// publisher that writes it (aMule `src/kademlia/kademlia/Search.cpp:821-835`
/// and `:883-884`, Fork Pin `ab483654`):
///
/// - `TAG_SOURCETYPE` `CTagVarInt(6)` — `UINT8` (`Tag.h:187-188` narrows it);
/// - `TAG_SOURCEPORT` `CTagVarInt(GetPort())` — `UINT16` for a port above 255;
/// - no `TAG_SOURCEUPORT`: `GetUseExternKadPort()` starts `true`;
/// - `TAG_FILESIZE` `CTagVarInt(size)` to a `from->GetVersion() >= 2` storer —
///   `UINT32` for a size in the u32 range;
/// - `TAG_ENCRYPTION` `CTagInt8(GetMyConnectOptions(true, true))` — bit 3
///   set by the same predicate that picked type 6 (`Prefs.cpp:224-226`).
///
/// No address of its own and no buddy trio: the storer pairs the row with
/// the address it observed the datagram arrive from.
#[test]
fn a_stated_direct_callback_bit_publishes_the_type_6_row() {
    let now = KadInstant::EPOCH;
    let (mut node, fan) = publisher_with(now, 65_536, firewalled(None), Some(0x08));
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(datagrams.len(), fan.len());

    let tags = &datagrams[0].1[34..];
    assert_eq!(
        tags,
        [
            0x04, // four tags
            0x09, 0x01, 0x00, 0xFF, 0x06, // TAG_SOURCETYPE, UINT8, 6
            0x08, 0x01, 0x00, 0xFD, 0x36, 0x12, // TAG_SOURCEPORT, UINT16, 4662
            0x03, 0x01, 0x00, 0x02, 0x00, 0x00, 0x01, 0x00, // TAG_FILESIZE, UINT32, 65536
            0x09, 0x01, 0x00, 0xF3, 0x08, // TAG_ENCRYPTION, UINT8, the told byte
        ],
        "aMule's type-6 row, in its publisher's order at its widths"
    );
}

/// aMule tests the direct callback *before* it looks at the buddy slot
/// (`Search.cpp:823-835` ahead of `:836`), so a publisher that can be called
/// back by UDP publishes type 6 even while a buddy is still held — above the
/// u32 size range too, since type 6 "supports >4GB" and has no large twin.
#[test]
fn the_direct_callback_bit_outranks_a_held_buddy() {
    for file_size in [65_536u64, u64::from(u32::MAX) + 1] {
        let now = KadInstant::EPOCH;
        let (mut node, _) =
            publisher_with(now, file_size, firewalled(Some(held_buddy())), Some(0x09));
        let (datagrams, _) = drain_split(&mut node);

        let Kad2Message::PublishSourceReq { source, .. } = decode_publish(&datagrams[0].1) else {
            panic!("the fan carries a 0x44");
        };
        assert_eq!(source.source_type, Some(6));
        assert_eq!(source.buddy, None, "a type-6 row names no buddy");
        assert_eq!(source.encryption, Some(0x09));
    }
}

/// The ring for type 6: rmule's writer → an rmule storer → rmule's reader.
/// The answered row is a **direct-UDP callback** candidate addressed at the
/// endpoint the storer observed — the one a `0x95` goes to (aMule
/// `CDownloadQueue::KademliaSearchFile` case 6, `src/DownloadQueue.cpp:1779-1797`,
/// `SetIP(ED2KID)` "which cannot be used for TCP but for UDP").
#[test]
fn a_published_type_6_row_comes_back_through_the_storer_as_a_direct_udp_candidate() {
    let now = KadInstant::EPOCH;
    let (mut publisher, _) = publisher_with(now, 65_536, firewalled(None), Some(0x08));
    let (published, _) = drain_split(&mut publisher);

    let mut storer = far_storer();
    storer.handle_datagram(now, lan_publisher(7), &published[0].1);
    let _ = drain_split(&mut storer);
    storer.handle_datagram(now, searcher(), &search_datagram(key(), 0, 65_536));
    let (datagrams, _) = drain_split(&mut storer);

    let rows = rows_answered_to(&datagrams, searcher());
    assert_eq!(rows.len(), 1);
    let observed = Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 7), 4007);
    assert_eq!(rows[0].refusal(), None, "a callable row is a candidate");
    assert_eq!(
        rows[0].peer_source(),
        None,
        "a firewalled source is not dialable"
    );
    assert_eq!(rows[0].buddy(), None);
    assert_eq!(rows[0].direct_udp_callback(), Some(observed));
    let facts = rows[0].facts().expect("a decoded row always has facts");
    assert_eq!(facts.source_type, 6);
    assert_eq!(facts.user_hash, UserHash::from_bytes(PUBLISHER_USER_HASH));
    assert!(
        facts
            .connect_options
            .is_some_and(rmule_primitives::SourceCryptOptions::supports_direct_udp_callback)
    );
}

/// A type-6 row that does not state bit 3 invites nothing: aMule drops it
/// ("has the direct callback flag not set", `src/DownloadQueue.cpp:1786-1792`),
/// and rmule keeps it as the `Firewalled` refusal it always was.
#[test]
fn a_type_6_row_without_the_direct_callback_bit_is_a_refusal() {
    let now = KadInstant::EPOCH;
    let mut storer = far_storer();
    storer.handle_datagram(
        now,
        lan_publisher(8),
        &rmule_testkit::kad_source::publish_datagram(
            key(),
            [0xC1; 16],
            rmule_kad::KadPublishedSource {
                source_type: Some(6),
                tcp_port: Some(4662),
                file_size: Some(65_536),
                encryption: Some(0x81),
                ..rmule_kad::KadPublishedSource::default()
            },
        ),
    );
    let _ = drain_split(&mut storer);
    storer.handle_datagram(now, searcher(), &search_datagram(key(), 0, 65_536));
    let (datagrams, _) = drain_split(&mut storer);
    let rows = rows_answered_to(&datagrams, searcher());

    assert_eq!(rows[0].refusal(), Some(KadSourceDiagnostic::Firewalled));
    assert_eq!(rows[0].direct_udp_callback(), None);
}

fn decode_publish(bytes: &[u8]) -> Kad2Message {
    let rmule_kad::KadDecoded::Plain(envelope) =
        rmule_kad::decode_exact(bytes).expect("a well-formed publish")
    else {
        panic!("publishes are plain 0xE4");
    };
    Kad2Message::decode(&envelope).expect("the publish codec round-trips")
}
