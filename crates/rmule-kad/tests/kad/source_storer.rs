//! The Kad Storer: what a publish puts in the bounded source index, the load
//! it acks, the caps and tolerance gates that refuse one, and the search serve
//! that hands the stored rows back.

use rmule_kad::KadNodeStart;
use std::net::Ipv4Addr;

use rmule_kad::{
    Kad2Message, KadBuddyContact, KadEvent, KadId, KadInstant, KadNode, KadNodeDiagnostic,
    KadNodeEndpoint, KadPublishRejection, KadPublishedSource,
};
use rmule_primitives::{Ipv4Endpoint, PeerEndpoint};
use rmule_testkit::drain_split;
use rmule_testkit::kad_source::{
    FILE_KEY, direct_publish, far_storer, key, lan_publisher, publish_datagram, rows_answered_to,
    search_datagram, searcher, storer_config,
};

/// A storer whose ID differs from the file key only in the least significant
/// word: the XOR distance's most significant 32-bit word is zero, so even a
/// WAN publisher is inside the tolerance gate.
fn near_storer() -> KadNode {
    let mut id = FILE_KEY;
    id[12] ^= 0x5A;
    KadNode::new(KadNodeStart::new(
        storer_config(KadId::from_bytes(id)),
        KadInstant::EPOCH,
    ))
}

/// A distinct LAN publisher endpoint for flood tests (u16-indexed). The last
/// octet stays fixed and non-zero so every flood row projects as a High ID
/// (the ClientId therefore always clears the Low ID threshold).
fn lan_publisher_wide(i: u16) -> KadNodeEndpoint {
    let [hi, lo] = i.to_be_bytes();
    KadNodeEndpoint::new(Ipv4Addr::new(10, hi, lo, 77), 5_000)
}

/// A WAN publisher endpoint (TEST-NET-2: subject to the tolerance gate).
fn wan_publisher(d: u8) -> KadNodeEndpoint {
    KadNodeEndpoint::new(Ipv4Addr::new(198, 51, 100, d), 4_000 + u16::from(d))
}

#[test]
fn lan_publish_is_indexed_and_acked_with_load_one() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();

    node.handle_datagram(now, lan_publisher(7), &direct_publish(key(), 0xB0));
    let (datagrams, events) = drain_split(&mut node);

    let expected_ack = Kad2Message::PublishRes {
        file: key(),
        load: 1,
        options: 0,
    }
    .encode()
    .encode();
    assert_eq!(datagrams, vec![(lan_publisher(7), expected_ack)]);
    assert_eq!(
        events,
        vec![
            KadEvent::HadContact {
                from: lan_publisher(7)
            },
            KadEvent::SourceIndexed {
                key: key(),
                rows_for_key: 1,
            }
        ]
    );
}

#[test]
fn stored_source_answers_search_with_a_reencoded_row_carrying_the_observed_ip() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();
    let publish = direct_publish(key(), 0xB0);
    node.handle_datagram(now, lan_publisher(7), &publish);
    let _ = drain_split(&mut node);

    node.handle_datagram(now, searcher(), &search_datagram(key(), 0, 65_536));
    let (datagrams, events) = drain_split(&mut node);

    // The publisher never sent a SOURCEIP tag (there is none in the 0x44
    // layout), so the IP in the answer can only be the storer's own
    // observation of the publish datagram's sender — a re-encoding by
    // construction, not an echo.
    assert!(
        !publish
            .windows(4)
            .any(|window| window == [10, 0, 0, 7] || window == [7, 0, 0, 10]),
        "the publish datagram must not contain the sender IP in any byte order"
    );
    let rows = rows_answered_to(&datagrams, searcher());
    assert_eq!(rows.len(), 1);
    let source = rows[0].peer_source().expect("a direct HighID row");
    assert_eq!(
        source.as_peer_endpoint().and_then(PeerEndpoint::as_v4),
        Some(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 7), 4662)),
        "answered IP is the observed publish sender, port is the published TCP port"
    );
    assert_eq!(
        events,
        vec![KadEvent::SourceSearchServed {
            from: searcher(),
            target: key(),
            rows: 1,
        }]
    );
}

/// A publish carrying `ip6` is re-served with it, as kno's storer does
/// (`KademliaUDPListener.cpp:1402`): the searcher reads one High-ID row
/// with the IPv6 beside it — the dual-stack source core's Dial Chooser picks
/// a family for. Stripping it would hide the publisher's IPv6 from
/// everyone who reached it through rmule.
#[test]
fn a_stored_ip6_is_re_served_beside_the_observed_ip() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();
    let ipv6: std::net::Ipv6Addr = "3fff:ed2:1::2".parse().unwrap();
    let publish = publish_datagram(
        key(),
        [0xB0; 16],
        KadPublishedSource {
            source_type: Some(1),
            tcp_port: Some(4662),
            ipv6: Some(ipv6),
            ..KadPublishedSource::default()
        },
    );
    node.handle_datagram(now, lan_publisher(7), &publish);
    let _ = drain_split(&mut node);

    node.handle_datagram(now, searcher(), &search_datagram(key(), 0, 0));
    let (datagrams, _) = drain_split(&mut node);

    let rows = rows_answered_to(&datagrams, searcher());
    let [row] = rows.as_slice() else {
        panic!("one publish, one row: {rows:?}");
    };
    assert_eq!(
        row.peer_source()
            .and_then(|source| source.as_peer_endpoint())
            .and_then(PeerEndpoint::as_v4),
        Some(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 7), 4662)),
    );
    assert_eq!(
        row.facts()
            .and_then(|facts| facts.ipv6)
            .map(|endpoint| (endpoint.ip, endpoint.port)),
        Some((ipv6, 4662)),
    );
}

/// A firewalled row's `bi6` goes through the store and back out, after its
/// `ip6`, as the last tag — the order eMuleAI's publisher writes and kno's
/// storer re-serves, upper-case as both writers spell it. A `bi6` the
/// publish reader refused (`IsUsableTagIdentity`: here v4-mapped) was never
/// stored, so it is never re-served; the row keeps its buddy trio either way.
#[test]
fn a_stored_bi6_is_re_served_last_and_an_unusable_one_never_is() {
    let own: std::net::Ipv6Addr = "3fff:ed2:1::7".parse().unwrap();
    let serve = |buddy_ipv6: std::net::Ipv6Addr| {
        let now = KadInstant::EPOCH;
        let mut node = far_storer();
        let publish = publish_datagram(
            key(),
            [0xB3; 16],
            KadPublishedSource {
                source_type: Some(3),
                tcp_port: Some(4662),
                encryption: Some(0x0B),
                ipv6: Some(own),
                buddy: Some(KadBuddyContact {
                    buddy_id: KadId::from_bytes([0xEF; 16]),
                    buddy_udp: Some(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 8), 4672)),
                    buddy_ipv6: Some(buddy_ipv6),
                    buddy_udp_ipv6: None,
                }),
                ..KadPublishedSource::default()
            },
        );
        node.handle_datagram(now, lan_publisher(7), &publish);
        let _ = drain_split(&mut node);
        node.handle_datagram(now, searcher(), &search_datagram(key(), 0, 0));
        let (datagrams, _) = drain_split(&mut node);
        let rows = rows_answered_to(&datagrams, searcher());
        let [(_, bytes)] = datagrams.as_slice() else {
            panic!("one row, one answer: {datagrams:?}");
        };
        (bytes.clone(), rows)
    };
    let tail = |name: &[u8; 3], hex: &[u8; 32]| {
        let mut tag = vec![0x02, 0x03, 0x00];
        tag.extend_from_slice(name);
        tag.extend_from_slice(&[0x20, 0x00]);
        tag.extend_from_slice(hex);
        tag
    };
    let ip6 = tail(b"ip6", b"3FFF0ED2000100000000000000000007");
    let bi6 = tail(b"bi6", b"3FFF0ED2000100000000000000000008");

    let (bytes, rows) = serve("3fff:ed2:1::8".parse().unwrap());
    assert!(
        bytes.ends_with(&[ip6.as_slice(), bi6.as_slice()].concat()),
        "the row closes `ip6` then `bi6`: {bytes:02X?}"
    );
    let [row] = rows.as_slice() else {
        panic!("one publish, one row: {rows:?}");
    };
    let buddy = row.facts().and_then(|facts| facts.buddy);
    assert_eq!(
        buddy.and_then(|contact| contact.buddy_ipv6),
        Some("3fff:ed2:1::8".parse().unwrap())
    );

    let (bytes, rows) = serve("::ffff:45.55.200.8".parse().unwrap());
    assert!(bytes.ends_with(&ip6), "no `bi6` after `ip6`: {bytes:02X?}");
    let [row] = rows.as_slice() else {
        panic!("one publish, one row: {rows:?}");
    };
    let buddy = row.facts().and_then(|facts| facts.buddy);
    assert_eq!(buddy.map(|contact| contact.buddy_ipv6), Some(None));
    assert_eq!(
        buddy.and_then(|contact| contact.buddy_udp),
        Some(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 8), 4672))
    );
}

#[test]
fn search_for_an_unknown_key_serves_zero_rows_and_stays_wire_silent() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();

    node.handle_datagram(now, searcher(), &search_datagram(key(), 0, 0));
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(datagrams, vec![], "an empty answer sends no datagram");
    assert_eq!(
        events,
        vec![
            KadEvent::HadContact { from: searcher() },
            KadEvent::SourceSearchServed {
                from: searcher(),
                target: key(),
                rows: 0,
            }
        ]
    );
}

#[test]
fn search_filters_rows_by_file_size() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();
    node.handle_datagram(now, lan_publisher(7), &direct_publish(key(), 0xB0));
    // A second publisher for the same key omits the size tag entirely.
    node.handle_datagram(
        now,
        lan_publisher(8),
        &publish_datagram(
            key(),
            [0xB1; 16],
            KadPublishedSource {
                source_type: Some(1),
                tcp_port: Some(4662),
                udp_port_tag: None,
                file_size: None,
                encryption: None,
                ..KadPublishedSource::default()
            },
        ),
    );
    let _ = drain_split(&mut node);

    // A mismatched search size excludes the sized row but not the sizeless one.
    node.handle_datagram(now, searcher(), &search_datagram(key(), 0, 999));
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(rows_answered_to(&datagrams, searcher()).len(), 1);

    // The matching size and the wildcard zero both return everything.
    for size in [65_536, 0] {
        node.handle_datagram(now, searcher(), &search_datagram(key(), 0, size));
        let (datagrams, _) = drain_split(&mut node);
        assert_eq!(rows_answered_to(&datagrams, searcher()).len(), 2);
    }
}

/// A publish over 4 GiB carries `TAG_FILESIZE` as `UINT64`
/// (aMule's `CTagVarInt` widens past `u32::MAX`, `Tag.h:186-195`). The storer
/// must decode that width, index the real size rather than treating it as
/// missing, and filter a search on it exactly as it would a `UINT32` size.
#[test]
fn the_storer_accepts_and_filters_on_a_uint64_widened_filesize_tag() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();
    let large = u64::from(u32::MAX) + 1;
    node.handle_datagram(
        now,
        lan_publisher(7),
        &publish_datagram(
            key(),
            [0xB2; 16],
            KadPublishedSource {
                source_type: Some(1),
                tcp_port: Some(4662),
                udp_port_tag: None,
                file_size: Some(large),
                encryption: None,
                ..KadPublishedSource::default()
            },
        ),
    );
    let _ = drain_split(&mut node);

    // A mismatched size (one byte short of the real one) excludes the row.
    node.handle_datagram(now, searcher(), &search_datagram(key(), 0, large - 1));
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(
        rows_answered_to(&datagrams, searcher()).len(),
        0,
        "a UINT64 size decoded as missing would wrongly match anything"
    );

    // The exact size, and the wildcard zero, both serve the row.
    for size in [large, 0] {
        node.handle_datagram(now, searcher(), &search_datagram(key(), 0, size));
        let (datagrams, _) = drain_split(&mut node);
        assert_eq!(rows_answered_to(&datagrams, searcher()).len(), 1);
    }
}

#[test]
fn republishing_from_the_same_endpoint_replaces_the_entry() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();
    node.handle_datagram(now, lan_publisher(7), &direct_publish(key(), 0xB0));
    let _ = drain_split(&mut node);

    node.handle_datagram(now, lan_publisher(7), &direct_publish(key(), 0xB0));
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        events,
        vec![KadEvent::SourceIndexed {
            key: key(),
            rows_for_key: 1,
        }],
        "a same-endpoint republish refreshes, never duplicates"
    );

    node.handle_datagram(now, searcher(), &search_datagram(key(), 0, 0));
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(rows_answered_to(&datagrams, searcher()).len(), 1);
}

// --- storer: bounds and hostile input ----------------------------------------

#[test]
fn per_key_cap_evicts_the_oldest_entry_and_reports_full_load() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();
    let cap = u16::try_from(KadNode::MAX_SOURCES_PER_KEY).unwrap();

    // Fill the key to its cap from distinct publishers, then one more.
    for i in 0..=cap {
        node.handle_datagram(now, lan_publisher_wide(i), &direct_publish(key(), 0xB0));
    }
    let (datagrams, events) = drain_split(&mut node);

    // Every publish was acked (the over-cap one evicted the oldest): the
    // documented load curve starts at 1 and saturates at 100.
    let loads: Vec<u8> = datagrams
        .iter()
        .map(|(_, bytes)| {
            assert_eq!(bytes[1], 0x4B);
            *bytes.last().unwrap()
        })
        .collect();
    assert_eq!(loads.len(), usize::from(cap) + 1);
    assert_eq!(loads[0], 1, "first entry for a key reports load 1");
    assert_eq!(
        loads[usize::from(cap) / 2],
        u8::try_from(usize::from(cap) / 2 * 100 / KadNode::MAX_SOURCES_PER_KEY).unwrap(),
        "mid-fill load follows the documented percentage curve"
    );
    assert_eq!(loads[usize::from(cap)], 100, "evicting publish reports 100");
    assert_eq!(
        events.len(),
        usize::from(cap) + 2,
        "every accepted publish emits SourceIndexed, plus the one silent→heard edge"
    );

    // Page through the whole index: the cap holds and publisher 0 (the
    // oldest) is gone while publisher 1 and the newest remain.
    let mut all_ips = Vec::new();
    let mut start = 0u16;
    loop {
        node.handle_datagram(now, searcher(), &search_datagram(key(), start, 0));
        let (datagrams, _) = drain_split(&mut node);
        let rows = rows_answered_to(&datagrams, searcher());
        if rows.is_empty() {
            break;
        }
        start += u16::try_from(rows.len()).unwrap();
        all_ips.extend(rows.iter().map(|row| {
            row.peer_source()
                .expect("all flood rows are direct")
                .as_peer_endpoint()
                .expect("flood rows are HighID")
                .as_v4()
                .expect("flood rows are IPv4")
                .ip
        }));
    }
    assert_eq!(all_ips.len(), KadNode::MAX_SOURCES_PER_KEY);
    let ip_of = |i: u16| lan_publisher_wide(i).ip();
    assert!(!all_ips.contains(&ip_of(0)), "the oldest entry was evicted");
    assert!(all_ips.contains(&ip_of(1)));
    assert!(all_ips.contains(&ip_of(cap)));
}

#[test]
fn total_index_cap_rejects_net_new_entries_but_allows_replacement() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();
    let total = u32::try_from(KadNode::MAX_SOURCE_INDEX_TOTAL).unwrap();

    // One entry per distinct key up to the total cap.
    for i in 0..total {
        let mut file = FILE_KEY;
        file[..4].copy_from_slice(&i.to_le_bytes());
        node.handle_datagram(
            now,
            lan_publisher(7),
            &direct_publish(KadId::from_bytes(file), 0xB0),
        );
    }
    let _ = drain_split(&mut node);

    // A net-new key is rejected with a diagnostic and no ack…
    let mut fresh = FILE_KEY;
    fresh[8] ^= 0xFF;
    node.handle_datagram(
        now,
        lan_publisher(9),
        &direct_publish(KadId::from_bytes(fresh), 0xB1),
    );
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(datagrams, vec![], "a rejected publish is wire-silent");
    assert_eq!(
        events,
        vec![KadEvent::Diagnostic(KadNodeDiagnostic::PublishRejected {
            from: lan_publisher(9),
            reason: KadPublishRejection::IndexFull,
        })]
    );

    // …while a same-endpoint replacement of an existing entry still lands.
    let mut existing = FILE_KEY;
    existing[..4].copy_from_slice(&0u32.to_le_bytes());
    node.handle_datagram(
        now,
        lan_publisher(7),
        &direct_publish(KadId::from_bytes(existing), 0xB0),
    );
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(datagrams.len(), 1, "replacement is acked");
    assert_eq!(
        events,
        vec![KadEvent::SourceIndexed {
            key: KadId::from_bytes(existing),
            rows_for_key: 1,
        }]
    );
}

#[test]
fn wan_publish_outside_tolerance_is_dropped_and_diagnosed() {
    let now = KadInstant::EPOCH;

    // Far storer + WAN sender: the XOR distance's top word is huge.
    let mut node = far_storer();
    node.handle_datagram(now, wan_publisher(7), &direct_publish(key(), 0xB0));
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(datagrams, vec![]);
    assert_eq!(
        events,
        vec![
            KadEvent::HadContact {
                from: wan_publisher(7)
            },
            KadEvent::Diagnostic(KadNodeDiagnostic::PublishOutsideTolerance {
                from: wan_publisher(7)
            })
        ]
    );

    // Near storer + the same WAN sender: inside tolerance, accepted.
    let mut node = near_storer();
    node.handle_datagram(now, wan_publisher(7), &direct_publish(key(), 0xB0));
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(datagrams.len(), 1, "in-tolerance WAN publish is acked");
    assert_eq!(
        events,
        vec![
            KadEvent::HadContact {
                from: wan_publisher(7)
            },
            KadEvent::SourceIndexed {
                key: key(),
                rows_for_key: 1,
            }
        ]
    );
}

#[test]
fn unindexable_publishes_are_diagnosed_without_growth() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();

    // No SOURCETYPE tag.
    node.handle_datagram(
        now,
        lan_publisher(7),
        &publish_datagram(
            key(),
            [0xB0; 16],
            KadPublishedSource {
                source_type: None,
                tcp_port: Some(4662),
                ..KadPublishedSource::default()
            },
        ),
    );
    // No SOURCEPORT tag.
    node.handle_datagram(
        now,
        lan_publisher(8),
        &publish_datagram(
            key(),
            [0xB1; 16],
            KadPublishedSource {
                source_type: Some(1),
                tcp_port: None,
                ..KadPublishedSource::default()
            },
        ),
    );
    // Zero TCP port.
    node.handle_datagram(
        now,
        lan_publisher(9),
        &publish_datagram(
            key(),
            [0xB2; 16],
            KadPublishedSource {
                source_type: Some(1),
                tcp_port: Some(0),
                ..KadPublishedSource::default()
            },
        ),
    );
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(datagrams, vec![], "nothing unindexable is ever acked");
    assert_eq!(
        events,
        vec![
            KadEvent::HadContact {
                from: lan_publisher(7)
            },
            KadEvent::Diagnostic(KadNodeDiagnostic::PublishRejected {
                from: lan_publisher(7),
                reason: KadPublishRejection::MissingSourceType,
            }),
            KadEvent::Diagnostic(KadNodeDiagnostic::PublishRejected {
                from: lan_publisher(8),
                reason: KadPublishRejection::MissingTcpPort,
            }),
            KadEvent::Diagnostic(KadNodeDiagnostic::PublishRejected {
                from: lan_publisher(9),
                reason: KadPublishRejection::MissingTcpPort,
            }),
        ]
    );

    node.handle_datagram(now, searcher(), &search_datagram(key(), 0, 0));
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        events,
        vec![KadEvent::SourceSearchServed {
            from: searcher(),
            target: key(),
            rows: 0,
        }],
        "the index stayed empty"
    );
}

// --- storer: expiry -----------------------------------------------------------

#[test]
fn entries_expire_on_tick_after_the_stored_lifetime() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();
    node.handle_datagram(now, lan_publisher(7), &direct_publish(key(), 0xB0));
    let _ = drain_split(&mut node);

    let expiry = now + KadNode::STORED_SOURCE_LIFETIME;
    assert_eq!(
        node.next_wake(),
        Some(expiry),
        "the storer arms a wake for the earliest entry expiry"
    );

    // One tick short of the lifetime the entry still answers.
    node.tick(KadInstant::from_millis(expiry.as_millis() - 1));
    node.handle_datagram(
        KadInstant::from_millis(expiry.as_millis() - 1),
        searcher(),
        &search_datagram(key(), 0, 0),
    );
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(rows_answered_to(&datagrams, searcher()).len(), 1);

    // At the lifetime it is pruned and the search misses.
    node.tick(expiry);
    node.handle_datagram(expiry, searcher(), &search_datagram(key(), 0, 0));
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(datagrams, vec![]);
    assert_eq!(
        events,
        vec![KadEvent::SourceSearchServed {
            from: searcher(),
            target: key(),
            rows: 0,
        }]
    );
    assert_eq!(node.next_wake(), None, "nothing left to expire");
}

// --- publisher: walk convergence into 0x44, ack consumption, republish ------
