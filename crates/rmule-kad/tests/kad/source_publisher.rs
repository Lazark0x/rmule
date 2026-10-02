//! The Kad Publisher: the `0x44` fan a publish command converges into, the
//! ack window that completes a round, the republish it schedules, and the
//! paging a search walks through.

use std::net::Ipv4Addr;

use rmule_kad::{
    Kad2Message, KadCommand, KadDecoded, KadEvent, KadId, KadInstant, KadNode, KadNodeConfig,
    KadNodeDiagnostic, KadNodeEndpoint, KadPublishEnd, KadPublishedSource, decode_exact,
};
use rmule_primitives::UserHash;
use rmule_testkit::drain_split;
use rmule_testkit::kad_node::{hello_req_from, lookup_res_bytes};
use rmule_testkit::kad_source::{
    FILE_KEY, contact_endpoint, direct_publish, far_storer, id_near_key, key, lan_publisher,
    publish_request, rows_answered_to, search_datagram, searcher,
};

/// The publisher's User Hash: what its `0x44` rows carry, word-swapped into
/// [`PUBLISHER_SOURCE_ID_WIRE`].
const PUBLISHER_USER_HASH: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34,
];

const PUBLISHER_SOURCE_ID_WIRE: [u8; 16] = [
    0x04, 0x03, 0x02, 0x01, 0x14, 0x13, 0x12, 0x11, 0x24, 0x23, 0x22, 0x21, 0x34, 0x33, 0x32, 0x31,
];

fn publisher_node() -> KadNode {
    KadNode::new(KadNodeConfig {
        id: KadId::from_bytes([0x0F; 16]),
        tcp_port: 4662,
        udp_port: 4672,
        user_hash: UserHash::from_bytes(PUBLISHER_USER_HASH),
    })
}

fn publish_res_bytes(file: KadId, load: u8) -> Vec<u8> {
    publish_res_bytes_with_options(file, load, 0)
}

fn publish_res_bytes_with_options(file: KadId, load: u8, options: u8) -> Vec<u8> {
    Kad2Message::PublishRes {
        file,
        load,
        options,
    }
    .encode()
    .encode()
}

/// A publisher with three validated contacts near the key, driven through
/// its walk until it fans the `0x44` to exactly those three.
fn fanned_publisher(now: KadInstant, file_size: u64) -> (KadNode, [KadNodeEndpoint; 3]) {
    let mut node = publisher_node();
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

#[test]
fn publish_command_converges_the_walk_into_the_documented_0x44_fan() {
    let now = KadInstant::EPOCH;
    let (mut node, fan) = fanned_publisher(now, 65_536);
    let (datagrams, events) = drain_split(&mut node);

    // The publisher's own endpoint tags, in the capture-pinned publisher order
    // — no SOURCEIP and no SOURCEUPORT (the storer substitutes both from its
    // own observation), no ENCRYPTION (deferred until obfuscated dialling),
    // FILESIZE as u32.
    let expected = Kad2Message::PublishSourceReq {
        file: key(),
        source_id: PUBLISHER_SOURCE_ID_WIRE,
        source: KadPublishedSource {
            source_type: Some(1),
            tcp_port: Some(4662),
            // No SOURCEUPORT: the storer indexes the port it observed, which
            // is the only one a NAT in the path leaves correct.
            udp_port_tag: None,
            file_size: Some(65_536),
            encryption: None,
            ..KadPublishedSource::default()
        },
    }
    .encode()
    .encode();
    assert_eq!(
        datagrams,
        vec![
            (fan[0], expected.clone()),
            (fan[1], expected.clone()),
            (fan[2], expected),
        ],
        "convergence fans the documented 0x44 to the three closest responded"
    );
    assert_eq!(events, vec![], "publishing is not an outcome yet");
    assert_eq!(
        node.next_wake(),
        Some(now + KadNode::PUBLISH_ACK_WINDOW),
        "the ack window is armed"
    );
}

#[test]
fn a_publish_res_requesting_the_0x4c_ack_stays_dormant_on_the_plain_path() {
    // ADR-0062: aMule answers a 0x4B that set options bit 0 with a
    // null-payload KADEMLIA2_PUBLISH_RES_ACK (0x4C), but only when the datagram
    // carried a crypt sender key. rmule threads no crypt sender key yet, so a
    // plain-path 0x4B — even one that requests the ack — provably draws no 0x4C
    // while the ack itself is still counted.
    let now = KadInstant::EPOCH;
    let (mut node, fan) = fanned_publisher(now, 65_536);
    let _ = drain_split(&mut node);

    node.handle_datagram(now, fan[0], &publish_res_bytes_with_options(key(), 1, 0x01));
    let (datagrams, events) = drain_split(&mut node);

    assert!(
        !datagrams
            .iter()
            .any(|(_, bytes)| bytes.get(1) == Some(&0x4C)),
        "no 0x4C publish-res-ack is emitted on the plain path"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, KadEvent::PublishAcked { .. })),
        "the ack is still counted"
    );
}

#[test]
fn oversized_file_publishes_as_type_four_with_a_widened_size_tag() {
    // TAG_FILESIZE is aMule's CTagVarInt (Tag.h:186-195, Fork Pin
    // ab483654), which widens past u32::MAX to UINT64 rather than dropping
    // the tag. The row-type choice (4, "large") is a separate fact, keyed on
    // OLD_MAX_FILE_SIZE (pinned by the boundary test below), not on this
    // tag's width.
    let now = KadInstant::EPOCH;
    let large = u64::from(u32::MAX) + 1;
    let (mut node, fan) = fanned_publisher(now, large);
    let (datagrams, _) = drain_split(&mut node);

    let expected = Kad2Message::PublishSourceReq {
        file: key(),
        source_id: PUBLISHER_SOURCE_ID_WIRE,
        source: KadPublishedSource {
            source_type: Some(4),
            tcp_port: Some(4662),
            // No SOURCEUPORT: the storer indexes the port it observed, which
            // is the only one a NAT in the path leaves correct.
            udp_port_tag: None,
            // >4 GiB no longer fits the u32 tag, so it widens to UINT64
            // (TagValue::compact_uint64) instead of the tag disappearing.
            file_size: Some(large),
            encryption: None,
            ..KadPublishedSource::default()
        },
    }
    .encode()
    .encode();
    assert_eq!(datagrams[0], (fan[0], expected));
}

/// The type boundary is `OLD_MAX_FILE_SIZE` = 4 290 048 000, compared with
/// `>` (kno `KnownFile.h:129` `IsLargeFile`, `Constants.h:89`; eMuleAI
/// `Search.cpp:901`, `Opcodes.h:165`), not the `u32` range: one byte past it
/// is type 4 though it still fits a `UINT32` `TAG_FILESIZE`, and the boundary
/// itself is type 1.
#[test]
fn the_large_file_type_starts_one_byte_past_old_max_file_size() {
    const OLD_MAX_FILE_SIZE: u64 = 4_290_048_000;
    let source_type = |file_size: u64| {
        let (mut node, _) = fanned_publisher(KadInstant::EPOCH, file_size);
        let (datagrams, _) = drain_split(&mut node);
        let KadDecoded::Plain(envelope) = decode_exact(&datagrams[0].1).unwrap() else {
            panic!("publishes are plain 0xE4");
        };
        let Ok(Kad2Message::PublishSourceReq { source, .. }) = Kad2Message::decode(&envelope)
        else {
            panic!("the fan carries a 0x44");
        };
        (source.source_type, source.file_size)
    };

    assert_eq!(
        source_type(OLD_MAX_FILE_SIZE),
        (Some(1), Some(OLD_MAX_FILE_SIZE))
    );
    assert_eq!(
        source_type(OLD_MAX_FILE_SIZE + 1),
        (Some(4), Some(OLD_MAX_FILE_SIZE + 1)),
        "one byte past the boundary is large, inside the u32 range"
    );
}

#[test]
fn all_acks_complete_the_publish_early_and_schedule_the_republish() {
    let now = KadInstant::EPOCH;
    let (mut node, fan) = fanned_publisher(now, 65_536);
    let _ = drain_split(&mut node);

    for (i, endpoint) in fan.iter().enumerate() {
        node.handle_datagram(
            now,
            *endpoint,
            &publish_res_bytes(key(), 10 * (i as u8 + 1)),
        );
    }
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(datagrams, vec![], "acks trigger no further datagrams");
    assert_eq!(
        events,
        vec![
            KadEvent::PublishAcked {
                target: key(),
                from: fan[0],
                load: 10,
            },
            KadEvent::PublishAcked {
                target: key(),
                from: fan[1],
                load: 20,
            },
            KadEvent::PublishAcked {
                target: key(),
                from: fan[2],
                load: 30,
            },
            KadEvent::PublishComplete {
                target: key(),
                acked_stores: 3,
                ended_by: KadPublishEnd::AllStoresAcked,
            },
        ]
    );
    assert_eq!(
        node.next_wake(),
        Some(now + KadNode::SOURCE_REPUBLISH_INTERVAL),
        "the next republish is anchored at the publish start"
    );
}

#[test]
fn partial_acks_complete_when_the_ack_window_elapses() {
    let now = KadInstant::EPOCH;
    let (mut node, fan) = fanned_publisher(now, 65_536);
    let _ = drain_split(&mut node);

    node.handle_datagram(now, fan[1], &publish_res_bytes(key(), 5));
    let _ = drain_split(&mut node);
    node.tick(now + KadNode::PUBLISH_ACK_WINDOW);
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        events,
        vec![KadEvent::PublishComplete {
            target: key(),
            acked_stores: 1,
            ended_by: KadPublishEnd::WindowElapsed,
        }]
    );

    // A straggler ack after completion is unsolicited.
    node.handle_datagram(
        now + KadNode::PUBLISH_ACK_WINDOW,
        fan[0],
        &publish_res_bytes(key(), 5),
    );
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        events,
        vec![KadEvent::Diagnostic(
            KadNodeDiagnostic::UnsolicitedPublishRes { from: fan[0] }
        )]
    );
}

#[test]
fn publish_res_gating_mirrors_the_search_side() {
    let now = KadInstant::EPOCH;
    let (mut node, fan) = fanned_publisher(now, 65_536);
    let _ = drain_split(&mut node);

    // Never-fanned endpoint: unsolicited.
    node.handle_datagram(now, contact_endpoint(99), &publish_res_bytes(key(), 1));
    // Fanned endpoint acking the wrong key: target mismatch, not consumed.
    let mut wrong = FILE_KEY;
    wrong[0] ^= 0xFF;
    node.handle_datagram(now, fan[0], &publish_res_bytes(KadId::from_bytes(wrong), 1));
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        events,
        vec![
            KadEvent::Diagnostic(KadNodeDiagnostic::UnsolicitedPublishRes {
                from: contact_endpoint(99)
            }),
            KadEvent::Diagnostic(KadNodeDiagnostic::PublishResTargetMismatch { from: fan[0] }),
        ]
    );

    // The mismatched ack did not count: the window closes with zero stores.
    node.tick(now + KadNode::PUBLISH_ACK_WINDOW);
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        events,
        vec![KadEvent::PublishComplete {
            target: key(),
            acked_stores: 0,
            ended_by: KadPublishEnd::WindowElapsed,
        }]
    );
}

#[test]
fn publish_with_an_empty_table_completes_and_still_schedules_the_retry() {
    let now = KadInstant::EPOCH;
    let mut node = publisher_node();

    node.handle_command(
        now,
        KadCommand::PublishSource {
            request: publish_request(65_536),
        },
    );
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(datagrams, vec![]);
    assert_eq!(
        events,
        vec![KadEvent::PublishComplete {
            target: key(),
            acked_stores: 0,
            ended_by: KadPublishEnd::NoPublishableContacts,
        }]
    );
    assert_eq!(
        node.next_wake(),
        Some(now + KadNode::SOURCE_REPUBLISH_INTERVAL),
        "an unpublishable file retries on the republish cadence"
    );
}

#[test]
fn republish_fires_on_tick_and_duplicate_commands_are_diagnosed() {
    let now = KadInstant::EPOCH;
    let (mut node, fan) = fanned_publisher(now, 65_536);
    let _ = drain_split(&mut node);
    for endpoint in fan {
        node.handle_datagram(now, endpoint, &publish_res_bytes(key(), 1));
    }
    let _ = drain_split(&mut node);

    // A second command for the same target keeps the registration.
    node.handle_command(
        now,
        KadCommand::PublishSource {
            request: publish_request(65_536),
        },
    );
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        events,
        vec![KadEvent::Diagnostic(KadNodeDiagnostic::DuplicatePublish {
            target: key()
        })]
    );

    // At the interval the registration starts a fresh walk toward the key.
    let republish_at = now + KadNode::SOURCE_REPUBLISH_INTERVAL;
    node.tick(republish_at);
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(datagrams.len(), 3, "a fresh α wave of lookups goes out");
    for (_, bytes) in &datagrams {
        assert_eq!(bytes[1], 0x21, "republish re-walks before re-publishing");
    }
    // And the wave after this one is anchored at the refire instant.
    for d in [10, 20, 30] {
        node.handle_datagram(
            republish_at,
            contact_endpoint(d),
            &lookup_res_bytes(key(), &[]),
        );
    }
    for endpoint in fan {
        node.handle_datagram(republish_at, endpoint, &publish_res_bytes(key(), 2));
    }
    let _ = drain_split(&mut node);
    assert_eq!(
        node.next_wake(),
        Some(republish_at + KadNode::SOURCE_REPUBLISH_INTERVAL)
    );
}

#[test]
fn search_start_position_pages_through_newest_first_rows() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();
    for d in [1u8, 2, 3] {
        node.handle_datagram(now, lan_publisher(d), &direct_publish(key(), d));
    }
    let _ = drain_split(&mut node);

    node.handle_datagram(now, searcher(), &search_datagram(key(), 1, 0));
    let (datagrams, _) = drain_split(&mut node);
    let rows = rows_answered_to(&datagrams, searcher());
    let ips: Vec<Ipv4Addr> = rows
        .iter()
        .map(|row| {
            row.peer_source()
                .unwrap()
                .as_peer_endpoint()
                .unwrap()
                .as_v4()
                .expect("a High-ID row is IPv4")
                .ip
        })
        .collect();
    assert_eq!(
        ips,
        vec![lan_publisher(2).ip(), lan_publisher(1).ip()],
        "start=1 skips the newest row; answers stay newest-first"
    );
}

// --- mesh-tier acceptance -----------------------------------------------------

/// The `ip6` tag is gated on a Known address carried in by the Advertised
/// Endpoints chooser (ADR-0084/0087). The node never reads an interface of its
/// own, so with no verdict the publish is byte-identical to before; once one
/// arrives the tag rides, and when it clears the tag goes with it — the tag is
/// a claim that this address works *now*.
#[test]
fn the_ip6_publish_tag_follows_the_choosers_verdict_and_nothing_else() {
    let now = KadInstant::EPOCH;
    let address: std::net::Ipv6Addr = "2a01:4f8::1".parse().unwrap();
    let hex = rmule_kad::ipv6_tags::encode_ipv6_hex(address);

    let with_address = publish_fan_under(now, Some(address));
    assert!(
        with_address
            .iter()
            .any(|(_, bytes)| contains(bytes, hex.as_bytes())),
        "a Known address puts its hex form on the publish"
    );

    let without = publish_fan_under(now, None);
    assert!(!without.is_empty(), "the fan still happens");
    for (_, bytes) in without {
        assert!(
            !contains(&bytes, b"ip6"),
            "no verdict, no tag — the node has no address of its own to read"
        );
    }
}

/// The node states only an address its own readers would take: a driver
/// that hands it an address failing `IsUsableTagIdentity` (link-local,
/// unique-local, loopback, unspecified, v4-mapped) publishes no `ip6` at all.
#[test]
fn an_unusable_advertised_ipv6_is_never_published() {
    let now = KadInstant::EPOCH;
    for unusable in ["fe80::1", "fd00::1", "::1", "::", "::ffff:45.55.200.8"] {
        let fan = publish_fan_under(now, Some(unusable.parse().unwrap()));
        assert!(!fan.is_empty(), "the fan still happens");
        for (_, bytes) in fan {
            assert!(!contains(&bytes, b"ip6"), "{unusable} is never stated");
        }
    }
}

/// The `0x44` fan a publisher emits while the chooser's verdict is `verdict`.
fn publish_fan_under(
    now: KadInstant,
    verdict: Option<std::net::Ipv6Addr>,
) -> Vec<(KadNodeEndpoint, Vec<u8>)> {
    let mut node = publisher_node();
    node.handle_command(now, KadCommand::SetAdvertisedIpv6 { address: verdict });
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
            request: publish_request(65_536),
        },
    );
    let _ = drain_split(&mut node);
    for d in [10, 20, 30] {
        node.handle_datagram(now, contact_endpoint(d), &lookup_res_bytes(key(), &[]));
    }
    drain_split(&mut node).0
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn a_withdrawn_file_is_not_republished_and_may_be_published_again() {
    let now = KadInstant::EPOCH;
    let (mut node, fan) = fanned_publisher(now, 65_536);
    let _ = drain_split(&mut node);
    for endpoint in fan {
        node.handle_datagram(now, endpoint, &publish_res_bytes(key(), 1));
    }
    let _ = drain_split(&mut node);

    node.handle_command(
        now,
        KadCommand::WithdrawSource {
            request: publish_request(65_536),
        },
    );
    node.tick(now + KadNode::SOURCE_REPUBLISH_INTERVAL);
    let (datagrams, _) = drain_split(&mut node);
    assert!(datagrams.is_empty(), "a withdrawn file is not republished");

    let later = now + KadNode::SOURCE_REPUBLISH_INTERVAL;
    node.handle_command(
        later,
        KadCommand::PublishSource {
            request: publish_request(65_536),
        },
    );
    let (datagrams, events) = drain_split(&mut node);
    assert!(
        !datagrams.is_empty(),
        "offered again, it is published again"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, KadEvent::Diagnostic(_))),
        "no longer a duplicate: {events:?}"
    );
}
