//! Mesh-level acceptance for the source DHT loop: publish, store, search and
//! republish closed inside an rmule-only `KadMeshSim`, including expiry misses
//! and a flooding fake peer meeting the per-key cap.

use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_kad::KadSourceLookupRequest;
use rmule_kad::{KadCommand, KadEvent, KadId, KadInstant, KadNode, KadNodeEndpoint, KadPublishEnd};
use rmule_primitives::{FileHash, Ipv4Endpoint, PeerEndpoint, SourceLookupTarget, kad_wire_id};
use rmule_testkit::kad_mesh::config as mesh_config;
use rmule_testkit::kad_mesh::{A, C, HUB, STORERS, a_endpoint, c_endpoint, hub_endpoint};
use rmule_testkit::kad_source::{
    FILE_KEY, contact_endpoint, direct_publish, id_near_key, key, publish_request,
};
use rmule_testkit::{FakeKadPeer, KadMeshSim, TraceEntry};

// requester
/// The requester-side lookup for the same file the publisher announces.
fn search_request() -> KadSourceLookupRequest {
    KadSourceLookupRequest::new(SourceLookupTarget::new(
        FileHash::from_bytes(kad_wire_id(FILE_KEY)),
        65_536,
    ))
}

/// A bootstrapped mesh: a far hub, three real storers near the key, a
/// publisher, and a requester. All endpoints are TEST-NET (non-LAN), so a
/// publish is accepted only through the storers' tolerance gate.
fn dht_mesh() -> KadMeshSim {
    let mut sim = KadMeshSim::new()
        .with_node(
            HUB,
            mesh_config(KadId::from_bytes([0xF0; 16]), hub_endpoint(), 0xF0),
            hub_endpoint(),
        )
        .with_node(
            A,
            mesh_config(KadId::from_bytes([0x0F; 16]), a_endpoint(), 0xAA),
            a_endpoint(),
        )
        .with_node(
            C,
            mesh_config(KadId::from_bytes([0xE0; 16]), c_endpoint(), 0xCC),
            c_endpoint(),
        );
    for (label, d) in STORERS {
        sim = sim.with_node(
            label,
            mesh_config(id_near_key(d), contact_endpoint(d), d),
            contact_endpoint(d),
        );
    }
    for (label, _) in STORERS {
        sim.command(
            label,
            KadCommand::Bootstrap {
                endpoint: hub_endpoint(),
            },
        );
    }
    sim.run_until_idle(10_000);
    sim.command(
        A,
        KadCommand::Bootstrap {
            endpoint: hub_endpoint(),
        },
    );
    sim.command(
        C,
        KadCommand::Bootstrap {
            endpoint: hub_endpoint(),
        },
    );
    sim.run_until_idle(10_000);
    sim
}

fn sources_found_for(trace: &[TraceEntry], label: &str) -> Vec<KadEvent> {
    trace
        .iter()
        .filter(|(_, at, event)| *at == label && matches!(event, KadEvent::SourcesFound { .. }))
        .map(|(_, _, event)| event.clone())
        .collect()
}

fn indexed_by(trace: &[TraceEntry], label: &str) -> Vec<KadEvent> {
    trace
        .iter()
        .filter(|(_, at, event)| *at == label && matches!(event, KadEvent::SourceIndexed { .. }))
        .map(|(_, _, event)| event.clone())
        .collect()
}

/// The candidate rows C received, asserted to be A's source through the
/// sealed projection: the storer-substituted observed IP plus A's TCP port.
fn assert_sources_are_a(founds: &[KadEvent]) {
    for event in founds {
        let KadEvent::SourcesFound { target, candidates } = event else {
            unreachable!()
        };
        assert_eq!(*target, search_request().target());
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0]
                .peer_source()
                .map(|s| s.as_peer_endpoint().and_then(PeerEndpoint::as_v4)),
            Some(Some(Ipv4Endpoint::new(a_endpoint().ip(), 4662))),
            "the row is A's endpoint as the storer observed it"
        );
    }
}

/// The loop closes (ADR-0043): the whole DHT round trip runs inside
/// an rmule-only mesh — A publishes, the three real storers nearest the key
/// index it, and C's lookup+search returns A's source through the sealed
/// projection. Deterministic: two independent builds produce literally equal
/// traces.
#[test]
fn mesh_publish_store_search_closes_the_dht_loop() {
    let build = || {
        let mut sim = dht_mesh();
        sim.command(
            A,
            KadCommand::PublishSource {
                request: publish_request(65_536),
            },
        );
        let after_publish = sim.now() + Duration::from_secs(30);
        sim.run_until(after_publish, 50_000);
        sim.command(
            C,
            KadCommand::SearchSources {
                request: search_request(),
            },
        );
        let after_search = sim.now() + Duration::from_secs(30);
        sim.run_until(after_search, 50_000);
        sim
    };
    let sim = build();

    // The publisher saw every fanned storer ack and completed early.
    let publish_events: Vec<&KadEvent> = sim
        .trace()
        .iter()
        .filter(|(_, at, event)| *at == A && matches!(event, KadEvent::PublishComplete { .. }))
        .map(|(_, _, event)| event)
        .collect();
    assert_eq!(
        publish_events,
        vec![&KadEvent::PublishComplete {
            target: key(),
            acked_stores: 3,
            ended_by: KadPublishEnd::AllStoresAcked,
        }]
    );

    // Bidirectional acceptance: each nearest storer indexed A's publish and
    // later served C's search from it.
    for (label, _) in STORERS {
        assert_eq!(
            indexed_by(sim.trace(), label),
            vec![KadEvent::SourceIndexed {
                key: key(),
                rows_for_key: 1,
            }],
            "{label} indexed exactly A's publish"
        );
    }

    // C received A's source from all three storers, through the sealed
    // projection only.
    let founds = sources_found_for(sim.trace(), C);
    assert_eq!(founds.len(), 3, "one solicited answer per fanned storer");
    assert_sources_are_a(&founds);

    assert_eq!(sim.trace(), build().trace());
}

/// Republish cadence keeps the source discoverable past the storers' entry
/// expiry: long after the original entries lapsed, a search still hits
/// because the registered publish re-fired through `tick`.
#[test]
fn mesh_republish_keeps_the_source_discoverable_past_expiry() {
    let build = || {
        let mut sim = dht_mesh();
        let start = sim.now();
        sim.command(
            A,
            KadCommand::PublishSource {
                request: publish_request(65_536),
            },
        );
        sim.run_until(start + Duration::from_secs(30), 50_000);
        // Cross the original entries' expiry AND the republish instant.
        sim.run_until(
            start + KadNode::SOURCE_REPUBLISH_INTERVAL + Duration::from_secs(60),
            200_000,
        );
        sim.command(
            C,
            KadCommand::SearchSources {
                request: search_request(),
            },
        );
        let after_search = sim.now() + Duration::from_secs(30);
        sim.run_until(after_search, 50_000);
        sim
    };
    let sim = build();

    // The storers indexed twice: the original publish and the republish.
    for (label, _) in STORERS {
        assert_eq!(
            indexed_by(sim.trace(), label).len(),
            2,
            "{label} must have indexed the republish too"
        );
    }

    // C searched only after the first entries' lifetime — only a republished
    // entry can answer.
    let founds = sources_found_for(sim.trace(), C);
    assert_eq!(founds.len(), 3);
    assert_sources_are_a(&founds);

    assert_eq!(sim.trace(), build().trace());
}

/// The full expiry choreography against a publisher that does NOT republish
/// (a scripted `FakeKadPeer`): stored → search hits → lifetime passes →
/// search misses → the fake republishes → search hits again.
#[test]
fn mesh_expiry_misses_then_a_late_republish_hits_again() {
    let b_ep = contact_endpoint(10);
    let fake_publisher_ep = contact_endpoint(66);
    let first_publish_at = KadInstant::from_millis(1_000);
    let republish_at = first_publish_at + KadNode::STORED_SOURCE_LIFETIME + Duration::from_secs(30);

    let build = || {
        let mut sim = KadMeshSim::new()
            .with_node(
                HUB,
                mesh_config(KadId::from_bytes([0xF0; 16]), hub_endpoint(), 0xF0),
                hub_endpoint(),
            )
            .with_node(
                C,
                mesh_config(KadId::from_bytes([0xE0; 16]), c_endpoint(), 0xCC),
                c_endpoint(),
            )
            .with_node("b", mesh_config(id_near_key(10), b_ep, 0xBB), b_ep)
            .with_fake(
                fake_publisher_ep,
                FakeKadPeer::new()
                    .unsolicited_at(first_publish_at, b_ep, direct_publish(key(), 0xB0))
                    .unsolicited_at(republish_at, b_ep, direct_publish(key(), 0xB0)),
            );
        sim.command(
            "b",
            KadCommand::Bootstrap {
                endpoint: hub_endpoint(),
            },
        );
        sim.run_until(KadInstant::from_millis(500), 10_000);
        sim.command(
            C,
            KadCommand::Bootstrap {
                endpoint: hub_endpoint(),
            },
        );
        sim.run_until(KadInstant::from_millis(900), 10_000);

        // Stored, then found.
        sim.run_until(first_publish_at + Duration::from_secs(1), 10_000);
        sim.command(
            C,
            KadCommand::SearchSources {
                request: search_request(),
            },
        );
        sim.run_until(first_publish_at + Duration::from_secs(30), 10_000);

        // Past the lifetime, before the fake's republish: the search misses.
        sim.run_until(
            first_publish_at + KadNode::STORED_SOURCE_LIFETIME + Duration::from_secs(5),
            50_000,
        );
        sim.command(
            C,
            KadCommand::SearchSources {
                request: search_request(),
            },
        );
        sim.run_until(sim.now() + Duration::from_secs(30), 10_000);

        // After the republish: the search hits again.
        sim.run_until(republish_at + Duration::from_secs(1), 10_000);
        sim.command(
            C,
            KadCommand::SearchSources {
                request: search_request(),
            },
        );
        sim.run_until(sim.now() + Duration::from_secs(30), 10_000);
        sim
    };
    let sim = build();

    // B indexed the fake's publish twice (fresh entry each time, the first
    // having been pruned by its lifetime tick).
    assert_eq!(
        indexed_by(sim.trace(), "b"),
        vec![
            KadEvent::SourceIndexed {
                key: key(),
                rows_for_key: 1
            },
            KadEvent::SourceIndexed {
                key: key(),
                rows_for_key: 1
            },
        ]
    );

    // B's serve log tells the story from the storer's own trace: hit, miss,
    // hit — the miss window is [expiry, republish).
    let served_rows: Vec<usize> = sim
        .trace()
        .iter()
        .filter_map(|(_, at, event)| match event {
            KadEvent::SourceSearchServed { from, rows, .. }
                if *at == "b" && *from == c_endpoint() =>
            {
                Some(*rows)
            }
            _ => None,
        })
        .collect();
    assert_eq!(served_rows, vec![1, 0, 1]);

    // And C saw sources exactly for searches one and three.
    let founds = sources_found_for(sim.trace(), C);
    assert_eq!(founds.len(), 2);
    for event in &founds {
        let KadEvent::SourcesFound { candidates, .. } = event else {
            unreachable!()
        };
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0]
                .peer_source()
                .map(|s| s.as_peer_endpoint().and_then(PeerEndpoint::as_v4)),
            Some(Some(Ipv4Endpoint::new(fake_publisher_ep.ip(), 4662))),
            "the served row carries the fake publisher's observed endpoint"
        );
    }

    assert_eq!(sim.trace(), build().trace());
}

/// Storer bounds under a `FakeKadPeer` publish flood over the wire: 1001
/// distinct fake publishers hammer one key; the storer acks every accepted
/// publish but its index never exceeds the per-key cap.
#[test]
fn mesh_fake_peer_publish_flood_respects_the_per_key_cap() {
    let b_ep = contact_endpoint(10);
    let flood = u16::try_from(KadNode::MAX_SOURCES_PER_KEY).unwrap() + 1;

    let build = || {
        let mut sim =
            KadMeshSim::new().with_node("b", mesh_config(id_near_key(10), b_ep, 0xBB), b_ep);
        for i in 0..flood {
            let [hi, lo] = i.to_be_bytes();
            let fake_ep = KadNodeEndpoint::new(Ipv4Addr::new(198, 51, hi, lo), 6_000);
            sim = sim.with_fake(
                fake_ep,
                FakeKadPeer::new().unsolicited_at(
                    KadInstant::from_millis(u64::from(i)),
                    b_ep,
                    direct_publish(key(), 0xB0),
                ),
            );
        }
        sim.run_until(KadInstant::from_millis(u64::from(flood) + 1_000), 50_000);
        sim
    };
    let sim = build();

    let indexed = indexed_by(sim.trace(), "b");
    assert_eq!(
        indexed.len(),
        usize::from(flood),
        "every accepted publish was indexed (the over-cap one evicting the oldest)"
    );
    let max_rows = indexed
        .iter()
        .map(|event| {
            let KadEvent::SourceIndexed { rows_for_key, .. } = event else {
                unreachable!()
            };
            *rows_for_key
        })
        .max();
    assert_eq!(
        max_rows,
        Some(KadNode::MAX_SOURCES_PER_KEY),
        "the index never grows past the per-key cap"
    );

    assert_eq!(sim.trace(), build().trace());
}
