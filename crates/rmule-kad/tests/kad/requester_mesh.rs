//! Kad Requester role, mesh tier (ADR-0043): the walk and the
//! source search it converges into, driven across a `KadMeshSim` of real
//! nodes and `FakeKadPeer`s (steering chains, scripted `0x3B` built from the
//! committed documentation-provenance fixture bytes, silent and adversarial
//! nodes). The node-level legs and the helpers shared here live in
//! [`super::requester`].

use std::net::Ipv4Addr;

use rmule_kad::{
    KadCommand, KadEvent, KadId, KadInstant, KadNode, KadNodeConfig, KadNodeDiagnostic,
    KadNodeEndpoint, KadSearchEnd,
};
use rmule_primitives::{ClientId, PeerSource};
use rmule_testkit::kad_mesh::A;
use rmule_testkit::kad_node::{hello_req_from, lookup_res_bytes};
use rmule_testkit::{FakeKadPeer, KadMeshSim};

use super::requester::{
    OWN_ID_BYTE, contact_near, endpoint_for, fixture_request, fixture_search_res_datagram,
    fixture_target, id_near, request, target,
};

const A_EP: KadNodeEndpoint = KadNodeEndpoint::new(Ipv4Addr::new(203, 0, 113, 254), 4999);

fn node_config(id: KadId, endpoint: KadNodeEndpoint) -> KadNodeConfig {
    KadNodeConfig {
        id,
        tcp_port: 4662,
        udp_port: endpoint.udp_port(),
        user_hash: rmule_kad::UserHash::from_bytes([0xEE; 16]),
    }
}

fn requester_config() -> KadNodeConfig {
    node_config(KadId::from_bytes([OWN_ID_BYTE; KadId::BYTE_LEN]), A_EP)
}

fn search_complete_events(trace: &[rmule_testkit::TraceEntry]) -> Vec<KadEvent> {
    trace
        .iter()
        .filter(|(_, label, event)| {
            *label == A && matches!(event, KadEvent::SourceSearchComplete { .. })
        })
        .map(|(_, _, event)| event.clone())
        .collect()
}

/// The real-node topology acceptance: a hub knows four responders near the
/// target; the requester bootstraps off the hub, walks, and only the nodes
/// nearest the target receive the `0x34` — proven from the *recipients'* own
/// traces (their storer role serves the search), not from the requester's
/// bookkeeping.
#[test]
fn mesh_walk_reaches_the_nearest_real_nodes_and_only_they_are_searched() {
    let build = || {
        let hub_ep = endpoint_for(200);
        let mut sim = KadMeshSim::new()
            .with_node(A, requester_config(), A_EP)
            .with_node("r-hub", node_config(id_near(target(), 200), hub_ep), hub_ep);
        for (label, d) in [("r10", 10u8), ("r20", 20), ("r30", 30), ("r40", 40)] {
            sim = sim.with_node(
                label,
                node_config(id_near(target(), d), endpoint_for(d)),
                endpoint_for(d),
            );
        }
        // The responders join the hub first; then the requester bootstraps
        // off the hub and learns all of them as hearsay rows it validates.
        for label in ["r10", "r20", "r30", "r40"] {
            sim.command(label, KadCommand::Bootstrap { endpoint: hub_ep });
        }
        sim.run_until_idle(10_000);
        sim.command(A, KadCommand::Bootstrap { endpoint: hub_ep });
        sim.run_until_idle(10_000);

        sim.command(A, KadCommand::SearchSources { request: request() });
        sim.run_until_idle(10_000);
        sim
    };
    let sim = build();

    // Bidirectional acceptance: the three nearest responders each SERVED the
    // 0x34 they received from the requester (empty index, zero rows — each
    // runs the storer role).
    let searched_by = |label: &'static str| {
        sim.trace()
            .iter()
            .filter(|(_, at, event)| {
                *at == label
                    && matches!(
                        event,
                        KadEvent::SourceSearchServed { from, rows: 0, .. } if *from == A_EP
                    )
            })
            .count()
    };
    assert_eq!(searched_by("r10"), 1);
    assert_eq!(searched_by("r20"), 1);
    assert_eq!(searched_by("r30"), 1);
    assert_eq!(
        searched_by("r40"),
        0,
        "the fourth-closest is never searched"
    );
    assert_eq!(searched_by("r-hub"), 0, "the far hub is never searched");

    assert_eq!(
        search_complete_events(sim.trace()),
        vec![KadEvent::SourceSearchComplete {
            target: target(),
            result_rows: 0,
            ended_by: KadSearchEnd::WindowElapsed,
        }],
        "real nodes have no storer role yet, so the window closes empty"
    );

    // And the whole choreography is deterministic.
    assert_eq!(sim.trace(), build().trace());
}

/// Fake storers answer the `0x34` with the committed documentation-provenance
/// fixture bytes; the closest fake stays silent through the walk; a bystander
/// fires an unsolicited `0x3B` mid-window. Sources arrive only from the
/// solicited endpoints, and the search still completes on time.
#[test]
fn mesh_fake_storers_deliver_fixture_sources_and_noise_stays_diagnostic() {
    let fixture_target = fixture_target();
    let noise_ep = endpoint_for(99);
    let build = || {
        let mut sim = KadMeshSim::new().with_node(A, requester_config(), A_EP);
        // The closest fake (d5) never answers lookups: its query must time
        // out without blocking convergence on the three storers.
        let silent = FakeKadPeer::new().unsolicited_at(
            KadInstant::EPOCH,
            A_EP,
            hello_req_from(id_near(fixture_target, 5), endpoint_for(5)),
        );
        sim = sim.with_fake(endpoint_for(5), silent);
        for d in [10u8, 20, 30] {
            let fake = FakeKadPeer::new()
                .unsolicited_at(
                    KadInstant::EPOCH,
                    A_EP,
                    hello_req_from(id_near(fixture_target, d), endpoint_for(d)),
                )
                .once_on_opcode(0x21, vec![lookup_res_bytes(fixture_target, &[])])
                .once_on_opcode(0x34, vec![fixture_search_res_datagram()]);
            sim = sim.with_fake(endpoint_for(d), fake);
        }
        // A bystander that was never queried nor searched shoots a fixture
        // 0x3B into the window.
        sim = sim.with_fake(
            noise_ep,
            FakeKadPeer::new().unsolicited_at(
                KadInstant::from_millis(5_000),
                A_EP,
                fixture_search_res_datagram(),
            ),
        );
        sim.run_until_idle(10_000);

        sim.command(
            A,
            KadCommand::SearchSources {
                request: fixture_request(),
            },
        );
        sim.run_until_idle(10_000);
        sim
    };
    let sim = build();

    let sources: Vec<&KadEvent> = sim
        .trace()
        .iter()
        .filter(|(_, _, event)| matches!(event, KadEvent::SourcesFound { .. }))
        .map(|(_, _, event)| event)
        .collect();
    assert_eq!(sources.len(), 3, "one solicited batch per fake storer");
    for event in sources {
        let KadEvent::SourcesFound {
            target, candidates, ..
        } = event
        else {
            unreachable!()
        };
        assert_eq!(*target, fixture_request().target());
        assert_eq!(candidates.len(), 5);
        assert_eq!(
            candidates[0].peer_source(),
            Some(PeerSource::new(ClientId::from_u32(0x0A64_33C6), 4662)),
            "the direct High ID row projects through the sealed boundary"
        );
    }

    assert!(
        sim.trace().iter().any(|(_, label, event)| {
            *label == A
                && *event
                    == KadEvent::Diagnostic(KadNodeDiagnostic::UnsolicitedSearchRes {
                        from: noise_ep,
                    })
        }),
        "the bystander 0x3B is diagnosed, never projected: {:?}",
        sim.trace()
    );
    assert_eq!(
        search_complete_events(sim.trace()),
        vec![KadEvent::SourceSearchComplete {
            target: fixture_target,
            result_rows: 15,
            ended_by: KadSearchEnd::WindowElapsed,
        }]
    );

    // The silent fake was queried but never searched; a storer got both.
    let opcodes = |ep: KadNodeEndpoint| -> Vec<u8> {
        sim.fake(ep)
            .received()
            .iter()
            .map(|(_, _, bytes)| bytes[1])
            .collect()
    };
    assert_eq!(opcodes(endpoint_for(5)), vec![0x19, 0x21]);
    assert_eq!(opcodes(endpoint_for(10)), vec![0x19, 0x21, 0x34]);

    assert_eq!(sim.trace(), build().trace());
}

/// A mesh of steering fakes, each pointing the walk at two strictly closer
/// fakes: without the query budget this chain never ends. The sim going idle
/// IS the termination proof; the budget pins how far the chase got.
#[test]
fn mesh_steering_chain_terminates_at_the_query_budget() {
    let build = || {
        let mut sim = KadMeshSim::new().with_node(A, requester_config(), A_EP);
        for d in 200u8..=252 {
            let mut fake = FakeKadPeer::new().once_on_opcode(
                0x21,
                vec![lookup_res_bytes(
                    target(),
                    &[contact_near(target(), d - 1), contact_near(target(), d - 2)],
                )],
            );
            // Only the three farthest fakes are seeds the requester knows;
            // everything closer must be reached through the steering chain.
            if d >= 250 {
                fake = fake.unsolicited_at(
                    KadInstant::EPOCH,
                    A_EP,
                    hello_req_from(id_near(target(), d), endpoint_for(d)),
                );
            }
            sim = sim.with_fake(endpoint_for(d), fake);
        }
        sim.run_until_idle(10_000);

        sim.command(A, KadCommand::SearchSources { request: request() });
        sim.run_until_idle(20_000);
        sim
    };
    let sim = build();

    let lookups_received: usize = (200u8..=252)
        .map(|d| {
            sim.fake(endpoint_for(d))
                .received()
                .iter()
                .filter(|(_, _, bytes)| bytes[1] == 0x21)
                .count()
        })
        .sum();
    assert_eq!(
        lookups_received,
        KadNode::LOOKUP_QUERY_BUDGET,
        "the chase stops exactly at the query budget"
    );

    let searches_received: usize = (200u8..=252)
        .map(|d| {
            sim.fake(endpoint_for(d))
                .received()
                .iter()
                .filter(|(_, _, bytes)| bytes[1] == 0x34)
                .count()
        })
        .sum();
    assert_eq!(
        searches_received,
        KadNode::SEARCH_FANOUT,
        "the walk still converges into a search"
    );

    assert_eq!(
        search_complete_events(sim.trace()),
        vec![KadEvent::SourceSearchComplete {
            target: target(),
            result_rows: 0,
            ended_by: KadSearchEnd::WindowElapsed,
        }]
    );

    assert_eq!(sim.trace(), build().trace());
}
