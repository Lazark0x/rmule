//! The **ed2k→Kad handoff** (ADR-0067): a connected eD2k peer carries a
//! Kad node hint, and while Kad is running but not yet joined rmule uses it to
//! bootstrap — aMule's `CKademlia::Bootstrap(ip, kadPort)`. Its gate is
//! **running ∧ not joined ∧ ≥ 10 s since the last bootstrap dial**, and that
//! 10 s throttle is the *same* `m_bootstrap` timestamp the dial loop
//! stamps, so the handoff and the list dials rate-couple.
//!
//! Node-level, explicit-time, no sockets (ADR-0045 deterministic tier). The
//! "running" leg of the gate is the *core* precondition — core brokers the hint
//! only to a live node (core wiring, tested there); at this level the
//! node applies the not-joined and shared-throttle legs. The seeding and dial
//! cadence themselves belong to the dial loop and are re-used, not re-tested
//! here.
//!
//! Capture tier (ADR-0067 "Handoff end-to-end") is **not** run here: ed2k-connect
//! a pinned aMule client, let its hello tags pin the `CT_EMULE_UDPPORTS`/kad-
//! version bytes, and observe rmule's resulting `BOOTSTRAP_REQ` draw aMule's
//! `BOOTSTRAP_RES`. Private-mesh, real-client bytes, never CI.

use crate::fixture::{SECOND, bootstrap_req_bytes, dial_destinations, ep, join_node};
use rmule_kad::{KadBootstrapNode, KadCommand, KadInstant, KadNode, KadNodeEndpoint};
use rmule_testkit::kad_mesh::{A, A_EP, B, B_EP, config};
use rmule_testkit::kad_node::id;
use rmule_testkit::{KadMeshSim, drain_split};

/// Issue a handoff, tick so the seeded dial fires, and return who was dialed.
fn handoff_dials(
    node: &mut KadNode,
    now: KadInstant,
    endpoint: KadNodeEndpoint,
) -> Vec<KadNodeEndpoint> {
    node.handle_command(now, KadCommand::BootstrapFromPeer { endpoint });
    node.tick(now);
    dial_destinations(&drain_split(node).0)
}

// --- the gate: running ∧ not joined ∧ shared 10 s throttle -----------------

/// A running (live), not-yet-joined node that has never dialed accepts the
/// handoff: the peer's Kad endpoint is seeded into the one Bootstrap Dial List
/// and dialed — "Kad joins with zero seeds the moment one eD2k peer connects."
#[test]
fn handoff_seeds_and_dials_the_peers_kad_endpoint() {
    let mut node = join_node();
    let t0 = KadInstant::EPOCH;
    assert!(!node.joined(t0), "a fresh node is not joined");

    assert_eq!(
        handoff_dials(&mut node, t0, ep(7)),
        vec![ep(7)],
        "the brokered peer Kad endpoint is dialed"
    );
}

/// aMule's `!IsConnected()` leg: once the node has joined (received any Kad
/// datagram within the 20 min window) the handoff is dropped — a joined node
/// needs no bootstrap. The hint is discarded, not queued (aMule early-returns).
#[test]
fn handoff_suppressed_once_joined() {
    let mut node = join_node();
    let t0 = KadInstant::EPOCH;
    // Any received datagram makes the node joined (contact at the entry gate).
    node.handle_datagram(t0, ep(9), &bootstrap_req_bytes());
    drain_split(&mut node);
    assert!(node.joined(t0), "a received datagram is contact");

    assert!(
        handoff_dials(&mut node, t0, ep(7)).is_empty(),
        "a joined node ignores the handoff"
    );
}

/// The 10 s throttle: a bootstrap dial stamps the shared `m_bootstrap`, so a
/// second handoff under 10 s later is suppressed, and one at exactly 10 s
/// (ADR-0067's "≥ 10 s") fires again.
#[test]
fn handoff_throttled_for_ten_seconds_after_a_dial() {
    let mut node = join_node();
    let t0 = KadInstant::EPOCH;
    // The first handoff dials (no prior dial) — and stamps the throttle.
    assert_eq!(handoff_dials(&mut node, t0, ep(1)), vec![ep(1)]);

    // 9 s later: still under the throttle, suppressed.
    assert!(
        handoff_dials(&mut node, t0 + 9 * SECOND, ep(2)).is_empty(),
        "throttled — under 10 s since the last dial"
    );
    // Exactly 10 s: the throttle opens, the handoff fires.
    assert_eq!(
        handoff_dials(&mut node, t0 + 10 * SECOND, ep(3)),
        vec![ep(3)],
        "the throttle opens at 10 s"
    );
}

/// The throttle is *shared* with the dial loop: a list dial (a config /
/// v3-file seed) stamps the very same `m_bootstrap`, so a peer handoff within
/// 10 s of a *list* dial is suppressed — the rate-coupling ADR-0067 names.
#[test]
fn the_shared_throttle_couples_the_handoff_with_the_dial_loop() {
    let mut node = join_node();
    let t0 = KadInstant::EPOCH;
    // A config-seed list dial at t0 stamps the shared throttle.
    node.handle_command(
        t0,
        KadCommand::SeedBootstrapDialList {
            candidates: vec![KadBootstrapNode::new(ep(1), None)],
        },
    );
    node.tick(t0);
    assert_eq!(
        dial_destinations(&drain_split(&mut node).0),
        vec![ep(1)],
        "the config seed dialed"
    );

    // A peer handoff 5 s after that *list* dial is throttled by its stamp.
    assert!(
        handoff_dials(&mut node, t0 + 5 * SECOND, ep(7)).is_empty(),
        "the list dial's stamp throttles the handoff — one shared throttle"
    );
    // 10 s after the list dial the shared throttle opens for the handoff.
    assert_eq!(
        handoff_dials(&mut node, t0 + 10 * SECOND, ep(7)),
        vec![ep(7)],
        "the throttle is shared: it opens 10 s after the list dial"
    );
}

// --- the mesh: cold join via the peer-handoff route ------------------------

fn two_node_mesh() -> KadMeshSim {
    KadMeshSim::new()
        .with_node(A, config(id(0xA1), A_EP, 0xA1), A_EP)
        .with_node(B, config(id(0xB1), B_EP, 0xB1), B_EP)
}

/// The third cold-join route (config seed and v3-file list belong to the dial
/// loop, already covered by `join_dial` / `mesh_sim`): a node with an empty
/// table **and** an
/// empty dial list learns its first Kad contact purely from an eD2k peer
/// handoff. Core brokers B's Kad endpoint, A dials it, B answers, A joins.
#[test]
fn cold_join_via_the_peer_handoff_route() {
    let mut sim = two_node_mesh();
    sim.command(A, KadCommand::BootstrapFromPeer { endpoint: B_EP });
    sim.run_until_idle(1_000);

    assert!(
        sim.node(A).joined(sim.now()),
        "A joined the Kad network via the eD2k peer handoff alone"
    );
    let b_in_a = sim
        .node(A)
        .routing_table()
        .get(id(0xB1))
        .expect("A stored B from the handoff bootstrap response");
    assert_eq!(b_in_a.endpoint(), B_EP);
}

/// The handoff feeds the *same* dial machinery as a config seed: a cold join via
/// `BootstrapFromPeer` reaches the identical joined routing state as one via
/// `SeedBootstrapDialList` — the third route unifies into the one Bootstrap Dial
/// List, it is not a parallel bootstrap path.
#[test]
fn the_handoff_route_matches_the_config_seed_route() {
    let cold_join = |seed: KadCommand| {
        let mut sim = two_node_mesh();
        sim.command(A, seed);
        sim.run_until_idle(1_000);
        (
            sim.node(A).joined(sim.now()),
            sim.node(A).routing_table().len(),
        )
    };

    let via_handoff = cold_join(KadCommand::BootstrapFromPeer { endpoint: B_EP });
    let via_seed = cold_join(KadCommand::SeedBootstrapDialList {
        candidates: vec![KadBootstrapNode::new(B_EP, None)],
    });

    assert_eq!(
        via_handoff,
        (true, 1),
        "the handoff cold-joins A with one contact"
    );
    assert_eq!(
        via_handoff, via_seed,
        "the handoff route lands the same joined state as the config-seed route"
    );
}
