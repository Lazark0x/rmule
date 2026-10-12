//! The **small-timer hello pass**: aMule's zone small timer
//! (`CKademlia::Process` → `CRoutingZone::OnSmallTimer`, `RoutingZone.cpp:926-1010`,
//! kno `ab483654`), run every minute with no `IsConnected` gate
//! (`Kademlia.cpp:187,277-280`). Each pass looks at every non-empty bucket's
//! oldest contact once: a contact still inside its expiry goes to the back
//! unhelloed, a due one draws one `KADEMLIA2_HELLO_REQ` and a 2-min check
//! window (`CContact::CheckingType`, `Contact.cpp:87-99`), and an answer marks
//! it alive for 1 h / 1.5 h / 2 h by age (`CContact::UpdateType`,
//! `Contact.cpp:101-119`) and moves it to the back (`CRoutingBin::SetAlive`).
//!
//! This is what makes a **Seeded Bootstrap** reach the network: a merge
//! (`MergeContacts`, aMule's nodes.dat `AddUnfiltered`) sends nothing, and a
//! counterparty only learns of this node when its own `HELLO_REQ` arrives
//! (`Process2HelloRequest` → `AddContact2`, `KademliaUDPListener.cpp:577-649`),
//! so the pass must reach merged contacts whatever the node's join state.
//!
//! Also here: [`KadEvent::HadContact`], the silent→heard transition edge of
//! aMule's `HasHadContact` (the ADR-0067 joined predicate) that the core
//! diagnostics latch consumes.
//!
//! Node-level, explicit-time, no sockets (ADR-0045 deterministic tier), the
//! `join_dial.rs` harness shape.

use rmule_kad::KadNodeStart;
use std::time::Duration;

use crate::fixture::{OWN_ID, SECOND, TWENTY_MIN, ep};
use rmule_kad::{
    Kad2Message, Kad2NodeInfo, KadCommand, KadContact, KadContactState, KadEvent, KadId,
    KadInstant, KadNode, KadNodeConfig, KadNodeEndpoint,
};
use rmule_testkit::drain_split;
use rmule_testkit::kad_node::T0;

fn config() -> KadNodeConfig {
    KadNodeConfig {
        id: KadId::from_bytes(OWN_ID),
        tcp_port: 4662,
        udp_port: 4672,
        user_hash: rmule_kad::UserHash::from_bytes([0xEE; 16]),
    }
}

fn node() -> KadNode {
    KadNode::new(KadNodeStart::new(config(), T0))
}

/// A node running the small-timer hello pass from [`T0`].
fn timed_node() -> KadNode {
    KadNode::new(KadNodeStart::new(config(), T0).small_timer())
}

/// A nodes.dat-merged contact: enters `Responded` (the `MergeContacts`
/// admission state) with no datagram ever received.
fn merged(id_byte: u8, last_octet: u8) -> KadContact {
    KadContact::with_state(
        KadId::from_bytes([id_byte; 16]),
        ep(last_octet),
        4662,
        8,
        KadContactState::Responded,
    )
}

fn merge(node: &mut KadNode, contacts: Vec<KadContact>) {
    merge_at(node, T0, contacts);
}

fn merge_at(node: &mut KadNode, at: KadInstant, contacts: Vec<KadContact>) {
    node.handle_command(at, KadCommand::MergeContacts { contacts });
    let (datagrams, _) = drain_split(node);
    assert!(datagrams.is_empty(), "a merge itself stays silent");
}

/// The exact hello probe this node sends (`hello_info`: header + `0xFC`
/// UDP-port tag, no misc options).
fn hello_req_bytes() -> Vec<u8> {
    Kad2Message::HelloReq(Kad2NodeInfo {
        id: KadId::from_bytes(OWN_ID),
        tcp_port: 4662,
        version: KadNode::KAD_VERSION,
        udp_port_tag: Some(4672),
        misc_options: 0,
    })
    .encode()
    .encode()
}

fn hello_res_bytes(id_byte: u8) -> Vec<u8> {
    Kad2Message::HelloRes(Kad2NodeInfo {
        id: KadId::from_bytes([id_byte; 16]),
        tcp_port: 4662,
        version: 8,
        udp_port_tag: None,
        misc_options: 0,
    })
    .encode()
    .encode()
}

fn ping_bytes() -> Vec<u8> {
    Kad2Message::Ping.encode().encode()
}

fn hello_destinations(datagrams: &[(KadNodeEndpoint, Vec<u8>)]) -> Vec<KadNodeEndpoint> {
    let req = hello_req_bytes();
    datagrams
        .iter()
        .filter(|(_, bytes)| *bytes == req)
        .map(|(to, _)| *to)
        .collect()
}

/// The first pass fires `SMALL_TIMER_INITIAL` after arming and hellos each
/// non-empty bucket's front contact — ending the merge-path silent window.
/// `next_wake` reports the pass, which is the driver's whole scheduling
/// contract.
#[test]
fn the_first_pass_hellos_each_bucket_front_within_seconds() {
    let mut n = timed_node();
    // Three contacts in three distinct buckets (first-byte XOR distances
    // 0x80/0x40/0x20 → buckets 0/1/2).
    merge(
        &mut n,
        vec![merged(0x8F, 1), merged(0x4F, 2), merged(0x2F, 3)],
    );

    assert_eq!(
        n.next_wake(),
        Some(T0 + KadNode::SMALL_TIMER_INITIAL),
        "the armed pass must be the node's next deadline, or a driver never wakes for it"
    );

    n.tick(T0 + KadNode::SMALL_TIMER_INITIAL);
    let (datagrams, _) = drain_split(&mut n);
    let mut helloed = hello_destinations(&datagrams);
    helloed.sort_by_key(|endpoint| endpoint.ip());
    assert_eq!(helloed, vec![ep(1), ep(2), ep(3)]);
    assert_eq!(
        datagrams.len(),
        3,
        "hello probes are the pass's only traffic: {datagrams:?}"
    );
}

/// A lapsed contact is not evicted on its first unanswered hello — the pass
/// gives it a second hello with its own check window first (`CContact::CheckingType` stepping
/// 2→3→4, `RoutingZone.cpp:960-968`), and
/// only evicts once that second hello also lapses unanswered. Never a
/// [`ContactFailed`](KadEvent::ContactFailed): the aging ladder decides
/// eviction on its own, not the probe machinery's timeout.
#[test]
fn a_lapsed_contact_gets_a_second_hello_before_it_is_evicted() {
    let mut n = timed_node();
    merge(&mut n, vec![merged(0x8F, 1)]);
    let id = KadId::from_bytes([0x8F; 16]);
    let check_window = Duration::from_secs(2 * 60);

    let mut hellos = Vec::new();
    let mut evicted_at = None;
    let mut at = T0 + KadNode::SMALL_TIMER_INITIAL;
    while evicted_at.is_none() && at <= T0 + 3 * check_window + KadNode::SMALL_TIMER_INTERVAL {
        n.tick(at);
        let (datagrams, events) = drain_split(&mut n);
        if !hello_destinations(&datagrams).is_empty() {
            hellos.push(at);
        }
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, KadEvent::ContactFailed { .. })),
            "the aging ladder evicts directly, never through a probe failure: {events:?}"
        );
        if events
            .iter()
            .any(|e| matches!(e, KadEvent::ContactEvicted { id: evicted } if *evicted == id))
        {
            evicted_at = Some(at);
        }
        at = at + KadNode::SMALL_TIMER_INTERVAL;
    }

    assert_eq!(
        hellos.len(),
        2,
        "exactly two hellos before eviction: {hellos:?}"
    );
    let evicted_at = evicted_at.expect("the exhausted contact is eventually evicted");
    // Each step (the second hello, then the eviction) lands on the first pass
    // past its predecessor's check window, the same one-interval slack
    // `an_answered_contact_is_not_regreeted_until_its_alive_window_lapses`
    // uses for aMule's per-minute sampling of a windowed deadline.
    let first_pass_after = |later: KadInstant, earlier: KadInstant| {
        later > earlier + check_window
            && later <= earlier + check_window + KadNode::SMALL_TIMER_INTERVAL
    };
    assert!(
        first_pass_after(hellos[1], hellos[0]),
        "the second hello follows the first by one check window: {hellos:?}"
    );
    assert!(
        first_pass_after(evicted_at, hellos[1]),
        "eviction follows the second hello by its own check window: hellos {hellos:?}, evicted {evicted_at:?}"
    );
}

/// An answer between the two hellos resets the ladder (`mark_alive` clears the check count):
/// the contact is never evicted, and the
/// usual alive-window re-greet cadence resumes.
#[test]
fn an_answer_between_the_two_hellos_saves_the_contact() {
    let mut n = timed_node();
    merge(&mut n, vec![merged(0x8F, 1)]);

    // First hello, unanswered.
    n.tick(T0 + KadNode::SMALL_TIMER_INITIAL);
    assert_eq!(
        hello_destinations(&drain_split(&mut n).0),
        vec![ep(1)],
        "hello 1"
    );

    // The second hello, three minutes later (past the first hello's 2-min
    // check window): this time it answers.
    let second_hello_at = T0 + KadNode::SMALL_TIMER_INITIAL + 3 * KadNode::SMALL_TIMER_INTERVAL;
    n.tick(second_hello_at);
    assert_eq!(
        hello_destinations(&drain_split(&mut n).0),
        vec![ep(1)],
        "hello 2"
    );
    n.handle_datagram(second_hello_at + SECOND, ep(1), &hello_res_bytes(0x8F));
    let (_, events) = drain_split(&mut n);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, KadEvent::ContactResponded { .. })),
        "the answer validates the contact: {events:?}"
    );

    // No third hello, no eviction, for the rest of the (1-h) alive window.
    let hour = Duration::from_secs(60 * 60);
    let mut at = second_hello_at + KadNode::SMALL_TIMER_INTERVAL;
    while at <= second_hello_at + hour {
        n.tick(at);
        let (datagrams, events) = drain_split(&mut n);
        assert!(
            datagrams.is_empty(),
            "no re-greet inside the alive window: {at:?}"
        );
        assert!(
            events.is_empty(),
            "no eviction: the answer saved the contact: {events:?}"
        );
        at = at + KadNode::SMALL_TIMER_INTERVAL;
    }
}

/// Un-armed (the routing-only mesh-sim posture): no hello cadence, no wake —
/// a merged table alone must keep the node quiescible.
#[test]
fn an_unarmed_node_runs_no_small_timer_and_stays_quiescible() {
    let mut n = node();
    merge(&mut n, vec![merged(0x8F, 1)]);
    assert_eq!(
        n.next_wake(),
        None,
        "nothing scheduled: the sim tier quiesces"
    );
    for minutes in [1u64, 2, 10] {
        n.tick(T0 + Duration::from_secs(minutes * 60));
        assert!(
            drain_split(&mut n).0.is_empty(),
            "an un-armed node never hellos"
        );
    }
}

/// `HadContact` is an edge, not a level: once per silent→heard transition —
/// the first datagram after start, and again after a 20-min lapse — never per
/// datagram.
#[test]
fn had_contact_fires_on_the_silent_to_heard_edge_only() {
    let mut n = node();
    let had_contacts = |events: &[KadEvent]| {
        events
            .iter()
            .filter(|e| matches!(e, KadEvent::HadContact { .. }))
            .count()
    };

    n.handle_datagram(T0, ep(9), &ping_bytes());
    assert_eq!(
        had_contacts(&drain_split(&mut n).1),
        1,
        "first datagram: the edge"
    );

    n.handle_datagram(T0 + SECOND, ep(9), &ping_bytes());
    assert_eq!(
        had_contacts(&drain_split(&mut n).1),
        0,
        "still heard: no re-fire"
    );

    n.handle_datagram(T0 + TWENTY_MIN + 2 * SECOND, ep(9), &ping_bytes());
    assert_eq!(
        had_contacts(&drain_split(&mut n).1),
        1,
        "after the 20-min lapse the next datagram is a new edge"
    );
}

/// The pass ignores join state (closing a divergence from aMule):
/// aMule's `CKademlia::Process` runs `OnSmallTimer` every minute with no
/// `IsConnected` gate (`Kademlia.cpp:187,277-280`), so a contact merged into
/// an already-joined node draws a hello within aMule's 1–2 min — here at the
/// very next pass, since a never-checked contact is due at once.
#[test]
fn a_merged_contact_draws_a_hello_while_joined() {
    let mut n = timed_node();
    n.handle_datagram(T0, ep(9), &ping_bytes());
    drain_split(&mut n);
    n.tick(T0 + KadNode::SMALL_TIMER_INITIAL);
    drain_split(&mut n);

    let merged_at = T0 + 30 * SECOND;
    merge_at(&mut n, merged_at, vec![merged(0x8F, 1)]);
    let next_pass = T0 + KadNode::SMALL_TIMER_INITIAL + KadNode::SMALL_TIMER_INTERVAL;
    assert_eq!(n.next_wake(), Some(next_pass));
    assert!(
        n.joined(next_pass),
        "still inside the 20-min contact window"
    );
    n.tick(next_pass);
    assert_eq!(
        hello_destinations(&drain_split(&mut n).0),
        vec![ep(1)],
        "a joined node greets a merged contact on its next pass"
    );
}

/// One hello per bucket per pass — aMule's one `GetOldest` per zone. A due
/// contact stays at the front after its hello (only an answer moves it,
/// `CRoutingBin::SetAlive`), so each answer hands the next pass the bucket's
/// next contact.
#[test]
fn each_bucket_greets_at_most_one_due_contact_per_pass() {
    let mut n = timed_node();
    // Three in bucket 0 (first-byte distance ≥ 0x80), one in bucket 1.
    merge(
        &mut n,
        vec![
            merged(0x8F, 1),
            merged(0x9F, 2),
            merged(0xAF, 3),
            merged(0x4F, 4),
        ],
    );
    let pass = |k: u32| T0 + KadNode::SMALL_TIMER_INITIAL + KadNode::SMALL_TIMER_INTERVAL * k;
    let greet = |n: &mut KadNode, at: KadInstant| {
        n.tick(at);
        let mut helloed = hello_destinations(&drain_split(n).0);
        helloed.sort_by_key(|endpoint| endpoint.ip());
        for (endpoint, id_byte) in [(ep(1), 0x8F), (ep(2), 0x9F), (ep(3), 0xAF), (ep(4), 0x4F)] {
            if helloed.contains(&endpoint) {
                n.handle_datagram(at + SECOND, endpoint, &hello_res_bytes(id_byte));
            }
        }
        drain_split(n);
        helloed
    };

    assert_eq!(
        greet(&mut n, pass(0)),
        vec![ep(1), ep(4)],
        "pass 1: one per bucket"
    );
    assert_eq!(
        greet(&mut n, pass(1)),
        vec![ep(2)],
        "pass 2: bucket 0's next contact; bucket 1's only one answered and is not due"
    );
    assert_eq!(greet(&mut n, pass(2)), vec![ep(3)], "pass 3");
    assert!(greet(&mut n, pass(3)).is_empty(), "every contact answered");
}

/// An answer marks the contact alive and keeps it out of the pass for aMule's
/// age ladder (`CContact::UpdateType`, `Contact.cpp:101-119`): 1 h while the
/// contact is under an hour old, 1.5 h in its second hour. The pass greets it
/// again only once that window lapses — the periodic re-reach that keeps a
/// long-running node's table honest.
#[test]
fn an_answered_contact_is_not_regreeted_until_its_alive_window_lapses() {
    let mut n = timed_node();
    merge(&mut n, vec![merged(0x8F, 1)]);
    let hour = Duration::from_secs(60 * 60);

    let mut greetings = Vec::new();
    let mut at = T0 + KadNode::SMALL_TIMER_INITIAL;
    while at <= T0 + 3 * hour {
        n.tick(at);
        if !hello_destinations(&drain_split(&mut n).0).is_empty() {
            greetings.push(at);
            n.handle_datagram(at + SECOND, ep(1), &hello_res_bytes(0x8F));
            let (_, events) = drain_split(&mut n);
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, KadEvent::ContactResponded { .. })),
                "the hello answer validates the contact: {events:?}"
            );
        }
        at = at + KadNode::SMALL_TIMER_INTERVAL;
    }

    assert_eq!(greetings.len(), 3, "greeted at {greetings:?}");
    // Each re-greeting lands on the first pass past the alive window.
    let first_pass_after = |greeted: KadInstant, answered: KadInstant, window: Duration| {
        greeted > answered + window && greeted <= answered + window + KadNode::SMALL_TIMER_INTERVAL
    };
    assert!(
        first_pass_after(greetings[1], greetings[0] + SECOND, hour),
        "an answer under an hour old holds the contact out for 1 h: {greetings:?}"
    );
    assert!(
        first_pass_after(greetings[2], greetings[1] + SECOND, hour + hour / 2),
        "an answer in the contact's second hour holds it out for 1.5 h: {greetings:?}"
    );
}
