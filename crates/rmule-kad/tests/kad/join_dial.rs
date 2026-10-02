//! The Kad **join** cadence (ADR-0067): the unified Bootstrap Dial
//! List consumed one-at-a-time on aMule's 15 s / 2 s cadence, the forced
//! self-lookup schedule (3 min then every 4 h), and the `joined = HasHadContact`
//! predicate the dial loop and the handoff gate on.
//!
//! Node-level, explicit-time, no sockets: every instant is injected, so the
//! cadence and schedule are asserted deterministically (ADR-0045 deterministic
//! tier). Dial cadence is own-emit timing — the deterministic tier owns it.
//!
//! The capture tier (ADR-0067, "Capture tier") is **not** run here: it is the
//! cold-join recipe — seed rmule with only a pinned aMule endpoint on a private
//! mesh, then capture aMule's `BOOTSTRAP_RES` and its answers to rmule's forced
//! self-lookup `FindNode` walk. Private-mesh, real-client bytes, never CI (the
//! `crates/rmule-kad/CONTEXT.md` Private Mesh Evidence doctrine).

use std::time::Duration;

use crate::fixture::{
    OWN_ID, SECOND, TWENTY_MIN, bootstrap_req_bytes, bootstrap_res_bytes, dial_destinations, ep,
    join_node,
};
use rmule_kad::{
    Kad2Message, KadBootstrapNode, KadCommand, KadContact, KadContactState, KadEvent, KadId,
    KadInstant, KadNode,
};
use rmule_testkit::drain_split;

fn candidate(last_octet: u8) -> KadBootstrapNode {
    KadBootstrapNode::new(ep(last_octet), None)
}

/// A live, servable routing-table contact (nodes.dat normal-reader shape):
/// entered `Responded` by `MergeContacts`, but with no datagram ever received
/// — so the table is non-empty while the node is still *not joined*.
fn merged_contact(id_byte: u8, last_octet: u8) -> KadContact {
    KadContact::with_state(
        KadId::from_bytes([id_byte; 16]),
        ep(last_octet),
        4662,
        8,
        KadContactState::Responded,
    )
}

const THREE_MIN: Duration = Duration::from_secs(3 * 60);
const FOUR_HOURS: Duration = Duration::from_secs(4 * 60 * 60);

// --- joined = HasHadContact within 20 min --------------------------------

/// aMule's `IsConnected` = `HasHadContact`: any received Kad datagram makes the
/// node joined, and it stays joined until 20 min (`KADEMLIADISCONNECTDELAY`)
/// pass with no further contact. The predicate is stamped at the ADR-0064 entry
/// gate, so *any* well-formed datagram counts — here an inbound bootstrap
/// request.
#[test]
fn joined_is_had_contact_within_the_twenty_minute_window() {
    let mut node = join_node();
    let t0 = KadInstant::EPOCH;
    assert!(!node.joined(t0), "a fresh node has had no contact");

    let contact_at = t0 + Duration::from_secs(30);
    node.handle_datagram(contact_at, ep(9), &bootstrap_req_bytes());
    drain_split(&mut node);
    assert!(node.joined(contact_at), "a received datagram is contact");

    // Still connected one millisecond inside the window, disconnected exactly
    // on it — aMule's strict `now - last < DELAY`.
    assert!(node.joined(contact_at + (TWENTY_MIN - Duration::from_millis(1))));
    assert!(!node.joined(contact_at + TWENTY_MIN));

    // A second datagram slides the window forward from the new contact instant.
    let refresh_at = contact_at + Duration::from_secs(10 * 60);
    node.handle_datagram(refresh_at, ep(9), &bootstrap_req_bytes());
    drain_split(&mut node);
    assert!(
        node.joined(contact_at + TWENTY_MIN),
        "refreshed by new contact"
    );
    assert!(!node.joined(refresh_at + TWENTY_MIN));
}

/// An undecodable datagram is dropped before the entry gate stamps contact, so
/// it never makes the node joined — the predicate tracks genuine Kad traffic,
/// not arbitrary bytes at the socket.
#[test]
fn garbage_datagrams_do_not_count_as_contact() {
    let mut node = join_node();
    let t0 = KadInstant::EPOCH;
    node.handle_datagram(t0, ep(9), &[0x00, 0x01, 0x02]);
    drain_split(&mut node);
    assert!(!node.joined(t0), "undecodable bytes are not Kad contact");
}

// --- the dial loop: unified list, one-at-a-time, 15 s / 2 s cadence -------

/// While the routing table is empty the dial loop pops the front candidate,
/// dials one `KADEMLIA2_BOOTSTRAP_REQ`, discards it, and paces the next dial 2 s
/// later — the fast empty-table cadence. Config seeds and file candidates are
/// unified into one list; here three seeds drain in order, one per cadence tick.
#[test]
fn dial_loop_pops_one_at_a_time_on_the_two_second_empty_table_cadence() {
    let mut node = join_node();
    let t0 = KadInstant::EPOCH;
    node.handle_command(
        t0,
        KadCommand::SeedBootstrapDialList {
            candidates: vec![candidate(1), candidate(2), candidate(3)],
        },
    );

    // The first dial fires as soon as the list is seeded.
    node.tick(t0);
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(
        dial_destinations(&datagrams),
        vec![ep(1)],
        "front dialed first"
    );

    // Nothing until the 2 s cadence elapses.
    node.tick(t0 + SECOND);
    assert!(
        drain_split(&mut node).0.is_empty(),
        "too early for the next dial"
    );

    node.tick(t0 + 2 * SECOND);
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(dial_destinations(&datagrams), vec![ep(2)]);

    node.tick(t0 + 4 * SECOND);
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(dial_destinations(&datagrams), vec![ep(3)]);

    // The list is drained: one at a time means no more dials, ever.
    node.tick(t0 + 6 * SECOND);
    assert!(
        drain_split(&mut node).0.is_empty(),
        "the dial list is exhausted"
    );
    // The dial loop cleared its timer: the only remaining wake is the first
    // dial's 180 s solicitation expiry (ADR-0064), not another 2 s dial.
    assert_eq!(
        node.next_wake(),
        Some(t0 + KadNode::BOOTSTRAP_SOLICITATION_WINDOW),
        "no further dial is scheduled once the list drains"
    );
}

/// A dial list fed from two sources — config-endpoint seeds and file-loaded
/// candidates — is one list, dialed front-to-back across the sources in the
/// order they were fed: two feeds, one list, one cadence.
#[test]
fn config_seeds_and_file_candidates_unify_into_one_dial_list() {
    let mut node = join_node();
    let t0 = KadInstant::EPOCH;
    // First the config seeds.
    node.handle_command(
        t0,
        KadCommand::SeedBootstrapDialList {
            candidates: vec![candidate(1)],
        },
    );
    // Then the file-loaded candidates append to the *same* list.
    node.handle_command(
        t0,
        KadCommand::SeedBootstrapDialList {
            candidates: vec![candidate(2), candidate(3)],
        },
    );

    let mut dialed = Vec::new();
    for step in 0..3u64 {
        node.tick(t0 + Duration::from_secs(2 * step));
        let (datagrams, _) = drain_split(&mut node);
        dialed.extend(dial_destinations(&datagrams));
    }
    assert_eq!(
        dialed,
        vec![ep(1), ep(2), ep(3)],
        "one unified front-to-back list"
    );
}

/// Once the routing table is non-empty the cadence relaxes from 2 s to 15 s
/// (aMule dials slower once it has contacts to work with). A `MergeContacts`
/// load fills the table without any datagram arriving, so the node is still not
/// joined and keeps dialing — but now on the slow cadence.
#[test]
fn dial_cadence_relaxes_to_fifteen_seconds_once_the_table_is_non_empty() {
    let mut node = join_node();
    let t0 = KadInstant::EPOCH;
    node.handle_command(
        t0,
        KadCommand::MergeContacts {
            contacts: vec![merged_contact(0x33, 8)],
        },
    );
    drain_split(&mut node);
    assert!(
        !node.joined(t0),
        "a merged contact is not a received datagram"
    );

    node.handle_command(
        t0,
        KadCommand::SeedBootstrapDialList {
            candidates: vec![candidate(1), candidate(2)],
        },
    );
    node.tick(t0);
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(dial_destinations(&datagrams), vec![ep(1)]);

    // The 2 s empty-table cadence is gone: nothing at 2 s.
    node.tick(t0 + 2 * SECOND);
    assert!(
        drain_split(&mut node).0.is_empty(),
        "a non-empty table dials on the 15 s cadence, not 2 s"
    );

    node.tick(t0 + 15 * SECOND);
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(dial_destinations(&datagrams), vec![ep(2)]);
}

/// The dial loop is gated on `not joined`: the first bootstrap response makes
/// the node joined (contact stamped at the entry gate), which stops the loop —
/// the remaining candidates are never dialed. This is aMule's stop-on-joined.
#[test]
fn a_bootstrap_response_marks_joined_and_stops_the_dial_loop() {
    let mut node = join_node();
    let t0 = KadInstant::EPOCH;
    node.handle_command(
        t0,
        KadCommand::SeedBootstrapDialList {
            candidates: vec![candidate(1), candidate(2), candidate(3)],
        },
    );
    node.tick(t0);
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(dial_destinations(&datagrams), vec![ep(1)], "ep(1) dialed");

    // ep(1) answers: the response is solicited (ep(1) is an outstanding dial),
    // so the node stores it and — having received a Kad datagram — is joined.
    let answered_at = t0 + Duration::from_millis(200);
    node.handle_datagram(answered_at, ep(1), &bootstrap_res_bytes([0x21; 16]));
    drain_split(&mut node);
    assert!(node.joined(answered_at), "the response is contact");

    // The cadence instants pass, but joined means no further dials.
    let mut later_dials = Vec::new();
    for secs in [2u64, 4, 15, 30] {
        node.tick(t0 + Duration::from_secs(secs));
        let (datagrams, _) = drain_split(&mut node);
        later_dials.extend(dial_destinations(&datagrams));
    }
    assert!(
        !later_dials.contains(&ep(2)) && !later_dials.contains(&ep(3)),
        "stop-on-joined: the undialed candidates stay undialed, got {later_dials:?}"
    );
}

// --- the forced self-lookup: 3 min, then every 4 h ------------------------

fn self_lookups(events: &[KadEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, KadEvent::SelfLookupStarted))
        .count()
}

/// The forced self-lookup fires 3 min after the join begins, then repeats every
/// 4 h (aMule's `m_nextSelfLookup = now + MIN2S(3)`, then `+ HR2S(4)`). The walk
/// rides the ordinary lookup machinery toward the node's own Kad ID, warming its
/// own-ID neighborhood — the join proper.
#[test]
fn self_lookup_fires_at_three_minutes_then_every_four_hours() {
    let mut node = join_node();
    let t0 = KadInstant::EPOCH;
    node.arm_self_lookup(t0);
    // A servable seed so the self-lookup has a contact to query.
    node.handle_command(
        t0,
        KadCommand::MergeContacts {
            contacts: vec![merged_contact(0x55, 5)],
        },
    );
    drain_split(&mut node);

    // Not yet, one second short of 3 min.
    node.tick(t0 + (THREE_MIN - SECOND));
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(self_lookups(&events), 0, "no self-lookup before 3 min");
    assert!(datagrams.is_empty());

    // At 3 min: the self-lookup starts and queries the seed toward the own ID.
    node.tick(t0 + THREE_MIN);
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(
        self_lookups(&events),
        1,
        "the forced self-lookup fires at 3 min"
    );
    let expected_find_node = Kad2Message::LookupReq {
        count: KadNode::LOOKUP_CONTACT_COUNT,
        target: KadId::from_bytes(OWN_ID),
        check: KadId::from_bytes([0x55; 16]),
    }
    .encode()
    .encode();
    assert_eq!(
        datagrams,
        vec![(ep(5), expected_find_node)],
        "a FindNode toward the own ID, warming the own-ID neighborhood"
    );

    // The refresh is 4 h after the first, not 4 h after start.
    let refresh_at = t0 + THREE_MIN + FOUR_HOURS;
    node.tick(t0 + (THREE_MIN + FOUR_HOURS - SECOND));
    assert_eq!(
        self_lookups(&drain_split(&mut node).1),
        0,
        "not before the 4 h refresh"
    );

    node.tick(refresh_at);
    assert_eq!(
        self_lookups(&drain_split(&mut node).1),
        1,
        "the self-lookup refreshes every 4 h"
    );
}

/// The self-lookup schedule is independent of the routing table: with an empty
/// table there is nothing to query, so no FindNode goes out — but the schedule
/// still fires (the `SelfLookupStarted` signal), exactly as aMule runs the timer
/// regardless of whether the table can seed a walk yet.
#[test]
fn self_lookup_schedule_fires_even_with_an_empty_table() {
    let mut node = join_node();
    let t0 = KadInstant::EPOCH;
    node.arm_self_lookup(t0);

    node.tick(t0 + THREE_MIN);
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(
        self_lookups(&events),
        1,
        "the schedule fires regardless of the table"
    );
    assert!(
        datagrams.is_empty(),
        "an empty table has nothing to query — no FindNode goes out"
    );
}

/// A node that never arms the self-lookup (the routing-only mesh-sim posture)
/// runs no join cadence at all: no schedule, and it can still quiesce.
#[test]
fn an_unarmed_node_runs_no_self_lookup() {
    let mut node = join_node();
    let t0 = KadInstant::EPOCH;
    node.tick(t0 + THREE_MIN);
    assert_eq!(self_lookups(&drain_split(&mut node).1), 0);
    assert_eq!(
        node.next_wake(),
        None,
        "no armed cadence keeps a routing-only node awake"
    );
}
