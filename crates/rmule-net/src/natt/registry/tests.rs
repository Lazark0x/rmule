//! The registry's admission rules, driven with explicit time.

use std::net::{IpAddr, Ipv4Addr};

use rmule_primitives::Ipv4Endpoint;

use super::*;

fn endpoint(last: u8) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, last), 4672))
}

fn at(last: u8, port: u16) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, last), port))
}

/// Every source expected: the rules below are about slots, not about who
/// may open one.
fn expected(_: IpAddr) -> bool {
    true
}

/// Only `198.51.100.{last}` expected.
fn only(last: u8) -> impl Fn(IpAddr) -> bool {
    move |ip| ip == IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))
}

/// An opening packet from a source the core expects nothing from opens no
/// slot, so the engine never answers it with an `ST_STATE` or a KEY frame.
#[test]
fn an_opening_packet_from_an_unexpected_ip_is_dropped() {
    let now = Instant::now();
    let mut registry = TunnelRegistry::new();
    assert_eq!(
        registry.admit(endpoint(1), true, only(2), now),
        Admission::Drop
    );
    assert!(registry.is_empty());
    assert_eq!(
        registry.admit(endpoint(2), true, only(2), now),
        Admission::Opened
    );
}

/// A flood of openers — spoofed from every port of one expected address and
/// from unexpected ones — leaves another expected address admissible: one IP
/// holds at most `OPENING_PER_IP` opening slots and a stranger holds none.
#[test]
fn a_flood_past_the_cap_keeps_a_live_expectation_admissible() {
    let now = Instant::now();
    let mut registry = TunnelRegistry::new();
    let expected_pair = |ip: IpAddr| ip == endpoint(1).ip() || ip == endpoint(2).ip();
    let opened = (1000..2000)
        .filter(|port| registry.admit(at(1, *port), true, expected_pair, now) == Admission::Opened)
        .count();
    assert_eq!(opened, OPENING_PER_IP);
    for last in 10..=250 {
        assert_eq!(
            registry.admit(at(last, 4672), true, expected_pair, now),
            Admission::Drop
        );
    }
    assert_eq!(
        registry.admit(at(2, 4662), true, expected_pair, now),
        Admission::Opened
    );
}

/// The node-wide cap holds however many addresses are expected, and the
/// tick's prune gives the room back once the window has passed.
#[test]
fn the_node_wide_cap_holds_until_the_tick_prunes_the_lapsed_window() {
    let now = Instant::now();
    let mut registry = TunnelRegistry::new();
    let mut opened = 0;
    for last in 1..=250 {
        for port in 0..OPENING_PER_IP as u16 {
            if registry.admit(at(last, 5000 + port), true, expected, now) == Admission::Opened {
                opened += 1;
            }
        }
    }
    assert_eq!(opened, OPENING_MAX);
    assert_eq!(
        registry.admit(at(251, 4672), true, expected, now),
        Admission::Drop
    );
    let later = now + OPENING_TTL;
    registry.prune(later);
    assert!(registry.is_empty());
    assert_eq!(
        registry.admit(at(251, 4672), true, expected, later),
        Admission::Opened
    );
}

/// The A2 rule: a non-opening frame from a stranger is dropped before the
/// engine sees it, so no `ST_RESET` reaches an address nobody verified.
#[test]
fn a_non_opening_frame_from_an_unknown_endpoint_is_dropped_unanswered() {
    let now = Instant::now();
    let mut registry = TunnelRegistry::new();
    assert_eq!(
        registry.admit(endpoint(1), false, expected, now),
        Admission::Drop
    );
    assert!(registry.is_empty(), "a dropped frame leaves no trace");
}

/// An opening packet admits the endpoint *and* its follow-ups: the
/// handshake's second packet is not itself an opening one.
#[test]
fn an_opening_packet_admits_the_handshake_that_follows_it() {
    let now = Instant::now();
    let mut registry = TunnelRegistry::new();
    assert_eq!(
        registry.admit(endpoint(1), true, expected, now),
        Admission::Opened
    );
    assert_eq!(registry.slot(endpoint(1)), Some(TunnelSlot::Opening));
    assert_eq!(
        registry.admit(endpoint(1), false, expected, now),
        Admission::Inject
    );
}

/// A dial opens the slot from our side, because our own `ST_SYN` leaves
/// rather than arrives and nothing inbound would have opened it.
#[test]
fn a_dial_opens_the_slot_so_the_answer_is_admitted() {
    let now = Instant::now();
    let mut registry = TunnelRegistry::new();
    registry.dialing(endpoint(1), now);
    assert_eq!(
        registry.admit(endpoint(1), false, expected, now),
        Admission::Inject
    );
}

/// An **inbound** opening slot expires; a held one does not. A forged
/// opening packet therefore buys one window, while a live transfer is never
/// evicted under it.
#[test]
fn an_opening_slot_ages_out_and_a_held_one_does_not() {
    let now = Instant::now();
    let mut registry = TunnelRegistry::new();
    assert_eq!(
        registry.admit(endpoint(1), true, expected, now),
        Admission::Opened
    );
    registry.held(endpoint(2), now);
    let later = now + OPENING_TTL;
    assert_eq!(
        registry.admit(endpoint(1), false, expected, later),
        Admission::Drop
    );
    assert_eq!(
        registry.admit(endpoint(2), false, expected, later),
        Admission::Inject
    );
    assert_eq!(registry.len(), 1);
}

/// The mismatch this slot exists to end: a dial outliving
/// `OPENING_TTL` kept waiting for an answer the registry had already
/// started dropping as a stranger's. A dial's own slot is not pruned —
/// while a forged inbound opener beside it still buys only one window.
#[test]
fn a_dials_own_slot_outlives_the_window_a_forged_opener_buys() {
    let now = Instant::now();
    let mut registry = TunnelRegistry::new();
    registry.dialing(endpoint(1), now);
    assert_eq!(
        registry.admit(endpoint(2), true, expected, now),
        Admission::Opened
    );
    let later = now + OPENING_TTL * 4;
    assert_eq!(
        registry.admit(endpoint(1), false, expected, later),
        Admission::Inject
    );
    assert_eq!(
        registry.admit(endpoint(2), false, expected, later),
        Admission::Drop
    );
}

/// The claim ends with the dial, however the dial ended — including the
/// cancellation a bounded, retried dial performs. A promoted slot stays:
/// it is the tunnel's now.
#[test]
fn a_dropped_dial_releases_its_slot_and_a_promoted_one_keeps_it() {
    let registry = Arc::new(Mutex::new(TunnelRegistry::new()));
    drop(DialingSlot::open(&registry, endpoint(1)));
    assert_eq!(registry.lock().unwrap().slot(endpoint(1)), None);

    let _tunnel = DialingSlot::open(&registry, endpoint(2)).held();
    assert_eq!(
        registry.lock().unwrap().slot(endpoint(2)),
        Some(TunnelSlot::Held)
    );
}

/// A dial that ends after somebody else's tunnel took the same endpoint
/// leaves that tunnel alone: the release is conditional on the slot still
/// being the dial's.
#[test]
fn a_dial_ending_never_evicts_a_tunnel_that_took_its_endpoint() {
    let registry = Arc::new(Mutex::new(TunnelRegistry::new()));
    let slot = DialingSlot::open(&registry, endpoint(1));
    registry.lock().unwrap().held(endpoint(1), Instant::now());
    drop(slot);
    assert_eq!(
        registry.lock().unwrap().slot(endpoint(1)),
        Some(TunnelSlot::Held)
    );
}

/// A released endpoint is a stranger again — so a late datagram for a
/// closed tunnel is dropped rather than reset.
#[test]
fn a_released_endpoint_is_a_stranger_again() {
    let now = Instant::now();
    let mut registry = TunnelRegistry::new();
    registry.held(endpoint(1), now);
    registry.release(endpoint(1));
    assert_eq!(registry.slot(endpoint(1)), None);
    assert_eq!(
        registry.admit(endpoint(1), false, expected, now),
        Admission::Drop
    );
}

/// Two tunnels on one endpoint — our dial and the peer's, both completing
/// in a simultaneous open — hold one slot, and the first to close leaves
/// the other admitted. The slot goes with the last one.
#[test]
fn a_held_slot_lives_until_its_last_tunnel_drops() {
    let registry = Arc::new(Mutex::new(TunnelRegistry::new()));
    let dialed = DialingSlot::open(&registry, endpoint(1)).held();
    let accepted = HeldSlot::hold(&registry, endpoint(1));
    drop(dialed);
    let now = Instant::now();
    assert_eq!(
        registry
            .lock()
            .unwrap()
            .admit(endpoint(1), false, expected, now),
        Admission::Inject,
        "the surviving tunnel is still admitted"
    );
    drop(accepted);
    assert_eq!(registry.lock().unwrap().slot(endpoint(1)), None);
    assert_eq!(
        registry
            .lock()
            .unwrap()
            .admit(endpoint(1), false, expected, now),
        Admission::Drop
    );
}

/// Re-dialing a path a tunnel already rides does not demote its slot: the
/// dial's end removes only a slot that is still `Dialing`, so a demoted
/// one would have been evicted from under the live tunnel.
#[test]
fn a_dial_over_a_held_path_leaves_the_tunnel_admitted() {
    let registry = Arc::new(Mutex::new(TunnelRegistry::new()));
    let _tunnel = HeldSlot::hold(&registry, endpoint(1));
    drop(DialingSlot::open(&registry, endpoint(1)));
    assert_eq!(
        registry.lock().unwrap().slot(endpoint(1)),
        Some(TunnelSlot::Held)
    );
}
