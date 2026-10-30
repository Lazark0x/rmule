//! The dual-stack fallback of the High-ID pool: a source that
//! named both families is dialed first in the family the Dial Chooser picks,
//! and a first dial that never connects falls to its other family once. A
//! failed dial spends its endpoint, single-address or half, for a re-ask
//! period.

use std::net::Ipv4Addr;

use rmule_primitives::{
    ClientId, Informant, Ipv4Endpoint, Ipv6Endpoint, PeerSource, SourceSighting, UserHash,
};

use super::*;

fn v4() -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 8), 4662)
}

/// Off every routed prefix on the bench (the `ipv6-extsx-emit` scenario's unroutable leg).
fn v6() -> Ipv6Endpoint {
    Ipv6Endpoint::new("3fff:ed2:2::8".parse().unwrap(), 4662)
}

fn known_ipv6() -> DialPosition {
    DialPosition {
        known_ipv6: Some("3fff:ed2:1::2".parse().unwrap()),
    }
}

/// A download already working `peer(1)`, with a free slot for whatever it
/// exchanges.
fn exchanging_state(dial: DialPosition) -> DownloadState {
    let mut state = pooled_state(
        file_hash_only_content(ONE_PART),
        &[peer(1)],
        SourcingPosture {
            dial,
            ..QUIET_POSTURE
        },
        2,
    );
    assert_eq!(spawned(&state.start(t0())), vec![peer(1)]);
    state
}

/// `peer(1)` hands over the dual-stack record ([`v4`] with [`v6`] beside it,
/// as an ExtSX `CT_MOD_IP_V6` names it); what gets dialed.
fn sight(state: &mut DownloadState) -> Vec<PeerEndpoint> {
    let source =
        SourceSighting::plain(PeerSource::HighId(v4()), Informant::Own).with_ipv6_half(Some(v6()));
    spawned(&via_exchange(state, peer(1), vec![source]))
}

fn end(state: &mut DownloadState, at: PeerEndpoint, event: PeerWorkerEvent) -> Vec<PeerEndpoint> {
    spawned(&state.on_worker_event(t0(), at, event))
}

#[test]
fn a_failed_ipv6_first_dial_falls_to_the_ipv4_half() {
    let mut state = exchanging_state(known_ipv6());
    assert_eq!(sight(&mut state), vec![PeerEndpoint::V6(v6())]);

    assert_eq!(
        end(
            &mut state,
            PeerEndpoint::V6(v6()),
            PeerWorkerEvent::Disconnected
        ),
        vec![PeerEndpoint::V4(v4())]
    );
}

/// The IPv4 was picked first because we held no IPv6; one arrived before
/// the IPv4 dial failed, so the half is dialable now.
#[test]
fn a_failed_ipv4_first_dial_falls_to_the_ipv6_half_once_we_can_dial_it() {
    let mut state = exchanging_state(DialPosition::default());
    assert_eq!(sight(&mut state), vec![PeerEndpoint::V4(v4())]);
    let _ = state.on_dial_position(t0(), known_ipv6());

    assert_eq!(
        end(
            &mut state,
            PeerEndpoint::V4(v4()),
            PeerWorkerEvent::Disconnected
        ),
        vec![PeerEndpoint::V6(v6())]
    );
}

#[test]
fn the_second_family_failing_too_retires_the_source() {
    let mut state = exchanging_state(known_ipv6());
    let _ = sight(&mut state);
    let _ = end(
        &mut state,
        PeerEndpoint::V6(v6()),
        PeerWorkerEvent::Disconnected,
    );

    assert!(
        end(
            &mut state,
            PeerEndpoint::V4(v4()),
            PeerWorkerEvent::Disconnected
        )
        .is_empty(),
        "one dial per family"
    );
}

/// The failed family is spent: after the IPv4 dial reached the peer and its
/// session ended, a later sighting dials the IPv4 straight away.
#[test]
fn a_later_sighting_skips_the_spent_family() {
    let mut state = exchanging_state(known_ipv6());
    let _ = sight(&mut state);
    let _ = end(
        &mut state,
        PeerEndpoint::V6(v6()),
        PeerWorkerEvent::Disconnected,
    );
    let _ = end(
        &mut state,
        PeerEndpoint::V4(v4()),
        PeerWorkerEvent::Connected,
    );
    let _ = end(
        &mut state,
        PeerEndpoint::V4(v4()),
        PeerWorkerEvent::Disconnected,
    );

    assert_eq!(sight(&mut state), vec![PeerEndpoint::V4(v4())]);
}

#[test]
fn a_first_dial_that_connected_never_falls_to_the_other_family() {
    let mut state = exchanging_state(known_ipv6());
    let _ = sight(&mut state);
    let _ = end(
        &mut state,
        PeerEndpoint::V6(v6()),
        PeerWorkerEvent::Connected,
    );

    assert!(
        end(
            &mut state,
            PeerEndpoint::V6(v6()),
            PeerWorkerEvent::Disconnected
        )
        .is_empty()
    );
}

/// Crypt incompatibility is the peer's stance, not its family: the other
/// half meets the same two stances.
#[test]
fn a_crypt_incompatible_first_dial_does_not_fall_to_the_other_family() {
    let mut state = exchanging_state(known_ipv6());
    let _ = sight(&mut state);

    assert!(
        end(
            &mut state,
            PeerEndpoint::V6(v6()),
            PeerWorkerEvent::CryptIncompatible
        )
        .is_empty()
    );
}

/// A peer the server lookup pooled as plain IPv4 (`peer(1)` beside it) is
/// revealed dual-stack by a later exchange: the half merges into the record
/// in hand, so the IPv4 dial's failure falls to it — once.
#[test]
fn a_peer_pooled_as_ipv4_gains_the_ipv6_half_a_later_sighting_names() {
    let mut state = pooled_state(
        file_hash_only_content(ONE_PART),
        &[peer(1), PeerEndpoint::V4(v4())],
        SourcingPosture {
            dial: known_ipv6(),
            ..QUIET_POSTURE
        },
        2,
    );
    assert_eq!(
        spawned(&state.start(t0())),
        vec![peer(1), PeerEndpoint::V4(v4())]
    );
    assert!(sight(&mut state).is_empty(), "the peer is in hand already");

    assert_eq!(
        end(
            &mut state,
            PeerEndpoint::V4(v4()),
            PeerWorkerEvent::Disconnected
        ),
        vec![PeerEndpoint::V6(v6())]
    );
    assert!(
        end(
            &mut state,
            PeerEndpoint::V6(v6()),
            PeerWorkerEvent::Disconnected
        )
        .is_empty(),
        "one dial per family"
    );
}

/// Both families failed: the second is spent as the first was, so a later
/// sighting of the peer dials neither.
#[test]
fn a_later_sighting_after_both_families_failed_dials_nothing() {
    let mut state = exchanging_state(known_ipv6());
    let _ = sight(&mut state);
    let _ = end(
        &mut state,
        PeerEndpoint::V6(v6()),
        PeerWorkerEvent::Disconnected,
    );
    let _ = end(
        &mut state,
        PeerEndpoint::V4(v4()),
        PeerWorkerEvent::Disconnected,
    );

    assert!(sight(&mut state).is_empty());
}

/// A dial that could not even start is a failed dial: the other family
/// follows, and the failed half leaves no fallback record behind. The path is
/// family-blind, so an IPv4-first order falls to its IPv6 half the same way.
#[test]
fn a_dual_stack_dial_that_fails_to_start_falls_to_its_other_family() {
    let mut state = exchanging_state(known_ipv6());
    assert_eq!(sight(&mut state), vec![PeerEndpoint::V6(v6())]);

    assert_eq!(
        spawned(&state.on_spawn_failed(t0(), PeerEndpoint::V6(v6()))),
        vec![PeerEndpoint::V4(v4())]
    );
    assert!(
        spawned(&state.on_spawn_failed(t0(), PeerEndpoint::V4(v4()))).is_empty(),
        "the failed half is no fallback left behind"
    );
}

/// `peer(1)` hands over a plain IPv4 record; what gets dialed.
fn sight_single(state: &mut DownloadState) -> Vec<PeerEndpoint> {
    let source = SourceSighting::plain(PeerSource::HighId(v4()), Informant::Own);
    spawned(&via_exchange(state, peer(1), vec![source]))
}

/// A single-address source is one half with no other: its failed dial spends
/// it, so a later sighting does not pay its timeout again.
#[test]
fn a_single_address_source_whose_dial_failed_is_not_redialled() {
    let mut state = exchanging_state(DialPosition::default());
    assert_eq!(sight_single(&mut state), vec![PeerEndpoint::V4(v4())]);
    let _ = end(
        &mut state,
        PeerEndpoint::V4(v4()),
        PeerWorkerEvent::Disconnected,
    );

    assert!(sight_single(&mut state).is_empty());
}

/// A source that completed its handshake is alive, however its session ended
/// — a slot wait that timed out here — so it is never spent.
#[test]
fn a_source_that_connected_is_redialled_when_sighted_again() {
    let mut state = exchanging_state(DialPosition::default());
    let _ = sight_single(&mut state);
    let _ = end(
        &mut state,
        PeerEndpoint::V4(v4()),
        PeerWorkerEvent::Connected,
    );
    let _ = end(
        &mut state,
        PeerEndpoint::V4(v4()),
        PeerWorkerEvent::SlotTimeout,
    );

    assert_eq!(sight_single(&mut state), vec![PeerEndpoint::V4(v4())]);
}

/// Spent lasts one to two re-ask periods, not the run: a source that was only
/// momentarily down comes back on a sighting once it has sat one out.
#[test]
fn a_spent_endpoint_is_redialled_after_it_sits_out_a_reask_period() {
    let mut state = exchanging_state(DialPosition::default());
    let _ = sight_single(&mut state);
    let _ = end(
        &mut state,
        PeerEndpoint::V4(v4()),
        PeerWorkerEvent::Disconnected,
    );

    let _ = state.on_tick(t0() + FILE_REASK_TIME);
    assert!(
        sight_single(&mut state).is_empty(),
        "spent in the period that just ended"
    );
    let _ = state.on_tick(t0() + FILE_REASK_TIME * 2);
    assert_eq!(sight_single(&mut state), vec![PeerEndpoint::V4(v4())]);
}

/// One client's two addresses as two records, both dialed: the IPv4 one named
/// `named`, as a source-exchange row may name a hash.
fn two_records_dialed(named: Option<UserHash>) -> DownloadState {
    let ipv6 = SourceSighting::plain(PeerSource::Ipv6(v6()), Informant::Own);
    let ipv4 = SourceSighting::new(
        PeerSource::HighId(v4()),
        named,
        Some(rmule_primitives::SourceCryptOptions::from_byte(0)),
        Informant::Own,
    );
    let mut state = state_from(
        file_hash_only_content(ONE_PART),
        SourcingPosture {
            dial: known_ipv6(),
            ..QUIET_POSTURE
        },
        2,
        no_facts(),
        vec![(Channel::Server, vec![ipv6, ipv4])],
        Vec::new(),
    );
    assert_eq!(spawned(&state.start(t0())).len(), 2);
    state
}

/// The hello of the client at [`v6`], on the IPv6 link: it names [`v4`] as its
/// High ID, on the same listen port.
fn hello_naming_v4(state: &mut DownloadState) -> Vec<Decision> {
    let at = PeerEndpoint::V6(v6());
    let hello = HelloFacts {
        client_id: ClientId::from_u32(u32::from_le_bytes(v4().ip.octets())),
        tcp_port: v4().port,
        ..HelloFacts::of(UserHash::from_bytes([0x41; UserHash::BYTE_LEN]))
    };
    let _ = state.on_worker_event(t0(), at, PeerWorkerEvent::Connected);
    state.on_worker_event(t0(), at, PeerWorkerEvent::Identity(hello.identity()))
}

/// Run `1793356626`'s shape: two channels sighted one client's two families
/// apart, and both were dialed. The hello of the first says the second is the
/// same client, whose dial ends as the same source (ADR-0087).
#[test]
fn a_hello_naming_the_other_record_folds_the_two_into_one_source() {
    let mut state = two_records_dialed(None);
    assert_eq!(state.known_sources(), 2);

    let decisions = hello_naming_v4(&mut state);

    assert_eq!(state.known_sources(), 1);
    assert!(decisions.iter().any(|decision| matches!(
        decision,
        Decision::EndWorker { peer, .. } if *peer == PeerEndpoint::V4(v4())
    )));
}

/// A hello proves its own address, not who holds the one it names: a record
/// that named another User Hash stays apart.
#[test]
fn a_record_naming_another_hash_is_not_folded_by_a_hello_naming_its_address() {
    let mut state = two_records_dialed(Some(UserHash::from_bytes([0x42; UserHash::BYTE_LEN])));

    let _ = hello_naming_v4(&mut state);

    assert_eq!(state.known_sources(), 2);
}
