//! The brain's half of source ownership (ADR-0090 "Source ownership"): what
//! the **Source Book**'s outcomes become as decisions — a remote-queued
//! source's TCP full ask dials it once, a proven sender of bad data is
//! distrusted durably and not dialed again, and a distrusted peer reached
//! without its hash is retired at its hello. The book's own invariants are
//! asserted in its tests.

use std::net::Ipv4Addr;

use rmule_primitives::{Informant, Ipv4Endpoint, PeerSource, SourceSighting, UserHash};

use crate::DownloadFailure;

use super::*;

fn source() -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 4662))
}

/// A download already working `peer(1)`, with a free slot for whatever it
/// exchanges, logged into a server, so a standing is asked again.
fn exchanging_state() -> DownloadState {
    exchanging_state_with(2)
}

fn exchanging_state_with(peer_concurrency: usize) -> DownloadState {
    let mut state = pooled_state(
        file_hash_only_content(ONE_PART),
        &[peer(1)],
        SourcingPosture {
            callback_capability: CallbackCapability::server_high_id(),
            ..QUIET_POSTURE
        },
        peer_concurrency,
    );
    assert_eq!(spawned(&state.start(t0())), vec![peer(1)]);
    state
}

/// `peer(1)` hands over [`source`]; what gets dialed.
fn sight(state: &mut DownloadState) -> Vec<PeerEndpoint> {
    let PeerEndpoint::V4(v4) = source() else {
        unreachable!()
    };
    spawned(&via_exchange(
        state,
        peer(1),
        vec![SourceSighting::plain(
            PeerSource::HighId(v4),
            Informant::Own,
        )],
    ))
}

/// A source that queued us and hung up holds its standing with no worker;
/// sighted again meanwhile, it is not dialed a second time, and the TCP full
/// ask that ends its standing dials it once.
#[test]
fn a_remote_queued_source_sighted_again_keeps_one_owner() {
    let mut state = exchanging_state();
    assert_eq!(sight(&mut state), vec![source()]);
    let _ = connect(&mut state, t0(), source());
    let _ = state.on_worker_event(t0(), source(), PeerWorkerEvent::Queued { rank: 3 });
    let _ = state.on_worker_event(t0(), source(), PeerWorkerEvent::Disconnected);

    assert!(sight(&mut state).is_empty(), "merged into the standing");
    let asked = state.on_tick(t0() + FILE_REASK_TIME);
    assert_eq!(spawned(&asked), vec![source()]);
    assert!(sight(&mut state).is_empty(), "the full ask holds it");
}

const BAD: UserHash = UserHash::from_bytes([0xBA; UserHash::BYTE_LEN]);
const CLEAN: UserHash = UserHash::from_bytes([0xC1; UserHash::BYTE_LEN]);

/// `peer(1)` hands over `sources` — each an address and the User Hash its
/// record carried, if any; what gets dialed.
fn sight_hashed(
    state: &mut DownloadState,
    sources: &[(PeerEndpoint, Option<UserHash>)],
) -> Vec<PeerEndpoint> {
    let sources = sources
        .iter()
        .map(|&(at, hash)| {
            let PeerEndpoint::V4(v4) = at else {
                unreachable!()
            };
            SourceSighting::new(PeerSource::HighId(v4), hash, None, Informant::Own)
        })
        .collect();
    spawned(&via_exchange(state, peer(1), sources))
}

/// `at` completes its hello naming `user_hash`, then connects.
fn hello(state: &mut DownloadState, at: PeerEndpoint, user_hash: UserHash) -> Vec<Decision> {
    let mut out = state.on_worker_event(t0(), at, identified(user_hash));
    out.extend(connect(state, t0(), at));
    out
}

/// `at`, the part's sole contributor, streams all of it and the part fails
/// its hash.
fn serve_bad_part(state: &mut DownloadState, at: PeerEndpoint) {
    let part = crate::planning::part_plan(ONE_PART, 0);
    let _ = state.on_worker_event(
        t0(),
        at,
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: part.offset,
            bytes: vec![0u8; part.len as usize],
        },
    );
    let failed = state.on_persist_result(t0(), 0, at, Err(DownloadFailure::PartVerificationFailed));
    assert!(
        failed
            .iter()
            .any(|d| matches!(d, Decision::DistrustPeer { user_hash } if *user_hash == BAD)),
        "the sole sender is distrusted, durably: {failed:?}"
    );
}

/// A peer that served this file bad data is not dialed again when a record
/// naming its User Hash is sighted; a peer whose session merely ended is.
#[test]
fn a_peer_that_served_bad_data_is_not_redialled_and_a_clean_one_is() {
    let (bad, clean) = (peer(2), peer(3));
    let mut state = exchanging_state_with(3);
    let both = [(bad, Some(BAD)), (clean, Some(CLEAN))];
    assert_eq!(sight_hashed(&mut state, &both), vec![bad, clean]);

    let _ = hello(&mut state, bad, BAD);
    serve_bad_part(&mut state, bad);
    let _ = hello(&mut state, clean, CLEAN);
    let _ = state.on_worker_event(t0(), clean, PeerWorkerEvent::Disconnected);

    assert_eq!(sight_hashed(&mut state, &both), vec![clean]);
}

/// A distrusted peer reached through a record that named no hash — here at an
/// address it moved to — is retired at its hello, before any part is
/// assigned, and its address is not spent: it answered.
#[test]
fn a_distrusted_peer_sighted_without_its_hash_is_retired_at_its_hello() {
    let (bad, moved) = (peer(2), peer(4));
    let mut state = exchanging_state_with(3);
    let _ = sight_hashed(&mut state, &[(bad, Some(BAD))]);
    let _ = hello(&mut state, bad, BAD);
    serve_bad_part(&mut state, bad);

    assert_eq!(sight_hashed(&mut state, &[(moved, None)]), vec![moved]);
    let met = hello(&mut state, moved, BAD);
    assert!(
        met.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PeerRetired {
                peer: p,
                reason: PeerRetirementReason::Distrusted,
                ..
            }) if *p == moved
        )),
        "{met:?}"
    );
    assert!(!state.is_working(moved), "no part went to it");
    assert_eq!(
        sight_hashed(&mut state, &[(moved, None)]),
        vec![moved],
        "its endpoint is not spent: it answered"
    );
}
