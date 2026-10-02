//! The download's source-ownership model (ADR-0090 "Source ownership"): one
//! owner per source, a sighting merges into it rather than pooling a second
//! copy, and a peer that served bad data is not pooled again.

use std::net::Ipv4Addr;

use rmule_primitives::{ExchangedSource, Ipv4Endpoint, PeerSource, UserHash};

use crate::DownloadFailure;

use super::*;

fn source() -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 4662))
}

/// A download already working `peer(1)`, with a free slot for whatever it
/// exchanges.
fn exchanging_state() -> DownloadState {
    exchanging_state_with(2)
}

fn exchanging_state_with(peer_concurrency: usize) -> DownloadState {
    let mut state = DownloadState::new(
        DownloadId::from_u64(1),
        file_hash_only_content(ONE_PART),
        high_id_candidates(vec![peer(1)]),
        QUIET_POSTURE,
        CALLBACK_TIMEOUT,
        peer_concurrency,
    );
    assert_eq!(spawned(&state.start()), vec![peer(1)]);
    state
}

/// `peer(1)` hands over [`source`]; what gets dialed.
fn sight(state: &mut DownloadState) -> Vec<PeerEndpoint> {
    let PeerEndpoint::V4(v4) = source() else {
        unreachable!()
    };
    spawned(&state.on_worker_event(
        peer(1),
        PeerWorkerEvent::SourcesReceived {
            sources: vec![ExchangedSource::plain(PeerSource::HighId(v4))],
        },
    ))
}

/// A source that queued us and hung up stands in the runner's Remote-Queued
/// Pool; sighted again meanwhile, it is not pooled a second time, and the
/// TCP full ask that ends its standing dials it once.
#[test]
fn a_remote_queued_source_sighted_again_keeps_one_owner() {
    let mut state = exchanging_state();
    assert_eq!(sight(&mut state), vec![source()]);
    let _ = state.on_worker_event(source(), PeerWorkerEvent::Connected);
    // The runner observes the retire-while-queued before the brain does.
    state.enter_remote_queue(source());
    let _ = state.on_worker_event(source(), PeerWorkerEvent::Disconnected);

    assert!(sight(&mut state).is_empty(), "merged into the standing");
    assert!(!state.pool.contains(&source()), "not pooled beside it");
    assert_eq!(spawned(&state.readd_source(source())), vec![source()]);
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
            ExchangedSource::new(PeerSource::HighId(v4), hash, None)
        })
        .collect();
    spawned(&state.on_worker_event(peer(1), PeerWorkerEvent::SourcesReceived { sources }))
}

/// `at` completes its hello naming `user_hash`, then connects.
fn hello(state: &mut DownloadState, at: PeerEndpoint, user_hash: UserHash) -> Vec<Decision> {
    let mut out = state.on_worker_event(
        at,
        PeerWorkerEvent::Identified {
            user_hash,
            crypt: None,
            software: hello_software(),
        },
    );
    out.extend(state.on_worker_event(at, PeerWorkerEvent::Connected));
    out
}

/// `at`, the part's sole contributor, streams all of it and the part fails
/// its hash.
fn serve_bad_part(state: &mut DownloadState, at: PeerEndpoint) {
    let part = crate::planning::part_plan(ONE_PART, 0);
    let _ = state.on_worker_event(
        at,
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: part.offset,
            bytes: vec![0u8; part.len as usize],
        },
    );
    let failed = state.on_persist_result(0, at, Err(DownloadFailure::PartVerificationFailed));
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
    let _ = state.on_worker_event(clean, PeerWorkerEvent::Disconnected);

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
    assert!(!state.spent.contains(&moved));
}

/// ADR-0049 (and ADR-0090 "Attachments"): a stance does
/// not outlive the record it attached to — `hello_crypts` and
/// `peer_user_hashes` are pruned with the endpoint's worker at its
/// retirement (`Decision::EndWorker`, ADR-0090 "Source ownership"), not
/// carried past it.
#[test]
fn a_retired_peers_hello_crypt_and_hash_do_not_outlive_its_worker() {
    let mut state = exchanging_state();
    let hash = UserHash::from_bytes([0xCD; UserHash::BYTE_LEN]);
    let _ = state.on_worker_event(peer(1), PeerWorkerEvent::Connected);
    let _ = state.on_worker_event(
        peer(1),
        PeerWorkerEvent::Identified {
            user_hash: hash,
            crypt: Some(rmule_primitives::CryptStance::disabled()),
            software: hello_software(),
        },
    );
    assert!(state.hello_crypt(peer(1)).is_some());

    let _ = state.on_worker_event(peer(1), PeerWorkerEvent::Disconnected);

    assert_eq!(state.hello_crypt(peer(1)), None);
    let mut out = Vec::new();
    state.distrust(peer(1), &mut out);
    assert!(out.is_empty(), "no hash left to distrust by: {out:?}");
}
