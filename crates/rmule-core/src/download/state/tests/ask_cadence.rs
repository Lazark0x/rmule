//! The source-ask cadence on the **Source Book**'s records (ADR-0108): the
//! brain decides whether each dial and each callback carries a source ask,
//! from the facts the peer's record and its names hold at the instant handed
//! in.

use super::*;

/// What a fresh High-ID worker at `at` is told about the source ask.
fn spawn_wants(decisions: &[Decision], at: PeerEndpoint) -> Option<bool> {
    decisions.iter().find_map(|decision| match decision {
        Decision::Spawn {
            peer, want_sources, ..
        } if *peer == at => Some(*want_sources),
        _ => None,
    })
}

/// What the connected-server callback for `low_id` is told about the source
/// ask.
fn callback_wants(decisions: &[Decision], low_id: ClientId) -> Option<bool> {
    decisions.iter().find_map(|decision| match decision {
        Decision::RequestCallback {
            low_id: asked,
            want_sources,
            ..
        } if *asked == low_id => Some(*want_sources),
        _ => None,
    })
}

/// Deciding to want sources stamps nothing: a peer whose connection ended
/// before any ask went out is still a peer never asked, and an answer alone
/// does not hold it off. Only the worker's report that the ask went out
/// stamps it, and an answer then holds the peer off for its next connection —
/// whose record is a new one, read under the endpoint the old one kept.
#[test]
fn only_an_ask_that_went_out_holds_the_peer_off() {
    let mut state = file_hash_only_state(vec![peer(1), peer(2)], 1);
    assert_eq!(spawn_wants(&state.start(t0()), peer(1)), Some(true));

    // An answer with no ask behind it, and a connection that ends.
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Connected);
    let _ = via_exchange(&mut state, peer(1), Vec::new());
    let next = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    assert_eq!(spawn_wants(&next, peer(2)), Some(true));
    let _ = take(&mut state, Channel::Server, plain_sightings(&[peer(1)]));
    let again = state.on_worker_event(t0(), peer(2), PeerWorkerEvent::Disconnected);
    assert_eq!(
        spawn_wants(&again, peer(1)),
        Some(true),
        "never asked: an answer alone does not hold it off"
    );

    // Asked and answered: the next connection to it carries no ask, while a
    // stranger's does.
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Connected);
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::SourcesAsked);
    let _ = via_exchange(&mut state, peer(1), Vec::new());
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    let held = take(
        &mut state,
        Channel::Server,
        plain_sightings(&[peer(1), peer(3)]),
    );
    assert_eq!(spawn_wants(&held.decisions, peer(1)), Some(false));
    let next = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    assert_eq!(
        spawn_wants(&next, peer(3)),
        Some(true),
        "a stranger is asked"
    );
}

/// A Low-ID peer has no endpoint before it connects, so its callback is
/// decided by the names its record holds (ADR-0108, aMule
/// `FindMatchingClient`): the `(server, low_id)` of its callback while that id
/// holds, its User Hash after. A peer asked on one callback connection is the
/// same peer to its next callback, and to a record under a new Low ID that
/// names its hash; a stranger is still asked.
#[test]
fn a_low_id_peer_called_back_again_is_the_peer_already_asked() {
    let hash = UserHash::from_bytes([
        0xE4, 0x1B, 0x72, 0x09, 0xAD, 0x35, 0xC8, 0x60, 0x1F, 0x94, 0x2E, 0xB7, 0x58, 0x03, 0xDA,
        0x6C,
    ]);
    let (first, next, stranger) = (low(0x0003_1A2B), low(0x0004_77C1), low(0x0005_0101));
    let mut state = callback_state(Vec::new(), vec![low_candidate(first.as_u32())], true, 1);
    assert_eq!(callback_wants(&state.start(t0()), first), Some(true));

    // The callback lands, the peer names its hash, is asked and answers.
    let connection = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 7), 51_234));
    let _ = state.on_callback_connected(t0(), connected_key(first), connection);
    let _ = state.on_worker_event(t0(), connection, PeerWorkerEvent::Connected);
    let _ = state.on_worker_event(t0(), connection, identified(hash));
    let _ = state.on_worker_event(t0(), connection, PeerWorkerEvent::SourcesAsked);
    let _ = via_exchange(&mut state, connection, Vec::new());

    // Its worker ends without a rank: the same record is called back again.
    let later = t0() + Duration::from_secs(10 * 60);
    let again = state.on_worker_event(later, connection, PeerWorkerEvent::Disconnected);
    assert_eq!(callback_wants(&again, first), Some(false));

    // The peer comes back under a new Low ID, its hash named; the first
    // callback lapses and the slot goes to it.
    let _ = take(
        &mut state,
        Channel::Server,
        [
            SourceSighting::new(
                rmule_primitives::PeerSource::new(next, 4662),
                Some(hash),
                None,
            ),
            low_candidate(stranger.as_u32()),
        ],
    );
    let renamed = until_road_ends(&mut state, connected_key(first));
    assert_eq!(callback_wants(&renamed, next), Some(false));
    let unknown = until_road_ends(&mut state, connected_key(next));
    assert_eq!(callback_wants(&unknown, stranger), Some(true));
}

/// Sightings a server names at `now`.
fn sighted_at(state: &mut DownloadState, now: Instant, at: &[PeerEndpoint]) -> Vec<Decision> {
    let filter = crate::ip_filter::IpFilter::default();
    let gate = Gate {
        filter: &filter,
        dial: state.dial,
    };
    state
        .on_sightings(now, Channel::Server, plain_sightings(at), &gate)
        .decisions
}

/// aMule forgets a client that is no longer a source at its client-list
/// cleanup, a pass every `CLIENTLIST_CLEANUP_TIME` (stock 2.3.3
/// `ClientList.cpp:975-1003`, 34 minutes: `Constants.h:74`). The facts a
/// departed peer's names kept go at the first pass that finds no record
/// answering to them, and the peer is a stranger again; a peer sighted again
/// before the pass has a record answering to its names, and keeps them.
#[test]
fn a_departed_peers_facts_go_at_the_client_list_cleanup() {
    let mut state = file_hash_only_state(vec![peer(1), peer(2)], 1);
    let _ = state.start(t0());
    let _ = state.on_tick(t0());
    for gone in [peer(1), peer(2)] {
        let _ = state.on_worker_event(t0(), gone, PeerWorkerEvent::Connected);
        let _ = state.on_worker_event(t0(), gone, PeerWorkerEvent::SourcesAsked);
        let _ = via_exchange(&mut state, gone, Vec::new());
        let _ = state.on_worker_event(t0(), gone, PeerWorkerEvent::Disconnected);
    }

    // Peer 1 is sighted again and connects before the pass: its record
    // answers to its endpoint when the pass runs.
    let soon = t0() + Duration::from_secs(10 * 60);
    assert_eq!(
        spawn_wants(&sighted_at(&mut state, soon, &[peer(1)]), peer(1)),
        Some(false)
    );
    let _ = state.on_worker_event(soon, peer(1), PeerWorkerEvent::Connected);

    let pass = t0() + CLIENT_LIST_CLEANUP;
    let _ = state.on_tick(pass);
    let _ = state.on_worker_event(pass, peer(1), PeerWorkerEvent::Disconnected);
    assert_eq!(
        spawn_wants(&sighted_at(&mut state, pass, &[peer(2)]), peer(2)),
        Some(true),
        "no record answered to it at the pass: forgotten"
    );
    let _ = state.on_worker_event(pass, peer(2), PeerWorkerEvent::Disconnected);
    assert_eq!(
        spawn_wants(&sighted_at(&mut state, pass, &[peer(1)]), peer(1)),
        Some(false),
        "its record answered at the pass: still the peer asked"
    );
}
