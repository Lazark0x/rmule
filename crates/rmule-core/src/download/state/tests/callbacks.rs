//! The Low-ID callback leg (ADR-0039): a capable download holding a slot for a
//! requested callback, an adopted peer binding to that slot and being assigned
//! on connect, a lapse freeing it for the next candidate, and the High-ID
//! preference that keeps callbacks last — plus ADR-0091's twelve-second
//! fallback, the second deadline that rides beside the first.

use rmule_primitives::UserHash;

use crate::callback::CallbackSilence;
use crate::service::PeerReachRoute;

use super::*;

/// A connected-server Low-ID source carrying the User Hash the rendezvous
/// ledger is keyed by: on our server, which can introduce us, so its callback
/// could fall to NAT traversal (ADR-0091).
fn punchable(n: u32) -> SourceSighting {
    SourceSighting::new(
        rmule_primitives::PeerSource::new(low(n), 4662),
        Some(UserHash::from_bytes([0xAB; UserHash::BYTE_LEN])),
        None,
        rmule_primitives::Informant::Own,
    )
}

#[test]
fn a_low_id_candidate_requests_a_callback_and_holds_a_slot_when_capable() {
    let mut state = callback_state(Vec::new(), vec![low_candidate(7)], true, 2);
    let decisions = state.start(t0());
    assert!(
        decisions
            .iter()
            .any(|d| matches!(d, Decision::RequestCallback { low_id, .. } if *low_id == low(7))),
        "a Low-ID candidate requests a callback: {decisions:?}"
    );
    // The slot is held for the dial-back, and released if the peer never
    // dials in.
    assert!(
        state
            .match_inbound_callback(connected_key(low(7)))
            .is_some()
    );
    let lapsed = until_road_ends(&mut state, connected_key(low(7)));
    assert!(!state.has_pending_callbacks(), "released: {lapsed:?}");
    assert!(
        !decisions
            .iter()
            .any(|d| matches!(d, Decision::Spawn { .. })),
        "a Low-ID candidate is never dialed"
    );
}

/// ADR-0091 rung 1 for the pair it was written for: a **Low-ID
/// downloader** with a Low-ID candidate on its own server admits it and punches
/// **at once**. No callback is asked for — every callback asks the target to
/// dial a node nothing can reach — and so no silence is armed to wait out;
/// twelve seconds of waiting would be twelve seconds spent on an invitation
/// that was never sent.
#[test]
fn a_low_id_downloader_punches_its_low_id_candidate_at_once() {
    let mut state = callback_state(
        Vec::new(),
        vec![low_candidate(7), low_candidate(8)],
        false,
        1,
    );
    let decisions = state.start(t0());
    assert!(
        !decisions
            .iter()
            .any(|d| matches!(d, Decision::RequestCallback { .. })),
        "no callback is requested when rmule cannot be called back: {decisions:?}"
    );
    assert!(
        decisions.iter().any(|d| matches!(
            d,
            Decision::FallToNatTraversal { candidate, silence, .. }
                if candidate.low_id == low(7)
                    && *silence == CallbackSilence::NoCallbackPossible
        )),
        "the first candidate falls to NAT traversal on admission: {decisions:?}"
    );
    assert_eq!(
        state.next_wake(),
        Some(t0() + CALLBACK_TIMEOUT),
        "there is no callback to measure silence from"
    );
}

/// On the punch road the slot waits on the attempt. The 30 s
/// slot release is still armed, but its lapse does not end a traversal that
/// is still running — ending it there would cut the 120 s budget to 30 s and
/// the ADR-0061 fall-through with it; the attempt's bound, armed beside the
/// punch, is what releases the slot to the next candidate.
#[test]
fn a_punch_road_slot_waits_on_the_attempt_not_the_30_s_release() {
    let mut state = callback_state(
        Vec::new(),
        vec![low_candidate(7), low_candidate(8)],
        false,
        1,
    );
    let _ = state.start(t0());

    assert!(state.on_tick(t0() + CALLBACK_TIMEOUT).is_empty());
    assert_eq!(
        state.next_wake(),
        Some(t0() + TRAVERSAL_SLOT_BOUND),
        "the punch's bound is what the slot waits on now"
    );

    let lapsed = state.on_tick(t0() + TRAVERSAL_SLOT_BOUND);
    assert!(
        lapsed.iter().any(|d| matches!(
            d,
            Decision::FallToNatTraversal { candidate, .. } if candidate.low_id == low(8)
        )),
        "the attempt's bound releases the slot to the next candidate: {lapsed:?}"
    );
}

/// The other half of the rule, and the honest starvation it keeps: a Low-ID
/// downloader whose only candidate is an ADR-0051 global source with no buddy
/// and no NAT-T bit can neither be called back for it nor have anyone introduce
/// it — its own server is not ours to ask — so the download fails
/// `NoUsableSources` as it always did.
#[test]
fn a_candidate_with_neither_callback_nor_coordinator_still_starves_the_download() {
    use rmule_primitives::PeerSource;
    // One dialable source so a fleet exists to starve, and the global Low-ID
    // one behind it.
    let mut state = callback_state(vec![peer(1)], Vec::new(), false, 1);
    let _ = state.start(t0());
    let _ = connect(&mut state, t0(), peer(1));

    let discovered = via_global(
        &mut state,
        source_server(9),
        vec![PeerSource::new(low(7), 4662)],
    );
    assert!(
        !discovered.iter().any(|d| matches!(
            d,
            Decision::RequestGlobalCallback { .. } | Decision::FallToNatTraversal { .. }
        )),
        "no road is open to it, so neither road is taken: {discovered:?}"
    );

    let retired = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    assert!(
        retired
            .iter()
            .any(|d| matches!(d, Decision::Fail(DownloadFailure::NoUsableSources))),
        "a candidate nobody can reach is not a usable source: {retired:?}"
    );
}
#[test]
fn an_adopted_global_callback_peer_binds_then_its_connected_event_assigns_it() {
    use rmule_primitives::PeerSource;
    let server = source_server(9);
    let key = CallbackKey {
        server: Some(server),
        low_id: low(7),
        kad_port: None,
    };
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    // Requests a per-server callback for low(7), holding slot 0.
    let _ = via_global(&mut state, server, vec![PeerSource::new(low(7), 4662)]);

    let adopted = state.on_callback_connected(t0(), key, peer(9)).decisions;

    // Bind-without-assign: the adopted peer is selected and its callback deadline
    // cancelled, but it is not yet working — its own Connected event assigns it.
    assert!(
        adopted.iter().any(|d| matches!(d,
            Decision::Emit(DownloadEvent::PeerSelected { peer: p, .. }) if *p == peer(9))),
        "the adopted global peer is selected: {adopted:?}"
    );
    assert!(
        adopted.iter().any(|d| matches!(
            d,
            Decision::EndCallback { key: k } if *k == key
        )),
        "adoption cancels the callback deadline: {adopted:?}"
    );
    assert!(
        !state.is_working(peer(9)),
        "not assigned until the adopted worker's own Connected arrives"
    );

    let _ = connect(&mut state, t0(), peer(9));
    assert!(
        state.is_working(peer(9)),
        "the adopted global peer holds a part once its Connected flows the normal path"
    );
}

#[test]
fn a_lapsed_global_callback_frees_its_slot_for_the_next_candidate() {
    use rmule_primitives::PeerSource;
    // One slot, two Low-ID globals from the same server: the first callback is
    // requested; on timeout the freed slot drives a callback for the second.
    let server = source_server(9);
    let key = CallbackKey {
        server: Some(server),
        low_id: low(7),
        kad_port: None,
    };
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let first = via_global(
        &mut state,
        server,
        vec![PeerSource::new(low(7), 4662), PeerSource::new(low(8), 4662)],
    );
    assert!(
        first.iter().any(|d| matches!(
            d,
            Decision::RequestGlobalCallback { low_id, .. } if *low_id == low(7)
        )),
        "the first Low-ID global is called back: {first:?}"
    );

    let next = state.on_tick(t0() + CALLBACK_TIMEOUT);

    // The lapse retracts the routing entry (EndCallback) and the freed
    // slot drives a callback for the next candidate.
    assert!(
        next.iter().any(|d| matches!(
            d,
            Decision::EndCallback { key: k } if *k == key
        )),
        "a lapsed global callback retracts its routing entry: {next:?}"
    );
    assert!(
        next.iter().any(|d| matches!(
            d,
            Decision::RequestGlobalCallback { low_id, .. } if *low_id == low(8)
        )),
        "a lapsed global callback frees the slot for the next candidate: {next:?}"
    );
}

#[test]
fn high_id_candidates_are_preferred_over_low_id_callbacks() {
    // One slot, one of each: the reachable High-ID peer dials; the Low-ID
    // callback waits for a free slot rather than racing the dial.
    let mut state = callback_state(vec![peer(1)], vec![low_candidate(7)], true, 1);
    let decisions = state.start(t0());
    assert!(
        decisions
            .iter()
            .any(|d| matches!(d, Decision::Spawn { peer: p, .. } if *p == peer(1))),
        "the High-ID candidate dials first: {decisions:?}"
    );
    assert!(
        !decisions
            .iter()
            .any(|d| matches!(d, Decision::RequestCallback { .. })),
        "no slot left for a callback while a High-ID dial holds it"
    );
}

#[test]
fn an_adopted_callback_peer_binds_then_its_connected_event_assigns_it() {
    let mut state = callback_state(Vec::new(), vec![low_candidate(7)], true, 1);
    let _ = state.start(t0()); // requests a callback for low(7), holding slot 0
    let adopted = state
        .on_callback_connected(t0(), connected_key(low(7)), peer(9))
        .decisions;
    // Bind-without-assign: adoption selects the peer and cancels its
    // callback deadline, but assigns only on the peer's own Connected event — the
    // normal path — so the runner forwards that Connected instead of dropping it.
    assert!(
        adopted
            .iter()
            .any(|d| matches!(d, Decision::Emit(DownloadEvent::PeerSelected { peer: p, .. }) if *p == peer(9))),
        "the adopted peer is selected: {adopted:?}"
    );
    assert!(
        adopted.iter().any(|d| matches!(
            d,
            Decision::EndCallback { key } if *key == connected_key(low(7))
        )),
        "adoption cancels the callback deadline: {adopted:?}"
    );
    assert!(
        !state.is_working(peer(9)),
        "not assigned until the adopted worker's own Connected arrives"
    );

    let _ = connect(&mut state, t0(), peer(9));
    assert!(
        state.is_working(peer(9)),
        "the adopted peer holds a part once its Connected flows the normal path"
    );
}

/// A called-back peer that dials in at an endpoint a live worker already holds
/// lands on that worker: the callback's record joins it, its slot frees, and
/// the landing names no slot — so the runner never registers the surplus
/// connection over the live worker's channel.
#[test]
fn a_callback_landing_on_a_worked_endpoint_names_no_slot() {
    let mut state = callback_state(vec![peer(9)], vec![low_candidate(7)], true, 2);
    let started = state.start(t0());
    assert!(
        started
            .iter()
            .any(|d| matches!(d, Decision::RequestCallback { low_id, .. } if *low_id == low(7))),
        "the second slot calls low(7) back beside the dial: {started:?}"
    );
    let _ = connect(&mut state, t0(), peer(9));
    assert!(state.is_working(peer(9)));

    let landing = state.on_callback_connected(t0(), connected_key(low(7)), peer(9));

    assert!(
        landing.worker_slot.is_none(),
        "the surplus connection takes no slot: {landing:?}"
    );
    assert!(
        landing.decisions.iter().any(|d| matches!(
            d,
            Decision::EndCallback { key } if *key == connected_key(low(7))
        )),
        "the callback is over: {landing:?}"
    );
    assert!(
        !landing
            .decisions
            .iter()
            .any(|d| matches!(d, Decision::Emit(DownloadEvent::PeerSelected { .. }))),
        "no second worker is selected at the endpoint: {landing:?}"
    );
    assert!(state.is_working(peer(9)), "the live worker keeps its part");
}

/// ADR-0090: a called-back Low-ID source keeps its record beside its adopted
/// worker, and when that worker ends without a queue rank the record returns
/// to its Low-ID lane — its next road is a callback again, not only a fresh
/// sighting, so the download does not starve on a source it still knows.
#[test]
fn a_called_back_source_whose_worker_ends_without_a_rank_is_called_back_again() {
    let mut state = callback_state(Vec::new(), vec![low_candidate(7)], true, 1);
    let _ = state.start(t0());
    let _ = state.on_callback_connected(t0(), connected_key(low(7)), peer(9));
    let _ = connect(&mut state, t0(), peer(9));

    let ended = state.on_worker_event(t0(), peer(9), PeerWorkerEvent::Disconnected);

    assert!(
        ended
            .iter()
            .any(|d| matches!(d, Decision::RequestCallback { low_id, .. } if *low_id == low(7))),
        "the source is called back again: {ended:?}"
    );
    assert!(
        !ended.iter().any(|d| matches!(d, Decision::Fail(_))),
        "{ended:?}"
    );
}

#[test]
fn a_lapsed_callback_frees_its_slot_for_the_next_candidate() {
    // One slot, two Low-ID candidates: the first callback is requested; on
    // timeout the freed slot drives a callback for the second.
    let mut state = callback_state(
        Vec::new(),
        vec![low_candidate(7), low_candidate(8)],
        true,
        1,
    );
    let first = state.start(t0());
    assert!(
        first
            .iter()
            .any(|d| matches!(d, Decision::RequestCallback { low_id, .. } if *low_id == low(7))),
        "the first Low-ID candidate is called back: {first:?}"
    );
    let next = until_road_ends(&mut state, connected_key(low(7)));
    assert!(
        next.iter()
            .any(|d| matches!(d, Decision::RequestCallback { low_id, .. } if *low_id == low(8))),
        "a lapsed callback frees the slot for the next candidate: {next:?}"
    );
}

/// ADR-0091: a callback for a candidate that *could* be introduced arms a
/// second, twelve-second deadline beside the thirty-second one, and on its
/// fire the brain hands the candidate's facts on — intact, because nothing but
/// this record still holds them.
#[test]
fn a_callback_silent_for_twelve_seconds_falls_to_nat_traversal_with_the_records_facts() {
    let candidate =
        LowIdCandidate::from_sighting(punchable(7), None).expect("a Low-ID source is a candidate");
    let mut state = callback_state(Vec::new(), vec![punchable(7)], true, 1);
    let requested = state.start(t0());
    assert!(
        requested
            .iter()
            .any(|d| matches!(d, Decision::RequestCallback { low_id, .. } if *low_id == low(7))),
        "{requested:?}"
    );
    assert_eq!(
        state.next_wake(),
        Some(t0() + CALLBACK_SILENCE_FALLBACK),
        "a punchable candidate's 12 s fallback falls before its 30 s deadline"
    );

    let fell = state.on_tick(t0() + CALLBACK_SILENCE_FALLBACK);
    let [
        Decision::FallToNatTraversal {
            candidate: fallen,
            silence,
            ..
        },
    ] = fell.as_slice()
    else {
        panic!("the silence raises exactly one fall decision: {fell:?}");
    };
    assert_eq!(*fallen, candidate, "the record's facts travel untouched");
    assert_eq!(
        *silence,
        CallbackSilence::After {
            taken: PeerReachRoute::Server { low_id: low(7) },
            elapsed: CALLBACK_SILENCE_FALLBACK,
        }
    );
    assert!(
        !fell
            .iter()
            .any(|d| matches!(d, Decision::EndCallback { .. })),
        "the 30 s deadline stays armed — the punch is an additional attempt"
    );
}

/// A legacy candidate — one no coordinator could introduce us to — arms
/// nothing extra and waits out its thirty seconds exactly as before. A global
/// source is the shape that can be one: its server is not ours to ask.
#[test]
fn a_legacy_candidate_arms_no_fallback_and_lapses_at_its_own_deadline() {
    use rmule_primitives::PeerSource;
    let server = source_server(9);
    let key = CallbackKey {
        server: Some(server),
        low_id: low(7),
        kad_port: None,
    };
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let requested = via_global(&mut state, server, vec![PeerSource::new(low(7), 4662)]);
    assert!(
        requested
            .iter()
            .any(|d| matches!(d, Decision::RequestGlobalCallback { .. })),
        "{requested:?}"
    );
    assert_eq!(
        state.next_wake(),
        Some(t0() + CALLBACK_TIMEOUT),
        "no coordinator can introduce us, so nothing fires at 12 s"
    );

    // And the lapse it does have behaves exactly as it did before rung 1.
    let lapsed = state.on_tick(t0() + CALLBACK_TIMEOUT);
    assert!(
        lapsed
            .iter()
            .any(|d| matches!(d, Decision::EndCallback { key: k } if *k == key)),
        "the lapse retracts its routing entry: {lapsed:?}"
    );
}

/// A callback that lands before the twelve seconds are up leaves nothing to
/// fall back from: adoption ends the road and both its deadlines with it.
#[test]
fn a_callback_that_lands_first_emits_no_fallback() {
    let mut state = callback_state(Vec::new(), vec![punchable(7)], true, 1);
    let _ = state.start(t0());
    let adopted = state
        .on_callback_connected(t0(), connected_key(low(7)), peer(9))
        .decisions;
    assert!(
        adopted.iter().any(|d| matches!(
            d,
            Decision::EndCallback { key } if *key == connected_key(low(7))
        )),
        "adoption ends the callback: {adopted:?}"
    );
    assert!(
        state.on_tick(t0() + CALLBACK_SILENCE_FALLBACK).is_empty(),
        "an adopted callback has nothing to fall back from"
    );
    assert_eq!(
        state.next_wake(),
        Some(t0() + FILE_REASK_TIME),
        "no deadline is left"
    );
}

/// ADR-0091: the **Traversal Attempt** the fallback began has
/// retired, and the news reaches the brain well inside the callback's own
/// thirty seconds.
///
/// What ends is the punch road and only the punch road. The claim is
/// retracted — no Tunnel will ever be dialed toward that target for this
/// callback, and a claim left standing holds the one entry that hash has in a
/// table another download may want — while the slot, the 30 s deadline and the
/// routing entry stay exactly where they were, because the server may still
/// relay the invitation it was asked for.
#[test]
fn a_retired_traversal_marks_the_source_unreachable_without_ending_its_callback() {
    let mut state = callback_state(Vec::new(), vec![punchable(7)], true, 1);
    let _ = state.start(t0());
    let key = connected_key(low(7));
    assert!(!state.on_tick(t0() + CALLBACK_SILENCE_FALLBACK).is_empty());

    let reason = crate::diagnostics::NattRetirement::ServerRefused(
        rmule_ed2k::HolepunchFailReason::TargetNoUdp,
    );
    let retired = state.on_traversal_retired(t0(), key, reason);
    assert!(
        matches!(
            retired.as_slice(),
            [Decision::RetractTunnelClaim { key: held }] if *held == key
        ),
        "the claim goes and nothing else does: {retired:?}"
    );

    assert!(
        state.on_traversal_retired(t0(), key, reason).is_empty(),
        "the source is already marked; a second retirement retracts nothing"
    );

    // The callback itself is untouched: its own deadline still releases the
    // slot and refills, which is the one path that ever did.
    let lapsed = state.on_tick(t0() + CALLBACK_TIMEOUT);
    assert!(
        lapsed
            .iter()
            .any(|d| matches!(d, Decision::EndCallback { key: held } if *held == key)),
        "the 30 s deadline still governs the callback: {lapsed:?}"
    );
}

/// The same news on the *other* road. A Low-ID downloader's
/// candidate had no callback behind it, so a traversal that retired — here
/// because nothing could be asked at all: our position offers no live server
/// punch and the candidate names no buddy — leaves it with nothing. The
/// candidate lapses at once rather than holding its slot for the thirty seconds
/// it would take to learn the same thing, and a download with no candidate left
/// fails `NoUsableSources` there and then.
#[test]
fn a_punch_that_was_the_only_road_ends_the_candidate_when_it_retires() {
    let mut state = callback_state(
        Vec::new(),
        vec![low_candidate(7), low_candidate(8)],
        false,
        1,
    );
    let _ = state.start(t0());
    let reason = crate::diagnostics::NattRetirement::NoCoordinator;

    // The first candidate's slot goes to the second, which takes the same road.
    let retired = state.on_traversal_retired(t0(), connected_key(low(7)), reason);
    assert!(
        retired.iter().any(|d| matches!(
            d,
            Decision::EndCallback { key } if *key == connected_key(low(7))
        )),
        "the candidate's one road ended, so the callback key ends with it: {retired:?}"
    );
    assert!(
        !retired
            .iter()
            .any(|d| matches!(d, Decision::RetractTunnelClaim { .. })),
        "the cancel already retracts the claim; a second retraction is not a decision: {retired:?}"
    );
    assert!(
        retired.iter().any(|d| matches!(
            d,
            Decision::FallToNatTraversal { candidate, .. } if candidate.low_id == low(8)
        )),
        "the released slot punches the next candidate: {retired:?}"
    );
    assert!(
        !retired
            .iter()
            .any(|d| matches!(d, Decision::Fail(DownloadFailure::NoUsableSources))),
        "a candidate still remains, so nothing fails yet: {retired:?}"
    );

    // With the last candidate gone there is nothing left to admit.
    let last = state.on_traversal_retired(t0(), connected_key(low(8)), reason);
    assert!(
        last.iter()
            .any(|d| matches!(d, Decision::Fail(DownloadFailure::NoUsableSources))),
        "no road, no candidate, no wait: {last:?}"
    );
    assert!(
        state
            .on_traversal_retired(t0(), connected_key(low(8)), reason)
            .is_empty(),
        "the candidate is gone; a second retirement ends nothing twice"
    );
}
