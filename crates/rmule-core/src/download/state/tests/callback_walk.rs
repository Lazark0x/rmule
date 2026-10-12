//! The buddy-callback road for a Kad row that named its buddy by **ID alone**
//! No `TAG_SERVERIP`/`TAG_SERVERPORT`, or zeros — aMule reads
//! both as `0` (`Search.cpp:1175-1176`) and takes its `FINDSOURCE` branch
//! whenever either is (`BaseClient.cpp:2134`). The road is admitted exactly as
//! for a known endpoint; the **Callback Walk** is the actor's to run. What the
//! brain owns is what the walk's failure costs: the road is over, so the
//! candidate falls to the next one — the punch when its facts admit a
//! coordinator, otherwise nothing, and its slot goes to the next candidate.

use rmule_kad::KadId;
use rmule_primitives::UserHash;

use crate::callback::CallbackSilence;
use crate::diagnostics::NattRetirement;

use super::*;

const TARGET: UserHash = UserHash::from_bytes([0xAB; UserHash::BYTE_LEN]);
const BUDDY_ID: KadId = KadId::from_bytes([0x7A; KadId::BYTE_LEN]);

/// A type-3 row whose buddy tags carried the ID and no endpoint. `0x00` is an
/// aMule row's `TAG_ENCRYPTION`; `0x81` an eMuleAI row's, NAT-T bit set.
fn id_only_row(connect_options: u8) -> SourceSighting {
    kad_buddy_sighting(Some(TARGET), BUDDY_ID, None, connect_options)
}

fn admitted(state: &mut DownloadState, connect_options: u8) -> CallbackKey {
    let decisions = via_kad(state, vec![id_only_row(connect_options)]);
    let Some(candidate) = decisions.iter().find_map(|d| match d {
        Decision::RequestBuddyCallback { candidate, .. } => Some(*candidate),
        _ => None,
    }) else {
        panic!("an ID-only buddy row takes the buddy-callback road: {decisions:?}");
    };
    assert_eq!(
        candidate
            .buddy
            .map(|buddy| (buddy.buddy_id, buddy.buddy_udp)),
        Some((BUDDY_ID, None)),
        "the candidate carries the ID and admits it has no endpoint"
    );
    assert!(
        state.match_inbound_callback(candidate.key()).is_some(),
        "the slot is held for the dial-back the walk may yet draw"
    );
    candidate.key()
}

fn releases(decisions: &[Decision], key: CallbackKey) -> bool {
    decisions
        .iter()
        .any(|d| matches!(d, Decision::EndCallback { key: held } if *held == key))
}

/// An aMule row: no NAT-T bit, so no punch behind the callback. A walk that met
/// nobody near the buddy ID leaves nothing to wait for, and the slot is not
/// held for thirty seconds of it.
#[test]
fn a_fruitless_callback_walk_releases_an_amule_rows_slot_at_once() {
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let key = admitted(&mut state, 0x00);

    let retired = state.on_traversal_retired(t0(), key, NattRetirement::BuddyNotFound);

    assert!(
        releases(&retired, key),
        "the candidate lapses now: {retired:?}"
    );
    assert!(
        !retired
            .iter()
            .any(|d| matches!(d, Decision::FallToNatTraversal { .. })),
        "nothing can punch an aMule row: {retired:?}"
    );
    assert!(
        state.on_tick(t0() + CALLBACK_TIMEOUT).is_empty(),
        "the 30 s has nothing left to release"
    );
}

/// An eMuleAI row falls to the punch the moment its walk fails — there is no
/// callback left whose silence twelve seconds could measure — and the punch is
/// now its only road: its retirement ends the candidate.
#[test]
fn a_fruitless_callback_walk_falls_a_natt_row_to_the_punch_now() {
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let key = admitted(&mut state, 0x81);

    let retired = state.on_traversal_retired(t0(), key, NattRetirement::BuddyNotFound);
    let [
        Decision::FallToNatTraversal {
            candidate, silence, ..
        },
    ] = retired.as_slice()
    else {
        panic!("the walk's failure raises exactly one fall: {retired:?}");
    };
    assert_eq!(candidate.key(), key);
    assert_eq!(*silence, CallbackSilence::NoCallbackPossible);

    assert!(
        state.on_tick(t0() + CALLBACK_SILENCE_FALLBACK).is_empty(),
        "the 12 s deadline armed for the callback raises no second punch"
    );
    let ended = state.on_traversal_retired(t0(), key, NattRetirement::NoCoordinator);
    assert!(
        releases(&ended, key),
        "the punch was the last road: {ended:?}"
    );
}

/// The real end of the chain, once only stood in for by
/// `NoCoordinator`: the walk fails, falls the row to the punch, and the
/// punch's own coordinator lookup finds the same buddy still has no endpoint
/// The dialect never resolves one for `OP_REASKCALLBACKUDP`,
/// so it retires with the reason that names that fact. Two brain calls, no
/// deadline in between: the candidate ends in one step from the walk's
/// failure, never touching the 30 s or the 12 s clocks.
#[test]
fn a_fruitless_walk_then_a_coordinatorless_punch_ends_the_candidate_in_one_step() {
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let key = admitted(&mut state, 0x81);

    let fell = state.on_traversal_retired(t0(), key, NattRetirement::BuddyNotFound);
    assert!(
        matches!(
            fell.as_slice(),
            [Decision::FallToNatTraversal { candidate, .. }] if candidate.key() == key
        ),
        "the walk's failure falls the row to the punch at once: {fell:?}"
    );

    let ended = state.on_traversal_retired(t0(), key, NattRetirement::CoordinatorEndpointUnknown);
    assert!(
        releases(&ended, key),
        "the same buddy still has no endpoint, so the punch ends now: {ended:?}"
    );
    assert!(
        !ended
            .iter()
            .any(|d| matches!(d, Decision::FallToNatTraversal { .. })),
        "no coordinator is left to fall to again: {ended:?}"
    );
}

/// A walk that fails after the 12 s silence already fell to the punch starts
/// nothing more — the punch running is the road now — and that punch's
/// retirement ends the candidate rather than leaving it to the 30 s.
#[test]
fn a_callback_walk_failing_after_the_punch_began_starts_no_second_punch() {
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let key = admitted(&mut state, 0x81);
    assert!(
        !state.on_tick(t0() + CALLBACK_SILENCE_FALLBACK).is_empty(),
        "the 12 s fell"
    );

    assert!(
        state
            .on_traversal_retired(t0(), key, NattRetirement::CallbackWalkBusy)
            .is_empty(),
        "the punch already running is the candidate's road"
    );
    let ended = state.on_traversal_retired(t0(), key, NattRetirement::NoCoordinator);
    assert!(
        releases(&ended, key),
        "and its end is the candidate's: {ended:?}"
    );
}

/// A walk failing after the punch beside it already retired leaves no road at
/// all.
#[test]
fn a_callback_walk_failing_after_the_punch_retired_releases_the_slot() {
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let key = admitted(&mut state, 0x81);
    assert!(!state.on_tick(t0() + CALLBACK_SILENCE_FALLBACK).is_empty());
    assert!(
        state
            .on_traversal_retired(t0(), key, NattRetirement::NoCoordinator)
            .is_empty(),
        "beside a live callback road the punch's end costs nothing"
    );

    let retired = state.on_traversal_retired(t0(), key, NattRetirement::BuddyNotFound);
    assert!(releases(&retired, key), "{retired:?}");
}

/// The buddy-callback road asked with no Kad node running ends
/// the same way a fruitless walk does — `ends_buddy_callback()` folds the new
/// reason in beside `BuddyNotFound`/`CallbackWalkBusy`, so an eMuleAI row
/// falls to the punch at once rather than holding its slot for thirty
/// seconds.
#[test]
fn kad_not_running_falls_a_natt_row_to_the_punch_now() {
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let key = admitted(&mut state, 0x81);

    let retired = state.on_traversal_retired(t0(), key, NattRetirement::KadNotRunning);
    let [
        Decision::FallToNatTraversal {
            candidate, silence, ..
        },
    ] = retired.as_slice()
    else {
        panic!("the retirement raises exactly one fall: {retired:?}");
    };
    assert_eq!(candidate.key(), key);
    assert_eq!(*silence, CallbackSilence::NoCallbackPossible);
}

/// The aMule-row sibling of the above: no NAT-T bit, so no punch behind the
/// callback — the slot releases to the next candidate at once.
#[test]
fn kad_not_running_releases_an_amule_rows_slot_at_once() {
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let key = admitted(&mut state, 0x00);

    let retired = state.on_traversal_retired(t0(), key, NattRetirement::KadNotRunning);
    assert!(
        releases(&retired, key),
        "the candidate lapses now: {retired:?}"
    );
    assert!(
        !retired
            .iter()
            .any(|d| matches!(d, Decision::FallToNatTraversal { .. })),
        "nothing can punch an aMule row: {retired:?}"
    );
}

/// The source's own hello names its buddy's endpoint, so its next
/// buddy callback goes straight to the buddy instead of walking toward its ID
/// again — the one its record draws back in its lane when its worker ends
/// without a rank (ADR-0090), and, once that lapses, the one a later ID-only
/// row draws.
#[test]
fn a_buddy_the_hello_named_takes_the_next_callback_without_a_walk() {
    let buddy_udp = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4672);
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let key = admitted(&mut state, 0x00);
    let named_buddy = |decisions: &[Decision]| {
        decisions.iter().find_map(|d| match d {
            Decision::RequestBuddyCallback { candidate, .. } => candidate
                .buddy
                .map(|buddy| (buddy.buddy_id, buddy.buddy_udp)),
            _ => None,
        })
    };

    let _ = state.on_callback_connected(t0(), key, peer(9));
    let mut ended = Vec::new();
    let named = HelloFacts {
        serving_buddy: Some(buddy_udp),
        ..HelloFacts::of(TARGET)
    };
    for event in [
        PeerWorkerEvent::Identity(named.identity()),
        PeerWorkerEvent::Connected,
        PeerWorkerEvent::Disconnected,
    ] {
        ended = state.on_worker_event(t0(), peer(9), event);
    }
    assert_eq!(
        named_buddy(&ended),
        Some((BUDDY_ID, Some(buddy_udp))),
        "back in its lane, the source's callback goes to the hello's endpoint: {ended:?}"
    );

    let _ = state.on_tick(t0() + CALLBACK_TIMEOUT);
    let later = via_kad(&mut state, vec![id_only_row(0x00)]);
    assert_eq!(
        named_buddy(&later),
        Some((BUDDY_ID, Some(buddy_udp))),
        "the row's ID with the hello's endpoint: {later:?}"
    );
}
