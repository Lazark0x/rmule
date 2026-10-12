//! ADR-0061's route 4 driven by a download: the classic **buddy
//! callback**. A callback-capable downloader asks a firewalled Kad publisher's
//! buddy to relay a `0x52`, and the publisher dials us back — the road aMule
//! takes for every buddy row it decodes (`CUpDownClient::TryToConnect`,
//! `BaseClient.cpp:2114-2172` at the pinned tree), with no connect-options bit
//! consulted. The punch is the fallback beside it, never ahead of it.

use rmule_kad::KadId;
use rmule_peer::natt::CALLBACK_SILENCE_FALLBACK;
use rmule_primitives::UserHash;

use crate::callback::{CallbackSilence, RoutePosition, callback_target, select_natt_for_download};
use crate::service::PeerReachRoute;

use super::*;

const TARGET: UserHash = UserHash::from_bytes([0xAB; UserHash::BYTE_LEN]);
const BUDDY_ID: KadId = KadId::from_bytes([0x7A; KadId::BYTE_LEN]);

fn buddy_udp() -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000)
}

/// A decoded type-3 row. `0x00` is what the captured aMule `0x44` carried in
/// its `TAG_ENCRYPTION`; `0x81` is eMuleAI's, NAT-T bit set.
pub(super) fn row(connect_options: u8) -> SourceSighting {
    kad_buddy_sighting(Some(TARGET), BUDDY_ID, Some(buddy_udp()), connect_options)
}

/// A type-6 row for the target [`row`] names, observed at the address
/// [`kad_buddy_sighting`] names: the publisher's direct-UDP callback.
fn direct_row(connect_options: u8) -> SourceSighting {
    SourceSighting::by_road(
        rmule_primitives::SourceRoad::DirectUdpCallback {
            kad_udp: Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 77), 4672),
            tcp_port: 4662,
        },
        Some(TARGET),
        Some(rmule_primitives::SourceCryptOptions::from_byte(
            connect_options,
        )),
    )
}

/// A capable downloader that has seen one publisher in a buddy row and in a
/// type-6 row: the two rows name one record, which states the type-6 fact and
/// still carries the buddy. Answers the record the type-6 row makes.
fn direct_and_buddy_state(connect_options: u8) -> (DownloadState, LowIdCandidate) {
    let state = callback_state(
        Vec::new(),
        vec![row(connect_options), direct_row(connect_options)],
        true,
        1,
    );
    let candidate = LowIdCandidate::from_sighting(direct_row(connect_options), None)
        .expect("a type-6 row is a candidate");
    (state, candidate)
}

pub(super) fn buddy_key(decisions: &[Decision]) -> CallbackKey {
    decisions
        .iter()
        .find_map(|d| match d {
            Decision::RequestBuddyCallback { candidate, .. } => Some(candidate.key()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("a buddy callback was requested: {decisions:?}"))
}

/// The headline case: an aMule buddy row — no NAT-T bit, crypt byte zero —
/// is no longer dropped. A capable downloader asks its buddy for a callback and
/// holds the slot for it, and with no coordinator to fall back on it arms only
/// the thirty seconds.
#[test]
fn a_capable_downloader_asks_an_amule_rows_buddy_for_a_callback() {
    let mut state = callback_state(Vec::new(), Vec::new(), true, 2);

    let decisions = via_kad(&mut state, vec![row(0x00)]);

    let key = buddy_key(&decisions);
    let Some(Decision::RequestBuddyCallback { candidate, .. }) = decisions
        .iter()
        .find(|d| matches!(d, Decision::RequestBuddyCallback { .. }))
    else {
        unreachable!()
    };
    assert_eq!(
        candidate.user_hash,
        Some(TARGET),
        "the dial-back is matched by it"
    );
    assert_eq!(
        candidate
            .buddy
            .map(|buddy| (buddy.buddy_id, buddy.buddy_udp)),
        Some((BUDDY_ID, Some(buddy_udp())))
    );
    assert!(
        state.match_inbound_callback(key).is_some(),
        "the slot is held"
    );
    assert_eq!(
        state.next_wake(),
        Some(t0() + CALLBACK_TIMEOUT),
        "held for the dial-back, with no silence to fall back from"
    );
    assert!(
        !decisions.iter().any(|d| matches!(
            d,
            Decision::FallToNatTraversal { .. }
                | Decision::RequestCallback { .. }
                | Decision::RequestGlobalCallback { .. }
        )),
        "no server is asked and nothing can punch an aMule row: {decisions:?}"
    );
}

/// An eMuleAI row takes the same road first — aMule reaches the punch only
/// under `!CanDoCallback` — and keeps the punch as the fallback: twelve silent
/// seconds hand the selector a *buddy* callback to fall back from, and the
/// selector names the same buddy as the coordinator.
#[test]
fn an_emuleai_rows_buddy_callback_falls_to_the_punch_after_twelve_silent_seconds() {
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let decisions = via_kad(&mut state, vec![row(0x81)]);
    let _ = buddy_key(&decisions);
    assert_eq!(
        state.next_wake(),
        Some(t0() + CALLBACK_SILENCE_FALLBACK),
        "a NAT-T row's fallback falls before its 30 s"
    );
    assert!(
        !decisions
            .iter()
            .any(|d| matches!(d, Decision::FallToNatTraversal { .. })),
        "the punch is not the first road for a capable downloader: {decisions:?}"
    );

    let fell = state.on_tick(t0() + CALLBACK_SILENCE_FALLBACK);
    let [
        Decision::FallToNatTraversal {
            candidate, silence, ..
        },
    ] = fell.as_slice()
    else {
        panic!("the silence raises exactly one fall decision: {fell:?}");
    };
    assert_eq!(
        *silence,
        CallbackSilence::After {
            taken: PeerReachRoute::Buddy {
                buddy_id: BUDDY_ID,
                emitted_to: Some(buddy_udp()),
            },
            elapsed: CALLBACK_SILENCE_FALLBACK,
        }
    );
    let ours = RoutePosition {
        reachable: true,
        udp_on: true,
        kad_running: true,
        dial: crate::dialable::DialPosition::default(),
        server_punch: false,
    };
    assert_eq!(
        select_natt_for_download(&callback_target(&candidate.reach(None)), &ours, silence),
        Some(PeerReachRoute::NatTraversal {
            buddy_id: BUDDY_ID,
            buddy_udp: buddy_udp(),
        })
    );
}

/// The punch beside a buddy callback retiring ends nothing: the dial-back is
/// still expected, and the claim it will be adopted through is the same entry
/// the punch was claimed under — so it is not retracted either. Only the 30 s
/// releases the slot.
#[test]
fn a_retired_punch_beside_a_buddy_callback_leaves_the_dial_back_standing() {
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let key = buddy_key(&via_kad(&mut state, vec![row(0x81)]));
    assert!(!state.on_tick(t0() + CALLBACK_SILENCE_FALLBACK).is_empty());

    let retired =
        state.on_traversal_retired(t0(), key, crate::diagnostics::NattRetirement::NoCoordinator);
    assert!(
        retired.is_empty(),
        "the dial-back's claim stays: {retired:?}"
    );
    assert!(
        state.on_tick(t0() + CALLBACK_SILENCE_FALLBACK).is_empty(),
        "no second punch after the first retired"
    );
    assert!(
        state
            .on_tick(t0() + CALLBACK_TIMEOUT)
            .iter()
            .any(|d| matches!(d, Decision::EndCallback { key: held } if *held == key)),
        "the slot-release deadline still ends it"
    );
}

/// The road needs both halves. A downloader that cannot be dialed back leaves
/// an aMule row roadless, exactly as aMule declines LowID→LowID; and a row with
/// no User Hash has nothing its dial-back could be matched by.
#[test]
fn a_buddy_callback_needs_a_callable_downloader_and_a_user_hash() {
    let mut firewalled = callback_state(Vec::new(), Vec::new(), false, 2);
    assert!(
        via_kad(&mut firewalled, vec![row(0x00)]).is_empty(),
        "a Low-ID downloader cannot be called back"
    );

    let mut anonymous = callback_state(Vec::new(), Vec::new(), true, 2);
    let decisions = via_kad(
        &mut anonymous,
        vec![kad_buddy_sighting(None, BUDDY_ID, Some(buddy_udp()), 0x00)],
    );
    assert!(
        decisions.is_empty(),
        "a dial-back from an unnamed publisher could never be adopted: {decisions:?}"
    );
}

/// The ordering leg: a row that states **both** the type-6 fact
/// and a buddy takes the direct-UDP road first — aMule tries `0x95` at
/// `BaseClient.cpp:2043`, before either callback at `:2114`. Bit 3 alone,
/// with no type-6 verdict, is not enough —
/// `candidate.rs`'s `a_kad_buddy_row_admits_its_buddy_as_the_coordinator_and_no_server`
/// covers that row falling to the buddy instead.
#[test]
fn a_row_with_the_direct_callback_bit_takes_it_ahead_of_its_own_buddy() {
    let (mut state, target_row) = direct_and_buddy_state(0x89);

    let decisions = state.start(t0());

    let Some(candidate) = decisions.iter().find_map(|d| match d {
        Decision::RequestDirectUdpCallback { candidate, .. } => Some(candidate),
        _ => None,
    }) else {
        panic!("the direct-UDP road is taken, not the buddy's: {decisions:?}");
    };
    assert_eq!(candidate.kad_udp, target_row.kad_udp);
    assert_eq!(candidate.user_hash, Some(TARGET));
    assert!(
        !decisions
            .iter()
            .any(|d| matches!(d, Decision::RequestBuddyCallback { .. })),
        "the buddy is not asked while the row's own invitation stands: {decisions:?}"
    );
}

/// The direct-UDP road's silence-fallback: twelve silent seconds hand the
/// selector a *direct-UDP* callback to fall back from, exactly as the buddy
/// road's does for its own taken route — and the selector still names the
/// row's buddy as the coordinator, since the direct-UDP road names a target,
/// not a coordinator of its own.
#[test]
fn a_direct_udp_callback_falls_to_the_punch_after_twelve_silent_seconds() {
    let (mut state, target_row) = direct_and_buddy_state(0x89);
    let decisions = state.start(t0());
    assert!(
        decisions
            .iter()
            .any(|d| matches!(d, Decision::RequestDirectUdpCallback { .. })),
        "a direct-UDP callback was requested: {decisions:?}"
    );
    assert_eq!(
        state.next_wake(),
        Some(t0() + CALLBACK_SILENCE_FALLBACK),
        "a NAT-T row's fallback falls before its 30 s"
    );

    let fell = state.on_tick(t0() + CALLBACK_SILENCE_FALLBACK);
    let [
        Decision::FallToNatTraversal {
            candidate, silence, ..
        },
    ] = fell.as_slice()
    else {
        panic!("the silence raises exactly one fall decision: {fell:?}");
    };
    assert_eq!(
        *silence,
        CallbackSilence::After {
            taken: PeerReachRoute::DirectUdp {
                target_kad_udp: target_row.kad_udp.expect("the row names one"),
            },
            elapsed: CALLBACK_SILENCE_FALLBACK,
        }
    );
    let ours = RoutePosition {
        reachable: true,
        udp_on: true,
        kad_running: true,
        dial: crate::dialable::DialPosition::default(),
        server_punch: false,
    };
    assert_eq!(
        select_natt_for_download(&callback_target(&candidate.reach(None)), &ours, silence),
        Some(PeerReachRoute::NatTraversal {
            buddy_id: BUDDY_ID,
            buddy_udp: buddy_udp(),
        })
    );
}

/// The punch beside a direct-UDP callback retiring ends nothing, exactly as it
/// leaves a buddy callback's dial-back standing (both share the one claim,
/// keyed by the row's User Hash): only the 30 s slot-release deadline governs
/// the candidate from here.
#[test]
fn a_retired_punch_beside_a_direct_udp_callback_leaves_the_dial_back_standing() {
    let (mut state, _) = direct_and_buddy_state(0x89);
    let key = state
        .start(t0())
        .iter()
        .find_map(|d| match d {
            Decision::RequestDirectUdpCallback { candidate, .. } => Some(candidate.key()),
            _ => None,
        })
        .expect("a direct-UDP callback was requested");
    assert!(!state.on_tick(t0() + CALLBACK_SILENCE_FALLBACK).is_empty());

    let retired =
        state.on_traversal_retired(t0(), key, crate::diagnostics::NattRetirement::NoCoordinator);
    assert!(
        retired.is_empty(),
        "the dial-back's claim stays: {retired:?}"
    );
}

/// A direct-UDP `0x95` that never left ends its road
/// the way a buddy callback that never left does — the row falls to the
/// punch now, rather than holding its slot for thirty seconds of silence
/// from a target that was never invited.
#[test]
fn a_direct_udp_callback_that_never_left_falls_to_the_punch_now() {
    let (mut state, _) = direct_and_buddy_state(0x89);
    let key = state
        .start(t0())
        .iter()
        .find_map(|d| match d {
            Decision::RequestDirectUdpCallback { candidate, .. } => Some(candidate.key()),
            _ => None,
        })
        .expect("a direct-UDP callback was requested");

    let retired = state.on_traversal_retired(
        t0(),
        key,
        crate::diagnostics::NattRetirement::CallbackNotSent,
    );
    assert!(
        matches!(
            retired.as_slice(),
            [Decision::FallToNatTraversal {
                silence: CallbackSilence::NoCallbackPossible,
                ..
            },]
        ),
        "the unsent invitation's road ends and the punch is the road now: {retired:?}"
    );
}
