//! The **Callback Capability** as the brain reads it: aMule's
//! `CanDoCallback` union, its same-server carve-out, and what a sample that
//! moves mid-run does to admission — and does not do to a callback already
//! asked for.

use rmule_primitives::ClientId;

use super::buddy_callback::{buddy_key, row};
use super::*;
use crate::own_identity::ConnectedSession;

/// Kad open, no server: aMule's "Only Kad Connected - Kad Open".
fn kad_only_open() -> CallbackCapability {
    CallbackCapability::of(true, None, true)
}

/// Logged in with a Low ID, Kad open: "Both Connected - Server lowID, Kad Open".
fn low_id_kad_open() -> CallbackCapability {
    CallbackCapability::of(
        true,
        Some(ConnectedSession {
            server: None,
            client_id: ClientId::from_u32(7),
        }),
        true,
    )
}

/// A download that waits on discovery rather than failing, starting from
/// `low_ids` under `capability`.
fn state_under(
    capability: CallbackCapability,
    low_ids: Vec<ConnectedServerCandidate>,
) -> DownloadState {
    DownloadState::new(
        DownloadId::from_u64(1),
        file_hash_only_content(ONE_PART),
        StartingCandidates {
            high_id: Vec::new(),
            peer_crypts: HashMap::new(),
            low_id: low_ids,
            distrusted: HashSet::new(),
            remembered: RememberedSeeds::default(),
        },
        SourcingPosture {
            callback_capability: capability,
            discovery_active: true,
            ..QUIET_POSTURE
        },
        CALLBACK_TIMEOUT,
        1,
    )
}

fn asks_for_a_callback(decisions: &[Decision]) -> bool {
    decisions.iter().any(|d| {
        matches!(
            d,
            Decision::RequestCallback { .. }
                | Decision::RequestGlobalCallback { .. }
                | Decision::RequestBuddyCallback { .. }
                | Decision::RequestDirectUdpCallback { .. }
        )
    })
}

/// The union's Kad half: with no server at all, an open Kad verdict is enough
/// to ask an aMule row's buddy for a callback — the road a server High ID
/// alone used to open.
#[test]
fn an_open_kad_verdict_alone_asks_a_buddy_rows_buddy_for_a_callback() {
    let mut state = state_under(kad_only_open(), Vec::new());

    let decisions = state.on_kad_sources(vec![row(0x00)]);

    buddy_key(&decisions);
}

/// The carve-out: Low-ID on our server but Kad-open, a candidate on that server
/// is punched through the server, never relayed a callback by it — while a Kad
/// row, on no server, still gets its buddy's callback.
#[test]
fn a_low_id_kad_open_downloader_never_asks_its_own_server_for_a_callback() {
    let mut state = state_under(low_id_kad_open(), vec![low_candidate(9)]);

    let started = state.start();
    assert!(
        !asks_for_a_callback(&started),
        "no callback for a candidate on our own server: {started:?}"
    );
    assert!(
        started.iter().any(|d| matches!(
            d,
            Decision::FallToNatTraversal {
                silence: CallbackSilence::NoCallbackPossible,
                ..
            }
        )),
        "the server introduces us instead: {started:?}"
    );

    let mut kad = state_under(low_id_kad_open(), Vec::new());
    buddy_key(&kad.on_kad_sources(vec![row(0x00)]));
}

/// Degradation, from aMule: a verdict that flips firewalled leaves a callback
/// already asked for alone — `DS_WAITCALLBACKKAD` waits for its answer or its
/// timeout — and only the next admission reads the new sample.
#[test]
fn a_lost_capability_keeps_the_held_slot_until_its_release_and_admits_nothing_new() {
    let mut state = state_under(kad_only_open(), Vec::new());
    let key = buddy_key(&state.on_kad_sources(vec![row(0x00)]));

    let flipped = state.on_callback_capability(CallbackCapability::of(true, None, false));
    assert!(
        flipped.is_empty(),
        "nothing is retired on the flip: {flipped:?}"
    );

    // A second aMule row arrives while the slot is held, then the slot lapses:
    // the freed slot finds no road to it, so no callback is asked for.
    let other = crate::KadSource {
        user_hash: Some(UserHash::from_bytes([0xCD; UserHash::BYTE_LEN])),
        ..row(0x00)
    };
    assert!(
        state.on_kad_sources(vec![other]).is_empty(),
        "the slot is held"
    );
    let lapsed = state.on_callback_timeout(key);
    assert!(
        matches!(lapsed.first(), Some(Decision::CancelCallbackTimeout { key: held }) if *held == key),
        "the slot is released on its own deadline: {lapsed:?}"
    );
    assert!(!asks_for_a_callback(&lapsed), "{lapsed:?}");
}

/// The other direction, aMule's `DS_LOWTOLOWIP` re-promotion: a row no road
/// reached while we were uncallable is admitted the moment the sample turns.
#[test]
fn a_gained_capability_admits_the_row_that_was_waiting() {
    let mut state = state_under(CallbackCapability::of(true, None, false), Vec::new());
    assert!(!asks_for_a_callback(&state.on_kad_sources(vec![row(0x00)])));

    buddy_key(&state.on_callback_capability(kad_only_open()));
    assert!(
        state.on_callback_capability(kad_only_open()).is_empty(),
        "an unchanged sample decides nothing"
    );
}
