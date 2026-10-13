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
fn state_under(capability: CallbackCapability, low_ids: Vec<SourceSighting>) -> DownloadState {
    state_from(
        file_hash_only_content(ONE_PART),
        SourcingPosture {
            callback_capability: capability,
            discovery_active: true,
            ..QUIET_POSTURE
        },
        1,
        no_facts(),
        Vec::new(),
        low_ids,
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

    let decisions = via_kad(&mut state, vec![row(0x00)]);

    buddy_key(&decisions);
}

/// The carve-out: Low-ID on our server but Kad-open, a candidate on that server
/// is punched through the server, never relayed a callback by it — while a Kad
/// row, on no server, still gets its buddy's callback.
#[test]
fn a_low_id_kad_open_downloader_never_asks_its_own_server_for_a_callback() {
    let mut state = state_under(low_id_kad_open(), vec![low_candidate(9)]);

    let started = state.start(t0());
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
    buddy_key(&via_kad(&mut kad, vec![row(0x00)]));
}

/// Degradation, from aMule: a verdict that flips firewalled leaves a callback
/// already asked for alone — `DS_WAITCALLBACKKAD` waits for its answer or its
/// timeout — and only the next admission reads the new sample.
#[test]
fn a_lost_capability_keeps_the_held_slot_until_its_release_and_admits_nothing_new() {
    let mut state = state_under(kad_only_open(), Vec::new());
    let key = buddy_key(&via_kad(&mut state, vec![row(0x00)]));

    let flipped = state.on_callback_capability(t0(), CallbackCapability::of(true, None, false));
    assert!(
        flipped.is_empty(),
        "nothing is retired on the flip: {flipped:?}"
    );

    // A second aMule row arrives while the slot is held, then the slot lapses:
    // the freed slot finds no road to it, so no callback is asked for.
    let other = kad_buddy_sighting(
        Some(UserHash::from_bytes([0xCD; UserHash::BYTE_LEN])),
        rmule_kad::KadId::from_bytes([0x7A; rmule_kad::KadId::BYTE_LEN]),
        Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000)),
        0x00,
    );
    assert!(
        via_kad(&mut state, vec![other]).is_empty(),
        "the slot is held"
    );
    let lapsed = state.on_tick(t0() + CALLBACK_TIMEOUT);
    assert!(
        matches!(lapsed.first(), Some(Decision::EndCallback { key: held }) if *held == key),
        "the slot is released on its own deadline: {lapsed:?}"
    );
    assert!(!asks_for_a_callback(&lapsed), "{lapsed:?}");
}

/// The other direction, aMule's `DS_LOWTOLOWIP` re-promotion: a row no road
/// reached while we were uncallable is admitted the moment the sample turns.
#[test]
fn a_gained_capability_admits_the_row_that_was_waiting() {
    let mut state = state_under(CallbackCapability::of(true, None, false), Vec::new());
    assert!(!asks_for_a_callback(&via_kad(&mut state, vec![row(0x00)])));

    buddy_key(&state.on_callback_capability(t0(), kad_only_open()));
    assert!(
        state
            .on_callback_capability(t0(), kad_only_open())
            .is_empty(),
        "an unchanged sample decides nothing"
    );
}

/// A server High ID on `server`.
fn high_id_on(server: Ipv4Endpoint) -> CallbackCapability {
    CallbackCapability::of(
        true,
        Some(ConnectedSession {
            server: Some(server),
            client_id: ClientId::from_u32(0x0A00_0001),
        }),
        false,
    )
}

/// A low id means something only beside the server that assigned it (aMule
/// `IsLocalServer`, stock 2.3.3 `BaseClient.cpp:1530`): after a move from A to
/// B, the low id 7 A named is relayed by A, and the low id 7 B names is
/// another source, which B's own session calls back.
#[test]
fn after_a_server_move_a_low_id_is_called_back_by_the_server_that_assigned_it() {
    let server_a = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 201, 1), 4661);
    let server_b = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 201, 2), 4661);
    let low_7 = || {
        SourceSighting::plain(
            rmule_primitives::PeerSource::new(low(7), 4662),
            rmule_primitives::Informant::Own,
        )
    };
    let mut state = state_from(
        file_hash_only_content(ONE_PART),
        SourcingPosture {
            callback_capability: high_id_on(server_a),
            discovery_active: true,
            ..QUIET_POSTURE
        },
        2,
        no_facts(),
        vec![(Channel::Server, vec![low_7()])],
        Vec::new(),
    );

    let moved = state.on_callback_capability(t0(), high_id_on(server_b));
    assert!(
        moved.iter().any(|d| matches!(
            d,
            Decision::RequestGlobalCallback { low_id, source_server, .. }
                if *low_id == low(7) && *source_server == server_a
        )),
        "A's low id is relayed by A: {moved:?}"
    );

    let taken = take(&mut state, Channel::Server, [low_7()]);
    assert_eq!(taken.tally.fresh, 1, "B's low id 7 is not A's");
    assert!(
        taken.decisions.iter().any(|d| matches!(
            d,
            Decision::RequestCallback { low_id, server, .. }
                if *low_id == low(7) && *server == Some(server_b)
        )),
        "B's low id is called back over our session: {:?}",
        taken.decisions
    );
}
