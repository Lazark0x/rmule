//! An uploader's grant on a link of its own (ADR-0057, "A grant by dial-back
//! is taken"): a source waiting in the RemoteQueued stage is promoted by its
//! uploader dialing us back, and its worker opens on that link at once.

use super::*;

fn spawned(decisions: &[Decision]) -> Vec<(PeerEndpoint, usize)> {
    decisions
        .iter()
        .filter_map(|d| match d {
            Decision::Spawn { peer, slot, .. } => Some((*peer, slot.as_usize())),
            _ => None,
        })
        .collect()
}

/// The grant opens the queued source's worker on a slot of its own while
/// the one slot the cap allows works another source — a granted slot is a
/// transfer, not a dial (ADR-0030) — and says so; a second grant for a
/// source already working, or one for an endpoint nobody waits at, opens
/// nothing.
#[test]
fn a_grant_by_dial_back_opens_the_queued_sources_worker_past_the_cap() {
    let mut state = pooled_state(
        file_hash_only_content(ONE_PART),
        &[peer(1), peer(2)],
        live_posture(),
        1,
    );
    let _ = state.start(t0());
    queue_and_hang_up(&mut state, peer(1), true, 5);
    let later = t0() + Duration::from_secs(90);
    let _ = connect(&mut state, later, peer(2));

    let granted = state.on_slot_offered(later, peer(1));
    assert!(
        granted.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::SlotOffered { peer: p, .. }) if *p == peer(1)
        )),
        "{granted:?}"
    );
    assert_eq!(
        spawned(&granted),
        [(peer(1), 1)],
        "past the cap of one, on a slot of its own"
    );
    assert!(state.on_slot_offered(later, peer(1)).is_empty());
    assert!(state.on_slot_offered(later, peer(3)).is_empty());
}

/// A grant with a slot free takes that slot rather than one past the cap.
#[test]
fn a_grant_with_a_slot_free_takes_it() {
    let mut state = standing();
    let granted = state.on_slot_offered(t0() + Duration::from_secs(90), peer(1));
    assert_eq!(spawned(&granted), [(peer(1), 0)]);
}
