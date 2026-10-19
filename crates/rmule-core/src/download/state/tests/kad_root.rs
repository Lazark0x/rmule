//! The Kad leg of the root authority (ADR-0038): a Qualified Kad Root is
//! trusted from the start and stays open to the peer vote, which leaves the
//! download rootless, durably and in the Run Log, when it commits another
//! root; a link's `h=` ranks above both and closes the vote.

use super::*;
use crate::KadAichRoot;
use crate::download::state::AichRootAuthority;

const LINK_ROOT: AichRootHash = AichRootHash::from_bytes([0x11; AichRootHash::BYTE_LEN]);
const KAD_ROOT: AichRootHash = AichRootHash::from_bytes([0xA1; AichRootHash::BYTE_LEN]);
const VOTED_ROOT: AichRootHash = AichRootHash::from_bytes([0xB2; AichRootHash::BYTE_LEN]);

/// A started one-part download under the authority its link's `h=` and its
/// record's Kad root give it.
fn started(link: Option<AichRootHash>, kad: Option<KadAichRoot>) -> DownloadState {
    let mut state = pooled_state(
        ContentFacts {
            aich_root: AichRootAuthority::at_start(link, kad),
            ..file_hash_only_content(ONE_PART)
        },
        &[peer(1)],
        QUIET_POSTURE,
        1,
    );
    let _ = state.start(t0());
    state
}

/// Ten distinct voters propose `root` (`peer(1..=10)` mask to ten IPs).
fn vote(state: &mut DownloadState, root: AichRootHash) -> Vec<Decision> {
    (1..=10)
        .flat_map(|n| {
            state.on_worker_event(
                t0(),
                peer(n),
                PeerWorkerEvent::AichFileHashReceived { root },
            )
        })
        .collect()
}

fn asks_for_roots(decisions: &[Decision]) -> bool {
    sent(decisions)
        .iter()
        .any(|(_, command)| *command == PeerWorkerCommand::RequestAichFileHash)
}

#[test]
fn a_kad_root_is_trusted_from_the_start_and_the_vote_still_asks() {
    let mut state = started(None, Some(KadAichRoot::Trusted(KAD_ROOT)));

    assert_eq!(state.trusted_aich_root(), Some(KAD_ROOT));
    assert!(asks_for_roots(&connect(&mut state, t0(), peer(1))));
}

#[test]
fn a_vote_naming_another_root_leaves_the_download_rootless_and_says_so() {
    let mut state = started(None, Some(KadAichRoot::Trusted(KAD_ROOT)));

    let decisions = vote(&mut state, VOTED_ROOT);

    assert_eq!(state.trusted_aich_root(), None);
    assert!(
        decisions
            .iter()
            .any(|d| matches!(d, Decision::ContestKadAichRoot)),
        "the contest is kept with the download: {decisions:?}"
    );
    assert!(
        decisions.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::KadAichRootContested {
                kad_root: KAD_ROOT,
                voted_root: VOTED_ROOT,
                ..
            })
        )),
        "the Run Log hears why: {decisions:?}"
    );
    let _ = vote(&mut state, VOTED_ROOT);
    assert_eq!(
        state.trusted_aich_root(),
        None,
        "the vote is over; its root is not trusted either"
    );
}

#[test]
fn a_vote_agreeing_with_the_kad_root_keeps_it() {
    let mut state = started(None, Some(KadAichRoot::Trusted(KAD_ROOT)));

    let decisions = vote(&mut state, KAD_ROOT);

    assert_eq!(state.trusted_aich_root(), Some(KAD_ROOT));
    assert!(
        !decisions
            .iter()
            .any(|d| matches!(d, Decision::ContestKadAichRoot | Decision::Emit(_))),
        "{decisions:?}"
    );
}

#[test]
fn a_link_root_beats_a_kad_root_and_closes_the_vote() {
    let mut state = started(Some(LINK_ROOT), Some(KadAichRoot::Trusted(KAD_ROOT)));

    assert_eq!(state.trusted_aich_root(), Some(LINK_ROOT));
    assert!(!asks_for_roots(&connect(&mut state, t0(), peer(1))));
    let _ = vote(&mut state, KAD_ROOT);
    assert_eq!(state.trusted_aich_root(), Some(LINK_ROOT));
}

#[test]
fn a_contested_record_starts_rootless_with_the_vote_closed() {
    let mut state = started(None, Some(KadAichRoot::Contested));

    assert_eq!(state.trusted_aich_root(), None);
    assert!(!asks_for_roots(&connect(&mut state, t0(), peer(1))));
    let _ = vote(&mut state, VOTED_ROOT);
    assert_eq!(state.trusted_aich_root(), None);
}
