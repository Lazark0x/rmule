//! Buddy link loss and reachability release, and refused and
//! refused-before-dial buddies.

use super::*;

/// The buddy hangs up: the slot empties, the link is counted lost, and the
/// loss is published — what the Kad pump's recruit rule reads to walk again
/// at once.
#[tokio::test(start_paused = true)]
async fn losing_the_link_empties_the_slot_and_publishes_the_loss() {
    let mut h = quiet_harness();
    let side = h.hold().await;

    side.send(PeerEvent::Connection(ConnectionEvent::Disconnected {
        reason: rmule_peer::PeerCloseReason::PeerClosed,
    }))
    .await;
    settle().await;
    let snapshot = h.buddy.snapshot();
    assert_eq!(snapshot.state, BuddyState::None);
    assert!(snapshot.lost_at.is_some(), "the loss arms an instant walk");
    assert_eq!(snapshot.publish, None);
    assert_eq!(h.diagnostics.snapshot().session.buddy_links_lost_total, 1);
}

/// An open Kad TCP verdict releases the held buddy and shuts its link — an
/// open node needs none — and a buddy adopted while the verdict reads open
/// is let go undialed.
#[tokio::test(start_paused = true)]
async fn an_open_kad_tcp_verdict_releases_the_buddy_and_dials_no_new_one() {
    let mut h = quiet_harness();
    let mut side = h.hold().await;

    h.kad.set_tcp(crate::reachability::TcpReachability::Open);
    settle().await;
    assert!(side.is_shut());
    assert_eq!(h.buddy.snapshot().state, BuddyState::None);

    assert_eq!(h.adopt(a_buddy()).await.outcome, AdoptOutcome::Adopted);
    settle().await;
    assert!(
        h.dials.try_recv().is_err(),
        "no dial for a buddy an open node lets go"
    );
    assert_eq!(h.buddy.snapshot().state, BuddyState::None);
}

/// A buddy whose dial is refused: the failure is reported with its cause and
/// the buddy's address — the only trace of why no link was held — counted,
/// and the slot freed with the loss published.
#[tokio::test(start_paused = true)]
async fn a_refused_buddy_dial_is_reported_with_its_cause() {
    let mut h = quiet_harness();
    h.kad_started();
    h.adopt(a_buddy()).await;
    let refused = BuddyDialFailure::Dial {
        cause: DialFailure::Os {
            kind: std::io::ErrorKind::ConnectionRefused,
            os_code: None,
        },
    };
    h.next_dial().await.fail(refused);

    let event = within("the failure report", h.events.recv()).await;
    assert!(
        matches!(
            &event,
            crate::CoreEvent::BuddyDialFailed { buddy, cause }
                if *buddy == a_buddy().tcp && *cause == refused
        ),
        "{event:?}"
    );
    settle().await;
    assert_eq!(h.diagnostics.snapshot().session.buddy_dials_failed_total, 1);
    let snapshot = h.buddy.snapshot();
    assert_eq!(snapshot.state, BuddyState::None);
    assert!(snapshot.lost_at.is_some());
}

/// The node that answered the dial is not the one the `0x5A` named: aMule
/// keys its buddy by hash, so that link could never carry a relay the `0x99`
/// check would accept. It is shut and reported a stranger.
#[tokio::test(start_paused = true)]
async fn a_dial_answered_by_a_stranger_is_shut_and_reported() {
    let mut h = quiet_harness();
    h.kad_started();
    h.adopt(a_buddy()).await;
    let mut side = h
        .next_dial()
        .await
        .answer_as(UserHash::from_bytes([0x99; UserHash::BYTE_LEN]), None);

    let event = within("the failure report", h.events.recv()).await;
    assert!(matches!(
        event,
        crate::CoreEvent::BuddyDialFailed {
            cause: BuddyDialFailure::Stranger,
            ..
        }
    ));
    assert!(side.is_shut());
    assert_eq!(h.buddy.snapshot().state, BuddyState::None);
}

/// A buddy whose `0x5A` *requires* the crypt layer (`0x07`), met by a node
/// whose layer is off, is refused unseated and never dialled — aMule seats
/// the byte (`ClientList.cpp:1144`) and its `CheckContactPreconditions` then
/// deletes the client (`BaseClient.cpp:1913-1919`) — and counted beside the
/// other buddy-dial refusals. A stray answer whose ID does not invert to ours
/// is rejected the same way, uncounted.
#[tokio::test(start_paused = true)]
async fn a_buddy_the_slot_refuses_is_never_dialled() {
    let mut h = quiet_harness();
    h.kad_started();
    let requiring =
        a_buddy_stating(rmule_primitives::SourceCryptOptions::from_byte(0x07).crypt_stance());
    let verdict = h.adopt(requiring).await;
    assert_eq!(verdict.outcome, AdoptOutcome::CryptIncompatible);
    assert_eq!(verdict.snapshot.state, BuddyState::None);
    assert_eq!(
        h.diagnostics
            .snapshot()
            .session
            .buddy_dials_crypt_incompatible_total,
        1
    );

    h.ask_adopt_for(a_buddy(), [0x33; 16]).await;
    let stray = within("the stray verdict", h.verdicts.recv()).await;
    assert_eq!(stray.outcome, AdoptOutcome::Rejected);
    settle().await;
    assert!(
        h.dials.try_recv().is_err(),
        "nothing seated, nothing dialled"
    );
}
