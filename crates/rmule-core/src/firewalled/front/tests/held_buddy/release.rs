//! The buddy's lifecycle around a dial that runs on its own task: whatever
//! lands late — a link or a failure — acts only on the buddy it was for, and
//! a buddy the Kad-scoped mechanism cannot use is let go rather than dialed.
//! One buddy is dialed once and linked once, however often it is adopted.

use super::*;

/// A buddy adopted while Kad is down is let go, never dialed: the mechanism
/// is Kad-scoped (ADR-0061), and a link dialed now could only be torn down.
#[tokio::test(start_paused = true)]
async fn a_buddy_adopted_with_kad_down_is_released_undialed() {
    let mut h = kad_down_harness();
    h.kad_started();
    assert_eq!(h.adopt(a_buddy()).await.outcome, AdoptOutcome::Adopted);
    settle().await;
    assert!(h.dials.try_recv().is_err());
    assert_eq!(h.buddy.snapshot().state, BuddyState::None);
}

/// Kad stopping lets the held buddy go **at once**: the front awaits Kad
/// Presence's change rather than noticing it on a tick, so the link is shut
/// with the clock quiet. A relay could never reach a node with no Kad.
#[tokio::test(start_paused = true)]
async fn kad_stopping_releases_the_held_buddy_without_waiting_for_a_tick() {
    let mut h = quiet_harness();
    let mut side = h.hold().await;

    drop(h.kad_lease.take());
    settle().await;
    assert!(side.is_shut());
    assert_eq!(h.buddy.snapshot().state, BuddyState::None);
    assert_eq!(h.diagnostics.snapshot().session.buddy_links_lost_total, 1);
}

/// A buddy dial that lands after its buddy was let go is shut, never held:
/// the dial runs on its own task, so an open Kad TCP verdict can release the
/// buddy while it is still in flight.
#[tokio::test(start_paused = true)]
async fn a_buddy_dial_landing_after_the_release_is_shut_not_held() {
    let mut h = quiet_harness();
    h.kad_started();
    h.adopt(a_buddy()).await;
    let dial = h.next_dial().await;

    h.kad.set_tcp(crate::reachability::TcpReachability::Open);
    settle().await;
    assert_eq!(h.buddy.snapshot().state, BuddyState::None);

    let mut side = dial.answer_as(buddy_hash(), None);
    settle().await;
    assert!(side.is_shut(), "the late link is shut");
    assert_eq!(
        h.buddy.snapshot().state,
        BuddyState::None,
        "nothing is held for a buddy that is gone"
    );
}

/// A buddy dial that fails after its buddy was let go and **another adopted**
/// frees nothing: the failure is the first buddy's, and the slot is no
/// longer its to free.
#[tokio::test(start_paused = true)]
async fn a_late_failed_dial_leaves_the_buddy_adopted_since() {
    let mut h = quiet_harness();
    h.kad_started();
    h.adopt(a_buddy()).await;
    let first = h.next_dial().await;

    // With the dial in flight, the first buddy is released (we turned
    // reachable), the verdict closes again, and a later walk adopts a second.
    h.kad.set_tcp(crate::reachability::TcpReachability::Open);
    settle().await;
    assert_eq!(h.buddy.snapshot().state, BuddyState::None);
    h.kad
        .set_tcp(crate::reachability::TcpReachability::Firewalled);
    let second = RecruitedBuddy {
        udp: Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 8), 4672),
        tcp: Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 8), 4662),
        ..a_buddy()
    };
    assert_eq!(h.adopt(second).await.outcome, AdoptOutcome::Adopted);
    let _second_dial = h.next_dial().await;

    first.fail(BuddyDialFailure::HelloIncomplete);
    settle().await;
    assert_eq!(h.diagnostics.snapshot().session.buddy_dials_failed_total, 1);
    let snapshot = h.buddy.snapshot();
    assert_eq!(
        snapshot.state,
        BuddyState::Recruited,
        "the first buddy's failure leaves the second buddy in the slot"
    );
    assert_eq!(
        snapshot.publish.map(|publish| publish.buddy_udp),
        Some(second.udp)
    );
}

/// A second adopt while the dial to that buddy is in flight starts no second
/// dial — a re-adopt, or a duplicate `0x5A`. Both dials would land `Held` on
/// the same buddy, and the second would replace the first link.
#[tokio::test(start_paused = true)]
async fn a_second_adopt_mid_dial_dials_once_and_holds_one_link() {
    let mut h = quiet_harness();
    h.kad_started();
    h.adopt(a_buddy()).await;
    let dial = h.next_dial().await;

    assert_eq!(h.adopt(a_buddy()).await.outcome, AdoptOutcome::Adopted);
    settle().await;
    assert_eq!(
        h.diagnostics.snapshot().session.buddy_dials_refused_total,
        1
    );
    assert!(h.dials.try_recv().is_err(), "one dial per buddy in flight");

    let mut side = dial.answer_as(buddy_hash(), None);
    settle().await;
    assert_eq!(h.buddy.snapshot().state, BuddyState::Held);
    let session = h.diagnostics.snapshot().session;
    assert_eq!(session.buddy_links_held_total, 1);
    assert_eq!(session.buddy_dials_failed_total, 0);

    // The one link is the one held: letting the buddy go shuts it.
    drop(h.kad_lease.take());
    settle().await;
    assert!(side.is_shut());
}

/// A Kad restart re-seats the slot against the new node's ID: whatever the
/// last node held is let go, and a `0x5A` verified against the old ID says
/// nothing about the new one.
#[tokio::test(start_paused = true)]
async fn a_kad_restart_re_seats_the_slot_against_the_new_nodes_id() {
    let mut h = quiet_harness();
    let mut side = h.hold().await;

    h.kad_started_as([0x33; 16]);
    settle().await;
    assert!(side.is_shut());
    assert_eq!(
        h.buddy.snapshot(),
        crate::firewalled::link::BuddySnapshot::default()
    );
    assert_eq!(h.adopt(a_buddy()).await.outcome, AdoptOutcome::Rejected);
    h.ask_adopt_for(a_buddy(), [0x33; 16]).await;
    assert_eq!(
        within("the verdict", h.verdicts.recv()).await.outcome,
        AdoptOutcome::Adopted
    );
}

/// A Kad start reaches the front however full its inbox is. Datagram-rate
/// commands (here standalone rendezvous from a stranger) fill the inbox before
/// the front has run at all; the start still lands, so the next node's `0x5A`
/// verifies against its own ID and the dial reads its hello.
#[tokio::test(start_paused = true)]
async fn a_kad_start_lands_however_full_the_inbox_is() {
    let mut h = quiet_harness();
    let stranger = || FirewalledCommand::StandaloneRendezvous {
        from: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 99), 4672)),
        body: Box::new(RendezvousBody {
            requester: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
            options: NattConnectOptions::from_byte(0x80),
            file_hash: None,
            claimed_endpoint: Some(requester()),
            transport_hint: None,
        }),
    };
    let mut queued = 0;
    while h.front.try_send(stranger()).is_ok() {
        queued += 1;
    }
    assert_eq!(queued, COMMAND_QUEUE_LEN, "the inbox is full");

    h.kad_started_as([0x33; 16]);
    settle().await;
    h.ask_adopt_for(a_buddy(), [0x33; 16]).await;
    assert_eq!(
        within("the verdict", h.verdicts.recv()).await.outcome,
        AdoptOutcome::Adopted
    );
    assert_eq!(h.next_dial().await.peer, PeerEndpoint::V4(a_buddy().tcp));
}

/// A restart under the same Kad ID (a pinned one) is still a new node: the
/// buddy the last one held is let go.
#[tokio::test(start_paused = true)]
async fn a_restart_under_the_same_kad_id_lets_the_old_buddy_go() {
    let mut h = quiet_harness();
    let mut side = h.hold().await;

    h.kad_started();
    settle().await;
    assert!(side.is_shut());
    assert_eq!(
        h.buddy.snapshot(),
        crate::firewalled::link::BuddySnapshot::default()
    );
}
