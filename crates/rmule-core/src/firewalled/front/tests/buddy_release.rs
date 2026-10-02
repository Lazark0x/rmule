//! The buddy's lifecycle around a dial that runs on its own task: whatever
//! lands late — a link or a failure — acts only on the buddy it was for
//! And a buddy the Kad-scoped mechanism cannot use is let
//! go rather than dialed. One buddy is dialed once and linked once, however
//! often it is adopted.

use super::*;

/// A buddy adopted while Kad is down is let go, never dialed: the mechanism
/// is Kad-scoped (ADR-0061), and a link dialed now could only be torn down.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_buddy_adopted_with_kad_down_is_released_undialed() {
    // A buddy that would answer: a dial here would be held, not fail and
    // release the slot on its own.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let buddy = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
    let slot = recruited(buddy);
    let h = kad_down_harness(&slot);
    let _peer = fake_buddy(listener, Vec::new());

    h.front.send(kad_started()).await.expect("front running");
    h.front
        .send(FirewalledCommand::BuddyAdopted)
        .await
        .expect("front running");

    // Kad never ran, so Kad Presence has no change to release on, and the
    // quiet clock never ticks: only `BuddyAdopted`'s own Kad gate can have
    // let the buddy go — and that gate returns before any dial spawns.
    until("the buddy to be released", || h.slot.buddy().is_none()).await;
}

/// Kad stopping lets the held buddy go **at once**: the front
/// awaits Kad Presence's change rather than noticing it on a tick, so the
/// link is shut with the clock quiet. A relay could never reach a node with
/// no Kad, and every `0x99` it sent meanwhile would only be dropped `KadDown`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kad_stopping_releases_the_held_buddy_without_waiting_for_a_tick() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let buddy = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
    let slot = recruited(buddy);
    let h = quiet_harness(&slot);
    let peer = fake_buddy(listener, Vec::new());

    h.front.send(kad_started()).await.expect("front running");
    h.front
        .send(FirewalledCommand::BuddyAdopted)
        .await
        .expect("front running");
    until("the link to be held", || {
        h.slot.state().0 == crate::firewalled::link::BuddyState::Held
    })
    .await;

    drop(h.kad_lease);
    until("the buddy to be released", || {
        h.slot.state().0 == crate::firewalled::link::BuddyState::None && h.slot.buddy().is_none()
    })
    .await;
    // The buddy sees its link shut: its read loop ends.
    within("the buddy link to be shut", async { peer.await.ok() }).await;
    assert_eq!(h.diagnostics.snapshot().session.buddy_links_lost_total, 1);
}

/// A buddy dial that lands after its buddy was let go is shut, never held
/// The dial runs on its own task, so an open Kad TCP verdict can
/// release the buddy while the dial is still in flight. Holding the late link
/// anyway reported `Held` with no buddy behind it and kept its socket open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_buddy_dial_landing_after_the_release_is_shut_not_held() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let buddy = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
    let slot = recruited(buddy);
    let h = harness(&slot);
    let (hello_tx, hello_rx) = tokio::sync::oneshot::channel::<()>();
    let (answer_tx, answer_rx) = tokio::sync::oneshot::channel::<()>();
    let peer = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("the front dials");
        let mut buf = Vec::new();
        next_packet(&mut sock, &mut buf).await.expect("a hello");
        hello_tx.send(()).expect("the leg waits for the hello");
        answer_rx.await.expect("the leg releases the answer");
        let answer = HelloAnswer::new(rmule_testkit::peer_session::answer_body(buddy_hash()))
            .encode_packet()
            .encode();
        sock.write_all(&answer).await.expect("the answer is framed");
        // Returns once the front hangs up.
        while next_packet(&mut sock, &mut buf).await.is_some() {}
    });

    h.front.send(kad_started()).await.expect("front running");
    h.front
        .send(FirewalledCommand::BuddyAdopted)
        .await
        .expect("front running");
    within("the dial's hello", async { hello_rx.await.ok() }).await;

    h.kad.set_tcp(crate::reachability::TcpReachability::Open);
    until("the release", || h.slot.buddy().is_none()).await;
    answer_tx.send(()).expect("the buddy waits to answer");

    within("the late link to be shut", async { peer.await.ok() }).await;
    assert_eq!(
        h.slot.state().0,
        crate::firewalled::link::BuddyState::None,
        "nothing is held for a buddy that is gone"
    );
}

/// A buddy dial that fails after its buddy was let go and **another adopted**
/// frees nothing: the failure is the first buddy's, and the slot
/// is no longer its to free. Releasing anyway threw the second buddy away and
/// armed an instant recruit beside a slot that was full.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_late_failed_dial_leaves_the_buddy_adopted_since() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let first = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
    let slot = recruited(first);
    // The clock never ticks, so the slot moves only on the leg's own events.
    let h = quiet_harness(&slot);
    let (hello_tx, hello_rx) = tokio::sync::oneshot::channel::<()>();
    let (fail_tx, fail_rx) = tokio::sync::oneshot::channel::<()>();
    let peer = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("the front dials");
        let mut buf = Vec::new();
        next_packet(&mut sock, &mut buf).await.expect("a hello");
        hello_tx.send(()).expect("the leg waits for the hello");
        fail_rx.await.expect("the leg releases the failure");
        // Hang up with the hello unanswered: the dial fails.
        drop(sock);
    });

    h.front.send(kad_started()).await.expect("front running");
    h.front
        .send(FirewalledCommand::BuddyAdopted)
        .await
        .expect("front running");
    within("the dial's hello", async { hello_rx.await.ok() }).await;

    // With the dial in flight, the first buddy is released (we turned
    // reachable) and a later walk adopts a second one.
    h.kad.set_tcp(crate::reachability::TcpReachability::Open);
    until("the first buddy's release", || h.slot.buddy().is_none()).await;
    let second = adopt(
        &h.slot,
        SocketAddrV4::new(Ipv4Addr::new(45, 55, 200, 8), 4662),
        [OUR_KAD_ID; rmule_kad::KadId::BYTE_LEN],
    );

    fail_tx.send(()).expect("the first buddy waits to hang up");
    until("the first buddy's dial to fail", || {
        h.diagnostics.snapshot().session.buddy_dials_failed_total == 1
    })
    .await;

    assert_eq!(
        h.slot.buddy(),
        Some(second),
        "the first buddy's failure leaves the second buddy in the slot"
    );
    assert_eq!(
        h.slot.state().0,
        crate::firewalled::link::BuddyState::Recruited
    );
    assert!(
        matches!(
            h.slot.consider_recruitment(
                &crate::firewalled::recruit::RecruitContext {
                    kad_connected: true,
                    tcp: crate::reachability::TcpReachability::Firewalled,
                    udp: crate::buddy::BuddyUdpPosture::Firewalled,
                    last_recheck: None,
                    crypt_required: false,
                },
                Instant::now(),
            ),
            crate::firewalled::recruit::RecruitDecision::Refuse {
                reason: crate::firewalled::recruit::RecruitRefusal::AlreadyHaveBuddy
            }
        ),
        "no recruit is armed while the slot holds a buddy"
    );
    peer.await.expect("the first buddy hung up");
}

/// A second `BuddyAdopted` while the dial to that buddy is in flight starts no
/// second dial — a re-adopt after a recruit tick, or a duplicate
/// `0x5A`. Both dials would land `Held` on the same buddy, and the second
/// silently replaced the first link, whose task kept a socket nothing relayed
/// down.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_adopt_mid_dial_dials_once_and_holds_one_link() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let buddy = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
    let slot = recruited(buddy);
    // The clock never ticks, so the slot moves only on the leg's own events.
    let h = quiet_harness(&slot);
    let (hello_tx, hello_rx) = tokio::sync::oneshot::channel::<()>();
    let (answer_tx, answer_rx) = tokio::sync::oneshot::channel::<()>();
    let peer = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("the front dials");
        let mut buf = Vec::new();
        next_packet(&mut sock, &mut buf).await.expect("a hello");
        hello_tx.send(()).expect("the leg waits for the hello");
        answer_rx.await.expect("the leg releases the answer");
        let answer = HelloAnswer::new(rmule_testkit::peer_session::answer_body(buddy_hash()))
            .encode_packet()
            .encode();
        sock.write_all(&answer).await.expect("the answer is framed");
        // Returns once the front hangs up.
        while next_packet(&mut sock, &mut buf).await.is_some() {}
    });

    h.front.send(kad_started()).await.expect("front running");
    h.front
        .send(FirewalledCommand::BuddyAdopted)
        .await
        .expect("front running");
    within("the dial's hello", async { hello_rx.await.ok() }).await;

    // The same buddy adopted again, with its dial still unanswered.
    h.front
        .send(FirewalledCommand::BuddyAdopted)
        .await
        .expect("front running");
    until("the second dial to be refused", || {
        h.diagnostics.snapshot().session.buddy_dials_refused_total == 1
    })
    .await;

    answer_tx.send(()).expect("the buddy waits to answer");
    until("the link to be held", || {
        h.slot.state().0 == crate::firewalled::link::BuddyState::Held
    })
    .await;
    let session = h.diagnostics.snapshot().session;
    assert_eq!(session.buddy_links_held_total, 1);
    assert_eq!(session.buddy_dials_failed_total, 0);

    // The one link is the one held: letting the buddy go shuts it.
    drop(h.kad_lease);
    within("the buddy link to be shut", async { peer.await.ok() }).await;
}
