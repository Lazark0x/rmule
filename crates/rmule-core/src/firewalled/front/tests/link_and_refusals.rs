//! Buddy link loss and reachability release, refused buddy dials, stranger
//! rendezvous refusal, and the crypt-required recruiting stop.

use super::*;

/// **Kad Presence**, not a task-local copy: the buddy link is
/// dialed and held with Kad up, then the pump's lease is dropped — never a
/// `KadStopped` command, there is none — and the very same relayed callback
/// that [`a_relayed_callback_is_consumed_and_counted`] dials back is dropped
/// by the Kad gate instead.
///
/// Losing the link empties the slot and re-arms the walk; becoming reachable
/// releases the buddy outright.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn link_loss_re_arms_the_walk_and_reachability_releases_the_buddy() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let buddy = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
    let slot = recruited(buddy);
    let h = harness(&slot);
    let peer = fake_buddy(listener, Vec::new());

    h.front.send(kad_started()).await.expect("front running");
    h.front
        .send(FirewalledCommand::BuddyAdopted)
        .await
        .expect("front running");
    within("the link to be held", async {
        for _ in 0..200 {
            if h.slot.state().0 == crate::firewalled::link::BuddyState::Held {
                return Some(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    })
    .await;

    // The buddy hangs up: the slot empties, and the recruit trigger's
    // 20-minute leg is satisfied at once.
    peer.abort();
    within("the slot to empty", async {
        for _ in 0..200 {
            if h.slot.state().0 == crate::firewalled::link::BuddyState::None {
                return Some(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    })
    .await;
    assert_eq!(h.slot.buddy(), None);
    assert!(matches!(
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
        crate::firewalled::recruit::RecruitDecision::Recruit { .. }
    ));

    // And an open verdict releases whatever the walk might find next.
    h.front.send(FirewalledCommand::BuddyAdopted).await.ok();
    h.kad.set_tcp(crate::reachability::TcpReachability::Open);
    within("the release", async {
        for _ in 0..200 {
            if h.slot.state().0 == crate::firewalled::link::BuddyState::None
                && h.slot.buddy().is_none()
            {
                return Some(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    })
    .await;
}

/// A buddy whose port refuses the dial: the failure is reported with its OS
/// cause and the buddy's address, the only trace of why no link was held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_buddy_dial_is_reported_with_its_cause() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let buddy = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
    drop(listener);
    let slot = recruited(buddy);
    let mut h = harness(&slot);

    h.front.send(kad_started()).await.expect("front running");
    h.front
        .send(FirewalledCommand::BuddyAdopted)
        .await
        .expect("front running");
    let event = tokio::time::timeout(Duration::from_secs(5), h.events.recv())
        .await
        .expect("the failure is reported within 5s")
        .expect("the front is running");
    assert!(
        matches!(
            event,
            crate::CoreEvent::BuddyDialFailed {
                buddy: at,
                cause: crate::BuddyDialFailure::Dial {
                    cause: crate::DialFailure::Os {
                        kind: std::io::ErrorKind::ConnectionRefused,
                        ..
                    }
                },
            } if at == Ipv4Endpoint::new(*buddy.ip(), buddy.port())
        ),
        "{event:?}"
    );
}

/// A standalone `0xC5 0xA0` from a stranger's endpoint is refused by the
/// carrier gate and counted — the acting path's only other inlet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_standalone_rendezvous_from_a_stranger_is_refused() {
    let slot: SharedFirewalledSlot = std::sync::Arc::new(FirewalledSlot::new(
        rmule_kad::KadId::from_bytes([OUR_KAD_ID; rmule_kad::KadId::BYTE_LEN]),
    ));
    let h = harness(&slot);
    h.front
        .send(FirewalledCommand::StandaloneRendezvous {
            from: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 99), 4672)),
            body: Box::new(RendezvousBody {
                requester: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
                options: NattConnectOptions::from_byte(0x80),
                file_hash: None,
                claimed_endpoint: Some(requester()),
                transport_hint: None,
            }),
        })
        .await
        .expect("front running");

    within("the refusal", async {
        for _ in 0..200 {
            let session = h.diagnostics.snapshot().session;
            if session.acting_refusals_total == 1 {
                assert_eq!(
                    session.acting_last_refusal,
                    Some(crate::diagnostics::ActingRefusal::NotFromOurBuddy)
                );
                return Some(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    })
    .await;
}

/// A `Required` crypt policy never recruits a buddy, and the front's own
/// clock — the one place the slot's state is copied into diagnostics — names
/// the reason rather than leaving `buddy_state: None` looking merely
/// un-recruited. Drives the same enacted slot the Kad pump's
/// recruit tick drives (`FirewalledSlot::consider_recruitment`), so this
/// proves the diagnostics wiring the front adds — the pure refusal matrix
/// itself is proven in `firewalled::tests`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crypt_required_recruits_no_buddy_and_diagnostics_names_it() {
    let slot: SharedFirewalledSlot = std::sync::Arc::new(FirewalledSlot::new(
        rmule_kad::KadId::from_bytes([OUR_KAD_ID; rmule_kad::KadId::BYTE_LEN]),
    ));
    let mut h = harness(&slot);

    // Both surfaces firewalled, Kad up, pacing due — every other leg of the
    // gate would recruit — but crypt is required, aMule's own limitation
    // (callback requests are not obfuscatable): refused.
    let decision = h.slot.consider_recruitment(
        &crate::firewalled::recruit::RecruitContext {
            kad_connected: true,
            tcp: crate::reachability::TcpReachability::Firewalled,
            udp: crate::buddy::BuddyUdpPosture::Firewalled,
            last_recheck: None,
            crypt_required: true,
        },
        Instant::now(),
    );
    assert_eq!(
        decision,
        crate::firewalled::recruit::RecruitDecision::Refuse {
            reason: crate::firewalled::recruit::RecruitRefusal::CryptRequired
        }
    );
    assert!(h.slot.buddy().is_none(), "nothing was ever recruited");

    // The front's tick is the one place this reading reaches diagnostics.
    within("the refusal to reach diagnostics", async {
        for _ in 0..200 {
            let session = h.diagnostics.snapshot().session;
            if session.buddy_last_recruit_refusal
                == Some(crate::firewalled::recruit::RecruitRefusal::CryptRequired)
            {
                assert_eq!(session.buddy_state, crate::diagnostics::BuddyState::None);
                return Some(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    })
    .await;

    // No walk was ever asked for.
    assert!(h.natt.try_recv().is_err());
}
