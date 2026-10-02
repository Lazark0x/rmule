//! Multiplexer-loop unit tests over the fake link: lookup demux and link-fault
//! failure paths, the announce and callback relays, the search requests and
//! their answers' places (in `search`), the welcome
//! burst landing the connected server's own facts, and the mid-session
//! IDCHANGE republishing our public IP.

use rmule_ed2k::{CommandRejectReason, Ed2kCommandKind, ServerAssignedFacts};
use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_primitives::{
    Ed2kText, Ipv4Endpoint, PeerEndpoint, PeerSource, SourceListTail, UserHash,
};

use super::super::tests::{FakeLink, client_id, connected, test_sinks};
use super::*;

mod callback;
mod more_results;
mod related_search;
mod search;
mod server_facts;

fn target(byte: u8) -> SourceLookupTarget {
    SourceLookupTarget::new(FileHash::from_bytes([byte; FileHash::BYTE_LEN]), 1024)
}

#[tokio::test]
async fn concurrent_lookups_are_demuxed_by_file_hash() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );

    let (a, b) = (target(0xAA), target(0xBB));
    let (ha, hb) = (handle.clone(), handle.clone());
    let lookup_a = tokio::spawn(async move { ha.lookup_sources(a).await });
    let lookup_b = tokio::spawn(async move { hb.lookup_sources(b).await });

    // Both requests reach the link as RequestSources.
    let mut requested = Vec::new();
    for _ in 0..2 {
        match cmd_rx.recv().await.unwrap() {
            Ed2kCommand::RequestSources { target } => requested.push(target.file_hash()),
            other => panic!("unexpected command {other:?}"),
        }
    }
    assert!(requested.contains(&a.file_hash()) && requested.contains(&b.file_hash()));

    // Answer out of order: each waiter gets ITS own sources (no stealing).
    let src_b = vec![ExchangedSource::plain(PeerSource::new(client_id(), 7001))];
    let src_a = vec![
        ExchangedSource::plain(PeerSource::new(client_id(), 7002)),
        ExchangedSource::plain(PeerSource::new(client_id(), 7003)),
    ];
    evt_tx
        .send(Ed2kEvent::SourcesFound {
            file_hash: b.file_hash(),
            sources: src_b.clone(),
            tail: SourceListTail::Read { sentinels: 0 },
        })
        .await
        .unwrap();
    evt_tx
        .send(Ed2kEvent::SourcesFound {
            file_hash: a.file_hash(),
            sources: src_a.clone(),
            tail: SourceListTail::Read { sentinels: 0 },
        })
        .await
        .unwrap();

    let outcome_a = lookup_a.await.unwrap().unwrap();
    let outcome_b = lookup_b.await.unwrap().unwrap();
    assert_eq!(outcome_a.sources, src_a);
    assert_eq!(outcome_b.sources, src_b);
    assert_eq!(outcome_a.client_id, client_id());
}

/// A file hash whose four 4-byte words all differ, so a word-order slip in any
/// codec would show.
fn uneven_target(seed: u8) -> SourceLookupTarget {
    let mut bytes = [0u8; FileHash::BYTE_LEN];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add(u8::try_from(index).expect("16 bytes").wrapping_mul(0x1D));
    }
    SourceLookupTarget::new(FileHash::from_bytes(bytes), 9_728_001)
}

/// ADR-0107 invariant 1: a second lookup for a hash already asked on the
/// session joins that ask — one `OP_GETSOURCES` on the wire, and the one
/// answer reaches both waiters. An ask whose every waiter has gone is asked
/// again rather than joined.
#[tokio::test]
async fn a_second_lookup_for_the_same_file_joins_the_ask_in_flight() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );
    let file = uneven_target(0x3C);

    // A waiter that gives up: its ask is on the wire, and then it is gone.
    let quitter = handle.clone();
    let gave_up = tokio::spawn(async move { quitter.lookup_sources(file).await });
    assert!(matches!(
        cmd_rx.recv().await.unwrap(),
        Ed2kCommand::RequestSources { target } if target == file
    ));
    gave_up.abort();
    let _ = gave_up.await;

    // Nobody listens to the first ask any more: the next lookup asks again.
    let (first, second) = (handle.clone(), handle.clone());
    let lookup_first = tokio::spawn(async move { first.lookup_sources(file).await });
    assert!(matches!(
        cmd_rx.recv().await.unwrap(),
        Ed2kCommand::RequestSources { target } if target == file
    ));
    // This one joins the ask in flight: nothing more reaches the wire.
    let lookup_second = tokio::spawn(async move { second.lookup_sources(file).await });
    // The answer must not overtake the join: let the joining request reach the
    // session task before the server speaks.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let answer = vec![ExchangedSource::plain(PeerSource::new(client_id(), 7104))];
    evt_tx
        .send(Ed2kEvent::SourcesFound {
            file_hash: file.file_hash(),
            sources: answer.clone(),
            tail: SourceListTail::Read { sentinels: 0 },
        })
        .await
        .unwrap();

    assert_eq!(lookup_first.await.unwrap().unwrap().sources, answer);
    assert_eq!(lookup_second.await.unwrap().unwrap().sources, answer);
    assert!(
        cmd_rx.try_recv().is_err(),
        "the joined lookup put a second ask on the wire"
    );
}

/// ADR-0091, the server coordinator through a live session. Asking puts the
/// `0x60` on the link and only then records it as pending. The server's
/// introduction — here unsolicited, as the *target's* copy always is — fires
/// the burst from the client-UDP send half; a refusal settles the request it
/// names. And when the session ends the coordinator stops being offered: the
/// flag the route chooser reads goes dark with it.
#[tokio::test]
async fn the_server_coordinator_asks_punches_and_ends_with_its_session() {
    use rmule_ed2k::{HolepunchFail, HolepunchFailReason, HolepunchInfo, HolepunchRole};

    use crate::natt::server_punch::{INTRODUCTION_TIMEOUT, SharedServerPunch};

    let punch = SharedServerPunch::default();
    let diagnostics = crate::diagnostics::DiagnosticsState::default();
    punch.install_diagnostics(diagnostics.clone());
    let (udp_tx, mut udp_rx) = mpsc::channel(64);
    punch.install_client_udp(udp_tx);
    punch.set_live(true);

    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        SessionSinks {
            server_ip: None,
            punch: punch.clone(),
            ..test_sinks(SharedOwnIdentity::default())
        },
    );

    let target = ClientId::from_u32(1337);
    handle.request_holepunch(target, 4665).await;
    match cmd_rx.recv().await.unwrap() {
        Ed2kCommand::RequestHolepunch {
            target: got,
            our_udp_port,
        } => assert_eq!((got, our_udp_port), (target, 4665)),
        other => panic!("unexpected command {other:?}"),
    }

    evt_tx
        .send(Ed2kEvent::HolepunchRefused {
            fail: HolepunchFail {
                target,
                reason: HolepunchFailReason::TargetNotConnected,
            },
        })
        .await
        .unwrap();
    evt_tx
        .send(Ed2kEvent::HolepunchIntroduced {
            info: HolepunchInfo {
                peer_udp: Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 7), 31999),
                peer_tcp_port: 4662,
                peer_hash: UserHash::from_bytes([0x44; 16]),
                role: HolepunchRole::Responder,
            },
        })
        .await
        .unwrap();

    let first = tokio::time::timeout(Duration::from_secs(5), udp_rx.recv())
        .await
        .expect("the burst was fired")
        .expect("send half open");
    assert_eq!(first.datagram, [0xC5, 0xA1]);
    assert_eq!(
        first.to,
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 7), 31999))
    );
    // Events are handled in order, so the refusal before it has settled:
    // nothing is left to time out.
    assert!(
        punch
            .ledger()
            .overdue(std::time::Instant::now() + INTRODUCTION_TIMEOUT)
            .is_empty()
    );

    // What the server said, and what came of it, is on the diagnostics row.
    let session = diagnostics.snapshot().session;
    assert_eq!(session.natt_server_punches_total, 1);
    assert_eq!(session.natt_server_refusals_total, 1);
    assert_eq!(
        session.natt_server_last_refusal,
        Some(HolepunchFailReason::TargetNotConnected)
    );

    drop(evt_tx);
    tokio::time::timeout(Duration::from_secs(5), async {
        while punch.is_live() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the coordinator went dark with its session");
}

#[tokio::test]
async fn a_dropped_link_fails_every_parked_lookup() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );

    let h = handle.clone();
    let lookup = tokio::spawn(async move { h.lookup_sources(target(0xAA)).await });
    assert!(matches!(
        cmd_rx.recv().await.unwrap(),
        Ed2kCommand::RequestSources { .. }
    ));

    // Link closes (driver gone): next_event yields None, the session ends
    // and every parked lookup is failed rather than hanging forever.
    drop(evt_tx);
    assert!(matches!(
        lookup.await.unwrap(),
        Err(DownloadFailure::ServerDisconnected)
    ));
}

#[tokio::test]
async fn a_command_rejection_fails_the_lookup() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );

    let h = handle.clone();
    let lookup = tokio::spawn(async move { h.lookup_sources(target(0xAA)).await });
    assert!(matches!(
        cmd_rx.recv().await.unwrap(),
        Ed2kCommand::RequestSources { .. }
    ));

    // The server rejects the request (no file hash on the event): the
    // session ends and the parked lookup fails promptly instead of hanging
    // until the link drops.
    evt_tx
        .send(Ed2kEvent::CommandRejected {
            command: Ed2kCommandKind::RequestSources,
            reason: CommandRejectReason::NotLoggedIn,
        })
        .await
        .unwrap();
    assert!(matches!(
        lookup.await.unwrap(),
        Err(DownloadFailure::ServerDisconnected)
    ));
}

#[tokio::test]
async fn announce_rides_the_session_as_offer_files() {
    let (_evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );

    let files = vec![OfferedFile::new(
        FileHash::from_bytes([0x01; FileHash::BYTE_LEN]),
        1024,
        Ed2kText::from_utf8("a.bin"),
    )];
    handle.announce(files.clone()).await.unwrap();
    match cmd_rx.recv().await.unwrap() {
        Ed2kCommand::OfferFiles { files: sent } => assert_eq!(sent, files),
        other => panic!("unexpected command {other:?}"),
    }
}

#[tokio::test]
async fn a_mid_session_idchange_republishes_our_public_ip() {
    // The session is the only writer of our public IP, and a *second*
    // `OP_IDCHANGE` — aMule
    // re-assigns mid-session — must be consumed too, in either direction.
    // Both UDP crypt send gates read the result.
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let own = SharedOwnIdentity::default();
    let _handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(own.clone()),
    );
    assert!(
        !own.public_ip_known(),
        "nothing published before an IDCHANGE"
    );

    let assigned = "198.51.100.7".parse().unwrap();
    evt_tx
        .send(Ed2kEvent::LoginAccepted {
            client_id: client_id(),
            tcp_flags: None,
            facts: ServerAssignedFacts {
                public_ip: Some(assigned),
                ..ServerAssignedFacts::default()
            },
        })
        .await
        .unwrap();
    let published = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Some(ip) = own.public_ip() {
                return ip;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the mid-session IDCHANGE published within 2s");
    assert_eq!(published, assigned);

    // A re-assignment down to LowID reports no public IP, and must clear it
    // rather than leave a stale one arming the crypt send paths.
    evt_tx
        .send(Ed2kEvent::LoginAccepted {
            client_id: ClientId::from_u32(0x0000_2A57),
            tcp_flags: None,
            facts: ServerAssignedFacts::default(),
        })
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while own.public_ip_known() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the LowID re-assignment cleared it within 2s");
}

/// The listener's hello follows a mid-session `OP_IDCHANGE`: the
/// **Hello Source** the accept pump reads names the id the server assigned
/// last, not the login's.
#[tokio::test]
async fn the_listeners_hello_names_the_id_a_mid_session_idchange_assigned() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let own = SharedOwnIdentity::default();
    let _handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(own.clone()),
    );
    own.set_connected_session(Some(crate::own_identity::ConnectedSession {
        server: None,
        client_id: client_id(),
    }));
    let hello = crate::server_session::HelloSource::live(
        rmule_testkit::peer_session::serverless_ctx().identity,
        own.clone(),
    );
    assert_eq!(hello.now().client_id, client_id(), "the login's id");

    let reassigned = ClientId::from_u32(0x0000_2A57);
    evt_tx
        .send(Ed2kEvent::LoginAccepted {
            client_id: reassigned,
            tcp_flags: None,
            facts: ServerAssignedFacts::default(),
        })
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while hello.now().client_id != reassigned {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the hello names the re-assigned id within 2s");
}

/// The session's High ID is a family of **Self Reach**:
/// it follows a mid-session re-assignment — aMule's `IsLowID()` reads the
/// live id, not the login's — and comes down when the session ends, each
/// move a **Reach Generation** the owner's subscribers wake on.
#[tokio::test]
async fn the_server_high_id_level_follows_reassignment_and_ends_with_the_session() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let own = SharedOwnIdentity::default();
    let reach = crate::reachability::SharedSelfReach::new(
        crate::KadReachLevel::fixed(false),
        own.clone(),
        crate::natt::front::SharedNattFront::default(),
    );
    let mut generation = reach.changes();
    assert!(!reach.server_high_id(), "no session: Low ID");
    let _handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(own.clone()),
    );
    // What establishment publishes the moment the session exists.
    own.set_connected_session(Some(crate::own_identity::ConnectedSession {
        server: None,
        client_id: client_id(),
    }));
    async fn settles(
        generation: &mut crate::reachability::ReachGeneration,
        reach: &crate::reachability::SharedSelfReach,
        high: bool,
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while reach.server_high_id() != high {
                generation.changed().await;
            }
        })
        .await
        .expect("the level moved within 2s");
    }
    settles(&mut generation, &reach, true).await;

    for (id, high) in [(0x0000_2A57, false), (0x0100_007F, true)] {
        evt_tx
            .send(Ed2kEvent::LoginAccepted {
                client_id: ClientId::from_u32(id),
                tcp_flags: None,
                facts: ServerAssignedFacts::default(),
            })
            .await
            .unwrap();
        settles(&mut generation, &reach, high).await;
    }

    drop(evt_tx);
    settles(&mut generation, &reach, false).await;
}
