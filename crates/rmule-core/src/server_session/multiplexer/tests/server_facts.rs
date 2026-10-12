//! What the session folds from the server: load, ident name, IPv6 verdict and
//! reflection, and the refused/ignored introduction.

use super::*;

/// Poll the surfaced row for the connected server until `settled` accepts
/// it — the session task consumes on its own schedule, so the assertion
/// waits for the write rather than racing it.
async fn settled_row(
    diagnostics: &crate::diagnostics::DiagnosticsState,
    settled: impl Fn(&crate::diagnostics::ServerDiagnostics) -> bool,
) -> crate::diagnostics::ServerDiagnostics {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let row = diagnostics
                .snapshot()
                .servers
                .into_iter()
                .find(|row| row.server.endpoint == connected())
                .expect("the connected server is listed");
            if settled(&row) {
                return row;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the session consumed the welcome burst within 2s")
}

/// The welcome burst is a source of the same two facts the UDP sweep asks
/// for (ADR-0080): the connected server states its load, and the row shows
/// it — without a ping, which only a UDP round trip can measure.
#[tokio::test]
async fn the_welcome_burst_lands_the_connected_servers_load_on_its_row() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let (facts, diagnostics) = crate::server_list::test_facts(&[connected()]);
    let _handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        SessionSinks {
            server_ip: None,
            own: SharedOwnIdentity::default(),
            ipv6_probe: crate::reachability::SharedIpv6Probe::default(),
            over_ipv6: false,
            punch: Default::default(),
            grants: rmule_ed2k::ServerGrants::default(),
            reach: None,
            server: connected(),
            facts,
        },
    );

    evt_tx
        .send(Ed2kEvent::ServerStatusReceived {
            status: rmule_primitives::ServerStatusReport {
                user_count: 120_000,
                file_count: 5_000_000,
            },
        })
        .await
        .unwrap();

    let row = settled_row(&diagnostics, |row| row.users.is_some()).await;
    assert_eq!(row.users, Some(120_000));
    assert_eq!(row.files, Some(5_000_000));
    assert_eq!(row.ping, None, "a TCP session measures no UDP round trip");
    assert_eq!(row.server.fail_count, 0);
}

/// `OP_SERVERIDENT` names the server we are connected to, and that name
/// folds into the list through the same merge a downloaded server.met row
/// takes — so a cold start that never read a mirror still learns it.
#[tokio::test]
async fn a_server_ident_folds_the_servers_own_name_into_the_list() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let (facts, diagnostics) = crate::server_list::test_facts(&[connected()]);
    let _handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        SessionSinks {
            server_ip: None,
            own: SharedOwnIdentity::default(),
            ipv6_probe: crate::reachability::SharedIpv6Probe::default(),
            over_ipv6: false,
            punch: Default::default(),
            grants: rmule_ed2k::ServerGrants::default(),
            reach: None,
            server: connected(),
            facts,
        },
    );

    evt_tx
        .send(Ed2kEvent::ServerIdentified {
            identity: rmule_primitives::ServerIdentity {
                name: Some(Ed2kText::from_utf8("eMule Security No1")),
                description: Some(Ed2kText::from_utf8("Big and fast")),
                ..rmule_primitives::ServerIdentity::default()
            },
        })
        .await
        .unwrap();
    let row = settled_row(&diagnostics, |row| !row.server.name.as_bytes().is_empty()).await;
    assert_eq!(row.server.name.to_display_string(), "eMule Security No1");
    assert_eq!(row.server.description.to_display_string(), "Big and fast");

    // A later ident that names the server but carries no description keeps
    // the one already known — aMule's per-field welcome-burst update.
    evt_tx
        .send(Ed2kEvent::ServerIdentified {
            identity: rmule_primitives::ServerIdentity {
                name: Some(Ed2kText::from_utf8("Renamed")),
                ..rmule_primitives::ServerIdentity::default()
            },
        })
        .await
        .unwrap();
    let row = settled_row(&diagnostics, |row| {
        row.server.name.to_display_string() == "Renamed"
    })
    .await;
    assert_eq!(row.server.description.to_display_string(), "Big and fast");
}

/// ADR-0087 §4.3's probe verdict, end to end through the session: a stated
/// `PROBED`-without-`REACHABLE` suppresses, a later ident that carries no tag
/// does **not** un-suppress, and the session's end clears it.
///
/// The three rules are one behaviour: the verdict is the connected server's
/// statement about this session's path, so only that server withdraws it and
/// only by contradicting itself.
#[tokio::test]
async fn the_servers_ipv6_verdict_is_published_kept_across_a_silent_ident_and_cleared_on_close() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let (facts, _diagnostics) = crate::server_list::test_facts(&[connected()]);
    let probe = crate::reachability::SharedIpv6Probe::default();
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        SessionSinks {
            server_ip: None,
            own: SharedOwnIdentity::default(),
            ipv6_probe: probe.clone(),
            over_ipv6: false,
            punch: Default::default(),
            grants: rmule_ed2k::ServerGrants::default(),
            reach: None,
            server: connected(),
            facts,
        },
    );
    assert_eq!(probe.get(), crate::reachability::Ipv6Probe::Unknown);

    evt_tx
        .send(Ed2kEvent::ServerIdentified {
            identity: rmule_primitives::ServerIdentity {
                ipv6_status: Some(rmule_primitives::ServerIpv6Status::from_bits(
                    rmule_primitives::ServerIpv6Status::HAVE
                        | rmule_primitives::ServerIpv6Status::PROBED,
                )),
                ..rmule_primitives::ServerIdentity::default()
            },
        })
        .await
        .unwrap();
    settled(&probe, crate::reachability::Ipv6Probe::ProbedUnreachable).await;

    // The second ident a `OP_GETSERVERLIST` draws normally carries no verdict.
    evt_tx
        .send(Ed2kEvent::ServerIdentified {
            identity: rmule_primitives::ServerIdentity {
                name: Some(Ed2kText::from_utf8("Renamed")),
                ..rmule_primitives::ServerIdentity::default()
            },
        })
        .await
        .unwrap();
    // A stated reachable verdict is the only thing that lifts it.
    evt_tx
        .send(Ed2kEvent::ServerIdentified {
            identity: rmule_primitives::ServerIdentity {
                ipv6_status: Some(rmule_primitives::ServerIpv6Status::from_bits(
                    rmule_primitives::ServerIpv6Status::HAVE
                        | rmule_primitives::ServerIpv6Status::REACHABLE
                        | rmule_primitives::ServerIpv6Status::PROBED,
                )),
                ..rmule_primitives::ServerIdentity::default()
            },
        })
        .await
        .unwrap();
    settled(&probe, crate::reachability::Ipv6Probe::ProbedReachable).await;

    drop(evt_tx);
    drop(handle);
    settled(&probe, crate::reachability::Ipv6Probe::Unknown).await;
}

/// Wait for the published verdict to reach `want`, or fail the test.
async fn settled(
    probe: &crate::reachability::SharedIpv6Probe,
    want: crate::reachability::Ipv6Probe,
) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while probe.get() != want {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("verdict never settled at {want:?}, still {:?}", probe.get()));
}

/// `CT_MOD_YOUR_IP`'s hash form is tier 1 of the address ladder — but only
/// from a session that actually ran over IPv6 (ADR-0087 §4.3). A reflection
/// arriving over an IPv4 session names an address the server never reached us
/// at, so it is dropped rather than voted on.
#[tokio::test]
async fn an_ipv6_reflection_is_adopted_only_from_an_ipv6_session() {
    let held: std::net::Ipv6Addr = "2001:db8::7".parse().unwrap();

    for (over_ipv6, expected_tier) in [
        (false, crate::address_learning::ConfidenceTier::Interface),
        (true, crate::address_learning::ConfidenceTier::Server),
    ] {
        let (evt_tx, evt_rx) = mpsc::channel(8);
        let (cmd_tx, _cmd_rx) = mpsc::channel(8);
        let (facts, _diagnostics) = crate::server_list::test_facts(&[connected()]);
        let own = SharedOwnIdentity::default();
        // The store's other half of the rule: a reflection is adopted only
        // when this host also holds the address.
        own.addresses().refresh_interfaces(&[held.into()]);
        let _handle = ServerSession::spawn(
            FakeLink {
                events: evt_rx,
                sent: cmd_tx,
            },
            client_id(),
            SessionSinks {
                server_ip: None,
                own: own.clone(),
                ipv6_probe: crate::reachability::SharedIpv6Probe::default(),
                over_ipv6,
                punch: Default::default(),
                grants: rmule_ed2k::ServerGrants::default(),
                reach: None,
                server: connected(),
                facts,
            },
        );

        evt_tx
            .send(Ed2kEvent::ServerIdentified {
                identity: rmule_primitives::ServerIdentity {
                    reflected_ipv6: Some(held),
                    ..rmule_primitives::ServerIdentity::default()
                },
            })
            .await
            .unwrap();
        // Let the session drain the event before reading the store.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // The tier is the discriminator, not the address: this host holds
        // `held` on an interface either way (tier 4, and the filter's
        // evidence), so only a reflection that was actually forwarded promotes
        // it to the server tier.
        assert_eq!(
            own.addresses()
                .address_tier(rmule_primitives::AddressFamily::V6),
            Some(expected_tier),
            "over_ipv6={over_ipv6}"
        );
    }
}

/// ADR-0091: whichever way an introduction dies, it reaches the
/// **NAT-T Front** — the one place holding the facts that pick the next
/// coordinator. A `0x62` names its target and settles it the moment it
/// arrives; a `0x60` the server simply ignores settles on the session's own
/// tick, because silence is the only thing a server that does not speak the
/// punch ever says, and the session is that introduction's whole lifetime.
#[tokio::test(start_paused = true)]
async fn a_refused_and_an_ignored_introduction_both_reach_the_natt_front() {
    use rmule_ed2k::{HolepunchFail, HolepunchFailReason};

    use crate::natt::front::{NattCommand, SharedNattFront};
    use crate::natt::server_punch::{INTRODUCTION_TIMEOUT, IntroductionFailure, SharedServerPunch};

    let punch = SharedServerPunch::default();
    let front = SharedNattFront::default();
    let (front_tx, mut front_rx) = mpsc::channel(8);
    front.install(front_tx);
    punch.install_natt_front(front);

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

    // Establishment's write: the keepalive started on this session.
    punch.go_live(&handle);

    let refused = ClientId::from_u32(1337);
    let ignored = ClientId::from_u32(1338);
    for target in [refused, ignored] {
        assert!(
            punch
                .coordinator_session()
                .request_introduction(target, 4665)
        );
        assert!(matches!(
            cmd_rx.recv().await.unwrap(),
            Ed2kCommand::RequestHolepunch { .. }
        ));
    }

    evt_tx
        .send(Ed2kEvent::HolepunchRefused {
            fail: HolepunchFail {
                target: refused,
                reason: HolepunchFailReason::TargetNoUdp,
            },
        })
        .await
        .unwrap();
    assert_eq!(
        front_rx.recv().await.expect("the front is told"),
        NattCommand::IntroductionFailed {
            target: refused,
            failure: IntroductionFailure::Refused {
                reason: HolepunchFailReason::TargetNoUdp,
                permanent: true,
            },
        }
    );

    // The other request is nobody's to answer. Only the clock settles it, and
    // it is reported exactly once.
    tokio::time::sleep(INTRODUCTION_TIMEOUT + Duration::from_secs(2)).await;
    assert_eq!(
        front_rx.try_recv().expect("silence is settled on the tick"),
        NattCommand::IntroductionFailed {
            target: ignored,
            failure: IntroductionFailure::Silence,
        }
    );
    tokio::time::sleep(INTRODUCTION_TIMEOUT).await;
    assert!(
        front_rx.try_recv().is_err(),
        "settled once, not once a second"
    );
}
