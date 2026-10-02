//! The Run Log by content: what each level writes into the file, and how the
//! file is bounded and how it fails.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::mpsc;

use rmule_core::{
    CoreEvent, DownloadEvent, ScanEvent, SearchEvent, ServeEvent, ServerConnectionEvent,
};
use rmule_primitives::UserHash;
use tracing_subscriber::EnvFilter;

use super::*;

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("log file")
}

#[test]
fn a_level_is_written_when_it_moves_and_not_while_it_holds() {
    let mut trail = ReachTrail::default();
    let mut snapshot = rmule_core::diagnostics::DiagnosticsSnapshot::default();
    assert_eq!(
        trail.observe(&snapshot).len(),
        5,
        "the first tick states every level"
    );
    assert!(trail.observe(&snapshot).is_empty());

    snapshot.connected_server =
        Some(rmule_primitives::ServerEndpoint::new("203.0.113.7", 4661).expect("endpoint"));
    let records = trail.observe(&snapshot);
    assert_eq!(records.len(), 1);
    let line = records[0].render(Level::Lean);
    assert!(line.starts_with("reach.server "), "{line}");
    assert!(line.contains("203.0.113.7:4661"), "{line}");
    assert!(trail.observe(&snapshot).is_empty());
}

/// The events one session of a client touches: each carries something the
/// lean level must not hold, and most carry something it must.
fn session_events() -> Vec<CoreEvent> {
    let peer = crate::fixture::peer_at(198, 51, 100, 9, 4662);
    let hash = crate::fixture::file_hash(0xAB);
    let server = rmule_primitives::ServerEndpoint::new("203.0.113.7", 4661).expect("endpoint");
    vec![
        CoreEvent::ServerConnection(ServerConnectionEvent::Connected {
            server,
            client_id: rmule_primitives::ClientId::from_u32(0x0A00_0007),
        }),
        CoreEvent::Serve(ServeEvent::ServingStarted {
            listen_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(203, 0, 113, 5), 4662),
        }),
        CoreEvent::Download(DownloadEvent::DownloadQueued {
            download_id: crate::fixture::download_id(3),
            file_hash: hash,
            metadata: crate::fixture::metadata(
                "secret holiday film.avi",
                734_003_200,
                rmule_core::DownloadMetadataOrigin::Link,
            ),
        }),
        CoreEvent::Download(DownloadEvent::PeerSelected {
            download_id: crate::fixture::download_id(3),
            peer,
        }),
        CoreEvent::Serve(ServeEvent::UploadSlotGranted {
            peer,
            file_hash: hash,
            software: Some(crate::fixture::amule_233()),
        }),
        CoreEvent::Scan(ScanEvent::Declined {
            dir: "/home/ann/private-share".into(),
        }),
        CoreEvent::SecuredIdentityMismatch {
            user_hash: UserHash::from_bytes([0xCD; 16]),
        },
        CoreEvent::PeerReachRouted {
            peer,
            route: rmule_core::PeerReachRoute::Direct,
        },
        CoreEvent::Search(SearchEvent::SearchResultsReceived {
            search_id: crate::fixture::search_id(1),
            results: vec![crate::fixture::search_result("what i looked for.avi", 5)],
        }),
    ]
}

/// Write `session_events` through the real subscriber into a fresh log, and
/// return what landed in the file.
fn written_at(level: Level) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = RunLog::open(dir.path(), CAP_BYTES, mpsc::channel().0).expect("open");
    let handle = LevelHandle::new(level);
    let subscriber = subscriber(log, EnvFilter::new("info"), handle.clone());
    tracing::subscriber::with_default(subscriber, || {
        for event in session_events() {
            write(&event::record(&event), handle.get());
        }
        tracing::info!("free-form line naming peer 198.51.100.9");
    });
    read(&dir.path().join(FILE_NAME))
}

#[test]
fn the_lean_log_holds_our_evidence_and_none_of_what_a_peer_or_a_file_is() {
    let text = written_at(Level::Lean);
    for withheld in [
        "198.51.100.9",
        "secret holiday film",
        "734003200",
        "ABABABAB",
        "CDCDCDCD",
        "private-share",
        "what i looked for",
        "aMule",
        "free-form line",
    ] {
        assert!(
            !text.contains(withheld),
            "lean log held {withheld}:\n{text}"
        );
    }
    for kept in [
        "server.connected server=203.0.113.7:4661 client_id=167772167",
        "serve.serving_started listen_addr=203.0.113.5:4662",
        "download.queued id=3",
        "peer_reach.routed route=direct",
        "results=1",
    ] {
        assert!(text.contains(kept), "lean log lost {kept}:\n{text}");
    }
}

/// Shares the Announce Policy kept from a related-search server are written
/// as withheld, with why — never as announced.
#[test]
fn withheld_shares_are_written_as_withheld_and_never_as_announced() {
    let event = CoreEvent::Serve(ServeEvent::FilesWithheld {
        file_count: 3,
        reason: rmule_core::SharesWithheld::RelatedSearchGranted,
    });
    let line = event::record(&event).render(Level::Lean);
    assert_eq!(
        line,
        "serve.files_withheld file_count=3 reason=related_search_granted"
    );
}

/// A dial that ended before the hello and a reask answer that changed
/// nothing say why at lean level; the peer's address waits for full.
#[test]
fn a_short_ended_source_road_says_why_and_names_the_peer_only_in_full() {
    let peer = rmule_primitives::PeerEndpoint::V4(rmule_primitives::Ipv4Endpoint::new(
        std::net::Ipv4Addr::new(192, 0, 2, 6),
        4672,
    ));
    let download_id = rmule_core::DownloadId::from_u64(3);
    let ignored = CoreEvent::Download(DownloadEvent::ReaskReplyIgnored {
        download_id,
        peer,
        reason: rmule_core::IgnoredReaskReply::Misframed,
    });
    let ended = CoreEvent::Download(DownloadEvent::DialEnded {
        download_id,
        peer,
        cause: rmule_core::DialEnd::CryptStanceUnknown,
    });
    assert_eq!(
        event::record(&ignored).render(Level::Lean),
        "download.reask_reply_ignored id=3 reason=misframed"
    );
    assert_eq!(
        event::record(&ended).render(Level::Lean),
        "download.dial_ended id=3 cause=crypt_stance_unknown"
    );
    assert!(
        event::record(&ended)
            .render(Level::Full)
            .ends_with("peer=192.0.2.6:4672")
    );
}

#[test]
fn the_full_log_holds_the_same_events_with_what_lean_withholds() {
    let text = written_at(Level::Full);
    for held in [
        "peer=198.51.100.9:4662",
        "name=\"secret holiday film.avi\"",
        "size=734003200",
        "file_hash=ABABABABABABABABABABABABABABABAB",
        "user_hash=CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD",
        "dir=\"/home/ann/private-share\"",
        "software=\"aMule",
        "free-form line naming peer 198.51.100.9",
        "server.connected server=203.0.113.7:4661",
    ] {
        assert!(text.contains(held), "full log lost {held}:\n{text}");
    }
    assert!(
        !text.contains("what i looked for"),
        "search text is written at no level:\n{text}"
    );
}

/// A login's steps as core reports them: what rmule claimed, the server's port
/// test inside its window, what the server answered and granted, a Low ID
/// whose report named the server itself, and a dial to a second server that
/// never came up, beside a peer's route, a failed buddy dial and a late Kad
/// helper test, whose addresses lean withholds.
fn login_events() -> Vec<CoreEvent> {
    let server = rmule_primitives::ServerEndpoint::new("203.0.113.7", 4661).expect("endpoint");
    let dead = rmule_primitives::ServerEndpoint::new("192.0.2.44", 4242).expect("endpoint");
    let login = |step| CoreEvent::ServerLogin {
        server: server.clone(),
        step,
    };
    vec![
        login(rmule_core::LoginStep::MappingWait {
            port: 4662,
            settled: false,
        }),
        login(rmule_core::LoginStep::LoginSent {
            claim: rmule_core::LoginClaim {
                family: Some(rmule_primitives::AddressFamily::V4),
                tcp_port: 4662,
                client_udp_port: Some(4665),
                kad_udp_port: Some(4673),
                advertised_ipv6: Some("2001:db8::5".parse().expect("ipv6")),
            },
        }),
        login(rmule_core::LoginStep::PortTestAwaited),
        login(rmule_core::LoginStep::PortTestArrived {
            admission: rmule_core::PortTestAdmission::TestConnection,
        }),
        login(rmule_core::LoginStep::PortTestEnded {
            end: rmule_core::PortTestEnd::TesterClosed,
        }),
        login(rmule_core::LoginStep::PortTestEnded {
            end: rmule_core::PortTestEnd::PeerConnectionEnded {
                closed_by: rmule_core::PortTestClosedBy::Peer,
            },
        }),
        login(rmule_core::LoginStep::Answered {
            assignment: rmule_core::IdAssignment {
                client_id: rmule_primitives::ClientId::from_u32(0x0500_71CB),
                address: rmule_core::AssignedAddress::Ours(std::net::Ipv4Addr::new(203, 0, 113, 5)),
                grants: rmule_core::ServerGrants {
                    compression: true,
                    large_files: true,
                    ..rmule_core::ServerGrants::default()
                },
            },
        }),
        login(rmule_core::LoginStep::PortTestWindowClosed { arrived: true }),
        login(rmule_core::LoginStep::PortTestLate {
            late_by: std::time::Duration::from_millis(1_250),
            admission: rmule_core::PortTestLateAdmission::Refused,
        }),
        login(rmule_core::LoginStep::Reassigned {
            assignment: rmule_core::IdAssignment {
                client_id: rmule_primitives::ClientId::from_u32(0x0000_2A17),
                address: rmule_core::AssignedAddress::ServerOwnRefused(std::net::Ipv4Addr::new(
                    203, 0, 113, 7,
                )),
                grants: rmule_core::ServerGrants::default(),
            },
        }),
        CoreEvent::ServerLogin {
            server: dead,
            step: rmule_core::LoginStep::DialFailed {
                cause: rmule_core::DialFailure::Os {
                    kind: std::io::ErrorKind::ConnectionRefused,
                    os_code: Some(61),
                },
            },
        },
        CoreEvent::PeerReachRouted {
            peer: crate::fixture::peer_at(198, 51, 100, 9, 4662),
            route: rmule_core::PeerReachRoute::Direct,
        },
        CoreEvent::BuddyDialFailed {
            buddy: rmule_primitives::Ipv4Endpoint::new(
                std::net::Ipv4Addr::new(198, 51, 100, 23),
                5731,
            ),
            cause: rmule_core::BuddyDialFailure::Dial {
                cause: rmule_core::DialFailure::TimedOut,
            },
        },
        CoreEvent::KadHelperTestLate {
            helper: std::net::Ipv4Addr::new(198, 51, 100, 31),
            late_by: std::time::Duration::from_millis(3_400),
            admission: rmule_core::PortTestLateAdmission::Refused,
        },
    ]
}

/// Every login event, written at `level`.
fn login_log(level: Level) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = RunLog::open(dir.path(), CAP_BYTES, mpsc::channel().0).expect("open");
    let handle = LevelHandle::new(level);
    let subscriber = subscriber(log, EnvFilter::new("info"), handle.clone());
    tracing::subscriber::with_default(subscriber, || {
        for event in login_events() {
            write(&event::record(&event), handle.get());
        }
    });
    read(&dir.path().join(FILE_NAME))
}

#[test]
fn the_lean_log_holds_the_login_steps_with_our_address_and_ports_and_no_peer() {
    let text = login_log(Level::Lean);
    for kept in [
        "server.login server=203.0.113.7:4661 step=mapping_wait port=4662 settled=no",
        "server.login server=203.0.113.7:4661 step=login_sent family=ipv4 tcp_port=4662 \
         client_udp_port=4665 kad_udp_port=4673 advertised_ipv6=2001:db8::5",
        "server.login server=203.0.113.7:4661 step=port_test_awaited",
        "server.login server=203.0.113.7:4661 step=port_test_arrived admission=test_connection",
        "server.login server=203.0.113.7:4661 step=port_test_ended end=tester_closed",
        "server.login server=203.0.113.7:4661 step=port_test_ended end=peer_connection_ended \
         closed_by=peer",
        "server.login server=203.0.113.7:4661 step=answered client_id=83915211 \
         public_ip=203.0.113.5 compression=yes new_tags=no unicode=no related_search=no \
         type_tag_integer=no large_files=yes tcp_obfuscation=no ipv6=no",
        "server.login server=203.0.113.7:4661 step=port_test_window_closed arrived=yes",
        "server.login server=203.0.113.7:4661 step=port_test_late late_by_ms=1250 \
         admission=refused",
        "server.login server=203.0.113.7:4661 step=reassigned client_id=10775 \
         public_ip=refused_server_own reported=203.0.113.7 compression=no",
        "server.login server=192.0.2.44:4242 step=dial_failed cause=os error=connection refused \
         os_code=61",
        "peer_reach.routed route=direct",
        "buddy.dial_failed cause=timed_out",
        "kad.helper_test_late late_by_ms=3400 admission=refused",
    ] {
        assert!(text.contains(kept), "lean log lost {kept}:\n{text}");
    }
    for withheld in ["198.51.100.9", "198.51.100.23", "198.51.100.31"] {
        assert!(
            !text.contains(withheld),
            "lean log held a peer or buddy address:\n{text}"
        );
    }
}

#[test]
fn the_full_log_adds_the_peer_and_buddy_addresses_to_the_login_steps() {
    let text = login_log(Level::Full);
    for kept in [
        "server.login server=203.0.113.7:4661 step=port_test_arrived admission=test_connection",
        "peer_reach.routed peer=198.51.100.9:4662 route=direct",
        "buddy.dial_failed buddy=198.51.100.23:5731 cause=timed_out",
        "kad.helper_test_late helper=198.51.100.31 late_by_ms=3400 admission=refused",
    ] {
        assert!(text.contains(kept), "full log lost {kept}:\n{text}");
    }
}

#[test]
fn a_level_changed_mid_run_governs_the_next_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = RunLog::open(dir.path(), CAP_BYTES, mpsc::channel().0).expect("open");
    let handle = LevelHandle::new(Level::Lean);
    let subscriber = subscriber(log, EnvFilter::new("info"), handle.clone());
    let peer = CoreEvent::Download(DownloadEvent::PeerSelected {
        download_id: crate::fixture::download_id(1),
        peer: crate::fixture::peer_at(198, 51, 100, 9, 4662),
    });
    tracing::subscriber::with_default(subscriber, || {
        write(&event::record(&peer), handle.get());
        handle.set(Level::Full);
        write(&event::record(&peer), handle.get());
    });
    let text = read(&dir.path().join(FILE_NAME));
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(!lines[0].contains("198.51.100.9"), "{text}");
    assert!(lines[1].contains("198.51.100.9"), "{text}");
}

#[test]
fn a_write_past_the_cap_moves_the_log_aside_and_keeps_one_predecessor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut log = RunLog::open(dir.path(), 10, mpsc::channel().0).expect("open");
    let current = dir.path().join(FILE_NAME);
    let predecessor = dir.path().join(PREDECESSOR_NAME);

    log.write_all(b"first\n").expect("write");
    assert!(!predecessor.exists());

    log.write_all(b"second\n").expect("write");
    assert_eq!(read(&predecessor), "first\n");
    assert_eq!(read(&current), "second\n");

    log.write_all(b"third\n").expect("write");
    assert_eq!(read(&predecessor), "second\n");
    assert_eq!(read(&current), "third\n");
}

#[test]
fn a_later_run_appends_and_counts_what_the_earlier_one_left() {
    let dir = tempfile::tempdir().expect("tempdir");
    let current = dir.path().join(FILE_NAME);
    RunLog::open(dir.path(), 10, mpsc::channel().0)
        .expect("open")
        .write_all(b"early\n")
        .expect("write");

    let mut later = RunLog::open(dir.path(), 10, mpsc::channel().0).expect("reopen");
    later.write_all(b"ok\n").expect("write");
    assert_eq!(read(&current), "early\nok\n");

    later.write_all(b"over\n").expect("write");
    assert_eq!(read(&dir.path().join(PREDECESSOR_NAME)), "early\nok\n");
    assert_eq!(read(&current), "over\n");
}

#[test]
fn an_event_larger_than_the_cap_lands_whole() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut log = RunLog::open(dir.path(), 4, mpsc::channel().0).expect("open");
    log.write_all(b"much longer than four\n").expect("write");
    assert_eq!(read(&dir.path().join(FILE_NAME)), "much longer than four\n");
    assert!(!dir.path().join(PREDECESSOR_NAME).exists());
}

/// A log directory that goes away under a run is told once and the writes
/// after it say nothing more.
#[test]
fn a_write_that_fails_is_told_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (tell, told) = mpsc::channel();
    let mut log = RunLog::open(dir.path(), 1 << 20, tell).expect("open");
    {
        let mut sink = log.sink.lock().expect("sink");
        sink.file = File::open(dir.path().join(FILE_NAME)).expect("read-only handle");
    }
    assert!(log.write_all(b"one\n").is_err());
    assert!(log.write_all(b"two\n").is_err());
    assert!(matches!(told.try_recv(), Ok(RunLogFailure::Write { .. })));
    assert!(told.try_recv().is_err(), "told once");
}

/// A rotation that cannot rename leaves the log growing, not ended.
#[test]
fn a_failed_rotation_keeps_the_log_going_and_is_told() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (tell, told) = mpsc::channel();
    let mut log = RunLog::open(dir.path(), 10, tell).expect("open");
    // A directory in the predecessor's place makes the rename fail.
    std::fs::create_dir(dir.path().join(PREDECESSOR_NAME)).expect("blocker");
    std::fs::write(dir.path().join(PREDECESSOR_NAME).join("keep"), b"x").expect("occupied");
    log.write_all(b"first\n").expect("write");
    log.write_all(b"second\n").expect("write past the cap");
    assert_eq!(read(&dir.path().join(FILE_NAME)), "first\nsecond\n");
    assert!(matches!(told.try_recv(), Ok(RunLogFailure::Rotate { .. })));
}

/// A refusal is paid for once per cap of growth: the writes after a failed
/// rotation do not try the rename again until the file has grown by another
/// cap, and the rotation that then succeeds is the ordinary one.
#[test]
fn a_failed_rotation_is_not_tried_again_on_every_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut log = RunLog::open(dir.path(), 10, mpsc::channel().0).expect("open");
    let blocker = dir.path().join(PREDECESSOR_NAME);
    std::fs::create_dir(&blocker).expect("blocker");
    std::fs::write(blocker.join("keep"), b"x").expect("occupied");
    log.write_all(b"first\n").expect("write");
    log.write_all(b"second\n").expect("the rotation fails here");

    // The way is clear again, but the failed try is not repeated while the
    // file has grown by less than a cap.
    std::fs::remove_file(blocker.join("keep")).expect("clear");
    std::fs::remove_dir(&blocker).expect("clear");
    log.write_all(b"third\n").expect("write");
    assert!(!blocker.exists(), "no retry before another cap of growth");
    assert_eq!(read(&dir.path().join(FILE_NAME)), "first\nsecond\nthird\n");

    // A cap's worth later it is tried again, and lands.
    log.write_all(b"fourth\n").expect("write");
    assert_eq!(read(&blocker), "first\nsecond\nthird\n");
    assert_eq!(read(&dir.path().join(FILE_NAME)), "fourth\n");
}
