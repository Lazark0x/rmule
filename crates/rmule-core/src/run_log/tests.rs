//! The Run Log by content: what each level writes into the file for each
//! event, through the real subscriber.

use std::path::Path;

use rmule_primitives::{Ed2kText, Ipv4Endpoint, PeerEndpoint, SearchResult, UserHash};
use tracing_subscriber::EnvFilter;

use super::*;
use crate::{
    CoreEvent, DownloadEvent, DownloadId, DownloadMetadata, ScanEvent, SearchEvent, SearchId,
    ServeEvent, ServerConnectionEvent,
};

mod pinned;

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("log file")
}

/// What lands in a fresh log opened at `level` while `run` writes into it.
fn written(level: Level, run: impl FnOnce(&LevelHandle)) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = RunLog::open(dir.path(), level).expect("open");
    let handle = log.level();
    let subscriber = sink::subscriber(log.file, EnvFilter::new("info"), handle.clone(), None);
    tracing::subscriber::with_default(subscriber, || run(&handle));
    read(&dir.path().join(FILE_NAME))
}

/// Write each of `events` at the level `handle` holds.
fn write_each(events: impl IntoIterator<Item = CoreEvent>, handle: &LevelHandle) {
    for event in events {
        write(&event.record(), handle.get());
    }
}

/// A peer at a full address, for lines that print one.
fn peer_at(a: u8, b: u8, c: u8, d: u8, port: u16) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(std::net::Ipv4Addr::new(a, b, c, d), port))
}

/// A content hash of one repeated byte.
fn file_hash(byte: u8) -> rmule_primitives::FileHash {
    rmule_primitives::FileHash::from_bytes([byte; 16])
}

/// aMule 2.3.3, as its captured hellos name it.
fn amule_233() -> rmule_peer::ClientSoftware {
    crate::diagnostics::client_software(0x0304_0D80, None)
}

/// A search id far above any the process mints.
fn search_id() -> SearchId {
    SearchId::from_u64((1 << 62) + 1)
}

/// A named search result with a reported source count.
fn search_result(name: &str, sources: u32) -> SearchResult {
    SearchResult::new(
        file_hash(0xAB),
        1024,
        vec![Ed2kText::from_utf8(name)],
        Vec::new(),
    )
    .expect("valid result")
    .with_reported_availability(sources)
}

/// The events one session of a client touches: each carries something the
/// lean level must not hold, and most carry something it must.
fn session_events() -> Vec<CoreEvent> {
    let peer = peer_at(198, 51, 100, 9, 4662);
    let hash = file_hash(0xAB);
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
            download_id: DownloadId::from_u64(3),
            file_hash: hash,
            metadata: DownloadMetadata {
                name: Ed2kText::from_utf8("secret holiday film.avi"),
                size: 734_003_200,
                origin: crate::DownloadMetadataOrigin::Link,
            },
            file_path: std::path::PathBuf::from("/home/ann/films/secret holiday film.avi.part"),
        }),
        CoreEvent::Download(DownloadEvent::PeerSelected {
            download_id: DownloadId::from_u64(3),
            peer,
        }),
        CoreEvent::Serve(ServeEvent::UploadSlotGranted {
            peer,
            file_hash: hash,
            software: Some(amule_233()),
            road: crate::GrantRoad::Linked,
        }),
        CoreEvent::Scan(ScanEvent::Declined {
            dir: "/home/ann/private-share".into(),
        }),
        CoreEvent::SecuredIdentityMismatch {
            user_hash: UserHash::from_bytes([0xCD; 16]),
        },
        CoreEvent::PeerReachRouted {
            peer,
            route: crate::PeerReachRoute::Direct { endpoint: peer },
        },
        CoreEvent::Search(SearchEvent::SearchResultsReceived {
            search_id: search_id(),
            results: vec![search_result("what i looked for.avi", 5)],
        }),
    ]
}

/// Write `session_events` through the real subscriber into a fresh log, and
/// return what landed in the file.
fn written_at(level: Level) -> String {
    written(level, |handle| {
        write_each(session_events(), handle);
        tracing::info!("free-form line naming peer 198.51.100.9");
    })
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
        reason: crate::SharesWithheld::RelatedSearchGranted,
    });
    let line = event.record().render(Level::Lean);
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
    let download_id = crate::DownloadId::from_u64(3);
    let ignored = CoreEvent::Download(DownloadEvent::ReaskReplyIgnored {
        download_id,
        peer,
        reason: crate::IgnoredReaskReply::Misframed,
    });
    let ended = CoreEvent::Download(DownloadEvent::DialEnded {
        download_id,
        peer,
        cause: crate::DialEnd::CryptStanceUnknown,
    });
    assert_eq!(
        ignored.record().render(Level::Lean),
        "download.reask_reply_ignored id=3 reason=misframed"
    );
    assert_eq!(
        ended.record().render(Level::Lean),
        "download.dial_ended id=3 cause=crypt_stance_unknown"
    );
    assert!(
        ended
            .record()
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
        "file_path=\"/home/ann/films/secret holiday film.avi.part\"",
        "software=\"amule\" software_version=\"2.3.3\"",
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
/// whose report named the server itself, and a second server whose
/// obfuscated dial failed its handshake and whose plain one never came up,
/// beside a peer's route, a failed buddy dial and a late Kad
/// helper test, whose addresses lean withholds.
fn login_events() -> Vec<CoreEvent> {
    let server = rmule_primitives::ServerEndpoint::new("203.0.113.7", 4661).expect("endpoint");
    let dead = rmule_primitives::ServerEndpoint::new("192.0.2.44", 4242).expect("endpoint");
    let login = |step| CoreEvent::ServerLogin {
        server: server.clone(),
        step,
    };
    vec![
        login(crate::LoginStep::MappingWait {
            port: 4662,
            settled: false,
        }),
        login(crate::LoginStep::LinkChosen {
            link: crate::LoginLink::Obfuscated { port: 4673 },
        }),
        login(crate::LoginStep::LoginSent {
            claim: crate::LoginClaim {
                family: Some(rmule_primitives::AddressFamily::V4),
                tcp_port: 4662,
                client_udp_port: Some(4665),
                kad_udp_port: Some(4673),
                advertised_ipv6: Some("2001:db8::5".parse().expect("ipv6")),
            },
        }),
        login(crate::LoginStep::PortTestAwaited),
        login(crate::LoginStep::PortTestArrived {
            admission: crate::PortTestAdmission::TestConnection,
        }),
        login(crate::LoginStep::PortTestEnded {
            end: crate::PortTestEnd::TesterClosed,
        }),
        login(crate::LoginStep::PortTestEnded {
            end: crate::PortTestEnd::PeerConnectionEnded {
                closed_by: crate::PortTestClosedBy::Peer,
            },
        }),
        login(crate::LoginStep::Answered {
            assignment: crate::IdAssignment {
                client_id: rmule_primitives::ClientId::from_u32(0x0500_71CB),
                address: crate::AssignedAddress::Ours(std::net::Ipv4Addr::new(203, 0, 113, 5)),
                grants: crate::ServerGrants {
                    compression: true,
                    large_files: true,
                    ..crate::ServerGrants::default()
                },
            },
        }),
        login(crate::LoginStep::PortTestWindowClosed { arrived: true }),
        login(crate::LoginStep::PortTestLate {
            late_by: std::time::Duration::from_millis(1_250),
            admission: crate::PortTestLateAdmission::Refused,
        }),
        login(crate::LoginStep::Reassigned {
            assignment: crate::IdAssignment {
                client_id: rmule_primitives::ClientId::from_u32(0x0000_2A17),
                address: crate::AssignedAddress::ServerOwnRefused(std::net::Ipv4Addr::new(
                    203, 0, 113, 7,
                )),
                grants: crate::ServerGrants::default(),
            },
        }),
        CoreEvent::ServerLogin {
            server: dead.clone(),
            step: crate::LoginStep::LinkChosen {
                link: crate::LoginLink::Obfuscated { port: 4254 },
            },
        },
        CoreEvent::ServerLogin {
            server: dead.clone(),
            step: crate::LoginStep::DialFailed {
                cause: crate::DialFailure::CryptHandshake {
                    kind: std::io::ErrorKind::UnexpectedEof,
                },
            },
        },
        CoreEvent::ServerLogin {
            server: dead.clone(),
            step: crate::LoginStep::LinkChosen {
                link: crate::LoginLink::Plain {
                    why: crate::PlainLinkReason::ObfuscatedAttemptFailed,
                },
            },
        },
        CoreEvent::ServerLogin {
            server: dead,
            step: crate::LoginStep::DialFailed {
                cause: crate::DialFailure::Os {
                    kind: std::io::ErrorKind::ConnectionRefused,
                    os_code: Some(61),
                },
            },
        },
        CoreEvent::PeerReachRouted {
            peer: peer_at(198, 51, 100, 9, 4662),
            route: crate::PeerReachRoute::Direct {
                endpoint: peer_at(198, 51, 100, 9, 4662),
            },
        },
        CoreEvent::BuddyDialFailed {
            buddy: rmule_primitives::Ipv4Endpoint::new(
                std::net::Ipv4Addr::new(198, 51, 100, 23),
                5731,
            ),
            cause: crate::BuddyDialFailure::Dial {
                cause: crate::DialFailure::TimedOut,
            },
        },
        CoreEvent::KadHelperTestLate {
            helper: std::net::Ipv4Addr::new(198, 51, 100, 31),
            late_by: std::time::Duration::from_millis(3_400),
            admission: crate::PortTestLateAdmission::Refused,
        },
    ]
}

/// Every login event, written at `level`.
fn login_log(level: Level) -> String {
    written(level, |handle| write_each(login_events(), handle))
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
        "server.login server=192.0.2.44:4242 step=dial_failed cause=os error=connection_refused \
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
        "peer_reach.routed peer=198.51.100.9:4662 route=direct dial=198.51.100.9:4662",
        "buddy.dial_failed buddy=198.51.100.23:5731 cause=timed_out",
        "kad.helper_test_late helper=198.51.100.31 late_by_ms=3400 admission=refused",
    ] {
        assert!(text.contains(kept), "full log lost {kept}:\n{text}");
    }
}

#[test]
fn a_level_changed_mid_run_governs_the_next_line() {
    let peer = CoreEvent::Download(DownloadEvent::PeerSelected {
        download_id: DownloadId::from_u64(1),
        peer: peer_at(198, 51, 100, 9, 4662),
    });
    let text = written(Level::Lean, |handle| {
        write(&peer.record(), handle.get());
        handle.set(Level::Full);
        write(&peer.record(), handle.get());
    });
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(!lines[0].contains("198.51.100.9"), "{text}");
    assert!(lines[1].contains("198.51.100.9"), "{text}");
}

/// What a mirror writes into a buffer the test reads.
#[derive(Clone, Default)]
struct Mirrored(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Mirrored {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("mirror").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Each line without its timestamp.
fn untimed(text: &str) -> Vec<&str> {
    text.lines()
        .map(|line| line.split_once(' ').map_or(line, |(_, rest)| rest))
        .collect()
}

/// The mirror holds every record as the file holds it and the free-form
/// lines too, even where the file, at lean, holds the records alone.
#[test]
fn the_mirror_holds_the_free_form_lines_the_lean_file_leaves_out() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = RunLog::open(dir.path(), Level::Lean).expect("open");
    let mirrored = Mirrored::default();
    let writer = mirrored.clone();
    let mirror = sink::Mirror {
        writer: tracing_subscriber::fmt::writer::BoxMakeWriter::new(move || writer.clone()),
        filter: EnvFilter::new("info"),
    };
    let subscriber = sink::subscriber(log.file, EnvFilter::new("info"), log.level, Some(mirror));
    let peer = CoreEvent::Download(DownloadEvent::PeerSelected {
        download_id: DownloadId::from_u64(1),
        peer: peer_at(198, 51, 100, 9, 4662),
    });
    tracing::subscriber::with_default(subscriber, || {
        write(&peer.record(), Level::Lean);
        tracing::info!("a free-form line");
    });
    let file = read(&dir.path().join(FILE_NAME));
    let mirror = String::from_utf8(mirrored.0.lock().expect("mirror").clone()).expect("utf-8");
    assert_eq!(untimed(&file).len(), 1, "{file}");
    assert!(!file.contains("a free-form line"), "{file}");
    assert_eq!(untimed(&mirror).len(), 2, "{mirror}");
    assert_eq!(untimed(&mirror)[0], untimed(&file)[0], "{mirror}");
    assert!(mirror.contains("a free-form line"), "{mirror}");
}

#[test]
fn a_run_starts_with_its_build_and_says_unknown_for_what_the_build_lacks() {
    assert_eq!(
        run_start("0.1.0", "0123456789ab", "2026-10-08", true).render(Level::Lean),
        "run_start version=0.1.0 commit=0123456789ab dirty=yes committed=2026-10-08"
    );
    assert_eq!(
        run_start("0.1.0", "", "", false).render(Level::Lean),
        "run_start version=0.1.0 commit=unknown dirty=no committed=unknown"
    );
}
