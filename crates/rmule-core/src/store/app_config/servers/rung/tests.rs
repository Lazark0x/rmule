//! The server rows' climb, rung by rung: each older shape reads back with
//! what it held, and what a later write adds survives a reopen.

use rmule_store::{Ladder, Schema};

use super::*;
use crate::server_list::{ServerFigures, ServerListStore};
use crate::store::DurableStore;
use crate::store::app_config::DurableAppConfig;

/// A version-8 store's server rows climb to version 9 with no
/// figures, keeping everything else; figures written after the rung
/// survive a reopen.
#[test]
fn a_version_eight_server_row_climbs_to_no_figures_and_later_ones_are_kept() {
    let endpoint = ServerEndpoint::new("10.1.2.3", 4661).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(crate::store::DURABLE_STORE_FILE);
    {
        let v8 = DurableStore::open(
            &file,
            &Schema::new().indexed(&SERVERS_V1),
            &Ladder::new(8, &[]),
        )
        .unwrap();
        v8.write(|txn| {
            SERVERS_V1.insert(
                txn,
                &1,
                &ServerRecordV1 {
                    endpoint: endpoint.clone(),
                    name: Ed2kText::from_utf8("kept"),
                    description: Ed2kText::from_utf8(""),
                    priority: 1,
                    is_static: true,
                    fail_count: 3,
                },
            )
        })
        .unwrap();
    }
    let list = DurableAppConfig::new(crate::store::open_durable_store(dir.path()).unwrap());
    let row = list.servers().unwrap().remove(0);
    assert_eq!(
        (row.name.to_display_string(), row.is_static, row.fail_count),
        ("kept".to_string(), true, 3)
    );
    assert_eq!(row.figures, None, "a row kept no figures before the rung");

    let figures = ServerFigures {
        ping: Some(std::time::Duration::from_millis(61)),
        users: Some(5000),
        version: Some("17.15".into()),
        ..ServerFigures::answered(1_700_000_000)
    };
    list.edit_server_figures(&endpoint, &mut |kept| *kept = Some(figures.clone()))
        .unwrap();
    drop(list);
    let reopened = DurableAppConfig::new(crate::store::open_durable_store(dir.path()).unwrap());
    assert_eq!(reopened.servers().unwrap()[0].figures, Some(figures));
}

/// A version-9 store's server rows climb to version 10 keeping their
/// figures, with no grants report and no UDP flags; a report written after
/// the rung survives a reopen.
#[test]
fn a_version_nine_server_row_climbs_to_no_grants_and_later_ones_are_kept() {
    let endpoint = ServerEndpoint::new("203.0.113.71", 4232).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(crate::store::DURABLE_STORE_FILE);
    {
        let v9 = DurableStore::open(
            &file,
            &Schema::new().indexed(&SERVERS_V2),
            &Ladder::new(9, &[]),
        )
        .unwrap();
        v9.write(|txn| {
            SERVERS_V2.insert(
                txn,
                &1,
                &ServerRecordV2 {
                    endpoint: endpoint.clone(),
                    name: Ed2kText::from_utf8("Lugdunum test"),
                    description: Ed2kText::from_utf8(""),
                    priority: 0,
                    is_static: false,
                    fail_count: 4,
                    figures: Some(FiguresRecordV2 {
                        answered_at: 1_700_000_123,
                        ping_ms: Some(83),
                        users: Some(41_207),
                        files: Some(9_880_311),
                        soft_files: Some(1_000),
                        hard_files: Some(1_500),
                        version: Some("17.15".into()),
                    }),
                },
            )
        })
        .unwrap();
    }
    let list = DurableAppConfig::new(crate::store::open_durable_store(dir.path()).unwrap());
    let row = list.servers().unwrap().remove(0);
    assert_eq!(row.fail_count, 4);
    let figures = row.figures.expect("the figures climbed");
    assert_eq!(
        (figures.users, figures.version.as_deref(), figures.udp_flags),
        (Some(41_207), Some("17.15"), None)
    );
    assert_eq!(
        row.grants, None,
        "no server was logged into before the rung"
    );

    let report = crate::server_list::ServerGrantsReport {
        tcp_flags: rmule_ed2k::ServerTcpFlags::from_bits(0x0000_05D9),
        reported_at: 1_700_000_456,
    };
    list.set_server_grants(&endpoint, report).unwrap();
    drop(list);
    let reopened = DurableAppConfig::new(crate::store::open_durable_store(dir.path()).unwrap());
    assert_eq!(reopened.servers().unwrap()[0].grants, Some(report));
}

/// A version-11 store's server rows climb to version 12 keeping their
/// figures and grants, with no UDP crypt facts; facts written after the
/// rung survive a reopen.
#[test]
fn a_version_eleven_server_row_climbs_to_no_udp_crypt_and_later_facts_are_kept() {
    let endpoint = ServerEndpoint::new("203.0.113.72", 4661).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(crate::store::DURABLE_STORE_FILE);
    {
        let v11 = DurableStore::open(
            &file,
            &Schema::new().indexed(&SERVERS_V3),
            &Ladder::new(11, &[]),
        )
        .unwrap();
        v11.write(|txn| {
            SERVERS_V3.insert(
                txn,
                &1,
                &ServerRecordV3 {
                    endpoint: endpoint.clone(),
                    name: Ed2kText::from_utf8("eleven"),
                    description: Ed2kText::from_utf8(""),
                    priority: 0,
                    is_static: true,
                    fail_count: 1,
                    figures: Some(FiguresRecordV3 {
                        answered_at: 1_700_000_321,
                        ping_ms: Some(40),
                        users: Some(12),
                        files: Some(34),
                        soft_files: None,
                        hard_files: None,
                        version: None,
                        udp_flags: Some(0x17FB),
                    }),
                    grants: Some(GrantsRecord {
                        tcp_flags: 0x0000_05D9,
                        reported_at: 1_700_000_400,
                    }),
                },
            )
        })
        .unwrap();
    }
    let list = DurableAppConfig::new(crate::store::open_durable_store(dir.path()).unwrap());
    let row = list.servers().unwrap().remove(0);
    assert_eq!((row.is_static, row.fail_count), (true, 1));
    assert_eq!(
        row.figures
            .and_then(|figures| figures.udp_flags)
            .map(rmule_ed2k::ServerUdpFlags::bits),
        Some(0x17FB)
    );
    assert_eq!(
        row.grants.map(|report| report.tcp_flags.bits()),
        Some(0x0000_05D9)
    );
    assert_eq!(
        row.udp_crypt, None,
        "no answer was kept for before the rung"
    );

    let crypt = crate::server_list::ServerUdpCrypt {
        obfuscation_udp_port: 4673,
        obfuscation_tcp_port: 4674,
        udp_key: 0xABCD_1234,
        key_ip: Some(std::net::Ipv4Addr::new(198, 51, 100, 7)),
    };
    list.set_server_udp_crypt(&endpoint, Some(crypt)).unwrap();
    drop(list);
    let reopened = DurableAppConfig::new(crate::store::open_durable_store(dir.path()).unwrap());
    assert_eq!(reopened.servers().unwrap()[0].udp_crypt, Some(crypt));
}

/// A version-13 store's server rows climb to version 14 keeping everything
/// they held, with no aux-ports list; a standard port learned after the
/// rung survives a reopen.
#[test]
fn a_version_thirteen_server_row_climbs_to_no_aux_ports_and_a_later_one_is_kept() {
    let endpoint = ServerEndpoint::new("203.0.113.73", 4232).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(crate::store::DURABLE_STORE_FILE);
    let crypt = UdpCryptRecord {
        obfuscation_udp_port: 4673,
        obfuscation_tcp_port: 4674,
        udp_key: 0xABCD_1234,
        key_ip: Some(std::net::Ipv4Addr::new(198, 51, 100, 7)),
    };
    {
        let v13 = DurableStore::open(
            &file,
            &Schema::new().indexed(&SERVERS_V4),
            &Ladder::new(13, &[]),
        )
        .unwrap();
        v13.write(|txn| {
            SERVERS_V4.insert(
                txn,
                &1,
                &ServerRecordV4 {
                    endpoint: endpoint.clone(),
                    name: Ed2kText::from_utf8("thirteen"),
                    description: Ed2kText::from_utf8(""),
                    priority: 1,
                    is_static: true,
                    fail_count: 2,
                    figures: None,
                    grants: None,
                    udp_crypt: Some(crypt),
                },
            )
        })
        .unwrap();
    }
    let list = DurableAppConfig::new(crate::store::open_durable_store(dir.path()).unwrap());
    let row = list.servers().unwrap().remove(0);
    assert_eq!(
        (row.endpoint.clone(), row.is_static, row.fail_count),
        (endpoint.clone(), true, 2)
    );
    assert_eq!(row.udp_crypt, Some(crypt.into()));
    assert_eq!(row.aux_ports, None, "no list was kept before the rung");

    list.set_server_standard_port(&endpoint, 4661).unwrap();
    drop(list);
    let reopened = DurableAppConfig::new(crate::store::open_durable_store(dir.path()).unwrap());
    let aux = reopened.servers().unwrap()[0].aux_ports.clone().unwrap();
    assert_eq!((aux.standard_port, aux.ports), (4661, vec![4232]));
}

/// One version-14 row's bytes: what the frozen shape writes, so the rung
/// reads the very encoding store version 14 left on disk.
fn v14_row(figures: Option<FiguresRecordV3>) -> ServerRecordV5 {
    ServerRecordV5 {
        endpoint: ServerEndpoint::new("203.0.113.74", 4661).unwrap(),
        name: Ed2kText::from_utf8("fourteen"),
        description: Ed2kText::from_utf8(""),
        priority: 0,
        is_static: false,
        fail_count: 0,
        figures,
        grants: None,
        udp_crypt: None,
        aux_ports: None,
        listed_udp_flags: None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The frozen version-5 row encodes as store version 14 wrote it, and the
/// version-6 figures add the second date after the first, each an option:
/// the bytes are pinned, so neither shape can drift under a stored row.
#[test]
fn the_frozen_version_five_row_and_the_version_six_figures_encode_as_pinned() {
    let frozen = v14_row(Some(FiguresRecordV3 {
        answered_at: 1_700_000_500,
        ping_ms: Some(40),
        users: Some(12),
        files: Some(34),
        soft_files: None,
        hard_files: None,
        version: None,
        udp_flags: Some(0x17FB),
    }));
    assert_eq!(
        hex(&postcard::to_allocvec(&frozen).unwrap()),
        "0c3230332e302e3131332e3734b52408666f75727465656e0000000001f4e5cfaa060128010c012200000001fb2f00000000"
    );
    let figures = FiguresRecord {
        answered_at: None,
        counted_at: Some(1_700_000_500),
        ping_ms: None,
        users: Some(12),
        files: Some(34),
        soft_files: None,
        hard_files: None,
        version: None,
        udp_flags: None,
    };
    assert_eq!(
        hex(&postcard::to_allocvec(&figures).unwrap()),
        "0001f4e5cfaa0600010c012200000000"
    );
}

/// A version-14 store's server rows climb to version 15 with the one date
/// split: figures that hold a round trip keep it as the status answer's
/// date and the counts', figures a login alone wrote keep it as the counts'
/// only — so that row reads as never answered — and a row with no figures
/// stays without.
#[test]
fn a_version_fourteen_server_row_climbs_to_a_status_date_apart_from_the_counts() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(crate::store::DURABLE_STORE_FILE);
    let pinged = ServerEndpoint::new("203.0.113.75", 4661).unwrap();
    let logged_in = ServerEndpoint::new("203.0.113.76", 4661).unwrap();
    let bare = ServerEndpoint::new("203.0.113.77", 4661).unwrap();
    let figures = |ping_ms: Option<u64>| FiguresRecordV3 {
        answered_at: 1_700_000_600,
        ping_ms,
        users: Some(41_207),
        files: Some(9_880_311),
        soft_files: None,
        hard_files: None,
        version: Some("17.15".into()),
        udp_flags: None,
    };
    {
        let v14 = DurableStore::open(
            &file,
            &Schema::new().indexed(&SERVERS_V5),
            &Ladder::new(14, &[]),
        )
        .unwrap();
        v14.write(|txn| {
            for (key, endpoint, row_figures) in [
                (1, &pinged, Some(figures(Some(83)))),
                (2, &logged_in, Some(figures(None))),
                (3, &bare, None),
            ] {
                let mut row = v14_row(row_figures);
                row.endpoint = endpoint.clone();
                SERVERS_V5.insert(txn, &key, &row)?;
            }
            Ok::<_, StoreError>(())
        })
        .unwrap();
    }
    let list = DurableAppConfig::new(crate::store::open_durable_store(dir.path()).unwrap());
    let rows = list.servers().unwrap();
    let dates = |at: usize| {
        rows[at]
            .figures
            .as_ref()
            .map(|figures| (figures.answered_at, figures.counted_at))
    };
    assert_eq!(dates(0), Some((Some(1_700_000_600), Some(1_700_000_600))));
    assert_eq!(
        dates(1),
        Some((None, Some(1_700_000_600))),
        "a login's counts were never a status answer"
    );
    assert_eq!(dates(2), None);
    assert_eq!(
        rows[1].figures.as_ref().and_then(|f| f.version.as_deref()),
        Some("17.15")
    );

    let fresh = ServerFigures {
        ping: Some(std::time::Duration::from_millis(50)),
        ..ServerFigures::reported(1_700_000_700)
    };
    list.edit_server_figures(&bare, &mut |kept| *kept = Some(fresh.clone()))
        .unwrap();
    drop(list);
    let reopened = DurableAppConfig::new(crate::store::open_durable_store(dir.path()).unwrap());
    assert_eq!(reopened.servers().unwrap()[2].figures, Some(fresh));
}
