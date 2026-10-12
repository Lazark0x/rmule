//! **How an older store's server rows climb** (ADR-0083's ladder): the row
//! shapes older store versions wrote, the server list's half of the 8 → 9
//! rung, which gives every row an empty set of figures, the 9 → 10 rung,
//! which gives every row no grants report and its figures no UDP flags, the
//! 11 → 12 rung, which gives every row no UDP crypt facts, and the 13 → 14
//! rung, which gives every row no aux-ports list.

use rmule_primitives::{Ed2kText, ServerEndpoint};
use rmule_store::redb::TableDefinition;
use rmule_store::{Indexed, Packed, Record, StoreError, WriteTransaction};
use serde::{Deserialize, Serialize};

use super::{FiguresRecord, GrantsRecord, SERVERS, ServerRecord, UdpCryptRecord};

/// The row as record version 1 wrote it, before the figures were kept.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ServerRecordV1 {
    pub(super) endpoint: ServerEndpoint,
    pub(super) name: Ed2kText,
    pub(super) description: Ed2kText,
    pub(super) priority: u32,
    pub(super) is_static: bool,
    pub(super) fail_count: u32,
}

impl Record for ServerRecordV1 {
    const NAME: &'static str = "app_config.server";
    const VERSION: u32 = 1;
}

/// An index-free view of the old table: the endpoint index is keyed by a
/// value the rung does not change, so its entries stay as they were.
pub(super) static SERVERS_V1: Indexed<u64, ServerRecordV1> = Indexed::new("app_config.server", &[]);

/// The endpoint index as store versions 1 to 8 declared it on the old shape.
#[cfg(test)]
static ENDPOINT_V1: rmule_store::UniqueIndex<(&'static str, u16), u64, ServerRecordV1> =
    rmule_store::UniqueIndex::new("app_config.server.endpoint", |record| {
        (record.endpoint.host(), record.endpoint.port())
    });

#[cfg(test)]
static SERVERS_V1_DECLARED: Indexed<u64, ServerRecordV1> =
    Indexed::new("app_config.server", &[&ENDPOINT_V1]);

/// The server list's table as store versions 1 to 8 declared it, with its
/// endpoint index, for a test that builds an older store.
#[cfg(test)]
pub(in crate::store::app_config) fn schema_v1() -> rmule_store::Schema {
    rmule_store::Schema::new().indexed(&SERVERS_V1_DECLARED)
}

/// Add a static server named `name` at `endpoint`, failed twice, as a
/// store of versions 1 to 8 would have: a key from the list's counter, the
/// row and its endpoint index entry.
///
/// # Errors
/// The store's.
#[cfg(test)]
pub(in crate::store::app_config) fn add_v1(
    txn: &WriteTransaction,
    endpoint: &ServerEndpoint,
    name: &str,
) -> Result<(), StoreError> {
    let key = super::SERVER_IDS.next(txn)?;
    SERVERS_V1_DECLARED.insert(
        txn,
        &key,
        &ServerRecordV1 {
            endpoint: endpoint.clone(),
            name: Ed2kText::from_utf8(name),
            description: Ed2kText::from_utf8(""),
            priority: 1,
            is_static: true,
            fail_count: 2,
        },
    )
}

/// The row as record version 2 (store version 9) wrote it, before it kept
/// the server's grants and UDP flags.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ServerRecordV2 {
    pub(super) endpoint: ServerEndpoint,
    pub(super) name: Ed2kText,
    pub(super) description: Ed2kText,
    pub(super) priority: u32,
    pub(super) is_static: bool,
    pub(super) fail_count: u32,
    pub(super) figures: Option<FiguresRecordV2>,
}

impl Record for ServerRecordV2 {
    const NAME: &'static str = "app_config.server";
    const VERSION: u32 = 2;
}

/// The figures as record version 2 kept them, before the UDP flags.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct FiguresRecordV2 {
    pub(super) answered_at: u64,
    pub(super) ping_ms: Option<u64>,
    pub(super) users: Option<u32>,
    pub(super) files: Option<u32>,
    pub(super) soft_files: Option<u32>,
    pub(super) hard_files: Option<u32>,
    pub(super) version: Option<String>,
}

/// An index-free view of the version-9 table, for the same reason as
/// [`SERVERS_V1`].
pub(super) static SERVERS_V2: Indexed<u64, ServerRecordV2> = Indexed::new("app_config.server", &[]);

/// The server list's half of store version 8 → 9: every row keeps what it
/// had and gains no figures — a row rmule had not kept them for has none to
/// give, and reads as never answered until the sweep reaches it. Written in
/// version 9's shape, so the next rung finds what it reads.
pub(crate) fn grow_from_v8(txn: &WriteTransaction) -> Result<(), StoreError> {
    let old = SERVERS_V1.iter(txn)?;
    txn.delete_table(TableDefinition::<u64, Packed<ServerRecordV1>>::new(
        "app_config.server",
    ))?;
    SERVERS_V2.create(txn)?;
    for (key, row) in old {
        let grown = ServerRecordV2 {
            endpoint: row.endpoint,
            name: row.name,
            description: row.description,
            priority: row.priority,
            is_static: row.is_static,
            fail_count: row.fail_count,
            figures: None,
        };
        SERVERS_V2.set(txn, &key, &grown)?;
    }
    Ok(())
}

/// The row as record version 3 (store versions 10 and 11) wrote it, before
/// it kept the server's UDP crypt facts.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ServerRecordV3 {
    pub(super) endpoint: ServerEndpoint,
    pub(super) name: Ed2kText,
    pub(super) description: Ed2kText,
    pub(super) priority: u32,
    pub(super) is_static: bool,
    pub(super) fail_count: u32,
    pub(super) figures: Option<FiguresRecord>,
    pub(super) grants: Option<GrantsRecord>,
}

impl Record for ServerRecordV3 {
    const NAME: &'static str = "app_config.server";
    const VERSION: u32 = 3;
}

/// An index-free view of the version-10 and -11 table, for the same reason
/// as [`SERVERS_V1`].
pub(super) static SERVERS_V3: Indexed<u64, ServerRecordV3> = Indexed::new("app_config.server", &[]);

/// Store version 9 → 10 (ADR-0080, "What a server grants is durable"):
/// every row keeps what it had, gains no grants report and its figures no
/// UDP flags — a server reads as never logged into until its next login.
/// Written in version 10's shape, so the 11 → 12 rung finds what it reads.
pub(crate) fn grow_from_v9(txn: &WriteTransaction) -> Result<(), StoreError> {
    let old = SERVERS_V2.iter(txn)?;
    txn.delete_table(TableDefinition::<u64, Packed<ServerRecordV2>>::new(
        "app_config.server",
    ))?;
    SERVERS_V3.create(txn)?;
    for (key, row) in old {
        let grown = ServerRecordV3 {
            endpoint: row.endpoint,
            name: row.name,
            description: row.description,
            priority: row.priority,
            is_static: row.is_static,
            fail_count: row.fail_count,
            figures: row.figures.map(|figures| FiguresRecord {
                answered_at: figures.answered_at,
                ping_ms: figures.ping_ms,
                users: figures.users,
                files: figures.files,
                soft_files: figures.soft_files,
                hard_files: figures.hard_files,
                version: figures.version,
                udp_flags: None,
            }),
            grants: None,
        };
        SERVERS_V3.set(txn, &key, &grown)?;
    }
    Ok(())
}

/// Store version 11 → 12 (ADR-0052, "a server's UDP crypt facts are
/// durable"): every row keeps what it had and gains no UDP crypt facts — a
/// server reads as not having said how to key UDP to it until its next
/// status answer. Written in version 12's shape, so the 13 → 14 rung finds
/// what it reads.
pub(crate) fn grow_from_v11(txn: &WriteTransaction) -> Result<(), StoreError> {
    let old = SERVERS_V3.iter(txn)?;
    txn.delete_table(TableDefinition::<u64, Packed<ServerRecordV3>>::new(
        "app_config.server",
    ))?;
    SERVERS_V4.create(txn)?;
    for (key, row) in old {
        let grown = ServerRecordV4 {
            endpoint: row.endpoint,
            name: row.name,
            description: row.description,
            priority: row.priority,
            is_static: row.is_static,
            fail_count: row.fail_count,
            figures: row.figures,
            grants: row.grants,
            udp_crypt: None,
        };
        SERVERS_V4.set(txn, &key, &grown)?;
    }
    Ok(())
}

/// The row as record version 4 (store versions 12 and 13) wrote it, before
/// it kept the server's aux-ports list.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ServerRecordV4 {
    pub(super) endpoint: ServerEndpoint,
    pub(super) name: Ed2kText,
    pub(super) description: Ed2kText,
    pub(super) priority: u32,
    pub(super) is_static: bool,
    pub(super) fail_count: u32,
    pub(super) figures: Option<FiguresRecord>,
    pub(super) grants: Option<GrantsRecord>,
    pub(super) udp_crypt: Option<UdpCryptRecord>,
}

impl Record for ServerRecordV4 {
    const NAME: &'static str = "app_config.server";
    const VERSION: u32 = 4;
}

/// An index-free view of the version-12 and -13 table, for the same reason as
/// [`SERVERS_V1`].
pub(super) static SERVERS_V4: Indexed<u64, ServerRecordV4> = Indexed::new("app_config.server", &[]);

/// The endpoint index as store versions 12 and 13 declared it on the old shape.
#[cfg(test)]
static ENDPOINT_V4: rmule_store::UniqueIndex<(&'static str, u16), u64, ServerRecordV4> =
    rmule_store::UniqueIndex::new("app_config.server.endpoint", |record| {
        (record.endpoint.host(), record.endpoint.port())
    });

#[cfg(test)]
static SERVERS_V4_DECLARED: Indexed<u64, ServerRecordV4> =
    Indexed::new("app_config.server", &[&ENDPOINT_V4]);

/// The server list's table as store versions 12 and 13 declared it, with its
/// endpoint index, for a test that builds an older store.
#[cfg(test)]
pub(in crate::store::app_config) fn schema_v13() -> rmule_store::Schema {
    rmule_store::Schema::new().indexed(&SERVERS_V4_DECLARED)
}

/// Store version 13 → 14 (ADR-0080, "Aux ports"): every row keeps what it
/// had and gains no aux-ports list — a row reads as dialed on its standard
/// port until a login or a downloaded list says otherwise.
pub(crate) fn grow_from_v13(txn: &WriteTransaction) -> Result<(), StoreError> {
    let old = SERVERS_V4.iter(txn)?;
    txn.delete_table(TableDefinition::<u64, Packed<ServerRecordV4>>::new(
        "app_config.server",
    ))?;
    SERVERS.create(txn)?;
    for (key, row) in old {
        let grown = ServerRecord {
            endpoint: row.endpoint,
            name: row.name,
            description: row.description,
            priority: row.priority,
            is_static: row.is_static,
            fail_count: row.fail_count,
            figures: row.figures,
            grants: row.grants,
            udp_crypt: row.udp_crypt,
            aux_ports: None,
            listed_udp_flags: None,
        };
        SERVERS.set(txn, &key, &grown)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
                        figures: Some(FiguresRecord {
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
}
