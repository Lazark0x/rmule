//! **How an older store's server rows climb** (ADR-0083's ladder): the row
//! shapes older store versions wrote, the server list's half of the 8 → 9
//! rung, which gives every row an empty set of figures, the 9 → 10 rung,
//! which gives every row no grants report and its figures no UDP flags, the
//! 11 → 12 rung, which gives every row no UDP crypt facts, the 13 → 14
//! rung, which gives every row no aux-ports list, and the server list's
//! half of the 14 → 15 rung, which splits the figures' one date into the
//! status answer's and the counts'.

use rmule_primitives::{Ed2kText, ServerEndpoint};
use rmule_store::redb::TableDefinition;
use rmule_store::{Indexed, Packed, Record, StoreError, WriteTransaction};
use serde::{Deserialize, Serialize};

use super::{AuxPortsRecord, FiguresRecord, GrantsRecord, SERVERS, ServerRecord, UdpCryptRecord};

#[cfg(test)]
mod tests;

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
    pub(super) figures: Option<FiguresRecordV3>,
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
            figures: row.figures.map(|figures| FiguresRecordV3 {
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
    pub(super) figures: Option<FiguresRecordV3>,
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
/// port until a login or a downloaded list says otherwise. Written in
/// version 14's shape, so the 14 → 15 rung finds what it reads.
pub(crate) fn grow_from_v13(txn: &WriteTransaction) -> Result<(), StoreError> {
    let old = SERVERS_V4.iter(txn)?;
    txn.delete_table(TableDefinition::<u64, Packed<ServerRecordV4>>::new(
        "app_config.server",
    ))?;
    SERVERS_V5.create(txn)?;
    for (key, row) in old {
        let grown = ServerRecordV5 {
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
        SERVERS_V5.set(txn, &key, &grown)?;
    }
    Ok(())
}

/// The figures as record versions 3 to 5 (store versions 10 to 14) kept
/// them: one date for the status answer and the counts alike.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct FiguresRecordV3 {
    pub(super) answered_at: u64,
    pub(super) ping_ms: Option<u64>,
    pub(super) users: Option<u32>,
    pub(super) files: Option<u32>,
    pub(super) soft_files: Option<u32>,
    pub(super) hard_files: Option<u32>,
    pub(super) version: Option<String>,
    pub(super) udp_flags: Option<u32>,
}

impl FiguresRecordV3 {
    /// The one date split in two. It is a status answer's when the figures
    /// hold what only a status answer leaves — a round trip or a UDP flags
    /// word — else it is the date a login's counts were written under. The
    /// counts take it whenever there are counts: a later login report kept
    /// no date of its own, so the older bound is the honest one.
    fn split(self) -> FiguresRecord {
        let answered = self.ping_ms.is_some() || self.udp_flags.is_some();
        let counted = self.users.is_some() || self.files.is_some();
        FiguresRecord {
            answered_at: answered.then_some(self.answered_at),
            counted_at: counted.then_some(self.answered_at),
            ping_ms: self.ping_ms,
            users: self.users,
            files: self.files,
            soft_files: self.soft_files,
            hard_files: self.hard_files,
            version: self.version,
            udp_flags: self.udp_flags,
        }
    }
}

/// The row as record version 5 (store version 14) wrote it, before its
/// figures dated the status answer apart from the counts.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ServerRecordV5 {
    pub(super) endpoint: ServerEndpoint,
    pub(super) name: Ed2kText,
    pub(super) description: Ed2kText,
    pub(super) priority: u32,
    pub(super) is_static: bool,
    pub(super) fail_count: u32,
    pub(super) figures: Option<FiguresRecordV3>,
    pub(super) grants: Option<GrantsRecord>,
    pub(super) udp_crypt: Option<UdpCryptRecord>,
    pub(super) aux_ports: Option<AuxPortsRecord>,
    pub(super) listed_udp_flags: Option<u32>,
}

impl Record for ServerRecordV5 {
    const NAME: &'static str = "app_config.server";
    const VERSION: u32 = 5;
}

/// An index-free view of the version-14 table, for the same reason as
/// [`SERVERS_V1`].
pub(super) static SERVERS_V5: Indexed<u64, ServerRecordV5> = Indexed::new("app_config.server", &[]);

/// The server list's half of store version 14 → 15 (ADR-0080): every row
/// keeps what it had, its figures' one date split into the status answer's
/// and the counts' ([`FiguresRecordV3::split`]), so a server only a login
/// reported on stops reading as answered and the next sweep makes its first
/// contact.
pub(crate) fn grow_from_v14(txn: &WriteTransaction) -> Result<(), StoreError> {
    let old = SERVERS_V5.iter(txn)?;
    txn.delete_table(TableDefinition::<u64, Packed<ServerRecordV5>>::new(
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
            figures: row.figures.map(FiguresRecordV3::split),
            grants: row.grants,
            udp_crypt: row.udp_crypt,
            aux_ports: row.aux_ports,
            listed_udp_flags: row.listed_udp_flags,
        };
        SERVERS.set(txn, &key, &grown)?;
    }
    Ok(())
}
