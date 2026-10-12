//! The Managed Server List (ADR-0080) on `rmule-store`: the
//! [`ServerListStore`] half of [`DurableAppConfig`].
//!
//! The row is keyed by a monotonic sequence number rather than by its
//! endpoint, because the seam promises *insertion* order — aMule appends
//! fresh servers and leaves installed ones where they are — and a key ordered
//! by host would reshuffle the list on every install. The endpoint is a
//! unique index instead, which is what makes a merge, a removal and the three
//! operator mutators one index probe each rather than a scan.

use std::net::Ipv4Addr;

use rmule_ed2k::ServerPriority;
use rmule_primitives::{Ed2kText, ServerEndpoint, ServerTcpFlags, ServerUdpFlags};
use rmule_store::{Indexed, Readable, Record, Schema, Sequence, StoreError, UniqueIndex};
use serde::{Deserialize, Serialize};

use crate::CoreError;
use crate::server_list::{
    ManagedServer, ServerAuxPorts, ServerFigures, ServerGrantsReport, ServerListStore, ServerMerge,
    ServerUdpCrypt,
};

use super::DurableAppConfig;

mod rung;

#[cfg(test)]
pub(super) use rung::{add_v1, schema_v1, schema_v13};
pub(crate) use rung::{grow_from_v8, grow_from_v9, grow_from_v11, grow_from_v13};

/// One managed-server row. The priority is stored as aMule's raw
/// `ST_PREFERENCE` word — the same mapping the wire uses, which
/// [`ServerPriority::from_raw`] is defined to round-trip — so the eD2k crate
/// needs no serde of its own for a three-valued enum.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct ServerRecord {
    endpoint: ServerEndpoint,
    name: Ed2kText,
    description: Ed2kText,
    priority: u32,
    is_static: bool,
    fail_count: u32,
    /// What the server last reported and when: kept since store
    /// version 9.
    figures: Option<FiguresRecord>,
    /// What the server granted at its last login and when: kept since store
    /// version 10.
    grants: Option<GrantsRecord>,
    /// How to key UDP to the server, as its last status answer said: kept
    /// since store version 12.
    udp_crypt: Option<UdpCryptRecord>,
    /// The standard port and aux-ports list of a row dialed on another port:
    /// kept since store version 14.
    aux_ports: Option<AuxPortsRecord>,
    /// The UDP flags word a server.met row named for a server with no dated
    /// figures: kept since store version 14.
    listed_udp_flags: Option<u32>,
}

impl Record for ServerRecord {
    const NAME: &'static str = "app_config.server";
    const VERSION: u32 = 5;
}

/// A server's aux-ports relation as the row keeps it.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct AuxPortsRecord {
    standard_port: u16,
    ports: Vec<u16>,
}

impl From<ServerAuxPorts> for AuxPortsRecord {
    fn from(aux: ServerAuxPorts) -> Self {
        Self {
            standard_port: aux.standard_port,
            ports: aux.ports,
        }
    }
}

impl From<AuxPortsRecord> for ServerAuxPorts {
    fn from(record: AuxPortsRecord) -> Self {
        Self {
            standard_port: record.standard_port,
            ports: record.ports,
        }
    }
}

/// A server's UDP crypt facts as the row keeps them (ADR-0052).
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct UdpCryptRecord {
    obfuscation_udp_port: u16,
    obfuscation_tcp_port: u16,
    udp_key: u32,
    key_ip: Option<Ipv4Addr>,
}

impl From<ServerUdpCrypt> for UdpCryptRecord {
    fn from(crypt: ServerUdpCrypt) -> Self {
        Self {
            obfuscation_udp_port: crypt.obfuscation_udp_port,
            obfuscation_tcp_port: crypt.obfuscation_tcp_port,
            udp_key: crypt.udp_key,
            key_ip: crypt.key_ip,
        }
    }
}

impl From<UdpCryptRecord> for ServerUdpCrypt {
    fn from(record: UdpCryptRecord) -> Self {
        Self {
            obfuscation_udp_port: record.obfuscation_udp_port,
            obfuscation_tcp_port: record.obfuscation_tcp_port,
            udp_key: record.udp_key,
            key_ip: record.key_ip,
        }
    }
}

/// A server's grants report as the row keeps it.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct GrantsRecord {
    tcp_flags: u32,
    reported_at: u64,
}

/// A server's figures as the row keeps them: the ping in whole milliseconds.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct FiguresRecord {
    answered_at: u64,
    ping_ms: Option<u64>,
    users: Option<u32>,
    files: Option<u32>,
    soft_files: Option<u32>,
    hard_files: Option<u32>,
    version: Option<String>,
    /// Kept since store version 10.
    udp_flags: Option<u32>,
}

impl From<ServerFigures> for FiguresRecord {
    fn from(figures: ServerFigures) -> Self {
        Self {
            answered_at: figures.answered_at,
            ping_ms: figures
                .ping
                .map(|ping| u64::try_from(ping.as_millis()).unwrap_or(u64::MAX)),
            users: figures.users,
            files: figures.files,
            soft_files: figures.soft_files,
            hard_files: figures.hard_files,
            version: figures.version,
            udp_flags: figures.udp_flags.map(ServerUdpFlags::bits),
        }
    }
}

impl From<FiguresRecord> for ServerFigures {
    fn from(record: FiguresRecord) -> Self {
        Self {
            answered_at: record.answered_at,
            ping: record.ping_ms.map(std::time::Duration::from_millis),
            users: record.users,
            files: record.files,
            soft_files: record.soft_files,
            hard_files: record.hard_files,
            version: record.version,
            udp_flags: record.udp_flags.map(ServerUdpFlags::from_bits),
        }
    }
}

impl From<ManagedServer> for ServerRecord {
    fn from(server: ManagedServer) -> Self {
        Self {
            endpoint: server.endpoint,
            name: server.name,
            description: server.description,
            priority: server.priority.to_raw(),
            is_static: server.is_static,
            fail_count: server.fail_count,
            figures: server.figures.map(FiguresRecord::from),
            grants: server.grants.map(|report| GrantsRecord {
                tcp_flags: report.tcp_flags.bits(),
                reported_at: report.reported_at,
            }),
            udp_crypt: server.udp_crypt.map(UdpCryptRecord::from),
            aux_ports: server.aux_ports.map(AuxPortsRecord::from),
            listed_udp_flags: server.listed_udp_flags.map(ServerUdpFlags::bits),
        }
    }
}

impl From<ServerRecord> for ManagedServer {
    fn from(record: ServerRecord) -> Self {
        Self {
            endpoint: record.endpoint,
            name: record.name,
            description: record.description,
            priority: ServerPriority::from_raw(record.priority),
            is_static: record.is_static,
            fail_count: record.fail_count,
            figures: record.figures.map(ServerFigures::from),
            grants: record.grants.map(|record| ServerGrantsReport {
                tcp_flags: ServerTcpFlags::from_bits(record.tcp_flags),
                reported_at: record.reported_at,
            }),
            udp_crypt: record.udp_crypt.map(ServerUdpCrypt::from),
            aux_ports: record.aux_ports.map(ServerAuxPorts::from),
            listed_udp_flags: record.listed_udp_flags.map(ServerUdpFlags::from_bits),
        }
    }
}

/// The list key: the canonical host text and the port, so one endpoint can
/// hold at most one row in the list.
static ENDPOINT: UniqueIndex<(&'static str, u16), u64, ServerRecord> =
    UniqueIndex::new("app_config.server.endpoint", |record| {
        (record.endpoint.host(), record.endpoint.port())
    });

pub(super) static SERVERS: Indexed<u64, ServerRecord> =
    Indexed::new(ServerRecord::NAME, &[&ENDPOINT]);

/// The counter handing out server-row keys. Strictly increasing and never
/// reused, so list order is insertion order for the life of the file.
static SERVER_IDS: Sequence = Sequence::new("app_config.server");

/// The tables this half of the seam owns, merged into [`super::schema`].
pub(super) fn schema() -> Schema {
    Schema::new().indexed(&SERVERS)
}

/// The row holding `endpoint` with its key, or `None` when the list has no
/// such row — the one probe behind the merge, the removal and the three
/// operator mutators.
fn row_at(
    txn: &impl Readable,
    endpoint: &ServerEndpoint,
) -> Result<Option<(u64, ServerRecord)>, StoreError> {
    let Some(key) = SERVERS.by_unique(txn, &ENDPOINT, (endpoint.host(), endpoint.port()))? else {
        return Ok(None);
    };
    Ok(SERVERS.get(txn, &key)?.map(|record| (key, record)))
}

/// The row listed under `standard` as its standard endpoint, for a row not
/// keyed by it — a scan, because only rows dialed on an aux port are listed
/// under a port other than their key's, and the list is small.
fn row_by_standard(
    txn: &impl Readable,
    standard: &ServerEndpoint,
) -> Result<Option<(u64, ServerRecord)>, StoreError> {
    Ok(SERVERS.iter(txn)?.into_iter().find(|(_, record)| {
        let listed = ManagedServer::from(record.clone());
        &listed.standard_endpoint() == standard
    }))
}

impl DurableAppConfig {
    /// Apply `edit` to the row holding `endpoint`, reporting whether it was
    /// there — the shared body of the three operator mutators, whose only
    /// difference is the field.
    fn edit_server(
        &self,
        endpoint: &ServerEndpoint,
        edit: impl FnOnce(&mut ServerRecord),
    ) -> Result<bool, CoreError> {
        self.store.write::<_, CoreError>(|txn| {
            let Some((key, mut record)) = row_at(txn, endpoint)? else {
                return Ok(false);
            };
            edit(&mut record);
            SERVERS.put(txn, &key, &record)?;
            Ok(true)
        })
    }
}

impl ServerListStore for DurableAppConfig {
    fn servers(&self) -> Result<Vec<ManagedServer>, CoreError> {
        let rows = self
            .store
            .read::<_, CoreError>(|txn| Ok(SERVERS.iter(txn)?))?;
        Ok(rows
            .into_iter()
            .map(|(_, record)| ManagedServer::from(record))
            .collect())
    }

    fn merge_server(&self, server: ManagedServer) -> Result<ServerMerge, CoreError> {
        self.store.write(|txn| {
            // A row is found by the endpoint it is dialed on, and failing
            // that by the standard endpoint it is listed under: a downloaded
            // row names a server by its standard port, aMule's dedup key
            // (`ServerList.cpp:223-237`), which an aux-port row is not keyed
            // by.
            let found = match row_at(txn, &server.endpoint)? {
                Some(found) => Some(found),
                None => row_by_standard(txn, &server.standard_endpoint())?,
            };
            match found {
                // The fold (ADR-0080) is the model's own rather than this seam's,
                // so what a downloaded row may touch is decided in one place: the
                // name always, the description when non-empty, and never the
                // priority, the static pin or the failure tally.
                Some((key, installed)) => {
                    let mut folded = ManagedServer::from(installed);
                    folded.fold(server);
                    SERVERS.put(txn, &key, &ServerRecord::from(folded))?;
                    Ok(ServerMerge::Updated)
                }
                None => {
                    let key = SERVER_IDS.next(txn)?;
                    SERVERS.insert(txn, &key, &ServerRecord::from(server))?;
                    Ok(ServerMerge::Added)
                }
            }
        })
    }

    fn remove_server(&self, endpoint: &ServerEndpoint) -> Result<bool, CoreError> {
        self.store.write(|txn| {
            let Some(key) =
                SERVERS.by_unique(txn, &ENDPOINT, (endpoint.host(), endpoint.port()))?
            else {
                return Ok(false);
            };
            Ok(SERVERS.remove(txn, &key)?.is_some())
        })
    }

    fn set_server_priority(
        &self,
        endpoint: &ServerEndpoint,
        priority: ServerPriority,
    ) -> Result<bool, CoreError> {
        self.edit_server(endpoint, |record| record.priority = priority.to_raw())
    }

    fn set_server_static(
        &self,
        endpoint: &ServerEndpoint,
        is_static: bool,
    ) -> Result<bool, CoreError> {
        self.edit_server(endpoint, |record| record.is_static = is_static)
    }

    fn set_server_fail_count(
        &self,
        endpoint: &ServerEndpoint,
        fail_count: u32,
    ) -> Result<bool, CoreError> {
        self.edit_server(endpoint, |record| record.fail_count = fail_count)
    }

    /// The read and the write are the one `edit_server` transaction, so the
    /// tally a sweep adds to is the tally it writes back — no window between
    /// them for a second failure, a login's absolution or a merge to land in.
    /// Saturating rather than wrapping: a server that has been unreachable
    /// `u32::MAX` times is no less unreachable on the next ping.
    fn count_server_failure(&self, endpoint: &ServerEndpoint) -> Result<bool, CoreError> {
        self.edit_server(endpoint, |record| {
            record.fail_count = record.fail_count.saturating_add(1);
        })
    }

    fn set_server_grants(
        &self,
        endpoint: &ServerEndpoint,
        report: ServerGrantsReport,
    ) -> Result<bool, CoreError> {
        self.edit_server(endpoint, |record| {
            record.grants = Some(GrantsRecord {
                tcp_flags: report.tcp_flags.bits(),
                reported_at: report.reported_at,
            });
        })
    }

    fn set_server_standard_port(
        &self,
        endpoint: &ServerEndpoint,
        standard_port: u16,
    ) -> Result<bool, CoreError> {
        self.store.write::<_, CoreError>(|txn| {
            let Some((key, record)) = row_at(txn, endpoint)? else {
                return Ok(false);
            };
            let mut row = ManagedServer::from(record);
            let Some(aux) = ServerAuxPorts::from_login(
                row.aux_ports.as_ref(),
                row.endpoint.port(),
                standard_port,
            ) else {
                return Ok(true);
            };
            row.aux_ports = Some(aux);
            // The standard endpoint may already be a row of its own: the
            // server was listed before it was dialed on an aux port.
            let standard = row.standard_endpoint();
            if let Some((other, listed)) = row_at(txn, &standard)?
                && other != key
            {
                SERVERS.remove(txn, &other)?;
                row.absorb(ManagedServer::from(listed));
            }
            SERVERS.put(txn, &key, &ServerRecord::from(row))?;
            Ok(true)
        })
    }

    fn set_server_obfuscation_tcp_port(
        &self,
        endpoint: &ServerEndpoint,
        port: u16,
    ) -> Result<bool, CoreError> {
        self.edit_server(endpoint, |record| {
            record
                .udp_crypt
                .get_or_insert_with(|| ServerUdpCrypt::from_tcp_port(port).into())
                .obfuscation_tcp_port = port;
        })
    }

    fn set_server_udp_crypt(
        &self,
        endpoint: &ServerEndpoint,
        crypt: Option<ServerUdpCrypt>,
    ) -> Result<bool, CoreError> {
        self.edit_server(endpoint, |record| {
            record.udp_crypt = crypt.map(UdpCryptRecord::from);
        })
    }

    fn edit_server_figures(
        &self,
        endpoint: &ServerEndpoint,
        edit: &mut dyn FnMut(&mut Option<ServerFigures>),
    ) -> Result<bool, CoreError> {
        self.edit_server(endpoint, |record| {
            let mut figures = record.figures.take().map(ServerFigures::from);
            edit(&mut figures);
            record.figures = figures.map(FiguresRecord::from);
        })
    }
}
