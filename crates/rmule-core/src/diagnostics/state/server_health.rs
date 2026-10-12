//! The server list's health on the level (ADR-0052, "dead servers are
//! marked, never removed"): the policy every row's health is derived under,
//! the swept list the global sweeps read, and whether the Status Ping Sweep
//! last heard nobody at all.
//!
//! The swept list is a projection of the Managed Server List (ADR-0051): every
//! listed server minus the dead, those the IP filter blocks as servers and the
//! connected one, in the list's order, each at the address it is reached at —
//! a row listed by name at its **Resolved Address**, and left out while it has
//! none (ADR-0052's amendment). The level holds those addresses too, so
//! the published rows and the swept list read the same answers. It is re-projected wherever the list,
//! the policy or the session moves, under the level's one lock, so the swept
//! list never reflects a row the published list does not.
//!
//! The level also dates each death (ADR-0052, "Dead since when"): the moment
//! a row's health turned dead, held in memory beside the row.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::Instant;

use rmule_ed2k::ServerUdpFlags;
use rmule_primitives::{Ipv4Endpoint, ServerEndpoint};

use super::{DiagnosticsInner, DiagnosticsState};
use crate::global_sources::SharedServerList;
use crate::ip_filter::SharedIpFilter;
use crate::server_list::{
    DeadSince, ManagedServer, ResolvedAddress, ResolvedAddresses, ServerPolicy, ServerUdpCrypt,
};

/// The health half of the level.
#[derive(Debug, Default)]
pub(super) struct ServerHealthLevel {
    policy: ServerPolicy,
    /// The list the sweeps read and the filter it is projected through.
    /// `None` for a level built without a core.
    swept: Option<(SharedServerList, SharedIpFilter)>,
    /// The sweep dropped a silence because no ping near it was answered, and
    /// has heard no answer since.
    unheard: bool,
    /// What each row listed by name last resolved to.
    resolved: ResolvedAddresses,
    /// When each dead row died: `None` for one already dead when the level
    /// first saw it.
    died: HashMap<ServerEndpoint, Option<Instant>>,
    /// The rows of the last projection, so a row the level already knew is
    /// told apart from one it sees for the first time.
    known: HashSet<ServerEndpoint>,
}

impl ServerHealthLevel {
    pub(super) const fn policy(&self) -> ServerPolicy {
        self.policy
    }

    pub(super) const fn unheard(&self) -> bool {
        self.unheard
    }

    /// What `row`'s name last resolved to; `None` for a row listed by
    /// address and a name never asked.
    pub(super) fn resolved_address(&self, row: &ServerEndpoint) -> Option<ResolvedAddress> {
        self.resolved.of(row)
    }

    /// Publish `rows` to the sweeps without the dead, the IP-filtered and
    /// `connected`, which both sweeps leave to the TCP session
    /// (`SearchList.cpp:907-918`, `DownloadQueue.cpp:1010-1013`). A row listed
    /// by name enters at its resolved address and stays out while it has
    /// none; the filter judges that address as it judges a listed one —
    /// aMule's DynIP exemption (`ServerList.cpp:204`) is about adding a row
    /// whose address is not yet known, and aMule filters the resolved one at
    /// connect (`ServerSocket.cpp:737`). A row's answer leaves with the row.
    /// When `row` died, as of now; `None` while it is not dead.
    pub(super) fn dead_since(&self, row: &ServerEndpoint) -> Option<DeadSince> {
        self.died.get(row).map(|moment| {
            moment.map_or(DeadSince::BeforeThisRun, |at| DeadSince::For(at.elapsed()))
        })
    }

    /// Date every death `rows` show under the policy: a row the level knew
    /// alive dies now; one dead at first sight died before this run, since
    /// only the list read at start can bring a tally (an import's is ours).
    fn date_deaths(&mut self, rows: &[ManagedServer]) {
        let now = Instant::now();
        let dead: HashSet<&ServerEndpoint> = rows
            .iter()
            .filter(|row| self.policy.is_dead(row))
            .map(|row| &row.endpoint)
            .collect();
        self.died.retain(|row, _| dead.contains(row));
        for row in dead {
            if !self.died.contains_key(row) {
                let moment = self.known.contains(row).then_some(now);
                self.died.insert(row.clone(), moment);
            }
        }
        self.known = rows.iter().map(|row| row.endpoint.clone()).collect();
    }

    pub(super) fn project(&mut self, rows: &[ManagedServer], connected: Option<&ServerEndpoint>) {
        self.resolved.keep_only(rows);
        self.date_deaths(rows);
        let Some((swept, ip_filter)) = &self.swept else {
            return;
        };
        let filter = ip_filter.read().expect("ip filter lock");
        let live = rows
            .iter()
            .filter(|row| !self.policy.is_dead(row))
            .filter(|row| connected != Some(&row.endpoint))
            .filter_map(|row| {
                let Some(reached) = self.resolved.udp_endpoint_of(row) else {
                    tracing::debug!(
                        host = %row.endpoint.host(),
                        "a server whose name has no address yet stays out of the swept list"
                    );
                    return None;
                };
                if filter.is_filtered_server(reached.ip) {
                    tracing::debug!(
                        host = %row.endpoint.host(),
                        port = row.endpoint.port(),
                        "an IP-filtered server stays out of the swept list"
                    );
                    return None;
                }
                ServerEndpoint::new(reached.ip.to_string(), reached.port).ok()
            })
            .collect();
        *swept.lock().expect("global source server list") = live;
    }
}

/// The server half of the level in one read: the server a session holds,
/// every listed row with the policy its health is judged under, whether the
/// Status Ping Sweep last heard nobody, and what the session was told of the
/// shares.
pub(crate) struct ServerHalf<'a> {
    pub(crate) connected: Option<&'a ServerEndpoint>,
    pub(crate) servers: &'a [ManagedServer],
    pub(crate) policy: ServerPolicy,
    pub(crate) unheard: bool,
    pub(crate) shares: Option<&'a crate::diagnostics::ShareAnnouncement>,
}

impl DiagnosticsState {
    fn with_health<T>(&self, act: impl FnOnce(&mut DiagnosticsInner) -> T) -> T {
        act(&mut self.inner.lock().expect("diagnostics mutex poisoned"))
    }

    /// A write to the server half landed: wake every subscriber, after the
    /// lock is released, so a reader woken by it reads the write.
    pub(super) fn server_moved(&self) {
        self.server_changes
            .send_modify(|generation| *generation += 1);
    }

    /// Subscribe to the server half of the level: one wake per write to the
    /// managed list, the connected server, the dead-server policy, the Status
    /// Ping Sweep's verdict or the share announcement. It says only that one
    /// was written; the subscriber reads the half again.
    pub(crate) fn server_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.server_changes.subscribe()
    }

    /// Read the server half under one lock.
    pub(crate) fn read_server_half<T>(&self, read: impl FnOnce(ServerHalf<'_>) -> T) -> T {
        self.with_health(|inner| {
            read(ServerHalf {
                connected: inner.connected_server.as_ref(),
                servers: &inner.servers,
                policy: inner.server_health.policy,
                unheard: inner.server_health.unheard,
                shares: inner.share_announcement.as_ref(),
            })
        })
    }

    /// Bind the list the global sweeps read, so the level keeps it a
    /// projection of the published list through `ip_filter`. Installed once
    /// by the actor.
    pub(crate) fn install_swept_servers(&self, swept: SharedServerList, ip_filter: SharedIpFilter) {
        self.with_health(|inner| {
            inner.server_health.swept = Some((swept, ip_filter));
            inner
                .server_health
                .project(&inner.servers, inner.connected_server.as_ref());
        });
    }

    /// Take up `policy`: every row's health is re-derived under it at once.
    pub(crate) fn set_server_policy(&self, policy: ServerPolicy) {
        self.with_health(|inner| {
            inner.server_health.policy = policy;
            inner
                .server_health
                .project(&inner.servers, inner.connected_server.as_ref());
        });
        self.server_moved();
    }

    /// The policy rows are judged under now.
    pub(crate) fn server_policy(&self) -> ServerPolicy {
        self.with_health(|inner| inner.server_health.policy)
    }

    /// What the connected session `server` was told of the share set.
    pub(crate) fn set_share_announcement(
        &self,
        server: &ServerEndpoint,
        shares: crate::diagnostics::SharesToServer,
    ) {
        self.with_health(|inner| {
            inner.share_announcement = Some(crate::diagnostics::ShareAnnouncement {
                server: server.clone(),
                shares,
            });
        });
        self.server_moved();
    }

    /// `row`'s name answered `address` just now: the row and the swept list
    /// take it at once.
    pub(crate) fn record_resolved_address(&self, row: &ServerEndpoint, address: ResolvedAddress) {
        self.with_health(|inner| {
            inner.server_health.resolved.record(row, address);
            let (servers, connected) = (&inner.servers, inner.connected_server.as_ref());
            inner.server_health.project(servers, connected);
        });
    }

    /// `row`'s resolved address when it may be reused without asking its
    /// name again.
    pub(crate) fn fresh_resolved_address(&self, row: &ServerEndpoint) -> Option<Ipv4Addr> {
        self.with_health(|inner| inner.server_health.resolved.fresh(row))
    }

    /// The listed row a server-UDP datagram from `endpoint` answers for: the
    /// row whose UDP endpoint (its reached address on its standard port) it
    /// is, else the address itself.
    pub(crate) fn listed_row_at(&self, endpoint: Ipv4Endpoint) -> Option<ServerEndpoint> {
        self.with_health(|inner| {
            inner.servers.iter().find_map(|row| {
                (inner.server_health.resolved.udp_endpoint_of(row) == Some(endpoint))
                    .then(|| row.endpoint.clone())
            })
        })
        .or_else(|| ServerEndpoint::new(endpoint.ip.to_string(), endpoint.port).ok())
    }

    /// The listed server whose saved obfuscation UDP port `udp_src` is, at
    /// the TCP endpoint its row is reached at, with the **Server UDP Crypt**
    /// and UDP flags its last answer left on the row — how a server this run
    /// has not heard is found by the port `server.met` gave it (ADR-0052's
    /// durable UDP crypt amendment; aMule `ServerList.cpp:643-654`).
    pub(crate) fn saved_udp_crypt_at(
        &self,
        udp_src: Ipv4Endpoint,
    ) -> Option<(Ipv4Endpoint, ServerUdpCrypt, Option<ServerUdpFlags>)> {
        self.with_health(|inner| {
            inner.servers.iter().find_map(|row| {
                let crypt = row.udp_crypt?;
                let reached = inner.server_health.resolved.udp_endpoint_of(row)?;
                (reached.ip == udp_src.ip && crypt.obfuscation_udp_port == udp_src.port).then(
                    || {
                        let flags = row.udp_flags();
                        (reached, crypt, flags)
                    },
                )
            })
        })
    }

    /// The **Server UDP Crypt** and UDP flags of the listed row whose UDP
    /// endpoint (its reached address on its standard port) is `server` — how
    /// a send keys a server this run has not heard (ADR-0052's durable UDP
    /// crypt amendment).
    pub(crate) fn saved_udp_crypt_of(
        &self,
        server: Ipv4Endpoint,
    ) -> Option<(ServerUdpCrypt, Option<ServerUdpFlags>)> {
        self.with_health(|inner| {
            inner.servers.iter().find_map(|row| {
                let crypt = row.udp_crypt?;
                (inner.server_health.resolved.udp_endpoint_of(row) == Some(server))
                    .then(|| (crypt, row.udp_flags()))
            })
        })
    }

    /// Whether a server session is up: the global source sweep asks only
    /// then (ADR-0051's amendment; aMule `DownloadQueue.cpp:870`).
    pub(crate) fn server_session_up(&self) -> bool {
        self.with_health(|inner| inner.connected_server.is_some())
    }

    /// Whether the Status Ping Sweep's latest verdict found nobody answering.
    pub(crate) fn set_status_sweep_unheard(&self, unheard: bool) {
        self.with_health(|inner| inner.server_health.unheard = unheard);
        self.server_moved();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    fn endpoint(host: &str) -> ServerEndpoint {
        ServerEndpoint::new(host, 4661).unwrap()
    }

    fn failed(host: &str, fail_count: u32) -> ManagedServer {
        ManagedServer {
            fail_count,
            ..ManagedServer::listed(endpoint(host))
        }
    }

    fn blocking(texts: &[&[u8]]) -> SharedIpFilter {
        let (filter, _) = crate::ip_filter::IpFilter::from_texts(texts, 127, true, true);
        Arc::new(std::sync::RwLock::new(filter))
    }

    /// The swept list is the published list as it stands: a server added
    /// or imported joins it, a removed one leaves it, the connected one is
    /// out while its session lasts, the dead are passed by and taken back, a
    /// new limit is followed at once, and a server the IP filter blocks never
    /// enters it; a row listed by name waits for its address.
    #[test]
    fn the_swept_list_is_the_managed_list_minus_the_dead_the_filtered_and_the_connected() {
        let level = DiagnosticsState::new();
        let swept: SharedServerList = Arc::new(Mutex::new(Vec::new()));
        level.install_swept_servers(
            swept.clone(),
            blocking(&[b"203.0.113.0-203.0.113.255,0,blocked servers\n".as_slice()]),
        );
        let read = || swept.lock().unwrap().clone();

        level.set_servers(vec![failed("192.0.2.10", 0)]);
        assert_eq!(read(), vec![endpoint("192.0.2.10")]);
        let session = (endpoint("192.0.2.10"), rmule_ed2k::ServerGrants::default());
        level.set_connected_server(Some(session));
        assert!(
            read().is_empty(),
            "the connected server is left to its session"
        );
        level.set_connected_server(None);
        assert_eq!(read(), vec![endpoint("192.0.2.10")]);

        let dns = ManagedServer::listed(ServerEndpoint::new("dyn.example.org", 4661).unwrap());
        level.set_servers(vec![
            failed("192.0.2.10", 3),
            failed("192.0.2.20", 2),
            failed("203.0.113.7", 0),
            dns.clone(),
        ]);
        assert_eq!(
            read(),
            vec![endpoint("192.0.2.20")],
            "the dead and the filtered are out, the added in, the named one waits for its address"
        );
        level.record_resolved_address(
            &dns.endpoint,
            ResolvedAddress::Resolved(Ipv4Addr::new(198, 51, 100, 9)),
        );
        assert_eq!(
            read(),
            vec![endpoint("192.0.2.20"), endpoint("198.51.100.9")]
        );

        level.set_server_policy(ServerPolicy {
            dead_after: 2,
            ..ServerPolicy::default()
        });
        assert_eq!(read(), vec![endpoint("198.51.100.9")]);

        level.set_servers(vec![failed("192.0.2.10", 0), failed("192.0.2.20", 0)]);
        assert_eq!(
            read(),
            vec![endpoint("192.0.2.10"), endpoint("192.0.2.20")],
            "an answer brings both back; the removed rows are swept no more"
        );
    }

    /// A death is dated when the level sees it happen: a row dead in the list
    /// read at start died before this run, one that dies later is dated then,
    /// a lower limit kills at once, and a row that lives again loses its date.
    #[test]
    fn a_death_is_dated_when_the_level_sees_it() {
        let level = DiagnosticsState::new();
        let since = |host: &str| {
            level
                .snapshot()
                .servers
                .into_iter()
                .find(|row| row.server.endpoint == endpoint(host))
                .and_then(|row| row.dead_since)
        };
        level.set_servers(vec![failed("192.0.2.10", 3), failed("192.0.2.20", 2)]);
        assert_eq!(since("192.0.2.10"), Some(DeadSince::BeforeThisRun));
        assert_eq!(since("192.0.2.20"), None);

        level.set_servers(vec![failed("192.0.2.10", 4), failed("192.0.2.20", 3)]);
        assert_eq!(since("192.0.2.10"), Some(DeadSince::BeforeThisRun));
        assert!(matches!(since("192.0.2.20"), Some(DeadSince::For(_))));

        level.set_servers(vec![failed("192.0.2.10", 0), failed("192.0.2.30", 1)]);
        assert_eq!(since("192.0.2.10"), None, "it lives again");
        level.set_server_policy(ServerPolicy {
            dead_after: 1,
            ..ServerPolicy::default()
        });
        assert!(matches!(since("192.0.2.30"), Some(DeadSince::For(_))));
    }

    /// A row an aux-port login re-ported is swept at its standard port, the
    /// one its UDP derives from (`ServerUDPSocket.cpp:363`), and a reply from
    /// that address is the row dialed on the other port.
    #[test]
    fn an_aux_port_row_is_swept_and_answered_at_its_standard_port() {
        let level = DiagnosticsState::new();
        let swept: SharedServerList = Arc::new(Mutex::new(Vec::new()));
        level.install_swept_servers(swept.clone(), blocking(&[]));
        let mut row = ManagedServer::listed(ServerEndpoint::new("192.0.2.10", 5000).unwrap());
        row.aux_ports = Some(crate::server_list::ServerAuxPorts {
            standard_port: 4661,
            ports: vec![5000],
        });
        level.set_servers(vec![row.clone()]);

        assert_eq!(
            swept.lock().unwrap().clone(),
            vec![ServerEndpoint::new("192.0.2.10", 4661).unwrap()]
        );
        assert_eq!(
            level.listed_row_at(rmule_primitives::Ipv4Endpoint::new(
                Ipv4Addr::new(192, 0, 2, 10),
                4661
            )),
            Some(row.endpoint),
        );
    }

    /// A named row enters the swept list at the address its name resolved
    /// to, the IP filter judging that address as it judges a listed one, and
    /// leaves it while its name gives none (ADR-0052's amendment). The
    /// published row keeps its name and carries the answer beside it; a
    /// removed row's answer goes with it.
    #[test]
    fn a_named_row_is_swept_at_its_resolved_address_when_the_filter_admits_it() {
        let level = DiagnosticsState::new();
        let swept: SharedServerList = Arc::new(Mutex::new(Vec::new()));
        level.install_swept_servers(
            swept.clone(),
            blocking(&[b"203.0.113.0-203.0.113.255,0,blocked servers\n".as_slice()]),
        );
        let read = || swept.lock().unwrap().clone();
        let named = ServerEndpoint::new("dyn.example.org", 4661).unwrap();
        level.set_servers(vec![ManagedServer::listed(named.clone())]);
        let published = || level.snapshot().servers[0].clone();

        assert!(read().is_empty(), "no address yet");
        assert_eq!(published().resolved_address, None);

        let resolved = ResolvedAddress::Resolved(Ipv4Addr::new(192, 0, 2, 77));
        level.record_resolved_address(&named, resolved);
        assert_eq!(read(), vec![endpoint("192.0.2.77")]);
        assert_eq!(published().server.endpoint, named, "the key stays the name");
        assert_eq!(published().resolved_address, Some(resolved));
        assert_eq!(
            level.listed_row_at(rmule_primitives::Ipv4Endpoint::new(
                Ipv4Addr::new(192, 0, 2, 77),
                4661
            )),
            Some(named.clone()),
            "a reply from the address is the named row's"
        );

        level.record_resolved_address(
            &named,
            ResolvedAddress::Resolved(Ipv4Addr::new(203, 0, 113, 7)),
        );
        assert!(read().is_empty(), "the filter judges the resolved address");

        level.record_resolved_address(&named, ResolvedAddress::DoesNotResolve);
        assert!(read().is_empty());
        assert_eq!(
            published().resolved_address,
            Some(ResolvedAddress::DoesNotResolve)
        );

        level.set_servers(vec![ManagedServer::listed(named.clone())]);
        level.set_servers(Vec::new());
        level.set_servers(vec![ManagedServer::listed(named)]);
        assert_eq!(
            published().resolved_address,
            None,
            "a removed row's answer went with it"
        );
    }
}
