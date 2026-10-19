//! The **Managed Server List** (ADR-0080): rmule's own record of the eD2k
//! servers it knows, the store seam that keeps it, and the two-step server.met
//! acquisition both the Join Sequence and `CoreCommand::ServerList` run
//! through.
//!
//! # One row, seven durable facts
//!
//! [`ManagedServer`] is the whole persisted model: the endpoint, the two
//! display strings server.met carries (`ST_SERVERNAME` / `ST_DESCRIPTION`),
//! aMule's three-valued priority, the operator's static pin, the running
//! failure tally, and the server's **Figures** — what it last reported about
//! itself (ping, users, files, limits, version) and when. The figures
//! are durable, as aMule keeps them in server.met, so a restart shows them at
//! once with their age; the surfaced row
//! ([`crate::diagnostics::ServerDiagnostics`]) carries that age.
//!
//! # The row, and the two things done to it
//!
//! This file is the model and its store seam. Beside it live the two
//! concerns that write through them: `acquisition` — the two-step
//! server.met fetch/install both the Join Sequence and
//! `CoreCommand::ServerList` run through — and `facts`, the one seam every
//! surface that *reaches* a server reports its round trip to.

mod acquisition;
mod aux_ports;
mod facts;
mod figures;
mod grants;
mod policy;
mod resolved_address;
mod udp_crypt;

use std::net::Ipv4Addr;
use std::sync::Arc;

use rmule_ed2k::{ServerMetEntry, ServerPriority, ServerUdpFlags};
use rmule_primitives::{Ed2kText, Ipv4Endpoint, ServerEndpoint};

use crate::CoreError;

pub(crate) use acquisition::acquire_server_met_walk;
pub use acquisition::{
    AutoUpdateFetch, ServerListFetcher, ServerListUpdate, ServerListUpdateError,
    ServerListUpdateFailure,
};
pub(crate) use acquisition::{ErasedFetcher, acquire_server_met, install_server_met_plan};
pub use aux_ports::ServerAuxPorts;
pub(crate) use facts::{ServerFacts, mutate_and_publish};
#[cfg(test)]
pub(crate) use facts::{test_facts, test_facts_rows};
pub use figures::{ServerFigures, unix_seconds};
pub use grants::ServerGrantsReport;
pub use policy::{DEFAULT_DEAD_AFTER, DeadSince, ServerHealth, ServerPolicy};
pub use resolved_address::ResolvedAddress;
pub(crate) use resolved_address::ResolvedAddresses;
pub use udp_crypt::ServerUdpCrypt;

/// One row of the managed server list — everything rmule persists about a
/// server it knows.
///
/// The first four fields are what a server.met row carries (ADR-0066's
/// decoder projects exactly these); the static pin and the failure tally are
/// rmule's own bookkeeping, which is why a merge never lets a downloaded list
/// overwrite them. The figures go with whichever side heard the server last.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedServer {
    /// Where the server is dialed. The list key: at most one row per
    /// endpoint, and a DNS-named row is a distinct key from its resolved IP
    /// (aMule keys its own list the same way).
    pub endpoint: ServerEndpoint,
    /// `ST_SERVERNAME` — the list name. Wire-faithful bytes (ADR-0019):
    /// server banners are routinely not UTF-8. Empty when unknown; a renderer
    /// falls back to the endpoint rather than core inventing a name.
    pub name: Ed2kText,
    /// `ST_DESCRIPTION` — the longer blurb. Empty when unknown.
    pub description: Ed2kText,
    /// aMule's `ST_PREFERENCE` (`Normal` / `High` / `Low`). Operator-owned: a
    /// downloaded list never changes it (aMule's own `LoadServerMet` rule).
    pub priority: ServerPriority,
    /// The operator pinned this row (aMule's `staticservers.dat` role). A
    /// pinned row is the operator's, not the mirror's.
    pub is_static: bool,
    /// How many times reaching this server has failed since the last reset —
    /// aMule's `SetFailedCount`. Written by the surfaces that do the reaching
    /// (the UDP status sweep, the session connect); never by a downloaded
    /// list.
    pub fail_count: u32,
    /// What the server last reported about itself, and when; `None`
    /// until it has answered — or, for an imported row, until its file named
    /// a time for the answer.
    pub figures: Option<ServerFigures>,
    /// What the server granted at its last login, and when; `None` for a
    /// server never logged into. rmule's own bookkeeping: a downloaded list
    /// never writes it.
    pub grants: Option<ServerGrantsReport>,
    /// How to key UDP to it, as its last status answer said; `None` until an
    /// answer carried it (ADR-0052). rmule's own bookkeeping, like the grants.
    /// The obfuscation TCP port in it may instead have been learned from the
    /// server's login answer or its server.met tag (aMule's one
    /// `m_nObfuscationPortTCP`), in which case the UDP half is zero.
    pub udp_crypt: Option<ServerUdpCrypt>,
    /// The standard port, when this row is dialed on another one, and the
    /// ports it takes aux-port logins on (aMule's `realport` and
    /// `ST_AUXPORTSLIST`); `None` while the dialed port is the standard one.
    /// Learned from an aux-port login's ID answer or a server.met row; a
    /// downloaded row's own list never replaces what a login taught.
    pub aux_ports: Option<ServerAuxPorts>,
    /// The UDP flags word a server.met row named (`ST_UDPFLAGS`), for a row
    /// whose figures carry none: an imported row never pinged has no dated
    /// figures to hold them. [`udp_flags`](Self::udp_flags) reads whichever is
    /// there.
    pub listed_udp_flags: Option<ServerUdpFlags>,
}

impl ManagedServer {
    /// A row for an endpoint nothing is known about yet: no name, no
    /// description, `Normal` priority, unpinned, no failures. What an operator
    /// `add server host:port` produces.
    #[must_use]
    pub fn listed(endpoint: ServerEndpoint) -> Self {
        Self {
            endpoint,
            name: Ed2kText::from_bytes(Vec::new()),
            description: Ed2kText::from_bytes(Vec::new()),
            priority: ServerPriority::Normal,
            is_static: false,
            fail_count: 0,
            figures: None,
            grants: None,
            udp_crypt: None,
            aux_ports: None,
            listed_udp_flags: None,
        }
    }

    /// Project a decoded server.met row onto a list row, its figures dated by
    /// the row's own last-ping time as of `now`. `None` when the row
    /// names no dialable address at all — a zero port, or the zero header IP
    /// with no `ST_IPV6` tag behind it (ADR-0087 §4.8) — so the row is dropped
    /// rather than installed as a server at `0.0.0.0`, matching
    /// [`ServerMetInstall::endpoints`](rmule_bootstrap::ServerMetInstall::endpoints).
    #[must_use]
    pub fn from_met(entry: &ServerMetEntry, now: std::time::SystemTime) -> Option<Self> {
        // The header port is the standard one; with an aux-ports list the row
        // is dialed on the list's first port (`Server.cpp:222-231`).
        let port = entry.endpoint().port;
        let aux_ports = ServerAuxPorts::from_met(port, entry.aux_ports());
        let dialed = aux_ports.as_ref().map_or(port, |aux| aux.ports[0]);
        let endpoint = match entry.dialable_address().ok_or(()).and_then(|ip| {
            // A zero standard port drops the row whatever the list says.
            ServerEndpoint::new(ip.to_string(), port).map_err(|_| ())?;
            ServerEndpoint::new(ip.to_string(), dialed).map_err(|_| ())
        }) {
            Ok(endpoint) => endpoint,
            Err(()) => {
                tracing::warn!(
                    ip = %entry.endpoint().ip,
                    ipv6 = ?entry.ipv6(),
                    port,
                    "dropping a server.met row that names no dialable address"
                );
                return None;
            }
        };
        let obfuscation = entry.obfuscation();
        // `ST_UDPFLAGS` rides with the figures it was written beside, so a
        // row with no dated answer keeps neither there (`ServerFigures::from_met`)
        // — the word is kept on the row itself instead, as aMule keeps it per
        // server whether or not it was ever pinged.
        let udp_flags = obfuscation.udp_flags.map(ServerUdpFlags::from_bits);
        let figures = ServerFigures::from_met(entry.figures(), now).map(|mut figures| {
            figures.udp_flags = udp_flags;
            figures
        });
        Some(Self {
            endpoint,
            name: entry.name().clone(),
            description: entry.description().clone(),
            priority: entry.priority(),
            is_static: false,
            fail_count: 0,
            figures,
            grants: None,
            udp_crypt: ServerUdpCrypt::from_met(&obfuscation),
            aux_ports,
            listed_udp_flags: udp_flags,
        })
    }

    /// Whether `informant`'s word cannot make this row a server: it is listed
    /// by an address in a Reserved Range that informant cannot vouch for
    /// (ADR-0085). A row listed by name is judged when it is dialed, not here.
    #[must_use]
    pub fn is_reserved_for(&self, informant: rmule_primitives::Informant) -> bool {
        self.endpoint
            .host()
            .parse()
            .is_ok_and(|ip| !informant.admits(ip))
    }

    /// The server's UDP flags: its last status answer's word, else the one a
    /// server.met row named for it.
    #[must_use]
    pub fn udp_flags(&self) -> Option<ServerUdpFlags> {
        self.figures
            .as_ref()
            .and_then(|figures| figures.udp_flags)
            .or(self.listed_udp_flags)
    }

    /// The port this server takes obfuscated TCP on, when it has said it
    /// does — aMule's `SupportsObfuscationTCP()` (`Server.h:163-168`): a
    /// non-zero obfuscation TCP port, and `TCPOBFUSCATION` in its UDP flags
    /// or in the TCP flags its last login granted. The port is the latest one
    /// its status answer (ADR-0052), its login answer or its server.met tag
    /// carried — aMule keeps one `m_nObfuscationPortTCP` for all three.
    #[must_use]
    pub fn obfuscation_tcp_port(&self) -> Option<u16> {
        let port = self
            .udp_crypt
            .map(|crypt| crypt.obfuscation_tcp_port)
            .filter(|port| *port != 0)?;
        let by_udp = self
            .udp_flags()
            .is_some_and(ServerUdpFlags::supports_tcp_obfuscation);
        let by_tcp = self
            .grants
            .is_some_and(|grants| grants.tcp_flags.supports_tcp_obfuscation());
        (by_udp || by_tcp).then_some(port)
    }

    /// Project back onto a server.met row so the downloaded list can be
    /// reconciled against what is already installed by
    /// `rmule-bootstrap`'s merge, which keys on `(ip, port)`. `None` for a
    /// DNS-named row: it has no `(ip, port)` key, so it cannot collide with a
    /// downloaded row and simply stays out of the reconciliation.
    #[must_use]
    fn to_met(&self) -> Option<ServerMetEntry> {
        let standard = self.standard_endpoint();
        let ip: Ipv4Addr = standard.host().parse().ok()?;
        Some(ServerMetEntry::new(
            Ipv4Endpoint::new(ip, standard.port()),
            self.name.clone(),
            self.description.clone(),
            self.priority,
        ))
    }

    /// The endpoint a downloaded server.met names this server by: the dialed
    /// host at its standard port. aMule keys its list and dedups additions on
    /// this port, not on the one it connects to (`GetPort()` against
    /// `GetConnPort()`, `ServerList.cpp:223-237`), which is why a downloaded
    /// row for a server rmule dials on an aux port finds its row.
    #[must_use]
    pub fn standard_endpoint(&self) -> ServerEndpoint {
        aux_ports::standard_endpoint(&self.endpoint, self.aux_ports.as_ref())
    }

    /// Fold a freshly learned row for the same server into this one —
    /// aMule's `LoadServerMet` duplicate branch, which is also what its
    /// `ServerList::AddServer` does for a known server: the **name always**
    /// takes the fresh value, the **description only when the fresh one is
    /// non-empty**, and everything else — priority, static pin, failure tally
    /// — stays ours. A downloaded list may rename a server; it may not
    /// re-prioritise, unpin, or absolve it.
    pub(crate) fn fold(&mut self, fresh: Self) {
        debug_assert_eq!(
            self.standard_endpoint(),
            fresh.standard_endpoint(),
            "ManagedServer::fold expects both rows to name one server"
        );
        // A row's own aux-ports list is kept; a downloaded one is taken only
        // for a row dialed on the very port it lists, so the dialed port and
        // the list can never disagree.
        if self.aux_ports.is_none() && self.endpoint == fresh.endpoint {
            self.aux_ports = fresh.aux_ports;
        }
        self.name = fresh.name;
        if !fresh.description.as_bytes().is_empty() {
            self.description = fresh.description;
        }
        // The later-dated figures win, by the later of each side's two
        // dates: an import dated after what rmule last heard replaces them,
        // an older one does not.
        if dated(fresh.figures.as_ref()) > dated(self.figures.as_ref()) {
            self.figures = fresh.figures;
        }
        // The obfuscation TCP port a downloaded row states is the server's
        // own word (`Server.cpp:256`); what a status answer taught us about
        // its UDP keying — port, key — outranks a list's, which only fills
        // what we lack.
        if let Some(listed) = fresh.udp_crypt {
            let mut crypt = self.udp_crypt.unwrap_or(ServerUdpCrypt::from_tcp_port(0));
            if listed.obfuscation_tcp_port != 0 {
                crypt.obfuscation_tcp_port = listed.obfuscation_tcp_port;
            }
            if crypt.obfuscation_udp_port == 0 {
                crypt.obfuscation_udp_port = listed.obfuscation_udp_port;
            }
            if crypt.udp_key == 0 {
                crypt.udp_key = listed.udp_key;
                crypt.key_ip = listed.key_ip;
            }
            self.udp_crypt = Some(crypt);
        }
        self.listed_udp_flags = fresh.listed_udp_flags.or(self.listed_udp_flags);
    }
}

impl ManagedServer {
    /// Take in the row a login just showed to be this same server: the one
    /// listed under its standard endpoint, which an aux-port login dialed
    /// past. The dialed row keeps the key (the session is running on it) and
    /// its own facts; it gains what only the listed row held — a name,
    /// description and priority the operator or a mirror set, the pin, and
    /// whatever of figures, grants and UDP crypt it lacks. aMule's
    /// `AddServer` refuses a second row for one `(address, port)`
    /// (`ServerList.cpp:223-237`); this is that rule applied after the fact.
    pub(crate) fn absorb(&mut self, listed: Self) {
        if self.name.as_bytes().is_empty() {
            self.name = listed.name;
        }
        if self.description.as_bytes().is_empty() {
            self.description = listed.description;
        }
        if self.priority == ServerPriority::Normal {
            self.priority = listed.priority;
        }
        self.is_static |= listed.is_static;
        if dated(listed.figures.as_ref()) > dated(self.figures.as_ref()) {
            self.figures = listed.figures;
        }
        self.grants = self.grants.or(listed.grants);
        self.udp_crypt = self.udp_crypt.or(listed.udp_crypt);
    }
}

/// When `figures` were last dated, by the later of their two dates; `None`
/// for a row with none — older than any dated figures.
fn dated(figures: Option<&ServerFigures>) -> Option<u64> {
    figures.and_then(ServerFigures::dated)
}

/// What [`ServerListStore::merge_server`] did with the row it was handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerMerge {
    /// The endpoint was new: the row was appended to the list.
    Added,
    /// The endpoint was already listed: the fresh row folded into it.
    Updated,
}

/// Durable owner of the managed server list.
///
/// Every method is `&self` and internally synchronised, matching
/// [`AppConfigStore`](crate::AppConfigStore) (of which this is a supertrait):
/// the list is small, mutations are point-in-time, and the store is shared
/// between the actor and its update task without a lock (ADR-0083).
///
/// The three `set_*` mutators and [`remove_server`](Self::remove_server) all
/// report `false` when no row holds the endpoint, so a caller can answer
/// "there is no such server" without a second read.
pub trait ServerListStore: Send + Sync {
    /// Every listed server, in list order (insertion order — aMule appends
    /// fresh servers and leaves installed ones where they are).
    fn servers(&self) -> Result<Vec<ManagedServer>, CoreError>;

    /// Add `server`, or fold it into the row already holding its endpoint
    /// (see `ManagedServer::fold` for exactly what a fold keeps).
    fn merge_server(&self, server: ManagedServer) -> Result<ServerMerge, CoreError>;

    /// Drop the row for `endpoint`.
    fn remove_server(&self, endpoint: &ServerEndpoint) -> Result<bool, CoreError>;

    /// Set one row's operator-owned priority.
    fn set_server_priority(
        &self,
        endpoint: &ServerEndpoint,
        priority: ServerPriority,
    ) -> Result<bool, CoreError>;

    /// Pin or unpin one row.
    fn set_server_static(
        &self,
        endpoint: &ServerEndpoint,
        is_static: bool,
    ) -> Result<bool, CoreError>;

    /// Record one row's failure tally. The caller decides what a failure is
    /// (a refused connect, an unanswered status ping) and what resets it; the
    /// store only remembers the number — this is the absolving half (set it
    /// to zero) and the seed; the counting half is
    /// [`count_server_failure`](Self::count_server_failure).
    fn set_server_fail_count(
        &self,
        endpoint: &ServerEndpoint,
        fail_count: u32,
    ) -> Result<bool, CoreError>;

    /// One more consecutive failure to reach `endpoint` — aMule's
    /// `AddFailedCount`, as one step the store takes rather than a tally the
    /// caller reads, adds one to, and writes back. The increment is the
    /// store's because only the store can read and write the row in one
    /// transaction; what counts as a failure stays the caller's.
    fn count_server_failure(&self, endpoint: &ServerEndpoint) -> Result<bool, CoreError>;

    /// Change one row's figures in one transaction: `edit` gets what
    /// the row holds and leaves what it should hold. The answer that moved
    /// them decides the edit; the store keeps them.
    fn edit_server_figures(
        &self,
        endpoint: &ServerEndpoint,
        edit: &mut dyn FnMut(&mut Option<ServerFigures>),
    ) -> Result<bool, CoreError>;

    /// Record what `endpoint` granted at its login (ADR-0080, "What a server
    /// grants is durable"), replacing the last report.
    fn set_server_grants(
        &self,
        endpoint: &ServerEndpoint,
        report: ServerGrantsReport,
    ) -> Result<bool, CoreError>;

    /// Record the obfuscation TCP port `endpoint` named in its login answer
    /// (`ServerSocket.cpp:333-341`), keeping every other crypt fact the row
    /// holds. Reports `false` for an endpoint no row holds.
    fn set_server_obfuscation_tcp_port(
        &self,
        endpoint: &ServerEndpoint,
        port: u16,
    ) -> Result<bool, CoreError>;

    /// Record the standard port `endpoint`'s ID answer named after an aux-port
    /// login (`ServerSocket.cpp:333-355`): the row keeps the dialed port in
    /// its aux-ports list. When another row already lists that standard
    /// endpoint, it is absorbed into this one (`ManagedServer::absorb`), so
    /// one server never holds two rows. A port of zero, or the dialed port
    /// itself, changes nothing. Reports `false` for an endpoint no row holds.
    fn set_server_standard_port(
        &self,
        endpoint: &ServerEndpoint,
        standard_port: u16,
    ) -> Result<bool, CoreError>;

    /// Record how to key UDP to `endpoint`, as its latest status answer said
    /// (ADR-0052, "a server's UDP crypt facts are durable"); `None` clears
    /// what an earlier answer said.
    fn set_server_udp_crypt(
        &self,
        endpoint: &ServerEndpoint,
        crypt: Option<ServerUdpCrypt>,
    ) -> Result<bool, CoreError>;
}

/// The actor's handle on the managed server list — the same type-erased
/// `Arc<dyn _>` shape the credit ring rides on, shared by the actor and its
/// update task with no lock around it (ADR-0083).
pub(crate) type SharedServerListStore = Arc<dyn ServerListStore>;

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(host: &str, port: u16) -> ServerEndpoint {
        ServerEndpoint::new(host, port).expect("valid endpoint")
    }

    /// The merge posture the whole list rests on: a downloaded row renames a
    /// known server and fills an empty description, but never touches the
    /// operator's priority, static pin, the failure tally, or the UDP crypt
    /// facts rmule learned from the server itself.
    #[test]
    fn a_downloaded_row_renames_a_known_server_but_keeps_operator_facts() {
        let store = crate::store::app_config::DurableAppConfig::new(rmule_testkit::memory_store());
        let crypt = ServerUdpCrypt {
            obfuscation_udp_port: 4673,
            obfuscation_tcp_port: 4674,
            udp_key: 0xABCD_1234,
            key_ip: None,
        };
        let known = ManagedServer {
            endpoint: endpoint("1.2.3.4", 4661),
            name: Ed2kText::from_utf8("Old"),
            description: Ed2kText::from_utf8("Old blurb"),
            priority: ServerPriority::High,
            is_static: true,
            fail_count: 7,
            figures: None,
            grants: None,
            udp_crypt: Some(crypt),
            aux_ports: None,
            listed_udp_flags: None,
        };
        assert_eq!(store.merge_server(known).unwrap(), ServerMerge::Added);

        let fresh = ManagedServer {
            endpoint: endpoint("1.2.3.4", 4661),
            name: Ed2kText::from_utf8("New"),
            description: Ed2kText::from_bytes(Vec::new()),
            priority: ServerPriority::Low,
            is_static: false,
            fail_count: 0,
            figures: None,
            grants: None,
            udp_crypt: None,
            aux_ports: None,
            listed_udp_flags: None,
        };
        assert_eq!(store.merge_server(fresh).unwrap(), ServerMerge::Updated);

        let row = &store.servers().unwrap()[0];
        assert_eq!(row.name.to_display_string(), "New");
        assert_eq!(row.description.to_display_string(), "Old blurb");
        assert_eq!(row.priority, ServerPriority::High);
        assert!(row.is_static);
        assert_eq!(row.fail_count, 7);
        assert_eq!(row.udp_crypt, Some(crypt));
    }

    /// aMule's `SupportsObfuscationTCP()`: a known obfuscation TCP port is
    /// not enough, the server must also have flagged TCP obfuscation, in its
    /// UDP flags or in the TCP flags its login granted.
    #[test]
    fn a_server_takes_obfuscated_tcp_only_where_a_flag_says_so() {
        let mut row = ManagedServer::listed(endpoint("1.2.3.4", 4661));
        row.udp_crypt = Some(ServerUdpCrypt {
            obfuscation_udp_port: 4673,
            obfuscation_tcp_port: 4674,
            udp_key: 1,
            key_ip: None,
        });
        assert_eq!(row.obfuscation_tcp_port(), None, "a port and no flag");

        row.grants = Some(ServerGrantsReport {
            tcp_flags: rmule_ed2k::ServerTcpFlags::from_bits(
                rmule_ed2k::ServerTcpFlags::TCPOBFUSCATION,
            ),
            reported_at: 0,
        });
        assert_eq!(
            row.obfuscation_tcp_port(),
            Some(4674),
            "the login's TCP flag"
        );

        row.udp_crypt = None;
        assert_eq!(row.obfuscation_tcp_port(), None, "a flag and no port");
    }

    /// A server.met row's `ST_UDPFLAGS` and `ST_TCPPORTOBFUSCATION` make the
    /// imported row dial obfuscated (`Server.cpp:256`); folding such a row
    /// into a known one takes the port and leaves the UDP key alone.
    #[test]
    fn an_imported_rows_obfuscation_tags_feed_the_dial() {
        use rmule_ed2k::{ServerMetFigures, ServerMetObfuscation};
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(10_000);
        let entry = ServerMetEntry::new(
            Ipv4Endpoint::new(Ipv4Addr::new(1, 2, 3, 4), 4661),
            Ed2kText::from_utf8("S"),
            Ed2kText::from_utf8(""),
            ServerPriority::Normal,
        )
        .with_figures(ServerMetFigures {
            last_ping: Some(9_000),
            ..ServerMetFigures::NONE
        })
        .with_obfuscation(ServerMetObfuscation {
            udp_flags: Some(rmule_ed2k::ServerUdpFlags::TCPOBFUSCATION),
            tcp_port: Some(4674),
            ..ServerMetObfuscation::NONE
        });
        let imported = ManagedServer::from_met(&entry, now).expect("a dialable row");
        assert_eq!(imported.obfuscation_tcp_port(), Some(4674));

        let mut known = ManagedServer::listed(imported.endpoint.clone());
        known.udp_crypt = Some(ServerUdpCrypt {
            obfuscation_udp_port: 4673,
            obfuscation_tcp_port: 5000,
            udp_key: 0xABCD_1234,
            key_ip: None,
        });
        known.fold(imported);
        let crypt = known.udp_crypt.expect("crypt facts kept");
        assert_eq!(
            (crypt.obfuscation_tcp_port, crypt.udp_key),
            (4674, 0xABCD_1234)
        );
    }

    /// A server.met row with an `ST_AUXPORTSLIST` is listed under its header
    /// port (the standard one) and dialed on the list's first port; its UDP
    /// crypt tags and the UDP flags word land on the row even when the file
    /// recorded no answer for it, and all of it survives the store.
    #[test]
    fn an_imported_row_with_aux_ports_and_crypt_tags_keeps_them_though_never_pinged() {
        use rmule_ed2k::ServerMetObfuscation;
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(10_000);
        let entry = ServerMetEntry::new(
            Ipv4Endpoint::new(Ipv4Addr::new(1, 2, 3, 4), 4661),
            Ed2kText::from_utf8("S"),
            Ed2kText::from_utf8(""),
            ServerPriority::Normal,
        )
        .with_aux_ports(vec![4232, 4242])
        .with_obfuscation(ServerMetObfuscation {
            udp_flags: Some(rmule_ed2k::ServerUdpFlags::TCPOBFUSCATION),
            tcp_port: Some(4674),
            udp_port: Some(4673),
            udp_key: Some(0xABCD_1234),
            udp_key_ip: Some(Ipv4Addr::new(198, 51, 100, 7)),
        });
        let imported = ManagedServer::from_met(&entry, now).expect("a dialable row");

        assert_eq!(imported.endpoint, endpoint("1.2.3.4", 4232));
        assert_eq!(imported.standard_endpoint(), endpoint("1.2.3.4", 4661));
        assert_eq!(imported.figures, None, "the file named no answer");
        assert_eq!(
            imported.udp_flags(),
            Some(rmule_ed2k::ServerUdpFlags::from_bits(
                rmule_ed2k::ServerUdpFlags::TCPOBFUSCATION
            ))
        );
        assert_eq!(imported.obfuscation_tcp_port(), Some(4674));
        assert_eq!(
            imported.udp_crypt,
            Some(ServerUdpCrypt {
                obfuscation_udp_port: 4673,
                obfuscation_tcp_port: 4674,
                udp_key: 0xABCD_1234,
                key_ip: Some(Ipv4Addr::new(198, 51, 100, 7)),
            })
        );

        let store = crate::store::app_config::DurableAppConfig::new(rmule_testkit::memory_store());
        store.merge_server(imported.clone()).unwrap();
        assert_eq!(store.servers().unwrap(), vec![imported]);
    }

    /// A downloaded row only fills the UDP facts a row lacks: what a status
    /// answer taught (the key) outranks the list's, a stated TCP port is the
    /// server's own word, and the flags word it names is kept.
    #[test]
    fn a_downloaded_rows_udp_crypt_fills_gaps_and_never_replaces_a_learned_key() {
        use rmule_ed2k::ServerMetObfuscation;
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(10_000);
        let row = |tcp, udp, key| {
            ServerMetEntry::new(
                Ipv4Endpoint::new(Ipv4Addr::new(1, 2, 3, 4), 4661),
                Ed2kText::from_utf8(""),
                Ed2kText::from_utf8(""),
                ServerPriority::Normal,
            )
            .with_obfuscation(ServerMetObfuscation {
                udp_flags: Some(0x400),
                tcp_port: Some(tcp),
                udp_port: Some(udp),
                udp_key: Some(key),
                udp_key_ip: Some(Ipv4Addr::new(203, 0, 113, 1)),
            })
        };
        let mut known = ManagedServer::from_met(&row(4674, 0, 0), now).unwrap();
        known.udp_crypt = Some(ServerUdpCrypt {
            obfuscation_udp_port: 0,
            obfuscation_tcp_port: 4674,
            udp_key: 0,
            key_ip: None,
        });
        known.fold(ManagedServer::from_met(&row(4675, 4673, 7), now).unwrap());
        let crypt = known.udp_crypt.expect("crypt facts");
        assert_eq!(
            (
                crypt.obfuscation_tcp_port,
                crypt.obfuscation_udp_port,
                crypt.udp_key
            ),
            (4675, 4673, 7),
            "the gaps are filled"
        );

        known.fold(ManagedServer::from_met(&row(4675, 9999, 8), now).unwrap());
        let crypt = known.udp_crypt.expect("crypt facts");
        assert_eq!(
            (crypt.obfuscation_udp_port, crypt.udp_key),
            (4673, 7),
            "a learned port and key stay"
        );
    }

    #[test]
    fn mutators_report_whether_the_row_existed() {
        let store = crate::store::app_config::DurableAppConfig::new(rmule_testkit::memory_store());
        let listed = endpoint("1.2.3.4", 4661);
        let absent = endpoint("9.9.9.9", 4661);
        store
            .merge_server(ManagedServer::listed(listed.clone()))
            .unwrap();

        assert!(
            store
                .set_server_priority(&listed, ServerPriority::Low)
                .unwrap()
        );
        assert!(store.set_server_static(&listed, true).unwrap());
        assert!(store.set_server_fail_count(&listed, 3).unwrap());
        assert!(
            !store
                .set_server_priority(&absent, ServerPriority::Low)
                .unwrap()
        );
        assert!(!store.set_server_static(&absent, true).unwrap());
        assert!(!store.set_server_fail_count(&absent, 3).unwrap());
        assert!(!store.remove_server(&absent).unwrap());

        let row = &store.servers().unwrap()[0];
        assert_eq!(row.priority, ServerPriority::Low);
        assert!(row.is_static);
        assert_eq!(row.fail_count, 3);

        assert!(store.remove_server(&listed).unwrap());
        assert!(store.servers().unwrap().is_empty());
    }
}
