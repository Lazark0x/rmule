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
mod facts;
mod figures;
mod grants;
mod policy;
mod resolved_address;
mod udp_crypt;

use std::net::Ipv4Addr;
use std::sync::Arc;

use rmule_ed2k::{ServerMetEntry, ServerPriority};
use rmule_primitives::{Ed2kText, Ipv4Endpoint, ServerEndpoint};

use crate::CoreError;

pub(crate) use acquisition::{ErasedFetcher, acquire_server_met, install_server_met_plan};
pub use acquisition::{
    ServerListFetcher, ServerListUpdate, ServerListUpdateError, ServerListUpdateFailure,
};
#[cfg(test)]
pub(crate) use facts::test_facts;
pub(crate) use facts::{ServerFacts, mutate_and_publish};
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
    pub udp_crypt: Option<ServerUdpCrypt>,
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
        let port = entry.endpoint().port;
        let endpoint = match entry
            .dialable_address()
            .ok_or(())
            .and_then(|ip| ServerEndpoint::new(ip.to_string(), port).map_err(|_| ()))
        {
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
        Some(Self {
            endpoint,
            name: entry.name().clone(),
            description: entry.description().clone(),
            priority: entry.priority(),
            is_static: false,
            fail_count: 0,
            figures: ServerFigures::from_met(entry.figures(), now),
            grants: None,
            udp_crypt: None,
        })
    }

    /// Project back onto a server.met row so the downloaded list can be
    /// reconciled against what is already installed by
    /// `rmule-bootstrap`'s merge, which keys on `(ip, port)`. `None` for a
    /// DNS-named row: it has no `(ip, port)` key, so it cannot collide with a
    /// downloaded row and simply stays out of the reconciliation.
    #[must_use]
    fn to_met(&self) -> Option<ServerMetEntry> {
        let ip: Ipv4Addr = self.endpoint.host().parse().ok()?;
        Some(ServerMetEntry::new(
            Ipv4Endpoint::new(ip, self.endpoint.port()),
            self.name.clone(),
            self.description.clone(),
            self.priority,
        ))
    }

    /// Fold a freshly learned row for the same endpoint into this one —
    /// aMule's `LoadServerMet` duplicate branch, which is also what its
    /// `ServerList::AddServer` does for a known server: the **name always**
    /// takes the fresh value, the **description only when the fresh one is
    /// non-empty**, and everything else — priority, static pin, failure tally
    /// — stays ours. A downloaded list may rename a server; it may not
    /// re-prioritise, unpin, or absolve it.
    pub(crate) fn fold(&mut self, fresh: Self) {
        debug_assert_eq!(
            self.endpoint, fresh.endpoint,
            "ManagedServer::fold expects both rows to share an endpoint key"
        );
        self.name = fresh.name;
        if !fresh.description.as_bytes().is_empty() {
            self.description = fresh.description;
        }
        // The later answer's figures win: an import dated after the
        // last answer rmule heard replaces them, an older one does not.
        let answered = |figures: &Option<ServerFigures>| figures.as_ref().map(|f| f.answered_at);
        if answered(&fresh.figures) > answered(&self.figures) {
            self.figures = fresh.figures;
        }
    }
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

    /// Record how to key UDP to `endpoint`, as its latest status answer said
    /// (ADR-0052, "a server's UDP crypt facts are durable"); `None` clears
    /// what an earlier answer said.
    fn set_server_udp_crypt(
        &self,
        endpoint: &ServerEndpoint,
        crypt: Option<ServerUdpCrypt>,
    ) -> Result<bool, CoreError>;

    /// The **Server Policy** the operator's preferences hold, defaults
    /// filling what is unset — read by the actor at its start, so its first
    /// act already runs under it.
    fn server_policy(&self) -> Result<ServerPolicy, CoreError>;
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

    /// The limit the operator stored is the one core judges by; an unset
    /// or unreadable one is aMule's default.
    #[test]
    fn the_server_policy_reads_the_stored_limit() {
        use crate::{AppConfigStore, Preference};
        let store = crate::store::app_config::DurableAppConfig::new(rmule_testkit::memory_store());
        assert_eq!(store.server_policy().unwrap(), ServerPolicy::default());
        store
            .set_preference(Preference::DeadServerRetries, "6")
            .unwrap();
        assert_eq!(store.server_policy().unwrap().dead_after, 6);
        store
            .set_preference(Preference::WithholdSharesFromRelatedSearch, "true")
            .unwrap();
        assert!(store.server_policy().unwrap().withhold_from_related_search);
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
