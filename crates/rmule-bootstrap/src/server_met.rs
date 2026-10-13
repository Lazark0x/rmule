//! The server.met acquisition pipeline (ADR-0065).
//!
//! One deterministic, sans-I/O pass: a bounded GET through the [`Fetcher`]
//! seam, then **parse in memory before any install** (a parse failure rejects
//! the payload and leaves the caller's list untouched — aMule's temp-file
//! discipline collapsed to parse-before-install), then reconcile against the
//! installed set with aMule's `LoadServerMet` add-new / update-known posture.
//!
//! The pipeline returns a [`ServerMetInstall`] *plan*, never an applied
//! effect: it touches no store and no socket beyond the fetch, so the merge
//! and reconciliation semantics are assertable as plain values. Persisting the
//! plan and reconnecting an idle session are the caller's effects, made by the
//! Join Sequence in `rmule_core::join` (ADR-0067).

mod list_host;

use rmule_ed2k::{ServerMet, ServerMetEntry, ServerMetError};
use rmule_primitives::ServerEndpoint;
use thiserror::Error;

use self::list_host::ListHost;
use crate::fetcher::{FetchError, Fetcher};

/// Why a server.met acquisition produced no install plan.
///
/// Either failure leaves the caller's installed list untouched
/// (parse-before-install): the pipeline reconciles only a fully parsed
/// payload.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ServerMetPipelineError {
    /// The fetch itself failed — nothing was parsed or installed.
    #[error("server.met fetch failed: {0}")]
    Fetch(#[from] FetchError),

    /// The bytes arrived but were not a valid server.met; the payload is
    /// rejected whole and the existing list stands (ADR-0065's
    /// parse-before-install: "parse failure rejects the payload, the existing
    /// list is untouched").
    #[error("server.met parse rejected the payload; the existing list is untouched: {0}")]
    Decode(#[from] ServerMetError),
}

/// The reconciled outcome of one server.met acquisition — a *plan* the caller
/// applies, not an applied effect.
///
/// `servers` is `installed ∪ fresh` in aMule's order: the installed entries
/// stay put (duplicates folded in place), new endpoints append. A successful
/// plan is itself the "reconnect if idle" trigger aMule fires after
/// `UpdateServerMetFromURL` — modelled as the `Ok` outcome rather than a
/// bool that is always `true` on success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerMetInstall {
    servers: Vec<ServerMetEntry>,
    added: usize,
    updated: usize,
}

impl ServerMetInstall {
    /// The reconciled server list to persist: installed entries first (with
    /// duplicates folded), fresh endpoints appended.
    #[must_use]
    pub fn servers(&self) -> &[ServerMetEntry] {
        &self.servers
    }

    /// How many fresh rows were new `(ip, port)` keys (appended).
    #[must_use]
    pub const fn added(&self) -> usize {
        self.added
    }

    /// How many fresh rows folded into an already-installed duplicate.
    #[must_use]
    pub const fn updated(&self) -> usize {
        self.updated
    }

    /// Build the aggregate install plan for the auto-update walk: the server
    /// list accumulated across every merged URL, carrying the running
    /// `added` / `updated` totals summed over each per-URL merge so the
    /// aggregate reports honest counts rather than zeros.
    #[must_use]
    pub(crate) fn from_walk(servers: Vec<ServerMetEntry>, added: usize, updated: usize) -> Self {
        Self {
            servers,
            added,
            updated,
        }
    }

    /// The reconciled list projected onto the endpoints core's managed server
    /// list stores (ADR-0069: `host` string + `port`) — the seam the Join
    /// Sequence (`rmule_core::join`) installs and dials through. A row whose address somehow does
    /// not form a valid [`ServerEndpoint`] is dropped rather than failing the
    /// whole install.
    #[must_use]
    pub fn endpoints(&self) -> Vec<ServerEndpoint> {
        self.servers
            .iter()
            .filter_map(|entry| {
                let port = entry.endpoint().port;
                // `dialable_address` is where the family choice lives: IPv4
                // when the header carries one (a HighID *is* the packed public
                // IPv4), the `ST_IPV6` tag when it does not, and `None` for the
                // zero-header-IP row with no tag behind it — the shape stock
                // eMule rejects outright rather than dialling `0.0.0.0`.
                match entry
                    .dialable_address()
                    .and_then(|ip| ServerEndpoint::new(ip.to_string(), port).ok())
                {
                    Some(server_endpoint) => Some(server_endpoint),
                    None => {
                        // Still drop the row rather than fail the whole install,
                        // but do not let it vanish silently: name the endpoint
                        // so a poisoned mirror list is diagnosable.
                        tracing::warn!(
                            ip = %entry.endpoint().ip,
                            ipv6 = ?entry.ipv6(),
                            port,
                            "dropping server.met row that names no dialable address"
                        );
                        None
                    }
                }
            })
            .collect()
    }

    /// Consume the plan for its reconciled entries.
    #[must_use]
    pub fn into_servers(self) -> Vec<ServerMetEntry> {
        self.servers
    }
}

/// Run the server.met pipeline once.
///
/// Bounded GET → parse-before-install → merge against `installed`. **One-shot,
/// no retry**: amuled's cold-start fetch does not loop — a failure waits for
/// the user (ADR-0065) — so this makes exactly one [`Fetcher::get`] call and
/// returns its first failure as-is. On success the returned plan reconciles
/// `installed` with the freshly parsed rows and is the caller's cue to persist
/// and reconnect if idle.
///
/// The fresh rows are the word of `url`'s host, and a row whose address no
/// server can be at as that host's word is dropped before the merge
/// (ADR-0085).
pub async fn fetch_server_met<F>(
    fetcher: &F,
    url: &str,
    max_bytes: usize,
    installed: Vec<ServerMetEntry>,
) -> Result<ServerMetInstall, ServerMetPipelineError>
where
    F: Fetcher + Sync,
{
    let bytes = fetcher.get(url, max_bytes).await?;
    let fresh = ServerMet::decode(&bytes)?;
    let host = ListHost::of(url);
    let fresh = fresh
        .into_entries()
        .into_iter()
        .filter(|entry| host.admits(entry))
        .collect();
    let install = merge_installed(installed, fresh);
    tracing::debug!(
        added = install.added,
        updated = install.updated,
        total = install.servers.len(),
        "server.met acquisition merged"
    );
    Ok(install)
}

/// aMule `LoadServerMet` reconciliation, keyed by
/// [`ServerMetEntry::identity`] — the dialable address and port, so two
/// IPv6-only rows (both `0.0.0.0` in their headers) stay two servers: an
/// already installed endpoint folds the fresh duplicate in via
/// [`ServerMetEntry::merge`] (listname always, description only when the fresh
/// one is non-empty, priority kept); a new endpoint appends. Installed order
/// is preserved. A duplicate *within* the fresh payload folds into the row it
/// duplicates, exactly as aMule adds fresh rows one at a time into the list it
/// is building.
fn merge_installed(installed: Vec<ServerMetEntry>, fresh: Vec<ServerMetEntry>) -> ServerMetInstall {
    let mut servers = installed;
    let mut added = 0;
    let mut updated = 0;

    for candidate in fresh {
        match servers
            .iter_mut()
            .find(|entry| entry.identity() == candidate.identity())
        {
            Some(slot) => {
                *slot = slot.clone().merge(candidate);
                updated += 1;
            }
            None => {
                servers.push(candidate);
                added += 1;
            }
        }
    }

    ServerMetInstall {
        servers,
        added,
        updated,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_ed2k::ServerPriority;

    use super::*;
    use crate::fixture::{
        FakeFetcher, RowSpec, SERVER_MET_CAP as CAP, installed_from, met_bytes, name_of,
    };

    #[tokio::test]
    async fn cold_start_installs_every_fresh_row_as_new() {
        let bytes = met_bytes(&[
            RowSpec::new(Ipv4Addr::new(1, 2, 3, 4), 4661).name("Alpha"),
            RowSpec::new(Ipv4Addr::new(5, 6, 7, 8), 4662).name("Beta"),
        ]);
        let fetcher = FakeFetcher::serving(bytes);

        let install = fetch_server_met(&fetcher, "http://mirror/server.met", CAP, Vec::new())
            .await
            .expect("cold-start acquisition");

        assert_eq!(install.added(), 2);
        assert_eq!(install.updated(), 0);
        let names: Vec<_> = install.servers().iter().map(name_of).collect();
        assert_eq!(names, vec!["Alpha", "Beta"]);
        assert_eq!(fetcher.call_count(), 1, "one-shot fetch");
    }

    #[tokio::test]
    async fn duplicate_endpoint_folds_via_amule_merge_posture() {
        // Installed: one server with a full record.
        let installed = installed_from(&[RowSpec::new(Ipv4Addr::new(1, 1, 1, 1), 4661)
            .name("Old Name")
            .description("Old description")
            .preference(1)]); // High
        // Fresh: the same endpoint renamed + repriced with no description, plus
        // a brand-new endpoint.
        let fresh = met_bytes(&[
            RowSpec::new(Ipv4Addr::new(1, 1, 1, 1), 4661)
                .name("New Name")
                .preference(2), // Low — must be ignored by the merge
            RowSpec::new(Ipv4Addr::new(2, 2, 2, 2), 4662).name("Fresh Server"),
        ]);
        let fetcher = FakeFetcher::serving(fresh);

        let install = fetch_server_met(&fetcher, "http://mirror/server.met", CAP, installed)
            .await
            .expect("acquisition");

        assert_eq!(install.added(), 1, "the new endpoint");
        assert_eq!(install.updated(), 1, "the duplicate endpoint");
        let dup = &install.servers()[0];
        assert_eq!(name_of(dup), "New Name", "listname always takes fresh");
        assert_eq!(
            dup.description().to_display_string(),
            "Old description",
            "empty fresh description is not written over the installed one"
        );
        assert_eq!(
            dup.priority(),
            ServerPriority::High,
            "priority is kept from the installed entry, never overwritten"
        );
        assert_eq!(name_of(&install.servers()[1]), "Fresh Server");
    }

    #[tokio::test]
    async fn two_ipv6_only_rows_on_one_port_stay_two_servers() {
        // emule-qt writes header IP 0 on every IPv6-only row (Server.cpp:294-298),
        // so the header endpoint is `0.0.0.0:4661` for both.
        let first: std::net::Ipv6Addr = "2a01:4f8::1".parse().unwrap();
        let second: std::net::Ipv6Addr = "2a01:4f8::2".parse().unwrap();
        let fetcher = FakeFetcher::serving(met_bytes(&[
            RowSpec::new(Ipv4Addr::UNSPECIFIED, 4661)
                .name("First")
                .ipv6(first),
            RowSpec::new(Ipv4Addr::UNSPECIFIED, 4661)
                .name("Second")
                .ipv6(second),
        ]));

        let install = fetch_server_met(&fetcher, "http://mirror/server.met", CAP, Vec::new())
            .await
            .expect("acquisition");

        assert_eq!(install.added(), 2, "neither folds into the other");
        assert_eq!(install.updated(), 0);
        let addresses: Vec<_> = install.servers().iter().map(ServerMetEntry::ipv6).collect();
        assert_eq!(addresses, vec![Some(first), Some(second)]);
    }

    #[tokio::test]
    async fn parse_failure_rejects_payload_and_keeps_installed_list() {
        let installed =
            installed_from(&[RowSpec::new(Ipv4Addr::new(9, 9, 9, 9), 4661).name("Kept")]);
        // 0x0F is the known.met header trap — a valid-looking but wrong file.
        let fetcher = FakeFetcher::serving(vec![0x0F, 0x00, 0x00, 0x00, 0x00]);

        let outcome =
            fetch_server_met(&fetcher, "http://mirror/server.met", CAP, installed.clone()).await;

        assert!(
            matches!(
                outcome,
                Err(ServerMetPipelineError::Decode(
                    ServerMetError::InvalidHeader { byte: 0x0F }
                ))
            ),
            "a bad payload is rejected as a decode error, got {outcome:?}"
        );
        // The caller's list is what it passed in — the pipeline never mutated
        // an external list, so a rejected fetch leaves it exactly as-is.
        assert_eq!(name_of(&installed[0]), "Kept");
    }

    #[tokio::test]
    async fn transport_failure_surfaces_without_retry() {
        let installed =
            installed_from(&[RowSpec::new(Ipv4Addr::new(9, 9, 9, 9), 4661).name("Kept")]);
        let fetcher = FakeFetcher::failing(FetchError::Transport {
            url: "http://mirror/server.met".to_owned(),
            detail: "connection refused".to_owned(),
        });

        let outcome = fetch_server_met(&fetcher, "http://mirror/server.met", CAP, installed).await;

        assert!(matches!(
            outcome,
            Err(ServerMetPipelineError::Fetch(FetchError::Transport { .. }))
        ));
        assert_eq!(
            fetcher.call_count(),
            1,
            "amuled parity: one-shot, a failed cold-start fetch does not loop"
        );
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_by_the_cap() {
        let big = met_bytes(&[RowSpec::new(Ipv4Addr::new(1, 1, 1, 1), 4661).name("Alpha")]);
        let cap = big.len() - 1;
        let fetcher = FakeFetcher::serving(big);

        let outcome = fetch_server_met(&fetcher, "http://mirror/server.met", cap, Vec::new()).await;

        assert_eq!(
            outcome,
            Err(ServerMetPipelineError::Fetch(FetchError::TooLarge { cap }))
        );
    }

    #[tokio::test]
    async fn empty_but_valid_server_met_installs_nothing() {
        // Valid header, zero declared rows — a mirror with an empty list.
        let fetcher = FakeFetcher::serving(met_bytes(&[]));

        let install = fetch_server_met(&fetcher, "http://mirror/server.met", CAP, Vec::new())
            .await
            .expect("valid empty list");

        assert_eq!(install.added(), 0);
        assert!(install.servers().is_empty());
    }

    /// A fetched list's rows are its URL host's word (ADR-0085): from a
    /// remote mirror every Reserved Range row is dropped and a LAN row stays;
    /// loopback stands only from a mirror on this host.
    #[tokio::test]
    async fn a_row_no_server_can_be_at_is_dropped_by_the_lists_host() {
        let rows = [
            RowSpec::new(Ipv4Addr::LOCALHOST, 4661).name("Loopback"),
            RowSpec::new(Ipv4Addr::BROADCAST, 4661).name("Broadcast"),
            RowSpec::new(Ipv4Addr::new(224, 0, 0, 1), 4661).name("Multicast"),
            RowSpec::new(Ipv4Addr::new(0, 0, 0, 5), 4661).name("This network"),
            RowSpec::new(Ipv4Addr::new(192, 168, 1, 10), 4661).name("Lan"),
            RowSpec::new(Ipv4Addr::new(45, 55, 200, 1), 4661).name("Public"),
        ];
        let remote = vec!["Lan", "Public"];
        let on_this_host = vec!["Loopback", "Lan", "Public"];
        for (url, expected) in [
            ("http://mirror.example/server.met", &remote),
            ("http://198.51.100.7:8080/server.met", &remote),
            ("http://127.0.0.1:8080/server.met", &on_this_host),
            ("http://localhost/server.met", &on_this_host),
            ("http://[::1]:8080/server.met", &on_this_host),
        ] {
            let fetcher = FakeFetcher::serving(met_bytes(&rows));

            let install = fetch_server_met(&fetcher, url, CAP, Vec::new())
                .await
                .expect(url);

            let names: Vec<_> = install.servers().iter().map(name_of).collect();
            assert_eq!(&names, expected, "{url}");
            assert_eq!(install.added(), expected.len(), "{url}");
        }
    }

    #[tokio::test]
    async fn endpoints_drops_only_rows_that_cannot_form_a_server_endpoint() {
        // The decoder is tolerant of a zero port, so a port-0 row lands in the
        // reconciled list as a ServerMetEntry — but it cannot become a
        // ServerEndpoint. endpoints() must drop that one row (logging a warn)
        // and still project the valid rows, never failing the whole install.
        let bytes = met_bytes(&[
            RowSpec::new(Ipv4Addr::new(1, 2, 3, 4), 0).name("Portless"),
            RowSpec::new(Ipv4Addr::new(5, 6, 7, 8), 4662).name("Valid"),
        ]);
        let fetcher = FakeFetcher::serving(bytes);

        let install = fetch_server_met(&fetcher, "http://mirror/server.met", CAP, Vec::new())
            .await
            .expect("acquisition");

        // Both rows survive the tolerant decode/merge...
        assert_eq!(install.servers().len(), 2);
        // ...but only the valid endpoint projects onto the store seam; the
        // port-0 row is dropped, leaving exactly the good one (port 4662).
        let endpoints = install.endpoints();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].port(), 4662);
    }
}
