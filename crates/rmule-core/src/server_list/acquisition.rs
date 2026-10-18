//! The two-step server.met acquisition the **Managed Server List** grows by,
//! and the boxed fetch capability it runs on.
//!
//! # Two steps, because the fetch must not hold the list
//!
//! [`acquire_server_met`] is the network step (bounded GET → parse → aMule
//! add-new/update-known merge, all of it `rmule-bootstrap`'s pipeline) and
//! [`install_server_met_plan`] is the store step. They are separate calls so a
//! caller that shares its store with a live actor can release the lock across
//! the seconds the fetch takes; a single-owner caller (the Join Sequence)
//! simply runs them back to back.
//!
//! # No HTTP client in core
//!
//! Core never links reqwest: it depends on `rmule-bootstrap` with
//! `default-features = false` and receives the fetch capability as an injected
//! [`ServerListFetcher`] — the object-safe form of the crate's [`Fetcher`]
//! seam, so an actor can hold one without a generic parameter.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rmule_bootstrap::{
    FetchError, Fetcher, ServerMetInstall, ServerMetPipelineError, UrlWalkOutcome,
};
use thiserror::Error;

use crate::CoreError;

use super::{ManagedServer, ServerListStore};

/// Core's object-safe view of `rmule-bootstrap`'s [`Fetcher`] seam.
///
/// [`Fetcher::get`] returns an RPITIT future, so a `dyn Fetcher` does not
/// exist — but the actor must hold its fetch capability in a plain field
/// (a generic parameter would spread across every `CoreBuilder` setter for one
/// HTTP GET a session). This is that seam boxed once: the blanket impl below
/// accepts any [`Fetcher`], so a front-end still injects
/// `rmule_bootstrap::ReqwestFetcher` directly and core links no HTTP client.
/// The fetch owns what it needs (an `Arc` of itself and the URL), so the boxed
/// future borrows nothing — which is what lets it be handed to a spawned task.
pub trait ServerListFetcher: Send + Sync + 'static {
    /// `GET url`, returning up to `max_bytes` of body — [`Fetcher::get`]'s
    /// contract, boxed.
    fn fetch(
        self: Arc<Self>,
        url: String,
        max_bytes: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, FetchError>> + Send>>;
}

impl<F> ServerListFetcher for F
where
    F: Fetcher + Send + Sync + 'static,
{
    fn fetch(
        self: Arc<Self>,
        url: String,
        max_bytes: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, FetchError>> + Send>> {
        Box::pin(async move { self.get(&url, max_bytes).await })
    }
}

/// Adapts the boxed seam back onto [`Fetcher`] so the actor's update task runs
/// the *same* `rmule-bootstrap` pipeline the Join Sequence does, rather than a
/// second copy of it.
pub(crate) struct ErasedFetcher(pub(crate) Arc<dyn ServerListFetcher>);

impl Fetcher for ErasedFetcher {
    fn get(
        &self,
        url: &str,
        max_bytes: usize,
    ) -> impl Future<Output = Result<Vec<u8>, FetchError>> + Send {
        let fetcher = Arc::clone(&self.0);
        let url = url.to_owned();
        async move { fetcher.fetch(url, max_bytes).await }
    }
}

/// What one server.met acquisition did to the list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerListUpdate {
    /// Downloaded rows whose endpoint was not listed before.
    pub added: usize,
    /// Downloaded rows that folded into an already-listed endpoint.
    pub updated: usize,
    /// How many servers the list holds now.
    pub total: usize,
}

/// Why an on-demand server-list update produced no new list.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ServerListUpdateError {
    /// The fetch or the parse rejected the payload; the list is untouched
    /// (ADR-0065's parse-before-install).
    #[error(transparent)]
    Acquisition(#[from] ServerMetPipelineError),
    /// The payload was good but the store would not take it.
    #[error("server list store rejected the update: {0}")]
    Store(#[from] CoreError),
}

impl ServerListUpdateError {
    /// The code a front end words for the operator. What the fetcher
    /// or the parser said beyond it — a URL, a transport's own sentence — is
    /// for the Run Log, where the update's failure is traced whole.
    #[must_use]
    pub fn failure(&self) -> ServerListUpdateFailure {
        match self {
            Self::Acquisition(ServerMetPipelineError::Fetch(fetch)) => match fetch {
                FetchError::Transport { .. } => ServerListUpdateFailure::Unreachable,
                FetchError::Timeout { .. } => ServerListUpdateFailure::TimedOut,
                FetchError::Status { status, .. } => ServerListUpdateFailure::HttpStatus(*status),
                FetchError::TooLarge { cap } => ServerListUpdateFailure::TooLarge { cap: *cap },
            },
            Self::Acquisition(ServerMetPipelineError::Decode(_)) => {
                ServerListUpdateFailure::NotServerMet
            }
            Self::Store(_) => ServerListUpdateFailure::StoreFailed,
        }
    }
}

/// Why a server-list update produced no new list, as a code with its data:
/// what [`ServerListEvent::ServerListUpdateFailed`](crate::ServerListEvent::ServerListUpdateFailed)
/// carries, so a front end owns the sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerListUpdateFailure {
    /// The fetch broke before a complete response: the host could not be
    /// resolved or reached, refused, or the connection dropped.
    Unreachable,
    /// The fetch did not answer in time.
    TimedOut,
    /// The web server answered with this HTTP status instead of the file.
    HttpStatus(u16),
    /// The response was larger than `cap` bytes, rmule's ceiling for a
    /// server.met.
    TooLarge {
        /// The ceiling, in bytes.
        cap: usize,
    },
    /// What came back is not a server.met rmule reads: empty, a bad header,
    /// corrupt, or a zip archive.
    NotServerMet,
    /// The list was good but the store would not take it.
    StoreFailed,
}

/// What one URL of a server.met auto-update walk gave (ADR-0065): what its
/// list merged, or why it gave none. The walk goes on either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutoUpdateFetch {
    /// Its list merged into the walk's.
    Merged {
        /// Rows whose endpoint the list had not held.
        added: usize,
        /// Rows folded into an already-listed endpoint.
        updated: usize,
    },
    /// It gave no list, for this reason.
    Failed(ServerListUpdateFailure),
}

/// A server.met auto-update walk, acquired: each URL with what it gave, in
/// walk order, and the plan every list that merged adds up to.
pub(crate) struct AutoUpdateWalk {
    /// Each URL walked, with what it gave.
    pub(crate) fetched: Vec<(String, AutoUpdateFetch)>,
    /// What [`install_server_met_plan`] folds into the list.
    pub(crate) plan: ServerMetInstall,
}

/// Step 1 of an auto-update — **acquire** every URL of `urls` in order:
/// `rmule-bootstrap`'s walk, each URL merged onto the rows before it, one
/// failure not stopping it, and every row judged by its own URL's host
/// (ADR-0085). Touches no store, as [`acquire_server_met`] does not.
pub(crate) async fn acquire_server_met_walk<F>(
    fetcher: &F,
    urls: &[String],
    max_bytes: usize,
    installed: &[ManagedServer],
) -> AutoUpdateWalk
where
    F: Fetcher + Sync,
{
    let installed = installed.iter().filter_map(ManagedServer::to_met).collect();
    let walk =
        rmule_bootstrap::fetch_server_met_auto_update(fetcher, urls, max_bytes, installed).await;
    let fetched = urls
        .iter()
        .cloned()
        .zip(walk.per_url)
        .map(|(url, outcome)| {
            let fetch = match outcome {
                UrlWalkOutcome::Ok(install) => AutoUpdateFetch::Merged {
                    added: install.added(),
                    updated: install.updated(),
                },
                UrlWalkOutcome::Err(error) => {
                    tracing::warn!(%error, %url, "a server list auto-update address gave no list");
                    AutoUpdateFetch::Failed(ServerListUpdateError::from(error).failure())
                }
            };
            (url, fetch)
        })
        .collect();
    AutoUpdateWalk {
        fetched,
        plan: walk.merged,
    }
}

/// Step 1 of an update — **acquire**: run `rmule-bootstrap`'s server.met
/// pipeline (bounded GET → parse-before-install → aMule add-new/update-known
/// merge) against the rows already listed, and return the reconciled plan.
///
/// Touches no store, so a caller sharing its store with a running actor holds
/// no lock across the fetch. DNS-named rows are not projected into the
/// reconciliation (they have no `(ip, port)` key) and are simply left alone by
/// [`install_server_met_plan`].
pub(crate) async fn acquire_server_met<F>(
    fetcher: &F,
    url: &str,
    max_bytes: usize,
    installed: &[ManagedServer],
) -> Result<ServerMetInstall, ServerMetPipelineError>
where
    F: Fetcher + Sync,
{
    let installed = installed.iter().filter_map(ManagedServer::to_met).collect();
    rmule_bootstrap::fetch_server_met(fetcher, url, max_bytes, installed).await
}

/// Step 2 of an update — **install**: fold every reconciled row of `plan` into
/// `store`.
///
/// Folding the already-installed rows again is deliberate and idempotent: they
/// come back carrying the merge's result (a fresh name, a fresh non-empty
/// description) and the store's own fold keeps priority, static pin, and
/// failure tally regardless. The reported `added` / `updated` are the
/// pipeline's tallies — how the *download* reconciled — not a count of rows
/// touched.
pub(crate) fn install_server_met_plan<S>(
    store: &S,
    plan: &ServerMetInstall,
) -> Result<ServerListUpdate, CoreError>
where
    S: ServerListStore + ?Sized,
{
    let now = std::time::SystemTime::now();
    for entry in plan.servers() {
        if let Some(server) = ManagedServer::from_met(entry, now) {
            store.merge_server(server)?;
        }
    }
    Ok(ServerListUpdate {
        added: plan.added(),
        updated: plan.updated(),
        total: store.servers()?.len(),
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_ed2k::ServerPriority;
    use rmule_primitives::{Ed2kText, Ipv4Endpoint, ServerEndpoint, Tag, TagName, TagValue};

    use crate::store::app_config::DurableAppConfig;

    use super::*;

    const TAG_SERVERNAME: u8 = 0x01;
    const TAG_DESCRIPTION: u8 = 0x0B;

    fn endpoint(host: &str, port: u16) -> ServerEndpoint {
        ServerEndpoint::new(host, port).expect("valid endpoint")
    }

    fn met_row(ip: Ipv4Addr, port: u16, name: &str, description: &str) -> Vec<u8> {
        let mut tags = vec![Tag::new(
            TagName::compact_id(TAG_SERVERNAME),
            TagValue::String(Ed2kText::from_utf8(name)),
        )];
        if !description.is_empty() {
            tags.push(Tag::new(
                TagName::compact_id(TAG_DESCRIPTION),
                TagValue::String(Ed2kText::from_utf8(description)),
            ));
        }
        let mut bytes = Ipv4Endpoint::new(ip, port).encode().to_vec();
        bytes.extend_from_slice(&u32::try_from(tags.len()).unwrap().to_le_bytes());
        for tag in &tags {
            bytes.extend(tag.encode());
        }
        bytes
    }

    fn met_bytes(rows: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![0xE0u8];
        bytes.extend_from_slice(&u32::try_from(rows.len()).unwrap().to_le_bytes());
        for row in rows {
            bytes.extend_from_slice(row);
        }
        bytes
    }

    struct FakeFetcher(Result<Vec<u8>, FetchError>);

    impl Fetcher for FakeFetcher {
        fn get(
            &self,
            _url: &str,
            _max_bytes: usize,
        ) -> impl Future<Output = Result<Vec<u8>, FetchError>> + Send {
            let result = self.0.clone();
            async move { result }
        }
    }

    /// An on-demand acquisition run through the two steps: the downloaded list
    /// appends what is new, folds what is known, and leaves a DNS-named row —
    /// which has no `(ip, port)` key to reconcile against — alone.
    #[tokio::test]
    async fn acquisition_appends_new_rows_folds_known_and_leaves_named_rows_alone() {
        let store = DurableAppConfig::new(rmule_testkit::memory_store());
        store
            .merge_server(ManagedServer {
                endpoint: endpoint("1.2.3.4", 4661),
                name: Ed2kText::from_utf8("Known"),
                description: Ed2kText::from_bytes(Vec::new()),
                priority: ServerPriority::High,
                is_static: false,
                fail_count: 2,
                figures: None,
                grants: None,
                udp_crypt: None,
                aux_ports: None,
                listed_udp_flags: None,
            })
            .unwrap();
        store
            .merge_server(ManagedServer::listed(endpoint("mirror.example", 4661)))
            .unwrap();

        let fetcher = FakeFetcher(Ok(met_bytes(&[
            met_row(Ipv4Addr::new(1, 2, 3, 4), 4661, "Renamed", "Fresh blurb"),
            met_row(Ipv4Addr::new(5, 6, 7, 8), 4662, "Brand New", ""),
        ])));

        let installed = store.servers().unwrap();
        let plan = acquire_server_met(&fetcher, "http://mirror/server.met", 4096, &installed)
            .await
            .expect("acquisition");
        let update = install_server_met_plan(&store, &plan).expect("install");

        assert_eq!(update.added, 1);
        assert_eq!(update.updated, 1);
        assert_eq!(update.total, 3);

        let servers = store.servers().unwrap();
        let known = &servers[0];
        assert_eq!(known.name.to_display_string(), "Renamed");
        assert_eq!(known.description.to_display_string(), "Fresh blurb");
        assert_eq!(known.priority, ServerPriority::High, "priority is ours");
        assert_eq!(known.fail_count, 2, "the failure tally is ours");
        assert_eq!(servers[1].endpoint, endpoint("mirror.example", 4661));
        assert_eq!(servers[2].endpoint, endpoint("5.6.7.8", 4662));
    }

    /// A rejected payload leaves the list exactly as it was — the acquisition
    /// step fails before the install step ever runs.
    #[tokio::test]
    async fn a_rejected_payload_never_reaches_the_store() {
        let store = DurableAppConfig::new(rmule_testkit::memory_store());
        store
            .merge_server(ManagedServer::listed(endpoint("1.2.3.4", 4661)))
            .unwrap();
        // 0x0F is the known.met header — ADR-0066's header trap.
        let fetcher = FakeFetcher(Ok(vec![0x0F, 0x00, 0x00, 0x00, 0x00]));

        let installed = store.servers().unwrap();
        let outcome = acquire_server_met(&fetcher, "http://mirror", 4096, &installed).await;

        assert!(
            matches!(outcome, Err(ServerMetPipelineError::Decode(_))),
            "a bad payload is a decode rejection, got {outcome:?}"
        );
        assert_eq!(store.servers().unwrap().len(), 1);
    }

    /// A row the decoder tolerates but that cannot form an endpoint (port 0)
    /// is dropped by the install instead of failing the whole update.
    #[tokio::test]
    async fn a_portless_row_is_dropped_not_installed() {
        let store = DurableAppConfig::new(rmule_testkit::memory_store());
        let fetcher = FakeFetcher(Ok(met_bytes(&[
            met_row(Ipv4Addr::new(1, 2, 3, 4), 0, "Portless", ""),
            met_row(Ipv4Addr::new(5, 6, 7, 8), 4662, "Valid", ""),
        ])));

        let plan = acquire_server_met(&fetcher, "http://mirror", 4096, &[])
            .await
            .expect("acquisition");
        let update = install_server_met_plan(&store, &plan).expect("install");

        assert_eq!(plan.added(), 2, "the decoder tolerates both rows");
        assert_eq!(update.total, 1, "only one of them forms an endpoint");
        assert_eq!(store.servers().unwrap()[0].endpoint.port(), 4662);
    }

    /// The boxed seam runs the same pipeline as a direct `Fetcher`: an actor
    /// holding `Arc<dyn ServerListFetcher>` acquires exactly what the Join
    /// Sequence's static-dispatch call would.
    #[tokio::test]
    async fn the_boxed_seam_acquires_like_a_direct_fetcher() {
        let boxed: Arc<dyn ServerListFetcher> = Arc::new(FakeFetcher(Ok(met_bytes(&[met_row(
            Ipv4Addr::new(1, 2, 3, 4),
            4661,
            "Through the seam",
            "",
        )]))));

        let plan = acquire_server_met(&ErasedFetcher(boxed), "http://mirror", 4096, &[])
            .await
            .expect("acquisition through the boxed seam");

        assert_eq!(plan.added(), 1);
        assert_eq!(
            plan.servers()[0].name().to_display_string(),
            "Through the seam"
        );
    }
}
