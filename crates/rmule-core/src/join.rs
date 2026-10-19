//! The core-owned **Join Sequence** (ADR-0067): cold-start orchestration
//! that joins both networks unattended, the way amuled does out of the box.
//!
//! aMule starts eD2k and Kad **independently and in parallel**, each gated only
//! on its own preference, with `ConnectToED2K` / `ConnectToKad` / `Autoconnect`
//! all defaulting **true** — a citizen daemon joins by itself. rmule reproduces
//! that as core policy rather than leaving it to every front-end (ADR-0067).
//!
//! # The sequence (order is load-bearing)
//!
//! On session start [`run_join_sequence`] runs, in this order:
//!
//! 1. **Load persisted state** — the managed server list from rmule's own store
//!    ([`ServerListStore::servers`]).
//! 2. **First-run server.met fetch** — iff the list is empty *and* eD2k is being
//!    joined *and* the operator switch is on ([`should_auto_fetch_server_met`]),
//!    run the server.met pipeline ([`fetch_server_met`](rmule_bootstrap::fetch_server_met)) through the injected
//!    [`Fetcher`], persist the reconciled endpoints, and reload. A returning
//!    user with a persisted list is not a cold start, so the fetch is skipped.
//!    A *failed* fetch does not abort or retry (amuled is one-shot: a failed
//!    cold-start fetch waits for the user) — the joins still proceed, the eD2k
//!    side simply idle with an empty list. Then, iff its switch is on, the
//!    **server.met auto-update walk** (ADR-0065): every configured URL in
//!    order over the list as loaded, one failure not stopping it, installed
//!    once, and each URL's outcome reported — aMule's `CServerList::Init`
//!    running `AutoUpdate` after its load (`ServerList.cpp:77-78`).
//! 3. **Kad seed resolution** ([`acquire_kad_seeds`]) — the same shape on the
//!    Kad side, gated only on the Kad switch: read the persisted routing table
//!    (`nodes.dat`, the file the running node writes), and only if *nothing*
//!    seeded it, run the opt-in one-shot acquisition. The switch is OFF by
//!    default, so this is aMule's "log and wait" by default (ADR-0067) and an
//!    acquisition only where a front-end asked for one.
//! 4. **Parallel independent joins** — the eD2k join (hand core the resolved
//!    rows through the list's one writer, one [`ServerListCommand::AddServer`]
//!    each, so its Managed Server List — and the swept list the global sweeps
//!    read from it, ADR-0051 — holds them) and the Kad
//!    join ([`CoreCommand::EnableKad`]) are each gated *only* on their own
//!    per-network switch. No eD2k-before-Kad dependency exists in aMule and
//!    none is invented; suppressing one network never touches the other. The
//!    Kad join fires whether or not it found seeds: an empty-table node is what
//!    arms the ed2k→Kad handoff.
//!
//! Step 3 is a leg of its own ([`kad_seeds`]) because a front-end that drives
//! `EnableKad` itself has to resolve seeds the same way without running the
//! rest of the sequence.
//!
//! # Defaults ON, caller-overridable per network
//!
//! [`JoinConfig`] defaults both switches ON — the unattended dual-network join
//! is core policy. A front-end overrides a single network
//! (`JoinConfig { connect_kad: false, ..Default::default() }`) without affecting
//! the other, honouring aMule's per-preference gating.
//!
//! # Consuming the server.met fetch without pulling reqwest into core
//!
//! The first-run hook calls `rmule-bootstrap`'s [`should_auto_fetch_server_met`] decision and
//! [`fetch_server_met`](rmule_bootstrap::fetch_server_met) pipeline through the pure [`Fetcher`] **seam** —
//! `rmule-bootstrap` with `default-features = false`, so no HTTP client or TLS
//! stack enters core's tree. The caller injects the [`Fetcher`] (a front-end
//! supplies `rmule_bootstrap::ReqwestFetcher`; tests a canned-bytes fake), so
//! core depends only on the decision + pipeline + seam.
//!
//! # Seams
//!
//! This module orchestrates the **start** of both joins. The Kad join's internal
//! cadence — the one-at-a-time bootstrap dial loop and the forced self-lookup —
//! is the Kad join mechanics (ADR-0067), downstream of the
//! [`CoreCommand::EnableKad`] issued here. The eD2k→Kad peer handoff (ADR-0067)
//! is likewise its own seam. Neither is reached by this module.

mod kad_seeds;
#[cfg(test)]
mod tests;

use std::future::Future;

use rmule_bootstrap::{
    BootstrapConfig, Fetcher, ServerMetPipelineError, should_auto_fetch_server_met,
};
use rmule_primitives::ServerEndpoint;

use crate::adapters::KadEnableConfig;
use crate::error::CoreError;
use crate::server_list::{
    AutoUpdateFetch, ServerListStore, acquire_server_met, acquire_server_met_walk,
    install_server_met_plan,
};
use crate::service::{Core, CoreCommand, ServerListCommand};

pub use kad_seeds::{KadSeedOutcome, SeedReadFault, acquire_kad_seeds};

/// Which networks the Join Sequence joins on start — **both default ON**
/// (aMule `ConnectToED2K` / `ConnectToKad`, both `true`). A front-end overrides
/// a single network without touching the other; the two joins are independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinConfig {
    /// Join the eD2k network on start (aMule `ConnectToED2K`, default `true`).
    /// Also gates the first-run server.met fetch — no point acquiring servers a
    /// disabled eD2k side will never reach.
    pub connect_ed2k: bool,
    /// Join the Kad network on start (aMule `ConnectToKad`, default `true`).
    pub connect_kad: bool,
}

impl Default for JoinConfig {
    /// aMule's out-of-box posture: both networks joined unattended.
    fn default() -> Self {
        Self {
            connect_ed2k: true,
            connect_kad: true,
        }
    }
}

/// What the first-run hook did — the observable result of step 2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirstRunFetch {
    /// The gate said no: a persisted list already existed, eD2k was not being
    /// joined, or the operator switch was off. No fetch was attempted.
    Skipped,
    /// The fetch ran and installed `added` fresh servers into the empty list.
    Installed {
        /// How many servers the fetched list added to the empty one.
        added: usize,
    },
    /// The fetch ran but failed. The list stays empty and the joins proceed;
    /// amuled is one-shot — a failed cold-start fetch waits for the user, it
    /// does not loop or abort the join (ADR-0065 / ADR-0067).
    Failed(ServerMetPipelineError),
}

/// What the server.met auto-update walk did (ADR-0065) — the second half of
/// step 2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AutoUpdateOutcome {
    /// Its switch is off (the default, as aMule's `AutoServerlist`).
    Skipped,
    /// It walked every configured URL in order: each with what it gave. An
    /// empty list means no URL is configured.
    Walked {
        /// Each URL walked, with what it gave.
        fetched: Vec<(String, AutoUpdateFetch)>,
    },
}

/// The observable outcome of the Join Sequence — what a caller logs and a test
/// asserts on. The dispatched join *commands* are proven separately (against a
/// recording sink); this is the resolved state after the sequence ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinOutcome {
    /// What the first-run server.met fetch did (step 2).
    pub first_run: FirstRunFetch,
    /// What the server.met auto-update walk did (step 2's second half).
    pub auto_update: AutoUpdateOutcome,
    /// The managed server list after the first-run hook and the walk — the
    /// exact rows the eD2k join handed core (empty when a fetch was skipped
    /// or failed on a cold start).
    pub servers: Vec<ServerEndpoint>,
    /// Where the Kad join's seeds came from (step 3).
    pub kad_seed: KadSeedOutcome,
}

/// Where the Join Sequence dispatches its join commands. Production passes the
/// live [`Core`]; tests pass a recording fake to assert the exact commands and
/// their order without a running actor. A genuine orchestration boundary (the
/// same RPITIT-async shape as the crate's other seams), not a test shim.
pub trait JoinCommandSink {
    /// Dispatch one join command. `Err` aborts the remaining joins — a dead
    /// core has nothing left to join.
    fn dispatch(&self, command: CoreCommand) -> impl Future<Output = Result<(), CoreError>> + Send;
}

impl JoinCommandSink for Core {
    fn dispatch(&self, command: CoreCommand) -> impl Future<Output = Result<(), CoreError>> + Send {
        self.send(command)
    }
}

/// Run the core Join Sequence (ADR-0067): load persisted state → first-run
/// server.met fetch if empty → parallel independent joins, defaults ON.
///
/// `store` is the persisted state (server list, read and, on a first run,
/// written). `fetcher` is the injected [`Fetcher`] seam the first-run hook
/// fetches through — reqwest stays out of core. `bootstrap` carries the
/// server.met URL, size cap, and auto-fetch switch. `join` is the per-network
/// defaults-ON posture. `kad_enable` is the front-end-assembled Kad start
/// config (the persisted-file path, any operator seeds); step 3 resolves its
/// seeds about `own_id`, the node's Kad ID
/// ([`Core::kad_id`](crate::Core::kad_id)), and it is dispatched iff
/// `join.connect_kad`, and dropped otherwise. `sink` receives the join
/// commands.
///
/// The order is load-bearing (see the module docs); the two joins are
/// independent (each gated only on its own switch). Returns the resolved
/// [`JoinOutcome`].
pub async fn run_join_sequence<S, F, K>(
    store: &S,
    fetcher: &F,
    bootstrap: &BootstrapConfig,
    join: &JoinConfig,
    mut kad_enable: KadEnableConfig,
    own_id: rmule_kad::KadId,
    sink: &K,
) -> Result<JoinOutcome, CoreError>
where
    S: ServerListStore + ?Sized,
    F: Fetcher + Sync,
    K: JoinCommandSink,
{
    // 1. Load persisted state.
    let mut listed = store.servers()?;

    // 2. First-run hook: fetch a server list iff this is a genuine cold start
    //    for a network we are joining (empty list ∧ eD2k on ∧ switch on).
    let first_run = if should_auto_fetch_server_met(
        join.connect_ed2k,
        listed.is_empty(),
        bootstrap.auto_fetch_server_met,
    ) {
        // The same two-step acquisition an on-demand update runs (ADR-0080):
        // the list is empty here, so the merge just parses and installs the
        // fresh rows — with their names, descriptions and priorities, so a
        // cold start never lands a nameless endpoint. One-shot: a failure is
        // reported, not retried.
        match acquire_server_met(
            fetcher,
            &bootstrap.server_met_url,
            bootstrap.max_server_met_bytes,
            &listed,
        )
        .await
        {
            Ok(plan) => {
                let update = install_server_met_plan(store, &plan)?;
                // Reload so the joined list is the store's persisted, deduped
                // view (the caller's source of truth), not the raw fetch order.
                listed = store.servers()?;
                FirstRunFetch::Installed {
                    added: update.added,
                }
            }
            Err(error) => FirstRunFetch::Failed(error),
        }
    } else {
        FirstRunFetch::Skipped
    };

    // 2b. The auto-update walk, behind its own switch (off by default), over
    //     the list as the first run left it. A URL that fails is reported and
    //     the walk goes on; nothing here stops the joins.
    let auto_update = if bootstrap.auto_update_enabled {
        let walk = acquire_server_met_walk(
            fetcher,
            &bootstrap.auto_update_urls,
            bootstrap.max_server_met_bytes,
            &listed,
        )
        .await;
        install_server_met_plan(store, &walk.plan)?;
        listed = store.servers()?;
        AutoUpdateOutcome::Walked {
            fetched: walk.fetched,
        }
    } else {
        AutoUpdateOutcome::Skipped
    };

    let servers: Vec<ServerEndpoint> = listed
        .iter()
        .map(|server| server.endpoint.clone())
        .collect();

    // 3. The Kad half of the same "load persisted state, then acquire only if
    //    there is nothing" shape: the persisted routing table first, an opt-in
    //    one-shot acquisition second. Gated on the Kad switch alone — the two
    //    networks stay independent — and never fatal: a stranded Kad still
    //    joins below.
    let kad_seed = if join.connect_kad {
        acquire_kad_seeds(&mut kad_enable, own_id, bootstrap, fetcher).await
    } else {
        KadSeedOutcome::Skipped
    };

    // 4. Parallel independent joins, each gated only on its own switch. Neither
    //    join waits on the other; a failed first-run fetch above still lets both
    //    fire (the eD2k side idle with an empty list, the Kad side join anyway).
    if join.connect_ed2k {
        // Through core's one list writer (ADR-0080): a core on another store,
        // or one that read its store before the fetch above wrote it, lists
        // them now; a core on the same store folds each onto itself.
        for server in listed {
            let add = ServerListCommand::AddServer { server };
            sink.dispatch(CoreCommand::ServerList(add)).await?;
        }
    }
    if join.connect_kad {
        sink.dispatch(CoreCommand::EnableKad(kad_enable)).await?;
    }

    Ok(JoinOutcome {
        first_run,
        auto_update,
        servers,
        kad_seed,
    })
}
