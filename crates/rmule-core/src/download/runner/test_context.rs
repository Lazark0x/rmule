//! A [`RunnerContext`] wired just enough for a runner leg to drive in a unit
//! test: an in-memory store, no network, no live session, and the lookup and
//! transfer seams the test brings. Shared by every runner module's tests so
//! the scaffolding exists once.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, mpsc, watch};

use super::{RunnerContext, StopReason};
use crate::callback::DownloadReach;

/// What a test holds besides the context: the download-reach channel the
/// callback legs send on, and the run's stop — a run whose stop sender is
/// gone reads as stopped.
pub(in crate::download) struct Held {
    pub(in crate::download) download_reach_rx: mpsc::Receiver<DownloadReach>,
    /// Every event the run sends.
    pub(in crate::download) evt_rx: mpsc::Receiver<crate::service::CoreEvent>,
    /// Held, never sent on: dropping it is what would stop the run.
    pub(in crate::download) _stop_tx: watch::Sender<StopReason>,
}

/// Build the context around `source_lookup` and `peer_transfer`.
pub(in crate::download) fn runner_context<S, P>(
    source_lookup: S,
    peer_transfer: P,
    diagnostics: crate::diagnostics::DiagnosticsState,
) -> (RunnerContext<S, P>, Held) {
    let store = rmule_testkit::memory_store();
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (stop_tx, stop_rx) = watch::channel(StopReason::Active);
    let (global_callback_tx, _global_callback_rx) = mpsc::channel(4);
    let (download_reach_tx, download_reach_rx) = mpsc::channel(4);
    let runner = RunnerContext {
        store: Arc::new(crate::store::download::DurableDownloadRepository::new(
            store.clone(),
        )),
        source_lookup: Arc::new(Mutex::new(source_lookup)),
        source_asks: Arc::default(),
        peer_transfer: Arc::new(Mutex::new(peer_transfer)),
        credit: Arc::new(crate::store::credit::DurableCreditStore::new(store)),
        evt_tx,
        stop_rx,
        diagnostics,
        server_session: crate::server_session::SharedServerSession::default(),
        pending_callbacks: crate::adapters::SharedCallbackTable::default(),
        source_lookup_timeout: Duration::from_secs(5),
        callback_timeout: Duration::from_secs(30),
        global_source_registry: Arc::new(std::sync::Mutex::new(HashMap::new())),
        global_callback_tx,
        kad_source_registry: Arc::new(std::sync::Mutex::new(HashMap::new())),
        reask_reply_sink: Arc::default(),
        client_udp_tx: None,
        ip_filter: Arc::new(std::sync::RwLock::new(crate::ip_filter::IpFilter::default())),
        ipv6_advert: crate::adapters::SharedIpv6Advert::default(),
        reach: crate::reachability::SharedSelfReach::new(
            crate::KadReachLevel::fixed(false),
            crate::own_identity::SharedOwnIdentity::default(),
            crate::natt::front::SharedNattFront::default(),
        ),
        download_reach_tx,
        tunnel_claims: crate::adapters::SharedTunnelClaims::default(),
        peer_roster: crate::peer_roster::SharedPeerRoster::default(),
        resolver: crate::name_resolver::FakeNameResolver::knowing(&[]),
        part_file: Mutex::new(None),
        later_links: Mutex::new(mpsc::unbounded_channel().1),
        repair: std::sync::atomic::AtomicBool::new(false),
        seeds_tx: watch::channel(Vec::new()).0,
    };
    (
        runner,
        Held {
            download_reach_rx,
            evt_rx,
            _stop_tx: stop_tx,
        },
    )
}
