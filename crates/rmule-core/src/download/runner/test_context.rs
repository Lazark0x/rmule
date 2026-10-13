//! A [`RunnerContext`] wired just enough for a runner leg to drive in a unit
//! test: an in-memory store, no network, no live session, and the lookup and
//! transfer seams the test brings — and the loop context a fleet arm or the
//! enactor runs on over it. Shared by every runner module's tests so the
//! scaffolding exists once.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kFileLink, Ed2kText, PeerEndpoint, SourceLookupTarget, UserHash,
};
use tokio::sync::{Mutex, mpsc, watch};

use super::callbacks::CallbackContext;
use super::enact::LoopCtx;
use super::{CallbackFacts, RunnerContext, StopReason};
use crate::SourceLookupOutcome;
use crate::adapters::{PeerTransferService, PeerWorker, SourceLookupService};
use crate::callback::DownloadReach;
use crate::download::SharedRuntime;
use crate::download::state::DownloadState;
use crate::download::worker_pool::{WorkerChannels, WorkerPool};
use crate::error::DownloadFailure;
use crate::service::DownloadId;

/// Never asked: the legs these tests drive look up no sources.
#[derive(Clone)]
pub(in crate::download) struct NeverLooksUp;

impl SourceLookupService for NeverLooksUp {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        unreachable!("the leg under test never looks up sources")
    }
}

/// Never asked: the legs these tests drive spawn no worker.
pub(in crate::download) struct NeverTransfers;

impl PeerTransferService for NeverTransfers {
    async fn start_peer_worker(
        &mut self,
        _peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        unreachable!("the leg under test never spawns a peer worker")
    }
}

/// What a test holds besides the context: the download-reach channel the
/// callback legs send on, and the run's stop — a run whose stop sender is
/// gone reads as stopped.
pub(in crate::download) struct Held {
    pub(in crate::download) download_reach_rx: mpsc::Receiver<DownloadReach>,
    /// Every event the run sends.
    pub(in crate::download) evt_rx: mpsc::Receiver<crate::service::CoreEvent>,
    /// Held, never sent on: dropping it is what would stop the run.
    pub(in crate::download) _stop_tx: watch::Sender<StopReason>,
    /// Where the run's in-place reports arrive: the test answers as the
    /// actor would.
    pub(in crate::download) in_place_rx: mpsc::Receiver<crate::download::FinalFileInPlace>,
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
    let (in_place_tx, in_place_rx) = mpsc::channel(4);
    let rt = Arc::new(SharedRuntime {
        store: Arc::new(crate::store::download::DurableDownloadRepository::new(
            store.clone(),
        )),
        source_lookup: Arc::new(Mutex::new(source_lookup)),
        source_asks: Arc::default(),
        peer_transfer: Arc::new(Mutex::new(peer_transfer)),
        credit: Arc::new(crate::store::credit::DurableCreditStore::new(store)),
        evt_tx,
        diagnostics,
        server_session: crate::server_session::SharedServerSession::default(),
        awaited_inbound: crate::adapters::AwaitedInbound::default(),
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
        peer_roster: crate::peer_roster::SharedPeerRoster::default(),
        resolver: crate::name_resolver::FakeNameResolver::knowing(&[]),
        completion_fs: Arc::new(crate::download::OsCompletionFs),
        copy_turn: Arc::new(tokio::sync::Semaphore::new(1)),
        in_place_tx,
    });
    let runner = RunnerContext {
        rt,
        stop_rx,
        part_file: Mutex::new(None),
        later_links: Mutex::new(mpsc::unbounded_channel().1),
        repair: std::sync::atomic::AtomicBool::new(false),
        seeds_tx: watch::channel(Vec::new()).0,
        served: None,
        run: 0,
        completion: Arc::new(crate::download::CompletionGate::open()),
    };
    (
        runner,
        Held {
            download_reach_rx,
            evt_rx,
            _stop_tx: stop_tx,
            in_place_rx,
        },
    )
}

/// The loop context of download 1 over `runner` for `file`, its brain
/// `state`: no worker live, no callback filed, nobody reachable.
pub(super) fn loop_ctx<'a, S, P>(
    runner: &'a RunnerContext<S, P>,
    file: &'a Ed2kFileLink,
    state: DownloadState,
) -> LoopCtx<'a, S, P> {
    let (fact_tx, fact_rx) = mpsc::channel(8);
    let (adopt_tx, _adopt_rx) = mpsc::channel(4);
    let (retire_tx, _retire_rx) = mpsc::channel(4);
    LoopCtx {
        state,
        runner,
        download_id: DownloadId::from_u64(1),
        file,
        evt_tx: &runner.rt.evt_tx,
        worker_pool: WorkerPool {
            runner,
            file,
            ctx: PeerHandshakeContext {
                identity: ClientIdentity::new(
                    UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
                    Ed2kText::from_utf8("runner-test"),
                    4662,
                    0x3C,
                ),
                client_id: ClientId::from_u32(0),
                ed2k_client_id: ClientId::from_u32(0),
                public_ip: None,
                connected_server: None,
            },
            fact_tx,
        },
        command_channels: WorkerChannels::default(),
        file_hash_only_parts: Vec::new(),
        fact_rx,
        callbacks: CallbackContext::new(
            CallbackFacts {
                reach: crate::reachability::SharedSelfReach::new(
                    crate::KadReachLevel::fixed(false),
                    crate::own_identity::SharedOwnIdentity::default(),
                    crate::natt::front::SharedNattFront::default(),
                ),
                our_tcp_port: 4662,
            },
            adopt_tx,
            retire_tx,
            runner.rt.awaited_inbound.clone(),
        ),
        queued_relations: std::collections::HashSet::new(),
    }
}
