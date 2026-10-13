//! The handles every download run shares (ADR-0093): built once by the core
//! actor, held behind one `Arc`, and cloned into each run's
//! [`RunnerContext`](crate::download::RunnerContext) at spawn. A new core-wide
//! handle is added here and where the actor builds this, nowhere else.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, mpsc};

use crate::callback::DownloadReach;
use crate::client_udp::ClientUdpSend;
use crate::credit::SharedCreditStore;
use crate::global_sources::{GlobalCallbackSender, GlobalSourceRegistry};
use crate::ip_filter::SharedIpFilter;
use crate::kad_sources::KadSourceRegistry;
use crate::server_session::SharedServerSession;
use crate::service::{CoreEvent, SharedReaskReplySink};
use crate::store::download::DurableDownloadRepository;

pub(crate) struct SharedRuntime<S, P> {
    pub(crate) store: Arc<DurableDownloadRepository>,
    /// The core's one lookup handle: each ask clones it and runs on its own
    /// copy, so the lock is held only for the clone (ADR-0107).
    pub(crate) source_lookup: Arc<Mutex<S>>,
    /// The core's **Source Ask Budget** (ADR-0107), shared by every run.
    pub(crate) source_asks: crate::download::source_asks::SharedSourceAskBudget,
    pub(crate) peer_transfer: Arc<Mutex<P>>,
    pub(crate) credit: SharedCreditStore,
    pub(crate) evt_tx: mpsc::Sender<CoreEvent>,
    pub(crate) diagnostics: crate::diagnostics::DiagnosticsState,
    /// The shared server session, used to relay a Low-ID `OP_CALLBACKREQUEST`
    /// when enacting a `RequestCallback` decision (ADR-0039).
    pub(crate) server_session: SharedServerSession,
    /// The core-owned **Awaited Inbound** registry: the runner files every
    /// road a pending callback may be answered on — the server-relayed one
    /// before the callback is asked for, a Pending Tunnel Claim before a
    /// fallback's punch or a buddy's dial-back is — so the accept-router
    /// hands the connection to this download instead of serving it. A
    /// callback's end releases both roads at once.
    pub(crate) awaited_inbound: crate::adapters::AwaitedInbound,
    /// How long the initial source lookup waits on the connected server
    /// before giving up (`CoreConfig::source_lookup_timeout`):
    /// bounds a sourceless file's `download start` so it terminates by
    /// default instead of parking forever on an `OP_FOUNDSOURCES` that may
    /// never come.
    pub(crate) source_lookup_timeout: Duration,
    /// How long a requested callback holds its slot before the runner times it
    /// out and tries the next candidate (`CoreConfig::callback_timeout`).
    pub(crate) callback_timeout: Duration,
    /// The core-owned global-source registry (ADR-0051): the runner registers
    /// `(file_hash, sink)` so the discovery task routes server-UDP-found sources
    /// to this download.
    pub(crate) global_source_registry: GlobalSourceRegistry,
    /// The runner → discovery-task channel for per-server Low-ID callbacks (ADR-0051): a
    /// `RequestGlobalCallback` is enacted by sending the encode inputs here (the
    /// discovery owns the UDP socket). Read by the `RequestGlobalCallback`
    /// enactment arm.
    pub(crate) global_callback_tx: GlobalCallbackSender,
    /// The core-owned Kad source registry (ADR-0043): the runner registers
    /// `(file_hash → (size, sink))` so the Kad discovery task routes projected
    /// sources to this download. Registered unconditionally — with Kad
    /// disabled nothing reads it.
    pub(crate) kad_source_registry: KadSourceRegistry,
    /// The installs for every **Remote-Queued Pool** reply sink in the
    /// **Download Set**: the shared client-UDP forwarder offers the reask
    /// reply quartet (`0x91`/`0x92`/`0x93`) to each (ADR-0057). This download
    /// installs its own under its id, leased for its run.
    pub(crate) reask_reply_sink: SharedReaskReplySink,
    /// The client-UDP send half a downloader `OP_REASKFILEPING` (`0x90`) rides
    /// out (ADR-0057); `None` when the shared client-UDP socket did not bind, in
    /// which case every reask falls to the TCP full ask.
    pub(crate) client_udp_tx: Option<mpsc::Sender<ClientUdpSend>>,
    /// The core-owned IP filter: every source-ingest path — the
    /// initial server snapshot, global-UDP, Kad, and source-exchange — drops
    /// filtered High-ID rows here, before they reach any candidate pool
    /// (aMule filters in `PartFile::AddSources`/`AddClientSources` and
    /// `DownloadQueue::KademliaSearchFile` for the same reason).
    pub(crate) ip_filter: SharedIpFilter,
    /// The **Advertised IPv6** (ADR-0087): the Dial Chooser's own half of the
    /// family question, published by the actor when the advert is settled. An
    /// IPv6 source is pooled only while this holds an address — there would be
    /// nowhere to dial it from otherwise, and a worker slot spent on a
    /// conversation that cannot start is worse than an honest drop.
    pub(crate) ipv6_advert: crate::adapters::SharedIpv6Advert,
    /// **Self Reach** (ADR-0060): the one owner the **Callback
    /// Capability** and the reask gate ask, read at use and subscribed to.
    pub(crate) reach: crate::reachability::SharedSelfReach,
    /// The runner → core-actor channel for a callback that has gone silent for
    /// twelve seconds (ADR-0091). The route decision needs *our* position —
    /// reachability, the client-UDP bind, the server's `0xF9` keepalive, Kad —
    /// which only the actor holds, so the runner sends the candidate's facts
    /// there rather than keeping a second chooser (ADR-0061: one selector,
    /// every caller). A full or closed channel costs a punch attempt, never a
    /// download.
    pub(crate) download_reach_tx: mpsc::Sender<DownloadReach>,
    /// The core-owned Peer Roster (ADR-0059): the fleet loop
    /// marks it when a worker's peer session connects (the hello completes)
    /// and forgets it when the worker ends — the download leg beside the
    /// upload queue's own `mark_known`/`forget`. A peer this
    /// download is also uploading to stays known through the upload queue's
    /// own membership; the roster is kept per endpoint, so the two writers
    /// never retire each other's reason.
    pub(crate) peer_roster: crate::peer_roster::SharedPeerRoster,
    /// The **Name Resolver** a link's named sources are resolved through
    /// (ADR-0089's amendment), off the actor and bounded.
    pub(crate) resolver: crate::name_resolver::SharedNameResolver,
    /// The completion move's rename and delete (ADR-0115): the operating
    /// system's, or a test's.
    pub(crate) completion_fs: Arc<dyn crate::download::CompletionFs>,
    /// The core's one **Completion Copy** turn (ADR-0115): copies across
    /// volumes run one at a time, as aMule's completion tasks do.
    pub(crate) copy_turn: Arc<tokio::sync::Semaphore>,
    /// Where a run reports its finished file in place to the core actor,
    /// which writes the registry row and ends the Served Download in one
    /// step (ADR-0115, step 6).
    pub(crate) in_place_tx: mpsc::Sender<crate::download::FinalFileInPlace>,
}
