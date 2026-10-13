//! The peer-transfer seam (ADR-0031): the worker handle a download runner
//! drives (commands in, events out) and the production service that dials a
//! source, runs the eD2k handshake — SUI, obfuscation, buddy posture — and
//! hands back a live [`PeerWorker`].

mod dial_end;
pub(super) mod worker;

use std::future::Future;
use std::time::{Duration, Instant};

use rmule_net::peer::{Connection as PeerConnection, ObfuscationPolicy, PeerNetError};
use rmule_peer::{PartBitmap, PeerCommand, PeerHandshakeContext, PeerIdentity, SideCommand};
use rmule_primitives::{
    AichRootHash, Ed2kFileLink, Ipv4Endpoint, PartHash, PeerCrypt, PeerEndpoint, SourceSighting,
    UserHash,
};
use tokio::sync::mpsc;

use crate::ban_store::SharedBanStore;
use crate::buddy::{BuddyServePosture, BuddyUdpPosture};
use crate::ip_filter::SharedIpFilter;
use crate::reachability::{SharedSelfReach, TcpReachability, UdpReachability};
use crate::service::DialEnd;
use crate::{DownloadFailure, PartPlan};

use super::HelloAdverts;
use super::dialed_serve::SharedDialedServeSink;
use super::kad_runtime::{KadPresenceView, SharedKadBootstrap, SharedKadPump};
use super::peer_transfer::worker::{drive_joined_worker, drive_peer_worker};
use super::{InboundPeerDeps, SharedTunnelAdmit};
use crate::buddy_link::SharedBuddySlot;

/// One contiguous run of bytes a peer served, tagged with where it belongs.
/// Never a whole part on its own: cross-peer assembly (ADR-0029) may stitch
/// runs from several peers into one part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownloadedPart {
    /// The zero-based part index the bytes fall in.
    pub part_index: u32,
    /// The absolute file offset of the first byte — not an offset within the
    /// part.
    pub offset: u64,
    /// The bytes themselves; `offset + bytes.len()` is where the run ends.
    pub bytes: Vec<u8>,
}

/// Everything one peer's transfer produced, as a batch adapter implementations
/// hand back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerDownloadOutcome {
    /// The part hash set the peer supplied, if it answered `OP_HASHSETANSWER`.
    /// Provisional: it only becomes authoritative if the finished file's hash
    /// confirms it.
    pub peer_hashes: Vec<PartHash>,
    /// The byte runs it served, in arrival order.
    pub parts: Vec<DownloadedPart>,
}

/// What core asks one download worker to do. Sent down the worker's command
/// channel; the worker answers with [`PeerWorkerEvent`]s.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerWorkerCommand {
    /// Ask the uploader for a slot (`OP_STARTUPLOADREQ`) with no part chosen
    /// (ADR-0026, "The slot ask"): the worker then waits on the link, reporting
    /// the ask leaving, each rank and the grant; its part comes at the grant.
    AskSlot,
    /// Ask the uploader for the file's part hash set (`OP_HASHSETREQUEST`): the
    /// download's one hash-set ask, whose answer arrives as
    /// [`PeerWorkerEvent::HashSetReceived`] (ADR-0026).
    RequestHashSet,
    /// Stream the bytes of `plan`'s part starting at `resume_offset` (the
    /// absolute file offset of the shared prefix end), block by block, to
    /// the end of the part. `resume_offset` equals `plan.offset` for a fresh
    /// part and advances as cross-peer assembly fills the prefix (ADR-0029).
    RequestPart {
        /// The part to fetch and the byte range it spans.
        plan: PartPlan,
        /// The absolute file offset to start at — the end of the prefix other
        /// peers already filled.
        resume_offset: u64,
    },
    /// Ask this peer for the AICH recovery data of `part`, quoting the trusted
    /// master `root` (ADR-0038). Core sends this after a part fails MD4 and a
    /// trusted AICH root is available; the answer returns as
    /// [`PeerWorkerEvent::AichAnswerReceived`].
    RequestAich {
        /// The zero-based part index that failed its MD4 check.
        part: u16,
        /// The trusted master root to quote, so the peer can answer from the
        /// same tree.
        root: AichRootHash,
    },
    /// Ask this peer for the download file's AICH master hash
    /// (`OP_AICHFILEHASHREQ`), to collect trusted-set root proposals when the
    /// link carried no `h=` (ADR-0038). Fire-and-forget: the answer arrives as
    /// [`PeerWorkerEvent::AichFileHashReceived`] while a part streams.
    RequestAichFileHash,
    /// Wind the worker down. `cancel` distinguishes the teardown reason
    /// (ADR-0056): a normal completion (`false`) releases the held slot
    /// silently (`OP_...` none — a plain `ReleaseSlot`), while a local-reason
    /// abandon (`true` — the download was `CancelDownload`/`PauseDownload`ed)
    /// emits `OP_CANCELTRANSFER` (`0x56`) to the uploader before releasing, so
    /// a live aMule ends its upload session at once instead of holding the slot
    /// until its stale-timeout fires.
    Shutdown {
        /// `true` when a local abandon caused the teardown, which is what puts
        /// `OP_CANCELTRANSFER` on the wire before the slot is released.
        cancel: bool,
    },
}

/// What one download worker reports back. The stream is per peer; core folds
/// every worker's events into the one scheduling brain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerWorkerEvent {
    /// The handshake finished and the peer is usable. Core asks nothing
    /// yet: the worker's slot ask waits for [`Self::PartsAdvertised`] and its
    /// first part for [`Self::SlotGranted`] (ADR-0112, ADR-0026), so neither a
    /// failed handshake nor a part the peer lacks strands one.
    Connected,
    /// The peer's identity, as its session keeps it: sent once its hello is
    /// read — immediately before `Connected` — and again whole each time the
    /// session revises it (a legacy `OP_EMULEINFO`, an `OP_CHANGE_CLIENT_IP`),
    /// in the session's order. Its User Hash keys the credit ledger, its
    /// stance is what every later dial of the peer meets while the worker
    /// lives (ADR-0049), its client-UDP contact and crypt target are what a
    /// queue standing it earns reasks with (ADR-0057, ADR-0046), its
    /// source-exchange facts feed the download's **Source Ask Clock**
    /// (ADR-0108), its serving buddy is kept under its hash for the source's
    /// next buddy callback (ADR-0061), and its software names the source row.
    /// A dialed worker's comes off its hello; an adopted inbound worker's is
    /// the one the accept side read off the same hello.
    Identity(PeerIdentity),
    /// Secure User Identification proved the peer owns the `user_hash` it
    /// claimed; `public_key` is its RSA public key DER (ADR-0041). Core binds
    /// it as a **Secured Identity**. A connection-lifecycle fact, not a
    /// transfer step: it may arrive at any point relative to the transfer
    /// events (including before `Identity` — the router forwards it
    /// directly, off the transfer flow).
    IdentityVerified {
        /// The hash the proof was for.
        user_hash: UserHash,
        /// Its RSA public key in DER form, bound as the peer's Secured Identity.
        public_key: Vec<u8>,
    },
    /// The peer answered `OP_HASHSETREQUEST`. These hashes are provisional
    /// until the finished file's own hash confirms them.
    HashSetReceived {
        /// The part hashes in part order.
        part_hashes: Vec<PartHash>,
    },
    /// Our upload request (`OP_STARTUPLOADREQ`) left: the peer queues us,
    /// ranked or not (aMule `DS_ONQUEUE`, ADR-0090).
    SlotAsked,
    /// The peer answered our upload request with a queue position
    /// (`OP_QUEUERANKING`). Non-terminal: the worker stays connected and
    /// keeps waiting for `OP_ACCEPTUPLOADREQ`.
    Queued {
        /// Our position in the peer's upload queue.
        rank: u16,
    },
    /// The peer granted the upload slot (`OP_ACCEPTUPLOADREQ`): the download
    /// hands the worker its part, or gives the slot back (ADR-0056).
    SlotGranted,
    /// The worker waited the configured slot budget without a grant and
    /// gave up. Terminal for this worker's current part.
    SlotTimeout,
    /// One block of `part_index` arrived at absolute file `offset`. Core
    /// merges it into the shared per-part contiguous prefix (ADR-0029); the
    /// worker neither accumulates bytes nor decides completion.
    BlockReceived {
        /// The zero-based part the block belongs to.
        part_index: u32,
        /// The block's absolute file offset.
        offset: u64,
        /// The block's contents.
        bytes: Vec<u8>,
    },
    /// The worker delivered its whole assigned range for `part_index` and is
    /// ready for the next assignment. Not a completion claim — core decides
    /// completion when the shared prefix reaches the part length.
    PartStreamed {
        /// The part whose assigned range is fully delivered.
        part_index: u32,
    },
    /// The peer answered the connect-time file probe, once per worker
    /// (ADR-0112): the parts it holds, which its Source Book record keeps and
    /// the brain assigns from, and whether its copy is complete — aMule's
    /// `m_bCompleteSource`, which the download's **Source Ask Clock** keeps
    /// for the run (ADR-0108). The worker's slot — or the hash set — is asked
    /// here.
    PartsAdvertised {
        /// Its **Advertised Parts** over the file's real parts; `None` when it
        /// answered `OP_FILEREQANSNOFIL`, lacking the file.
        parts: Option<PartBitmap>,
        /// aMule's part-count-0 "complete" sentinel, or a one-part file's
        /// name answer — never a spelled-out bitmap, however full. `false`
        /// when it lacks the file.
        complete: bool,
    },
    /// The connect-time file request carried a source ask (ADR-0108), as the
    /// session that framed it says (`FileRequestSent`). The download stamps
    /// its **Source Ask Clock** here, not when it decided to want sources:
    /// aMule stamps inside `SendFileRequest`, after the hello.
    SourcesAsked,
    /// The peer answered our `OP_REQUESTSOURCES` with sources (ADR-0055). The
    /// runner refills the candidate pool from these. Non-terminal; may be empty.
    /// Each source carries the optional User Hash + crypt options a v≥2 exchange
    /// answer adds (ADR-0042), so the runner can obfuscate-dial a crypt-capable
    /// source.
    SourcesReceived {
        /// The sources it named, each with the optional User Hash and crypt
        /// options a v≥2 answer adds.
        sources: Vec<SourceSighting>,
    },
    /// The peer answered our `OP_AICHREQUEST` with the AICH recovery data for
    /// `part` (ADR-0038). `recovery_data` is the opaque tree branch; the runner
    /// verifies it against the trusted root and localizes corrupt blocks. May be
    /// empty (the peer had nothing to send).
    AichAnswerReceived {
        /// The part the recovery data is for.
        part: u16,
        /// The opaque tree branch; may be empty when the peer had nothing.
        recovery_data: Vec<u8>,
    },
    /// A peer answered our `OP_AICHFILEHASHREQ` with its AICH master `root` for
    /// the download file (ADR-0038). The runner counts it as a trusted-set root
    /// proposal from this peer's IP.
    AichFileHashReceived {
        /// The master root this peer proposes for the file.
        root: AichRootHash,
    },
    /// The peer ended our granted slot and put us back on its queue
    /// (`OP_OUTOFPARTREQS`, ADR-0057). Not terminal: the worker stays on its
    /// link, queued, and the next grant hands it its part.
    Requeued,
    /// The connection ended, for any reason. Terminal — no further event
    /// follows, and core retires the worker.
    Disconnected,
    /// The dial ended before the peer's hello, for `cause`. Not terminal on
    /// its own: [`Self::Disconnected`] or [`Self::CryptIncompatible`] follows
    /// at once, and this only names why.
    DialEnded {
        /// Why the dial ended.
        cause: crate::service::DialEnd,
    },
    /// The dial was refused before any socket: the peer's stated crypt
    /// stance and ours cannot meet (ADR-0049's outbound rule).
    /// Terminal like [`Self::Disconnected`], but core retires the source for
    /// this reason — every road to it meets the same two stances.
    CryptIncompatible,
}

#[cfg(test)]
impl PeerWorkerEvent {
    /// A probe answer spelling out every part of a `file_size`-byte file — not
    /// the complete-source sentinel, so the source-ask gate reads it as it
    /// reads a source that never advertised (ADR-0108). What an in-process
    /// fake sends after `Connected` (ADR-0030).
    ///
    /// `rmule_testkit::every_part` is the same answer for integration tests;
    /// this crate's own tests cannot take it, since the testkit links its own
    /// build of this crate, whose event is not the one under test.
    pub(crate) fn every_part(file_size: u64) -> Self {
        Self::PartsAdvertised {
            parts: Some(PartBitmap::all_present(rmule_primitives::part_count(
                file_size,
            ))),
            complete: false,
        }
    }
}

/// Whether a raw part status a source advertised — a `0x91`'s, unexpanded —
/// says it holds the whole file: aMule's part-count-0 sentinel alone
/// (ADR-0108; `m_bCompleteSource`, stock 2.3.3 `DownloadClient.cpp:405-409`,
/// `:428`, eMule `DownloadClient.cpp:516`). A spelled-out bitmap with every
/// part present is a part file whose last part arrived, not complete.
pub(crate) fn advertises_complete(status: &PartBitmap) -> bool {
    status.part_count() == 0
}

/// Core's handle to one live download worker: commands down, events up. Core
/// never touches the socket; the worker's task owns it.
pub struct PeerWorker {
    peer: PeerEndpoint,
    command_tx: mpsc::Sender<PeerWorkerCommand>,
    event_rx: mpsc::Receiver<PeerWorkerEvent>,
}

impl PeerWorker {
    /// Wrap the two channel halves of a worker whose task the caller already
    /// spawned.
    #[must_use]
    pub fn new(
        peer: PeerEndpoint,
        command_tx: mpsc::Sender<PeerWorkerCommand>,
        event_rx: mpsc::Receiver<PeerWorkerEvent>,
    ) -> Self {
        Self {
            peer,
            command_tx,
            event_rx,
        }
    }

    /// The endpoint this worker is dialing or connected to — the key core
    /// tracks it by.
    #[must_use]
    pub const fn peer(&self) -> PeerEndpoint {
        self.peer
    }

    /// Push one command to the worker. A closed channel means the worker
    /// already died, reported as [`DownloadFailure::PeerDisconnected`].
    pub async fn send(&self, command: PeerWorkerCommand) -> Result<(), DownloadFailure> {
        self.command_tx
            .send(command)
            .await
            .map_err(|_| DownloadFailure::PeerDisconnected)
    }

    /// A detached sender for the same worker, so a caller can hold the command
    /// half while the event half is borrowed mutably.
    #[must_use]
    pub fn command_sender(&self) -> mpsc::Sender<PeerWorkerCommand> {
        self.command_tx.clone()
    }

    /// Await the worker's next event. `None` is terminal and means the same as
    /// [`PeerWorkerEvent::Disconnected`] — the worker is gone.
    pub async fn next_event(&mut self) -> Option<PeerWorkerEvent> {
        self.event_rx.recv().await
    }
}

/// The peer-dial seam (ADR-0031): how core turns a candidate endpoint into a
/// live [`PeerWorker`] without owning a socket. The production adapter dials
/// for real; a test adapter hands back a scripted worker.
pub trait PeerTransferService: Send + 'static {
    /// Dial `peer` and drive a download worker for `file`. The dial proves
    /// rmule's identity with the Secure User Identification keypair the
    /// Hello Adverts hold (ADR-0041) — the Core's, the one
    /// every other hello proves with — and verifies the peer's in return.
    fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> impl Future<Output = Result<PeerWorker, DownloadFailure>> + Send;

    /// Dial `peer` with the download's [`WorkerBrief`] — how to dial and what
    /// rmule already holds. The runner always dials through here. The default
    /// ignores the brief and dials via
    /// [`start_peer_worker`](Self::start_peer_worker), so only the runtime
    /// adapter (which actually opens sockets and speaks the wire) implements
    /// it — the in-process fakes inherit the plain default.
    fn start_download_worker(
        &mut self,
        peer: PeerEndpoint,
        ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
        brief: WorkerBrief,
    ) -> impl Future<Output = Result<PeerWorker, DownloadFailure>> + Send {
        let _ = brief;
        self.start_peer_worker(peer, ctx, file)
    }

    /// Adopt the builder's one set of `AdapterCells`
    /// (ADR-0048 "Identity ownership"): `Core::builder`
    /// weaves its own adapter through this, and `CoreBuilder::peer_transfer`
    /// calls it on the adapter it installs, so an injected dial adapter's
    /// hellos state the node's adverts and SUI key, and its dials meet the
    /// node's ban store, IP filter, Address Learning and Kad handoff — never a
    /// private copy of any. Default no-op: a fake that dials nothing holds no
    /// cell.
    fn adopt_cells(&mut self, _cells: &super::AdapterCells) {}

    /// Re-point a dialed link's `0x99` Kad gate at `kad_presence`, the way
    /// [`ServeRuntimeService::set_kad_presence`](crate::adapters::ServeRuntimeService::set_kad_presence)
    /// does for a served one. Default no-op: a fake that dials nothing gates
    /// on nothing.
    fn set_kad_presence(&mut self, _kad_presence: KadPresenceView) {}
}

/// What the download runner tells a worker beyond the file it downloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerBrief {
    /// The peer's crypt side (ADR-0049): the stance its source
    /// record stated — a server-lookup `0x44` row, a source-exchange answer, a
    /// Kad row's `TAG_ENCRYPTION`, or a rung-0 Low-ID candidate's — and its
    /// User Hash, the obfuscation key's seed (ADR-0042). The dial meets it
    /// with our policy by aMule's outbound rule ([`PeerCrypt::outbound`]);
    /// [`PeerCrypt::unknown`] reads as a peer that stated no crypt.
    pub peer_crypt: PeerCrypt,
    /// What rmule already holds of the file
    /// ([`PartBitmap::downloader`](rmule_peer::PartBitmap::downloader)) when
    /// the worker is spawned. The connect-time name ask carries it,
    /// and aMule refuses a complete file's source-exchange answer to an
    /// asker whose name ask carried none.
    pub own_status: PartBitmap,
    /// Whether the connect-time request carries a source-exchange ask — the
    /// download's source need and timing (ADR-0108, aMule
    /// `IsSourceRequestAllowed`). The peer's own hello still decides whether it
    /// can be asked at all.
    pub want_sources: bool,
}

impl WorkerBrief {
    /// A plaintext dial for a download that holds nothing of `file` yet.
    #[must_use]
    pub fn fresh(file: &Ed2kFileLink) -> Self {
        Self {
            peer_crypt: PeerCrypt::unknown(),
            own_status: PartBitmap::downloader_empty(file.size),
            want_sources: true,
        }
    }
}

/// The production peer-transfer adapter. Each dialed connection is owned by a
/// per-connection **router** that fans events to the download half and (while
/// serving) the serve half; see `route_dialed_connection`.
#[derive(Clone)]
pub struct RuntimePeerTransferService {
    slot_wait_timeout: Duration,
    /// Where each dialed connection's serve half is pushed while serving
    /// (ADR-0031). Empty for download-only callers, in which case dialed
    /// connections never serve and shut down when their download finishes.
    dialed_serve_sink: SharedDialedServeSink,
    /// The core-owned `BanStore` (ADR-0064). Default/empty on the
    /// non-`Core::new` constructors (nothing is ever banned); `Core::builder`
    /// shares one instance across this adapter, `RuntimeServeRuntimeService`,
    /// and the Kad event fold.
    ban_store: SharedBanStore,
    /// The ed2k→Kad handoff sink (ADR-0067): each dialed peer that carries a
    /// Kad node hint is brokered to the running node. Default/empty on the
    /// non-`Core::new` constructors (no handoff); `Core::builder` shares one
    /// instance across this adapter, `RuntimeServeRuntimeService`, and the Kad
    /// factory.
    kad_bootstrap: SharedKadBootstrap,
    /// What a dialed peer's hello states about this node: the one
    /// [`HelloAdverts`] every hello-sending road reads per connection — the
    /// live `CT_EMULE_UDPPORTS` ports (ADR-0057), the Advertised IPv6
    /// (ADR-0087), the serving buddy and our obfuscation
    /// policy (ADR-0042/0046), which also decides with the source's stance
    /// whether the dial itself is obfuscated. Default/empty on the
    /// non-`Core::new` constructors (no advert, plaintext); `Core::builder`
    /// shares the one instance.
    adverts: HelloAdverts,
    /// The **Address Learning** store a dialed peer's `CT_MOD_YOUR_IP`
    /// reflection votes into (ADR-0084/0087).
    addresses: crate::address_learning::SharedAddressLearning,
    /// The core-owned IP filter. Default/empty on the
    /// non-`Core::new` constructors (nothing is ever filtered);
    /// `Core::builder` shares one instance across this adapter, the serve
    /// adapter, and the runner's ingest gates.
    ip_filter: SharedIpFilter,
    /// Where a dialed peer's refused hello is reported (ADR-0050). Default
    /// (never installed, reports go nowhere) off `Core::builder`.
    hello_refusals: crate::hello_refusals::SharedHelloRefusals,
    /// The node-wide services a dialed link's side-channel frames are carried
    /// to, as an accepted link's are. Default (never installed) off
    /// `Core::builder`: the frames reach nothing.
    side: SideServices,
    /// The **Served Links** a download joins before it dials (ADR-0107).
    /// Default/unshared off `Core::builder`: every download dials.
    served_links: super::SharedServedLinks,
}

/// The cells only a link's side-channel frames reach (Kad firewall checks, the
/// buddy keepalive, `0x99`); the rest of what that carrying needs the service
/// already holds.
#[derive(Clone, Default)]
struct SideServices {
    kad_pump: SharedKadPump,
    buddy_slot: SharedBuddySlot,
    peer_roster: crate::peer_roster::SharedPeerRoster,
    kad_presence: KadPresenceView,
    file_known: crate::known_files::SharedFileKnown,
    tunnel_admit: SharedTunnelAdmit,
}

impl RuntimePeerTransferService {
    /// What a link this service drives hands its frames and hello facts to.
    fn link_deps(&self) -> InboundPeerDeps {
        InboundPeerDeps {
            slot_wait_timeout: self.slot_wait_timeout,
            dialed_serve_sink: self.dialed_serve_sink.clone(),
            kad_bootstrap: self.kad_bootstrap.clone(),
            kad_pump: self.side.kad_pump.clone(),
            buddy_slot: self.side.buddy_slot.clone(),
            addresses: self.addresses.clone(),
            peer_roster: self.side.peer_roster.clone(),
            kad_presence: self.side.kad_presence.clone(),
            file_known: self.side.file_known.clone(),
            tunnel_admit: self.side.tunnel_admit.clone(),
            hello_refusals: self.hello_refusals.clone(),
            served_links: self.served_links.clone(),
        }
    }
}

impl RuntimePeerTransferService {
    /// A download-only adapter: dialed connections never produce a serve half.
    #[must_use]
    pub fn new(slot_wait_timeout: Duration) -> Self {
        Self {
            slot_wait_timeout,
            dialed_serve_sink: SharedDialedServeSink::default(),
            ban_store: SharedBanStore::default(),
            kad_bootstrap: SharedKadBootstrap::default(),
            adverts: HelloAdverts::default(),
            addresses: crate::address_learning::SharedAddressLearning::new(),
            ip_filter: SharedIpFilter::default(),
            hello_refusals: crate::hello_refusals::SharedHelloRefusals::default(),
            side: SideServices::default(),
            served_links: super::SharedServedLinks::default(),
        }
    }

    /// An adapter whose dialed connections also serve: each one's serve half is
    /// pushed to `dialed_serve_sink` when it holds a sender (i.e. while the
    /// serve activity is running). `Core::new` shares one sink between this
    /// adapter and the actor (ADR-0031).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_dialed_serve_sink(
        slot_wait_timeout: Duration,
        dialed_serve_sink: SharedDialedServeSink,
    ) -> Self {
        Self {
            slot_wait_timeout,
            dialed_serve_sink,
            ban_store: SharedBanStore::default(),
            kad_bootstrap: SharedKadBootstrap::default(),
            adverts: HelloAdverts::default(),
            addresses: crate::address_learning::SharedAddressLearning::new(),
            ip_filter: SharedIpFilter::default(),
            hello_refusals: crate::hello_refusals::SharedHelloRefusals::default(),
            side: SideServices::default(),
            served_links: super::SharedServedLinks::default(),
        }
    }

    /// Share the core-owned `BanStore` (ADR-0064): every dial checks it
    /// first and skips the connect attempt entirely for a banned candidate —
    /// "banned source candidates not dialed." `Core::builder` wires the one
    /// production instance in; the default (unset) store bans nothing.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_ban_store(mut self, ban_store: SharedBanStore) -> Self {
        self.ban_store = ban_store;
        self
    }

    /// Share the one [`HelloAdverts`]: a dialed peer's hello
    /// states what every other hello this node sends states, each advert read
    /// per dial, and at `Requested`/`Required` the dial itself is obfuscated
    /// when the source came with a User Hash. `Core::builder` wires the one
    /// production instance in; the default states nothing and dials plaintext.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_hello_adverts(mut self, adverts: HelloAdverts) -> Self {
        self.adverts = adverts;
        self
    }

    /// Share the core-owned IP filter: every dial checks it and a
    /// filtered candidate source is never connected to at all. `Core::builder`
    /// wires the one production instance in; the default (empty) filter blocks
    /// nothing.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_ip_filter(mut self, ip_filter: SharedIpFilter) -> Self {
        self.ip_filter = ip_filter;
        self
    }

    /// Share the **Served Links** a download joins before it dials
    /// (ADR-0107). `Core::builder` wires the one instance in through
    /// `adopt_cells`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_served_links(mut self, served_links: super::SharedServedLinks) -> Self {
        self.served_links = served_links;
        self
    }
}

impl Default for RuntimePeerTransferService {
    fn default() -> Self {
        Self::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT)
    }
}

impl PeerTransferService for RuntimePeerTransferService {
    fn adopt_cells(&mut self, cells: &super::AdapterCells) {
        self.dialed_serve_sink = cells.dialed_serve_sink.clone();
        self.ban_store = cells.ban_store.clone();
        self.kad_bootstrap = cells.kad_bootstrap.clone();
        self.adverts = cells.hello_adverts.clone();
        self.addresses = cells.addresses().clone();
        self.ip_filter = cells.ip_filter.clone();
        self.hello_refusals = cells.hello_refusals.clone();
        self.side.kad_pump = cells.kad_pump.clone();
        self.side.buddy_slot = cells.buddy_slot.clone();
        self.side.peer_roster = cells.peer_roster.clone();
        self.side.file_known = cells.file_known.clone();
        self.side.tunnel_admit = cells.tunnel_admit.clone();
        self.served_links = cells.served_links.clone();
    }

    fn set_kad_presence(&mut self, kad_presence: KadPresenceView) {
        self.side.kad_presence = kad_presence;
    }

    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let brief = WorkerBrief::fresh(&file);
        self.start_download_worker(peer, ctx, file, brief).await
    }

    async fn start_download_worker(
        &mut self,
        peer: PeerEndpoint,
        ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
        brief: WorkerBrief,
    ) -> Result<PeerWorker, DownloadFailure> {
        let WorkerBrief {
            peer_crypt,
            own_status,
            want_sources,
        } = brief;
        let ban_store = self.ban_store.clone();
        let ip_filter = self.ip_filter.clone();
        let served_links = self.served_links.clone();
        let deps = self.link_deps();
        // Every advert read now, per dial: what is true when the
        // peer is met is what the hello says — the SUI keypair included, with
        // a challenge minted for this dial alone (ADR-0041 anti-replay), so a
        // download proves with the one key every other hello proves with
        // `peer_crypt` is the peer's stated crypt side; the dial
        // meets it with our policy by aMule's outbound rule (ADR-0049) —
        // obfuscated, plaintext, or refused before any socket.
        let options = self.adverts.connect_options(peer_crypt);
        let ours = ObfuscationPolicy::stance_of(options.obfuscation.map(|config| config.policy));
        let (command_tx, command_rx) = mpsc::channel(8);
        let (event_tx, event_rx) = mpsc::channel(16);
        tokio::spawn(async move {
            // The IP filter, aMule `CUpDownClient::TryToConnect` /
            // `SendHelloPacket`: a candidate source whose IP is filtered is
            // never dialed — reported like a connect failure so the runner
            // backfills the slot (the ban gate's exact shape, below). The
            // verdict is bound first so the read guard never crosses an await.
            let ip_filtered = ip_filter
                .read()
                .expect("ip filter lock")
                .is_filtered_peer(peer);
            if ip_filtered {
                end_dial(&event_tx, DialEnd::IpFiltered).await;
                let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                return;
            }
            // ADR-0064, peer-TCP enforcement: a banned candidate source is
            // never dialed at all — reported the same way a real connect
            // failure is, so the runner backfills the slot exactly as it
            // would for any other dead source. Kad's own routing/search
            // surface is untouched (no ban gate there).
            if ban_store.lock().await.is_banned(peer.ip(), Instant::now()) {
                end_dial(&event_tx, DialEnd::Banned).await;
                let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                return;
            }
            // One peer, one link (ADR-0107): a peer linked to us already is
            // asked over that link, as aMule asks a client over the socket it
            // holds (`BaseClient.cpp:1489-1496`); a second link would make it
            // drop the first (`ClientList.cpp:400-403`).
            if let Some(joined) = served_links.join(peer, &event_tx).await {
                tracing::debug!(?peer, "download rides the peer's served link");
                drive_joined_worker(
                    joined,
                    file,
                    own_status,
                    want_sources,
                    command_rx,
                    event_tx,
                    deps.slot_wait_timeout,
                )
                .await;
                return;
            }
            // Connect + identify run inside the worker task, off the runner's
            // critical path (ADR-0030). A connect or handshake failure becomes
            // an ordinary `Disconnected` worker event so the runner backfills
            // a replacement instead of aborting the whole download.
            let conn = match PeerConnection::connect(peer, ctx, options).await {
                Ok(conn) => conn,
                // The stances cannot meet: named apart from a
                // dead source, so the brain retires the source for that
                // reason rather than as unreachable.
                Err(PeerNetError::CryptIncompatible) => {
                    end_dial(&event_tx, dial_end::crypt_refusal(peer_crypt, ours)).await;
                    let _ = event_tx.send(PeerWorkerEvent::CryptIncompatible).await;
                    return;
                }
                Err(error) => {
                    end_dial(&event_tx, dial_end::connect_failure(&error)).await;
                    let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                    return;
                }
            };
            // A dialed worker has not identified yet (`None`), so the drive body
            // waits for the peer's hello. An adopted inbound worker passes
            // `Some((user_hash, crypt))` instead (ADR-0039).
            drive_peer_worker(
                conn,
                peer,
                file,
                own_status,
                want_sources,
                None,
                command_rx,
                event_tx,
                deps,
            )
            .await;
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

/// Name why a dial ended before the hello; the terminal event follows.
pub(super) async fn end_dial(event_tx: &mpsc::Sender<PeerWorkerEvent>, cause: DialEnd) {
    let _ = event_tx.send(PeerWorkerEvent::DialEnded { cause }).await;
}

/// Enact one ADR-0058 firewall-check **dial-back** (the responder's v7+ path):
/// connect back to the firewalled `requester`'s TCP port over the reusable
/// peer-TCP dial surface, complete the eD2k hello, and deliver the null
/// `OP_KAD_FWTCPCHECK_ACK` — the connect-back that proves the requester's TCP
/// port is reachable — then close. A refused dial (connect failure, or a peer
/// that never finishes its hello) is silent, matching aMule's `RequestTCP`.
///
/// `requester_crypt` is the requester's own crypt side as the broker read it
/// off the check, met with our policy from `adverts` by the
/// shared rule [`PeerCrypt::outbound`]: obfuscated toward the requester's
/// hash when both support crypt and one asks, as a must when either requires
/// it; plaintext otherwise; and refused before any socket when a side that
/// requires crypt meets one that cannot provide it.
///
/// The hello is the one every outbound connection sends (aMule
/// `CClientTCPSocket::OnConnect` → `SendHelloPacket`,
/// `ClientTCPSocket.cpp:2036`; emule-qt `UpDownClient.cpp:2047-2049`), so it
/// starts from the same [`HelloAdverts`] read as every other hello:
/// our reask/Kad ports (`BaseClient.cpp:1482` writes `UDPPORTS` on
/// every hello) and the Kad-version nibble with them, our IPv6, our real crypt
/// policy, and our buddy — whose tags gate only on firewalled-and-buddied
/// And nothing keeps a firewalled node that holds a buddy from
/// answering a firewall check.
pub(crate) async fn enact_tcp_dial_back(
    requester: Ipv4Endpoint,
    requester_crypt: PeerCrypt,
    adverts: &HelloAdverts,
    ctx: PeerHandshakeContext,
) {
    let peer = PeerEndpoint::V4(requester);
    let options = adverts.connect_options(requester_crypt);
    match PeerConnection::connect_identified(peer, ctx, options).await {
        Ok((conn, _identity)) => {
            let _ = conn
                .send(PeerCommand::Side(SideCommand::SendKadFirewallAck))
                .await;
            // `shutdown` drains the queued ack onto the socket before it closes
            // (the driver frames each command in order), then ends the session —
            // aMule's `KS_CONNECTED_FWCHECK` → `KS_NONE`.
            let _ = conn.shutdown().await;
            tracing::debug!(
                ?requester,
                "kad firewall dial-back: OP_KAD_FWTCPCHECK_ACK delivered (ADR-0058 responder)"
            );
        }
        Err(error) => {
            tracing::debug!(
                ?requester,
                %error,
                "kad firewall dial-back connect refused; silent (ADR-0058)"
            );
        }
    }
}

/// Map the Kad flag of **Self Reach** onto the ADR-0061
/// buddy-serve posture the FINDBUDDY responder reads — Kad alone, as aMule's
/// responder reads `GetFirewalled()` and the UDP tester
/// (`KademliaUDPListener.cpp:1430`, `4e8f2b3c`): an open node (both TCP and UDP
/// open) may serve as a buddy; a firewalled or not-yet-verified surface
/// refuses.
pub(crate) fn buddy_serve_posture(reach: &SharedSelfReach) -> BuddyServePosture {
    BuddyServePosture {
        tcp_reachable: matches!(reach.kad_tcp(), TcpReachability::Open),
        udp: match reach.kad_udp() {
            UdpReachability::Open { .. } => BuddyUdpPosture::Open,
            UdpReachability::Firewalled => BuddyUdpPosture::Firewalled,
            UdpReachability::Unverified => BuddyUdpPosture::Unverified,
        },
    }
}

#[cfg(test)]
mod tests;
