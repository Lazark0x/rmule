//! The Kad seam (ADR-0043/0067): the channel core talks to a running Kad node
//! through, the enable-time configuration, the ed2k→Kad bootstrap handoff
//! sink, and the projection of Kad keyword rows onto core search vocabulary.

mod callback_walk;
mod cells;
pub(crate) use callback_walk::{CallbackWalkAsk, CallbackWalkReply, request_kad_callback_walk};
pub use cells::KadCells;
mod handoff;
mod node;
mod presence;
pub(crate) use presence::{KadPresenceChanges, KadPresenceLease, KadPresenceView};
mod pump_state;
mod udp_firewall_check;

pub use node::RuntimeKadFactory;

use std::future::Future;
use std::net::SocketAddrV4;
use std::sync::Arc;

use rmule_peer::PeerIdentity;
use rmule_primitives::{
    Ed2kText, FileHash, Ipv4Endpoint, KeywordQuery, PeerEndpoint, SearchResult, SearchResultOrigin,
    SourceLookupTarget,
};
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::CoreError;
use rmule_ed2k::SearchResultSkipReason;

/// The **ed2k→Kad handoff** broker sink (ADR-0067): where a connected eD2k
/// peer's Kad node hint is pushed for the running Kad node to bootstrap from.
/// Carries the projected `Ipv4Endpoint` (peer IP + parsed Kad UDP port), never a
/// Kad wire type — the Kad seam's projected-vocabulary rule (the pump converts to
/// `KadNodeEndpoint` at the boundary). **Empty (`None`) until `EnableKad`**
/// installs a sender through the running node's factory — that emptiness is the
/// gate's **running** leg: a peer that carries a Kad hint while Kad is off has
/// its hint dropped here, exactly as aMule's `CKademlia::Bootstrap` early-returns
/// on `!m_running`. The node then applies the *not-joined* and *shared 10 s
/// throttle* legs. Mirrors [`SharedDialedServeSink`](super::dialed_serve::SharedDialedServeSink)'s "empty while not
/// serving" ownership pattern (`Core::builder` creates it, clones it into every
/// adapter that pushes, and the Kad factory installs the sender on start).
pub(crate) type SharedKadBootstrap = crate::mailbox::Mailbox<Ipv4Endpoint>;

/// The one core-owned way to reach a running Kad node from **outside its own
/// pump** — the two ADR-0058 requester signals that originate on other surfaces.
///
/// Empty until `EnableKad` installs a sender, and empty again once the node
/// stops — which is the honest gate: a port-mapping grant that lands while Kad
/// is off has nothing to recheck, a firewall-check ack that arrives then
/// answers a check nobody made, and an absent sender says so without anyone
/// having to ask whether Kad is running. Created once by `Core::builder`,
/// cloned into the Kad factory (which fills it) and into the port-mapping
/// runtime, the accept path and the actor (which drain it), the same shape as
/// [`SharedKadBootstrap`] above.
///
/// Every use is a `try_send` that never crosses an `.await`, and neither the
/// port mapper's enactment path nor the peer accept path must be able to block
/// on a Kad lock.
pub(crate) type SharedKadPump = crate::mailbox::Mailbox<KadPumpCommand>;

/// Ask the running Kad node to recheck our reachability now (ADR-0086).
///
/// Best effort in both directions: no node running is a no-op, and a
/// momentarily full inbox drops the request rather than blocking the caller.
/// Dropping is safe *because* the node rate-limits externally triggered
/// rechecks anyway — a lost one would have been refused by the five-minute
/// guard more often than not.
pub(crate) fn request_kad_recheck(sink: &SharedKadPump) {
    push_kad_pump(sink, KadPumpCommand::RecheckReachability);
}

/// Carry one `OP_KAD_FWTCPCHECK_ACK` (`0xA8`) from the peer surface it landed on
/// to the running Kad node (ADR-0058 requester, the v7+ ack path).
///
/// A helper answering our `0x53` proves our TCP port open by *dialing it* and
/// acking over that link, so the proof arrives on the peer socket — the one
/// surface that knows nothing about Kad. This is the whole bridge: the peer
/// session reports the packet, core names the dialing peer's IP, and the node
/// applies the 180 s outstanding-check window before it counts a leg. Without
/// it the ≥2-ack rule can only be met by the legacy `0x59`, which rmule requests
/// solely from a Kad-version-≤6 contact, so a modern counterparty could never
/// carry the verdict open however reachable we actually were.
///
/// An IPv6 peer is dropped: a Kad contact packs a 32-bit address (ADR-0085), so
/// no `0x53` this node ever sent could have named it.
pub(crate) fn report_kad_firewall_ack(sink: &SharedKadPump, peer: PeerEndpoint) {
    let Some(peer) = peer.as_v4() else {
        tracing::debug!(%peer, "kad TCP check: OP_KAD_FWTCPCHECK_ACK from an IPv6 peer dropped");
        return;
    };
    tracing::debug!(
        from = %peer.ip,
        port = peer.port,
        "kad TCP check: OP_KAD_FWTCPCHECK_ACK arrived on a peer link; handed to the Kad node"
    );
    push_kad_pump(sink, KadPumpCommand::TcpFirewallAck(peer.ip));
}

/// Carry one `OP_FWCHECKUDPREQ` (`0xA7`) from the peer link it landed on to
/// the running Kad node (ADR-0058, rmule as **UDP Firewall Helper**; aMule
/// `ClientTCPSocket.cpp:1942-1948`).
///
/// The request rides peer TCP but its answer is a Kad datagram, so the
/// Kad-ignorant session reports the body and core names the dialing peer's
/// IP — the address the node sends `0x62` to. With no node running the
/// request is dropped, as aMule ignores it when Kad is off
/// (`BaseClient.cpp:3993-3997`). An IPv6 peer is dropped too: the `0x62`
/// is a Kad datagram, and Kad speaks IPv4 only (ADR-0085).
///
/// `roster` answers the helper-bias question the sans-I/O node cannot
/// (aMule `GetUploadState() != US_NONE || GetDownloadState() != DS_NONE
/// || GetChatState() != MS_NONE`, `BaseClient.cpp:4002-4003`): whether we
/// already have an active upload, download or chat with this exact IP,
/// consulted here — the one place both the peer's identity and core's roster
/// are in scope — and carried into the node's answer as `caller_known`.
pub(crate) fn report_kad_udp_firewall_request(
    sink: &SharedKadPump,
    peer: PeerEndpoint,
    request: Vec<u8>,
    roster: &crate::peer_roster::SharedPeerRoster,
) {
    let Some(peer) = peer.as_v4() else {
        return;
    };
    let caller_known = roster.knows(peer.ip);
    push_kad_pump(
        sink,
        KadPumpCommand::UdpFirewallRequest {
            requester: peer.ip,
            request,
            caller_known,
        },
    );
}

/// Best-effort push onto a running node's pump: no node is a no-op, and a full
/// inbox drops rather than blocking a caller that is holding a socket open.
fn push_kad_pump(sink: &SharedKadPump, command: KadPumpCommand) {
    if let Err(reason) = sink.send(command) {
        tracing::trace!(?reason, "Kad pump signal dropped");
    }
}

/// Broker one connected peer's Kad hint to the running node (ADR-0067). A
/// no-op unless the peer advertised a usable Kad contact
/// ([`PeerIdentity::kad_bootstrap_port`] — aMule's `KadPort ∧ KadVersion > 1`)
/// *and* Kad is running (the sink holds a sender). The hello carries only the
/// Kad port, so the endpoint's IP is the live connection's remote address. Best
/// effort: a full sink just drops the hint (the node bootstraps from the next
/// peer), never blocking the connection path.
pub(crate) async fn broker_peer_kad_handoff(
    sink: &SharedKadBootstrap,
    peer: PeerEndpoint,
    identity: &PeerIdentity,
) {
    let Some(kad_port) = identity.kad_bootstrap_port() else {
        return;
    };
    // A Kad contact packs a 32-bit address (ADR-0085): an IPv6 peer's hint
    // names no contact this node could dial.
    let Some(peer) = peer.as_v4() else {
        return;
    };
    if let Err(reason) = sink.send(Ipv4Endpoint::new(peer.ip, kad_port)) {
        tracing::trace!(?reason, "ed2k->Kad handoff hint dropped");
    }
}

/// The Core-side seam to one running Kad node (ADR-0043). Deliberately in
/// *projected* vocabulary — file hashes and proven Peer Sources, never Kad
/// wire types: the **Kad Source Row Projection** is sealed inside `rmule-kad`
/// (only its decoder mints direct candidates), so a test fake of this trait
/// cannot fabricate provenance it doesn't have, and Core correctness tests
/// run with no socket. `&self` receivers so the discovery task drives sends
/// and receives from one `select!` (the transport precedent above).
pub trait KadSourceChannel: Send + Sync + 'static {
    /// Walk toward `target`'s Kad key and search the nearest nodes for
    /// sources (the **Kad Requester** role).
    fn search_sources(&self, target: SourceLookupTarget) -> impl Future<Output = ()> + Send;

    /// Register `target` for publication (the **Kad Publisher** role): the
    /// node publishes immediately and republishes on its own 5-hour cadence.
    fn publish_source(&self, target: SourceLookupTarget) -> impl Future<Output = ()> + Send;

    /// Withdraw `target` from publication (the **Kad Publisher** role): the
    /// node stops republishing it, because it is no longer offered (ADR-0106,
    /// "The registry against the disk"). Default: a channel that never
    /// republishes has nothing to withdraw.
    fn withdraw_source(&self, target: SourceLookupTarget) -> impl Future<Output = ()> + Send {
        let _ = target;
        async {}
    }

    /// The next projected source batch for a searched file, or `None` once
    /// the node has stopped.
    ///
    /// Must be cancel-safe: the discovery task races it against its sweep
    /// tick in one `select!` and drops the pending call at every sweep, and it
    /// reads the first `None` as the node's death — the one liveness signal
    /// the Kad Activity retires on. A cancelled call must lose
    /// nothing a later call needs to answer.
    fn next_sources(
        &self,
    ) -> impl Future<Output = Option<(FileHash, crate::kad_sources::KadAnswer)>> + Send;

    /// Walk toward `query`'s lead-keyword Kad ID and search the nearest storers'
    /// keyword indexes (the **Kad Requester**, ADR-0062) — or join the walk
    /// already on that keyword. The v1 emit is the plain lead keyword; every
    /// row is screened by `query` before it reaches `results` (ADR-0034).
    /// The walk's answers arrive on `results` alone, already
    /// in the search stream's `SearchResult` vocabulary (the pump projects the
    /// node's dual-form rows, keeping this seam free of Kad wire types), and
    /// `results` is dropped when the walk ends — the Kad leg's
    /// settle signal — after it is told how the walk ended.
    /// Default: a channel without keyword support drops `results`, settling
    /// the leg at once.
    fn search_keyword(
        &self,
        query: KeywordQuery,
        results: crate::KadKeywordSink,
    ) -> impl Future<Output = ()> + Send {
        let _ = (query, results);
        async {}
    }
}

/// One Kad node, two drivers: the discovery engine (search + receive) and the
/// **Kad Publisher** (publish) both reach it through an `Arc`. The seam's
/// `&self` methods are already `Sync`, so the split needs no extra channel.
impl<C: KadSourceChannel> KadSourceChannel for Arc<C> {
    fn search_sources(&self, target: SourceLookupTarget) -> impl Future<Output = ()> + Send {
        (**self).search_sources(target)
    }

    fn publish_source(&self, target: SourceLookupTarget) -> impl Future<Output = ()> + Send {
        (**self).publish_source(target)
    }

    fn withdraw_source(&self, target: SourceLookupTarget) -> impl Future<Output = ()> + Send {
        (**self).withdraw_source(target)
    }

    fn next_sources(
        &self,
    ) -> impl Future<Output = Option<(FileHash, crate::kad_sources::KadAnswer)>> + Send {
        (**self).next_sources()
    }

    fn search_keyword(
        &self,
        query: KeywordQuery,
        results: crate::KadKeywordSink,
    ) -> impl Future<Output = ()> + Send {
        (**self).search_keyword(query, results)
    }
}

/// This node as its Kad node presents itself (ADR-0043, ADR-0048): core's
/// own, never a front end's to carry. The actor hands it to
/// [`KadRuntimeFactory::start`] beside the command's [`KadEnableConfig`].
#[derive(Clone, Debug)]
pub struct KadNodeIdentity {
    /// The durable node ID: this node's 128-bit place in the Kad keyspace,
    /// read from core's own store at build
    /// (`AppConfigStore::ensure_kad_identity`) unless a tool named one with
    /// [`CoreBuilder::kad_id`](crate::CoreBuilder::kad_id) — stable across
    /// restarts and across a port change.
    ///
    /// No UDP port rides with it: the node shares the core's one client-UDP
    /// bind (ADR-0057), so a port here could only be a second truth to
    /// disagree with it. [`CoreSettings::udp_port`](crate::CoreSettings::udp_port)
    /// is where the operator's port is configured.
    pub kad_id: rmule_kad::KadId,
    /// The **credentials** rmule presents when it dials a peer on Kad's
    /// behalf — the ADR-0058 firewall-check dial-back's connect-back and the
    /// UDP-check helper dial: the Core Settings' (ADR-0069), as the node's
    /// other starts present them. Their TCP port is also the one advertised
    /// in Kad hellos and carried as the publish `SOURCEPORT` — peers dial it.
    /// The User Hash they present — also the Kad Publisher's source ID and
    /// our buddy identity's hash — is the node's, fixed at build; a
    /// firewalled requester only needs a well-formed hello plus the ack to
    /// count our connect-back, so it never correlates on these fields. The
    /// SUI keypair that proves it is the Core's, loaded at build, so a
    /// Kad-only node that never serves still proves itself on every hello.
    pub peer_credentials: crate::ClientCredentials,
    /// The **Kad UDP Key**: the private per-installation seed every Kad UDP
    /// verify key this node hands out is derived from — aMule's
    /// `thePrefs::GetKadUDPKey()`, persisted as `/Obfuscation/CryptoKadUDPKey`
    /// and minted once from `GetRandomUint32()` (`Preferences.cpp:1541`), fed
    /// per target IP through `CPrefs::GetUDPVerifyKey`
    /// (`kademlia/kademlia/Prefs.cpp:235-243`). Never transmitted, only its
    /// per-IP derivations are.
    ///
    /// Read from core's own store at build
    /// (`AppConfigStore::ensure_kad_udp_key`), because it must survive a
    /// restart: a fresh seed silently invalidates every key a counterparty
    /// learned for us, pushing each back through the three-way. Read only
    /// while the core's obfuscation policy arms the Kad crypt
    /// ([`CoreSettings::obfuscation`](crate::CoreSettings::obfuscation)).
    pub kad_udp_key: u32,
}

/// Everything `CoreCommand::EnableKad` carries to start the Kad node
/// (ADR-0043): how to start it — seeds, the persisted routing table, the
/// bench knobs. Who it is, [`KadNodeIdentity`], is core's own.
#[derive(Clone, Debug)]
pub struct KadEnableConfig {
    /// Known node endpoints (IP, UDP port) to bootstrap the routing table
    /// from.
    pub bootstrap: Vec<SocketAddrV4>,
    /// Contacts that already carry an **earned Kad ID** — the "v1/v2-merge"
    /// half of a decoded nodes.dat ([`NodesDatInstall::Contacts`],
    /// ADR-0065). They enter the routing table directly
    /// (`KadCommand::MergeContacts`), no bootstrap round trip needed, which is
    /// what makes a warm restart actually warm: the file the driver writes on
    /// shutdown ([`nodes_dat_path`](Self::nodes_dat_path)) comes back as these.
    ///
    /// Distinct from [`bootstrap`](Self::bootstrap) on purpose: a bare
    /// endpoint has to be *asked* who it is (dial, wait for the answer, one at
    /// a time on the 15 s/2 s cadence), while a contact is already placed in
    /// the keyspace.
    ///
    /// [`NodesDatInstall::Contacts`]: rmule_bootstrap::NodesDatInstall::Contacts
    pub contacts: Vec<rmule_kad::KadContact>,
    /// Where to persist the routing table as a v2 `nodes.dat`:
    /// the front-end supplies `<data-dir>/nodes.dat` — the same config-dir the
    /// server list and identity load from — so the node reloads its contacts
    /// across restarts (ending cold-start-every-run Kad). `None` keeps the node
    /// ephemeral (the test shape; the public-smoke path writes nothing to
    /// disk). Threaded straight to the driver's
    /// [`rmule_net::kad::KadNetConfig::nodes_dat_path`].
    pub nodes_dat_path: Option<std::path::PathBuf>,
    /// Declare our own reachability open instead of waiting for the ADR-0058
    /// self-checks to converge — the **Core-Pumped Stimulus Node** posture
    /// Applied through
    /// `Reachability::assume_open`.
    ///
    /// `false` everywhere but the harness stimulus: a deployment keeps the live
    /// verdicts, so a genuinely firewalled node still refuses to serve as a buddy.
    /// The stimulus needs it because the ADR-0061 recruit gate reads *both*
    /// verdicts, and neither can settle open in a two-node swarm — the counterparty
    /// would be refused before it ever revealed the behaviour under capture.
    pub assume_open_reachability: bool,
    /// Where to write the node's per-datagram tap (ADR-0022), the same
    /// format `kad join-node --capture-dir` writes and
    /// `assert_kad_verify_keys`-style verdicts read. `None` (every caller but
    /// `ed2k serve start --kad-capture-dir`) writes no bytes to disk — the
    /// tap is a diagnostic opt-in, not a default. Threaded
    /// straight to [`rmule_net::kad::KadNetConfig::capture_dir`]; no TUI knob.
    pub kad_capture_dir: Option<std::path::PathBuf>,
    /// A caller's own stop lever over the running node, which
    /// the pump's `Arc`-shared [`RuntimeKadChannel`] would otherwise stop only
    /// when its last holder drops at process exit. `None` for every caller but `ed2k serve start
    /// --kad-capture-dir`, which needs to observe a *finalized* ADR-0022 tap
    /// before its own exit. The activity always wires its own lever into the
    /// pump; a lever installed here becomes a caller of
    /// that activity's one stop, confirmed once the pump ended clean.
    pub kad_shutdown: Option<KadShutdownSlot>,
}

/// The pump task's half of a [`KadShutdownSlot`]: the stop signal to await
/// and the confirmation to fire once stopped.
type KadShutdownParts = (oneshot::Receiver<()>, oneshot::Sender<()>);

/// A one-shot stop request into a running node's driver-pump task, paired
/// with a one-shot confirmation fired once the pump has called
/// [`KadNetHandle::shutdown`](rmule_net::kad::KadNetHandle::shutdown) and
/// returned — the ADR-0022 tap, if any, is finalized by the time it fires
/// Installed on [`KadEnableConfig::kad_shutdown`] before
/// `EnableKad`; `KadShutdownSlot::take` hands the pump task its half at
/// start, [`KadShutdownHandle::request_and_wait`] is the caller's half.
#[derive(Clone, Default)]
pub struct KadShutdownSlot(Arc<std::sync::Mutex<Option<KadShutdownParts>>>);

impl std::fmt::Debug for KadShutdownSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KadShutdownSlot").finish_non_exhaustive()
    }
}

impl KadShutdownSlot {
    /// A fresh, empty slot plus the caller-side handle. The caller installs
    /// the slot on [`KadEnableConfig::kad_shutdown`] and keeps the handle to
    /// fire once the node should stop.
    #[must_use]
    pub fn new() -> (Self, KadShutdownHandle) {
        let (stop_tx, stop_rx) = oneshot::channel();
        let (stopped_tx, stopped_rx) = oneshot::channel();
        (
            Self(Arc::new(std::sync::Mutex::new(Some((stop_rx, stopped_tx))))),
            KadShutdownHandle {
                stop: Some(stop_tx),
                stopped: Some(stopped_rx),
            },
        )
    }

    /// Take the pump task's half, once. Every start gets a slot of its own
    /// (a restart calls `KadRuntimeFactory::start` again over the same
    /// factory, with a fresh slot), so a slot the node never started —
    /// `start` never called, or one a node already took — finds it empty and
    /// runs with no external lever, same as `None`.
    pub(crate) fn take(&self) -> Option<KadShutdownParts> {
        self.0.lock().ok()?.take()
    }
}

/// The caller's half of a [`KadShutdownSlot`].
pub struct KadShutdownHandle {
    stop: Option<oneshot::Sender<()>>,
    stopped: Option<oneshot::Receiver<()>>,
}

/// Split an installed [`KadEnableConfig::kad_shutdown`] slot into the pump
/// task's two halves, or `(None, None)` for a caller that installed none.
pub(crate) fn split_kad_shutdown(
    config: &KadEnableConfig,
) -> (Option<oneshot::Receiver<()>>, Option<oneshot::Sender<()>>) {
    match config.kad_shutdown.as_ref().and_then(KadShutdownSlot::take) {
        Some((rx, tx)) => (Some(rx), Some(tx)),
        None => (None, None),
    }
}

impl KadShutdownHandle {
    /// Signal the node's pump task to stop and wait up to `grace` for its
    /// ADR-0022 tap to finalize. `true` once confirmed inside `grace`;
    /// `false` on timeout (the node may still finish, unobserved) or if the
    /// node was never started — the stopped receiver then closes at once,
    /// which reads the same as a timeout: this lever has nothing useful to
    /// report either way.
    pub async fn request_and_wait(mut self, grace: std::time::Duration) -> bool {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let Some(stopped) = self.stopped.take() else {
            return false;
        };
        matches!(tokio::time::timeout(grace, stopped).await, Ok(Ok(())))
    }
}

impl KadNodeIdentity {
    /// The node's Kad-UDP crypt under the core's obfuscation policy: the
    /// verify keys `(seed, own public IP)` always, and datagram obfuscation
    /// while a policy is set.
    ///
    /// One policy, not a Kad knob (ADR-0046 "Policy surface": a separate
    /// datagram policy was rejected because aMule exposes one crypt setting):
    /// aMule obfuscates a Kad datagram only while
    /// `IsClientCryptLayerSupported()` (`MuleUDPSocket.cpp:282-284`), which is
    /// what a set policy arms for the send side, and the crypt ladder the
    /// node's source publishes (`TAG_ENCRYPTION`, ADR-0091) is one it
    /// actually speaks. The receive side is not policy-gated: aMule derives
    /// the verify key whatever its setting and tries it on every client
    /// datagram (`EncryptedDatagramSocket.cpp:187-195`), so the keys are held
    /// under `off` too.
    ///
    /// The public IP binds the keys counterparties hand us (aMule
    /// `CKadUDPKey(key, GetPublicIP())`); unknown at start, it is
    /// `0.0.0.0` — aMule's `GetPublicIP() == 0` — under which learned keys
    /// still echo, since both sides of the binding read the same value.
    pub(crate) fn kad_crypt(
        &self,
        policy: Option<rmule_net::peer::ObfuscationPolicy>,
        public_ip: Option<std::net::Ipv4Addr>,
    ) -> rmule_kad::KadObfuscation {
        let public_ip = public_ip.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
        if policy.is_some() {
            rmule_kad::KadObfuscation::new(rmule_net::kad::os_datagram_nonce)
                .with_verify_keys(self.kad_udp_key, public_ip)
        } else {
            rmule_kad::KadObfuscation::receive_only(self.kad_udp_key, public_ip)
        }
    }
}

/// The core's one bound client-UDP socket, as a starting Kad node sees it
/// (ADR-0057's socket unification).
///
/// Handed to [`KadRuntimeFactory::start`] rather than held by the factory,
/// because the factory is woven before any socket exists and the socket is
/// bound before any `EnableKad` can arrive: passing it at the one moment both
/// are true removes the late-bound cell the two would otherwise need, and
/// makes the dependency impossible to forget — there is no way to start a Kad
/// node without naming the bind it rides.
#[derive(Clone)]
pub struct ClientUdpBind {
    /// The socket every Kad datagram leaves by — the port a serving buddy
    /// observed at the `0x51` recruit, and the one a NAT-T punch must reach.
    pub(crate) socket: std::sync::Arc<rmule_net::ed2k::ClientUdpSocket>,
    /// Where the running node's inbound half is installed for the demux front
    /// to find (`crate::client_udp::SharedKadInlet`). Filled on start, cleared
    /// when the node's pump ends, because the socket outlives the node.
    pub(crate) kad_inlet: crate::client_udp::SharedKadInlet,
    /// **Self Reach** (ADR-0060): the one owner of our own
    /// reachability, whose NAT-T family is the front on this socket — so a
    /// punch toward what the node publishes lands where a uTP Tunnel can
    /// rise, and the publish may say so for exactly as long as
    /// the front's own loop runs.
    pub(crate) reach: crate::reachability::SharedSelfReach,
}

impl ClientUdpBind {
    /// The one bound UDP port — what a Kad hello advertises and what the
    /// `CT_EMULE_UDPPORTS` tag's Kad half carries.
    #[must_use]
    pub fn udp_port(&self) -> u16 {
        self.socket.local_port()
    }
}

impl std::fmt::Debug for ClientUdpBind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientUdpBind")
            .field("port", &self.socket.local_port())
            .finish()
    }
}

/// The Kad node's moving facts as the pump keeps them (they ride the core's
/// [`KadCells`]): shared cells, cheap to clone, read at the instant a snapshot
/// asks.
#[derive(Clone, Debug, Default)]
pub struct KadFactsView {
    /// Live routing-table size (adds minus evictions).
    pub(crate) contact_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// The `(keyword, file)` rows the node's keyword index stores for others.
    pub(crate) keywords_stored: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Kad datagrams and wire bytes across the shared client-UDP bind.
    pub(crate) traffic: rmule_net::kad::KadTraffic,
}

/// Factory for the Kad channel (the `serve_runtime` adapter precedent): held
/// by the Core actor for its whole life, and started by each
/// `CoreCommand::EnableKad` — once per node, again after every stop. Tests inject a fake whose channel is socket-free; production
/// wiring injects [`RuntimeKadFactory`]. Kad disabled = the command never
/// arrives = nothing starts.
pub trait KadRuntimeFactory: Send + 'static {
    /// The channel a started node hands back — core's only handle on Kad.
    type Channel: KadSourceChannel;

    /// Start the node as `node` over the core's client-UDP `bind` and yield
    /// its channel, publishing into and counting through `cells`: the one set
    /// core built before any start and lends to every start. Called once per
    /// node and again on each restart; the actor ignores an `EnableKad` while a
    /// node runs rather than starting a second one, so a started node's cells
    /// are only ever refilled after it is retired (or while a predecessor that
    /// outlived its stop is still tearing down — each node clears only the
    /// cells it filled). An error here leaves the session running without Kad —
    /// and with the sockets unified, a client-UDP bind that failed at core
    /// start is one such error: there is no second socket for Kad to fall back
    /// to.
    fn start(
        &mut self,
        config: &KadEnableConfig,
        node: &KadNodeIdentity,
        bind: ClientUdpBind,
        cells: &KadCells,
    ) -> impl Future<Output = Result<Self::Channel, CoreError>> + Send;
}

pub(crate) enum KadPumpCommand {
    Search(SourceLookupTarget),
    Publish(SourceLookupTarget),
    /// Stop republishing a file no longer offered (ADR-0106).
    Withdraw(SourceLookupTarget),
    /// The ADR-0062 keyword requester: join — or start — the walk toward the
    /// query's lead-keyword ID over the nearest storers' keyword indexes
    /// (`0x33`). The node's `KeywordsFound` rows, projected to `SearchResult`s
    /// and screened by this query, arrive on this search's own `results`
    /// sink, closed when the walk ends (ADR-0034).
    SearchKeyword {
        query: KeywordQuery,
        results: crate::KadKeywordSink,
    },
    /// The ed2k→Kad handoff (ADR-0067): bootstrap from a peer-carried Kad
    /// endpoint. The pump converts the projected `Ipv4Endpoint` to the node's
    /// `KadNodeEndpoint` and issues `KadCommand::BootstrapFromPeer`, where the
    /// node applies the not-joined + shared-throttle gate.
    BootstrapFromPeer(Ipv4Endpoint),
    /// Start a firewall self-check now, outside its hourly clock (ADR-0086):
    /// a port-mapping grant landed on the exact ports, a gateway epoch reset
    /// re-added the mapping set, or the operator asked. The node applies its
    /// own guards (one at a time, at most one per five minutes).
    RecheckReachability,
    /// A v7+ helper dialed our eD2k port back and delivered
    /// `OP_KAD_FWTCPCHECK_ACK` there (ADR-0058): count one reachability leg for
    /// that IP. The pump converts it to `KadCommand::TcpFirewallAck`, where the
    /// node window-guards it against its own outstanding checks.
    TcpFirewallAck(std::net::Ipv4Addr),
    /// A peer asked us over peer TCP (`OP_FWCHECKUDPREQ`, `0xA7`) to prove its
    /// Kad UDP port reachable: the pump issues
    /// `KadCommand::UdpFirewallRequest`, and the node answers `0x62`.
    UdpFirewallRequest {
        /// The dialing peer's IP — where the `0x62` goes.
        requester: std::net::Ipv4Addr,
        /// The request body as it arrived.
        request: Vec<u8>,
        /// Whether core's peer roster already knows this IP:
        /// biases the answer the same way a routing-zone contact does.
        caller_known: bool,
    },
    /// Our link to an engaged UDP Firewall Helper ended after the request
    /// went out (ADR-0058): `KadCommand::UdpFirewallCheckFailed`.
    UdpFirewallCheckFailed(std::net::Ipv4Addr),
    /// Our dial to an engaged UDP Firewall Helper ended before the request
    /// could go out (ADR-0058): `KadCommand::UdpFirewallCheckCancelled`.
    UdpFirewallCheckCancelled(std::net::Ipv4Addr),
    /// ADR-0061 route 4: ask a firewalled source's buddy to
    /// relay a callback. The pump issues `KadCommand::RequestBuddyCallback`,
    /// whose `0x52` the node sends in the clear.
    BuddyCallback(BuddyCallbackAsk),
    /// The buddy was named by ID alone, so walk toward it (aMule's
    /// `FINDSOURCE`). The pump issues `KadCommand::CallbackWalk` and carries
    /// the walk's failure back to the ask's retire channel.
    CallbackWalk(CallbackWalkAsk),
}

/// What a `0x52 KADEMLIA_CALLBACK_REQ` names, as the core actor resolved it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BuddyCallbackAsk {
    /// The buddy's Kad UDP endpoint, from the source row.
    pub(crate) buddy_udp: Ipv4Endpoint,
    /// The buddy relationship ID the row named.
    pub(crate) buddy_id: rmule_kad::KadId,
    /// The file the target must know before it dials us back.
    pub(crate) file_hash: rmule_primitives::FileHash,
    /// Where the target must dial us — our advertised TCP port.
    pub(crate) tcp_port: u16,
}

/// Hand one buddy callback to the running node, reporting whether a node was
/// there to take it. `false` — Kad is off, or its inbox is full — means no
/// `0x52` will leave, which the caller reports rather than assumes.
pub(crate) fn request_kad_buddy_callback(sink: &SharedKadPump, ask: BuddyCallbackAsk) -> bool {
    sink.send(KadPumpCommand::BuddyCallback(ask)).is_ok()
}

/// Production [`KadSourceChannel`] over a live `rmule_net::kad` node. A pump
/// task owns the node handle; each source answer carries the lookup target
/// the node echoes, so it maps back to the file hash the walk was issued for.
/// Everything below the seam stays in Kad vocabulary; everything above sees
/// only projected Peer Sources.
pub struct RuntimeKadChannel {
    commands: mpsc::Sender<KadPumpCommand>,
    sources: Mutex<mpsc::Receiver<(FileHash, crate::kad_sources::KadAnswer)>>,
}

impl KadSourceChannel for RuntimeKadChannel {
    async fn search_sources(&self, target: SourceLookupTarget) {
        let _ = self.commands.send(KadPumpCommand::Search(target)).await;
    }

    async fn publish_source(&self, target: SourceLookupTarget) {
        let _ = self.commands.send(KadPumpCommand::Publish(target)).await;
    }

    async fn withdraw_source(&self, target: SourceLookupTarget) {
        let _ = self.commands.send(KadPumpCommand::Withdraw(target)).await;
    }

    async fn next_sources(&self) -> Option<(FileHash, crate::kad_sources::KadAnswer)> {
        self.sources.lock().await.recv().await
    }

    async fn search_keyword(&self, query: KeywordQuery, results: crate::KadKeywordSink) {
        // A stopped pump hands the command back: the leg ends as never taken
        // instead of waiting on a walk that will never run.
        if let Err(mpsc::error::SendError(KadPumpCommand::SearchKeyword { results, .. })) = self
            .commands
            .send(KadPumpCommand::SearchKeyword { query, results })
            .await
        {
            results.tell(crate::search::KadWalkFact::Ended(
                crate::search::KadKeywordEnd::NotTaken,
            ));
        }
    }
}

/// Project one **Kad Keyword Result Row** into the search stream's vocabulary
/// (ADR-0062 requester merge): the wire-form file ID un-swaps back to the eD2k
/// file hash, FILESIZE widens to the stream's `u64`, and the storer's
/// popularity-winning FILENAME becomes the result name. A row missing a name or
/// a size cannot key into the `(hash, size)` result set, and one above eD2k's
/// size limit names no file eD2k can fetch, so each is dropped by its reason —
/// the storer rejects size-less/name-less publishes, so a well-formed answer
/// never hits those two. aMule drops the same rows, logging them for debugging
/// only (`kademlia/kademlia/Search.cpp:1051-1055`, `SearchList.cpp:561-569` at
/// stock 2.3.3). Peer sources stay empty: a keyword row carries a source *count*,
/// not endpoints (those ride the source-search path) — which is exactly why the
/// count itself has to be carried across, or a Kad-only row reaches the app
/// claiming zero sources.
///
/// The row's `TAG_SOURCES` becomes the result's **availability**, not its
/// complete-source count, even though a publisher fills that tag from its
/// complete-sources figure (`Search.cpp:1188`): aMule's requester reads it into
/// `m_sourceCount` (`Search.cpp:1033` → `SearchList.cpp`'s `FT_SOURCES` tag →
/// `SearchFile.cpp:79`), and the app-facing meaning is the consumer's. The
/// `> 65500` clamp is aMule's rogue-publisher guard from the same site.
pub(crate) fn project_keyword_result(
    row: &rmule_kad::KadKeywordResult,
) -> Result<SearchResult, SearchResultSkipReason> {
    let name = row
        .filename
        .clone()
        .ok_or(SearchResultSkipReason::MissingFileName)?;
    let size = row.size.ok_or(SearchResultSkipReason::MissingFileSize)?;
    let result = SearchResult::new(
        kad_file_id_to_file_hash(row.file_id),
        size,
        vec![Ed2kText::from_utf8(name)],
        Vec::new(),
    )
    .map_err(|error| match error {
        rmule_primitives::PrimitiveError::FileSizeAboveLimit { .. } => {
            SearchResultSkipReason::FileSizeAboveLimit
        }
        rmule_primitives::PrimitiveError::FileSizeZero => SearchResultSkipReason::FileSizeZero,
        _ => SearchResultSkipReason::MissingFileName,
    })?
    .with_origin(SearchResultOrigin::Kad);
    let result = match row.complete_sources {
        Some(availability) if availability <= KAD_MAX_PLAUSIBLE_AVAILABILITY => {
            result.with_reported_availability(availability)
        }
        Some(_) => result.with_reported_availability(0),
        None => result,
    };
    Ok(match &row.file_type {
        Some(file_type) => result.with_file_type(Ed2kText::from_utf8(file_type.clone())),
        None => result,
    })
}

/// The node's keyword rows projected: the rows that stand, and why each one
/// that does not was dropped, in the order the storers sent them.
pub(crate) fn project_keyword_rows(
    rows: &[rmule_kad::KadKeywordResult],
) -> (Vec<SearchResult>, Vec<SearchResultSkipReason>) {
    let mut kept = Vec::new();
    let mut skipped = Vec::new();
    for row in rows {
        match project_keyword_result(row) {
            Ok(result) => kept.push(result),
            Err(reason) => skipped.push(reason),
        }
    }
    (kept, skipped)
}

/// aMule's ceiling on a Kad-reported availability before it calls the
/// publisher rogue and zeroes the figure (`Search.cpp:1033-1036`).
const KAD_MAX_PLAUSIBLE_AVAILABILITY: u32 = 65_500;

/// Invert the Kad wire-form file ID back to the eD2k file hash: the per-32-bit
/// word byte-swap is its own inverse, so the same transform recovers the hash
/// the publisher word-swapped in.
fn kad_file_id_to_file_hash(file_id: rmule_kad::KadId) -> FileHash {
    FileHash::from_bytes(rmule_primitives::kad_wire_id(*file_id.as_bytes()))
}

#[cfg(test)]
mod tests;
