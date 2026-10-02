//! The typed build of a [`Core`]: the runtime adapters a session runs against
//! — source lookup, peer transfer, serve runtime and Kad factory — are chosen
//! one at a time, each setter swapping one type parameter, so a half-built
//! core cannot be spawned. The durable seams (download repository, shared-file
//! registry, credit ledger, server list) are not slots: they are always the
//! store views [`Core::builder`] opens on the one handle it is given, since
//! nothing ever ran a core over any other implementation.

use std::sync::Arc;

use rmule_primitives::{SecureIdentKey, UserHash};
use tokio::sync::Mutex;

use crate::adapters::{
    AdapterCells, KadRuntimeFactory, PeerTransferService, RuntimeKadFactory,
    RuntimePeerTransferService, RuntimeServeRuntimeService, RuntimeSourceLookupService,
    ServeRuntimeService, SharedCallbackTable, SharedDialedServeSink, SharedKadBootstrap,
    SharedKadPump, SourceLookupService,
};
use crate::app_config::AppConfigStore;
use crate::ban_store::SharedBanStore;
use crate::buddy_link::SharedBuddySlot;
use crate::credit::SharedCreditStore;
use crate::ip_filter::{IpFilter, SharedIpFilter};
use crate::server_list::{ServerListFetcher, SharedServerListStore};
use crate::server_session::SharedServerSession;
use crate::store::DurableStore;
use crate::store::app_config::DurableAppConfig;
use crate::store::credit::DurableCreditStore;
use crate::store::download::DurableDownloadRepository;
use crate::store::registry::DurableSharedFileRegistry;

use super::actor::CoreWiring;
use super::{Core, CoreConfig};

/// Every knob [`Core`] needs, each defaulting to the shared-session production
/// adapter set — the single home for the default wiring that replaces the old
/// constructor telescope. Start it with [`Core::builder`], override any slot
/// with the matching setter, and [`build`](Self::build) spawns the actor.
///
/// The builder is the one wiring point (ADR-0048 "Identity ownership"):
/// every shared cell it owns lives in one `AdapterCells`, and
/// its own default adapters and any adapter a caller injects adopt that one
/// set through the same `adopt_cells` trait method — so a core with custom
/// fakes stays wired the same everywhere, and an injected runtime adapter
/// never runs on a private copy of a cell. The durable seams have no setters:
/// the repository, registry and credit ledger are always
/// [`DurableDownloadRepository`], [`DurableSharedFileRegistry`] and
/// [`DurableCreditStore`] over the store [`Core::builder`] was given; a test
/// that needs to read or seed one opens its own view on that same store.
pub struct CoreBuilder<S, P, L, K> {
    source_lookup: S,
    peer_transfer: P,
    serve_runtime: L,
    kad: K,
    node: NodeParts,
}

/// Everything a [`CoreBuilder`] holds besides its four adapter slots — moved
/// whole when a setter swaps one slot's type.
struct NodeParts {
    config: CoreConfig,
    repository: DurableDownloadRepository,
    registry: DurableSharedFileRegistry,
    credit: DurableCreditStore,
    /// The one set of shared cells every adapter adopts.
    cells: AdapterCells,
    /// The node's **User Hash**, fixed here at build time (ADR-0048 "Identity ownership"):
    /// [`Core::builder`] reads it from the store it
    /// is given — the same generate-once row a front-end's
    /// [`AppConfigStore::ensure_identity`] reads — and a tool that names its
    /// hash on the command line replaces it with [`CoreBuilder::user_hash`].
    /// No command carries one.
    user_hash: UserHash,
    /// The **Interface Source** (ADR-0084) core polls for the addresses this
    /// host holds. `Core::builder` installs the live enumeration.
    interface_source: Option<Arc<dyn rmule_net::interfaces::InterfaceSource>>,
    /// The **Gateway Source** (ADR-0086) the mapping runtime asks for the
    /// default route. `Core::builder` installs the live route lookup; a test or
    /// a harness pins the gateway instead.
    gateway_source: Arc<dyn rmule_net::portmap::GatewaySource>,
    /// The **Mapping Backends** (ADR-0086) the racer drives — one per protocol.
    /// Empty leaves the whole subsystem unstarted.
    mapping_backends: Vec<Arc<dyn rmule_net::portmap::MappingBackend>>,
    /// Where the **learned method** is remembered between runs (ADR-0086).
    port_mapping_preferences: Arc<dyn crate::adapters::PortMappingPreferences>,
    ip_filter_dir: Option<std::path::PathBuf>,
    clients_met_dir: Option<std::path::PathBuf>,
    /// What the Shared Directory List's guards refuse (ADR-0101).
    share_guards: crate::ShareGuards,
    /// The credentials core's own restarts of downloads present (ADR-0094),
    /// or `None`: then attach starts none.
    restore_credentials: Option<super::ClientCredentials>,
    /// The managed server list the actor owns (ADR-0080), type-erased.
    server_list: SharedServerListStore,
    /// The one URL-acquisition capability core is given (ADR-0080), or `None`
    /// — the default, since core links no HTTP client.
    server_list_fetcher: Option<Arc<dyn ServerListFetcher>>,
}

impl<S, P, L, K> CoreBuilder<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Inject a source-lookup adapter (tests pass a fake). It adopts the
    /// builder's cells, so it logs in on the node's one server session.
    #[must_use]
    pub fn source_lookup<S2: SourceLookupService>(
        self,
        mut source_lookup: S2,
    ) -> CoreBuilder<S2, P, L, K> {
        source_lookup.adopt_cells(&self.node.cells);
        CoreBuilder {
            source_lookup,
            peer_transfer: self.peer_transfer,
            serve_runtime: self.serve_runtime,
            kad: self.kad,
            node: self.node,
        }
    }

    /// Inject a peer-transfer adapter (tests pass a fake). It adopts every
    /// cell the builder owns, so its hellos state what
    /// every other road's do and its dials meet the node's ban store, IP
    /// filter, Address Learning and Kad handoff.
    #[must_use]
    pub fn peer_transfer<P2: PeerTransferService>(
        self,
        mut peer_transfer: P2,
    ) -> CoreBuilder<S, P2, L, K> {
        peer_transfer.adopt_cells(&self.node.cells);
        CoreBuilder {
            source_lookup: self.source_lookup,
            peer_transfer,
            serve_runtime: self.serve_runtime,
            kad: self.kad,
            node: self.node,
        }
    }

    /// Inject a serve-runtime adapter (tests pass a fake). It adopts every
    /// cell the builder owns and the installed Kad
    /// factory's **Kad Presence**, so its accepts meet the node's
    /// session, gates and Peer Roster.
    #[must_use]
    pub fn serve_runtime<L2: ServeRuntimeService>(
        self,
        mut serve_runtime: L2,
    ) -> CoreBuilder<S, P, L2, K> {
        serve_runtime.adopt_cells(&self.node.cells);
        serve_runtime.set_kad_presence(self.kad.kad_presence());
        CoreBuilder {
            source_lookup: self.source_lookup,
            peer_transfer: self.peer_transfer,
            serve_runtime,
            kad: self.kad,
            node: self.node,
        }
    }

    /// Inject a Kad factory (ADR-0043); the default is [`RuntimeKadFactory`].
    /// Core correctness tests pass a fake so Kad-fed sources reach the scheduler
    /// with no socket and no server. It adopts the builder's cells.
    #[must_use]
    pub fn kad<K2: KadRuntimeFactory>(mut self, mut kad: K2) -> CoreBuilder<S, P, L, K2> {
        kad.adopt_cells(&self.node.cells);
        // A served link's `0x99`/`0x95` gate must track *this* factory's own
        // **Kad Presence**: the default wiring bound the serve
        // runtime to the *default* factory's view, and a factory swap here
        // would otherwise leave it reading a cell no pump ever leases.
        self.serve_runtime.set_kad_presence(kad.kad_presence());
        CoreBuilder {
            source_lookup: self.source_lookup,
            peer_transfer: self.peer_transfer,
            serve_runtime: self.serve_runtime,
            kad,
            node: self.node,
        }
    }

    /// Fix the node's **User Hash** (ADR-0048 "Identity ownership")
    /// in place of the one [`Core::builder`] read from the store — for a
    /// tool or a test that names its hash. Build time is the only time a hash
    /// is chosen: no command carries one.
    #[must_use]
    pub fn user_hash(mut self, user_hash: UserHash) -> Self {
        self.node.user_hash = user_hash;
        self
    }

    /// Prove the node's hellos with `key` (ADR-0041) in place of the one
    /// [`Core::builder`] loaded from the store — for a tool whose store is
    /// throwaway but whose SUI key must stay the one a counterparty's
    /// `clients.met` already binds to its hash. Every adapter
    /// installed so far re-adopts the cells, and any installed later adopts
    /// them with the key already in place.
    #[must_use]
    pub fn secure_ident_key(mut self, key: SecureIdentKey) -> Self {
        self.node.cells.hello_adverts.secure_ident = Some(Arc::new(key));
        self.source_lookup.adopt_cells(&self.node.cells);
        self.peer_transfer.adopt_cells(&self.node.cells);
        self.serve_runtime.adopt_cells(&self.node.cells);
        self.kad.adopt_cells(&self.node.cells);
        self
    }

    /// Persist the credit ring as `clients.met` in `dir`: the
    /// actor seeds the ring from the file on spawn and flushes a snapshot back
    /// on shutdown (see [`Core::shutdown`]). Off by default — tests and
    /// ephemeral tools keep an unpersisted ring.
    #[must_use]
    pub fn persist_credit_in(mut self, dir: std::path::PathBuf) -> Self {
        self.node.clients_met_dir = Some(dir);
        self
    }

    /// Refuse to share the operator's home directory and rmule's own data
    /// directory, and every directory inside the data directory or holding
    /// it (ADR-0101, "Shared Directories"). Core never reads the environment
    /// for them; without this only the filesystem's own guards apply.
    #[must_use]
    pub fn share_guards(mut self, guards: crate::ShareGuards) -> Self {
        self.node.share_guards = guards;
        self
    }

    /// Load IP filter dat files from `dir`: `ipfilter.dat` then
    /// `ipfilter_static.dat` on top, aMule's two-file order — the static file
    /// wins overlaps. [`build`](Self::build) performs the load synchronously
    /// before the actor spawns, so no accepted or dialed connection can ever
    /// precede the loaded table (the guarantee aMule's not-ready-blocks-all
    /// branch exists to approximate). Off by default: with no directory the
    /// filter table stays empty and nothing is filtered — exactly an
    /// out-of-box aMule, whose filtering is on but whose table is empty.
    #[must_use]
    pub fn ip_filter_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.node.ip_filter_dir = Some(dir);
        self
    }

    /// Give core the ability to fetch a server.met (ADR-0080) — any
    /// `rmule_bootstrap::Fetcher`, in production its `ReqwestFetcher`. Off by
    /// default: core links no HTTP client, so without this
    /// [`ServerListCommand::UpdateServerList`](crate::ServerListCommand::UpdateServerList) is rejected with
    /// [`CoreCommandRejectReason::ServerListFetchUnavailable`](crate::CoreCommandRejectReason::ServerListFetchUnavailable) rather than
    /// silently doing nothing.
    #[must_use]
    pub fn server_list_fetcher(mut self, fetcher: impl ServerListFetcher + 'static) -> Self {
        self.node.server_list_fetcher = Some(Arc::new(fetcher));
        self
    }

    /// Replace the **Interface Source** (ADR-0084) core polls for the
    /// addresses this host holds.
    ///
    /// [`Core::builder`] installs the live enumeration, which answers whatever
    /// the machine happens to have — so the two rules that read the set, the
    /// interface tier and the local-interface corroboration filter, could not
    /// otherwise be driven. A test or a harness pins the set here instead.
    #[must_use]
    pub fn interface_source(
        mut self,
        source: impl rmule_net::interfaces::InterfaceSource + 'static,
    ) -> Self {
        self.node.interface_source = Some(Arc::new(source));
        self
    }

    /// Replace the **Gateway Source** (ADR-0086) the mapping runtime asks for
    /// the default route.
    ///
    /// The live lookup answers whatever the machine running the test happens to
    /// be behind — and a test that reached a real router would forward real
    /// ports on it as a side effect. A test or a harness names the gateway here
    /// instead.
    #[must_use]
    pub fn gateway_source(
        mut self,
        source: impl rmule_net::portmap::GatewaySource + 'static,
    ) -> Self {
        self.node.gateway_source = Arc::new(source);
        self
    }

    /// Install the **Mapping Backends** (ADR-0086) the racer drives, replacing
    /// whatever was there.
    ///
    /// Given rather than constructed: the three live backends speak three
    /// protocols over two third-party crates, and a core that built them itself
    /// could not be tested against a scripted gateway at all. An empty set
    /// leaves the subsystem unstarted.
    #[must_use]
    pub fn mapping_backends(
        mut self,
        backends: Vec<Arc<dyn rmule_net::portmap::MappingBackend>>,
    ) -> Self {
        self.node.mapping_backends = backends;
        self
    }

    /// The builder's one **Peer Roster** (ADR-0059) — the instance every
    /// adapter adopted and the actor will hold — so a test can read
    /// [`SharedPeerRoster::knows`](crate::peer_roster::SharedPeerRoster::knows)
    /// back after a real session. A handle onto the one roster, never a
    /// replacement for it.
    #[cfg(test)]
    pub(crate) fn shared_peer_roster(&self) -> crate::peer_roster::SharedPeerRoster {
        self.node.cells.peer_roster.clone()
    }

    /// The builder's one server session cell — the slot the actor reads a
    /// session from — so a test can put a session there itself.
    #[cfg(test)]
    pub(crate) fn shared_server_session(&self) -> crate::server_session::SharedServerSession {
        self.node.cells.session.clone()
    }

    /// The node's credentials at attach (ADR-0093) — the ones the front end
    /// gives every `ResumeDownload` and `ConnectToServer`. With them, attach
    /// binds the eD2k listener on their TCP port (the Serve activity, so the
    /// port mapping starts too) and starts again every download the last
    /// process left running, each riding the operator's session or waiting
    /// for one. Without them, attach binds nothing and reports those downloads
    /// without starting any: core holds no identity of its own (ADR-0069), so
    /// a tool that opens a store only to read it listens on nothing.
    #[must_use]
    pub fn restore_credentials(mut self, credentials: super::ClientCredentials) -> Self {
        self.node.restore_credentials = Some(credentials);
        self
    }

    /// The serve runtime installed so far, for a test that checks what it
    /// adopted.
    #[cfg(test)]
    pub(crate) fn installed_serve_runtime(&self) -> &L {
        &self.serve_runtime
    }

    /// Spawn the core actor with the assembled wiring and return its handle.
    /// The stores are shared here — the sole place — as plain `Arc`s the
    /// actor, the serve activity and every download runner call through
    /// (every seam method is `&self`, ADR-0083); the two services keep their
    /// `Arc<Mutex<_>>`; the serve runtime goes into the `Option` that
    /// `StartServing` takes it out of exactly once.
    #[must_use]
    pub fn build(self) -> Core {
        let node = self.node;
        // Every front end builds its Core here, so every Run Log states the
        // one obfuscation policy (ADR-0046) the session ran under.
        tracing::info!(
            policy = node.config.peer_crypt.map_or("off", |policy| match policy {
                rmule_net::peer::ObfuscationPolicy::Supported => "supported",
                rmule_net::peer::ObfuscationPolicy::Requested => "requested",
                rmule_net::peer::ObfuscationPolicy::Required => "required",
            }),
            "obfuscation policy"
        );
        // The IP filter load happens here, synchronously, before
        // the actor spawns: rmule's replacement for aMule's background load +
        // filter-not-ready-blocks-everything branch. The adapters already
        // hold clones of the handle, so the swap is visible everywhere.
        if let Some(dir) = node.ip_filter_dir.as_deref() {
            let loaded = IpFilter::load_dir(
                dir,
                node.config.ip_filter_level,
                node.config.ip_filter_clients,
                node.config.ip_filter_servers,
            );
            *node.cells.ip_filter.write().expect("ip filter lock") = loaded;
        }
        // The node's hash, fixed before anything can read it:
        // every reader — the peer-UDP crypt layer, NAT-T, the Kad node, each
        // login and hello — reads this one cell or the actor's copy of it.
        node.cells.own_identity().set_user_hash(node.user_hash);
        let cells = node.cells;
        let credit: SharedCreditStore = Arc::new(node.credit);
        Core::spawn_with_dialed_serve(CoreWiring {
            config: node.config,
            store: Arc::new(node.repository),
            registry: Arc::new(node.registry),
            credit,
            user_hash: node.user_hash,
            source_lookup: Arc::new(Mutex::new(self.source_lookup)),
            peer_transfer: Arc::new(Mutex::new(self.peer_transfer)),
            serve_runtime: Some(self.serve_runtime),
            kad_factory: self.kad,
            udp_ports_advert: cells.hello_adverts.udp_ports.clone(),
            ipv6_advert: cells.hello_adverts.ipv6.clone(),
            shared_server_session: cells.session,
            dialed_serve_sink: cells.dialed_serve_sink,
            callbacks: cells.callbacks,
            buddy_slot: cells.buddy_slot,
            hello_adverts: cells.hello_adverts,
            firewalled_front: cells.firewalled_front,
            file_known: cells.file_known,
            tunnel_admit: cells.tunnel_admit,
            tunnel_claims: cells.tunnel_claims,
            hello_refusals: cells.hello_refusals,
            ip_filter: cells.ip_filter,
            interface_source: node.interface_source,
            gateway_source: node.gateway_source,
            mapping_backends: node.mapping_backends,
            kad_pump: cells.kad_pump,
            peer_roster: cells.peer_roster,
            port_mapping_preferences: node.port_mapping_preferences,
            clients_met_dir: node.clients_met_dir,
            share_guards: node.share_guards,
            restore_credentials: node.restore_credentials,
            server_list: node.server_list,
            server_list_fetcher: node.server_list_fetcher,
        })
    }
}

impl Core {
    /// Open a [`CoreBuilder`] pre-wired with the shared-session production
    /// adapter set over `store` — the single private home for the default
    /// wiring the old `new_production` owned.
    ///
    /// `store` is the one open Durable Store this core runs on: all four store
    /// seams (downloads, shared files, credit, server list) are opened on it
    /// here, so they share one handle exactly as a front-end's do. A front-end
    /// passes [`open_durable_store`](crate::open_durable_store); a test or an
    /// ephemeral tool passes
    /// [`open_durable_store_in_memory`](crate::open_durable_store_in_memory),
    /// which is the same store on the engine's in-memory backend rather than a
    /// twin (ADR-0083). The three shared handles are created once here,
    /// woven into the default adapters, and also handed to the actor by
    /// [`CoreBuilder::build`], so the default path reproduces production exactly:
    /// source-lookup and the serve announce reuse one server session (ADR-0032),
    /// the serve accept-router and every download runner share one Low-ID
    /// callback table (ADR-0039), and each dialed download connection's serve
    /// half reaches the one upload queue through the shared dialed-serve sink
    /// (ADR-0031). Override any slot with the setters; anything left keeps
    /// this default and its shared handles.
    #[must_use]
    pub fn builder(
        config: CoreConfig,
        store: Arc<DurableStore>,
    ) -> CoreBuilder<
        RuntimeSourceLookupService,
        RuntimePeerTransferService,
        RuntimeServeRuntimeService,
        RuntimeKadFactory,
    > {
        let session = SharedServerSession::default();
        let dialed_serve_sink = SharedDialedServeSink::default();
        let callbacks = SharedCallbackTable::default();
        // One core-owned BanStore (ADR-0064), shared by the Kad event fold
        // and both peer-TCP enforcement surfaces — mirrors how `session` /
        // `dialed_serve_sink` / `callbacks` are each created once here and
        // cloned into every adapter that needs them.
        let ban_store = SharedBanStore::default();
        // One core-owned ed2k→Kad handoff sink (ADR-0067), shared by the Kad
        // factory (which installs its sender when the node starts) and both peer
        // adapters (which broker a connected peer's Kad hint into it) — the same
        // create-once-clone-into-every-adapter pattern as `ban_store` above.
        let kad_bootstrap = SharedKadBootstrap::default();
        // One core-owned `CT_EMULE_UDPPORTS` advert (ADR-0057), read by every
        // hello through the Hello Adverts below and set by the actor while the
        // reask uploader serves. Cloned out of the session cell rather than created here, for
        // the reason the Advertised IPv6 below is: the login's `0xF9` UDP-ports
        // advert is built during *establishment*, which runs off the actor and
        // holds only that cell, and two cells would let the hello and the
        // login disagree about whether a Kad node runs.
        let udp_ports_advert = session.udp_ports_advert().clone();
        // One Advertised IPv6 (ADR-0087), read by every hello through the
        // Hello Adverts below, the Kad runtime and the download runner — a
        // view over Address Learning, its one owner, settled at every read.
        // Cloned out of the session cell rather than created here: the login's
        // `CT_MOD_IP_V6` tag is built during *establishment*, which runs off
        // the actor and holds only that cell, and two cells would let the hello
        // and the login name different addresses.
        let ipv6_advert = session.ipv6_advert().clone();
        // One core-owned IP filter (aMule `CIPFilter` parity),
        // shared by the accept, dial, server-dial, source-ingest, and
        // server-list gates — the same create-once-clone-into-every-adapter
        // pattern as `ban_store`. Created empty with the config's gates;
        // `CoreBuilder::build` loads the dat files into it (before the actor
        // spawns, so no connection can ever precede the loaded table) when
        // `ip_filter_dir` names a directory.
        let ip_filter: SharedIpFilter = Arc::new(std::sync::RwLock::new(IpFilter::empty(
            config.ip_filter_clients,
            config.ip_filter_servers,
        )));
        // One core-owned enacted buddy slot (socket unification, ADR-0061),
        // shared by the Kad factory (0x51 recruit + 0x52 relay), the accept
        // path (holds the buddy's persistent inbound link, routes ping/close),
        // and the client-UDP front (0x94 relay) — the same pattern again.
        let buddy_slot = SharedBuddySlot::default();
        // And its firewalled mirror: the slot the Kad factory
        // fills from a verified `0x5A`, plus the late-bound command half of
        // the front that dials it. Woven here for the same reason the buddy
        // slot is — two adapters and one actor-spawned task share them. Every
        // hello reads the slot too, through the Hello Adverts below, for the
        // serving buddy.
        let firewalled_slot = crate::firewalled::link::SharedFirewalledSlot::default();
        // One view of the store for the managed server list, the learned
        // port-mapping method and the node's SUI keypair: they are the same
        // durable handle (ADR-0083), so a second one would only be a second
        // name for it.
        let app_config = Arc::new(DurableAppConfig::new(Arc::clone(&store)));
        // The node's Secure User Identification keypair (ADR-0041), loaded
        // once, here, and never replaced (ADR-0048 "Identity ownership"):
        // aMule's `CClientCreditsList` loads `cryptkey.dat` once
        // at construction and a failed load leaves crypto unavailable rather
        // than failing start (`ClientCreditsList.cpp:49-54`, `:282-323`).
        let secure_ident = match app_config.ensure_secure_ident_key() {
            Ok(key) => Some(Arc::new(key)),
            Err(error) => {
                tracing::warn!(%error, "no SUI keypair; every hello runs without Secure User Identification");
                None
            }
        };
        // The one Hello Adverts read, woven from the cells above:
        // every road that sends a hello — the accept pump and a risen Tunnel,
        // a download dial, the Kad firewall-check dial-back and UDP-check
        // helper dial, the buddy dial, a callback dial-back — starts its
        // options from it, so none can state less than another.
        let hello_adverts = crate::adapters::HelloAdverts {
            udp_ports: udp_ports_advert.clone(),
            ipv6: ipv6_advert.clone(),
            firewalled_slot,
            crypt_policy: config.peer_crypt,
            secure_ident,
        };
        let firewalled_front = crate::firewalled::front::SharedFirewalledFront::default();
        // The file-known predicate, woven here for the same
        // reason: the serve/download command arms and the firewalled front
        // are built at different sites below and share no other lifetime.
        let file_known = crate::known_files::SharedFileKnown::default();
        // One core-owned cell for the seam a punched path's Tunnel enters the
        // serve pipeline by (ADR-0091): the serve adapter fills it at every
        // `start`, the NAT-T front reads it when a tunnel rises — so a
        // punched path meets the IP filter, the ban gate and the inbound
        // triage exactly as a TCP accept does.
        let tunnel_admit = crate::adapters::SharedTunnelAdmit::default();
        // The second road a pending Low-ID callback may be answered on
        // (ADR-0091): a download whose callback went silent registers its
        // target here, and the serve adapter's triage hands it the Dialer
        // Tunnel the punch raised. One table, cloned into the adapter and
        // into every runner — the pattern above, again.
        let tunnel_claims = crate::adapters::SharedTunnelClaims::default();
        // One core-owned sink for the out-of-band signals a running Kad node
        // takes (ADR-0058/0086), shared by the Kad factory (which installs its
        // pump sender on start), the port-mapping runtime (a fresh Exact grant,
        // an epoch re-add), the accept path (an inbound `OP_KAD_FWTCPCHECK_ACK`)
        // and the actor (the operator's recheck) — the same
        // create-once-clone-into-every-adapter pattern as `kad_bootstrap`.
        let kad_pump = SharedKadPump::default();
        // One core-owned Peer Roster (ADR-0059), shared by the
        // serve adapter (which marks/forgets it on an upload slot's grant/
        // queue/release and hands it to inbound triage) and the Kad factory
        // (whose requester gate reads it before dialling a helper) — the
        // same create-once-clone-into-every-adapter pattern as `ban_store`.
        let peer_roster = crate::peer_roster::SharedPeerRoster::default();
        // The node's User Hash (ADR-0048 "Identity ownership"):
        // the store's generate-once identity row, the one a front-end reads
        // for its nickname and ports — so the hash and the SUI key loaded
        // above come from one place. A failed read mints a fresh hash for
        // this run rather than failing start, the SUI key's posture.
        let user_hash = match app_config.ensure_identity() {
            Ok(identity) => identity.user_hash(),
            Err(error) => {
                tracing::warn!(%error, "no stored identity; this run uses a fresh user hash");
                crate::app_config::generate_user_hash()
            }
        };
        let cells = AdapterCells {
            session,
            callbacks,
            dialed_serve_sink,
            slot_wait_timeout: config.slot_wait_timeout,
            ban_store,
            kad_bootstrap,
            kad_pump,
            peer_roster,
            hello_adverts,
            buddy_slot,
            ip_filter,
            firewalled_front,
            file_known,
            tunnel_admit,
            tunnel_claims,
            address_families: config.address_families,
            // One cell every peer connection's first reader reports a refused
            // hello to (ADR-0050); the actor's prologue installs its bus.
            hello_refusals: crate::hello_refusals::SharedHelloRefusals::default(),
        };
        // One wiring path: the default adapters adopt the cells
        // exactly as an injected one does.
        let mut source_lookup = RuntimeSourceLookupService::default();
        source_lookup.adopt_cells(&cells);
        let mut peer_transfer = RuntimePeerTransferService::new(config.slot_wait_timeout);
        peer_transfer.adopt_cells(&cells);
        let kad = RuntimeKadFactory::new(&cells);
        let mut serve_runtime = RuntimeServeRuntimeService::new();
        serve_runtime.adopt_cells(&cells);
        // A served link's `0x99` (ADR-0061 route 4) reads the
        // Kad factory's own **Kad Presence** — the pump it spawns is that
        // cell's only writer.
        serve_runtime.set_kad_presence(kad.kad_presence());
        CoreBuilder {
            source_lookup,
            peer_transfer,
            serve_runtime,
            kad,
            node: NodeParts {
                repository: DurableDownloadRepository::new(store.clone()),
                registry: DurableSharedFileRegistry::new(store.clone()),
                credit: DurableCreditStore::new(store.clone()),
                config,
                cells,
                user_hash,
                // The one place rmule asks the OS which addresses it holds
                // (ADR-0084). Installed for every production core.
                interface_source: Some(Arc::new(rmule_net::interfaces::SystemInterfaces)),
                // The one place rmule asks the OS where its default route
                // points (ADR-0086); a test or a harness replaces it.
                gateway_source: Arc::new(rmule_net::portmap::SystemGateways),
                // Empty until the live PCP / NAT-PMP / UPnP backends are
                // installed by the front end: an empty set leaves the
                // subsystem unstarted.
                mapping_backends: Vec::new(),
                // The learned method rides the one open store the managed
                // server list is already a view of (ADR-0086).
                port_mapping_preferences: Arc::new(crate::adapters::DurablePortMappingPreferences(
                    Arc::clone(&app_config),
                )),
                ip_filter_dir: None,
                clients_met_dir: None,
                share_guards: crate::ShareGuards::default(),
                restore_credentials: None,
                server_list: app_config,
                server_list_fetcher: None,
            },
        }
    }
}

#[cfg(test)]
mod tests;
