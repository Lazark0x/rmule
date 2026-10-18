//! The engineering knobs a session runs against ([`CoreConfig`]: timeouts,
//! concurrency, cadences) and the verification stance a download's hash
//! authority grants it. The operator's preferences are not here: they are
//! **Core Settings** (ADR-0069). Every default here is aMule's, so a stock
//! session behaves like a stock aMule — but for the streaming window, which
//! aMule does not have (ADR-0112).

use std::time::Duration;

use rmule_net::family::FamilySelection;

use crate::address_learning::ExternalAddressOverride;
use crate::port_mapping::PortMappingConfig;
use serde::{Deserialize, Serialize};

/// Where a download's part hashes came from, which is what verifying a part
/// against them is worth. Ordered strongest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationAuthority {
    /// The part hash set rode in on the ed2k link itself: it is as trusted as
    /// the link, so a matching part is final.
    LinkPartHashSet,
    /// A peer supplied the set (`OP_HASHSETANSWER`). Parts verify against it
    /// provisionally; the whole-file hash at finalize is what confirms it.
    PeerHashSet,
    /// No part hashes at all — only the file hash. Parts cannot be checked
    /// individually, so verification is deferred to the finished file and a bad
    /// source is only discovered at the end.
    FileHashOnly,
}

/// Generous default budget for waiting on a busy peer's upload slot.
/// eMule queue waits are open-ended in reality, so this is a patience cap
/// to keep a download from hanging forever on one stuck peer, not a tight
/// deadline.
pub const DEFAULT_SLOT_WAIT_TIMEOUT: Duration = Duration::from_secs(180);

/// The engineering knobs one session runs against, fixed for the life of the
/// [`Core`] it is built with — timeouts, concurrency, cadences. What the
/// operator chooses is [`CoreSettings`](crate::CoreSettings), not this. Three
/// defaults differ from stock aMule by design, and each says why on its own
/// field: [`CoreConfig::upload_slot_budget`], [`CoreConfig::max_upload_queue_len`]
/// and [`CoreConfig::streaming_window_parts`]. The rest are engineering values;
/// a field cites the aMule source where it follows one.
///
/// [`Core`]: crate::Core
#[derive(Clone, Debug)]
pub struct CoreConfig {
    /// The node's **Connection Budget** (ADR-0116): how many connections the
    /// downloads open per 5-second window and hold at once. It paces asking
    /// only; every granted slot transfers, and no download has a worker cap.
    /// Both defaults are aMule's.
    pub peer_connections: PeerConnections,
    /// How many parts from the lowest unverified one a **Streaming Priority**
    /// download fetches in order before ranking the rest by rarity — the
    /// **Streaming Window** (ADR-0112 §5). `0` is no window. aMule has none;
    /// the default `8` is the width the bench against stock seeds measured to
    /// grow the contiguous prefix soonest.
    pub streaming_window_parts: u32,
    /// How long a peer worker waits for the answer to its slot ask — a rank
    /// or a grant — before it is retired; a rank without a grant hangs it up
    /// at once (ADR-0116).
    pub slot_wait_timeout: Duration,
    /// Concurrent upload slots the serve side grants across all connections
    /// (ADR-0031: the cross-connection slot budget). FIFO admission fills
    /// these before queuing.
    ///
    /// Not aMule's: aMule sizes its slots from the configured upload rate (one
    /// per 2 kB/s, at least 2). rmule has no upload-rate setting to size from,
    /// so the default is a fixed, conservative `4`.
    pub upload_slot_budget: usize,
    /// Maximum waiting requesters before the serve side refuses new ones —
    /// in silence, as both references do.
    ///
    /// Not aMule's: aMule queues up to 5000. The default `64` keeps the wait
    /// list, its re-ranking and the connections it holds small, which a node
    /// serving a handful of slots has no use to exceed.
    pub max_upload_queue_len: usize,
    /// How often the serve activity re-ranks its idle waiters so a queued
    /// peer's reported `OP_QUEUERANKING` tracks elapsed wait and any credit it
    /// gained while waiting.
    pub queue_rerank_interval: Duration,
    /// The **Search Quiet Timeout**: how long a search stays open after the
    /// last accepted result batch — counted only once every leg (server, global
    /// sweep, Kad walk) has settled — before core reports
    /// completion.
    pub search_quiet_timeout: Duration,
    /// How long a search awaits the connected server's first answer before
    /// its TCP leg settles unanswered (amule-kno `SERVER_ANSWER_TIMEOUT_MS`,
    /// 12 s).
    pub search_server_answer_timeout: Duration,
    /// The Kad keyword leg's ceiling should its walk's end never be reported
    /// (aMule `SEARCHKEYWORD_LIFETIME`, 45 s).
    pub search_kad_lifetime: Duration,
    /// The global UDP search sweep's pacing (ADR-0051): one server per tick
    /// (aMule's 750 ms `m_searchTimer`).
    pub global_search_tick: Duration,
    /// How long a download's initial source lookup (`OP_GETSOURCES` →
    /// `OP_FOUNDSOURCES`) waits on the connected server before giving up, so
    /// a sourceless file's `download start` terminates by default instead of
    /// hanging forever: the
    /// server can go quiet for a hash it has no sources for — a connected,
    /// silent server, not a disconnect — and the plain per-request wait had
    /// no bound of its own. aMule has no directly analogous per-request
    /// timer (it sweeps overall connection liveness on `CONSERVTIMEOUT` /
    /// `CONNECTION_TIMEOUT`, 25 s / 40 s — see
    /// `docs/reference/notes/ed2k-runtime.md`); this reuses the same
    /// magnitude as `callback_timeout`'s established external-wait cap. The
    /// CLI's `--max-seconds` bounds the *whole run*; this bounds just this
    /// one RPC.
    pub source_lookup_timeout: Duration,
    /// How far apart attach starts the downloads the last process left
    /// running (ADR-0094): one per pace, in store order, so a store of forty
    /// downloads does not start forty runs in one tick.
    pub download_restore_pace: Duration,
    /// How long a dialed eD2k server may leave the login unanswered before the
    /// session gives up with
    /// [`ServerConnectFailure::LoginTimedOut`](crate::ServerConnectFailure::LoginTimedOut)
    /// Not a second timer: it is the value the eD2k session's own
    /// login deadline (`CloseReason::LoginTimeout`) is armed with, lifted to
    /// config so the bound is a core decision rather than a `-net` default. The
    /// default matches that default (15 s).
    pub server_login_timeout: Duration,
    /// The delay before the first re-make of a lost session the operator's
    /// intent keeps (ADR-0096): aMule's `CS_RETRYCONNECTTIME`, 30 s. Each
    /// later attempt doubles it, up to [`Self::server_reconnect_ceiling`].
    pub server_reconnect_first: Duration,
    /// Where the reconnect delay stops growing: 10 minutes.
    pub server_reconnect_ceiling: Duration,
    /// How long a re-made session must hold before the reconnect count starts
    /// over (ADR-0096, "A lost session is re-made"): 10 minutes, the ceiling.
    /// One that ends sooner continues the count it came up on, so a server
    /// that accepts the login and then drops is dialed ever less often.
    pub server_session_holds: Duration,
    /// How many re-makes a lost session gets before rmule stops and waits for
    /// the operator; `None` never stops while the intent stands (ADR-0096,
    /// "How many attempts"). The default is
    /// [`RECONNECT_ATTEMPTS`](crate::RECONNECT_ATTEMPTS).
    pub server_reconnect_attempts: Option<u32>,
    /// How long a requested Low-ID callback (ADR-0039) holds its worker slot
    /// waiting for the peer to dial in before the slot is released and the next
    /// candidate tried. A callback round-trips server-relay → peer-dial, a
    /// distinct latency regime from a slot wait, so it is its own knob.
    pub callback_timeout: Duration,
    /// How often the server-UDP global source discovery task (ADR-0051) sweeps
    /// the managed server list for active downloads' sources.
    pub global_source_interval: Duration,
    /// The status-ping sweep's first-contact pace (ADR-0052): a
    /// server never probed this run — a fresh import, or every row at start —
    /// is probed at one per tick, 250 ms (eMuleAI's `UDPSEARCHSPEED`, the
    /// family's fastest shipped server-UDP fan-out).
    pub status_ping_first_contact_tick: Duration,
    /// The status-ping sweep's refresh pace and start delay (ADR-0052): at most
    /// one refresh `0x96` per tick across the list (aMule `UDPSERVERSTATTIME`,
    /// 5 s).
    pub status_ping_tick: Duration,
    /// The per-server status re-ask window (ADR-0052): 20 min,
    /// aMule's `UDPSERVSTATMINREASKTIME` floor — the shortest interval the
    /// family itself ever re-pings one server at. A server pinged within it is
    /// walked past, not re-asked.
    pub status_ping_reask: Duration,
    /// The crypt-ping reply grace before a plain fallback (aMule's 20 s
    /// `CryptPingReplyPending` window, ADR-0046).
    pub crypt_ping_grace: Duration,
    /// How often the Kad source discovery task (ADR-0043) scans the active
    /// downloads and shared files for due work. Bounds first-ask and
    /// first-publish latency; the protocol cadences below gate actual sends.
    pub kad_sweep_interval: Duration,
    /// eMule's per-file Kad source re-ask spacing (`KADEMLIAREASKTIME`,
    /// aMule `Constants.h`: 1 hour). A download is re-asked no more often.
    pub kad_reask_interval: Duration,
    /// How often the serve task purges waiters that stopped reasking or whose
    /// file was unshared (aMule `CUploadQueue::Process`) — the
    /// disconnected-standing reap cadence (ADR-0057).
    pub upload_purge_interval: Duration,
    /// A waiting peer's reask-silence deadline before purge (aMule
    /// `MAX_PURGEQUEUETIME`, 1 h): disconnected standing survives only while
    /// the reask heartbeat keeps beating (ADR-0057).
    pub upload_reask_purge_after: Duration,
    /// How long a shared directory that is not there waits between looks for
    /// its return (ADR-0101, "Missing"): one `stat` a minute.
    pub missing_directory_look: Duration,
    /// Whether the peer-TCP surfaces consult the IP filter (aMule
    /// `IpFilterClients`, default **true** — aMule filters out of the box,
    /// with an empty table until a dat file exists). Gates the accept, dial,
    /// and source-ingest checks; with no [`CoreBuilder::ip_filter_dir`](crate::CoreBuilder::ip_filter_dir) the
    /// table is empty and nothing is ever filtered regardless.
    pub ip_filter_clients: bool,
    /// Whether the server surfaces consult the IP filter (aMule
    /// `IpFilterServers`, default **true**): the server dial and the
    /// global-source server-list install.
    pub ip_filter_servers: bool,
    /// The IP filter access-level threshold (aMule `FilterLevel`, default
    /// 127): only ranges whose level is **strictly below** this block, and
    /// the cut is applied when the table is built from the dat files.
    pub ip_filter_level: u8,
    /// The UDP port the **server-UDP** socket binds (the global source
    /// sweep, status pings and the server description ask). Unlike the
    /// client-UDP port ([`CoreSettings::udp_port`](crate::CoreSettings::udp_port))
    /// this is never advertised — no server or peer is ever told this number,
    /// a reply simply returns to whichever port sent the ask — so `0`, the
    /// default, is right for every real deployment as well as a test. The
    /// field exists at all so a test can pin it and hold it, the way the
    /// client-UDP port already lets one prove a **Half-Bound Pair**.
    pub server_udp_port: u16,
    /// Which **Address Families** every socket role binds (ADR-0085): the
    /// peer TCP listener, client UDP and server UDP each bind a **Family
    /// Pair** at one port. Both families by default; a family whose bind is
    /// refused is reported and simply absent, so turning one off is a
    /// deployment choice, never a correctness one. A listener pinned to a
    /// literal address binds that address's family alone — the address is the
    /// point there, and there is no second family to pair with.
    pub address_families: FamilySelection,
    /// The operator's **External Endpoint** override, per **Address Family**
    /// (ADR-0084). `None` in a family — the default — leaves **Address
    /// Learning** to work the address out from what the wire reports. A value
    /// outranks every observation, including the server's own assignment: an
    /// operator who states an address has information rmule does not, and is
    /// the only source exempt from the local-interface corroboration filter.
    pub external_address: ExternalAddressOverride,
    /// The **Port Mapping** knobs (ADR-0086): which of PCP / NAT-PMP / UPnP
    /// may be raced, the lifetime to ask a gateway for, and whether mappings
    /// are withdrawn on a clean exit. Whether to map at all is the operator's
    /// [`CoreSettings::port_mapping`](crate::CoreSettings::port_mapping).
    pub port_mapping: PortMappingConfig,
    /// The **NAT-T** knobs (ADR-0091). Today one: `natt.port_prediction`,
    /// the one-symmetric birthday policy of ADR-0091's port-prediction
    /// amendment, **on by default** since its bench rows passed
    /// (`natt-server-punch-one-symmetric`, `natt-server-punch-symmetric
    /// --port-prediction` and `natt-server-punch-cone` green).
    pub natt: NattConfig,
    /// Response-body cap for the server.met download an on-demand
    /// [`ServerListCommand::UpdateServerList`](crate::ServerListCommand::UpdateServerList) runs (ADR-0080). The URL rides
    /// the command — the operator may name any mirror for one update — but
    /// the hardening cap is core's, so no caller can raise it.
    pub max_server_met_bytes: usize,
}

/// The **Connection Budget**'s two knobs [`CoreConfig::peer_connections`]
/// carries (ADR-0116), shared by every download of the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerConnections {
    /// The **Dial Window**: roads the downloads open per 5-second window — a
    /// dial, a callback ask, a punch, a TCP full ask. aMule's
    /// `MaxConPerFive`, default 20 (stock 2.3.3 `Preferences.cpp:1029`). `0`
    /// reads as 1, so a zero starves nothing.
    pub dials_per_window: u32,
    /// The **Connection Ceiling**: connections the downloads hold at once,
    /// asking and transferring. aMule's `MaxConnections`, 500 where the
    /// descriptor limit is above 520 or unknown (stock 2.3.3
    /// `Preferences.cpp:1028`, `:1493-1500`). `0` reads as 1.
    pub max_connections: usize,
}

impl Default for PeerConnections {
    fn default() -> Self {
        Self {
            dials_per_window: 20,
            max_connections: 500,
        }
    }
}

/// The NAT-T knobs [`CoreConfig::natt`] carries (ADR-0091).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NattConfig {
    /// `natt.port_prediction` (ADR-0091's amendment). `Off` is eMuleAI's
    /// six on target plus the ±16 sweep, byte-identical to the behaviour before
    /// the knob existed. `Birthday` lets a node whose Kad observers disagree on
    /// its UDP port open a 256-socket Fan, and one whose observers agree send
    /// 256 random-port probes, per introduction.
    pub port_prediction: rmule_peer::natt::PortPrediction,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            peer_connections: PeerConnections::default(),
            streaming_window_parts: 8,
            slot_wait_timeout: DEFAULT_SLOT_WAIT_TIMEOUT,
            upload_slot_budget: 4,
            max_upload_queue_len: 64,
            queue_rerank_interval: Duration::from_secs(20),
            search_quiet_timeout: Duration::from_secs(3),
            search_server_answer_timeout: Duration::from_secs(12),
            search_kad_lifetime: Duration::from_secs(45),
            global_search_tick: Duration::from_millis(750),
            source_lookup_timeout: Duration::from_secs(30),
            download_restore_pace: Duration::from_secs(1),
            server_login_timeout: Duration::from_secs(15),
            server_reconnect_first: Duration::from_secs(30),
            server_reconnect_ceiling: Duration::from_secs(600),
            server_session_holds: Duration::from_secs(600),
            server_reconnect_attempts: crate::RECONNECT_ATTEMPTS,
            callback_timeout: Duration::from_secs(30),
            global_source_interval: Duration::from_secs(60),
            status_ping_first_contact_tick: Duration::from_millis(250),
            status_ping_tick: Duration::from_secs(5),
            status_ping_reask: Duration::from_secs(20 * 60),
            crypt_ping_grace: Duration::from_secs(20),
            server_udp_port: 0,
            address_families: FamilySelection::default(),
            external_address: ExternalAddressOverride::default(),
            port_mapping: PortMappingConfig::default(),
            natt: NattConfig::default(),
            kad_sweep_interval: Duration::from_secs(10),
            kad_reask_interval: Duration::from_secs(3600),
            upload_purge_interval: Duration::from_secs(60),
            upload_reask_purge_after: Duration::from_secs(3600),
            missing_directory_look: Duration::from_secs(60),
            ip_filter_clients: true,
            ip_filter_servers: true,
            ip_filter_level: 127,
            max_server_met_bytes: rmule_bootstrap::DEFAULT_MAX_SERVER_MET_BYTES,
        }
    }
}
