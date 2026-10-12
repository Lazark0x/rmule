//! Application-facing orchestration for rmule: the crate a front end talks to.
//! It owns the session's activities — downloads, the serve side, searches, the
//! server list and Kad — behind one [`Core`] actor, and owns none of the wire
//! formats they ride (those live in `rmule-ed2k`, `rmule-peer`, `rmule-kad` and
//! `rmule-net`). Everything durable reaches disk through a store seam, so the
//! same session runs on the engine's in-memory backend for a test and on the
//! user's `rmule.redb` in production.

#![warn(missing_docs)]

mod adapters;
// The core-owned **Address Learning** store (ADR-0084): the sans-I/O sibling
// of `Reachability` that turns typed `AddressObservation`s into one External
// Endpoint verdict per address family and socket role. The port mapper
// and the IPv6 dialect are its other two feeders, so some constructors
// and the chooser's IPv6 half have no production caller until those land.
#[cfg_attr(not(test), allow(dead_code))]
mod address_learning;
mod app_config;
mod assembly;
mod ban_store;
mod hello_refusals;
// The core-owned open-node buddy service (ADR-0061): the single-slot citizen
// next to `Reachability` that serves firewalled peers — the FINDBUDDY refusal
// matrix, the verified `0x52`→`0x99` / `0x94`→`0x9A` relays, and the ping/pong
// keepalive. `buddy_link` holds the live socket, so the allow covers only what
// no production path reaches yet: `drop_stale`, which needs a keepalive timer
// nothing arms, and the test-tier accessors.
#[cfg_attr(not(test), allow(dead_code))]
mod buddy;
mod buddy_link;
// The core-side callback route chooser (ADR-0061): one sans-I/O selector every
// dial path asks to reach a peer, so route precedence is decided in exactly one
// place. **Peer Reach** (`peer_reach`) asks it and carries its verdict out.
mod callback;
// The one client-UDP demux front (ADR-0057): the single place an inbound
// datagram on the bound UDP port is sorted into its protocol surface — the
// peer-UDP reply matrix, the NAT-T front, and the running Kad node's inlet.
mod client_udp;
mod clients_met;
mod content;
mod credit;
mod data_dir;
pub mod diagnostics;
mod dialable;
mod directory_scan;
mod download;
mod durable;
mod error;
mod file_key;
// The core-owned firewalled-node operation (ADR-0061): the sibling of the
// open-node `buddy` service — buddy recruitment (gated on both surfaces
// firewalled), the relayed-callback consume, the rate-limited/Reachability-gated
// `0x95` direct-callback consume, and the buddy info our source publishes carry.
// Live now that the firewalled-node front runs: `firewalled::link` holds the dialed buddy link and
// `firewalled::front` is the task that drives it, so nothing here waits on a
// front any more.
mod firewalled;
mod global_sources;
mod hashing;
#[cfg(test)]
mod hello_facts;
mod interval_limiter;
mod mailbox;
// The core-owned IP filter: aMule 2.3.3 `CIPFilter` parity —
// the two-format dat parser with malformed tolerance, the access-level
// threshold applied at build time, the last-write-wins range store behind the
// static-file precedence, and the shared verdict handle the accept / dial /
// server-dial / source-ingest gates consult.
mod ip_filter;
mod join;
mod kad_sources;
// The file-known predicate: mirrors the Shared File Registry's
// key set plus the Download Set's file hashes, so the firewalled front can
// answer its `0x99` gate without awaiting the actor.
mod known_files;
mod name_resolver;
// The Awaited Testers (ADR-0046 "Test Connections"): who may dial the
// listener plain under `Required`, read by the accept pump without awaiting.
mod awaited_testers;
// The File History (ADR-0100): the registry's entries and the cancelled
// downloads, read together for a front end's Known-File Marks.
pub mod file_history;
// What rmule knows about itself on the wire: its user hash, plus its external
// address projected from `address_learning` — the self-facts both UDP crypt
// surfaces key on (ADR-0046 as amended by ADR-0084).
// The core-owned NAT traversal citizen (ADR-0091): the rendezvous emit, the
// acting path, and the relay service with its direction-split limiters.
mod natt;
mod obfuscation_policy;
mod own_identity;
// **Peer Reach** (ADR-0061, ADR-0091): the one module that reaches a peer —
// our route position read, the road chosen, carried out and reported.
mod peer_reach;
mod peer_roster;
mod planning;
// The core-owned **Port Mapping** brain (ADR-0086): the sans-I/O mapper that
// derives the Desired Mapping Set from the bound Family Pairs, races PCP /
// NAT-PMP / UPnP, grades every trial on the exact external port, renews on the
// RFC ladder and re-adds the set after a gateway reboot. `adapters::port_mapping`
// is the runtime that enacts its commands; the allow covers the grading and
// lease vocabulary that only the deterministic tier reads back.
#[cfg_attr(not(test), allow(dead_code))]
pub mod port_mapping;
// The Run Log (ADR-0075): the record vocabulary every core event projects
// into, its two levels, and the file a front end writes them to.
pub mod run_log;
// The core-owned Reachability verdict store, its Kad-event projection, and the
// firewall-check dial-back broker (ADR-0058). The single answer to "can a peer
// reach us" — `server-High-ID or Kad-open` — which the ADR-0057 reask gate in
// the download brain reads rather than guessing.
mod reachability;
mod registry;
mod registry_check;
mod scheduler;
mod search;
mod serve;
mod server_capabilities;
/// The managed server list: model, store seam, and server.met acquisition
/// (ADR-0080).
mod server_list;
mod server_session;
mod server_udp;
mod service;
mod settings;
mod source_discovery;
mod storage;
mod store;
mod upload_queue;

pub use adapters::{
    AnnounceOutcome, ClientUdpBind, DownloadedPart, KadCells, KadEnableConfig, KadNodeIdentity,
    KadRuntimeFactory, KadShutdownHandle, KadShutdownSlot, KadSourceChannel, PeerDownloadOutcome,
    PeerTransferService, PeerWorker, PeerWorkerCommand, PeerWorkerEvent, RuntimeKadChannel,
    RuntimeKadFactory, RuntimePeerTransferService, RuntimeServeRuntimeService,
    RuntimeSourceLookupService, ServeConnection, ServeInput, ServeOutput, ServeRuntimeService,
    SourceLookupOutcome, SourceLookupService, WorkerBrief,
};
pub use address_learning::{
    AddressObservation, AssignedAddress, ConfidenceTier, EndpointVerdict, ExternalAddressOverride,
    NatHint, ObservationOutcome, ObservationSource, SocketRole,
};
pub use app_config::{
    AppConfigStore, DEFAULT_NICKNAME, DEFAULT_PROTOCOL_VERSION, DEFAULT_TCP_PORT, DEFAULT_UDP_PORT,
    KadIdentity, Preference,
};
pub use clients_met::{
    CLIENTS_MET_FILE, CREDITFILE_VERSION, ClientsMetError, CreditRecord, EXPIRY_SECS,
    load_clients_met, save_clients_met, seed_credit_ring,
};
pub use content::{ContentFileStore, PartFileChange, RestoredProgress, Revalidation};
pub use credit::{CreditStore, CreditTotals, KeyBinding, PeerCredit, credit_modifier};
pub use data_dir::{DataDir, DataDirSource, home_dir, resolve_data_dir};
pub use directory_scan::{
    DirectoryOffer, DirectoryRefusal, DirectoryRole, DirectoryScanDiagnostics, DirectoryState,
    ScanPhase, ScanSummary, ShareGuards, SharedDirectoryDiagnostics, WatchFault,
};
pub use download::source_seeds::{RememberPeers, SeedRank, SourceSeed};
pub use durable::{
    DownloadLifecycle, DownloadMetadata, DownloadMetadataOrigin, DownloadPaths,
    DurableDownloadRecord, VerifiedPartRecord,
};
pub use error::{CoreError, DownloadFailure, FinalizeError, PartFault, StorageIntegrityFault};
pub use join::{
    FirstRunFetch, JoinCommandSink, JoinConfig, JoinOutcome, KadSeedOutcome, SeedReadFault,
    acquire_kad_seeds, run_join_sequence,
};
pub use kad_sources::KadAnswer;
pub use planning::PartPlan;
pub use reachability::KadReachLevel;
/// Why a search row was skipped: the code a `SearchResultSkipped` event carries.
pub use rmule_ed2k::SearchResultSkipReason;
pub use server_list::{
    DEFAULT_DEAD_AFTER, DeadSince, ManagedServer, ResolvedAddress, ServerFigures,
    ServerGrantsReport, ServerHealth, ServerListFetcher, ServerListStore, ServerListUpdate,
    ServerListUpdateError, ServerListUpdateFailure, ServerMerge, ServerPolicy,
};
pub use settings::{
    CoreSettings, CoreSettingsHandle, Setting, SettingError, SettingRefusal, TakesEffect,
};
// The one obfuscation policy `CoreSettings::obfuscation` carries across the peer
// stream + datagram surfaces (ADR-0042/0046), re-exported so an application can
// set it without depending on `rmule_net::peer` directly.
pub use registry::{ShareSource, SharedFileEntry, SharedFileRegistry};
pub use registry_check::{Withheld, WithheldReason};
/// aMule's three-valued server priority (`ST_PREFERENCE`), re-exported so a
/// front-end sets [`ManagedServer::priority`] without depending on
/// `rmule-ed2k` directly (ADR-0080).
pub use rmule_ed2k::{HolepunchFailReason, ServerGrants, ServerPriority};
/// The **Half-Bound Pair** vocabulary — re-exported for the same
/// reason [`ObfuscationPolicy`] is: a front end renders
/// [`CoreEvent::SocketBoundWithoutFamily`] and
/// [`DiagnosticsSnapshot::half_bound_pairs`](crate::diagnostics::DiagnosticsSnapshot::half_bound_pairs)
/// without depending on `rmule_net` directly.
pub use rmule_net::family::{Consequence, HalfBound, PairRole};
pub use rmule_net::natt::TunnelTransport;
pub use rmule_net::peer::{ObfuscationPolicy, PeerStreamRole};
/// The seam [`live_mapping_backends`] fills and [`CoreBuilder::mapping_backends`]
/// takes, re-exported so an application can name the set it installs — the
/// live three, or none — without depending on `rmule_net::portmap`.
pub use rmule_net::portmap::MappingBackend;
/// The three live **Mapping Backends** (ADR-0086) — PCP and NAT-PMP over
/// `crab_nat`, UPnP-IGD over `igd-next` — re-exported so an application hands
/// them to [`CoreBuilder::mapping_backends`] without depending on
/// `rmule_net::portmap` directly, the same reason [`ObfuscationPolicy`] is
/// re-exported. Core installs none by default: talking to the operator's router
/// is a deployment decision, so a test, a tool or a harness holds none of these
/// and maps nothing.
pub use rmule_net::portmap::live_backends as live_mapping_backends;
/// The `natt.port_prediction` knob's values, re-exported so a front end
/// configures [`NattConfig`] without depending on `rmule-peer` (ADR-0091's
/// port-prediction amendment).
pub use rmule_peer::natt::{OwnMapping, PortPrediction};
pub use rmule_peer::{HelloRefusal, HelloRefusalCode};
pub use scheduler::DownloadScheduler;
pub use search::{KadKeywordSink, MORE_RESULTS_ASKS, RelatedSearchRefusal, ServerMoreResults};
pub use server_session::build_peer_handshake_context;
pub use service::{
    BuddyDialFailure, ClientCredentials, Core, CoreBuilder, CoreCommand, CoreCommandRejectReason,
    CoreConfig, CoreEvent, DEFAULT_SLOT_WAIT_TIMEOUT, DialEnd, DialFailure, DownloadCommand,
    DownloadEvent, DownloadId, IdAssignment, IgnoredReaskReply, Ipv6Probe, KadStopReason,
    KadUnavailableReason, LegNotSent, LoginClaim, LoginCloseCause, LoginLink, LoginStep, NameTaken,
    NatTraversalUnavailableReason, NattConfig, PartReleaseReason, PartsLost, PeerBuddy, PeerReach,
    PeerReachDropReason, PeerReachRoute, PeerRetirementReason, PlainLinkReason, PortTestAdmission,
    PortTestClosedBy, PortTestEnd, PortTestLateAdmission, PurgedSource, QuitStep,
    RECONNECT_ATTEMPTS, ReconnectEnd, RestartOutcome, ScanCommand, ScanEvent, SearchCommand,
    SearchEvent, SearchFailure, SearchId, SearchLegState, SearchLegs, ServeCommand, ServeEvent,
    ServeStartFailure, ServeStopReason, ServerConnectFailure, ServerConnectionEvent,
    ServerListCommand, ServerListEvent, ShareRejectReason, SharesWithheld, SourcePurgeReason,
    SourceWait, SweepTally, VerificationAuthority,
};
pub use storage::{DownloadRepository, ResolvedAuthority};
pub use store::app_config::DurableAppConfig;
pub use store::credit::DurableCreditStore;
pub use store::download::{DurableDownloadRepository, LoadedSeeds};
pub use store::registry::DurableSharedFileRegistry;
pub use store::{
    DURABLE_STORE_FILE, DurableStore, open_durable_store, open_durable_store_in_memory,
};
pub use upload_queue::{
    Admission, LOW_ID_ABUSE_WAIT_LIST_THRESHOLD, MAX_WAITING_PER_ADDRESS, Promotion,
    ReaskResolution, UploadSlotQueue, WaiterLeaveCause,
};

/// One routing-table contact, re-exported so a front-end can hand
/// [`KadEnableConfig::contacts`] a decoded nodes.dat's "v1/v2-merge" seeds
/// without depending on `rmule-kad` directly (ADR-0065).
pub use rmule_kad::KadContact;
/// The Kad node ID type, re-exported for [`KadIdentity`],
/// [`KadNodeIdentity`] and [`CoreBuilder::kad_id`] (ADR-0043).
pub use rmule_kad::KadId;
