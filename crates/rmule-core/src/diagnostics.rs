//! Diagnostic phase tracking for **Multi-peer Download Scheduling**
//! (ADR-0027, ADR-0028), the **Transfer Byte Counters** (ADR-0077) and the
//! **Positional Part Map** (ADR-0079).
//!
//! Defines [`WorkerPhase`] — the currently observed orchestration state of
//! one worker slot — plus the [`WorkerEntry`] and [`DownloadDiagnostics`]
//! records that the per-download task in `download::runner` maintains as the
//! single writer per slot, and the [`UploadDiagnostics`] rows the serve
//! task maintains for the peers it is feeding.
//!
//! A download's progress is one fact: [`DownloadDiagnostics::parts`], the
//! per-index [`PartState`] vector the scheduler's own partition produces. The
//! tallies a consumer reads are *derived* from that vector on demand
//! ([`DownloadDiagnostics::part_counts`]), never stored beside it, so a
//! positional renderer and a percentage renderer cannot disagree (ADR-0079).
//!
//! Every byte figure here is a **monotonic fact**: a running total of payload
//! bytes that crossed the core's wire boundary. Core derives nothing from a
//! clock — no rates, no averages, no windows (ADR-0077). A consumer that wants
//! a rate differences two snapshots itself; that is what the TUI bridge does
//! (ADR-0069 §Dataflow) and what the future EC surface will do over the same
//! counters.
//!
//! The matching mutable [`DiagnosticsState`] handle — the single writer behind
//! all of it — lives in the `state` submodule; [`crate::Core`] owns one and
//! exposes read-only snapshotting through
//! [`crate::Core::diagnostics_snapshot`].

use std::collections::BTreeMap;
use std::time::Instant;

/// The client identification a peer's hello yields, carried on source and
/// upload-peer rows.
pub use rmule_peer::{ClientFamily, ClientMod, ClientSoftware, ClientVersion};
use rmule_primitives::{AddressFamily, FileHash, PeerEndpoint, ServerEndpoint};

use crate::address_learning::{EndpointVerdict, NatHint, SocketRole};

use crate::{DownloadId, DownloadMetadata, PeerRetirementReason};

mod counters;
mod download;
mod kad;
pub(crate) use kad::KadFactsSource;
mod server;
mod shared_files;
mod software;
mod state;

/// Why an `OP_NATT_ENDPOINT_HINT` was dropped instead of punched at — the
/// requester ledger's own verdict, surfaced so a node that never punches can
/// say which of the four acceptance facts kept failing.
pub use crate::natt::front::AttemptRetirement as NattRetirement;
/// Why an introduction started no **Prediction Plan**, or a plan's attempt
/// did not fire (ADR-0091's amendment).
pub use crate::natt::front::PredictionRefusal as NattPredictionRefusal;
pub use crate::natt::requester::HintRefusal as NattHintRefusal;

/// Why a rendezvous relayed *to* this node was not acted on (ADR-0091's
/// acting path) — surfaced so a firewalled node that never punches can say
/// which gate kept failing.
pub use crate::natt::acting::ActingRefusal;

/// Where this node's own buddy stands (ADR-0061 firewalled-node operation).
pub use crate::firewalled::link::BuddyState;

/// Why the most recent recruit tick refused to walk — surfaced
/// so a `BuddyState::None` node can say whether it is merely between pacing
/// ticks or permanently unable to recruit (`CryptRequired`).
pub use crate::firewalled::recruit::RecruitRefusal;

pub use counters::SessionCounters;
pub use download::{
    DIAL_ENDS_KEPT, DownloadDiagnostics, PartCounts, PartState, SourceDialEnd, UploadDiagnostics,
    WorkerEntry, WorkerPhase, WorkerSlot,
};
pub use kad::{
    KadFirewallCheck, KadFirewallVerdict, KadRuntimeDiagnostics, KadState, KadTraffic,
    KadUdpVerdict,
};
pub use server::{ServerDiagnostics, ShareAnnouncement, SharesToServer};
pub use shared_files::{ShareTotals, SharedFileCounters};
#[cfg(test)]
pub(crate) use software::client_software;
pub use software::{SoftwareName, SoftwareParts, software_parts};
pub use state::{BuddyHashSpellingCounters, DiagnosticsState};
pub(crate) use state::{ServerHalf, address_rows};

/// One **Address Learning** row (ADR-0084): what rmule believes about where
/// one of its own sockets is, in one **Address Family**.
///
/// There is no separate freshness field because the verdict already is one:
/// [`Known`](EndpointVerdict::Known) means a tier holds *now* and names which,
/// [`Stale`](EndpointVerdict::Stale) carries the instant the last one lapsed,
/// and [`Unknown`](EndpointVerdict::Unknown) means nothing was ever learned.
/// Splitting that into a level plus a timestamp would let a renderer show the
/// two disagreeing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressDiagnostics {
    /// Which family this row is about.
    pub family: AddressFamily,
    /// Which of our sockets.
    pub role: SocketRole,
    /// Where the outside world reaches it, and how confidently.
    pub verdict: EndpointVerdict,
    /// What the sources disagree about, when they do — the trace of a NAT
    /// rmule cannot see directly. Per family, so the three roles of one family
    /// carry the same hint: the disagreement is about our *address*.
    pub hint: Option<NatHint>,
}

/// Atomic point-in-time view of [`DiagnosticsState`].
///
/// Returned by [`crate::Core::diagnostics_snapshot`] and echoed via
/// `CoreCommand::DumpDiagnostics` for mpsc-only consumers.
#[derive(Clone, Debug, Default)]
pub struct DiagnosticsSnapshot {
    /// Every download with a live row, keyed by id. A completed or cancelled
    /// download's row is gone, so absence here is not "never existed".
    pub downloads: BTreeMap<DownloadId, DownloadDiagnostics>,
    /// The peers the serve activity currently holds an upload slot for, with
    /// their monotonic `bytes_sent` (ADR-0077). Written by the serve task
    /// through the shared [`DiagnosticsState`], so the sync
    /// [`crate::Core::diagnostics_snapshot`] accessor reports it in full —
    /// no actor round trip needed.
    pub uploads: BTreeMap<PeerEndpoint, UploadDiagnostics>,
    /// Every shared file the serve activity has done something for this run,
    /// with what it did: requests drawn and bytes served. Never retired, so a
    /// file keeps its figures after its peers leave.
    pub shared_files: BTreeMap<FileHash, SharedFileCounters>,
    /// Process-lifetime down/up totals (ADR-0077). Like `uploads` and
    /// `downloads` these ride the shared state, so the sync accessor reports
    /// them in full.
    pub session: SessionCounters,
    /// The **managed server list** in list order (ADR-0080) — the whole list,
    /// republished by the actor whenever it changes, so a consumer renders it
    /// without replaying any event. Rides the shared state like `uploads`, so
    /// the sync [`crate::Core::diagnostics_snapshot`] accessor reports it in
    /// full.
    ///
    /// Which row is *connected* is deliberately not a field here: it is one
    /// fact about the session, not a flag on N rows — see
    /// [`connected_server`](Self::connected_server).
    pub servers: Vec<ServerDiagnostics>,
    /// The **Status Ping Sweep** judged a silence with no answered ping near
    /// it, and has heard no answer since: the network, not the servers, looks
    /// down, and no failure tally moved for it (ADR-0052).
    pub status_sweep_unheard: bool,
    /// What the connected session was told of the share set; `None` with no
    /// session, or before the session's first decision (ADR-0099).
    pub share_announcement: Option<ShareAnnouncement>,
    /// The server rmule currently holds a live eD2k session with (ADR-0080 amendment),
    /// or `None` when no session is established.
    ///
    /// **One** fact, matched against a row rather than repeated across the
    /// list. Written only by the session layer — set when a login is accepted,
    /// cleared when that session's task ends, whichever side ended it — so it
    /// reports a connection that exists, never an intent. It is not pruned by
    /// a list republish: removing a server does not disconnect from it
    /// (aMule's `RemoveServer`), so the marker can honestly name an endpoint
    /// the list no longer holds.
    pub connected_server: Option<ServerEndpoint>,
    /// What [`connected_server`](Self::connected_server) granted at its last
    /// `OP_IDCHANGE` (ADR-0047); nothing while there is no session. A menu
    /// reads [`Self::related_search_refusal`] off it without sending a command.
    pub connected_server_grants: rmule_ed2k::ServerGrants,
    /// The search the connected server holds more rows for — its answer said
    /// so, and no search request has gone out since (ADR-0036);
    /// `None` otherwise, and whenever there is no session. What a front
    /// end offers `SearchCommand::MoreResults` by.
    pub search_more_results: Option<crate::search::ServerMoreResults>,
    /// When the snapshot was read, so a consumer can difference two of them
    /// into a rate. `None` on the `Default` value, which is not a reading.
    pub taken_at: Option<Instant>,
    /// The **Address Learning** rows (ADR-0084), one per bound socket role
    /// per address family, in role order within family order. Empty when
    /// nothing has been learned *and* nothing has bound — which a consumer
    /// renders as "not known yet", never as "no address".
    ///
    /// Rides the shared state like `uploads`, so the sync
    /// [`crate::Core::diagnostics_snapshot`] accessor reports it in full.
    pub addresses: Vec<AddressDiagnostics>,
    /// The **Port Mapping** rows (ADR-0086), one per *desired* mapping — one
    /// per bound socket role per address family that rmule wants forwarded.
    /// Empty when port mapping is off, when no socket has bound, or when no
    /// backend is installed.
    ///
    /// A row exists whether or not the mapping was granted: "the eD2k listener
    /// is not mapped" is the fact an operator most needs, and a table that
    /// lists only successes cannot state it. Rides the shared state like
    /// `uploads`, so the sync [`crate::Core::diagnostics_snapshot`] accessor
    /// reports it in full.
    pub mappings: Vec<crate::port_mapping::MappingDiagnostics>,
    /// The Kad runtime's cold-start state (ADR-0067): `None` until
    /// `CoreCommand::EnableKad` started the node, `Some` thereafter. Populated
    /// by the Kad Activity through the shared state like `uploads`, so the sync
    /// [`crate::Core::diagnostics_snapshot`] accessor reports it in full.
    pub kad: Option<KadRuntimeDiagnostics>,
    /// Where the Kad activity stands: off, running or stopping.
    pub kad_state: KadState,
    /// The **Shared Directory List** (ADR-0101, "Shared Directories"), in
    /// list order, with each entry's state and its scan's progress; a
    /// directory being added follows the list. Empty while no download
    /// directory is set and none was added.
    pub shared_directories: Vec<crate::SharedDirectoryDiagnostics>,
    /// Our **Own Mapping** for the client-UDP role (ADR-0091's port-prediction
    /// amendment), read from Address Learning at the snapshot. `None` for a
    /// state built without a core.
    pub natt_own_mapping: Option<rmule_peer::natt::OwnMapping>,
    /// How many **Kad Activity** tasks the actor currently holds a
    /// `JoinHandle` for: the discovery pump, the publisher, and
    /// the ed2k→Kad handoff forwarder, so `0..=3`. Installed and
    /// cleared with `kad`: `0` on the `Default` value and again once
    /// `retire_kad` has joined every one back.
    pub kad_tasks_live: usize,
    /// The one client-UDP socket's total bind failure (ADR-0057),
    /// or `None` on a core whose socket came up — including one that bound
    /// only one **Address Family** (ADR-0085): a partial bind is not this
    /// fact, and Kad, the reask surface and NAT-T all still have a socket to
    /// run on. Set once, at core start, and never cleared: there is no retry
    /// (ADR-0057 amendment), so the row this seeds is the whole session's
    /// answer to "why is Kad off". Rides the shared state like `addresses`, so
    /// the sync [`crate::Core::diagnostics_snapshot`] accessor reports it
    /// before the actor has answered its first command.
    pub client_udp_bind_failure: Option<ClientUdpBindFailure>,
    /// Every **Half-Bound Pair**, for all three roles:
    /// a socket role whose Family Pair came up, but without a family
    /// it *selected* — so the role runs on the other family alone, and
    /// whatever rode the missing one is off.
    ///
    /// The other side of `client_udp_bind_failure`: that row names a bind
    /// that produced no socket at all, this one a bind that produced half the
    /// sockets asked for. ADR-0085's rule — one family refusing must not take
    /// the other down — is why the half-bound case is not a failure; it is
    /// still a *fact*, since a client-UDP pair on `::`
    /// alone leaves Kad and the NAT-T punch path dead while every other
    /// surface reads "bound".
    ///
    /// The eD2k listener's and client-UDP's rows are read from the
    /// **Address Learning** bind table rather than copied beside it, like
    /// `addresses`: the table already learns each role's `FamilyBinds` at its
    /// bind, so there is one writer and no second copy to drift.
    /// Server-UDP's row is the odd one out: `SocketRole` (the
    /// bind table's key) deliberately has no `ServerUdp` variant, because a
    /// row there is what feeds the Desired Mapping Set (ADR-0086) and nothing
    /// addresses or maps the server-UDP socket — so its fact is recorded
    /// beside the table instead and appended last here. Empty when every pair
    /// came up whole. Never cleared — there is no re-bind (ADR-0057
    /// amendment).
    pub half_bound_pairs: Vec<rmule_net::family::HalfBound>,
}

/// Why the one client-UDP socket (ADR-0057) never bound, and what was asked
/// for — the diagnostics half of naming a failed bind's port and error.
/// [`CoreEvent::ClientUdpBindFailed`](crate::CoreEvent::ClientUdpBindFailed)
/// carries the same two facts at the instant the bind was attempted;
/// [`CoreCommandRejectReason::KadUnavailable`](crate::CoreCommandRejectReason::KadUnavailable)
/// carries them again for whichever `EnableKad` a caller sends afterward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientUdpBindFailure {
    /// The port core asked the OS for — [`CoreSettings::udp_port`](crate::CoreSettings::udp_port).
    pub port: u16,
    /// The OS's reason. When every selected **Address Family** refused the
    /// bind, `UdpFamilyPair::bind` (ADR-0085) joins their reasons into one
    /// `io::Error` whose kind is a real one: the shared kind when every
    /// refused family agrees, else the IPv4 half's (the common case is an
    /// operator's own port conflict, `AddrInUse`, and IPv4 is the family it
    /// almost always hits first — see `refused_every_family`'s doc comment
    /// for the full rule). The whole `io::Error`, with every family's own
    /// reason, is logged once at `warn` where the bind was attempted.
    pub kind: std::io::ErrorKind,
}
