//! What the core reports back. One [`CoreEvent`] per fact, grouped by activity,
//! carrying the peer-reach, release and retirement vocabulary the events name.
//! Events are facts about what happened, never requests — a front end may drop
//! every one of them and the session still runs.

mod buddy;
mod download;
mod lifecycle;
mod login;
mod peer_reach;
mod scan;
mod search;
mod source_ends;

pub use buddy::BuddyDialFailure;
pub use download::{CompletionStep, DownloadEvent, PartsLost, RestartOutcome, SourceWait};
pub use lifecycle::{KadStopReason, QuitStep, ServeStopReason};
pub use login::{
    DialFailure, IdAssignment, Ipv6Probe, LoginClaim, LoginCloseCause, LoginLink, LoginStep,
    PlainLinkReason, PortTestAdmission, PortTestClosedBy, PortTestEnd, PortTestLateAdmission,
};
pub use peer_reach::{
    NatTraversalUnavailableReason, PeerBuddy, PeerReach, PeerReachDropReason, PeerReachRoute,
};
pub use scan::ScanEvent;
pub use search::{LegNotSent, SearchEvent, SearchFailure, SearchLegState, SearchLegs, SweepTally};
pub use source_ends::{DialEnd, IgnoredReaskReply, PurgedSource, SourcePurgeReason};

use std::net::SocketAddrV4;

use rmule_ed2k::ServerPriority;
use rmule_primitives::{ClientId, FileHash, Ipv4Endpoint, ServerEndpoint, UserHash};

use super::CoreCommandRejectReason;
use crate::server_list::ServerListUpdateFailure;

/// The serve activity's event vocabulary. Wrapped by [`CoreEvent::Serve`];
/// variants carry a file's content identity, never a `DownloadId`
/// (ADR-0031).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServeEvent {
    /// A file was added to the **Shared File Registry** (explicit share or
    /// auto-registered completed download).
    FileShared {
        /// The content identity now offered to peers.
        file_hash: FileHash,
    },
    /// A file was removed from the registry by `UnshareFile`.
    FileUnshared {
        /// The content identity no longer offered.
        file_hash: FileHash,
    },
    /// A registry row's file is not readable now: the row is kept, and
    /// nothing is offered for it until a look finds it readable again
    /// (ADR-0106, "The registry against the disk").
    FileWithheld {
        /// The content identity no longer offered.
        file_hash: FileHash,
        /// Why.
        reason: crate::WithheldReason,
        /// When rmule noticed.
        since: std::time::SystemTime,
    },
    /// A withheld row's file is readable again, and it is offered again.
    FileOffered {
        /// The content identity offered again.
        file_hash: FileHash,
    },
    /// A download began to offer the parts it verified: a **Partial Share**
    /// (ADR-0113). It is the download's own, never a registry row.
    PartialOffered {
        /// The content identity whose verified parts are offered.
        file_hash: FileHash,
    },
    /// A Partial Share stopped being offered.
    PartialWithdrawn {
        /// The content identity no longer offered in part.
        file_hash: FileHash,
        /// Why.
        cause: crate::PartialEnd,
    },
    /// A restarted download's **Offer Check** finished (ADR-0113 §"A paused
    /// download"): the parts it recorded were read again and hashed against
    /// their records before it may be offered. Said once for each check
    /// whose result is applied, whatever it found, with what the read cost.
    OfferChecked {
        /// The content identity whose recorded parts were read.
        file_hash: FileHash,
        /// The bytes read from the part file.
        bytes_read: u64,
        /// How long the read took, from taking the scans' hashing turn to
        /// its last part.
        took: std::time::Duration,
    },
    /// The folders of the shared files outside the download directory cannot
    /// be watched; the log says why. A file that goes from one is noticed at
    /// a peer's failed read or at the next start. Said once.
    SharesUnwatched,
    /// An `UnshareFile` could not be honoured.
    ShareRejected {
        /// Why the registry refused it.
        reason: ShareRejectReason,
    },
    /// The serve activity bound its listener and is accepting peers.
    ///
    /// **The bind fact, emitted at the bind**. It says nothing
    /// about the server login the same command causes: the listener accepts
    /// whether or not a server ever answers, and the two have latencies orders
    /// of magnitude apart. A consumer that needs the assigned client id —
    /// High-ID, callback capability — watches
    /// [`CoreEvent::ServerConnection`] instead.
    ///
    /// Re-emitted, unchanged, for a `StartServing` that arrives while this
    /// activity is already serving: the command is idempotent, so its answer is
    /// too.
    ServingStarted {
        /// The address the listener actually bound — the port rmule then
        /// advertises, since eD2k requires advertising what you bind.
        listen_addr: SocketAddrV4,
    },
    /// `StartServing` produced no serving activity. Terminal for
    /// that command and for nothing else: no listener bound, no activity
    /// exists, and the serve adapter is still there — so a retry is a real
    /// retry, and it will answer with one of these or with
    /// [`Self::ServingStarted`], never with silence.
    ServingFailed {
        /// What stopped it.
        reason: ServeStartFailure,
    },
    /// `OP_OFFERFILES` was sent for `file_count` shared files.
    FilesAnnounced {
        /// How many registry entries went into the announce.
        file_count: usize,
    },
    /// The **Announce Policy** kept `file_count` shared files from the
    /// connected server: nothing went on the wire (ADR-0099).
    FilesWithheld {
        /// How many registry entries the set held.
        file_count: usize,
        /// Why the server was not told them.
        reason: SharesWithheld,
    },
    /// A requesting peer was granted an upload slot for `file_hash`.
    UploadSlotGranted {
        /// The peer now allowed to pull bytes.
        peer: rmule_primitives::PeerEndpoint,
        /// The file the slot is for.
        file_hash: FileHash,
        /// The client the peer's hello named; `None` when the serve side
        /// holds no hello for it.
        software: Option<rmule_peer::ClientSoftware>,
    },
    /// A requesting peer is waiting at queue position `rank` for `file_hash`.
    /// Raised again whenever the rank or the file moves: a waiter follows the
    /// last file it asked about (aMule's one upload file per client).
    PeerQueued {
        /// The waiting peer.
        peer: rmule_primitives::PeerEndpoint,
        /// Its position in our upload queue, as we just told it.
        rank: u16,
        /// The shared file it waits for.
        file_hash: FileHash,
        /// The client the peer's hello named — kept while it waits, across
        /// its hang-up; `None` when the serve side holds no hello for it.
        software: Option<rmule_peer::ClientSoftware>,
    },
    /// The queue was at capacity, so a requesting peer was refused. Nothing
    /// was sent to it — both references `return` at the wait-list cap without
    /// framing a packet — so this event is the refusal's only trace.
    UploadQueueFull {
        /// The peer that was turned away.
        peer: rmule_primitives::PeerEndpoint,
    },
    /// A requesting peer was turned away by the **Low-ID abuse guard**
    /// (ADR-0031 amendment): we are Low-ID, the asker holds no slot
    /// of ours, is no friend, is not on our server, and more than fifty peers
    /// already wait. Nothing was sent — the references `return` here — so this
    /// event is the refusal's only trace.
    UploadLowIdAbuseRefused {
        /// The peer that was turned away.
        peer: rmule_primitives::PeerEndpoint,
    },
    /// A queued waiter that claims UDPv4 and extended requests pinged
    /// `OP_REASKFILEPING` (`0x90`) cut short for that claim — the file hash
    /// alone, a status short of the file's part count, or no complete-source
    /// count from a claim above `1`. Its part status stands as far as it was
    /// read and nothing was sent, as aMule's reader throws and its dispatcher
    /// only logs (ADR-0055 §Serving), so this event is the ping's
    /// only trace.
    ReaskPingMalformed {
        /// The waiter whose ping it was (its TCP endpoint).
        peer: rmule_primitives::PeerEndpoint,
    },
    /// A peer whose hello claimed extended requests asked a shared file's
    /// name (`OP_REQUESTFILENAME`, `0x58`) with the file hash alone —
    /// malformed for that claim. Its part status was cleared, nothing was
    /// answered and its connection was closed, as aMule's reader throws and
    /// its packet handler disconnects (ADR-0055 §Serving).
    NameAskMalformed {
        /// The asker (its TCP endpoint).
        peer: rmule_primitives::PeerEndpoint,
    },
    /// A requesting peer was turned away because its accounting key — one IPv4
    /// address, one IPv6 `/64` — already holds
    /// [`MAX_WAITING_PER_ADDRESS`](crate::MAX_WAITING_PER_ADDRESS) wait-list
    /// places (ADR-0088). Nothing was sent to it; this event is the only trace,
    /// which is why the counter behind it exists.
    UploadAddressCapReached {
        /// The peer that was turned away.
        peer: rmule_primitives::PeerEndpoint,
    },
    /// A peer left the queue/slot; its slot (if held) is freed for promotion.
    UploadSlotReleased {
        /// The peer that left.
        peer: rmule_primitives::PeerEndpoint,
    },
    /// A wait-list entry left the queue without ever holding a slot — the
    /// Waiter relation's terminal (ADR-0059 "Roster relations"). Distinct
    /// from [`Self::UploadSlotReleased`], which only a slot holder earns: the
    /// reclaimed dial-back leg of the purge sweep emits that one alone, never
    /// this too. A promotion is not a leave — the waiter becomes
    /// a holder (`UploadSlotGranted`).
    WaiterLeft {
        /// The waiter that left.
        peer: rmule_primitives::PeerEndpoint,
        /// Why it left.
        cause: crate::WaiterLeaveCause,
    },
    /// A waiter came back on a new link and keeps its place: the new link's
    /// hello named the client waiting at `from`, whose link had ended or
    /// came from the same address and listen port (aMule attaches the new
    /// socket to the client it knows, `ClientList.cpp:371-412`, and a client
    /// already queued keeps its place, `UploadQueue.cpp:395-431`). Every row
    /// and mark keyed by `from` is now keyed by `to`; a `from` still live is
    /// closed after this.
    WaiterRelinked {
        /// The link the waiter waited on.
        from: rmule_primitives::PeerEndpoint,
        /// The link it waits on now.
        to: rmule_primitives::PeerEndpoint,
    },
    /// A peer's source-exchange request was answered with `count` sources
    /// (ADR-0055 §Serving) — the serve-side mirror of a download's
    /// `SourcesReceived`. A throttled or empty-pool ask emits nothing.
    SourcesServed {
        /// The peer that asked.
        peer: rmule_primitives::PeerEndpoint,
        /// The file the sources are for.
        file_hash: FileHash,
        /// How many sources the answer carried, after selection and throttling.
        count: usize,
    },
    /// The serve activity ended, and with it the adapter came back: the actor
    /// emits this only once serving is startable again, so a
    /// front end that answers it with `StartServing` never races the teardown.
    ServingStopped {
        /// What ended it.
        reason: ServeStopReason,
    },
}

/// Why a `StartServing` produced no serving activity.
///
/// A **login** failure is never one of these. Serving does not wait for the
/// login, so a server that refuses, hangs up or goes mute is reported by
/// [`ServerConnectionEvent::ConnectFailed`] while the listener keeps accepting
/// — which is exactly the distinction this type exists to make: a bind
/// failure and a login failure are told apart by the events alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServeStartFailure {
    /// The inbound listener did not bind. The `ErrorKind` is the OS's reason,
    /// portably — `AddrInUse` for a held port, `AddrNotAvailable` for an
    /// address this host does not hold; the whole `io::Error` is logged where
    /// it happened. A retry once the port is free succeeds.
    Bind(std::io::ErrorKind),
    /// The serve adapter itself refused the start: this core has none left —
    /// which now means only that a serve task ended abnormally
    /// and took it down (`ServeStopReason::TaskFailed`), an activity that ends
    /// any other way hands it back — or a non-production adapter failed for a
    /// reason of its own. Nothing bound.
    Adapter,
}

/// Why the **Announce Policy** kept the share set from the connected server
/// (ADR-0099, "What is announced to a server that answers related searches").
/// Both are the operator's preference meeting the server's related-search
/// grant (`SRV_TCPFLG_RELATEDSEARCH`, `0x40`); they differ in what the
/// server already holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SharesWithheld {
    /// The server grants related search, and holds none of our files.
    RelatedSearchGranted,
    /// The server grants related search, and keeps the set announced to it
    /// before the preference was switched on: an offer cannot be taken back
    /// in the session, so the newer set stays here.
    RelatedSearchGrantedAfterAnnounce,
}

/// Why an `UnshareFile` was refused. A file is shared by sharing its
/// directory (ADR-0101, "Shared Directories"), whose refusals are
/// [`DirectoryRefusal`](crate::DirectoryRefusal)s.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShareRejectReason {
    /// `UnshareFile` named a file that was not in the registry.
    NotShared,
    /// The durable registry rejected the write.
    RegistryError,
}

/// What happened to the **managed server list** (ADR-0080).
///
/// Edges, in the ADR-0069 sense: each one reports a change a consumer may want
/// to flash or log. The list *itself* is a level — it rides
/// [`DiagnosticsSnapshot::servers`](crate::diagnostics::DiagnosticsSnapshot::servers)
/// — so a consumer never has to fold these into a list of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerListEvent {
    /// A server that was not listed before is listed now.
    ServerAdded {
        /// The newly listed server.
        server: ServerEndpoint,
    },
    /// A server that was already listed folded a fresh record (a re-add, or a
    /// downloaded row): its name and possibly its description changed, its
    /// priority, static pin and failure tally did not.
    ServerUpdated {
        /// The server whose record was folded.
        server: ServerEndpoint,
    },
    /// A server left the list. A session connected to it is untouched.
    ServerRemoved {
        /// The server that left the list.
        server: ServerEndpoint,
    },
    /// A listed server's `ST_PREFERENCE` was set, which is what auto-connect
    /// server ordering reads.
    ServerPriorityChanged {
        /// The server that was re-prioritized.
        server: ServerEndpoint,
        /// Its new priority.
        priority: ServerPriority,
    },
    /// A listed server's static pin was set. A static server survives a list
    /// update and the failure-tally drop that removes dead servers.
    ServerStaticChanged {
        /// The server that was pinned or unpinned.
        server: ServerEndpoint,
        /// Whether it is now pinned.
        is_static: bool,
    },
    /// An [`ServerListCommand::UpdateServerList`](crate::ServerListCommand::UpdateServerList) was accepted and its fetch
    /// is running. The command is answered off the actor, so without this a
    /// consumer could not tell an accepted update from an ignored one.
    ServerListUpdateStarted {
        /// The server.met URL being fetched.
        url: String,
    },
    /// The update finished: `added` downloaded rows were new endpoints,
    /// `updated` folded into known ones, and the list now holds `total`.
    ServerListUpdated {
        /// Downloaded rows that were endpoints the list had never held.
        added: usize,
        /// Downloaded rows folded into an already-listed server.
        updated: usize,
        /// The list's size after the install.
        total: usize,
    },
    /// The update produced no new list. The old one is untouched — the fetch
    /// parses before it installs (ADR-0065).
    ServerListUpdateFailed {
        /// Where the fetch or the parse stopped, as a code; the error behind
        /// it is in the Run Log.
        reason: ServerListUpdateFailure,
    },
}

/// What happened to the **server session** (ADR-0080 amendment).
///
/// Edges to the list's level: which server rmule is connected to is a level
/// ([`DiagnosticsSnapshot::connected_server`](crate::diagnostics::DiagnosticsSnapshot::connected_server)),
/// and these report the transitions a consumer wants to flash or log.
///
/// Emitted for **every** session, not just an operator's
/// [`CoreCommand::ConnectToServer`](crate::CoreCommand::ConnectToServer): a search or a download that establishes
/// the session on its own is just as much a connection, and a consumer that
/// folded only the explicit ones would show "not connected" while rmule was
/// logged in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerConnectionEvent {
    /// The dial to `server` has started. No level has moved yet.
    Connecting {
        /// The server being dialed.
        server: ServerEndpoint,
        /// The server whose session this connect ended to make room, when it
        /// was another: its `Disconnected` came just before.
        leaving: Option<ServerEndpoint>,
    },
    /// `server` accepted the login and assigned `client_id`. The connected
    /// marker is up and the server's failure tally is cleared.
    Connected {
        /// The server now logged in to.
        server: ServerEndpoint,
        /// The id it assigned: High-ID (routable) or Low-ID, which decides
        /// whether peers can dial rmule directly.
        client_id: ClientId,
    },
    /// The connect did not produce a session. The connected marker stays down;
    /// the operator's *choice* of server stands, so a retry needs no re-pick.
    ConnectFailed {
        /// The server that was tried.
        server: ServerEndpoint,
        /// Why no session came of it — which also decides whether the server's
        /// failure tally moves.
        reason: ServerConnectFailure,
    },
    /// The session with `server` ended — switched out by an operator connect,
    /// hung up by the server, or lost with the link. The connected marker is
    /// down and every parked request has been failed.
    Disconnected {
        /// The server the ended session was with.
        server: ServerEndpoint,
    },
    /// The session with `server` was lost (or a retry to re-make it failed)
    /// while the operator's intent to stay connected to it stands (ADR-0096,
    /// "A lost session is re-made"): rmule dials it again at `at`,
    /// through the one establishment. `attempt` counts from 1, at most
    /// `bound` when one is set.
    Reconnecting {
        /// The server the operator connected to.
        server: ServerEndpoint,
        /// Which attempt the next dial is.
        attempt: u32,
        /// The most attempts rmule makes
        /// ([`CoreConfig::server_reconnect_attempts`](crate::CoreConfig::server_reconnect_attempts));
        /// `None`, it keeps trying while the intent stands.
        bound: Option<u32>,
        /// The delay set for it, as of the scheduling.
        next_in: std::time::Duration,
        /// When it dials, on the monotonic clock: a front end subtracts its
        /// own `now` to count down.
        at: std::time::Instant,
        /// The delay has reached its ceiling: every later attempt waits the
        /// same.
        steady: bool,
    },
    /// rmule stopped trying to re-make the session with `server`, and why.
    /// Nothing more is dialed until the operator connects.
    ReconnectEnded {
        /// The server it was trying.
        server: ServerEndpoint,
        /// What ended the tries.
        reason: ReconnectEnd,
    },
}

/// Why rmule stopped re-making a lost session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconnectEnd {
    /// The operator disconnected.
    OperatorDisconnected,
    /// The operator connected to another server, which replaced the intent.
    Replaced,
    /// Every attempt failed; only with a bound set
    /// ([`CoreConfig::server_reconnect_attempts`](crate::CoreConfig::server_reconnect_attempts)).
    AttemptsSpent {
        /// How many attempts were made.
        attempts: u32,
    },
    /// The server is no longer in the list; only a listed server is dialed.
    Unlisted,
}

/// Why a connect produced no session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerConnectFailure {
    /// The server's IP is in the filter table: rmule never
    /// dialed, so nothing was learned about the server and its failure tally
    /// does not move.
    Filtered,
    /// The TCP dial did not come up: refused, unreachable, or timed out.
    /// aMule's `CServerConnect::ConnectionFailed`: the server's failure tally
    /// climbs by one, as it does for every failure below but [`Self::Filtered`].
    Unreachable,
    /// The server answered the login with a refusal (`OP_REJECT`).
    LoginRefused,
    /// The server closed the link before answering the login.
    ClosedBeforeAnswer,
    /// The TCP connection came up but the login was never answered inside
    /// [`CoreConfig::server_login_timeout`](crate::CoreConfig::server_login_timeout)
    /// — the eD2k session's own `CloseReason::LoginTimeout`, surfaced apart.
    /// A server that accepts and then says nothing is a
    /// different fault from one that refuses, and a serve activity that is
    /// already accepting peers must not look like a listener that never
    /// bound. The tally moves: silence is a failure to reach the server.
    LoginTimedOut,
}

/// Top-level event from the core actor: a per-activity event, or a
/// cross-activity fact. Thin wrapper so serve events are a new arm.
// CoreEvent is sent over a low-frequency mpsc channel; the size imbalance
// between Download(DownloadEvent) and the small cross-activity arms is
// intentional (mirrors CoreCommand), so boxing would add indirection for no
// measurable gain.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum CoreEvent {
    /// A download activity fact (ADR-0030).
    Download(DownloadEvent),
    /// A serve-side fact (ADR-0031): a file was shared, unshared, or a share
    /// command was refused.
    Serve(ServeEvent),
    /// A connected-server search activity fact (ADR-0034).
    Search(SearchEvent),
    /// A **Download Directory Scan** fact (ADR-0100).
    Scan(ScanEvent),
    /// A managed server list fact (ADR-0080).
    ServerList(ServerListEvent),
    /// A server-session lifecycle fact (ADR-0080 amendment).
    ServerConnection(ServerConnectionEvent),
    /// A Secure User Identification exchange completed under a *different*
    /// public key than the peer's stored **Secured Identity** (ADR-0041,
    /// eMule `IS_IDFAILED`): the claim is denied, the stored key is never
    /// overwritten, and the peer's unsecured accrual continues. Cross-activity
    /// — download- and serve-side verifications both report here.
    SecuredIdentityMismatch {
        /// The peer whose stored key the failed claim was checked against.
        user_hash: UserHash,
    },
    /// A command was refused for the current session/state (cross-activity).
    CommandRejected {
        /// Which precondition the command did not meet.
        reason: CoreCommandRejectReason,
    },
    /// **Peer Reach** took a road to a peer (ADR-0061): for a
    /// [`CoreCommand::ReachPeer`](crate::CoreCommand::ReachPeer) or a
    /// download's Low-ID candidate. Route 2 ([`PeerReachRoute::DirectUdp`]) is
    /// enacted by core (the `0x95` is already on the wire when this event
    /// fires), and so is route 4 for a download's Kad source, whose `0x52`
    /// [`Buddy`](PeerReachRoute::Buddy) reports; rung 1 has been handed to the
    /// NAT-T Front, which puts it on the wire; [`Direct`](PeerReachRoute::Direct)
    /// and [`Server`](PeerReachRoute::Server) report the verdict for the caller
    /// to enact (the dial / the `0x1C`). Cross-activity: the download worker, a
    /// LowID source-exchange candidate and the ADR-0057 LowID grant dial-back
    /// all ask the same selector, so they all report here.
    PeerReachRouted {
        /// The peer the route was chosen for.
        peer: rmule_primitives::PeerEndpoint,
        /// The chosen route, and for route 2 whether it could be enacted.
        route: PeerReachRoute,
    },
    /// A NAT-T **Tunnel** rose over a punched path (ADR-0091) and is now
    /// carrying an ordinary peer session. The one observable that says the
    /// whole ladder worked — rendezvous or introduction, hint, burst,
    /// transport — as opposed to a route merely chosen.
    NattTunnelRisen {
        /// The peer at the far end of the punched path.
        peer: rmule_primitives::PeerEndpoint,
        /// Which transport carried it.
        transport: rmule_net::natt::TunnelTransport,
        /// Whether rmule dialed it or accepted it — the dialect's asymmetry:
        /// the side that asked for the introduction dials.
        role: rmule_net::peer::PeerStreamRole,
    },
    /// The one client-UDP socket (ADR-0057) failed to bind at core start: the
    /// port asked for, and the OS's reason. Emitted exactly
    /// once, at start — there is no retry (ADR-0057 amendment, "stay down
    /// until restart"; a periodic re-bind would be restartability
    /// work, not this fact's) — so a consumer that logs every `CoreEvent`
    /// sees this line exactly once per session and never again.
    /// [`CoreCommandRejectReason::KadUnavailable`] carries the same two facts
    /// for whichever `EnableKad` a caller sends after this, so a consumer
    /// that missed the start event still learns why.
    ///
    /// Follows the `ServeEvent::ServingFailed { reason: Bind(io::ErrorKind) }`
    /// precedent: a bind failure is named, not merely logged. `None` of this
    /// ever fires for a core whose socket bound, including one that bound
    /// only one **Address Family** (ADR-0085) — a partial bind is not a total
    /// one, and Kad, the reask surface and NAT-T all still have a socket.
    ClientUdpBindFailed {
        /// The port core asked the OS for — `CoreSettings::udp_port`.
        port: u16,
        /// The OS's reason. When every selected **Address Family** refused
        /// the bind, `UdpFamilyPair::bind` (ADR-0085) picks a real kind
        /// rather than a catch-all — the shared kind when every refusal
        /// agrees, else the IPv4 half's (`refused_every_family`'s rule).
        kind: std::io::ErrorKind,
    },
    /// A socket role's **Family Pair** came up, but without a family it
    /// selected — so the role runs on the other family alone and
    /// whatever rode the missing one is off until restart.
    ///
    /// The half-bound sibling of [`Self::ClientUdpBindFailed`]: that one is a
    /// bind that produced no socket, this one a bind that produced half the
    /// sockets asked for. ADR-0085's rule — one family refusing must not take
    /// the other down — is why this is not a failure; a client-UDP pair on
    /// `::` alone, with Kad and the NAT-T punch path dead and every other
    /// surface reading "bound", is why it is still said out loud.
    ///
    /// Emitted once per role, at the bind, and never again: there is no
    /// re-bind (ADR-0057 amendment). A family that was never *selected* never
    /// raises this — an operator who configured one family has lost nothing.
    /// The same fact rides `DiagnosticsSnapshot::half_bound_pairs` for a
    /// consumer that missed the event, and
    /// [`CoreCommandRejectReason::KadUnavailable`] for an `EnableKad` sent
    /// afterward.
    SocketBoundWithoutFamily {
        /// The role, the missing family, the OS's reason — and, through
        /// `HalfBound::forfeits`, what that costs: codes a front end words
        /// (the TUI does); `HalfBound`'s `Display` is the CLI's and the
        /// logs' line.
        half_bound: rmule_net::family::HalfBound,
    },
    /// A peer's hello was refused under a named code (ADR-0050):
    /// today, a hello that counts a tag it never wrote, which
    /// both references refuse as well. Cross-activity — a dialed source's
    /// answer and an accepted peer's opening both report here — and counted in
    /// [`SessionCounters::peer_hellos_refused_total`](crate::diagnostics::SessionCounters::peer_hellos_refused_total).
    /// Carries no peer address: what the peer said of itself (its name and
    /// mod, as it wrote them) is the whole identification.
    PeerHelloRefused {
        /// The code, and the name and mod the peer wrote before the frame
        /// went wrong.
        refusal: rmule_peer::HelloRefusal,
    },
    /// Diagnostic echo of the current [`DiagnosticsSnapshot`](crate::diagnostics::DiagnosticsSnapshot) in response to
    /// [`CoreCommand::DumpDiagnostics`](crate::CoreCommand::DumpDiagnostics) (ADR-0028). Domain consumers may
    /// ignore this variant; it is intended for hang investigation by tools
    /// and tests. Cross-activity.
    DiagnosticsSnapshot {
        /// The levels as they read at the moment the dump was served.
        snapshot: crate::diagnostics::DiagnosticsSnapshot,
    },
    /// The **File History** as the store holds it, answering
    /// [`CoreCommand::DumpFileHistory`](crate::CoreCommand::DumpFileHistory)
    /// (ADR-0100). Cross-activity: it reads the registry and the download
    /// store together.
    FileHistory {
        /// The registry's entries and the cancelled downloads.
        history: crate::file_history::FileHistory,
    },
    /// The Kad activity was retired (ADR-0093) — by `DisableKad`, by its
    /// pump's own death or at quit: its Kad Presence lease is
    /// dropped, so every "is Kad running" reader reads "not running" from
    /// here on.
    /// Cross-activity, like [`Self::DiagnosticsSnapshot`]: nothing else owns
    /// the Kad node's whole-session liveness.
    KadStopped {
        /// Why it ended.
        reason: KadStopReason,
    },
    /// Quit (ADR-0093) has begun `step` — one event per step that has
    /// something to stop, in quit order, so a front end can name the step in
    /// progress without issuing the stops itself. Only a caller
    /// draining [`Core::quit`](crate::Core::quit)'s stream sees these.
    Quitting {
        /// The step now running.
        step: QuitStep,
    },
    /// A step of a login to `server` between its session edges (ADR-0075,
    /// Run Log): evidence for a reachability diagnosis, never a level.
    ServerLogin {
        /// The server being logged in to.
        server: ServerEndpoint,
        /// The step.
        step: LoginStep,
    },
    /// A dial to the own recruited buddy did not hold a link (ADR-0075, Run
    /// Log): the buddy's state stays where it was, so this is the only trace
    /// of why.
    BuddyDialFailed {
        /// The buddy's TCP endpoint, the one the dial aimed at.
        buddy: Ipv4Endpoint,
        /// Why.
        cause: BuddyDialFailure,
    },
    /// The **Obfuscation Policy** this core starts under (ADR-0046): our own
    /// posture, stated once before anything is dialed, so the Run Log says
    /// what every later crypt decision read.
    ObfuscationPolicyAtStart {
        /// The policy; `None` for none.
        policy: Option<crate::ObfuscationPolicy>,
    },
    /// The operator changed the **Obfuscation Policy** live (ADR-0046): from
    /// here on every surface decides under it, while a connection that
    /// already negotiated keeps what it agreed.
    ObfuscationPolicyChanged {
        /// The policy now in force; `None` for none.
        policy: Option<crate::ObfuscationPolicy>,
    },
    /// A Kad helper's connect-back came after its firewall-check window
    /// closed, within the Awaited Testers' memory of it (ADR-0075, Run Log):
    /// its window lapsed or was dropped, so the test no longer counts. Names
    /// no server, so it is not a [`LoginStep`].
    KadHelperTestLate {
        /// The helper's address — a stranger peer's, so the full level's
        /// alone.
        helper: std::net::Ipv4Addr,
        /// How long after its window closed it came.
        late_by: std::time::Duration,
        /// What became of it.
        admission: PortTestLateAdmission,
    },
}

impl From<DownloadEvent> for CoreEvent {
    fn from(event: DownloadEvent) -> Self {
        Self::Download(event)
    }
}

impl From<ServeEvent> for CoreEvent {
    fn from(event: ServeEvent) -> Self {
        Self::Serve(event)
    }
}

impl From<SearchEvent> for CoreEvent {
    fn from(event: SearchEvent) -> Self {
        Self::Search(event)
    }
}

impl From<ServerListEvent> for CoreEvent {
    fn from(event: ServerListEvent) -> Self {
        Self::ServerList(event)
    }
}
