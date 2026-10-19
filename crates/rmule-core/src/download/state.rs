//! The synchronous, sans-I/O core of the multi-peer download runner.
//!
//! [`DownloadState`] owns every channel-free scheduling decision for one
//! in-flight download: which part a peer works, how cross-peer blocks
//! assemble (ADR-0029), when a raced part completes and clears its losers
//! (ADR-0026), which candidate backfills a retired worker (ADR-0030), and
//! when a source's ask or reask falls due. It never touches a socket, the
//! store, or an `mpsc` channel, and reads no clock: time arrives as the `now`
//! every entry takes, [`DownloadState::on_tick`] runs what has fallen due, and
//! [`DownloadState::next_wake`] names when the runner should call it next (ADR-0026).
//! Each entry point returns an ordered `Vec<`[`Decision`]`>` that the async
//! runner *enacts*. Persistence is a fallible effect, so it round-trips:
//! the state emits [`Decision::PersistPart`] and resumes on
//! [`DownloadState::on_persist_result`].
//!
//! This split is what makes the racing / mid-part-resume / retire-all /
//! backfill behaviours assertable as plain `Vec<Decision>` values instead of
//! only through a live Tokio actor with `timeout`-polled events.
//!
//! The runner ([`runner`](super::runner)) drives this core: it feeds worker
//! events in and enacts the returned decisions against the live runtime.

mod aich;
mod candidate;
mod candidates;
mod capability;
mod direct_ipv6;
mod remote_queued;
mod seeds;
mod sightings;
mod slot_ask;
mod slots;
#[cfg(test)]
mod tests;
mod tick;
mod worker_event;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::{Duration, Instant};

use rmule_peer::PartBitmap;
use rmule_primitives::{
    AichRootHash, ClientId, FileHash, Ipv4Endpoint, PartHash, PartHashSet, PeerCrypt, PeerEndpoint,
    UserHash,
};

pub(crate) use candidate::LowIdCandidate;
pub(crate) use capability::CallbackCapability;
pub(super) use direct_ipv6::LowIdRoute;
use seeds::SeedDials;
pub(crate) use sightings::{Channel, Taken, Tally};

use crate::DownloadFailure;
use crate::adapters::{CallbackKey, PeerWorkerCommand};
use crate::assembly::PartAssembly;
use crate::callback::CallbackSilence;
use crate::delivery_rate::DeliveryRate;
use crate::diagnostics::{PartState, WorkerPhase, WorkerSlot};
use crate::dialable::DialPosition;
use crate::download::connection_budget::BudgetSeat;
use crate::download::queue_standings::StandingSeat;
use crate::download::source_book::SourceBook;
use crate::download::source_seeds::SeedLedger;
use crate::hashing::ResolvedHashSet;
use crate::scheduler::{DownloadScheduler, PartOrder};
use crate::service::{DownloadEvent, DownloadId, PartReleaseReason};

/// One effect the async runner must enact, drained in order from a
/// [`DownloadState`] entry point. Everything that touches I/O, a clock, a
/// channel, or the store is data here, not an inline `await`.
#[derive(Clone, Debug)]
pub(crate) enum Decision {
    /// Forward a domain event to the download's consumer.
    Emit(DownloadEvent),
    /// Update a worker's diagnostics row (ADR-0028). Clock-free: the state
    /// names the phase; the runner stamps it.
    Phase {
        slot: WorkerSlot,
        phase: WorkerPhase,
    },
    /// Name the client a worker's peer runs on its diagnostics row, read
    /// off its hello.
    Identify {
        slot: WorkerSlot,
        software: rmule_peer::ClientSoftware,
    },
    /// Send a command to the live worker channel for `peer`.
    Send {
        peer: PeerEndpoint,
        command: PeerWorkerCommand,
    },
    /// End the live worker on `peer`: the brain released it. Every
    /// retirement — whatever its reason — ends its worker through this one
    /// decision (ADR-0090 "Source ownership"); the runner sends it
    /// `PeerWorkerCommand::Shutdown { cancel }`. `cancel` is true for a
    /// source that holds nothing we need, so a slot it granted is given back
    /// with `OP_CANCELTRANSFER` (ADR-0056, ADR-0112).
    EndWorker { peer: PeerEndpoint, cancel: bool },
    /// Credit `user_hash` for serving `bytes`; the runner holds the
    /// ledger lock.
    RecordCredit { user_hash: UserHash, bytes: u64 },
    /// Bind `public_key` as `user_hash`'s **Secured Identity** (ADR-0041).
    /// The runner (ledger-holder) performs the store's atomic compare-and-set;
    /// a `Mismatch` denies the claim (theft fact), never overwriting the key.
    BindIdentity {
        user_hash: UserHash,
        public_key: Vec<u8>,
    },
    /// Verify and persist the assembled bytes of `part_index` (contributed
    /// by `peer`). A fallible effect: the runner reports the outcome back
    /// through [`DownloadState::on_persist_result`].
    PersistPart {
        part_index: u32,
        peer: PeerEndpoint,
        offset: u64,
        bytes: Vec<u8>,
    },
    /// Persist a newly-adopted provisional peer hash set (ADR-0027 authority).
    PersistProvisionalHashes(Vec<PartHash>),
    /// Persist that this download distrusts `user_hash`: it served this file
    /// bad data (ADR-0090 "Source ownership").
    DistrustPeer { user_hash: UserHash },
    /// Backfill a retired worker: connect `peer` into the freed `slot`
    /// (ADR-0030).
    Spawn {
        peer: PeerEndpoint,
        slot: WorkerSlot,
        /// Whether the connection carries a source ask (ADR-0108): the
        /// peer's ask facts, read at the decision.
        want_sources: bool,
    },
    /// Ask the connected server to call back a Low-ID source it assigned
    /// (ADR-0039). The runner enacts it via the server session and files the
    /// server-relayed road under `{ server, low_id }` — the candidate's key; a
    /// `None` server is resolved to the live connected server, a runtime fact
    /// the brain does not hold. The called-back peer dials in and is adopted
    /// by the accept-router. The held slot's deadline sits on the candidate's
    /// record (ADR-0090).
    RequestCallback {
        low_id: ClientId,
        /// The server that assigned `low_id`, when the brain knew it: ours.
        server: Option<Ipv4Endpoint>,
        /// Whether the connection carries a source ask (ADR-0108): the
        /// peer's ask facts, read at the decision.
        want_sources: bool,
    },
    /// Ask a Low-ID **global** source's own `source_server` — over UDP, with no
    /// TCP session — to relay a callback (ADR-0051, ADR-0039 generalized
    /// per-server). The runner enacts it via the discovery UDP socket and
    /// files the server-relayed road under `{ server: Some(source_server), low_id }`;
    /// the called-back peer dials in (`connected_server = source_server`) and is
    /// adopted. The held slot's deadline sits on the candidate's record.
    RequestGlobalCallback {
        low_id: ClientId,
        source_server: Ipv4Endpoint,
        /// Whether the connection carries a source ask (ADR-0108): the
        /// peer's ask facts, read at the decision.
        want_sources: bool,
    },
    /// Ask `candidate`'s Kad buddy to relay a callback (ADR-0061 route 4).
    /// The runner registers a **dial-back** claim under the
    /// candidate's User Hash — the one name the target's hello will report,
    /// since a Kad candidate's [`CallbackKey`] is not an id any hello carries
    /// — and asks the core actor to emit the `0x52`. The held slot's deadline
    /// sits on the candidate's record.
    RequestBuddyCallback {
        candidate: LowIdCandidate,
        /// Whether the connection carries a source ask (ADR-0108): the
        /// peer's ask facts, read at the decision.
        want_sources: bool,
    },
    /// Ask `candidate`'s Kad buddy once more, under the **other spelling** of
    /// its `TAG_BUDDYHASH`: `candidate.buddy` already names the
    /// fallback ID. Enacted exactly as [`Self::RequestBuddyCallback`] — the
    /// same dial-back claim, the same `0x52` to the same buddy, file and port —
    /// and counted apart, because it is the one leg built on a source reading
    /// (eMule 0.70b / eMuleAI `GetData()`) rather than a capture.
    RequestFallbackBuddyCallback {
        candidate: LowIdCandidate,
        /// Whether the connection carries a source ask (ADR-0108): the
        /// peer's ask facts, read at the decision.
        want_sources: bool,
    },
    /// Ask `candidate` itself for a direct-UDP callback (ADR-0061 route 2):
    /// the `0x95` to the Kad UDP endpoint its own row carried —
    /// no server and no buddy involved. The runner claims the same
    /// **dial-back** entry a buddy callback claims, keyed by the candidate's
    /// User Hash, because a Kad candidate's [`CallbackKey`] is a synthetic id
    /// (its own address read as one) that no hello will ever report — and
    /// asks the core actor to emit the `0x95`. The held slot's deadline sits on
    /// the candidate's record.
    RequestDirectUdpCallback {
        candidate: LowIdCandidate,
        /// Whether the connection carries a source ask (ADR-0108): the
        /// peer's ask facts, read at the decision.
        want_sources: bool,
    },
    /// Ask the one ADR-0061 selector to reach `candidate` by a punch (ADR-0091
    /// rung 1). The slot stays held, and now waits on the attempt: the 30 s
    /// slot release does not end a traversal still running — its
    /// retirement, its Tunnel, or the traversal bound set on the candidate's
    /// record with it does. NAT traversal is an attempt *beside* whatever else is
    /// outstanding, so whichever connection arrives first wins.
    ///
    /// Raised on either of the candidate's two roads, and `silence` is which:
    /// a callback that has said nothing for twelve seconds, or a candidate no
    /// callback was ever possible for — the LowID↔LowID pair, which asks now.
    FallToNatTraversal {
        /// The candidate's facts, as the channels that named it gave them.
        candidate: LowIdCandidate,
        /// What was measured before asking (ADR-0091: the pair decides the
        /// road). The selector reads it to refuse falling back from something
        /// that was never a callback.
        silence: CallbackSilence,
        /// Whether the connection carries a source ask (ADR-0108): the
        /// peer's ask facts, read at the decision.
        want_sources: bool,
    },
    /// Retract `key`'s **Pending Tunnel Claim** and leave everything else
    /// standing (ADR-0091). The punch road is over for this
    /// callback — its **Traversal Attempt** retired — but the callback itself
    /// is not: the server may still relay it, so its slot, its 30 s deadline
    /// and its routing-index entry are untouched. Distinct from
    /// [`Decision::EndCallback`] for exactly that reason; ending the whole
    /// callback here would forfeit a slot the peer may still dial into.
    RetractTunnelClaim { key: CallbackKey },
    /// Release `key`'s **Awaited Inbound** registration — the callback is over
    /// (adopted, lapsed or merged away), and its deadlines went with its
    /// record's road. Idempotent by design: on adoption the accept-router
    /// already spent the registration's roads and only the handle remains.
    /// Resolving a connected-server `None` to the live server it was filed
    /// under is the runner's concern.
    EndCallback { key: CallbackKey },
    /// Send `ping`, a source's `OP_REASKFILEPING` (`0x90`) or the
    /// `OP_REASKCALLBACKUDP` (`0x94`) its buddy relays, out the shared
    /// client-UDP socket (ADR-0057). The brain framed it for the source
    /// standing at `peer` and set its one-in-flight latch; the runner claims
    /// `answered_from` in the **Reask Routes** first (ADR-0107) and, when
    /// another download's ping holds it, hands it back through
    /// [`DownloadState::on_ping_held`].
    SendReaskPing {
        /// The endpoint the source's record stands at.
        peer: PeerEndpoint,
        /// The datagram, its client-UDP destination and crypt target.
        ping: crate::client_udp::ClientUdpSend,
        /// The source's client-UDP endpoint its answer comes from: the
        /// ping's destination, or past a buddy, the source's own.
        answered_from: PeerEndpoint,
    },
    /// The worker at `peer` holds a granted slot: call every other
    /// download's record waiting on the peer's **Queue Standing** to this
    /// link, where each waits as a Link Rider and the swap rule hands the link
    /// on (ADR-0107).
    CallStandingWaiters {
        /// The granted worker's endpoint.
        peer: PeerEndpoint,
    },
    /// Every part is verified — assemble and finalize the file.
    Finalize,
    /// The download cannot proceed; fail it with `reason`.
    Fail(DownloadFailure),
}

/// What the brain knows about the content before any peer speaks: the file's
/// size, the verification authority in force (ADR-0027), the link's own part
/// hash set, the trusted AICH root when the link carried one (ADR-0038), and
/// the parts an earlier run already verified on disk.
pub(crate) struct ContentFacts {
    /// The file's ED2K hash — what a peer-supplied part hash set must hash to.
    pub(crate) file_hash: FileHash,
    pub(crate) file_size: u64,
    /// The link's own part hash set, if the ed2k link carried one; kept so a
    /// peer-supplied hash set can be re-resolved against it (ADR-0027).
    pub(crate) link_part_hash_set: Option<PartHashSet>,
    /// The verification authority in force. The link-vs-persisted-provisional
    /// read is an async store effect, so the caller resolves it and injects it.
    pub(crate) resolved: ResolvedHashSet,
    /// The trusted AICH master root from the link `h=`; `None` leaves the
    /// root to the trusted-set vote.
    pub(crate) trusted_aich_root: Option<AichRootHash>,
    /// Parts an earlier run already verified; they are never re-fetched.
    pub(crate) verified_parts: Vec<u32>,
    /// How its parts are ranked: with the Preview Band and the Streaming
    /// Window when it is Streaming Priority (`DownloadMetadata::
    /// is_streaming_priority`, ADR-0112 §5).
    pub(crate) order: PartOrder,
}

/// How a Low-ID candidate is to be reached — the three callback roads and the
/// punch ADR-0091 leaves open, and the vocabulary of the admission rule
/// ([`LowIdRoute::of`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LowIdRoad {
    /// Ask the candidate itself for a direct-UDP callback (`0x95`, ADR-0061 route 2):
    /// the row's own type-6 verdict
    /// ([`LowIdCandidate::direct_udp_callback`]) plus a Kad UDP
    /// endpoint on its row — the road needs neither a server nor a buddy, and
    /// is the one aMule's `TryToConnect` tries before either
    /// (`BaseClient.cpp:2043`, ahead of the server relay at `:2114`). **Not**
    /// bit 3 alone: a type-3/5 buddy row can state bit 3 too, but aMule keeps
    /// the observed IP for the `0x95` only on a type-6 row
    /// (`DownloadQueue.cpp:1797`), so such a row falls to
    /// [`Self::BuddyCallback`] instead. Only a Kad source row carries a Kad
    /// UDP endpoint today, so this road opens for a Kad-sourced candidate.
    /// The same twelve-second punch may ride beside it when the candidate's
    /// facts admit a coordinator.
    DirectUdp,
    /// Ask a server to relay a callback and hold the slot until the target
    /// dials in (ADR-0039 / ADR-0051). A punch may still ride beside it, twelve
    /// seconds later, if the candidate's facts admit a coordinator.
    Callback,
    /// Ask the candidate's Kad buddy to relay a callback (`0x52`, ADR-0061 route 4)
    /// and hold the slot until the target dials in. The
    /// Kad-row sibling of [`Self::Callback`]: no server can relay for a Kad
    /// row, but its buddy can, and aMule takes this road for every buddy row
    /// with no connect-options bit consulted. The same twelve-second punch
    /// may ride beside it when the candidate's facts admit a coordinator. A
    /// buddy named by ID alone is reached by a **Callback Walk**,
    /// and a walk that reaches nobody turns this road into [`Self::Punch`].
    BuddyCallback,
    /// Punch, now (ADR-0091 rung 1). We cannot be dialed back, so
    /// no callback is asked for and there is no silence to measure — the only
    /// clock on this road is the slot-release deadline the punch runs under.
    Punch,
}

impl LowIdRoad {
    /// The **admission rule** for a Low-ID candidate, as ADR-0091 settled and
    /// ordered it: *a callback, or a coordinator* — and
    /// among callbacks, the candidate's own direct-UDP invitation first,
    /// matching aMule's `TryToConnect`.
    ///
    /// `capability` is our half — aMule's `CanDoCallback`, asked of this
    /// candidate ([`CallbackCapability`]) — and
    /// [`NattFacts::admits_coordinator`](crate::callback::NattFacts::admits_coordinator)
    /// is the candidate's (on our server, or NAT-T plus a buddy). Whether a
    /// coordinator is actually *available* — our client-UDP bind, the server's
    /// `0xF9` keepalive, Kad — is the ADR-0061 selector's to judge against our
    /// live position, which no caller of this rule holds; a candidate admitted
    /// here whose punch turns out unroutable holds its slot until the
    /// slot-release deadline, exactly as a callback nobody answers does.
    ///
    /// `None` is the honest starvation a download fails `NoUsableSources` on:
    /// an ADR-0051 global source with no buddy and no NAT-T bit, that we cannot
    /// be called back for either.
    ///
    /// Stated here rather than in [`DownloadState`] because the runner asks it
    /// too, of the lookup snapshot, before any brain exists.
    pub(super) fn of(capability: &CallbackCapability, candidate: &LowIdCandidate) -> Option<Self> {
        // aMule asks `CanDoCallback` once, ahead of every callback road
        // (`TryToConnect`, `BaseClient.cpp:1991-2004`); a `false` is
        // `DS_LOWTOLOWIP` and only the punch is left.
        let callable = capability.admits(candidate);
        // The candidate's own direct-UDP callback goes first, exactly as
        // aMule tries it before the server relay: the row's own
        // type-6 verdict plus a Kad UDP endpoint — never bit 3 alone, because
        // a type-3/5 buddy row can state it too and aMule still relays
        // through the buddy for one. Only a Kad source row
        // carries a Kad UDP endpoint today, so a server-sourced candidate
        // (`kad_udp` always `None`) never takes this branch and falls through
        // to the next one unchanged.
        if callable
            && candidate.direct_udp_callback
            && candidate.kad_udp.is_some()
            && candidate.user_hash.is_some()
        {
            Some(Self::DirectUdp)
        // A Kad-row candidate has no *server* callback however capable we are:
        // it is in no server's namespace (`LowIdCandidate::from_kad`).
        // Its buddy relays one instead — when the dial-back can be matched to
        // this download, which only the target's User Hash can do.
        } else if capability.server_relays() && !candidate.from_kad {
            Some(Self::Callback)
        } else if callable && candidate.buddy.is_some() && candidate.user_hash.is_some() {
            Some(Self::BuddyCallback)
        } else if candidate
            .natt_facts(capability.server())
            .admits_coordinator()
        {
            Some(Self::Punch)
        } else {
            None
        }
    }
}

/// What one run starts with besides its sources, which all arrive as
/// sightings ([`DownloadState::on_sightings`]).
pub(crate) struct StartingFacts {
    /// The peers this download distrusts, as its durable record holds them
    /// A source whose record names one of these is not pooled.
    pub(crate) distrusted: HashSet<UserHash>,
    /// How many **Source Seeds** the last run wrote that were under a day old
    /// (ADR-0109): the seeds this run dials are reported against it.
    pub(crate) seeds_written: usize,
}

/// What rmule's own network position lets this run attempt — the gates that turn
/// on us rather than on any source.
#[derive(Clone, Copy)]
pub(crate) struct SourcingPosture {
    /// Our half of the **Low-ID Admission** at start (aMule's `CanDoCallback`);
    /// the runner hands the brain a fresh sample whenever the live
    /// facts move ([`DownloadState::on_callback_capability`]).
    pub(crate) callback_capability: CallbackCapability,
    /// Our half of the family question at start (ADR-0087): whether we hold a
    /// Known IPv6 to dial a Low-ID candidate's IPv6 half from — rung 0 of the
    /// route tree. Re-sampled like the capability
    /// ([`DownloadState::on_dial_position`]).
    pub(crate) dial: DialPosition,
    /// Any background source-discovery channel armed: server-UDP global sweep
    /// (ADR-0051) and/or Kad (ADR-0043). Starvation then waits, never fails.
    pub(crate) discovery_active: bool,
    /// A client-UDP socket is bound for the run (ADR-0057): our UDP advert is
    /// live, so a remote-queued source may be pinged rather than only
    /// re-asked over TCP.
    pub(crate) client_udp: bool,
}

/// The sans-I/O scheduling brain for one download. See the module docs.
pub(crate) struct DownloadState {
    download_id: DownloadId,
    file_hash: FileHash,
    file_size: u64,
    scheduler: DownloadScheduler,
    /// One shared contiguous-prefix buffer per in-flight part (ADR-0029),
    /// keyed by part index. Blocks from every contributing peer feed the
    /// same buffer, so a mid-part drop preserves the prefix.
    assembly: HashMap<u32, PartAssembly>,
    /// Assemblies removed from `assembly` when their `PersistPart` was
    /// emitted, held until `on_persist_result` so a verification failure can
    /// retire every contributor (ADR-0029's retire-all).
    pending_persist: HashMap<u32, PartAssembly>,
    /// Completed-but-MD4-failed assemblies awaiting an AICH recovery answer
    /// (ADR-0038). Held here (with their per-block provenance) between the
    /// `OP_AICHREQUEST` and `on_aich_answer`, where the corruption is localized.
    awaiting_recovery: HashMap<u32, PartAssembly>,
    /// Peer → the diagnostics slot its worker occupies. The live command
    /// channel for each peer stays in the runner, whether it has completed its
    /// handshake in the **Source Book**; the brain owns only the slot number.
    worker_slots: HashMap<PeerEndpoint, WorkerSlot>,
    /// Each live worker's **Delivery Rate**, from its block arrivals: what a
    /// Tail Race reads (ADR-0026 "Bounded racing").
    delivery: HashMap<PeerEndpoint, DeliveryRate>,
    /// Where each worker's slot ask stands at its uploader, and the download's
    /// one hash-set ask in flight (ADR-0026).
    slot_asks: slot_ask::SlotAsks,
    /// The link's own part hash set, if the ed2k link carried one. Held so a
    /// peer-supplied hash set can be re-resolved against it (ADR-0027).
    link_part_hash_set: Option<PartHashSet>,
    /// The verification authority in force (ADR-0027), resolved up front and
    /// possibly upgraded by a peer hash set.
    resolved: ResolvedHashSet,
    /// The trusted AICH master root for this download (ADR-0038). Set up front
    /// from the link `h=`, or committed by the trusted-set vote
    /// (`aich_root_votes`) when the link carried none. Its presence enables
    /// block-level recovery on an MD4 failure; `None` keeps the failure path at
    /// ADR-0029's retire-all.
    trusted_aich_root: Option<AichRootHash>,
    /// Trusted-set tally for a rootless download: each proposed AICH master root
    /// → the set of distinct masked peer IPs that proposed it (ADR-0038, eMule
    /// secure-AICH). A root is committed to `trusted_aich_root` once it clears
    /// the agreement thresholds. Empty (and unused) when the link carried `h=`.
    aich_root_votes: HashMap<AichRootHash, HashSet<aich::AichVoter>>,
    retired_peers: u32,
    /// The download's sources, one record per source, and who owns each
    /// (ADR-0090). Every pooling seam, every slot fill and every worker's end
    /// asks it; the brain keeps what the book does not — slot numbers, the
    /// callbacks' deadlines and the part scheduler.
    sources: SourceBook,
    /// Diagnostics slot numbers a retired worker or road freed; a new one
    /// takes the lowest of them before a number past every one in use, so the
    /// rows stay as many as the most held at once (ADR-0116).
    free_slots: BTreeSet<usize>,
    /// This run's seat in the node's **Connection Budget** (ADR-0116): every
    /// road a fill opens is admitted by it first; a grant never asks it.
    budget: BudgetSeat,
    /// When a fill the budget refused fills again: the Dial Window's turn.
    budget_wake: Option<Instant>,
    /// This run's seat in the node's **Queue Standings** (ADR-0107): which of
    /// the downloads queued at a peer re-asks it, and the peer's clock.
    standings: StandingSeat,
    /// The diagnostics slot every callback in flight holds (ADR-0039 /
    /// ADR-0051) — connected-server (`CallbackKey.server` = `None`) and
    /// per-server global alike — until the inbound peer is adopted
    /// ([`Self::on_callback_connected`]) or its road ends. How far the road has
    /// run and its deadlines ride the candidate's **Source Book** record; the
    /// runner's **Awaited Inbound** registrations key on the same
    /// [`CallbackKey`].
    callback_slots: HashMap<CallbackKey, WorkerSlot>,
    /// Whether, and for whom, rmule can be called back — the latest sample the
    /// runner handed in. Where it admits nobody, no callback is
    /// ever requested — every one of them asks the target to dial a node
    /// nothing can reach — and a Low-ID candidate is admitted only by the
    /// coordinator half of the rule (ADR-0091 rung 1: the LowID↔LowID pair
    /// punches instead of dropping).
    callback_capability: CallbackCapability,
    /// Our Known IPv6, if any — the latest sample the runner handed in
    /// (ADR-0087). Rung 0 of a Low-ID candidate's route reads it.
    dial: DialPosition,
    /// How long a requested callback holds its slot before it lapses (ADR-0039,
    /// `CoreConfig::callback_timeout`): set on the road's record from the
    /// instant the road opens.
    callback_timeout: Duration,
    /// Whether any background source-discovery channel is armed for this
    /// download: the server-UDP global sweep (ADR-0051) and/or Kad (ADR-0043).
    /// When true, "no usable source right now" is a *wait* (a discovery
    /// channel may backfill), not a terminal failure — so
    /// `no_usable_candidate` never reports true.
    discovery_active: bool,
    /// Who earned which **Source Seeds** class this run (ADR-0109), fed from
    /// the **Source Book**'s outcomes.
    seeds: SeedLedger,
    /// The seeds' dials not yet reported, `None` once reported or when the
    /// run had no seeds.
    seed_dials: Option<SeedDials>,
    /// Whether [`Self::start`] has run: until then sightings only pool, so the
    /// run's snapshot is in the book before its first slot is filled.
    started: bool,
    /// A client-UDP socket is bound: every reask ping's first gate (ADR-0057).
    our_udp_enabled: bool,
    /// The UDP version our hello advertised — what a source read when it
    /// decided whether to ride its part status in the `0x91` reply, so the
    /// reply is read by it (aMule writes its status only to a UDPv4 waiter,
    /// stock 2.3.3 `ClientUDPSocket.cpp:213-219`). Read from the registry
    /// value every hello states, never passed in.
    our_udp_version: u8,
}

impl DownloadState {
    /// Build the scheduling state from what the run knows up front — the
    /// content, the candidate sources and rmule's own sourcing posture — plus
    /// the slot economy: the run's seat in the node's **Connection Budget**,
    /// and how long a callback holds a slot before it lapses.
    pub(crate) fn new(
        download_id: DownloadId,
        content: ContentFacts,
        facts: StartingFacts,
        posture: SourcingPosture,
        callback_timeout: Duration,
        budget: BudgetSeat,
    ) -> Self {
        let ContentFacts {
            file_hash,
            file_size,
            link_part_hash_set,
            resolved,
            trusted_aich_root,
            verified_parts,
            order,
        } = content;
        let StartingFacts {
            distrusted,
            seeds_written,
        } = facts;
        let mut sources = SourceBook::new(distrusted, rmule_primitives::part_count(file_size));
        sources.logged_into(posture.callback_capability.server());
        let seeds = SeedLedger::default();
        let our_udp_version = if posture.client_udp {
            rmule_primitives::Capabilities::shipped(rmule_primitives::CryptStance::disabled())
                .peer_udp_version()
        } else {
            0
        };
        Self {
            download_id,
            file_hash,
            file_size,
            scheduler: DownloadScheduler::new(file_size, verified_parts, order),
            assembly: HashMap::new(),
            pending_persist: HashMap::new(),
            awaiting_recovery: HashMap::new(),
            worker_slots: HashMap::new(),
            delivery: HashMap::new(),
            slot_asks: slot_ask::SlotAsks::default(),
            link_part_hash_set,
            resolved,
            trusted_aich_root,
            aich_root_votes: HashMap::new(),
            retired_peers: 0,
            sources,
            free_slots: BTreeSet::new(),
            budget,
            budget_wake: None,
            standings: StandingSeat::alone(download_id),
            callback_slots: HashMap::new(),
            callback_capability: posture.callback_capability,
            dial: posture.dial,
            callback_timeout,
            discovery_active: posture.discovery_active,
            seeds,
            seed_dials: SeedDials::new(seeds_written),
            started: false,
            our_udp_enabled: posture.client_udp,
            our_udp_version,
        }
    }

    /// Seat the run in the node's shared **Queue Standings** (ADR-0107) rather
    /// than in a registry of its own.
    #[must_use]
    pub(crate) fn with_standings(mut self, seat: StandingSeat) -> Self {
        self.standings = seat;
        self
    }

    /// Spawn the initial fleet of workers from the candidate pool, as the
    /// **Connection Budget** admits them (ADR-0116). The runner enacts each [`Decision::Spawn`] by
    /// putting that peer on the wire; the worker asks its slot on its probe's
    /// answer and is handed its first part at the grant (ADR-0030, ADR-0026).
    pub(crate) fn start(&mut self, now: Instant) -> Vec<Decision> {
        self.started = true;
        self.sources.turn_spent(now);
        let _ = self
            .sources
            .purge(now, &self.callback_capability, self.dial);
        let mut out = Vec::new();
        self.fill(now, &mut out);
        self.settle_seed_dials(&mut out);
        out
    }

    /// No source we can still reach: nothing the **Source Book** holds can
    /// reach a slot (ADR-0039 / ADR-0091), and no discovery channel is armed —
    /// when one is (ADR-0051), a future sweep may backfill, so the download
    /// waits rather than being *out* of candidates.
    pub(crate) fn no_usable_candidate(&self) -> bool {
        self.sources.starved(&self.callback_capability, self.dial) && !self.discovery_active
    }

    /// ADR-0026's terminal condition (ADR-0030): nothing holds a slot,
    /// nothing can reach one, and the file is not complete.
    fn out_of_sources(&self) -> bool {
        self.sources.slots_in_use() == 0
            && self.no_usable_candidate()
            && !self.scheduler.is_complete()
    }

    /// The crypt side `peer` stated — its stance and User Hash — by the
    /// ADR-0049 precedence: the peer's own hello, else its record
    /// — the server-lookup reply (`0x44`, ADR-0046), a source-exchange answer
    /// (ADR-0042) or a Kad row's `TAG_ENCRYPTION`, or, for a rung-0 dial, the
    /// Low-ID candidate it belongs to ([`LowIdCandidate::peer_crypt`])
    /// — else [`PeerCrypt::unknown`]. The runner hands it to the
    /// worker's brief; the dial meets it with our policy (ADR-0049).
    pub(crate) fn peer_crypt(&self, peer: PeerEndpoint) -> PeerCrypt {
        self.sources.peer_crypt(peer)
    }

    /// Our current availability for the file as aMule's `WritePartStatus` writes
    /// it ([`PartBitmap::downloader`]) — the parts we have verified — for a
    /// source-reask ping's body (ADR-0057: rides the `0x90` when the source's
    /// UDP version is `> 3`) and a new worker's connect-time name ask,
    /// telling the uploader which parts we still need.
    ///
    /// A part verified while no whole part hash set was held is left out until
    /// one is: it is outside the Verified Range, which the serve side reads
    /// (ADR-0113 rule 2), and aMule never holds such a part. A file of one part
    /// has no set; its file hash proves its part.
    pub(crate) fn our_part_status(&self) -> PartBitmap {
        let set_held = match PartHashSet::expected_hash_count(self.file_size) {
            Ok(0) => true,
            Ok(expected) => self.resolved.hashes.len() == expected,
            Err(_) => false,
        };
        PartBitmap::downloader(self.file_size, |part| {
            set_held && self.scheduler.is_part_verified(part.value())
        })
    }

    /// The pool a source-exchange answer for this file is drawn from while it
    /// downloads (ADR-0113): the sources we download from or wait at that are
    /// not queue-full, and how many sources the book knows.
    pub(crate) fn exchange_pool(&self) -> crate::served_downloads::ExchangePool {
        crate::served_downloads::ExchangePool {
            sources: self
                .sources
                .exchange_pool(|endpoint| self.scheduler.is_working(endpoint)),
            known: self.sources.counts().known,
        }
    }

    /// The live facts behind our **Callback Capability** moved:
    /// a login — to another server, whose namespace a Low ID is now read in —
    /// or re-assignment, a session's end, the Kad TCP verdict flipping.
    ///
    /// Only *admission* reads the new sample — aMule's `TryToConnect` asks
    /// `CanDoCallback` per attempt (`BaseClient.cpp:1991-2004`) and its
    /// `CPartFile::Process` re-promotes a `DS_LOWTOLOWIP` source the moment
    /// the answer turns (`PartFile.cpp:1751-1765`), so a candidate starved
    /// under the old sample is admitted now and the free slots fill. A callback
    /// already asked for is left alone: aMule never withdraws a
    /// `DS_WAITCALLBACK`/`DS_WAITCALLBACKKAD` on a flip, it waits for the
    /// answer or the timeout, so the slot holds until its own release
    /// deadline, as a callback nobody answers always did.
    pub(crate) fn on_callback_capability(
        &mut self,
        now: Instant,
        capability: CallbackCapability,
    ) -> Vec<Decision> {
        if capability == self.callback_capability {
            return Vec::new();
        }
        self.callback_capability = capability;
        self.sources.logged_into(capability.server());
        let mut out = Vec::new();
        // A standing that fell due while we were connected to no network is
        // asked the moment we are (stock 2.3.3 `PartFile.cpp:1460`, `:1475`).
        if capability.connected() {
            self.reask_sweep(now, &mut out);
        }
        self.fill(now, &mut out);
        out
    }

    /// A fresh sample of whether any discovery channel may still backfill
    /// (ADR-0093), the `on_callback_capability` shape: a no-op when nothing
    /// moved; otherwise a refill, which is also where a starved download
    /// whose last channel just died fails `NoUsableSources`.
    pub(crate) fn on_discovery_active(&mut self, now: Instant, active: bool) -> Vec<Decision> {
        if active == self.discovery_active {
            return Vec::new();
        }
        self.discovery_active = active;
        let mut out = Vec::new();
        self.fill(now, &mut out);
        // ADR-0026's terminal condition, as every other refill states it: the
        // last channel that made an empty pool a wait is gone.
        if self.out_of_sources() {
            out.push(Decision::Fail(DownloadFailure::NoUsableSources));
        }
        out
    }

    /// Whether `peer` currently holds an in-flight part. A test affordance for
    /// asserting scheduling outcomes; the runner drives off `is_complete` and
    /// the decisions, never this read.
    #[cfg(test)]
    pub(crate) fn is_working(&self, peer: PeerEndpoint) -> bool {
        self.scheduler.is_working(peer)
    }

    /// The trusted AICH root in force (test affordance for asserting the
    /// trusted-set vote outcome).
    #[cfg(test)]
    pub(crate) fn trusted_aich_root(&self) -> Option<AichRootHash> {
        self.trusted_aich_root
    }

    /// Whether every part is verified.
    pub(crate) fn is_complete(&self) -> bool {
        self.scheduler.is_complete()
    }

    /// The verification authority in force (ADR-0027). The runner reads it to
    /// verify-and-persist a completed part — the persist effect's only input
    /// drawn from the state.
    pub(crate) fn resolved(&self) -> &ResolvedHashSet {
        &self.resolved
    }

    /// `(parts, retired)`: the positional part map (ADR-0079) plus the
    /// retired-peer tally the runner mirrors into the diagnostics row after
    /// each drain (ADR-0028). The row's part counts are read off the vector,
    /// so scheduler shape and published tallies cannot disagree.
    pub(crate) fn part_map(&self) -> (Vec<PartState>, u32) {
        (self.scheduler.part_states(), self.retired_peers)
    }

    /// Tear the download down for a stop `reason` (pause / cancel): release
    /// every in-flight part with the matching reason, shut each worker's
    /// diagnostics row, and fail. Mirrors the runner's graceful shutdown.
    pub(crate) fn on_stop(&mut self, reason: DownloadFailure) -> Vec<Decision> {
        let mut out = Vec::new();
        let release_reason = match reason {
            DownloadFailure::Paused => PartReleaseReason::Paused,
            _ => PartReleaseReason::Cancelled,
        };
        let mut released = self.scheduler.take_in_flight();
        released.sort_unstable_by_key(|(_, plan)| plan.part_index);
        for (peer, plan) in released {
            out.push(Decision::Emit(DownloadEvent::PartReleased {
                download_id: self.download_id,
                peer,
                part_index: plan.part_index,
                reason: release_reason,
            }));
        }
        let mut slots: Vec<usize> = self.worker_slots.values().map(|s| s.as_usize()).collect();
        slots.sort_unstable();
        for slot_idx in slots {
            out.push(Decision::Phase {
                slot: WorkerSlot::from_usize(slot_idx),
                phase: WorkerPhase::ShutDown,
            });
        }
        out.push(Decision::Fail(reason));
        self.settle_seed_dials(&mut out);
        out
    }
}
