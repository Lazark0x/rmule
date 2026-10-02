//! The synchronous, sans-I/O core of the multi-peer download runner.
//!
//! [`DownloadState`] owns every clock-free, channel-free scheduling decision
//! for one in-flight download: which part a peer works, how cross-peer blocks
//! assemble (ADR-0029), when a raced part completes and clears its losers
//! (ADR-0026), and which candidate backfills a retired worker (ADR-0030). It
//! never touches a socket, a clock, the store, or an `mpsc` channel; instead
//! each entry point returns an ordered `Vec<`[`Decision`]`>` that the async
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
mod distrust;
mod dual_stack;
mod remote_queued;
mod seeds;
mod slots;
mod spent;
#[cfg(test)]
mod tests;
mod worker_event;

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::time::Duration;

use rmule_peer::PartBitmap;
use rmule_primitives::{
    AichRootHash, ClientId, FileHash, Ipv4Endpoint, PartHash, PartHashSet, PeerCrypt, PeerEndpoint,
    UserHash,
};

pub(crate) use candidate::{ConnectedServerCandidate, LowIdCandidate};
pub(crate) use capability::CallbackCapability;
pub(super) use direct_ipv6::LowIdRoute;
pub(crate) use seeds::RememberedSeeds;
use seeds::SeedDials;
use spent::SpentEndpoints;

use crate::DownloadFailure;
use crate::adapters::{CallbackKey, PeerWorkerCommand};
use crate::assembly::PartAssembly;
use crate::callback::CallbackSilence;
use crate::diagnostics::{PartState, WorkerPhase, WorkerSlot};
use crate::dialable::DialPosition;
use crate::download::source_seeds::SeedLedger;
use crate::hashing::ResolvedHashSet;
use crate::scheduler::DownloadScheduler;
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
    /// `PeerWorkerCommand::Shutdown { cancel: false }`.
    EndWorker { peer: PeerEndpoint },
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
    },
    /// Ask the connected server to call back a Low-ID source (ADR-0039). The
    /// runner enacts it via the server session and registers the routing index
    /// under this download's connected server (the brain's `CallbackKey.server`
    /// is `None` — the connected-server form — and the runner resolves it); the
    /// called-back peer dials in and is adopted by the accept-router. Paired with
    /// an [`Decision::ArmCallbackTimeout`] for the held slot.
    RequestCallback { low_id: ClientId },
    /// Ask a Low-ID **global** source's own `source_server` — over UDP, with no
    /// TCP session — to relay a callback (ADR-0051, ADR-0039 generalized
    /// per-server). The runner enacts it via the discovery UDP socket and
    /// registers the routing index keyed `{ server: Some(source_server), low_id }`;
    /// the called-back peer dials in (`connected_server = source_server`) and is
    /// adopted. Paired with an [`Decision::ArmCallbackTimeout`] for the held slot.
    RequestGlobalCallback {
        low_id: ClientId,
        source_server: Ipv4Endpoint,
    },
    /// Ask `candidate`'s Kad buddy to relay a callback (ADR-0061 route 4).
    /// The runner registers a **dial-back** claim under the
    /// candidate's User Hash — the one name the target's hello will report,
    /// since a Kad candidate's [`CallbackKey`] is not an id any hello carries
    /// — and asks the core actor to emit the `0x52`. Paired with an
    /// [`Decision::ArmCallbackTimeout`] for the held slot.
    RequestBuddyCallback { candidate: LowIdCandidate },
    /// Ask `candidate`'s Kad buddy once more, under the **other spelling** of
    /// its `TAG_BUDDYHASH`: `candidate.buddy` already names the
    /// fallback ID. Enacted exactly as [`Self::RequestBuddyCallback`] — the
    /// same dial-back claim, the same `0x52` to the same buddy, file and port —
    /// and counted apart, because it is the one leg built on a source reading
    /// (eMule 0.70b / eMuleAI `GetData()`) rather than a capture.
    RequestFallbackBuddyCallback { candidate: LowIdCandidate },
    /// Ask `candidate` itself for a direct-UDP callback (ADR-0061 route 2):
    /// the `0x95` to the Kad UDP endpoint its own row carried —
    /// no server and no buddy involved. The runner claims the same
    /// **dial-back** entry a buddy callback claims, keyed by the candidate's
    /// User Hash, because a Kad candidate's [`CallbackKey`] is a synthetic id
    /// (its own address read as one) that no hello will ever report — and
    /// asks the core actor to emit the `0x95`. Paired with an
    /// [`Decision::ArmCallbackTimeout`] for the held slot.
    RequestDirectUdpCallback { candidate: LowIdCandidate },
    /// Arm the per-callback slot-release deadline for `key` (ADR-0039 / ADR-0051). The
    /// brain owns the *policy* (which key, the `after` span from its injected
    /// callback timeout); the runner's heap is a dumb enactor that resolves
    /// `after` against the clock (`now + after`) and, on fire, calls back
    /// [`DownloadState::on_callback_timeout`] with this same `key`. Emitted right
    /// after the matching `RequestCallback` / `RequestGlobalCallback`.
    ArmCallbackTimeout { key: CallbackKey, after: Duration },
    /// Arm the **callback-silence fallback** deadline for `key` (ADR-0091): the
    /// shorter, 12 s one, armed *beside* the slot-release deadline and only for
    /// a candidate whose own facts admit a Rendezvous coordinator. On fire the
    /// runner calls [`DownloadState::on_callback_silence`] with this `key`; a
    /// `CancelCallbackTimeout` for the key drops both deadlines, because
    /// adoption and lapse end both.
    ArmCallbackSilenceFallback { key: CallbackKey, after: Duration },
    /// Arm the **traversal bound** for `key` (ADR-0091 "Attempt lifecycle"):
    /// the latest the **Traversal Attempt** a
    /// [`Decision::FallToNatTraversal`] begins can still be running, so a slot
    /// that waits on the attempt is released even if its end is never
    /// reported. On fire the runner calls [`DownloadState::on_traversal_bound`];
    /// a `CancelCallbackTimeout` for the key drops it with the others.
    ArmTraversalBound { key: CallbackKey, after: Duration },
    /// Ask the one ADR-0061 selector to reach `candidate` by a punch (ADR-0091
    /// rung 1). The slot stays held, and now waits on the attempt: the 30 s
    /// slot release does not end a traversal still running — its
    /// retirement, its Tunnel, or the paired [`Decision::ArmTraversalBound`]
    /// does. NAT traversal is an attempt *beside* whatever else is
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
    },
    /// Retract `key`'s **Pending Tunnel Claim** and leave everything else
    /// standing (ADR-0091). The punch road is over for this
    /// callback — its **Traversal Attempt** retired — but the callback itself
    /// is not: the server may still relay it, so its slot, its 30 s deadline
    /// and its routing-index entry are untouched. Distinct from
    /// [`Decision::CancelCallbackTimeout`] for exactly that reason; ending the
    /// whole callback here would forfeit a slot the peer may still dial into.
    RetractTunnelClaim { key: CallbackKey },
    /// Cancel `key`'s armed deadline and retract its routing-index entry — the
    /// callback is over (adopted or lapsed). Idempotent by design: on adoption the
    /// accept-router already claimed the routing entry (only the deadline remains);
    /// on timeout the deadline already fired (only the entry remains). Resolving a
    /// connected-server `None` to the live server for the routing index is the
    /// runner's concern.
    CancelCallbackTimeout { key: CallbackKey },
    /// Every part is verified — assemble and finalize the file.
    Finalize,
    /// The download cannot proceed; fail it with `reason`.
    Fail(DownloadFailure),
}

/// A worker's runner-independent identity: the diagnostics slot it occupies
/// and whether it has reported `Connected` (only connected workers are
/// eligible for the reassign-on-retirement path, ADR-0030).
#[derive(Clone, Copy, Debug)]
struct Worker {
    slot: WorkerSlot,
    connected: bool,
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
}

/// One outstanding callback: the diagnostics slot it holds until adoption or
/// lapse, and the candidate record it was requested for — kept because rung 1's
/// fallback (ADR-0091) needs the candidate's facts twelve seconds later, and
/// nothing can recover them by then.
#[derive(Clone, Copy, Debug)]
struct PendingCallback {
    slot: WorkerSlot,
    candidate: LowIdCandidate,
    /// Which road the candidate was admitted by — and therefore what a retired
    /// traversal costs it. On the callback road the punch ran *beside* a
    /// relayed invitation that is still outstanding, so its end retracts only
    /// the claim; on the punch road it was the candidate's **only** road, so
    /// its end is the candidate's.
    road: LowIdRoad,
    /// Why the punch running beside this callback ended, once it has
    /// (ADR-0091). `None` while a **Traversal Attempt** is still
    /// open — or was never begun. Set, it means the source is *temporarily
    /// unreachable by NAT traversal*: no coordinator is left to ask, so a
    /// second silence must not start a second punch, and the callback's own
    /// deadline is the only clock still running for it.
    traversal_retired: Option<crate::diagnostics::NattRetirement>,
    /// Whether a punch was ever asked for this candidate — at admission on the
    /// punch road, or by the 12 s fallback. A road that ends under a punch
    /// already begun must not begin a second one.
    traversal_begun: bool,
    /// Whether the slot-release deadline came due while a traversal was still
    /// running: the slot waited on the attempt, so the attempt's
    /// end is the callback's lapse.
    slot_lapsed: bool,
    /// Whether the buddy callback's one fallback-spelling `0x52` has gone out
    /// So a second lapse ends the road rather than trying a
    /// third time.
    fallback_spelling_sent: bool,
}

/// How a Low-ID candidate is to be reached — the three callback roads and the
/// punch ADR-0091 leaves open, and the vocabulary of the admission rule
/// ([`DownloadState::low_id_route`]).
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
        } else if candidate.natt_facts().admits_coordinator() {
            Some(Self::Punch)
        } else {
            None
        }
    }
}

/// The candidate sources one run starts from: the single server-lookup snapshot
/// (ADR-0030), already split by what the runner can do with each.
pub(crate) struct StartingCandidates {
    /// Usable High-ID sources in dial order. The runner spawns up to
    /// `peer_concurrency` workers off the front and backfills from the rest
    /// rather than discarding what it did not use.
    pub(crate) high_id: Vec<PeerEndpoint>,
    /// The crypt side each source's obfuscation-aware `0x44` reply stated — its
    /// crypt byte and User Hash (ADR-0046), met with our policy at the dial
    /// (ADR-0049). Empty for a plain `0x42` reply: those sources stated
    /// nothing and read as [`PeerCrypt::unknown`].
    pub(crate) peer_crypts: HashMap<PeerEndpoint, PeerCrypt>,
    /// Low-ID sources: no dialable endpoint, reachable only if the connected
    /// server relays a callback (ADR-0039). Ids of 0 are never in here, and
    /// each carries whatever the lookup answer said about it. The type is what
    /// holds the namespace invariant — every record here is in the connected
    /// server's, because that is the only kind that can be constructed.
    pub(crate) low_id: Vec<ConnectedServerCandidate>,
    /// The peers this download distrusts, as its durable record holds them
    /// A source whose record names one of these is not pooled.
    pub(crate) distrusted: HashSet<UserHash>,
    /// The download's **Source Seeds** this run dials (ADR-0109): a worker
    /// dialed at one is marked `remembered`.
    pub(crate) remembered: RememberedSeeds,
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
    /// Peer → diagnostics slot + connected flag. The live command channel for
    /// each peer stays in the runner; the state owns only this identity.
    workers: HashMap<PeerEndpoint, Worker>,
    /// Peer → its `UserHash` once `Identified`, used to key credit. Never
    /// pruned across a re-dial that lands before its worker ends. `release`
    /// drops this entry with the `Worker` it rides (`Decision::EndWorker`):
    /// the attachment is the endpoint's known hash, and once
    /// nothing holds that endpoint the hash is not this run's to keep
    /// (ADR-0049, ADR-0090 "Attachments") — a later re-dial
    /// simply re-learns it off the next hello. `hello_crypts` is pruned the
    /// same way, at the same site.
    peer_user_hashes: HashMap<PeerEndpoint, UserHash>,
    /// High-ID peer → the crypt side its record stated (stance + User Hash).
    /// Seeded from the server-lookup reply (`OP_FOUNDSOURCES_OBFU`, ADR-0046)
    /// and extended by source-exchange answers (ADR-0042) and Kad rows'
    /// `TAG_ENCRYPTION`. The runner reads it when spawning a
    /// worker, and the dial meets it with our policy by aMule's outbound rule
    /// (ADR-0049); a peer absent here stated nothing.
    peer_crypts: HashMap<PeerEndpoint, PeerCrypt>,
    /// Peer → the crypt side its own hello stated (`CT_EMULE_MISCOPTIONS2`'s
    /// crypt bits and the hello's User Hash), written on a worker's
    /// `Identified`. Outranks `peer_crypts` at every later dial
    /// of that peer — a re-dial after a drop or its next appearance as a
    /// source — because the peer said it itself, on a connection, where a
    /// record only relays what someone else heard (ADR-0049). Pruned with
    /// `peer_user_hashes`, at the same site (`release`): the
    /// stance never outlives the endpoint's worker.
    hello_crypts: HashMap<PeerEndpoint, PeerCrypt>,
    /// Source User Hash → the serving-buddy endpoint its own hello named
    /// (`CT_EMULE_BUDDYIP`/`BUDDYUDP`). A Low-ID source's later
    /// sighting that names its buddy by ID alone takes this endpoint
    /// ([`Self::admit_low_id`]), so its buddy callback goes straight to the
    /// buddy rather than walking toward it. Keyed on the source's User Hash,
    /// not its endpoint, so it is unaffected by `hello_crypts`' pruning
    /// and — like `peer_crypts` below — stays for the run.
    hello_buddies: HashMap<UserHash, Ipv4Endpoint>,
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
    /// Unused candidate sources, in snapshot order; a fill pops the front
    /// (ADR-0030). Owning the pool lets the same path serve the initial fill
    /// and the on-retirement backfill, and lets the state decide the terminal
    /// "pool exhausted" failure itself.
    pool: VecDeque<PeerEndpoint>,
    /// Free diagnostics slots (`0..peer_concurrency`); a backfilled worker
    /// reuses a slot freed by a retired one.
    free_slots: BTreeSet<usize>,
    /// Caps active + connecting workers (one socket-use knob, ADR-0030).
    peer_concurrency: usize,
    /// Unused Low-ID candidates in the connected server's namespace, in
    /// discovery order (ADR-0039) — every record here has `source_server:
    /// None`. Drained by `fill` after the High-ID `pool` — dialing a reachable
    /// source is preferred over a callback's round-trip + timeout — and only
    /// for the records the admission rule ([`Self::low_id_route`]) says are
    /// reachable at all. An inadmissible record is skipped, not dropped: it
    /// costs a queue entry and states, honestly, a source this run cannot use.
    low_id_pool: VecDeque<LowIdCandidate>,
    /// Unused Low-ID **global** candidates (ADR-0051 + ADR-0039),
    /// discovered over server-UDP from a server rmule is *not* logged into. Each
    /// carries its own `source_server` because its callback must be relayed by
    /// that server, never the connected one. Drained by `fill` after both the
    /// High-ID `pool` and the connected-server `low_id_pool`.
    low_id_global_pool: VecDeque<LowIdCandidate>,
    /// The one pending-callback set (ADR-0039 / ADR-0051): every Low-ID candidate a
    /// callback has been requested for — connected-server (`CallbackKey.server` =
    /// `None`) and per-server global (`Some(source_server)`) alike — mapped to the
    /// slot it holds and the record it was requested for, until the inbound peer
    /// is adopted ([`Self::on_callback_connected`]) or the callback lapses
    /// ([`Self::on_callback_timeout`]). Each entry counts toward the concurrency
    /// cap. The single [`CallbackKey`] is what the runner's deadline heap and the
    /// shared routing index key on too, so all three stay in lockstep.
    pending_callbacks: HashMap<CallbackKey, PendingCallback>,
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
    /// Rung-0 dials in flight: the IPv6 endpoint a worker is dialing → the
    /// Low-ID candidate it belongs to, kept so a dial that never connects can
    /// hand the candidate to its callback roads.
    direct_ipv6_dials: HashMap<PeerEndpoint, LowIdCandidate>,
    /// Dual-stack High-ID sources pooled or being dialed: the half being
    /// dialed → the same peer's other half, which a dial that never connects
    /// falls to once unless it is spent (ADR-0090). The second dial
    /// keeps its spent first half here too, so its own failure spends it.
    dual_stack_fallbacks: HashMap<PeerEndpoint, PeerEndpoint>,
    /// Endpoints whose dial ended short of a completed handshake — High-ID
    /// single-address sources, dual-stack halves of either family, and Low-ID
    /// rung-0 IPv6 halves: not pooled, kept as a fallback nor dialed at rung 0
    /// until they sit out a re-ask period (ADR-0090).
    /// Keyed by the endpoint, not the source: a Low-ID candidate later
    /// seen at a different half re-opens rung 0 there.
    spent: SpentEndpoints,
    /// How long a requested callback holds its slot before it lapses (ADR-0039,
    /// `CoreConfig::callback_timeout`). A pure span, not a clock read, so the brain
    /// stays clock-free: it emits it as [`Decision::ArmCallbackTimeout`]'s `after`
    /// and the runner resolves it against `Instant::now()`.
    callback_timeout: Duration,
    /// Whether any background source-discovery channel is armed for this
    /// download: the server-UDP global sweep (ADR-0051) and/or Kad (ADR-0043).
    /// When true, "no usable source right now" is a *wait* (a discovery
    /// channel may backfill), not a terminal failure — so
    /// `no_usable_candidate` never reports true.
    discovery_active: bool,
    /// The sources the runner's **Remote-Queued Pool** holds (ADR-0057): each
    /// queued us and hung up, and its earned standing rides the reask
    /// heartbeat, runner-side with its clock. The brain keeps the membership
    /// because it is the owner check every pooling seam reads (ADR-0090 "Source ownership"):
    /// a source held here is not pooled again by a
    /// sighting. The runner moves a source in with
    /// [`enter_remote_queue`](Self::enter_remote_queue) and out with
    /// [`leave_remote_queue`](Self::leave_remote_queue) or
    /// [`readd_source`](Self::readd_source). Like `discovery_active`, a
    /// non-empty set is a live path back to a slot (its `FILEREASKTIME` TCP
    /// full ask re-dials), so the download waits rather than failing
    /// `NoUsableSources`.
    remote_queued: HashSet<PeerEndpoint>,
    /// The peers this download distrusts (ADR-0090 "Source ownership"):
    /// each served this file bad data. Keyed by User Hash, so the distrust
    /// follows a peer to a new address; kept for the download's life,
    /// durably ([`distrust`]).
    distrusted: HashSet<UserHash>,
    /// Who earned which **Source Seeds** class this run (ADR-0109).
    seeds: SeedLedger,
    /// The pooled endpoints that came from a seed.
    remembered: HashSet<PeerEndpoint>,
    /// The seeds' dials not yet reported, `None` once reported or when the
    /// run had no seeds.
    seed_dials: Option<SeedDials>,
}

impl DownloadState {
    /// Build the scheduling state from what the run knows up front — the
    /// content, the candidate sources and rmule's own sourcing posture — plus
    /// the slot economy: how many workers or pending callbacks may hold a slot
    /// at once, and how long a callback holds one before it lapses.
    pub(crate) fn new(
        download_id: DownloadId,
        content: ContentFacts,
        candidates: StartingCandidates,
        posture: SourcingPosture,
        callback_timeout: Duration,
        peer_concurrency: usize,
    ) -> Self {
        let ContentFacts {
            file_hash,
            file_size,
            link_part_hash_set,
            resolved,
            trusted_aich_root,
            verified_parts,
        } = content;
        let StartingCandidates {
            high_id,
            peer_crypts,
            low_id,
            distrusted,
            remembered,
        } = candidates;
        let distrusts =
            |hash: Option<UserHash>| hash.is_some_and(|hash| distrusted.contains(&hash));
        let high_id: Vec<_> = high_id
            .into_iter()
            .filter(|peer| !distrusts(peer_crypts.get(peer).and_then(|c| c.user_hash())))
            .collect();
        let mut seeds = SeedLedger::default();
        for &peer in &high_id {
            seeds.dialable(peer);
        }
        Self {
            download_id,
            file_hash,
            file_size,
            scheduler: DownloadScheduler::new(file_size, verified_parts),
            assembly: HashMap::new(),
            pending_persist: HashMap::new(),
            awaiting_recovery: HashMap::new(),
            workers: HashMap::new(),
            peer_user_hashes: HashMap::new(),
            peer_crypts,
            hello_crypts: HashMap::new(),
            hello_buddies: HashMap::new(),
            link_part_hash_set,
            resolved,
            trusted_aich_root,
            aich_root_votes: HashMap::new(),
            retired_peers: 0,
            pool: high_id.into_iter().collect(),
            free_slots: (0..peer_concurrency).collect(),
            peer_concurrency,
            low_id_pool: low_id
                .into_iter()
                .map(ConnectedServerCandidate::into_inner)
                .filter(|candidate| !distrusts(candidate.user_hash))
                .collect(),
            low_id_global_pool: VecDeque::new(),
            pending_callbacks: HashMap::new(),
            callback_capability: posture.callback_capability,
            dial: posture.dial,
            direct_ipv6_dials: HashMap::new(),
            dual_stack_fallbacks: HashMap::new(),
            spent: SpentEndpoints::default(),
            callback_timeout,
            discovery_active: posture.discovery_active,
            remote_queued: HashSet::new(),
            distrusted,
            seeds,
            seed_dials: SeedDials::new(&remembered),
            remembered: remembered.endpoints,
        }
    }

    /// Spawn the initial fleet of workers from the candidate pool, up to
    /// `peer_concurrency`. The runner enacts each [`Decision::Spawn`] by
    /// putting that peer on the wire; the worker is assigned its first part on
    /// its own `Connected` event (ADR-0030).
    pub(crate) fn start(&mut self) -> Vec<Decision> {
        let mut out = Vec::new();
        self.fill(&mut out);
        self.settle_seed_dials(&mut out);
        out
    }

    /// No source we can still reach: the High-ID pool is empty and no Low-ID
    /// candidate is admissible (ADR-0039 / ADR-0091). When true with no live
    /// workers or pending callbacks, the download fails `NoUsableSources`.
    fn no_usable_candidate(&self) -> bool {
        // When global discovery is armed (ADR-0051), a future UDP sweep may
        // backfill, so we are never *out* of candidates — the download waits.
        self.pool.is_empty()
            && self.next_low_id_route().is_none()
            && !self.discovery_active
            && self.remote_queued.is_empty()
    }

    /// The first admissible Low-ID candidate's route, in drain order:
    /// connected-server candidates (ADR-0039) before per-server global ones
    /// (ADR-0051), because the connected server is already logged in. Reads
    /// only — [`Self::take_low_id`] is the taking half.
    fn next_low_id_route(&self) -> Option<LowIdRoute> {
        self.low_id_pool
            .iter()
            .chain(self.low_id_global_pool.iter())
            .find_map(|candidate| self.low_id_route(candidate))
    }

    /// The crypt side `peer` stated — its stance and User Hash — by the
    /// ADR-0049 precedence: the peer's own hello, else its record
    /// — the server-lookup reply (`0x44`, ADR-0046), a source-exchange answer
    /// (ADR-0042) or a Kad row's `TAG_ENCRYPTION`, or, for a rung-0 dial, the
    /// Low-ID candidate it belongs to ([`LowIdCandidate::peer_crypt`])
    /// — else [`PeerCrypt::unknown`]. The runner hands it to the
    /// worker's brief; the dial meets it with our policy (ADR-0049).
    pub(crate) fn peer_crypt(&self, peer: PeerEndpoint) -> PeerCrypt {
        self.hello_crypts
            .get(&peer)
            .or_else(|| self.peer_crypts.get(&peer))
            .copied()
            .or_else(|| {
                self.direct_ipv6_dials
                    .get(&peer)
                    .map(LowIdCandidate::peer_crypt)
            })
            .unwrap_or_default()
    }

    /// The crypt side `peer`'s own hello stated, when a worker read one — the
    /// one attachment both the TCP re-dial ([`Self::peer_crypt`]) and the
    /// `0x90` reask's UDP crypt target read (ADR-0049).
    pub(crate) fn hello_crypt(&self, peer: PeerEndpoint) -> Option<PeerCrypt> {
        self.hello_crypts.get(&peer).copied()
    }

    /// Remember the crypt side a High-ID source's record stated, for the dial
    /// that spawns against `endpoint`, folded into what earlier records said
    /// ([`PeerCrypt::fold_newer`], ADR-0049): the newer statement wins,
    /// silence — a record with no crypt byte — keeps the stated stance, and a
    /// record naming another User Hash replaces the record whole.
    fn note_peer_crypt(&mut self, endpoint: PeerEndpoint, crypt: PeerCrypt) {
        if crypt.is_unknown() {
            return;
        }
        let held = self.peer_crypts.get(&endpoint).copied().unwrap_or_default();
        self.peer_crypts.insert(endpoint, held.fold_newer(crypt));
    }

    /// Our current availability for the file as aMule's `WritePartStatus` writes
    /// it ([`PartBitmap::downloader`]) — the parts we have verified — for a
    /// source-reask ping's body (ADR-0057: rides the `0x90` when the source's
    /// UDP version is `> 3`) and a new worker's connect-time name ask,
    /// telling the uploader which parts we still need.
    pub(crate) fn our_part_status(&self) -> PartBitmap {
        PartBitmap::downloader(self.file_size, |part| {
            self.scheduler.is_part_verified(part.value())
        })
    }

    /// The live facts behind our **Callback Capability** moved:
    /// a login or re-assignment, a session's end, the Kad TCP verdict flipping.
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
        capability: CallbackCapability,
    ) -> Vec<Decision> {
        if capability == self.callback_capability {
            return Vec::new();
        }
        self.callback_capability = capability;
        let mut out = Vec::new();
        self.fill(&mut out);
        out
    }

    /// A fresh sample of whether any discovery channel may still backfill
    /// (ADR-0093), the `on_callback_capability` shape: a no-op when nothing
    /// moved; otherwise a refill, which is also where a starved download
    /// whose last channel just died fails `NoUsableSources`.
    pub(crate) fn on_discovery_active(&mut self, active: bool) -> Vec<Decision> {
        if active == self.discovery_active {
            return Vec::new();
        }
        self.discovery_active = active;
        let mut out = Vec::new();
        self.fill(&mut out);
        // ADR-0026's terminal condition, as every other refill states it: the
        // last channel that made an empty pool a wait is gone.
        if self.workers.is_empty()
            && self.pending_callbacks.is_empty()
            && self.no_usable_candidate()
            && !self.scheduler.is_complete()
        {
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
        let mut slots: Vec<usize> = self.workers.values().map(|w| w.slot.as_usize()).collect();
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
