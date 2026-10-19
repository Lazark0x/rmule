//! The core actor and the vocabulary a front end speaks to it: commands in,
//! events out, and the [`Core`] handle that carries them. The actor owns every
//! activity a session runs — downloads, the serve side, searches, the server
//! list and Kad — and is the only place they meet; the seams it drives (store,
//! registry, transports, Kad factory) are chosen through [`CoreBuilder`].

mod activity;
mod actor;
pub use self::actor::RECONNECT_ATTEMPTS;
mod builder;
mod command;
mod config;
mod event;
mod inbox;

pub(crate) use self::activity::FinishedActivity;
pub(crate) use self::inbox::SettingsDoor;

use self::actor::{CoreWiring, run_core_with_adapters};

pub use self::builder::CoreBuilder;
pub use self::command::{
    CoreCommand, CoreCommandRejectReason, DownloadCommand, KadUnavailableReason, NameTaken,
    ScanCommand, SearchCommand, ServeCommand, ServerListCommand,
};
pub use self::config::{
    CeilingLowered, CoreConfig, DEFAULT_SLOT_WAIT_TIMEOUT, NattConfig, PeerConnections,
    VerificationAuthority, descriptor_room,
};
pub use self::event::LinkTurn;
pub use self::event::{
    BuddyDialFailure, CompletionStep, CoreEvent, DialEnd, DialFailure, DownloadEvent, IdAssignment,
    IgnoredReaskReply, Ipv6Probe, KadStopReason, LegNotSent, LoginClaim, LoginCloseCause,
    LoginLink, LoginStep, NatTraversalUnavailableReason, PartsLost, PeerBuddy, PeerReach,
    PeerReachDropReason, PeerReachRoute, PlainLinkReason, PortTestAdmission, PortTestClosedBy,
    PortTestEnd, PortTestLateAdmission, PurgedSource, QuitStep, ReconnectEnd, RestartOutcome,
    ScanEvent, SearchEvent, SearchFailure, SearchLegState, SearchLegs, ServeEvent,
    ServeStartFailure, ServeStopReason, ServerConnectFailure, ServerConnectionEvent,
    ServerListEvent, ShareRejectReason, SharesWithheld, SourcePurgeReason, SourceWait, SweepTally,
};
pub use self::event::{DialBackEnd, GrantRoad};

use std::sync::Arc;

use rmule_primitives::ClientIdentity;
use tokio::sync::mpsc;

use crate::CoreError;
use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};

/// One download activity's caller-visible handle. Minted by core when a
/// `StartDownload` is accepted, persisted with the download, and reused
/// unchanged across restarts — so it is stable, not a per-run counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DownloadId(u64);

impl DownloadId {
    /// Rebuild an id from a value that came out of [`DownloadId::as_u64`] — a
    /// store row or a CLI argument. It is not validated against live activities.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// The raw value, for printing it or writing it to a store row.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// One search activity's caller-visible handle, chosen by the caller and
/// carried by its `StartSearch`, so every outcome — refusal included — names
/// what the caller sent (ADR-0034). Unlike a [`DownloadId`] it
/// lives only for the process, since a result set is not durable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SearchId(u64);

impl SearchId {
    /// A fresh id, never handed out before in this process and greater than
    /// every earlier one — so front ends sharing a core never collide.
    #[must_use]
    pub fn mint() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    /// Rebuild an id from a value that came out of [`SearchId::as_u64`].
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// The raw value, for printing it or logging it.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// The handle a front end holds on a running session: commands in, events out.
/// Building one spawns the actor, so a `Core` is live from construction until
/// [`Core::shutdown`] or drop. It is not `Clone` — the event stream has exactly
/// one reader, so every fact is delivered once.
pub struct Core {
    commands: inbox::CommandDoor,
    evt_rx: mpsc::Receiver<CoreEvent>,
    diagnostics: crate::diagnostics::DiagnosticsState,
    settings: crate::CoreSettingsHandle,
    kad_id: crate::KadId,
}

impl Core {
    /// The production Core over one open Durable Store: the shared-session
    /// adapter set (source lookup, peer transfer, serve runtime + Low-ID
    /// callback routing) with all four store seams on `store`. A one-line
    /// convenience over [`Core::builder`], which is what to reach for when any
    /// seam needs overriding.
    #[must_use]
    pub fn new(config: CoreConfig, store: Arc<crate::DurableStore>) -> Self {
        Self::builder(config, store).build()
    }

    /// Queue a command for the actor. Returns once it is queued, not once it
    /// is carried out — the answer arrives as events. The actor takes it after
    /// everything queued before it, live settings included: a command sent
    /// after [`settings`](Self::settings) answered
    /// [`TakesEffect::Now`](crate::TakesEffect::Now) runs under that setting.
    /// Waits while the actor is behind on earlier commands. Fails with
    /// [`CoreError::ServiceStopped`] when the actor is gone.
    pub async fn send(&self, command: CoreCommand) -> Result<(), CoreError> {
        self.commands.send(command).await
    }

    /// Await the next fact from the session. `None` means the actor stopped and
    /// no further event will ever arrive. Events are buffered by the channel, so
    /// a slow reader delays them but does not lose them.
    pub async fn next_event(&mut self) -> Option<CoreEvent> {
        self.evt_rx.recv().await
    }

    /// Shut the actor down and wait for its persistence flush. Closing the
    /// command channel is the shutdown signal; the actor then runs **Quit** —
    /// every activity's stop, in order (ADR-0093) — writes `clients.met`
    /// (when [`CoreBuilder::persist_credit_in`] configured a dir) and drops
    /// its event sender — the drained event stream is the completion signal,
    /// so when this returns the flush has happened.
    pub async fn shutdown(self) {
        let mut events = self.quit();
        while events.recv().await.is_some() {}
    }

    /// Begin **Quit** and hand back the rest of the event stream:
    /// the facts quit reports as it runs — a
    /// [`CoreEvent::Quitting`] per step, the activities' own stop events —
    /// ending once the flush has happened. [`shutdown`](Self::shutdown) is
    /// this, drained unread; a front end that names quit's progress reads it.
    #[must_use = "the stream's end is quit's completion"]
    pub fn quit(self) -> mpsc::Receiver<CoreEvent> {
        let Self {
            commands,
            evt_rx,
            diagnostics: _,
            settings: _,
            kad_id: _,
        } = self;
        drop(commands);
        evt_rx
    }

    fn spawn_with_dialed_serve<S, P, L, K>(
        wiring: CoreWiring<S, P, L, K>,
        store: Arc<crate::DurableStore>,
    ) -> Self
    where
        S: SourceLookupService,
        P: PeerTransferService,
        L: ServeRuntimeService,
        K: KadRuntimeFactory,
    {
        let (commands, inbox) = inbox::inbox();
        let (evt_tx, evt_rx) = mpsc::channel(32);
        let diagnostics = crate::diagnostics::DiagnosticsState::new();
        let settings = crate::CoreSettingsHandle::running(
            store,
            commands.settings_door(),
            wiring.share_guards.clone(),
        );
        let kad_id = wiring.kad_id;
        tokio::spawn(run_core_with_adapters(
            wiring,
            inbox,
            evt_tx,
            diagnostics.clone(),
        ));
        Self {
            commands,
            evt_rx,
            diagnostics,
            settings,
            kad_id,
        }
    }

    /// This node's **Kad ID** (ADR-0043): the one its Kad node starts under,
    /// read from the store at build or named by a tool with
    /// [`CoreBuilder::kad_id`]. A front end that resolves Kad seeds measures
    /// distance from it ([`acquire_kad_seeds`](crate::acquire_kad_seeds)).
    #[must_use]
    pub fn kad_id(&self) -> crate::KadId {
        self.kad_id
    }

    /// The **Core Settings** handle of this running core (ADR-0069): a set
    /// through it persists, and a live key — `Remember peers`, the server
    /// policy, the download directory — is queued for the actor with the
    /// commands, so every command sent after the set runs under it. The
    /// handle outlives the core; once the core has stopped, every set answers
    /// [`TakesEffect::NextStart`](crate::TakesEffect::NextStart).
    #[must_use]
    pub fn settings(&self) -> crate::CoreSettingsHandle {
        self.settings.clone()
    }

    /// Atomic snapshot of the current **Worker Phase** map and per-download
    /// scheduler counts, used for hang investigation (ADR-0028).
    #[must_use]
    pub fn diagnostics_snapshot(&self) -> crate::diagnostics::DiagnosticsSnapshot {
        self.diagnostics.snapshot()
    }
}

pub(crate) async fn send_download_event(evt_tx: &mpsc::Sender<CoreEvent>, event: DownloadEvent) {
    let _ = evt_tx.send(event.into()).await;
}

/// The **Reask Routes** the one shared client-UDP socket's downloader reply
/// inbox (`OP_REASKACK`/`OP_FILENOTFOUND`/`OP_QUEUEFULL`, `0x91`/`0x92`/`0x93`)
/// forwards through (ADR-0057, ADR-0107): one sink per member of the
/// **Download Set**, installed for its run, and the one `0x90` in flight per
/// peer endpoint. The quartet names no file, so a reply goes to the download
/// whose ping it answers and to no other; a reply nothing asked for drops.
pub(crate) type SharedReaskReplySink = Arc<std::sync::Mutex<crate::download::ReaskRoutes>>;

/// Who this client says it is on a wire-touching command: the presentation
/// half of its eD2k identity — nickname, listen port, protocol version and
/// any opaque extra tags. It carries **no User Hash and no Secure User
/// Identification keypair**: both are the node's, fixed when the core is
/// built (ADR-0048 "Identity ownership"), so no command can
/// name another hash — there is no field to name it in.
///
/// ```compile_fail
/// # use rmule_core::ClientCredentials;
/// # fn f(c: &ClientCredentials) {
/// let _ = c.user_hash();
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientCredentials {
    nickname: rmule_primitives::Ed2kText,
    tcp_port: u16,
    protocol_version: u32,
    extra_tags: Vec<rmule_primitives::Tag>,
}

impl ClientCredentials {
    /// The three facts a login presents besides the node's hash.
    #[must_use]
    pub fn new(nickname: rmule_primitives::Ed2kText, tcp_port: u16, protocol_version: u32) -> Self {
        Self {
            nickname,
            tcp_port,
            protocol_version,
            extra_tags: Vec::new(),
        }
    }

    /// Attach opaque forward-compatibility tags (see
    /// [`ClientIdentity::with_extra_tags`]).
    #[must_use]
    pub fn with_extra_tags(mut self, extra_tags: Vec<rmule_primitives::Tag>) -> Self {
        self.extra_tags = extra_tags;
        self
    }

    /// The display name announced to servers and peers.
    #[must_use]
    pub fn nickname(&self) -> &rmule_primitives::Ed2kText {
        &self.nickname
    }

    /// The port this client listens on for peer connections.
    #[must_use]
    pub fn tcp_port(&self) -> u16 {
        self.tcp_port
    }

    /// The eD2k protocol version advertised at login.
    #[must_use]
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// These credentials presenting `tcp_port` in place of their own: the
    /// port a bound listener holds, which is the one a peer is told to dial.
    #[must_use]
    pub(crate) fn on_port(mut self, tcp_port: u16) -> Self {
        self.tcp_port = tcp_port;
        self
    }

    /// The full wire identity these credentials present as the node whose
    /// hash is `user_hash` — composed by core, never by a caller.
    pub(crate) fn identity(&self, user_hash: rmule_primitives::UserHash) -> ClientIdentity {
        ClientIdentity::new(
            user_hash,
            self.nickname.clone(),
            self.tcp_port,
            self.protocol_version,
        )
        .with_extra_tags(self.extra_tags.clone())
    }
}

/// The presentation half of a stored identity — what a front-end holding the
/// store's generate-once [`ClientIdentity`] sends. The identity's hash is
/// dropped: the node's is the store's own, fixed at build.
impl From<ClientIdentity> for ClientCredentials {
    fn from(identity: ClientIdentity) -> Self {
        Self::new(
            identity.nickname().clone(),
            identity.tcp_port(),
            identity.protocol_version(),
        )
        .with_extra_tags(identity.extra_tags().to_vec())
    }
}

/// Why an in-flight part was released. Peer-caused releases nest the
/// retirement cause rather than duplicating its variants; caller-initiated
/// stops stay distinct.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PartReleaseReason {
    /// The assigned part was released because the peer was retired; see
    /// [`PeerRetirementReason`] for the specific cause.
    PeerRetired(PeerRetirementReason),
    /// The download was paused by the caller.
    Paused,
    /// The download was cancelled by the caller.
    Cancelled,
    /// The uploader ended our granted slot and put us back on its queue
    /// (`OP_OUTOFPARTREQS`, ADR-0057): the worker stays on its link, queued,
    /// and the part goes back for retry.
    BackOnQueue,
}

/// Why a peer was retired from a download. The single retirement-reason
/// vocabulary shared by the public `PartReleased`/`PeerRetired` events and
/// the diagnostics `WorkerPhase::Retired` row (core `CONTEXT.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PeerRetirementReason {
    /// The peer closed the connection, or the link failed under it.
    PeerDisconnected,
    /// `slot_wait_timeout` elapsed with the peer still queueing us.
    SlotTimeout,
    /// The peer queued us and gave us a rank, and no slot: the ask is
    /// answered, so the worker hung up, and the source keeps its place by the
    /// reask (the **Queued Hang-Up**, ADR-0116). Alive and honest.
    Queued,
    /// A part this peer served did not match its hash — the peer is dropped,
    /// not just the part, since the bytes cannot be trusted.
    PartVerificationFailed,
    /// The peer offered a part hash set that contradicts the authority the
    /// download already verifies against, so nothing it serves can be checked.
    VerificationAuthorityMismatch,
    /// The peer's stated crypt stance and ours cannot meet — one side requires
    /// obfuscation the other cannot provide (ADR-0049) — so it
    /// was never dialed. Not a dead source: a reachable one this node chose
    /// not to reach, as aMule's contact precondition drops it.
    CryptIncompatible,
    /// The peer's hello named a User Hash this download distrusts: it served
    /// this file bad data before (ADR-0090 "Source ownership").
    Distrusted,
    /// A sighting proved this worker's peer the same source another worker
    /// already reaches, and this one, the newer, gave way (ADR-0090's merge
    /// rule). The peer is alive, so its endpoint is not spent.
    SameSource,
    /// The peer's Advertised Parts hold no part the file still lacks (aMule
    /// `DS_NONEEDEDPARTS`, ADR-0112): it waits as a queued source, asked again
    /// over TCP at twice the reask period. Alive and honest, so neither spent
    /// nor distrusted.
    NoNeededParts,
    /// The peer granted a slot this worker had no part to work: every part it
    /// holds that we lack is in flight elsewhere (ADR-0112). The slot went back
    /// with `OP_CANCELTRANSFER` (ADR-0056) and the source waits as a queued
    /// one, asked again on the ordinary cadence (ADR-0057). Alive and honest.
    NoFreePart,
    /// The peer said it does not have the file (`OP_FILEREQANSNOFIL`): its
    /// record is spent for this download under every name it holds, for the
    /// re-ask period, as aMule dead-lists it (ADR-0090). Honest, so not
    /// distrusted.
    FileNotFound,
}
