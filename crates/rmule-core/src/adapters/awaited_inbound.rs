//! The **Awaited Inbound** registry: the one place that knows a download is
//! waiting for a peer to reach us, whatever road the peer takes.
//!
//! A pending Low-ID callback can be answered down two roads (ADR-0039 +
//! ADR-0091). The peer may dial in because a server relayed the callback, and
//! its hello then reports `(connected_server, low_id)`, the **Pending
//! Callback**'s key. Or a punch toward it may raise a **Dialer Tunnel**, or a
//! buddy may relay our ask so that it dials us back, and then only its **User
//! Hash** names it, the **Pending Tunnel Claim**'s key. Both are attempts on
//! the *one* callback, so a download holds one registration per callback,
//! reachable by either key, as an [`AwaitedInboundHandle`].
//!
//! # One question
//!
//! Inbound triage asks [`AwaitedInbound::triage`] once per identified
//! connection, with how it came in and what its hello says, and gets an
//! [`InboundVerdict`]. An adoption spends the whole registration under the
//! lock that found it: whichever road lands first takes the slot, and the
//! other road is gone before a second connection can reach it.
//!
//! # The hello decides
//!
//! A claim is spent on a Tunnel this node dialed only when the hello's User
//! Hash is the claimed one. Behind a NAT the address that answers a punch is a
//! mapping, not an identity, so a mismatch closes the connection and leaves
//! the claim pending, because the target may still be on its way. A path
//! nothing here aimed is adopted by its hash only for a claim that asked the
//! target to dial us (ADR-0061 route 4), and only when the callback key
//! missed.
//!
//! # Several downloads, one key
//!
//! One peer may hold two files the **Download Set** fetches (ADR-0107). A
//! callback or a punch opens one connection, so each key keeps its
//! registrations in the order they were filed: the oldest takes a connection,
//! the others stay pending to their own deadlines, a retirement reaches every
//! claimant, and the **NAT-T Front** is told the attempt is abandoned only
//! when its last claimant lets go.
//!
//! # Release
//!
//! The registry sits behind a short std mutex never held across an await, so
//! dropping a handle releases both of its keys synchronously, on every road a
//! callback or its run can end, an aborted task included.

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use rmule_peer::PartBitmap;
use rmule_primitives::{ClientId, Ed2kFileLink, Ipv4Endpoint, UserHash};
use tokio::sync::mpsc;

use crate::diagnostics::DiagnosticsState;
use crate::natt::front::{AttemptRetirement, NattRisenSender};

use super::peer_transfer::PeerWorker;
use registrations::{CallbackRoad, ClaimRoad, Landing, LetGo, Registrations, Road};

/// Identifies one pending Low-ID callback (ADR-0039 / ADR-0051) — the single key
/// `download::state`'s `DownloadState` owns and threads verbatim through
/// its Source Book's road deadlines and its adoption routing.
/// `low_id` is the source's server-assigned id (unique only per server, so the
/// server namespaces it); `server` is the server that relays the callback and
/// that the called-back peer reports as its `connected_server`:
/// - `None` — the *connected-server* form: the download's own connected server.
///   The sans-I/O brain does not hold that endpoint (a runtime fact, like the
///   clock), so it leaves `None`; the runner resolves it to the live connected
///   server when it files the callback here.
/// - `Some(server)` — a *per-server global* callback (ADR-0051): the source-server that
///   answered `OP_GLOBFOUNDSOURCES` and relays the callback.
///
/// The key a callback is filed under here is always the concrete endpoint the
/// inbound peer reports (the runner has resolved any `None`) — a `None` there
/// could never match an inbound hello. It stays `Option` because a DNS-named
/// server's hello encodes `0.0.0.0:0` → `None`; such a callback simply
/// degrades to the timeout.
///
/// `kad_port` is `Some` for a **Kad source row** alone, which is in no
/// server's namespace: `low_id` is then read from the address its publisher
/// was observed at, and the Kad UDP port beside it tells two publishers behind
/// one address apart, as aMule tells Low IDs apart by IP and Kad port
/// (`CClientList::FindMatchingClient`, stock 2.3.3 `ClientList.cpp:264-280`;
/// ADR-0090). A server-assigned id leaves it `None`: its server tells it
/// apart. An inbound hello reports `None` too, so a Kad row's key never
/// matches a reported one.
///
/// It lives here, not in `download::state`, so that the vocabulary it shares
/// with this registry and `PeerWorkerEvent`/`PeerWorkerCommand` has one home
/// and the `download::state -> adapters` dependency direction holds; the
/// lifecycle (the pending set and all callback policy) is still the brain's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CallbackKey {
    pub(crate) server: Option<Ipv4Endpoint>,
    pub(crate) low_id: ClientId,
    pub(crate) kad_port: Option<u16>,
}

/// Where an adopted worker is handed back, tagged with the brain's key of the
/// callback it settles.
pub(crate) type AdoptSender = mpsc::Sender<(CallbackKey, PeerWorker)>;

/// Where a retired **Traversal Attempt** is reported, tagged the same way.
pub(crate) type RetireSender = mpsc::Sender<(CallbackKey, AttemptRetirement)>;

/// What a download states when it files a road: what the adopted worker asks
/// for on connect. Each road keeps the brief it was filed with.
pub(crate) struct AdoptionBrief {
    /// The file the adopted worker downloads — the triage knows only the key.
    pub(crate) file: Ed2kFileLink,
    /// What the download held when it filed the road — the adopted worker's
    /// connect-time name ask carries it.
    pub(crate) own_status: PartBitmap,
    /// Whether the adopted worker's connect-time request asks for sources —
    /// the download's decision when it filed the road (ADR-0108).
    pub(crate) want_sources: bool,
}

/// How an identified connection reached the triage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InboundArrival {
    /// Accepted: somebody dialed us — an ordinary peer, a called-back one, or
    /// a target dialing back on a buddy's relay; nothing tells them apart
    /// before the hello.
    Accepted,
    /// A **Dialer Tunnel**: this node raised it toward the named User Hash.
    DialedToward(UserHash),
}

/// The registry's answer to [`AwaitedInbound::triage`].
pub(crate) enum InboundVerdict {
    /// A download was waiting for this peer: the registration is spent, both
    /// of its roads with it, and the connection is that download's worker.
    Adopt(Adoption),
    /// A Dialer Tunnel's hello names somebody other than its target. The
    /// claims on the target stay pending — the real target may still arrive —
    /// and the connection is closed rather than served: nothing asked for it.
    Mismatch,
    /// Nobody waits for this peer: the serve road.
    Unclaimed,
}

/// A spent registration, as the triage needs it to build and hand over the
/// adopted worker.
pub(crate) struct Adoption {
    /// What the worker asks for on connect — the brief of the road that landed.
    pub(crate) brief: AdoptionBrief,
    /// The brain's key of the callback this connection settles, whichever road
    /// it came down, so the brain ends exactly one pending callback.
    pub(crate) callback: CallbackKey,
    /// The registering download's adoption channel.
    pub(crate) adopt_tx: AdoptSender,
}

/// The core-owned registry. The actor owns it; the serve adapter clones one
/// (its triage asks it), the NAT-T front clones one (a retirement reaches the
/// claimants through it), and each download's runner clones one (it files its
/// callbacks into it).
///
/// It carries its own diagnostics and front handles because the facts only
/// *it* sees — an adoption granted or refused on the hello, a claim let go —
/// are decided in the serve adapter's triage and in a runner's drop, both
/// built before the core's [`DiagnosticsState`] and the front exist. Each is
/// installed afterwards; an uninstalled cell simply reports nothing.
#[derive(Clone, Default)]
pub(crate) struct AwaitedInbound {
    registrations: Arc<Mutex<Registrations>>,
    diagnostics: Arc<OnceLock<DiagnosticsState>>,
    /// The front's own risen-tunnel sender: where a confirmed hello and a
    /// last claimant letting go are reported, exactly as a closed **Punched
    /// Path** is.
    risen: Arc<OnceLock<NattRisenSender>>,
}

/// One download's registration for one pending callback. Not `Clone`: the
/// download holds exactly one per callback, and dropping it releases both
/// keys at once.
pub(crate) struct AwaitedInboundHandle {
    registry: AwaitedInbound,
    id: registrations::RegistrationId,
}

impl AwaitedInbound {
    /// Install where adoption outcomes are counted. Idempotent.
    pub(crate) fn install_diagnostics(&self, diagnostics: DiagnosticsState) {
        let _ = self.diagnostics.set(diagnostics);
    }

    /// Install where a confirmed hello and an abandoned claim are reported.
    /// Idempotent, and installed by the front whose wiring holds this same
    /// registry; one no front was built over reports nothing.
    pub(crate) fn install_risen(&self, risen: NattRisenSender) {
        let _ = self.risen.set(risen);
    }

    /// Whether a **Dial-Back Claim** stands anywhere: a source asked to dial
    /// us back may open a Tunnel from an address nothing here knows, since a
    /// Low-ID callback names no address for it (ADR-0091, security rule 10).
    pub(crate) fn awaits_dial_back(&self) -> bool {
        self.registrations
            .lock()
            .is_ok_and(|registrations| registrations.awaits_dial_back())
    }

    /// Open a download's registration for the pending callback `callback` (the
    /// brain's key). It is reachable by no key until a road is filed through
    /// the handle.
    pub(crate) fn register(
        &self,
        callback: CallbackKey,
        adopt_tx: AdoptSender,
        retire_tx: RetireSender,
    ) -> AwaitedInboundHandle {
        let id = self.lock().open(callback, adopt_tx, retire_tx);
        AwaitedInboundHandle {
            registry: self.clone(),
            id,
        }
    }

    /// Who gets a connection that came in by `arrival` and whose hello named
    /// `hello` and reported the callback key `reported` — its
    /// `(connected_server, client_id)`.
    ///
    /// In order: a Dialer Tunnel's target, when somebody claims it; the
    /// callback key; and, on a key miss, a claim that asked `hello` to dial
    /// us back. An adoption is reported back to the **NAT-T Front** whatever
    /// road found it, because the front's own end is a no-op for a peer it
    /// never held an attempt for.
    pub(crate) fn triage(
        &self,
        arrival: InboundArrival,
        hello: UserHash,
        reported: CallbackKey,
    ) -> InboundVerdict {
        let (verdict, landing) = self.lock().triage(arrival, hello, reported);
        if let Some(diagnostics) = self.diagnostics.get() {
            if matches!(verdict, InboundVerdict::Mismatch) {
                diagnostics.count_natt_download_adoption_refused();
            }
            if landing
                .as_ref()
                .is_some_and(|landing| landing.road == Road::DialedTunnel)
            {
                diagnostics.count_natt_download_adoption();
            }
        }
        if let Some(Landing { let_go, .. }) = landing {
            if let Some(risen) = self.risen.get() {
                risen.identified(hello);
            }
            self.let_go(let_go);
        }
        verdict
    }

    /// Tell every download that claimed `target` that the **Traversal
    /// Attempt** toward it retired, with the reason (ADR-0091; ADR-0107).
    /// Reports whether there was a claimant to tell.
    ///
    /// **The claims are left standing.** Whether the road ends is the
    /// download's to decide, downstream of the brain being told.
    ///
    /// `try_send`, never `send`: the caller is the NAT-T front's own loop,
    /// which may not wait on a consumer it does not drain. A runner that has
    /// stopped draining loses its notice and falls back on the callback's
    /// 30 s deadline.
    pub(crate) fn retire(&self, target: UserHash, reason: AttemptRetirement) -> bool {
        let told = self.lock().claimants(target);
        for (callback, retire_tx) in &told {
            if retire_tx.try_send((*callback, reason)).is_err() {
                tracing::debug!(
                    ?target,
                    ?reason,
                    "a retired NAT-T attempt had nowhere to report; the callback's own deadline stands"
                );
            }
        }
        !told.is_empty()
    }

    /// Whether no registration is held at all.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.lock().held.is_empty()
    }

    fn lock(&self) -> MutexGuard<'_, Registrations> {
        self.registrations
            .lock()
            .expect("the awaited-inbound registry is never poisoned")
    }

    /// A claim on `target` was dropped by its own download: count it, and
    /// when it was the `last` claimant tell the **NAT-T Front**, which ends
    /// the attempt rather than dialing on for nobody.
    fn let_go(&self, let_go: Option<LetGo>) {
        let Some(LetGo { target, last }) = let_go else {
            return;
        };
        if let Some(diagnostics) = self.diagnostics.get() {
            diagnostics.count_natt_download_claim_retired();
        }
        if last && let Some(risen) = self.risen.get() {
            risen.abandoned(target);
        }
    }
}

impl AwaitedInboundHandle {
    /// File the server-relayed road: the called-back peer's hello will report
    /// `routing`, the brain's key with any connected-server `None` resolved.
    /// Filing it again under the same key keeps the registration's turn.
    pub(crate) fn await_callback(&self, routing: CallbackKey, brief: AdoptionBrief) {
        self.registry
            .lock()
            .file_callback(self.id, CallbackRoad { routing, brief });
    }

    /// File the tunnel road: claim the connection `target` may open toward
    /// us, a Dialer Tunnel always, and a path nothing here aimed too when
    /// `dial_back`. Claiming the same target again keeps the claim's turn and
    /// the dial-back an earlier claim stated: a punch beside a buddy callback
    /// is a second road to one slot, not a replacement for the first.
    pub(crate) fn claim_tunnel(&self, target: UserHash, brief: AdoptionBrief, dial_back: bool) {
        let moved = self.registry.lock().file_claim(
            self.id,
            ClaimRoad {
                target,
                brief,
                dial_back,
            },
        );
        self.registry.let_go(moved);
    }

    /// Retract just the tunnel road, leaving the callback's own road filed:
    /// its **Traversal Attempt** retired, so no Tunnel will be dialed for it.
    /// Idempotent.
    pub(crate) fn retract_claim(&self) {
        let retracted = self.registry.lock().retract_claim(self.id);
        self.registry.let_go(retracted);
    }
}

impl Drop for AwaitedInboundHandle {
    fn drop(&mut self) {
        let released = self.registry.lock().release(self.id);
        self.registry.let_go(released);
    }
}

mod registrations;
#[cfg(test)]
mod tests;
