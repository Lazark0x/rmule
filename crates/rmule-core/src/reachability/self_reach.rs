//! **Self Reach**: the one live owner of our own reachability (ADR-0060 "Self Reach").
//!
//! Four families, each with one writer, read through one API:
//!
//! - **Kad running** — **Kad Presence**, whose one lease the Kad Activity in
//!   the actor's ledger holds from start to retire (ADR-0093);
//! - **Kad TCP** and **Kad UDP** — the published self-check verdicts
//!   ([`KadReachLevel`]), written only by the Kad pump and reset by that same
//!   lease at the node's start and end — one fact, so a reader never sees a
//!   stopped node with a live verdict or a running one with a stale flag;
//! - **Server High ID** — the session self-facts
//!   ([`SharedOwnIdentity::connected_session`]), read, never copied;
//! - **NAT-T front** — [`SharedNattFront::is_live`].
//!
//! It also carries `CanDoCallback`'s one non-reach conjunct, whether a serve
//! listener is bound ([`SharedServeListener`]), so that answer is
//! composed here too and its moves wake the same generation.
//!
//! The union rules aMule answers every reader with live
//! (`IsFirewalledKad`, `IsFirewalled`, `CanDoCallback`, the direct-callback
//! bit; `amule.cpp:1668-1805`, `Prefs.cpp:228`, `4e8f2b3c`) live here and
//! nowhere else: a reader asks the question and never composes two facts
//! itself. A reader that must cache subscribes to the **Reach Generation**
//! ([`SharedSelfReach::changes`]) and re-derives on it.

use std::future::pending;

use tokio::sync::watch;

use super::{KadReachLevel, KadVerdicts, KadVerdictsLease, TcpReachability, UdpReachability};
use crate::adapters::{KadPresenceLease, KadPresenceView};
use crate::download::CallbackCapability;
use crate::natt::front::SharedNattFront;
use crate::own_identity::{ConnectedSession, SharedOwnIdentity};
use crate::serve::SharedServeListener;

/// The owner. Cheap to clone; every clone reads the same families.
#[derive(Clone)]
pub(crate) struct SharedSelfReach {
    kad: KadReachLevel,
    kad_presence: KadPresenceView,
    own: SharedOwnIdentity,
    natt: SharedNattFront,
    /// The one serve-listener cell, bound and cleared by the actor's ledger.
    listener: SharedServeListener,
}

impl std::fmt::Debug for SharedSelfReach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSelfReach")
            .field("kad", &self.kad.get())
            .field("kad_running", &self.kad_running())
            .field("server_high_id", &self.server_high_id())
            .field("natt_live", &self.natt_live())
            .field("listener_bound", &self.listener.is_live())
            .finish()
    }
}

impl SharedSelfReach {
    /// The owner over the families' writers: the Kad runtime's published
    /// level, the session self-facts, and the NAT-T front's cell. The listener
    /// cell is the owner's own, handed to the actor through
    /// [`listener`](Self::listener).
    ///
    /// Its Kad Presence is a fresh cell until [`with_kad_presence`](Self::with_kad_presence)
    /// names the Kad runtime's.
    pub(crate) fn new(kad: KadReachLevel, own: SharedOwnIdentity, natt: SharedNattFront) -> Self {
        Self {
            kad,
            kad_presence: KadPresenceView::default(),
            own,
            natt,
            listener: SharedServeListener::default(),
        }
    }

    /// Read "Kad running" from `presence` — the Kad runtime's cell, which its
    /// own surfaces (the serve bridge, the firewalled front) read too.
    pub(crate) fn with_kad_presence(mut self, presence: KadPresenceView) -> Self {
        self.kad_presence = presence;
        self
    }

    /// Whether a Kad node runs — aMule's `Kademlia::IsRunning()`: the Kad
    /// Activity holds its lease (ADR-0093).
    pub(crate) fn kad_running(&self) -> bool {
        self.kad_presence.running_as().is_some()
    }

    /// The Kad Presence cell, for a surface that reads it from a task of its
    /// own.
    pub(crate) fn kad_presence(&self) -> &KadPresenceView {
        &self.kad_presence
    }

    /// The Kad Activity's one lease on the Kad half (ADR-0093):
    /// the verdicts reset to the fresh-node posture and Kad Presence reads
    /// `kad_id` — and on drop, whatever ended the activity, both go back
    /// together.
    pub(crate) fn lease_kad(&self, kad_id: crate::KadId) -> KadRunLease {
        KadRunLease {
            _verdicts: self.kad.lease(),
            _presence: self.kad_presence.lease(kad_id),
        }
    }

    /// The Kad TCP verdict (the ≥2-ack rule, snapshot-while-rechecking).
    pub(crate) fn kad_tcp(&self) -> TcpReachability {
        self.kad.get().tcp
    }

    /// The Kad UDP tester's verdict.
    pub(crate) fn kad_udp(&self) -> UdpReachability {
        self.kad.get().udp
    }

    /// aMule's `!IsFirewalledKad()` (`amule.cpp:1677-1681`): the Kad TCP
    /// verdict reads reachable. A stopped node reads firewalled — its pump
    /// resets the verdicts as it ends.
    pub(crate) fn kad_tcp_open(&self) -> bool {
        self.kad_tcp().is_reachable()
    }

    /// A live eD2k session holds a High ID (`IsConnectedED2K() &&
    /// !IsLowID()`), read from the session self-facts at the call.
    pub(crate) fn server_high_id(&self) -> bool {
        self.own
            .connected_session()
            .is_some_and(|session| session.client_id.is_high_id())
    }

    /// The live session's self-facts as the High-ID family reads them —
    /// for a reader that also needs *which* id (a global callback's
    /// requester contact), so it asks the same owner rather than a second
    /// handle.
    pub(crate) fn session(&self) -> Option<ConnectedSession> {
        self.own.connected_session()
    }

    /// aMule's `IsFirewalled()` (`amule.cpp:1668-1675`): firewalled unless a
    /// server High ID or an open Kad TCP verdict says otherwise.
    pub(crate) fn firewalled(&self) -> bool {
        !self.server_high_id() && !self.kad_tcp_open()
    }

    /// Whether we accept an `OP_DIRECTCALLBACKREQ` (`0x95`) — the publish
    /// connect options' bit `0x08` (`Prefs.cpp:228`): the `IsFirewalled()`
    /// union, and the UDP tester verified open. "Kad running" is carried by
    /// the verdicts themselves: a stopped node's read unverified.
    pub(crate) fn accepts_direct_udp_callback(&self) -> bool {
        self.firewalled() && matches!(self.kad_udp(), UdpReachability::Open { .. })
    }

    /// The hello's `MiscOptions2` direct-callback bit (bit 12): aMule's hello
    /// writer (`BaseClient.cpp:1131-1132`, `4e8f2b3c`) tests the **Kad flag
    /// alone** — `CKademlia::IsFirewalled()` with UDP verified open — not the
    /// `IsFirewalled()` union the publish byte reads, so a server High ID
    /// does not dim it. It is the advert of the `0x95` consume gate, which is
    /// Kad-only too (`ClientUDPSocket.cpp:286`).
    pub(crate) fn hello_direct_udp_callback(&self) -> bool {
        !self.kad_tcp_open() && matches!(self.kad_udp(), UdpReachability::Open { .. })
    }

    /// aMule's `CanDoCallback` (`amule.cpp:1758-1805`) over the families and
    /// the listener conjunct — whether a serve listener is bound.
    pub(crate) fn callback_capability(&self) -> CallbackCapability {
        CallbackCapability::of(
            self.listener.is_live(),
            self.own.connected_session(),
            self.kad_tcp_open(),
        )
    }

    /// The Kad TCP verdict as the diagnostics snapshot states it.
    pub(crate) fn kad_firewall_verdict(&self) -> crate::diagnostics::KadFirewallVerdict {
        match self.kad_tcp() {
            TcpReachability::Open => crate::diagnostics::KadFirewallVerdict::Open,
            TcpReachability::Checking { .. } => crate::diagnostics::KadFirewallVerdict::Checking,
            TcpReachability::Firewalled => crate::diagnostics::KadFirewallVerdict::Firewalled,
        }
    }

    /// What the Kad TCP check has drawn, as the diagnostics snapshot states it.
    pub(crate) fn kad_firewall_check(&self) -> crate::diagnostics::KadFirewallCheck {
        self.kad.get().tcp_check
    }

    /// The Kad UDP verdict as the diagnostics snapshot states it.
    pub(crate) fn kad_udp_verdict(&self) -> crate::diagnostics::KadUdpVerdict {
        match self.kad_udp() {
            UdpReachability::Open { port } => crate::diagnostics::KadUdpVerdict::Open { port },
            UdpReachability::Firewalled => crate::diagnostics::KadUdpVerdict::Firewalled,
            UdpReachability::Unverified => crate::diagnostics::KadUdpVerdict::Unverified,
        }
    }

    /// Whether the NAT-T front's loop still runs.
    pub(crate) fn natt_live(&self) -> bool {
        self.natt.is_live()
    }

    /// The NAT-T front's cell — for the actor that installs and addresses it.
    pub(crate) fn natt(&self) -> &SharedNattFront {
        &self.natt
    }

    /// The serve-listener cell — for the actor's ledger, which binds and
    /// clears it exactly where the serve activity starts and ends.
    pub(crate) fn listener(&self) -> &SharedServeListener {
        &self.listener
    }

    /// Subscribe to the **Reach Generation**: one wake per change to any
    /// family — a Kad start or stop, a Kad verdict write, a session write
    /// (login, re-assignment, end), the NAT-T front's end — and to the
    /// listener (a bind, a clear).
    pub(crate) fn changes(&self) -> ReachGeneration {
        ReachGeneration {
            kad_presence: self.kad_presence.changes(),
            kad: self.kad.subscribe(),
            session: self.own.subscribe_session(),
            listener: self.listener.subscribe(),
            natt_ended: false,
            owner: self.clone(),
        }
    }
}

/// A running Kad Activity's hold on the Kad half of Self Reach (ADR-0093):
/// present exactly as long as this is, and nothing proven once it drops.
/// Fields drop in declaration order: Kad Presence clears, then the verdicts
/// reset.
#[must_use = "dropping the lease is the Kad node's end"]
pub(crate) struct KadRunLease {
    _presence: KadPresenceLease,
    _verdicts: Option<KadVerdictsLease>,
}

/// A subscription to the **Reach Generation**.
///
/// It says only *that* something moved; the subscriber re-reads the owner.
/// A NAT-T front installed after the subscription is announced by no wake —
/// the front is installed at the client-UDP bind, before any subscriber
/// exists, and a reader of it reads at use regardless.
pub(crate) struct ReachGeneration {
    kad_presence: crate::adapters::KadPresenceChanges,
    kad: Option<watch::Receiver<KadVerdicts>>,
    session: watch::Receiver<Option<ConnectedSession>>,
    listener: watch::Receiver<Option<tokio::task::AbortHandle>>,
    natt_ended: bool,
    /// Holds every sender, so no arm can see its channel close and spin.
    owner: SharedSelfReach,
}

impl ReachGeneration {
    /// Wait for the next change. Cancel-safe: every arm is a `watch`
    /// `changed` or an `mpsc::Sender::closed`.
    pub(crate) async fn changed(&mut self) {
        let Self {
            kad_presence,
            kad,
            session,
            listener,
            natt_ended,
            owner,
        } = self;
        tokio::select! {
            () = kad_presence.changed() => {}
            Ok(()) = async {
                match kad.as_mut() {
                    Some(kad) => kad.changed().await,
                    None => pending().await,
                }
            } => {}
            Ok(()) = session.changed() => {}
            Ok(()) = listener.changed() => {}
            () = async {
                if *natt_ended {
                    pending::<()>().await;
                }
                owner.natt.ended().await;
            } => *natt_ended = true,
        }
    }
}

#[cfg(test)]
mod tests;
