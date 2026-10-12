//! **Self Reach**: the one live owner of our own reachability (ADR-0060 "Self Reach").
//!
//! Its families, each with one writer, read through one API:
//!
//! - **Kad running** — **Kad Presence**, whose one lease the Kad Activity in
//!   the actor's ledger holds from start to retire (ADR-0093);
//! - **Kad TCP**, **Kad UDP** and **Kad joined** — the published self-check
//!   verdicts and join latch ([`KadReachLevel`]), written only by the Kad
//!   pump and reset by that same lease at the node's start and end — one
//!   fact, so a reader never sees a stopped node with a live verdict or a
//!   running one with a stale flag;
//! - **Server High ID** — the session self-facts
//!   ([`SharedOwnIdentity::connected_session`]), read, never copied;
//! - **NAT-T front** — [`NattLiveness::is_live`], its liveness alone: the
//!   front's command half rides the wiring of whoever sends to it;
//! - **Client-UDP send half bound** — [`ClientUdpBound`], written by the
//!   client-UDP bind at the actor's prologue and cleared at Quit;
//! - **Server Coordinator live** — [`CoordinatorSession`], written by the
//!   server session as its punch keepalive starts and as it ends.
//!
//! It also carries `CanDoCallback`'s one non-reach conjunct, whether a serve
//! listener is bound ([`SharedServeListener`]), so that answer is
//! composed here too and its moves wake the same generation — and the
//! **Advertised IPv6** the Dial Chooser reads, so the route tree's whole
//! half of a decision is one read ([`SharedSelfReach::route_position`]).
//!
//! The union rules aMule answers every reader with live
//! (`IsFirewalledKad`, `IsFirewalled`, `CanDoCallback`, the direct-callback
//! bit, `GetID`; `amule.cpp:1668-1805`, `amule.cpp:2043-2059`,
//! `Prefs.cpp:228`, `4e8f2b3c`) live here and
//! nowhere else: a reader asks the question and never composes two facts
//! itself. A reader that must cache subscribes to the **Reach Generation**
//! ([`SharedSelfReach::changes`]) and re-derives on it.

use std::future::pending;

use rmule_primitives::ClientId;
use tokio::sync::watch;

use super::{
    ClientUdpBound, KadReachLevel, KadVerdicts, KadVerdictsLease, TcpReachability, UdpReachability,
};
use crate::adapters::{KadPresenceLease, KadPresenceView, SharedIpv6Advert};
use crate::callback::RoutePosition;
use crate::dialable::DialPosition;
use crate::download::CallbackCapability;
use crate::natt::front::{NattLiveness, SharedNattFront};
use crate::natt::server_punch::CoordinatorSession;
use crate::own_identity::{ConnectedSession, SharedOwnIdentity};
use crate::serve::{BoundListener, SharedServeListener};
use crate::server_session::SessionLink;

/// The owner. Cheap to clone; every clone reads the same families.
#[derive(Clone)]
pub(crate) struct SharedSelfReach {
    kad: KadReachLevel,
    kad_presence: KadPresenceView,
    own: SharedOwnIdentity,
    natt: NattLiveness,
    client_udp: ClientUdpBound,
    server_coordinator: CoordinatorSession,
    /// The **Advertised IPv6** (ADR-0087), the Advertised Endpoints
    /// chooser's verdict: read through, never owned here.
    ipv6_advert: SharedIpv6Advert,
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
            .field("client_udp_bound", &self.client_udp.is_bound())
            .field(
                "server_coordinator_live",
                &self.server_coordinator.is_live(),
            )
            .field("listener_bound", &self.listener.is_live())
            .finish()
    }
}

impl SharedSelfReach {
    /// The owner over the families' writers: the Kad runtime's published
    /// level, the session self-facts, and the NAT-T front's cell — of which
    /// it keeps the liveness alone. The listener cell is the owner's own,
    /// handed to the actor through [`listener`](Self::listener).
    ///
    /// Its Kad Presence, client-UDP and Server Coordinator families and its
    /// Advertised IPv6 are fresh cells — nothing running, nothing bound,
    /// nothing live, no address — until the `with_*` builders name the
    /// writers' own.
    pub(crate) fn new(kad: KadReachLevel, own: SharedOwnIdentity, natt: SharedNattFront) -> Self {
        Self {
            kad,
            kad_presence: KadPresenceView::default(),
            own,
            natt: natt.liveness(),
            client_udp: ClientUdpBound::default(),
            server_coordinator: CoordinatorSession::default(),
            ipv6_advert: SharedIpv6Advert::default(),
            listener: SharedServeListener::default(),
        }
    }

    /// Read "client-UDP send half bound" from `bound` — the cell the
    /// client-UDP bind writes.
    pub(crate) fn with_client_udp(mut self, bound: ClientUdpBound) -> Self {
        self.client_udp = bound;
        self
    }

    /// Read "Server Coordinator live" from `session` — the cell the server
    /// session writes.
    pub(crate) fn with_server_coordinator(mut self, session: CoordinatorSession) -> Self {
        self.server_coordinator = session;
        self
    }

    /// Read the Advertised IPv6 the route position carries from `advert`.
    pub(crate) fn with_ipv6_advert(mut self, advert: SharedIpv6Advert) -> Self {
        self.ipv6_advert = advert;
        self
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

    /// aMule's `CKademlia::IsConnected()` (`HasHadContact`, `Kademlia.h:76`):
    /// a node runs and has heard a counterparty since it started.
    pub(crate) fn kad_connected(&self) -> bool {
        self.kad_running() && self.kad.get().joined
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

    /// The TCP port we present now for the Core Settings' `configured` one,
    /// by the hello's rule ([`presented_tcp_port`]) over the same
    /// self-facts — for a global callback's requester contact.
    ///
    /// [`presented_tcp_port`]: crate::server_session::presented_tcp_port
    pub(crate) fn presented_tcp_port(&self, configured: u16) -> u16 {
        crate::server_session::presented_tcp_port(configured, &self.own)
    }

    /// The **Presented Client ID**: the id every hello and hello answer names
    /// for us, in aMule's `GetID` order (`amule.cpp:2043-2059`, eMuleAI
    /// `Emule.cpp:2673-2680`):
    ///
    /// 1. Kad connected and its TCP verdict open: our address, as a High ID —
    ///    aMule trusts Kad above eD2k, so a server Low ID does not hide it;
    /// 2. else a live session: the id the server assigned last;
    /// 3. else Kad connected and firewalled: `1`, the id a peer reads as a
    ///    Low ID — never `0`, which aMule takes for "use the address I see"
    ///    (`BaseClient.cpp:678`) and so for a High ID;
    /// 4. else `0`.
    ///
    /// Our address is the **Address Learning** verdict (aMule reads the
    /// Kad-confirmed `CKademlia::GetIPAddress()`); an open verdict with no
    /// address learned yet is no address to name, and falls through.
    pub(crate) fn presented_client_id(&self) -> ClientId {
        let kad_connected = self.kad_connected();
        if kad_connected
            && self.kad_tcp_open()
            && let Some(address) = self.own.public_ip()
        {
            return ClientId::from_u32(u32::from_le_bytes(address.octets()));
        }
        if let Some(session) = self.own.connected_session() {
            return session.client_id;
        }
        if kad_connected && !self.kad_tcp_open() {
            return ClientId::from_u32(1);
        }
        ClientId::from_u32(0)
    }

    /// The eD2k ID: the id the live server session holds, or `0` with none —
    /// aMule's `GetED2KID` (`amule.cpp:2039-2041`). Unlike the Presented
    /// Client ID it never reads Kad; the Secure User Identification V2
    /// challenge IP keys on it (`BaseClient.cpp:2096-2104`).
    pub(crate) fn ed2k_client_id(&self) -> ClientId {
        self.own
            .connected_session()
            .map_or_else(|| ClientId::from_u32(0), |session| session.client_id)
    }

    /// Our public IPv4 as Address Learning holds it: aMule's
    /// `GetPublicIP(true)`.
    pub(crate) fn public_ip(&self) -> Option<std::net::Ipv4Addr> {
        self.own.public_ip()
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
    /// the listener conjunct — whether a serve listener is bound — with
    /// whether Kad is connected, for the source loop's `IsConnected()`.
    pub(crate) fn callback_capability(&self) -> CallbackCapability {
        CallbackCapability::of(
            self.listener.is_live(),
            self.own.connected_session(),
            self.kad_tcp_open(),
        )
        .with_kad_connected(self.kad_connected())
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

    /// Our own half of the ADR-0061 route tree, in one read: aMule's
    /// `!IsFirewalled()` (`amule.cpp:1668-1675`, a server High ID or an open
    /// Kad TCP verdict), the client-UDP send half bound, Kad running, the
    /// Advertised IPv6 rung 0 pairs with a peer's (ADR-0087), and whether the
    /// Server Coordinator can introduce us (ADR-0091) — each a family read at
    /// this call, so a reader is handed a position and composes none.
    pub(crate) fn route_position(&self) -> RoutePosition {
        RoutePosition {
            reachable: !self.firewalled(),
            udp_on: self.client_udp.is_bound(),
            kad_running: self.kad_running(),
            dial: DialPosition {
                known_ipv6: self.ipv6_advert.get(),
            },
            server_punch: self.server_coordinator.is_live(),
        }
    }

    /// The port a callback invites the target to dial back on: the bound
    /// serve listener's, while its activity runs. `None` with no listener —
    /// there is nothing to invite a dial to.
    pub(crate) fn listener_port(&self) -> Option<u16> {
        self.listener.port()
    }

    /// The serve-listener cell — for the actor's ledger, which binds and
    /// clears it exactly where the serve activity starts and ends.
    pub(crate) fn listener(&self) -> &SharedServeListener {
        &self.listener
    }

    /// Subscribe to the **Reach Generation**: one wake per change to any
    /// family — a Kad start or stop, a Kad verdict write, a session write
    /// (login, re-assignment, end), the NAT-T front's end, the client-UDP
    /// bind or its clear, the Server Coordinator going live or dark — and to
    /// the listener (a bind, a clear).
    pub(crate) fn changes(&self) -> ReachGeneration {
        ReachGeneration {
            kad_presence: self.kad_presence.changes(),
            kad: self.kad.subscribe(),
            session: self.own.subscribe_session(),
            listener: self.listener.subscribe(),
            client_udp: self.client_udp.subscribe(),
            server_coordinator: self.server_coordinator.subscribe(),
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
    listener: watch::Receiver<Option<BoundListener>>,
    client_udp: watch::Receiver<bool>,
    server_coordinator: watch::Receiver<Option<SessionLink>>,
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
            client_udp,
            server_coordinator,
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
            Ok(()) = client_udp.changed() => {}
            Ok(()) = server_coordinator.changed() => {}
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
