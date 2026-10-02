//! The shared **session slot** (ADR-0032): the one cross-activity cell that
//! holds the live server-session handle, the self-facts the login is the only
//! source of (ADR-0046), the operator's standing server choice,
//! the in-flight operator-connect claim that serializes activities behind an
//! explicit connect, and the **Session Generation** a follower
//! wakes on. Activities and adapters clone the cell, not the handle: the slot
//! is `None` until the operator's connect establishes a session, and nothing
//! refills it after a disconnect but that connect's intent re-making a lost
//! session or the next connect (ADR-0095, "Connecting is the operator's act",
//! "A lost session is re-made").

use std::sync::Arc;

use tokio::sync::{Mutex, watch};

use super::ServerSessionHandle;
use crate::own_identity::SharedOwnIdentity;
use crate::reachability::SharedIpv6Probe;
use crate::server_list::ServerFacts;

/// The shared server-session slot the production source-lookup and serve
/// adapters consult, paired with the **self-facts** the session is the only
/// source of.
///
/// The slot itself is `None` until the operator's connect establishes the
/// session; a dead handle (`!is_alive()`) stays until the next connect replaces
/// it. The
/// [`SharedOwnIdentity`] rides alongside because logging in is precisely where
/// rmule learns who it is on the wire — the credentials it presents and the
/// public IP the server reports back in `OP_IDCHANGE` — and those facts outlive
/// any one session handle. Layers that bound before the login (the UDP crypt
/// surfaces) hold a clone of the cell, not of the handle.
#[derive(Clone)]
pub(crate) struct SharedServerSession {
    slot: Arc<Mutex<Option<ServerSessionHandle>>>,
    own: SharedOwnIdentity,
    /// What the connected server said about reaching us over IPv6
    /// (`ST_IPV6_STATUS`, ADR-0084). It rides the session cell for the same
    /// reason the self-facts do: the session is its only writer and its
    /// lifetime, and the layers that read it were woven before the login.
    ipv6_probe: SharedIpv6Probe,
    /// The live `CT_EMULE_UDPPORTS` advert (ADR-0057/0047): rmule's bound
    /// client-UDP port while it serves, and the running Kad node's port.
    ///
    /// It rides here for the same reason [`ipv6_advert`](Self::ipv6_advert)
    /// does: the login's `0xF9` UDP-ports advert is built by *establishment*,
    /// off the actor, and its Kad half must say what the hello's says —
    /// "which port is your Kad node on, if one runs at all". One cell, so the
    /// login and the hello cannot disagree.
    udp_ports_advert: crate::adapters::SharedUdpPortsAdvert,
    /// The **server coordinator** (ADR-0091): the punch ledger, the
    /// client-UDP send half its burst and keepalive leave by, and whether the
    /// live session is one the server can introduce us through. It rides
    /// here because establishment advertises and starts the keepalive, the
    /// multiplexer hears the answers, and the actor chooses the route — and
    /// all three already hold this cell.
    server_punch: crate::natt::server_punch::SharedServerPunch,
    /// The **Interface Source** (ADR-0084), installed by `Core::builder`.
    ///
    /// It rides here because *connecting to a server* is one of the three
    /// moments the ADR polls at — a session is exactly when a host's routing
    /// may have changed under us — and establishment happens off the actor,
    /// which owns the other two. `None` for a core built without one.
    interfaces: Arc<std::sync::OnceLock<Arc<dyn rmule_net::interfaces::InterfaceSource>>>,
    /// Where the connected server's welcome burst lands (ADR-0080 §Dynamic
    /// server facts). Late-bound: the adapters that hold this cell are woven
    /// before the actor exists, and the actor owns both the list store and the
    /// diagnostics level the facts are written to, so it installs the pair
    /// before it takes its first command.
    facts: Arc<std::sync::OnceLock<ServerFacts>>,
    /// The **Session Generation**: bumped each time an establishment installs
    /// a live session, so a follower that must act on every new session — the
    /// serve's hello context and announce, the actor's waiting searches —
    /// wakes without polling the slot.
    sessions: Arc<watch::Sender<u64>>,
    /// The operator connect currently in flight, if any. The
    /// `ConnectToServer` handler installs it **synchronously at command
    /// accept** — before the connect task is spawned, so no scheduling can
    /// reorder the claim — and the receiver closes when that connect resolves,
    /// however it ends. [`live_session`](Self::live_session) waits for a
    /// live claim before touching the slot: command order is establishment
    /// order, and an activity racing the connect rides the operator's session
    /// rather than the one the connect is about to end.
    ///
    /// A `std::sync::Mutex`: one small value, never held across an await.
    pending_connect: Arc<std::sync::Mutex<Option<watch::Receiver<()>>>>,
    /// How long a dialed server may leave the login unanswered.
    ///
    /// Late-bound like [`facts`](Self::facts), and for the same reason: the
    /// adapters holding this cell are woven before the actor that knows the
    /// [`CoreConfig`](crate::CoreConfig) exists. Unset means the eD2k
    /// connection layer's own default, which is the value core's default
    /// config also names.
    login_timeout: Arc<std::sync::OnceLock<std::time::Duration>>,
    /// The **Announce Policy** (ADR-0099): whether the share set is withheld
    /// from a server that grants related search. Rides the session cell
    /// because the serve's follower, which applies it to each session, was
    /// woven before the actor that reads it from the store exists; a `watch`,
    /// so a change reaches the live session at once.
    withhold_shares: Arc<watch::Sender<bool>>,
}

impl Default for SharedServerSession {
    /// A fresh cell whose adverts project through its own self-facts'
    /// Address Learning store — the one owner every advert reads.
    fn default() -> Self {
        let own = SharedOwnIdentity::default();
        Self {
            udp_ports_advert: crate::adapters::SharedUdpPortsAdvert::over(own.addresses().clone()),
            own,
            slot: Arc::default(),
            ipv6_probe: SharedIpv6Probe::default(),
            server_punch: crate::natt::server_punch::SharedServerPunch::default(),
            interfaces: Arc::default(),
            facts: Arc::default(),
            sessions: Arc::new(watch::channel(0).0),
            pending_connect: Arc::default(),
            login_timeout: Arc::default(),
            withhold_shares: Arc::new(watch::channel(false).0),
        }
    }
}

/// Proof that an operator `ConnectToServer` is in flight.
/// Dropping it — the connect resolved, succeeded or not, or its task died —
/// releases every activity waiting in
/// [`live_session`](SharedServerSession::live_session). Resolution *is* the drop, so no
/// failure path can strand a waiter.
pub(crate) struct OperatorConnectClaim {
    _resolved_on_drop: watch::Sender<()>,
}

impl SharedServerSession {
    /// The self-facts cell every UDP crypt surface reads (ADR-0046).
    pub(crate) fn own_identity(&self) -> &SharedOwnIdentity {
        &self.own
    }

    /// The server-told IPv6 probe verdict (ADR-0084) — written by the session,
    /// read by the **Advertised Endpoints** chooser.
    pub(crate) fn ipv6_probe(&self) -> &SharedIpv6Probe {
        &self.ipv6_probe
    }

    /// The **server coordinator** (ADR-0091).
    pub(crate) fn server_punch(&self) -> &crate::natt::server_punch::SharedServerPunch {
        &self.server_punch
    }

    /// The **Advertised IPv6** (ADR-0087) the login's `CT_MOD_IP_V6` tag and
    /// its coupled `SRVCAP_IPV6` bit ride, and the builder clones into every
    /// hello, the Kad publisher and both dial roads — a view over this cell's
    /// own Address Learning store and probe verdict, so the login and a hello
    /// can never name different addresses and none of them caches one.
    pub(crate) fn ipv6_advert(&self) -> crate::adapters::SharedIpv6Advert {
        crate::adapters::SharedIpv6Advert::over(
            self.own.addresses().clone(),
            self.ipv6_probe.clone(),
        )
    }

    /// The live `CT_EMULE_UDPPORTS` advert cell (ADR-0057/0047).
    pub(crate) fn udp_ports_advert(&self) -> &crate::adapters::SharedUdpPortsAdvert {
        &self.udp_ports_advert
    }

    /// Bind the **Interface Source** every poll site shares. Idempotent — the
    /// first install (the builder's) is the one that stands.
    pub(crate) fn install_interfaces(
        &self,
        source: Arc<dyn rmule_net::interfaces::InterfaceSource>,
    ) {
        let _ = self.interfaces.set(source);
    }

    /// Whether a source was installed at all.
    pub(crate) fn has_interface_source(&self) -> bool {
        self.interfaces.get().is_some()
    }

    /// Re-poll the **Interface Source** and hand the result to **Address
    /// Learning** (ADR-0084). A no-op with no source installed, which is the
    /// honest answer for a core that was never given one: it holds no
    /// interface tier and no corroboration evidence, rather than a stale set.
    pub(crate) fn refresh_interfaces(&self) {
        if let Some(source) = self.interfaces.get() {
            self.own.addresses().refresh_interfaces(&source.addresses());
        }
    }

    /// The live handle slot, for callers that read it without establishing.
    pub(crate) fn slot(&self) -> &Mutex<Option<ServerSessionHandle>> {
        &self.slot
    }

    /// Bind the actor's list store and diagnostics level as the destination
    /// for every session's welcome burst. Idempotent — a second install is
    /// ignored, so the first (the actor's) is the one that stands.
    pub(crate) fn install_facts(&self, facts: ServerFacts) {
        let _ = self.facts.set(facts);
    }

    /// The installed destination, or a private sink for a session established
    /// without an actor (the adapter unit tests).
    pub(crate) fn server_facts(&self) -> &ServerFacts {
        self.facts.get_or_init(ServerFacts::default)
    }

    /// Bind the login deadline every establishment arms its connection with
    /// Idempotent — the first install (the actor's, off
    /// `CoreConfig`) is the one that stands.
    pub(crate) fn install_login_timeout(&self, timeout: std::time::Duration) {
        let _ = self.login_timeout.set(timeout);
    }

    /// The installed login deadline, or the eD2k connection layer's default
    /// for a session established without an actor.
    pub(crate) fn login_timeout(&self) -> std::time::Duration {
        self.login_timeout
            .get()
            .copied()
            .unwrap_or_else(|| rmule_net::ed2k::ConnectOptions::default().login_timeout)
    }

    /// The live session, or `None` — and never a dial (ADR-0093, "Connecting
    /// is the operator's act"). An operator connect in flight is waited out
    /// first: the handle in the slot may be the one that connect
    /// is about to end, and the session it makes is the one to ride.
    pub(crate) async fn live_session(&self) -> Option<ServerSessionHandle> {
        self.wait_for_operator_connect().await;
        self.session_in_slot().await
    }

    /// The live session as it stands this instant, for a caller that must not
    /// wait (the actor): `None` while an operator connect is in flight, since
    /// the session it makes is the one to ride, and `None` with no session.
    pub(crate) async fn session_now(&self) -> Option<ServerSessionHandle> {
        if self.operator_connect_pending() {
            return None;
        }
        self.session_in_slot().await
    }

    /// The live handle in the slot, if any, read without regard to an
    /// operator connect in flight — for a follower woken by the **Session
    /// Generation**, whose bump comes before that connect's claim drops.
    pub(crate) async fn session_in_slot(&self) -> Option<ServerSessionHandle> {
        self.slot
            .lock()
            .await
            .as_ref()
            .filter(|handle| handle.is_alive())
            .cloned()
    }

    /// Take up the **Announce Policy**; a follower re-decides the live
    /// session at once when it changes.
    pub(crate) fn set_withhold_shares(&self, withhold: bool) {
        self.withhold_shares.send_if_modified(|held| {
            let changed = *held != withhold;
            *held = withhold;
            changed
        });
    }

    /// The **Announce Policy** as it stands, woken on each change.
    pub(crate) fn withhold_shares(&self) -> watch::Receiver<bool> {
        self.withhold_shares.subscribe()
    }

    /// Wake on every session an establishment installs from now on.
    pub(crate) fn session_changes(&self) -> watch::Receiver<u64> {
        self.sessions.subscribe()
    }

    /// Record that a live session was just installed in the slot.
    pub(crate) fn session_established(&self) {
        self.sessions.send_modify(|generation| *generation += 1);
    }

    /// Claim establishment authority for an operator connect.
    /// Called by the `ConnectToServer` handler on the actor, before the
    /// connect task is spawned; the claim moves into that task and its drop —
    /// success, failure, or panic — is the release.
    pub(crate) fn claim_connect(&self) -> OperatorConnectClaim {
        let (tx, rx) = watch::channel(());
        *self
            .pending_connect
            .lock()
            .expect("pending connect lock poisoned") = Some(rx);
        OperatorConnectClaim {
            _resolved_on_drop: tx,
        }
    }

    /// Whether an operator connect holds establishment authority right now
    /// — read synchronously, so a caller on the actor sees the
    /// claim the same command just took.
    pub(crate) fn operator_connect_pending(&self) -> bool {
        self.pending_connect
            .lock()
            .expect("pending connect lock poisoned")
            .as_ref()
            .is_some_and(|rx| rx.has_changed().is_ok())
    }

    /// Park until no operator connect is in flight. Returns
    /// immediately when none was ever claimed or the last one has resolved;
    /// otherwise waits for the claim to drop — which the connect's own
    /// connect/login timeouts bound, so a caller can never hang here.
    pub(crate) async fn wait_for_operator_connect(&self) {
        loop {
            let live = {
                let pending = self
                    .pending_connect
                    .lock()
                    .expect("pending connect lock poisoned");
                match pending.as_ref() {
                    // `has_changed` errors once the sender dropped — a
                    // resolved claim is the same as none.
                    Some(rx) if rx.has_changed().is_ok() => Some(rx.clone()),
                    _ => None,
                }
            };
            let Some(mut rx) = live else { return };
            // The claim never sends a value; the sender dropping (`Err`) is
            // the resolution. Loop to catch a newer claim installed since.
            let _ = rx.changed().await;
        }
    }
}
