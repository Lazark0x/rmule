//! The serve-side runtime adapter (ADR-0031): the bound `PeerListener` accept
//! pump, the **Session Follower** that points its hellos and its
//! `OP_OFFERFILES` announce at whatever session the operator makes (ADR-0032,
//! ADR-0095) — the whole socket concern behind one seam so core owns policy
//! and stays socket-free.

use std::future::Future;
use std::net::SocketAddrV4;
use std::time::Duration;

use rmule_ed2k::OfferedFile;
use rmule_net::family::FamilySelection;
use rmule_net::peer::{PeerListener, PeerNetError};
use tokio::sync::mpsc;

use crate::CoreError;
use crate::ban_store::SharedBanStore;
use crate::buddy_link::SharedBuddySlot;
use crate::ip_filter::SharedIpFilter;
use crate::server_session::SharedServerSession;
use crate::service::{LoginStep, PortTestEnd, SharesWithheld};

mod accept;
mod connection;
mod follower;
mod test_connection;

pub use connection::{ServeConnection, ServeInput, ServeOutput};

use accept::{AcceptGates, spawn_accept_pump};
pub(crate) use accept::{AdmittedPeer, SharedTunnelAdmit};
use follower::SessionFollower;

use super::HelloAdverts;
use super::awaited_inbound::AwaitedInbound;
use super::dialed_serve::SharedDialedServeSink;
use super::inbound_triage::{InboundEnd, InboundPeerDeps, triage_inbound_connection};
use super::kad_runtime::{KadPresenceView, SharedKadBootstrap, SharedKadPump};

/// The serve-side runtime adapter (ADR-0031): the socket concern behind one
/// seam, so core owns policy and stays socket-free. The sibling of
/// [`SourceLookupService`](crate::SourceLookupService) / [`PeerTransferService`](crate::PeerTransferService).
///
/// The server login is the operator's (ADR-0095), held in the shared
/// `ServerSession` (ADR-0032): a started adapter follows it for the High-ID
/// `client_id` its hellos carry and the session its announce rides, and
/// never opens one.
pub trait ServeRuntimeService: Send + 'static {
    /// Bind the inbound listener on `listen_addr` (port 0 = OS-chosen) and
    /// return the bound address — **the bind is the whole contract**. It dials no server: the
    /// listener follows whatever session the operator makes (ADR-0095), and is accepting whether
    /// or not one ever exists. `identity` is the node's wire identity — the Core
    /// Settings' credentials as the build-time hash; one naming port `0`
    /// names the port bound. When the Hello
    /// Adverts carry a SUI keypair (ADR-0041), accepted
    /// connections run Secure User Identification.
    ///
    /// # Errors
    /// The listener did not bind. Nothing was started, and the adapter is
    /// intact: the caller may start it again.
    fn start(
        &mut self,
        identity: rmule_primitives::ClientIdentity,
        listen_addr: SocketAddrV4,
    ) -> impl Future<Output = Result<SocketAddrV4, CoreError>> + Send;

    /// Await the next accepted, identified serve connection. `None` once the
    /// listener is closed (the serve activity then winds down).
    fn accept(&mut self) -> impl Future<Output = Option<ServeConnection>> + Send;

    /// How many admitted peers are still queued behind the one
    /// [`accept`](Self::accept) just handed over — the **accept backlog**.
    ///
    /// Sampled by the serve runner immediately after each accept, which is the
    /// deepest the channel is ever *seen*: the runner has just come back from
    /// whatever it was doing, so the queue holds everything that arrived while
    /// it was away. The runner adds the peer it took, so the gauge reads as a
    /// depth rather than as a remainder.
    ///
    /// `None` for an adapter with no such channel, whose backlog is not a fact
    /// — never `Some(0)`, which would claim a measurement.
    fn accept_backlog(&self) -> Option<usize> {
        None
    }

    /// Send `OP_OFFERFILES` over the live server session, and to every session
    /// the operator makes after it, as the **Announce Policy** allows.
    /// Re-called whenever the share set changes; with no session the set waits
    /// for one, and what that session is told arrives from
    /// [`take_session_told`](Self::take_session_told).
    fn announce(
        &mut self,
        files: Vec<OfferedFile>,
    ) -> impl Future<Output = Result<AnnounceOutcome, CoreError>> + Send;

    /// Take the stream of what each session made after an
    /// [`announce`](Self::announce) was told of the set, each time it is news;
    /// the start's follower has one, taken once. `None` by default: an adapter
    /// that follows no session has nothing later to say.
    fn take_session_told(&mut self) -> Option<mpsc::UnboundedReceiver<AnnounceOutcome>> {
        None
    }

    /// Undo what [`start`](Self::start) installed and leave this adapter
    /// startable again: the listener down, its port free, and
    /// every cell the start filled emptied.
    ///
    /// Awaited by the activity that ends, so "the adapter is back" and "the
    /// port is free" are one fact — a second start on the same port binds it.
    /// The default releases nothing, which is the truth for an adapter that
    /// binds nothing.
    fn release(&mut self) -> impl Future<Output = ()> + Send {
        std::future::ready(())
    }

    /// Re-point a served link's `0x99`/`0x95` Kad gate at `kad_presence`
    /// `CoreBuilder::kad` calls this on whichever runtime is
    /// currently installed, so a swapped-in factory's own **Kad Presence**
    /// reaches it too — the default wiring bound this runtime to the
    /// *default* factory's view, which a later `.kad()` would otherwise
    /// orphan. Default no-op: a fake that gates on nothing need not track it.
    fn set_kad_presence(&mut self, _kad_presence: KadPresenceView) {}

    /// Adopt the builder's one set of `AdapterCells`
    /// (ADR-0048 "Identity ownership"):
    /// `Core::builder` weaves its own runtime through this, and
    /// `CoreBuilder::serve_runtime` calls it on the runtime it installs, so an
    /// injected runtime's accepts meet the node's session, ban store, IP
    /// filter, Peer Roster, Awaited Inbound registry and Hello Adverts — never
    /// a private copy of any. Default no-op: a fake that accepts nothing holds
    /// no cell.
    fn adopt_cells(&mut self, _cells: &super::AdapterCells) {}
}

/// What an announce did with the share set — the fact the serve raises as
/// [`ServeEvent::FilesAnnounced`](crate::ServeEvent::FilesAnnounced) or
/// [`ServeEvent::FilesWithheld`](crate::ServeEvent::FilesWithheld).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnnounceOutcome {
    /// `OP_OFFERFILES` went out with `file_count` files.
    Announced {
        /// How many files the offer carried.
        file_count: usize,
    },
    /// The **Announce Policy** kept the set of `file_count` files from the
    /// server; nothing went on the wire.
    Withheld {
        /// How many files the set held.
        file_count: usize,
        /// Why the server was not told them.
        reason: SharesWithheld,
    },
    /// Nothing was said: there is no session to tell yet, or the live one
    /// already holds this set.
    Unsaid,
}

/// The production serve runtime: a bound `PeerListener` plus a handle to the
/// shared `ServerSession` (ADR-0032). The session — not this adapter — owns the
/// logged-in ed2k `Connection`, which only the operator's connect makes; this
/// adapter follows it for the High-ID `client_id` and routes `OP_OFFERFILES`
/// through it, so source-lookup and the serve announce share one login.
#[derive(Default)]
pub struct RuntimeServeRuntimeService {
    /// Ready connections from the accept pump `start` spawned. A dedicated
    /// task owns the `PeerListener` because `accept` is raced inside the serve
    /// runner's `select!`: with obfuscation armed the listener's accept holds
    /// an already-accepted `TcpStream` across the byte-0 peek await, and
    /// cancelling that future mid-peek silently drops (FINs) the peer — the
    /// interop bench observed a stock aMule's source dial die exactly that way
    /// whenever another serve-loop branch woke first. An
    /// `mpsc::Receiver::recv` is cancel-safe, and every connection on the
    /// channel has already passed the **Accept Gates**, so the race is
    /// harmless.
    accept_rx: Option<mpsc::Receiver<AdmittedPeer>>,
    /// The pump task itself, held only so [`release`](ServeRuntimeService::release)
    /// can *await* its end: dropping `accept_rx` tells it to stop, and joining
    /// it is what makes the bound port free by the time a restart asks for it.
    accept_pump: Option<tokio::task::JoinHandle<()>>,
    session: SharedServerSession,
    /// The **Session Follower** the last `start` spawned; `None` before the
    /// first start and after a release, where an announce is refused.
    follower: Option<SessionFollower>,
    /// The **Awaited Inbound** registry (ADR-0039, ADR-0091) the accept-router
    /// asks who gets an identified connection, plus what it needs to build an
    /// adopted download worker over it. Default/empty on the non-`Core::new`
    /// constructors, whose adapters never adopt: nothing is filed there, so
    /// every inbound peer and every admitted tunnel is served as before.
    awaited_inbound: AwaitedInbound,
    slot_wait_timeout: Duration,
    dialed_serve_sink: SharedDialedServeSink,
    /// The core-owned `BanStore` (ADR-0064), the second **Accept Gate**.
    /// Default/empty on the non-`Core::new` constructors (nothing is ever
    /// banned); `Core::builder` shares one instance across this adapter,
    /// `RuntimePeerTransferService`, and the Kad event fold.
    ban_store: SharedBanStore,
    /// The ed2k→Kad handoff sink (ADR-0067): each accepted peer that carries a
    /// Kad node hint is brokered to the running node through it. Default/empty on
    /// the non-`Core::new` constructors (no handoff); `Core::builder` shares one
    /// instance across this adapter, `RuntimePeerTransferService`, and the Kad
    /// factory (which installs its sender on start).
    kad_bootstrap: SharedKadBootstrap,
    /// The running Kad node's out-of-band signal sink (ADR-0058): an accepted
    /// peer's `OP_KAD_FWTCPCHECK_ACK` — the connect-back that proves *our* TCP
    /// port open — is carried to the node through it. Default/empty on the
    /// non-`Core::new` constructors (no Kad node, so nothing asked for a
    /// connect-back); `Core::builder` shares the one instance the Kad factory
    /// fills on start.
    kad_pump: SharedKadPump,
    /// The core-owned Peer Roster (ADR-0059): fed here on every
    /// upload-queue grant/queue/release, and read by inbound triage for the
    /// helper-bias question. Default/empty on the non-`Core::new`
    /// constructors (nothing is ever known); `Core::builder` shares the one
    /// production instance with inbound triage's `InboundPeerDeps` and the
    /// Kad factory's requester gate.
    peer_roster: crate::peer_roster::SharedPeerRoster,
    /// What every accepted peer's hello states about this node, read per
    /// accept: the live `CT_EMULE_UDPPORTS` ports (ADR-0057), the
    /// **Advertised IPv6** (ADR-0087), the firewalled slot's serving buddy
    /// and our obfuscation policy, which also arms the
    /// accept's dual-path byte-0 peek. Default/empty on the non-`Core::new`
    /// constructors (no advert of any kind, plaintext only); `Core::builder`
    /// shares the one instance every hello-sending road reads.
    adverts: HelloAdverts,
    /// The enacted buddy slot (socket unification, ADR-0061): an accepted
    /// inbound peer whose identity matches the recruited buddy attaches here as
    /// the held persistent link relays/pongs ride. Default/empty on the
    /// non-`Core::new` constructors (never recruited → never attaches);
    /// `Core::builder` shares the one instance with the Kad factory and the
    /// client-UDP front.
    buddy_slot: SharedBuddySlot,
    /// The core-owned IP filter, the first **Accept Gate**. Default/empty on
    /// the non-`Core::new` constructors (nothing is ever filtered);
    /// `Core::builder` shares one instance across this adapter, both peer
    /// adapters, and the runner's ingest gates.
    ip_filter: SharedIpFilter,
    /// Which **Address Families** the inbound listener's Family Pair binds
    /// (`CoreConfig::address_families`, ADR-0085). Both by default; a literal
    /// listen address overrides it with the family it names.
    address_families: FamilySelection,
    /// Where a risen NAT-T **Tunnel** joins this adapter's accept channel
    /// (ADR-0091). Filled at every `start`, so a punched path meets the IP
    /// filter, the ban gate and `inbound_triage` exactly as a TCP accept
    /// does. Default/empty on the non-`Core::new` constructors — nothing
    /// drives a tunnel there, and an unfilled cell simply refuses one.
    tunnel_admit: SharedTunnelAdmit,
    /// Where an accepted peer's refused hello is reported (ADR-0050).
    hello_refusals: crate::hello_refusals::SharedHelloRefusals,
    /// **Kad Presence**: a served link's `0x99` is read against
    /// the running node's own Kad ID. Default on the non-`Core::builder`
    /// constructors — a view of no node, so every `0x99` drops `KadDown`;
    /// `Core::builder` hands in the Kad factory's own view.
    kad_presence: KadPresenceView,
    /// The file-known predicate a served link's `0x99` consults.
    /// Default/empty on the non-`Core::builder` constructors (nothing known);
    /// `Core::builder` shares the one instance the actor's serve and download
    /// arms keep current.
    file_known: crate::known_files::SharedFileKnown,
    /// Where each served link is filed for a download of its peer to ride
    /// (ADR-0107). Default/unshared off `Core::builder`: no download joins.
    peer_links: super::SharedPeerLinks,
}

impl RuntimeServeRuntimeService {
    /// Construct with its **own**, unshared session slot, which no connect
    /// ever fills; `Core::builder` shares the node's one slot instead
    /// (`adopt_cells`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Share the core-owned `BanStore` (ADR-0064): every accepted
    /// connection is checked against it before it reaches the accept channel.
    /// `Core::builder` wires the one production instance in; the default
    /// (unset) store bans nothing.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_ban_store(mut self, ban_store: SharedBanStore) -> Self {
        self.ban_store = ban_store;
        self
    }

    /// Share the one [`HelloAdverts`]: an accepted peer's hello
    /// states what every other hello this node sends states — ports, IPv6,
    /// serving buddy, crypt — each read per accept. Honest Capability
    /// Advertisement (ADR-0057): the crypt advert and the dual-path accept are
    /// lit by the same policy, so rmule never claims a crypt tier this adapter
    /// would refuse. `Core::builder` wires the one production instance in; the
    /// default states nothing and accepts plaintext only.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_hello_adverts(mut self, adverts: HelloAdverts) -> Self {
        self.adverts = adverts;
        self
    }

    /// Share the core-owned IP filter: every accepted connection
    /// is checked against it before the ban gate and the accept channel.
    /// `Core::builder` wires the
    /// one production instance in; the default (empty) filter blocks nothing.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_ip_filter(mut self, ip_filter: SharedIpFilter) -> Self {
        self.ip_filter = ip_filter;
        self
    }

    /// Share the NAT-T **Tunnel** admit cell (ADR-0091): a punched path's
    /// risen tunnel enters through this adapter's own accept channel, with the
    /// same handshake context and per-accept options a TCP accept gets.
    /// `Core::builder` wires the one production instance in; the default
    /// (empty) cell refuses every tunnel, which is what a core that never
    /// serves should do with one.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_tunnel_admit(mut self, tunnel_admit: SharedTunnelAdmit) -> Self {
        self.tunnel_admit = tunnel_admit;
        self
    }

    /// Share the **Awaited Inbound** registry: a connection some download
    /// waits for becomes that download's worker instead of a serve
    /// connection. `Core::builder` wires the one production instance in; the
    /// default (empty) registry awaits nothing, so every connection takes the
    /// serve road exactly as it did before.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_awaited_inbound(mut self, awaited_inbound: AwaitedInbound) -> Self {
        self.awaited_inbound = awaited_inbound;
        self
    }

    /// Share the **Served Links** a dial adapter joins (ADR-0107);
    /// `Core::builder` shares the one instance through `adopt_cells`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_peer_links(mut self, peer_links: super::SharedPeerLinks) -> Self {
        self.peer_links = peer_links;
        self
    }
}

/// The portable summary of a failed listener bind. `PeerListener`'s bind paths
/// only ever return [`PeerNetError::Bind`]; the fallback keeps the match total
/// rather than describing a reachable case.
fn bind_error_kind(error: &PeerNetError) -> std::io::ErrorKind {
    match error {
        PeerNetError::Bind { source } => source.kind(),
        _ => std::io::ErrorKind::Other,
    }
}

impl ServeRuntimeService for RuntimeServeRuntimeService {
    async fn start(
        &mut self,
        identity: rmule_primitives::ClientIdentity,
        listen_addr: SocketAddrV4,
    ) -> Result<SocketAddrV4, CoreError> {
        // The SUI keypair this node answers peers under (ADR-0041) is already
        // in the Hello Adverts the accept pump reads: the Core's, loaded at
        // build.
        // The listener must be accepting before any login: the server
        // determines High-ID by connecting back to the advertised port during
        // the login handshake, or it assigns Low-ID (ADR-0039 — rmule must be
        // High-ID to be callback-capable). A backlog-completed TCP handshake
        // alone is NOT enough: the check is an `OP_HELLO` that must be
        // answered, which is why accepts run in their own pump.
        // A wildcard listen address binds the Family Pair both families
        // share; a literal one binds exactly the address it names (ADR-0085).
        let listener = if listen_addr.ip().is_unspecified() {
            PeerListener::bind_port(listen_addr.port(), self.address_families).await
        } else {
            PeerListener::bind(listen_addr).await
        }
        .map_err(|error| {
            // The whole `io::Error` is logged here and the portable `ErrorKind`
            // rides the event (the `CloseReason::Io` shape): a front end needs
            // "the port is taken" to be matchable, not a locale-dependent
            // string.
            tracing::warn!(%error, %listen_addr, "serve: inbound listener did not bind");
            CoreError::ListenerBind(bind_error_kind(&error))
        })?;
        // The Family Pair shares one port across both families (ADR-0085);
        // the advertised address is the IPv4 one the eD2k login names.
        let bound = SocketAddrV4::new(*listen_addr.ip(), listener.local_port());
        // What actually came up is the truth every advert derives from
        // (ADR-0084) — recorded here, at the bind, never inferred from the
        // configured selection, which says only what was attempted.
        self.session.own_identity().addresses().record_bind(
            crate::address_learning::SocketRole::Tcp,
            listener.binds(),
            listener.local_port(),
        );
        // The accept loop must run CONCURRENTLY with the login (bench-proven against Lugdunum
        // eserver 17.15): the server's High-ID
        // port-check back-connects the advertised port and sends `OP_HELLO`
        // *before* it resolves the login, granting High-ID only when the
        // `OP_HELLOANSWER` comes back within its check window. A bound-but-mute
        // listener fails the check ("WARNING : No answer from your <port>
        // port") and the login lands Low-ID. The accepting itself lives in the
        // pump from bind: with an obfuscation policy armed an accept holds
        // its accepted stream across the byte-0 peek await, so it must never
        // run inside a future a caller's `select!` can cancel. Each connection
        // the pump accepts is answered by its driver
        // (`PeerSession::new_inbound`) the moment its hello arrives — read
        // live: the Presented Client ID as Self Reach answers it then (`0`
        // and no server before any session or Kad join, as an aMule
        // mid-login answer carries) and the session's server — and the serve
        // loop serves it from the channel.
        //
        // Rebuilt at every start, never carried over: a restart's
        // hellos are answered under the identity *this* start named. One
        // naming port `0` (the OS's choice) names the port bound, which a
        // start learns only here (ADR-0040).
        let identity = if identity.tcp_port() == 0 {
            rmule_primitives::ClientIdentity::new(
                identity.user_hash(),
                identity.nickname().clone(),
                bound.port(),
                identity.protocol_version(),
            )
            .with_extra_tags(identity.extra_tags().to_vec())
        } else {
            identity
        };
        // Self Reach as the core installed it in the Hello Adverts before any
        // start. A runtime started outside a core has no Kad node and no
        // NAT-T front, so the owner it reads is the session facts alone.
        let reach = self.adverts.reach.get().cloned().unwrap_or_else(|| {
            crate::reachability::SharedSelfReach::new(
                crate::KadReachLevel::fixed(false),
                self.session.own_identity().clone(),
                crate::natt::front::SharedNattFront::default(),
            )
        });
        let hello = crate::server_session::HelloSource::live(identity, reach);
        let gates = AcceptGates::new(
            self.ip_filter.clone(),
            self.ban_store.clone(),
            self.kad_pump.clone(),
        );
        let pump = spawn_accept_pump(
            listener,
            hello,
            self.adverts.clone(),
            &self.tunnel_admit,
            self.session.own_identity().awaited_testers().clone(),
            gates,
        );
        self.accept_rx = Some(pump.accepted);
        self.accept_pump = Some(pump.task);
        // No login is caused here (ADR-0095): the listener is accepting, which
        // is what *serving* means, and the session it names and announces to
        // is the operator's to make. The follower announces to each one as it
        // comes; the hellos read the live session themselves.
        self.follower = Some(SessionFollower::spawn(&self.session));
        Ok(bound)
    }

    async fn accept(&mut self) -> Option<ServeConnection> {
        // The receive is this future's only await, and `recv` is cancel-safe,
        // so the serve runner may race it in its `select!` freely: a cancel
        // before it resolves leaves the connection on the channel for the next
        // call, and nothing after it awaits. That holds because the producers
        // run the **Accept Gates** — the IP filter, the ban, the Test
        // Connection carve-out — before the channel, never here: the ban
        // check's lock and a refused port test's report would each be an await
        // a cancel could drop a taken connection at. The listener lives in the
        // pump task for the same reason, so the race never drops a
        // mid-handshake socket either. `None` means the pump ended — a fatal
        // listener error or serve shutdown — and winds the activity down. A
        // connection the pump accepted before the serve loop began (the
        // server's High-ID port-check among them) waits in the channel,
        // already answered by its own driver.
        let AdmittedPeer {
            conn,
            dialed_toward,
            awaited_server,
        } = self.accept_rx.as_mut()?.recv().await?;
        let peer = conn.peer_endpoint();
        let (command_tx, command_rx) = mpsc::channel(16);
        let (event_tx, event_rx) = mpsc::channel(16);
        // Triage, don't bridge eagerly (ADR-0039): the per-connection task drains
        // the inbound hello and, on a pending-callback match, adopts the raw
        // connection as a download worker instead of serving it.
        let triage = triage_inbound_connection(
            conn,
            dialed_toward,
            command_rx,
            event_tx,
            self.awaited_inbound.clone(),
            InboundPeerDeps {
                slot_wait_timeout: self.slot_wait_timeout,
                dialed_serve_sink: self.dialed_serve_sink.clone(),
                kad_bootstrap: self.kad_bootstrap.clone(),
                kad_pump: self.kad_pump.clone(),
                buddy_slot: self.buddy_slot.clone(),
                // The one Address Learning store, reached the way every
                // other feeder reaches it (ADR-0084).
                addresses: self.session.own_identity().addresses().clone(),
                peer_roster: self.peer_roster.clone(),
                kad_presence: self.kad_presence.clone(),
                file_known: self.file_known.clone(),
                tunnel_admit: self.tunnel_admit.clone(),
                hello_refusals: self.hello_refusals.clone(),
                peer_links: self.peer_links.clone(),
            },
        );
        // A connection from the awaited server admitted as an ordinary
        // peer: its test's one knowable end is its peer connection's, and
        // who closed it. One adopted as a download worker has not ended.
        tokio::spawn(async move {
            let InboundEnd::Closed(closed_by) = triage.await else {
                return;
            };
            if let Some(server) = awaited_server {
                let end = PortTestEnd::PeerConnectionEnded { closed_by };
                server.report(LoginStep::PortTestEnded { end }).await;
            }
        });
        Some(ServeConnection::new(peer, command_tx, event_rx))
    }

    fn accept_backlog(&self) -> Option<usize> {
        self.accept_rx.as_ref().map(mpsc::Receiver::len)
    }

    /// Refused before `start` and after a release: there is no listener to
    /// announce for. Otherwise the follower keeps the set and sends it to the
    /// live session, if any, and to each later one.
    async fn announce(&mut self, files: Vec<OfferedFile>) -> Result<AnnounceOutcome, CoreError> {
        match self.follower.as_ref() {
            Some(follower) => follower.announce(files).await,
            None => Err(CoreError::Repository("serve not started".into())),
        }
    }

    fn take_session_told(&mut self) -> Option<mpsc::UnboundedReceiver<AnnounceOutcome>> {
        self.follower.as_mut()?.take_session_told()
    }

    async fn release(&mut self) {
        // The cell first: while it holds this pump's weak sender a risen
        // tunnel would be refused as "pipeline closing" rather than as what it
        // is — a node that is not serving.
        self.tunnel_admit.clear();
        // Stop following: a session the operator makes after this is not told
        // about files this node no longer serves.
        self.follower = None;
        // Dropping the receiver is the pump's stop signal (`accept_tx.closed()`);
        // joining it is what makes the listener — and its port — gone rather
        // than merely told to go.
        self.accept_rx = None;
        if let Some(pump) = self.accept_pump.take() {
            let _ = pump.await;
        }
    }

    fn set_kad_presence(&mut self, kad_presence: KadPresenceView) {
        self.kad_presence = kad_presence;
    }

    fn adopt_cells(&mut self, cells: &super::AdapterCells) {
        self.session = cells.session.clone();
        self.awaited_inbound = cells.awaited_inbound.clone();
        self.slot_wait_timeout = cells.slot_wait_timeout;
        self.dialed_serve_sink = cells.dialed_serve_sink.clone();
        self.ban_store = cells.ban_store.clone();
        self.kad_bootstrap = cells.kad_bootstrap.clone();
        self.kad_pump = cells.kad_pump.clone();
        self.peer_roster = cells.peer_roster.clone();
        self.adverts = cells.hello_adverts.clone();
        self.buddy_slot = cells.buddy_slot.clone();
        self.ip_filter = cells.ip_filter.clone();
        self.address_families = cells.address_families;
        self.tunnel_admit = cells.tunnel_admit.clone();
        self.hello_refusals = cells.hello_refusals.clone();
        self.file_known = cells.file_known.clone();
        self.peer_links = cells.peer_links.clone();
    }
}

#[cfg(test)]
mod tests;
