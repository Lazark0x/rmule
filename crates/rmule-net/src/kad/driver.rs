//! The one-task-per-node UDP driver loop.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rmule_kad::{
    DatagramNonce, KadCommand, KadEvent, KadInstant, KadNode, KadNodeConfig, KadNodeEndpoint,
    KadNodeStart, KadObfuscation, KadOutput, KadSelfCheck,
};
use rmule_primitives::Ipv4Endpoint;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::family::{FamilySelection, ReceiveErrorBudget, ReceiveErrorOutcome, UdpFamilyPair};
use crate::kad::KadNetError;
use crate::kad::capture::{CaptureMeta, CaptureTap, DatagramFrame, Direction};
use crate::kad::transport::{KadInlet, KadReceive, KadTransport};

#[cfg(test)]
mod tests;

/// Everything one live Kad node needs **beyond its transport**: who it is,
/// what it records, and which optional capabilities it starts with.
///
/// Transport-free on purpose (ADR-0057): the same config starts a node that
/// owns its socket ([`spawn`]) and one that rides the core's unified
/// client-UDP bind ([`spawn_over`]), so neither entry can configure the node
/// differently from the other.
#[derive(Clone, Debug)]
pub struct KadNetConfig {
    /// The sans-I/O node identity. A `udp_port` of 0 is patched to the real
    /// bound port once the transport is known, so ephemeral-port tests and
    /// fixed-port deployments use the same config shape.
    pub node: KadNodeConfig,
    /// When set, every in/out datagram is recorded here (ADR-0022).
    pub capture_dir: Option<PathBuf>,
    /// When set, the routing table is persisted here as a v2 `nodes.dat` on
    /// clean shutdown and every half hour while running,
    /// ending cold-start-every-run Kad. `None` disables persistence — the
    /// public-network smoke path keeps it `None` so it writes no bytes to disk
    /// (`rmule-cli kad join` doctrine).
    pub nodes_dat_path: Option<PathBuf>,
    /// Start the node with its own Kad firewall self-check (ADR-0058 requester cycle): on
    /// join the node piggybacks version-gated `0x50`/`0x53` checks on hello
    /// traffic, consumes `0x58`/`0x59`, and rechecks hourly, emitting the
    /// `Reachability*` events the core store projects. Off by default — the same
    /// capture-gating the node's [`KadSelfCheck`] carries — so the
    /// routing-only mesh sim runs no firewall cadence; a requester-capture driver
    /// arms it.
    pub firewall_self_check: bool,
    /// Obfuscate outbound datagrams (ADR-0046), with the Kad UDP verify keys
    /// inside when the value carries them — the one start value the node
    /// itself takes, so verify keys without obfuscation cannot be written
    /// here either: the trailer rides inside the crypt header. `None` (the
    /// default posture) leaves the node plaintext-faithful to a keyless
    /// aMule: nothing verifies and no `0x22` is answered. A running node is
    /// re-armed with [`KadCommand::SetObfuscation`].
    ///
    /// A live node draws its per-packet entropy from [`os_datagram_nonce`].
    pub obfuscation: Option<KadObfuscation>,
    /// Arm the node's contact-admission verdict: the IP-filter
    /// consult aMule runs at every Kad contact intake (`CRoutingZone::Add`,
    /// the nodes.dat / bootstrap loads, lookup-response rows). `None` admits
    /// everything — the empty-filter posture; `rmule-core` passes a closure
    /// over its core-owned IP filter.
    pub contact_admission: Option<rmule_kad::KadContactAdmission>,
}

/// Counters the driver returns on clean shutdown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KadNetSummary {
    /// Datagrams handed to the node, after the non-IPv4 drop below.
    pub datagrams_in: u64,
    /// Datagrams the driver wrote to the socket.
    pub datagrams_out: u64,
    /// Datagrams from non-IPv4 sources, dropped before the node saw them
    /// (Kad2 contact rows are IPv4-only). Only an **owned** transport can
    /// raise it: a node on the core's unified socket is fed by a front that
    /// rules on family first and counts its own drops there.
    pub non_ipv4_dropped: u64,
}

/// The caller's handle to one running Kad node.
///
/// Dropping the handle without [`shutdown`](Self::shutdown) closes the
/// command channel, which the driver treats as a shutdown request; the
/// capture (if any) still finalizes.
pub struct KadNetHandle {
    local_addr: SocketAddr,
    commands: mpsc::Sender<KadCommand>,
    events: mpsc::Receiver<KadEvent>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<KadNetSummary, KadNetError>>,
}

impl KadNetHandle {
    /// The socket address actually bound (resolves port 0).
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Issue a driver command to the node.
    pub async fn command(&self, command: KadCommand) -> Result<(), KadNetError> {
        self.commands
            .send(command)
            .await
            .map_err(|_| KadNetError::DriverGone)
    }

    /// Issue a driver command without waiting for inbox room. `Ok(true)` when
    /// queued, `Ok(false)` when the inbox is momentarily full.
    ///
    /// The escape hatch for a task that is also this handle's sole event
    /// drainer: an awaited [`command`](Self::command) there can deadlock —
    /// driver blocked emitting an event, drainer blocked sending a command,
    /// neither queue moving. A full inbox instead reports `false` so the caller
    /// can drop-and-log a losable command and keep draining.
    pub fn try_command(&self, command: KadCommand) -> Result<bool, KadNetError> {
        match self.commands.try_send(command) {
            Ok(()) => Ok(true),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(KadNetError::DriverGone),
        }
    }

    /// Room in the node's command inbox, awaited apart from this handle: the
    /// caller that drains this handle's events polls
    /// [`KadCommandRoom::ready`] beside [`next_event`](Self::next_event)
    /// and sends again with [`try_command`](Self::try_command) once it
    /// resolves, so a full inbox never stops it draining.
    #[must_use]
    pub fn command_room(&self) -> KadCommandRoom {
        KadCommandRoom {
            commands: self.commands.downgrade(),
        }
    }

    /// The next node event, or `None` once the driver has stopped.
    pub async fn next_event(&mut self) -> Option<KadEvent> {
        self.events.recv().await
    }

    /// Stop the driver, finalize any capture, and return the run summary.
    ///
    /// # Errors
    /// [`KadNetError::Join`] if the driver task panicked or was cancelled,
    /// or [`KadNetError::TransportFailing`] if the transport's
    /// consecutive-error budget ended the run before this call — the driver
    /// still ran its clean-shutdown path (persist, capture finalize) either
    /// way, this call just reports which happened.
    pub async fn shutdown(mut self) -> Result<KadNetSummary, KadNetError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.await.map_err(|_| KadNetError::Join)?
    }
}

/// Room in one node's command inbox ([`KadNetHandle::command_room`]). It
/// holds the inbox weakly, so it never keeps a node running.
pub struct KadCommandRoom {
    commands: mpsc::WeakSender<KadCommand>,
}

impl KadCommandRoom {
    /// Resolves once the inbox has room for one command, or at once when the
    /// node is gone. It takes no slot: while the handle is the inbox's one
    /// sender, the room is the handle's next command's. Cancel-safe.
    pub async fn ready(&self) {
        if let Some(commands) = self.commands.upgrade() {
            let _ = commands.reserve().await;
        }
    }
}

/// Bind a socket of this node's own and start its driver — the **standalone**
/// entry (the `rmule-tools` drivers, the Kad Stimulus Node, the mesh sim, a
/// loopback test).
///
/// `bind` is the UDP socket address to take (port 0 for ephemeral). A wildcard
/// address binds a **Family Pair** (ADR-0085) — the `::` socket exists for
/// symmetry and is unused, since Kad is IPv4-only end to end and no
/// interoperable IPv6 contact format exists; a literal address binds that one
/// family, which is how a loopback test or an operator pins an interface.
///
/// # Errors
/// [`KadNetError::Bind`] when no family bound, [`KadNetError::Capture`] when
/// the capture directory could not be opened.
pub async fn spawn(config: KadNetConfig, bind: SocketAddr) -> Result<KadNetHandle, KadNetError> {
    let socket = if bind.ip().is_unspecified() {
        UdpFamilyPair::bind(bind.port(), FamilySelection::default()).await
    } else {
        UdpFamilyPair::bind_literal(bind).await
    }
    .map_err(KadNetError::Bind)?;
    let local_addr = SocketAddr::new(bind.ip(), socket.local_port());
    start(config, KadTransport::Owned(socket), local_addr).await
}

/// Start a node over a socket somebody else owns — the **unified** entry
/// (ADR-0057): the core's one client-UDP bind, whose demux front fills the
/// inlet and whose port every Kad answer leaves by.
///
/// The node binds nothing, so there is no bind to fail; the only error left is
/// the capture directory.
///
/// # Errors
/// [`KadNetError::Capture`] when the capture directory could not be opened.
pub async fn spawn_over(
    config: KadNetConfig,
    inlet: KadInlet,
) -> Result<KadNetHandle, KadNetError> {
    // The wildcard address with the shared bind's real port: a Family Pair has
    // two binds and this address is only ever read back as a capture-meta and
    // log label, so naming the port honestly and the address generically is
    // the one answer that cannot be wrong.
    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), inlet.socket.local_port());
    start(config, KadTransport::Shared(inlet), local_addr).await
}

/// Arm the capture tap, weave the channels, and spawn the one driver task —
/// everything both entries share, so the transport is the only thing that
/// differs between a standalone node and a unified one.
async fn start(
    config: KadNetConfig,
    transport: KadTransport,
    local_addr: SocketAddr,
) -> Result<KadNetHandle, KadNetError> {
    let KadNetConfig {
        node: mut node_config,
        capture_dir,
        nodes_dat_path,
        firewall_self_check,
        obfuscation,
        contact_admission,
    } = config;
    if node_config.udp_port == 0 {
        node_config.udp_port = transport.local_port();
    }

    let capture = match capture_dir {
        Some(dir) => Some(CaptureTap::start(dir).await.map_err(KadNetError::Capture)?),
        None => None,
    };
    let node_id_hex = node_config
        .id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let node_start = node_start(
        node_config,
        firewall_self_check,
        obfuscation,
        contact_admission,
    );

    let (command_tx, command_rx) = mpsc::channel(64);
    let (event_tx, event_rx) = mpsc::channel(1024);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(run_driver(
        transport,
        node_start,
        command_rx,
        event_tx,
        shutdown_rx,
        RunRecord {
            bind: local_addr,
            node_id_hex,
            capture,
            nodes_dat_path,
        },
    ));

    Ok(KadNetHandle {
        local_addr,
        commands: command_tx,
        events: event_rx,
        shutdown: Some(shutdown_tx),
        task,
    })
}

/// How often the driver flushes the routing table to `nodes_dat_path` while
/// running. aMule persists nodes.dat on shutdown only (its
/// `CRoutingZone` destructor is the single `WriteFile` caller); rmule adds this
/// periodic safety flush so an *unclean* exit — a crash, a SIGKILL — still
/// leaves a warm table to reload, rather than losing everything learned since
/// the last clean stop. A documented, wire-unobservable divergence: the file's
/// bytes are aMule's exact format, only the write *cadence* is rmule's.
const NODES_DAT_FLUSH_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Map the driver's monotonic clock onto the node's explicit-time scale:
/// driver start is the node's epoch.
fn instant_at(start: Instant) -> KadInstant {
    KadInstant::from_millis(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX))
}

/// Snapshot the node's routing contacts and persist them as a v2 nodes.dat,
/// logging the outcome. A no-op when persistence is disabled (`path` is
/// `None`). Failures are logged, never propagated — a full disk must not stop
/// the node.
async fn persist_routing(path: Option<&std::path::Path>, node: &KadNode) {
    let Some(path) = path else { return };
    let contacts: Vec<_> = node.routing_table().contacts().copied().collect();
    match crate::kad::persist::write_nodes_dat(path, &contacts).await {
        Ok(true) => {
            tracing::debug!(contacts = contacts.len(), path = %path.display(), "persisted nodes.dat");
        }
        Ok(false) => tracing::debug!(
            contacts = contacts.len(),
            "skipped nodes.dat write (below the 25-contact floor)"
        ),
        Err(error) => tracing::warn!(%error, path = %path.display(), "failed to persist nodes.dat"),
    }
}

/// The **Kad Node Start** a live node is built from, at the driver's epoch
/// (the driver maps its clock so that its start is `KadInstant::EPOCH`): the
/// join cadence every live node runs, and the optional capabilities its
/// [`KadNetConfig`] names. The node orders it itself (admission before any
/// traffic, obfuscation before its verify keys).
fn node_start(
    node: KadNodeConfig,
    firewall_self_check: bool,
    obfuscation: Option<KadObfuscation>,
    contact_admission: Option<rmule_kad::KadContactAdmission>,
) -> KadNodeStart {
    // Join: the forced self-lookup fires 3 min after start, then every 4 h;
    // the small-timer hello pass reaches a *merged* table (a v1/v2 nodes.dat
    // seeds contacts, not dial candidates). The bootstrap dial loop arms
    // itself separately, when the driver seeds the dial list.
    let mut start = KadNodeStart::new(node, KadInstant::EPOCH)
        .self_lookup()
        .small_timer();
    if let Some(admission) = contact_admission {
        start = start.admission(admission);
    }
    // The ADR-0058 requester (a requester-capture run); its UDP half finds its
    // own helpers through a lookup toward a random target.
    if firewall_self_check {
        start = start.self_check(KadSelfCheck::new().with_udp_helper_lookup(os_random_kad_id));
    }
    // ADR-0046. Verify keys exist only inside the obfuscation: the trailer
    // rides inside the crypt header.
    if let Some(obfuscation) = obfuscation {
        start = start.obfuscation(obfuscation);
    }
    start
}

/// What one run leaves on disk: the datagram tap (ADR-0022) and the
/// routing-table persistence path, plus the bound address and node ID the
/// capture meta names. Both outputs are optional and neither may stall the
/// node.
struct RunRecord {
    bind: SocketAddr,
    node_id_hex: String,
    capture: Option<CaptureTap>,
    nodes_dat_path: Option<PathBuf>,
}

/// OS-entropy nonce for one obfuscated Kad datagram: the semi-random marker
/// byte (its low bits are overwritten with the key-family index) and the 2-byte
/// key seed sent in the clear. aMule disables UDP padding outright
/// (`EncryptSendClient`: "padding disabled for UDP currently"), so rmule emits
/// none either — padding would still decode, but it would not be byte-shaped
/// like aMule's.
pub fn os_datagram_nonce() -> DatagramNonce {
    let mut raw = [0u8; 3];
    getrandom::fill(&mut raw).expect("OS entropy for the Kad-UDP crypt nonce");
    DatagramNonce {
        marker_byte: raw[0],
        random_key: u16::from_le_bytes([raw[1], raw[2]]),
        padding: Vec::new(),
    }
}

/// OS-entropy Kad ID for the UDP tester's helper lookup — aMule's
/// `FindNodeFWCheckUDP` walks toward `GetRandomUint128()`, a point with no
/// relation to our own ID, so the rows it returns are strangers to our table.
fn os_random_kad_id() -> rmule_kad::KadId {
    let mut raw = [0u8; rmule_kad::KadId::BYTE_LEN];
    getrandom::fill(&mut raw).expect("OS entropy for the Kad helper-lookup target");
    rmule_kad::KadId::from_bytes(raw)
}

async fn run_driver(
    mut transport: KadTransport,
    node_start: KadNodeStart,
    mut commands: mpsc::Receiver<KadCommand>,
    events: mpsc::Sender<KadEvent>,
    mut shutdown: oneshot::Receiver<()>,
    run_record: RunRecord,
) -> Result<KadNetSummary, KadNetError> {
    let RunRecord {
        bind: local_addr,
        node_id_hex,
        capture,
        nodes_dat_path,
    } = run_record;
    // The driver's epoch: the node is built now, at the `KadInstant::EPOCH`
    // its start names.
    let start = Instant::now();
    let started_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    let mut node = KadNode::new(node_start);
    let mut summary = KadNetSummary::default();
    // One UDP datagram can never exceed 64 KiB.
    let mut buf = vec![0u8; 64 * 1024];
    // The consecutive-error budget for this transport's receive arm:
    // tolerated up to `RECEIVE_ERROR_BUDGET`, reset by any successful
    // receive. `Some` once it trips — checked after the loop so the
    // clean-shutdown path below (persist, capture finalize) still runs on a
    // dead socket exactly as it does on a requested stop.
    let mut receive_failure: Option<KadNetError> = None;
    let mut receive_errors = ReceiveErrorBudget::new();

    // The periodic routing-table flush. Always created (cheap);
    // its select arm is gated on `nodes_dat_path.is_some()`, so with
    // persistence disabled the timer fires into a disabled branch and does
    // nothing. The immediate first tick is consumed so the first real flush is
    // one interval out, not at t=0 (a cold table has nothing to save).
    let mut flush_tick = tokio::time::interval(NODES_DAT_FLUSH_INTERVAL);
    flush_tick.tick().await;

    loop {
        // The node's next deadline, mapped back onto the tokio clock.
        let wake = node
            .next_wake()
            .map(|at| start + Duration::from_millis(at.as_millis()));

        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            command = commands.recv() => match command {
                Some(command) => node.handle_command(instant_at(start), command),
                // Every handle clone is gone: treat as shutdown.
                None => break,
            },
            received = transport.recv(&mut buf) => match received {
                // Kad packs a 32-bit address end to end (ADR-0085), so the
                // pair's IPv6 socket has no dialect to feed: a datagram that
                // does arrive on it is counted and dropped at the transport,
                // never inside the node.
                KadReceive::Datagram { from, len } => {
                    receive_errors.record_success();
                    summary.datagrams_in += 1;
                    let addr = SocketAddr::new(IpAddr::V4(from.ip), from.port);
                    record(&capture, start, Direction::Inbound, addr, &buf[..len]).await;
                    let endpoint = KadNodeEndpoint::new(from.ip, from.port);
                    node.handle_datagram(instant_at(start), endpoint, &buf[..len]);
                }
                KadReceive::NonIpv4 => {
                    receive_errors.record_success();
                    summary.non_ipv4_dropped += 1;
                }
                // Tolerated up to the budget (the network is lossy); beyond
                // it, a dead socket, not a lossy network — end the run
                // (the hot-loop defect class on the receive arm).
                KadReceive::Transient(kind) => match receive_errors.record_error(kind) {
                    ReceiveErrorOutcome::Tolerated => {
                        // A receive error returns immediately, with no
                        // natural network delay behind it: without this
                        // pause, retrying while still under budget would
                        // hot-spin exactly as hard as the exhausted case
                        // must not.
                        tokio::time::sleep(crate::family::RECEIVE_ERROR_BACKOFF).await;
                    }
                    ReceiveErrorOutcome::Exhausted { kind, consecutive } => {
                        tracing::warn!(
                            ?kind,
                            consecutive,
                            "Kad UDP receive failed repeatedly; ending the driver"
                        );
                        receive_failure = Some(KadNetError::TransportFailing { kind, consecutive });
                        break;
                    }
                },
                // The socket's owner is gone: there is nothing left to receive
                // and nothing left to answer on (a closed channel ends the
                // task rather than spinning the loop).
                KadReceive::Closed => break,
            },
            () = tokio::time::sleep_until(wake.unwrap_or_else(Instant::now)), if wake.is_some() => {
                node.tick(instant_at(start));
            }
            _ = flush_tick.tick(), if nodes_dat_path.is_some() => {
                persist_routing(nodes_dat_path.as_deref(), &node).await;
            }
        }

        drain(
            &mut node,
            &transport,
            &events,
            &capture,
            start,
            &mut summary,
        )
        .await;
    }

    // Flush anything the node produced just before shutdown.
    drain(
        &mut node,
        &transport,
        &events,
        &capture,
        start,
        &mut summary,
    )
    .await;

    // Persist the routing table on clean shutdown — aMule's `CRoutingZone`
    // destructor `WriteFile`. A no-op when persistence is off.
    persist_routing(nodes_dat_path.as_deref(), &node).await;

    if let Some(capture) = capture {
        capture
            .finalize(CaptureMeta {
                bind: local_addr,
                node_id_hex,
                started_unix_secs,
                duration_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                datagrams_in: summary.datagrams_in,
                datagrams_out: summary.datagrams_out,
                non_ipv4_dropped: summary.non_ipv4_dropped,
            })
            .await;
    }
    match receive_failure {
        Some(error) => Err(error),
        None => Ok(summary),
    }
}

/// Flush node outputs: send datagrams (tapping them), forward events.
async fn drain(
    node: &mut KadNode,
    transport: &KadTransport,
    events: &mpsc::Sender<KadEvent>,
    capture: &Option<CaptureTap>,
    start: Instant,
    summary: &mut KadNetSummary,
) {
    while let Some(output) = node.poll_output() {
        match output {
            KadOutput::Datagram { to, bytes } => {
                let addr = SocketAddr::new(IpAddr::V4(to.ip()), to.udp_port());
                match transport
                    .send_to(Ipv4Endpoint::new(to.ip(), to.udp_port()), &bytes)
                    .await
                {
                    Ok(()) => summary.datagrams_out += 1,
                    // UDP send errors are as transient as receive errors;
                    // the protocol tolerates loss.
                    Err(error) => {
                        tracing::debug!(%error, %addr, "transient Kad UDP send error");
                    }
                }
                record(capture, start, Direction::Outbound, addr, &bytes).await;
            }
            KadOutput::Event(event) => {
                // A gone or saturated event consumer must not stall traffic;
                // command-channel closure is the shutdown signal, not this.
                if events.try_send(event).is_err() {
                    tracing::debug!("kad event receiver gone or full; dropping event");
                }
            }
        }
    }
}

async fn record(
    capture: &Option<CaptureTap>,
    start: Instant,
    direction: Direction,
    remote: SocketAddr,
    bytes: &[u8],
) {
    if let Some(tap) = capture {
        tap.record(DatagramFrame {
            at_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            direction,
            remote,
            bytes: bytes.to_vec(),
        })
        .await;
    }
}
