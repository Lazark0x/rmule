//! The **ed2k→Kad handoff** runner (ADR-0067): one process that is at once
//! eD2k-connected to a peer *and* running a Kad node, so the peer-tag consume
//! reaches the Kad dial — the integrated citizen that makes flow G executable.
//! It dials the peer, reads its hello's `CT_EMULE_UDPPORTS` Kad half, brokers
//! that endpoint into the running node's [`KadCommand::BootstrapFromPeer`] (the
//! exact command core's `SharedKadBootstrap` broker issues into the node's
//! pump), and reports the node reaching Kad contact.
//!
//! Deterministic doctrine (ADR-0045): the [`KadNode`](rmule_kad::KadNode) stays
//! sans-I/O / explicit-time; this composition root wires the real tokio runtime,
//! the UDP socket (the `rmule_net::kad` driver), and the eD2k/peer TCP sessions —
//! exactly the "wire real time/IO at the edge" split the other `rmule-tools`
//! live commands use. The peer-tag consume ([`PeerIdentity::kad_bootstrap_port`])
//! and the node's gate (`BootstrapFromPeer` → not-joined + shared 10 s throttle)
//! are the unchanged core/kad logic, driven here, not reimplemented.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Args;
use rmule_ed2k::Ed2kEvent;
use rmule_kad::{KadCommand, KadEvent, KadId, KadNodeConfig, KadNodeEndpoint};
use rmule_net::ed2k::{ConnectOptions, Connection};
use rmule_net::kad::{KadNetConfig, KadNetHandle};
use rmule_net::peer::{ConnectOptions as PeerConnectOptions, Connection as PeerConnection};
use rmule_peer::{ConnectionEvent, PeerEvent, PeerHandshakeContext, PeerIdentity, UdpPortsAdvert};
use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, ServerEndpoint, TagValue, UserHash};

use crate::operand::{parse_peer_endpoint, parse_user_hash};

/// `CT_EMULE_UDPPORTS` (aMule `ProcessHelloTypePacket`): the packed hello tag
/// whose high 16 bits are the peer's Kad UDP port and low 16 bits its
/// client UDP port (the half peer-UDP reask uses). Read verbatim off the hello here.
const CT_EMULE_UDPPORTS: u8 = 0xF9;

/// `CT_EMULE_MISCOPTIONS2` as aMule 2.3.3 actually sends it in a peer hello:
/// special tag id `0xFE` (captured live, flow G) — its low nibble is the Kad
/// protocol version (aMule `KADEMLIA_VERSION` = 8, value `0x…8`).
///
/// FLOW-G FINDING: rmule-peer's `PeerIdentity` reads MiscOptions2
/// under `0x55` (`capability::CT_EMULE_MISCOPTIONS2`, offset `[pending]`), so it
/// misses the `0xFE` tag, reports `kad_version = 0`, and
/// `PeerIdentity::kad_bootstrap_port` returns `None` — the ADR-0067 handoff
/// gate (`KadPort ∧ KadVersion > 1`) never opens against a real aMule. The core
/// fix is a one-line constant change in `rmule-peer`; that crate is owned by a
/// concurrent worktree here, so this runner reads the capture-correct `0xFE` tag
/// itself to drive the handoff, and the finding is reported for the core fix.
const CT_EMULE_MISCOPTIONS2: u8 = 0xFE;

#[derive(Debug, Args)]
pub(crate) struct KadHandoffArgs {
    /// The peer's eD2k TCP endpoint (`ipv4:port`) to dial for the hello — the
    /// Kad-running aMule whose `CT_EMULE_UDPPORTS` carries the bootstrap port.
    #[arg(long)]
    peer: String,
    /// Optional eD2k server (`host:port`). When set, log in first and build the
    /// peer handshake context from the assigned client id (topology parity with
    /// a server-connected citizen); omitted → a synthetic context (direct dial).
    #[arg(long)]
    server: Option<String>,
    /// UDP address to bind rmule's Kad node on (`0.0.0.0:0` binds ephemeral).
    #[arg(long, default_value = "0.0.0.0:0")]
    kad_bind: String,
    /// rmule's Kad node ID as 32 hex chars.
    #[arg(long, default_value = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")]
    kad_id: String,
    /// Local user hash as upper-case hex (32 chars).
    #[arg(long, default_value = "42424242424242424242424242424242")]
    user_hash: String,
    /// Local eD2k TCP port advertised in the hello / Kad headers.
    #[arg(long, default_value_t = 4662)]
    tcp_port: u16,
    /// CT_VERSION value.
    #[arg(long, default_value_t = 60)]
    protocol_version: u32,
    /// Local nickname tag.
    #[arg(long, default_value = "rmule-tools")]
    nickname: String,
    /// Output directory for the peer/server/Kad capture taps and the run summary.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Connect timeout, seconds.
    #[arg(long, default_value_t = 10)]
    connect_timeout: u64,
    /// Login + hello response timeout, seconds.
    #[arg(long, default_value_t = 15)]
    response_timeout: u64,
    /// Max seconds to wait for the Kad node to reach contact after the handoff
    /// before failing the run.
    #[arg(long, default_value_t = 60)]
    max_seconds: u64,
}

/// The observed `CT_EMULE_UDPPORTS` (`0xF9`) hello layout plus the Kad version
/// from `CT_EMULE_MISCOPTIONS2` (`0xFE`) — the capture fact that pins both
/// halves: the Kad port with its version, and the client-UDP port. Read off the live peer
/// hello, never assumed.
struct ObservedUdpPorts {
    /// The raw packed `0xF9` value, or `None` if the peer sent no such tag.
    packed: Option<u32>,
    /// High 16 bits: the peer's advertised Kad UDP port.
    kad_udp_port: u16,
    /// Low 16 bits: the peer's advertised client UDP port (ADR-0057 reask half).
    client_udp_port: u16,
    /// The peer's Kad protocol version — low nibble of the `0xFE` MiscOptions2
    /// tag (the capture-correct id; see [`CT_EMULE_MISCOPTIONS2`]).
    kad_version: u8,
    /// The handoff port under the ADR-0067 gate (`kad port != 0 ∧ version > 1`),
    /// computed from the capture-correct `0xFE` read.
    gated_kad_port: Option<u16>,
    /// What rmule-peer's current (`0x55`) consume yields — recorded to document
    /// the core gap this flow surfaced (`None` against a real aMule).
    core_gated_kad_port: Option<u16>,
}

impl ObservedUdpPorts {
    fn from_identity(identity: &PeerIdentity) -> Self {
        let tag_u32 = |wanted: u8| {
            identity
                .unknown_tags()
                .iter()
                .find_map(|tag| match (tag.name().id(), tag.value()) {
                    (Some(id), TagValue::U32(value)) if id == wanted => Some(*value),
                    _ => None,
                })
        };
        let packed = tag_u32(CT_EMULE_UDPPORTS);
        let kad_udp_port = packed.map_or(0, |packed| (packed >> 16) as u16);
        let kad_version = tag_u32(CT_EMULE_MISCOPTIONS2).map_or(0, |bits| (bits & 0x0f) as u8);
        Self {
            packed,
            kad_udp_port,
            client_udp_port: packed.map_or(0, |packed| packed as u16),
            kad_version,
            gated_kad_port: (kad_udp_port != 0 && kad_version > 1).then_some(kad_udp_port),
            core_gated_kad_port: identity.kad_bootstrap_port(),
        }
    }

    /// The single-line capture record the run log carries.
    fn summary_line(&self) -> String {
        let packed = self
            .packed
            .map_or_else(|| "absent".to_owned(), |packed| format!("0x{packed:08X}"));
        format!(
            "kad-handoff observed CT_EMULE_UDPPORTS packed={packed} kad_udp_port={} \
             client_udp_port={} kad_version={} gated_kad_port={:?} core_gated_kad_port={:?}",
            self.kad_udp_port,
            self.client_udp_port,
            self.kad_version,
            self.gated_kad_port,
            self.core_gated_kad_port
        )
    }
}

pub(crate) async fn run(args: KadHandoffArgs) -> Result<()> {
    let peer_endpoint = parse_peer_endpoint(&args.peer)?;
    // A Kad contact packs a 32-bit address (ADR-0085), so this handoff drives
    // an IPv4 peer or none: the family decision lives here, in the driver.
    let Some(peer_ipv4) = peer_endpoint.as_v4() else {
        anyhow::bail!("the ed2k→Kad handoff names a Kad contact, so --peer must be IPv4");
    };
    let user_hash_bytes = parse_user_hash(&args.user_hash)?;
    let user_hash = UserHash::from_bytes(user_hash_bytes);
    let kad_id = KadId::from_bytes(parse_user_hash(&args.kad_id)?);
    let kad_bind: SocketAddr = args
        .kad_bind
        .parse()
        .with_context(|| format!("parse --kad-bind {}", args.kad_bind))?;

    if let Some(dir) = &args.out {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }

    // 1. Start rmule's Kad node. The `rmule_net::kad` driver owns the real UDP
    //    socket and clock; the node is sans-I/O. A fresh node is not joined —
    //    the handoff's "not joined" gate leg is open, and any later contact is
    //    caused by the brokered dial, not by pre-seeded state.
    let mut kad = rmule_net::kad::spawn(
        KadNetConfig {
            node: KadNodeConfig {
                id: kad_id,
                tcp_port: args.tcp_port,
                udp_port: kad_bind.port(),
                user_hash,
            },
            capture_dir: args.out.as_ref().map(|dir| dir.join("kad-tap")),
            nodes_dat_path: None,
            firewall_self_check: false,
            obfuscation: None,
            contact_admission: None,
        },
        kad_bind,
    )
    .await
    .context("spawn rmule Kad node")?;
    println!("kad-handoff kad_node_bound addr={}", kad.local_addr());

    // 2. eD2k identity + optional server login → the peer handshake context.
    let identity = ClientIdentity::new(
        user_hash,
        Ed2kText::from_utf8(&args.nickname),
        args.tcp_port,
        args.protocol_version,
    );
    let response_timeout = Duration::from_secs(args.response_timeout);
    let ctx = build_handshake_context(&args, &identity, response_timeout).await?;

    // 3. Dial the peer and consume its hello. Advertise rmule's real bound Kad
    //    UDP port in `CT_EMULE_UDPPORTS` (kad half; client half 0 — this runner
    //    serves no peer-UDP reask) so the aMule counterparty can reciprocate the
    //    ed2k→Kad handoff (ADR-0057/0067 s3, Honest Capability Advertisement).
    let peer_options = PeerConnectOptions {
        capture_dir: args.out.as_ref().map(|dir| dir.join("peer")),
        connect_timeout: Duration::from_secs(args.connect_timeout),
        hello_timeout: response_timeout,
        udp_ports: Some(UdpPortsAdvert::new(0, kad.local_addr().port())),
        ..Default::default()
    };
    let mut peer_conn = PeerConnection::connect(peer_endpoint, ctx, peer_options)
        .await
        .with_context(|| format!("dial peer {}", args.peer))?;
    let peer_identity = wait_for_peer_identity(&mut peer_conn).await?;
    let _ = peer_conn.shutdown().await;

    // 4. Record the observed CT_EMULE_UDPPORTS layout (the UDP-ports capture fact).
    let observed = ObservedUdpPorts::from_identity(&peer_identity);
    println!("{}", observed.summary_line());
    for tag in peer_identity.unknown_tags() {
        if let (Some(id), TagValue::U32(value)) = (tag.name().id(), tag.value()) {
            println!("kad-handoff hello_tag id=0x{id:02X} u32=0x{value:08X} ({value})");
        }
    }
    if let Some(dir) = &args.out {
        let path = dir.join("handoff-summary.txt");
        std::fs::write(&path, format!("{}\n", observed.summary_line()))
            .with_context(|| format!("write {}", path.display()))?;
    }

    // 5. Broker the peer-tag consume into the Kad dial (ADR-0067): pair the
    //    hello's Kad port with the live connection's IP and hand it to the node,
    //    which applies aMule's not-joined + shared 10 s throttle gate.
    let Some(kad_port) = observed.gated_kad_port else {
        bail!(
            "peer advertised no usable Kad handoff endpoint (kad_udp_port={}, gate needs \
             kad_port != 0 ∧ kad_version > 1) — the handoff cannot fire; {}",
            observed.kad_udp_port,
            observed.summary_line()
        );
    };
    let endpoint = KadNodeEndpoint::new(peer_ipv4.ip, kad_port);
    kad.command(KadCommand::BootstrapFromPeer { endpoint })
        .await
        .context("broker the peer Kad endpoint into the node")?;
    println!(
        "kad-handoff brokered ip={} kad_port={} (BootstrapFromPeer)",
        peer_ipv4.ip, kad_port
    );

    // 6. Wait for the node to reach Kad contact via the handoff dial. aMule's
    //    "joined"/HasHadContact is receiving any Kad datagram; the node surfaces
    //    that as `ContactResponded` when the dialed peer answers our BOOTSTRAP_REQ.
    let joined = wait_for_kad_contact(&mut kad, Duration::from_secs(args.max_seconds)).await;
    let summary = kad.shutdown().await.ok();
    if let Some(summary) = summary {
        println!(
            "kad-handoff kad_summary datagrams_in={} datagrams_out={}",
            summary.datagrams_in, summary.datagrams_out
        );
    }
    if joined {
        println!("kad-handoff result=joined joined=true");
        Ok(())
    } else {
        bail!(
            "kad node did not reach contact within {} s after the handoff (no ContactResponded)",
            args.max_seconds
        );
    }
}

/// Build the peer handshake context: a real one behind a server login (parity
/// with a server-connected citizen) or a synthetic one for a direct dial.
async fn build_handshake_context(
    args: &KadHandoffArgs,
    identity: &ClientIdentity,
    response_timeout: Duration,
) -> Result<PeerHandshakeContext> {
    let Some(server) = &args.server else {
        return Ok(PeerHandshakeContext {
            identity: identity.clone(),
            client_id: ClientId::from_u32(0x1000_0001),
            ed2k_client_id: ClientId::from_u32(0x1000_0001),
            public_ip: None,
            connected_server: None,
        });
    };

    let server_endpoint = ServerEndpoint::parse_host_port(server)
        .with_context(|| format!("parse server endpoint {server}"))?;
    let server_options = ConnectOptions {
        capture_dir: args.out.as_ref().map(|dir| dir.join("server")),
        connect_timeout: Duration::from_secs(args.connect_timeout),
        login_timeout: response_timeout,
        obfuscation: None,
        obfuscated_port: None,
        advertised_ipv6: None,
        udp_ports: None,
    };
    let mut server_conn =
        Connection::connect_with_options(server_endpoint.clone(), identity.clone(), server_options)
            .await?;

    let mut client_id = None;
    while let Some(event) = server_conn.next_event().await {
        match event {
            Ed2kEvent::LoginAccepted { client_id: id, .. } => {
                client_id = Some(id);
                break;
            }
            Ed2kEvent::Disconnected { reason } => {
                bail!("server session ended before LoginAccepted: {reason:?}");
            }
            _ => {}
        }
    }
    let client_id = client_id.context("LoginAccepted not observed")?;
    println!("kad-handoff server_login client_id={}", client_id.as_u32());
    let ctx = rmule_core::build_peer_handshake_context(client_id, &server_endpoint, identity);
    let _ = server_conn.shutdown().await;
    Ok(ctx)
}

/// Drain the peer session until it identifies (hello answered) or ends.
async fn wait_for_peer_identity(conn: &mut PeerConnection) -> Result<PeerIdentity> {
    while let Some(event) = conn.next_event().await {
        match event {
            PeerEvent::Connection(ConnectionEvent::Identified { identity }) => return Ok(identity),
            PeerEvent::Connection(ConnectionEvent::Disconnected { reason }) => {
                bail!("peer disconnected before identifying: {reason:?}");
            }
            other => println!("kad-handoff peer_event={other}"),
        }
    }
    bail!("peer session ended before Identified")
}

/// Wait (bounded) for the node to reach Kad contact after the handoff dial.
/// Returns `true` on the first `ContactResponded` (the dialed peer answered our
/// BOOTSTRAP_REQ — aMule's HasHadContact), `false` on the deadline.
async fn wait_for_kad_contact(kad: &mut KadNetHandle, window: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => return false,
            event = kad.next_event() => match event {
                Some(event) => {
                    println!("kad-handoff kad_event={event:?}");
                    if matches!(event, KadEvent::ContactResponded { .. }) {
                        return true;
                    }
                }
                None => return false,
            },
        }
    }
}
