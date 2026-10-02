//! `rmule-tools ipv6 route` — ask a real [`Core`] which of the ADR-0061 routes
//! reaches a peer that is **Low ID on IPv4 and reachable on IPv6**, and record
//! the verdict it publishes.
//!
//! Rung 0 (ADR-0087) is an AND: the peer named a usable IPv6 *and* this node
//! holds a Known one. Both halves are supplied here as facts a flow can vary —
//! `--peer-ipv6` is what the counterparty's own hello carried, `--external-v6`
//! is the Override tier of **Address Learning**, which is how a container
//! states the address its interface holds without waiting for a quorum.
//!
//! The verdict alone is rmule's own state and proves nothing (ADR-0045). What
//! it is *for* is the control half of the `ipv6-direct-dial-lowid` row: the
//! same target dialled with and without our own address, so the flow can show
//! that the IPv6 dial happened **because** of rung 0 and not because the peer
//! had nowhere else to be reached.

use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, ExternalAddressOverride, PeerReach, PeerReachRoute,
    ServeCommand, open_durable_store_in_memory,
};
use rmule_net::family::FamilySelection;
use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, Ipv6Endpoint, PeerEndpoint, UserHash};

use crate::driver_row::Row;

#[derive(Debug, Args)]
pub(crate) struct Ipv6RouteArgs {
    /// The peer's server-assigned id. Below `0x01000000` it is a Low ID, which
    /// is the case the row is about.
    #[arg(long, default_value_t = 42)]
    peer_client_id: u32,
    /// The peer's last-seen IPv4 endpoint — never dialled for a Low ID, and
    /// carried so the row shows the chooser had one and declined it.
    #[arg(long, default_value = "45.55.200.9:4662")]
    peer_tcp: String,
    /// The peer's own IPv6 (its `CT_MOD_IP_V6`), and its peer TCP port.
    #[arg(long)]
    peer_ipv6: Option<Ipv6Addr>,
    /// The port on that address.
    #[arg(long, default_value_t = 4662)]
    peer_ipv6_port: u16,
    /// Whether the peer is on the server we are connected to — the server
    /// callback rung, kept available so rung 0 is seen to outrank it.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    on_our_server: bool,
    /// Our own Known IPv6, stated at the Override tier.
    #[arg(long)]
    external_v6: Option<Ipv6Addr>,
    /// Which families this node's sockets bind. The control leg passes `v4`,
    /// and that — not merely omitting `--external-v6` — is what makes it a
    /// control: on a dual-stack container the **Interface Source** finds the
    /// real address by itself, so a node that still binds IPv6 holds one
    /// whether or not an override named it, and rung 0's AND would be
    /// satisfied from the other side.
    #[arg(long, default_value = "both")]
    families: String,
    /// Bind the eD2k peer listener here. Binding it is what gives the
    /// **Advertised Endpoints** chooser a v6 TCP endpoint to name: the chooser
    /// refuses to advertise an address with no socket behind it, so an
    /// `--external-v6` alone leaves rung 0's own half empty. The **Family
    /// Pair** binds this port in both families.
    #[arg(long, default_value = "0.0.0.0:4662")]
    listen: std::net::SocketAddrV4,
    /// Our user hash, hex.
    #[arg(long, default_value = "42424242424242424242424242424242")]
    user_hash: String,
    /// How long to wait for the verdict.
    #[arg(long, default_value_t = 30)]
    window_secs: u64,
    /// Where to write the row.
    #[arg(long)]
    out: PathBuf,
}

/// The chooser's verdict for one target.
#[derive(Debug)]
struct RouteRow {
    /// The target's id and class.
    peer_client_id: u32,
    peer_is_low_id: bool,
    /// Its IPv4 endpoint, as supplied.
    peer_tcp: String,
    /// Its IPv6, or empty.
    peer_ipv6: String,
    /// Our own address, as stated — rung 0's second half.
    our_ipv6: String,
    /// Whether the peer was reachable through its server.
    on_our_server: bool,
    /// The route name the Core published: `direct`, `direct-udp`,
    /// `direct-udp-unavailable`, `server`, `buddy`, `dropped`, or `none` when
    /// no verdict arrived inside the window.
    route: &'static str,
    /// The verdict rendered whole, for the record.
    route_detail: String,
    /// Whether that route is rung 0 — a direct dial while the peer is Low ID,
    /// which no other rung can produce.
    rung_zero: bool,
}

/// Boot a Core, ask it, and write the row.
///
/// # Errors
/// If the endpoint will not parse, the Core will not start, or the row cannot
/// be written.
pub(crate) async fn run_route(args: Ipv6RouteArgs) -> Result<()> {
    let peer_tcp: std::net::SocketAddrV4 = args
        .peer_tcp
        .parse()
        .with_context(|| format!("parse peer TCP endpoint {}", args.peer_tcp))?;
    let config = CoreConfig {
        external_address: ExternalAddressOverride {
            v4: None,
            v6: args.external_v6,
        },
        address_families: match args.families.as_str() {
            "v4" => FamilySelection {
                v4: true,
                v6: false,
            },
            "v6" => FamilySelection {
                v4: false,
                v6: true,
            },
            "both" => FamilySelection { v4: true, v6: true },
            other => anyhow::bail!("unknown --families {other}; expected v4, v6 or both"),
        },
        ..CoreConfig::default()
    };
    let user_hash = UserHash::from_bytes(crate::operand::parse_user_hash(&args.user_hash)?);
    let mut core = Core::builder(config, open_durable_store_in_memory()?)
        .user_hash(user_hash)
        .build();
    let identity = ClientIdentity::new(user_hash, Ed2kText::from_utf8("rmule-tools"), 4662, 60);
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: args.listen,
        credentials: identity.into(),
    }))
    .await?;

    let peer_ipv6 = args
        .peer_ipv6
        .map(|address| Ipv6Endpoint::new(address, args.peer_ipv6_port));
    let reach = PeerReach {
        id: ClientId::from_u32(args.peer_client_id),
        tcp: PeerEndpoint::V4(rmule_primitives::Ipv4Endpoint::new(
            *peer_tcp.ip(),
            peer_tcp.port(),
        )),
        supports_direct_udp_callback: false,
        kad_udp: None,
        on_our_server: args.on_our_server,
        buddy: None,
        ipv6: peer_ipv6,
        supports_natt: false,
        // Rung 1 is not this driver's route; the ledger key it would need
        // is only ever a hash the caller already holds.
        user_hash: None,
    };

    let mut row = RouteRow {
        peer_client_id: args.peer_client_id,
        peer_is_low_id: !ClientId::from_u32(args.peer_client_id).is_high_id(),
        peer_tcp: peer_tcp.to_string(),
        peer_ipv6: peer_ipv6.map(|e| e.to_string()).unwrap_or_default(),
        our_ipv6: args.external_v6.map(|a| a.to_string()).unwrap_or_default(),
        on_our_server: args.on_our_server,
        route: "none",
        route_detail: String::new(),
        rung_zero: false,
    };

    // The ask is repeated rather than asked once: the chooser's own half of
    // rung 0 is the **Advertised IPv6**, which is settled on the session's poll
    // after the listener binds, so the first verdict of a fresh Core is taken
    // before there is anything to advertise. The loop stops at the first
    // non-`server` route and otherwise keeps the last one, so the row records
    // what the chooser settled on rather than what it started with.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.window_secs);
    let mut next_ask = tokio::time::Instant::now();
    loop {
        if tokio::time::Instant::now() >= next_ask {
            core.send(CoreCommand::ReachPeer(reach)).await?;
            next_ask = tokio::time::Instant::now() + Duration::from_secs(2);
        }
        let event = tokio::select! {
            () = tokio::time::sleep_until(deadline) => break,
            () = tokio::time::sleep_until(next_ask) => continue,
            event = core.next_event() => event,
        };
        let Some(event) = event else { break };
        if let CoreEvent::PeerReachRouted { route, .. } = event {
            row.route = name(route);
            row.route_detail = format!("{route:?}");
            row.rung_zero = matches!(route, PeerReachRoute::Direct) && row.peer_is_low_id;
            if row.rung_zero || !row.peer_is_low_id {
                break;
            }
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), core.shutdown()).await;

    println!(
        "ipv6-route peer_low_id={} peer_ipv6={:?} our_ipv6={:?} route={} rung_zero={}",
        row.peer_is_low_id, row.peer_ipv6, row.our_ipv6, row.route, row.rung_zero
    );
    let mut out = Row::new(
        "rmule-tools ipv6 route — the ADR-0061 route chooser's verdict for a\n\
         Low-ID peer that named an IPv6 (rung 0, ADR-0087). Stimulus: rmule's own\n\
         decision, judged against whether the counterparty then answered.",
    );
    out.int("peer_client_id", i64::from(row.peer_client_id))
        .bool("peer_is_low_id", row.peer_is_low_id)
        .str("peer_tcp", &row.peer_tcp)
        .str("peer_ipv6", &row.peer_ipv6)
        .str("our_ipv6", &row.our_ipv6)
        .bool("on_our_server", row.on_our_server)
        .str("route", row.route)
        .str("route_detail", &row.route_detail)
        .bool("rung_zero", row.rung_zero);
    crate::driver_row::write_row(&args.out, out)
}

const fn name(route: PeerReachRoute) -> &'static str {
    match route {
        PeerReachRoute::Direct => "direct",
        PeerReachRoute::DirectUdp { .. } => "direct-udp",
        PeerReachRoute::DirectUdpUnavailable { .. } => "direct-udp-unavailable",
        PeerReachRoute::Server { .. } => "server",
        PeerReachRoute::Buddy { .. } | PeerReachRoute::CallbackWalk { .. } => "buddy",
        PeerReachRoute::NatTraversal { .. } => "nat-traversal",
        PeerReachRoute::NatTraversalUnavailable { .. } => "nat-traversal-unavailable",
        PeerReachRoute::ServerPunch { .. } => "server-punch",
        PeerReachRoute::ServerPunchUnavailable { .. } => "server-punch-unavailable",
        PeerReachRoute::Dropped { .. } => "dropped",
    }
}
