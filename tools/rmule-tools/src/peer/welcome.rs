//! The `peer welcome capture` command: dial one peer through the eD2k login
//! that supplies its callback context and record the hello exchange both
//! directions, so a handshake fixture can be promoted from a live counterparty.

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_ed2k::Ed2kEvent;
use rmule_net::ed2k::{ConnectOptions, Connection};
use rmule_net::peer::{ConnectOptions as PeerConnectOptions, Connection as PeerConnection};
use rmule_peer::{ConnectionEvent, PeerEvent};
use rmule_primitives::{ClientIdentity, Ed2kText, ServerEndpoint, UserHash};

use crate::operand::{parse_peer_endpoint, parse_user_hash};

#[derive(Debug, Args)]
pub(crate) struct PeerCaptureArgs {
    /// Peer endpoint as `ipv4:port` (e.g. `203.0.113.1:4662`).
    #[arg(long)]
    peer_endpoint: String,
    /// Server endpoint as `host:port`; needed so the live client
    /// observes `LoginAccepted` and builds a `PeerHandshakeContext`.
    #[arg(long)]
    server: String,
    /// Output directory for capture artifacts
    /// (`inbound.bin` / `outbound.bin` / `meta.toml` / `events.toml`).
    #[arg(long)]
    out: std::path::PathBuf,
    /// After capture, slice the eD2k server-side `s2c.bin` into per-packet
    /// fixture files (mirrors `ed2k server welcome slice`). Peer-side
    /// slicing is not yet supported.
    #[arg(long = "slice-server", alias = "slice")]
    slice_server: bool,
    /// Client nickname tag value.
    #[arg(long, default_value = "rmule-tools")]
    nickname: String,
    /// 16-byte user hash as upper-case hex (32 chars).
    #[arg(long, default_value = "42424242424242424242424242424242")]
    user_hash: String,
    /// Local TCP port advertised in the peer hello.
    #[arg(long, default_value_t = 4662)]
    tcp_port: u16,
    /// CT_VERSION value.
    #[arg(long, default_value_t = 60)]
    protocol_version: u32,
    /// Connect timeout, seconds.
    #[arg(long, default_value_t = 10)]
    connect_timeout: u64,
    /// Login + hello response timeout, seconds.
    #[arg(long, default_value_t = 15)]
    response_timeout: u64,
}

pub(crate) async fn welcome_capture(args: PeerCaptureArgs) -> Result<()> {
    let server_endpoint = ServerEndpoint::parse_host_port(&args.server)
        .with_context(|| format!("parse server endpoint {}", args.server))?;
    let peer_endpoint = parse_peer_endpoint(&args.peer_endpoint)?;
    let user_hash = UserHash::from_bytes(parse_user_hash(&args.user_hash)?);
    let identity = ClientIdentity::new(
        user_hash,
        Ed2kText::from_utf8(&args.nickname),
        args.tcp_port,
        args.protocol_version,
    );
    let response_timeout = Duration::from_secs(args.response_timeout);
    let server_options = ConnectOptions {
        capture_dir: Some(args.out.join("server")),
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
                anyhow::bail!("server session ended before LoginAccepted: {reason:?}");
            }
            _ => {}
        }
    }
    let client_id = client_id.context("LoginAccepted not observed")?;

    let ctx = rmule_core::build_peer_handshake_context(client_id, &server_endpoint, &identity);
    let peer_options = PeerConnectOptions {
        capture_dir: Some(args.out.join("peer")),
        connect_timeout: Duration::from_secs(args.connect_timeout),
        hello_timeout: response_timeout,
        ..Default::default()
    };
    let mut peer_conn = PeerConnection::connect(peer_endpoint, ctx, peer_options).await?;
    while let Some(event) = peer_conn.next_event().await {
        println!("{event}");
        if matches!(
            event,
            PeerEvent::Connection(ConnectionEvent::Identified { .. })
        ) {
            break;
        }
        if matches!(
            event,
            PeerEvent::Connection(ConnectionEvent::Disconnected { .. })
        ) {
            break;
        }
    }
    let _ = peer_conn.shutdown().await;
    let _ = server_conn.shutdown().await;

    if args.slice_server {
        crate::ed2k::slice_capture(&args.out.join("server"))?;
    }
    Ok(())
}
