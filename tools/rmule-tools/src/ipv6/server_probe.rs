//! `rmule-tools ipv6 server-probe` — log in to a live eD2k server with the
//! dialect's advert on, ask it for a file's sources and its server list, and
//! write down the *server's* whole IPv6 surface.
//!
//! This is the driver behind `ipv6-server-sentinel`. Its first job is the one
//! ADR-0092's IPv6 server row cannot assume: **whether the pinned server speaks the
//! dialect at all.** A server that never sets `SRV_TCPFLG`'s `0x4000`, never
//! sends `ST_IPV6_STATUS`, never names its own `CT_MOD_SVR_IP_V6` and returns
//! no **Sentinel Source** has said so in its own bytes, and that measured
//! silence is what a **Documented Absence** has to rest on — rather than on a
//! reading of a release note.
//!
//! When a capable pin does appear, the same row carries the positive case
//! without a change: the sentinel count, the IPv6 sources the tail yielded, and
//! the trailing v6 block of `OP_SERVERLIST`.

use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_ed2k::{Ed2kCommand, Ed2kEvent};
use rmule_net::ed2k::{ConnectOptions, Connection};
use rmule_primitives::{
    ClientIdentity, Ed2kText, FileHash, PeerSource, ServerEndpoint, SourceLookupTarget, UserHash,
};

use crate::driver_row::Row;
use crate::operand::{parse_hex16, parse_user_hash};

#[derive(Debug, Args)]
pub(crate) struct Ipv6ServerProbeArgs {
    /// The server, `host:port`.
    #[arg(long)]
    server: String,
    /// Our Known IPv6 — advertised at login as `CT_MOD_IP_V6` with its coupled
    /// `SRVCAP_IPV6` capability bit. Omitted, neither is sent, which is the
    /// control leg.
    #[arg(long)]
    advertise_ipv6: Option<Ipv6Addr>,
    /// Ask for this file's sources once logged in; a sentinel-bearing answer is
    /// what the IPv6 server row is looking for.
    #[arg(long)]
    file_hash: Option<String>,
    /// The file size that accompanies the source request.
    #[arg(long, default_value_t = 1_048_576)]
    file_size: u64,
    /// Nickname tag.
    #[arg(long, default_value = "rmule-tools")]
    nickname: String,
    /// Our user hash, hex.
    #[arg(long, default_value = "42424242424242424242424242424242")]
    user_hash: String,
    /// The TCP port the login advertises.
    #[arg(long, default_value_t = 4662)]
    tcp_port: u16,
    /// `CT_VERSION`.
    #[arg(long, default_value_t = 60)]
    protocol_version: u32,
    /// Capture directory for the session's raw streams.
    #[arg(long)]
    capture: PathBuf,
    /// Where to write the row.
    #[arg(long)]
    out: PathBuf,
    /// Connect budget, seconds.
    #[arg(long, default_value_t = 15)]
    connect_timeout: u64,
    /// How long to keep reading after login before writing the row.
    #[arg(long, default_value_t = 25)]
    window_secs: u64,
}

/// The server's IPv6 surface, as the server itself presented it.
#[derive(Debug)]
struct ServerProbeRow {
    /// The endpoint dialled.
    server: String,
    /// What we advertised, or empty.
    advertised_ipv6: String,
    /// Whether the TCP session came up.
    connected: bool,
    /// Whether the login was accepted.
    login_accepted: bool,
    /// The assigned id.
    client_id: u32,
    /// Whether the id is a High one.
    high_id: bool,
    /// Whether the server sent capability flags at all, and the word it sent.
    tcp_flags_present: bool,
    tcp_flags_bits: u32,
    /// `SRV_TCPFLG_IPV6` (`0x4000`) — the server saying it speaks the dialect.
    /// **This is the gate**: every other row below is only meaningful once it
    /// holds.
    server_claims_ipv6: bool,
    /// Whether an `OP_SERVERIDENT` arrived, and what its IPv6 tags carried.
    server_ident_received: bool,
    server_ipv6: String,
    reflected_ipv6: String,
    ipv6_status_present: bool,
    ipv6_status_bits: u32,
    /// Whether the trailing IPv6 block of `OP_SERVERLIST` carried anything —
    /// the surface ADR-0087 classifies as **`single-oracle`** (eNode-go alone).
    server_list_received: bool,
    server_list_v4_count: usize,
    server_list_v6_count: usize,
    /// Whether a source list came back, and what its **Sentinel Source** tail
    /// read.
    sources_requested: bool,
    sources_received: bool,
    source_count: usize,
    sentinel_count: usize,
    sentinel_tail_malformed: bool,
    /// The IPv6 sources the tail actually yielded, rendered.
    ipv6_sources: Vec<String>,
    /// Why the session ended.
    closed: String,
}

/// Log in, ask, listen, and write the row.
///
/// # Errors
/// If an operand will not parse or the row cannot be written. A server that
/// refuses the login, or that answers nothing, is a row — that is the whole
/// point of this driver.
pub(crate) async fn run_server_probe(args: Ipv6ServerProbeArgs) -> Result<()> {
    let endpoint = ServerEndpoint::parse_host_port(&args.server)
        .with_context(|| format!("parse server endpoint {}", args.server))?;
    let user_hash = UserHash::from_bytes(parse_user_hash(&args.user_hash)?);
    let identity = ClientIdentity::new(
        user_hash,
        Ed2kText::from_utf8(&args.nickname),
        args.tcp_port,
        args.protocol_version,
    );
    let file_hash = args
        .file_hash
        .as_deref()
        .map(|hex| parse_hex16("--file-hash", hex))
        .transpose()?
        .map(FileHash::from_bytes);

    let mut row = ServerProbeRow {
        server: format!("{}:{}", endpoint.host(), endpoint.port()),
        advertised_ipv6: args
            .advertise_ipv6
            .map(|a| a.to_string())
            .unwrap_or_default(),
        connected: false,
        login_accepted: false,
        client_id: 0,
        high_id: false,
        tcp_flags_present: false,
        tcp_flags_bits: 0,
        server_claims_ipv6: false,
        server_ident_received: false,
        server_ipv6: String::new(),
        reflected_ipv6: String::new(),
        ipv6_status_present: false,
        ipv6_status_bits: 0,
        server_list_received: false,
        server_list_v4_count: 0,
        server_list_v6_count: 0,
        sources_requested: false,
        sources_received: false,
        source_count: 0,
        sentinel_count: 0,
        sentinel_tail_malformed: false,
        ipv6_sources: Vec::new(),
        closed: String::new(),
    };

    let options = ConnectOptions {
        capture_dir: Some(args.capture.clone()),
        connect_timeout: Duration::from_secs(args.connect_timeout),
        login_timeout: Duration::from_secs(args.connect_timeout),
        obfuscation: None,
        obfuscated_port: None,
        advertised_ipv6: args.advertise_ipv6,
        udp_ports: None,
    };
    match Connection::connect_with_options(endpoint, identity, options).await {
        Ok(connection) => {
            row.connected = true;
            listen(connection, &args, file_hash, &mut row).await;
        }
        Err(error) => row.closed = error.to_string(),
    }

    println!(
        "ipv6-server-probe claims_ipv6={} ident={} status={} sentinels={} v6_servers={}",
        row.server_claims_ipv6,
        row.server_ident_received,
        row.ipv6_status_present,
        row.sentinel_count,
        row.server_list_v6_count
    );
    let mut out = Row::new(
        "rmule-tools ipv6 server-probe — the eD2k server's own IPv6 surface\n\
         (ADR-0087). `server_claims_ipv6` is the gate: false means the pinned\n\
         server does not speak the dialect, which is the measured silence a\n\
         Documented Absence rests on.",
    );
    out.str("server", &row.server)
        .str("advertised_ipv6", &row.advertised_ipv6)
        .bool("connected", row.connected)
        .bool("login_accepted", row.login_accepted)
        .int("client_id", i64::from(row.client_id))
        .bool("high_id", row.high_id)
        .bool("tcp_flags_present", row.tcp_flags_present)
        .int("tcp_flags_bits", i64::from(row.tcp_flags_bits))
        .bool("server_claims_ipv6", row.server_claims_ipv6)
        .bool("server_ident_received", row.server_ident_received)
        .str("server_ipv6", &row.server_ipv6)
        .str("reflected_ipv6", &row.reflected_ipv6)
        .bool("ipv6_status_present", row.ipv6_status_present)
        .int("ipv6_status_bits", i64::from(row.ipv6_status_bits))
        .bool("server_list_received", row.server_list_received)
        .int(
            "server_list_v4_count",
            i64::try_from(row.server_list_v4_count).unwrap_or(-1),
        )
        .int(
            "server_list_v6_count",
            i64::try_from(row.server_list_v6_count).unwrap_or(-1),
        )
        .bool("sources_requested", row.sources_requested)
        .bool("sources_received", row.sources_received)
        .int(
            "source_count",
            i64::try_from(row.source_count).unwrap_or(-1),
        )
        .int(
            "sentinel_count",
            i64::try_from(row.sentinel_count).unwrap_or(-1),
        )
        .bool("sentinel_tail_malformed", row.sentinel_tail_malformed)
        .list("ipv6_sources", &row.ipv6_sources)
        .str("closed", &row.closed);
    crate::driver_row::write_row(&args.out, out)
}

/// Drain the session's events for the window, recording every IPv6-bearing
/// fact the server volunteered.
async fn listen(
    mut connection: Connection,
    args: &Ipv6ServerProbeArgs,
    file_hash: Option<FileHash>,
    row: &mut ServerProbeRow,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.window_secs);
    loop {
        let event = tokio::select! {
            () = tokio::time::sleep_until(deadline) => break,
            event = connection.next_event() => event,
        };
        let Some(event) = event else { break };
        match event {
            Ed2kEvent::LoginAccepted {
                client_id,
                tcp_flags,
                ..
            } => {
                row.login_accepted = true;
                row.client_id = client_id.as_u32();
                row.high_id = client_id.is_high_id();
                if let Some(flags) = tcp_flags {
                    row.tcp_flags_present = true;
                    row.tcp_flags_bits = flags.bits();
                    row.server_claims_ipv6 = flags.supports_ipv6();
                }
                // Both asks go out at once: the server list is where the
                // trailing v6 block lives, the source list is where a Sentinel
                // Source would.
                let _ = connection.send(Ed2kCommand::RequestServerList).await;
                if let Some(hash) = file_hash {
                    row.sources_requested = true;
                    let _ = connection
                        .send(Ed2kCommand::RequestSources {
                            target: SourceLookupTarget::new(hash, args.file_size),
                        })
                        .await;
                }
            }
            Ed2kEvent::LoginRejected => {
                row.closed = "the server rejected the login".to_owned();
                break;
            }
            Ed2kEvent::ServerIdentified { identity } => {
                row.server_ident_received = true;
                if let Some(address) = identity.server_ipv6 {
                    row.server_ipv6 = address.to_string();
                }
                if let Some(address) = identity.reflected_ipv6 {
                    row.reflected_ipv6 = address.to_string();
                }
                if let Some(status) = identity.ipv6_status {
                    row.ipv6_status_present = true;
                    row.ipv6_status_bits = status.bits();
                }
            }
            Ed2kEvent::ServerListReceived {
                servers,
                ipv6_servers,
            } => {
                row.server_list_received = true;
                row.server_list_v4_count = servers.len();
                row.server_list_v6_count = ipv6_servers.len();
            }
            Ed2kEvent::SourcesFound { sources, tail, .. } => {
                row.sources_received = true;
                row.source_count = sources.len();
                row.sentinel_count = tail.sentinels();
                row.sentinel_tail_malformed = tail.is_malformed();
                row.ipv6_sources = sources
                    .iter()
                    .filter_map(|source| match source.peer_source()? {
                        PeerSource::Ipv6(endpoint) => Some(endpoint.to_string()),
                        PeerSource::HighId(_) | PeerSource::LowId { .. } => None,
                    })
                    .collect();
            }
            Ed2kEvent::Disconnected { reason } => {
                row.closed = format!("{reason:?}");
                break;
            }
            other => println!("{other}"),
        }
    }
    let _ = connection.shutdown().await;
}
