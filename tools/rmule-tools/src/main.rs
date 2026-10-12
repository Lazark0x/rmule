//! `rmule-tools` — protocol primitive inspection and live-capture CLI.
//!
//! This entry point installs the process-wide tracing subscriber and routes;
//! each protocol area owns its commands, argument structs, and verbose
//! inspectors in a dedicated module, and the one-line event summaries printed
//! during captures are the co-located `Display` projections on the event enums
//! (`Ed2kEvent`, `PeerEvent`, the core event enums) rather than re-walked here.

#![warn(missing_docs)]

mod bootstrap_fetch;
mod capture;
mod cli;
mod download;
mod driver_row;
mod ed2k;
mod ipv6;
mod kad_handoff;
mod kad_join_node;
mod nat;
mod natt;
mod node;
mod operand;
mod output;
mod peer;
mod register_sources;
mod search;
mod serve;
mod share;

use anyhow::Result;
use clap::Parser;

use cli::{
    Cli, Command, DownloadCommand, Ed2kCommand, Ipv6Subcommand, KadSubcommand, LoginCommand,
    NatSubcommand, NattSubcommand, PacketCommand, PeerSubcommand, PeerTransferCommand,
    PeerWelcomeCommand, ServeCommand, ServerCommand, WelcomeCommand,
};

/// Install a tracing subscriber driven by `RMULE_LOG`, `RMULE_LOG_FORMAT`,
/// and `RMULE_LOG_FILE` (ADR-0027). The returned guard keeps the file
/// appender's non-blocking writer alive for the lifetime of `main`.
fn init_tracing() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = EnvFilter::try_from_env("RMULE_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let format = std::env::var("RMULE_LOG_FORMAT").unwrap_or_else(|_| "pretty".into());
    let file_path = std::env::var("RMULE_LOG_FILE").ok();

    let (file_layer, guard): (
        Option<Box<dyn tracing_subscriber::Layer<_> + Send + Sync>>,
        _,
    ) = match file_path {
        Some(path) => {
            let path = std::path::PathBuf::from(path);
            let dir = path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            let prefix = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "rmule".into());
            let appender = tracing_appender::rolling::daily(dir, prefix);
            let (writer, guard) = tracing_appender::non_blocking(appender);
            let layer = fmt::layer().with_writer(writer).with_ansi(false);
            (Some(Box::new(layer)), Some(guard))
        }
        None => (None, None),
    };

    let stderr_layer: Box<dyn tracing_subscriber::Layer<_> + Send + Sync> = if format == "json" {
        Box::new(fmt::layer().json().with_writer(std::io::stderr))
    } else {
        Box::new(fmt::layer().with_writer(std::io::stderr))
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer)
        .with(file_layer)
        .init();

    guard
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let _tracing_guard = init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Command::Ed2k { command } => match command {
            Ed2kCommand::ParseLink { link } => ed2k::parse_link(&link)?,
            Ed2kCommand::CanonicalLink { link } => ed2k::canonical_link(&link)?,
            Ed2kCommand::HashFile { path } => ed2k::hash_file(&path)?,
            Ed2kCommand::PartHashes { path } => ed2k::part_hashes(&path)?,
            Ed2kCommand::SentinelProbe => ed2k::sentinel_probe()?,
            Ed2kCommand::SentinelStimulus(args) => ed2k::sentinel_stimulus(args).await?,
            Ed2kCommand::Download { command } => match command {
                DownloadCommand::Start(args) => download::start(args).await?,
                DownloadCommand::Resume(args) => download::resume(args).await?,
                DownloadCommand::Pause(args) => download::pause(args)?,
                DownloadCommand::Status(args) => download::status(args)?,
            },
            Ed2kCommand::Packet { command } => match command {
                PacketCommand::Inspect { path } => ed2k::inspect_packet(&path)?,
            },
            Ed2kCommand::Login { command } => match command {
                LoginCommand::Inspect { path } => ed2k::inspect_login(&path)?,
            },
            Ed2kCommand::ServerPacket { command } => match command {
                PacketCommand::Inspect { path } => ed2k::inspect_server_packet(&path)?,
            },
            Ed2kCommand::ClientPacket { command } => match command {
                PacketCommand::Inspect { path } => ed2k::inspect_client_packet(&path)?,
            },
            Ed2kCommand::Server { command } => match command {
                ServerCommand::Welcome { command } => match command {
                    WelcomeCommand::Live(args) => ed2k::welcome_live(args).await?,
                    WelcomeCommand::Slice(args) => ed2k::welcome_slice(args)?,
                },
                ServerCommand::Probe(args) => ed2k::server_probe(args).await?,
                ServerCommand::UdpCapture(args) => ed2k::server_udp_capture(args).await?,
                ServerCommand::SearchWire(args) => ed2k::search_wire(args).await?,
            },
            Ed2kCommand::Search(args) => search::run(args).await?,
            Ed2kCommand::Serve { command } => match command {
                ServeCommand::Start(args) => serve::start(args).await?,
            },
            Ed2kCommand::RegisterSources(args) => register_sources::run(args).await?,
            Ed2kCommand::Peer { command } => match command {
                PeerSubcommand::Welcome { command } => match command {
                    PeerWelcomeCommand::Capture(args) => peer::welcome_capture(args).await?,
                },
                PeerSubcommand::Transfer { command } => match command {
                    PeerTransferCommand::Capture(args) => peer::transfer_capture(args).await?,
                },
                PeerSubcommand::Packet { command } => match command {
                    PacketCommand::Inspect { path } => peer::inspect_packet(&path)?,
                },
                PeerSubcommand::ReaskCapture(args) => peer::reask_capture(args).await?,
            },
            Ed2kCommand::KadHandoff(args) => kad_handoff::run(args).await?,
            Ed2kCommand::BootstrapFetch(args) => bootstrap_fetch::run(args).await?,
        },
        Command::Kad { command } => match command {
            KadSubcommand::JoinNode(args) => kad_join_node::run(args).await?,
        },
        Command::Nat { command } => match command {
            NatSubcommand::Probe(args) => nat::run_nat_probe(args)?,
            NatSubcommand::PeerReach(args) => nat::run_nat_peer_reach(args)?,
            NatSubcommand::Portmap(args) => nat::run_nat_portmap(*args).await?,
        },
        Command::Ipv6 { command } => match command {
            Ipv6Subcommand::Hello(args) => ipv6::run_hello(args).await?,
            Ipv6Subcommand::UdpKey(args) => ipv6::run_udp_key(args).await?,
            Ipv6Subcommand::Route(args) => ipv6::run_route(args).await?,
            Ipv6Subcommand::ServerProbe(args) => ipv6::run_server_probe(args).await?,
            Ipv6Subcommand::HoldSlot(args) => ipv6::run_hold_slot(args).await?,
            Ipv6Subcommand::SxAsk(args) => ipv6::run_sx_ask(args).await?,
        },
        Command::Natt { command } => match command {
            NattSubcommand::CapsUtp(args) => natt::run_caps_utp(args).await?,
            NattSubcommand::ServerPunch(args) => natt::run_server_punch(*args).await?,
            NattSubcommand::TunnelTransfer(args) => natt::run_tunnel_transfer(*args).await?,
            NattSubcommand::BuddyRendezvous(args) => {
                natt::run_buddy_rendezvous(*args).await?;
            }
        },
    }

    Ok(())
}
