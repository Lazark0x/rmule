//! Multi-registrant source staging (ADR-0043 controlled-identity harness leg).
//! Stages fabricated High-ID identities that each **serve** one file
//! on a live eD2k server, so a downloading aMule that get-sources the hash learns
//! ≥12 sources, connects to and *establishes* them (they answer the file request
//! with a full part status), and then — when a peer asks it for sources — packs
//! its `OP_ANSWERSOURCES` above the 354-byte threshold (the packed-source capture recipes).
//!
//! Each registrant is a full serve session (`rmule serve`, ADR-0031), and that
//! is load-bearing twice over. `CPartFile::CreateSrcInfoPacket` @4e8f2b3 counts
//! a source only if it is **not Low-ID** and is **established** —
//! `DS_DOWNLOADING`, or `DS_ONQUEUE` with room — with a known part status. So a
//! registrant must earn High-ID *and* actually serve the real file, so the
//! downloading aMule connects to it and learns its part status.
//!
//! The harness keeps that aMule mid-download by sizing the shared file beyond
//! what it can finish in the capture window — its `MaxDownload` cap is a
//! lagging feedback controller and cannot be relied on. A
//! *completed* file is no longer a partfile and has no source list to answer
//! with at all.
//!
//! Lugdunum assigns High-ID **per source IP**, so each identity runs in its own
//! container on a distinct static IP (many identities from one IP collapse to
//! one High-ID, the rest dropped — ADR-0040). `--count` is normally `1`.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, ServeCommand as CoreServeCommand, ServeEvent,
    ServerConnectionEvent, open_durable_store_in_memory,
};
use rmule_primitives::{ClientIdentity, Ed2kText, ServerEndpoint, UserHash};

/// Port offset between staging attempts for one identity, wide enough that a
/// retry never lands on another identity's port.
const RETRY_PORT_STRIDE: u16 = 1000;

#[derive(Debug, Args)]
pub(crate) struct RegisterSourcesArgs {
    /// File to serve (its ED2K hash is what every registrant registers as a
    /// source of).
    #[arg(long)]
    file: PathBuf,
    /// eD2k server endpoint as `host:port`.
    #[arg(long)]
    server: String,
    /// How many identities to stage from this process. Normally `1` (one
    /// identity per distinct-IP container); >1 shares this process's single IP
    /// and so only the first earns High-ID.
    #[arg(long, default_value_t = 1)]
    count: u16,
    /// Offset added to every identity's index so N single-identity containers
    /// still mint distinct user hashes (pass a different `--index-base` each).
    #[arg(long, default_value_t = 0)]
    index_base: u16,
    /// The advertised/listen TCP port; identity `i` serves on `port_base + i`.
    #[arg(long, default_value_t = 14662)]
    port_base: u16,
    /// CT_VERSION value advertised in each login.
    #[arg(long, default_value_t = 60)]
    protocol_version: u32,
    /// Per-registrant announce timeout, seconds.
    #[arg(long, default_value_t = 30)]
    announce_timeout: u64,
    /// Seconds to hold the registrations open after the last one announces; `0`
    /// runs until killed.
    #[arg(long, default_value_t = 0)]
    max_seconds: u64,
}

pub(crate) async fn run(args: RegisterSourcesArgs) -> Result<()> {
    let server = ServerEndpoint::parse_host_port(&args.server)
        .with_context(|| format!("parse server endpoint {}", args.server))?;
    println!(
        "register_sources: file={} count={} port_base={}",
        args.file.display(),
        args.count,
        args.port_base,
    );

    let mut announced = 0u16;
    for index in 0..args.count {
        let port = match args.port_base.checked_add(index) {
            Some(port) => port,
            None => {
                eprintln!("registrant[{index}]: port_base + {index} overflows u16; stopping");
                break;
            }
        };
        let identity_index = args.index_base.wrapping_add(index);
        // Retry with backoff; each attempt is a fresh serve session on the same
        // identity. Only genuine transients are in scope — a server that grants
        // concurrent High-ID logins needs no retry to reach its quota.
        let mut staged = false;
        for attempt in 0..4u32 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(u64::from(attempt))).await;
            }
            // A timed-out attempt's serve activity keeps its listener bound, so
            // reusing the port makes every retry fail with EADDRINUSE instead of
            // retrying anything. Each attempt therefore takes its own port; the
            // advertised port travels in the identity, so whichever attempt wins
            // is the one the server publishes.
            let attempt_port = port.saturating_add(
                u16::try_from(attempt)
                    .unwrap_or(0)
                    .saturating_mul(RETRY_PORT_STRIDE),
            );
            match stage_one(&args, server.clone(), identity_index, attempt_port).await {
                Ok(()) => {
                    staged = true;
                    break;
                }
                Err(error) => {
                    eprintln!(
                        "registrant[{identity_index}] port={attempt_port} attempt {attempt}: {error:#}"
                    );
                }
            }
        }
        if staged {
            announced += 1;
        }
    }

    println!(
        "register_sources: requested={} live={announced}",
        args.count,
    );
    // The readiness marker the harness waits on before it starts the downloader.
    println!("rmule-registrants-ready {announced}");

    if announced == 0 {
        anyhow::bail!("no registrant announced its share — cannot stage sources");
    }

    if args.max_seconds > 0 {
        tokio::time::sleep(Duration::from_secs(args.max_seconds)).await;
    } else {
        std::future::pending::<()>().await;
    }
    Ok(())
}

/// Spawn one serve session (share + StartServing), wait for it to announce, then
/// hand its `Core` to a background drain task that keeps it alive and serving.
async fn stage_one(
    args: &RegisterSourcesArgs,
    server: ServerEndpoint,
    index: u16,
    port: u16,
) -> Result<()> {
    let identity = ClientIdentity::new(
        registrant_user_hash(index),
        Ed2kText::from_utf8(format!("rmule-reg-{index}")),
        port,
        args.protocol_version,
    );

    let mut core = Core::builder(CoreConfig::default(), open_durable_store_in_memory()?)
        .user_hash(identity.user_hash())
        .build();
    let share = crate::share::share_files(&mut core, std::slice::from_ref(&args.file), |_| {})
        .await
        .context("share file")?;
    core.send(CoreCommand::Serve(CoreServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port),
        credentials: identity.clone().into(),
    }))
    .await
    .context("start serving")?;
    crate::node::connect(&core, &server, identity.into()).await?;

    // Wait for the login AND the announce. Two facts, two events: the serve
    // start does not wait for the login, and `FilesAnnounced` is raised when
    // `OP_OFFERFILES` goes out on the session. They can arrive in either
    // order.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.announce_timeout);
    let (mut announced, mut logged_in) = (false, false);
    while !(announced && logged_in) {
        match tokio::time::timeout_at(deadline, core.next_event()).await {
            Ok(Some(CoreEvent::Serve(ServeEvent::FilesAnnounced { file_count }))) => {
                println!("registrant[{index}]: port={port} announced file_count={file_count}");
                announced = true;
            }
            Ok(Some(CoreEvent::ServerConnection(ServerConnectionEvent::Connected {
                client_id,
                ..
            }))) => {
                println!("registrant[{index}]: port={port} logged in client_id={client_id:?}");
                logged_in = true;
            }
            Ok(Some(CoreEvent::ServerConnection(ServerConnectionEvent::ConnectFailed {
                reason,
                ..
            }))) => anyhow::bail!("registrant login failed: {reason:?}"),
            Ok(Some(CoreEvent::Serve(ServeEvent::ServingFailed { reason }))) => {
                anyhow::bail!("the registrant's listener never bound: {reason:?}")
            }
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("serve event stream ended before announce"),
            Err(_) => anyhow::bail!(
                "serve did not announce and log in within {}s",
                args.announce_timeout
            ),
        }
    }

    // Keep the Core alive and draining so it keeps serving for the whole window.
    // The share's directory lives as long as the core serves from it.
    tokio::spawn(async move {
        let _share = share;
        while core.next_event().await.is_some() {}
    });
    Ok(())
}

/// A distinct 16-byte User Hash per registrant: a fixed marker prefix, the
/// eMule client-hash sentinel bytes (`[5] = 14`, `[14] = 111`) so the server
/// treats it as an eMule client, and the index in the leading bytes so every
/// registrant is a different source identity.
fn registrant_user_hash(index: u16) -> UserHash {
    let mut bytes = [0x11u8; UserHash::BYTE_LEN];
    bytes[5] = 14;
    bytes[14] = 111;
    let idx = index.to_le_bytes();
    bytes[0] = idx[0];
    bytes[1] = idx[1];
    UserHash::from_bytes(bytes)
}
