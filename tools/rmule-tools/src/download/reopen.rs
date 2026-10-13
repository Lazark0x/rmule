//! `download reopen`: open a Durable Store as a restarted node does and serve
//! what it holds, resuming nothing. Every queued or paused download attaches
//! as a Served Download with an empty Verified Range and is offered only once
//! its **Offer Check** has read its recorded parts again (ADR-0113 §"A paused
//! download"); the run then serves it until its deadline.
//!
//! Core's `serve.offer_checked` record says what each check read and how
//! long the read took; this run bounds the whole wait from outside it: the
//! wall clock at the reopen, the bytes the store recorded verified, and the
//! moment the download is offered again.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_core::{
    CoreCommand, CoreConfig, CoreEvent, CoreSettings, DownloadRepository,
    DurableDownloadRepository, ServeCommand, ServeEvent,
};
use rmule_primitives::{FileHash, ServerEndpoint};

use super::served::{ServedArgs, unix_ms};
use super::{open_store, print_parts_tick};
use crate::cli::DownloadIdentityArgs;

#[derive(Debug, Args)]
pub(crate) struct DownloadReopenArgs {
    /// Data directory holding the Durable Store (`rmule.redb`) a past
    /// `download start` wrote.
    #[arg(long)]
    data_dir: PathBuf,
    /// eD2k server endpoint as `host:port`.
    #[arg(long)]
    server: String,
    /// The download directory the downloads finish in — the folder the past
    /// run's `--out` named.
    #[arg(long)]
    download_dir: PathBuf,
    /// The one client-UDP port; `0` takes an ephemeral one. A peer that
    /// reasks the past run's port needs the same one here.
    #[arg(long, default_value_t = 0)]
    udp_port: u16,
    /// Every this many milliseconds, print each download's positional part
    /// map, as `download start --report-parts-every-ms` does.
    #[arg(long)]
    report_parts_every_ms: Option<u64>,
    /// The run's length in seconds; it then quits.
    #[arg(long)]
    max_seconds: u64,
    #[command(flatten)]
    served: ServedArgs,
    #[command(flatten)]
    identity: DownloadIdentityArgs,
}

pub(crate) async fn reopen(args: DownloadReopenArgs) -> Result<()> {
    let server = ServerEndpoint::parse_host_port(&args.server)
        .with_context(|| format!("parse server endpoint {}", args.server))?;
    let store = open_store(&args.data_dir)?;
    let held = held_bytes(&DurableDownloadRepository::new(std::sync::Arc::clone(
        &store,
    )))?;
    let settings = args.served.settings(args.identity.settings(CoreSettings {
        udp_port: args.udp_port,
        download_dir: Some(args.download_dir.clone()),
        ..CoreSettings::default()
    }));
    let began = tokio::time::Instant::now();
    println!(
        "download reopened downloads={} verified_bytes={} at_unix_ms={}",
        held.len(),
        held.values().sum::<u64>(),
        unix_ms()
    );
    let mut core = args
        .identity
        .core_builder(args.served.config(CoreConfig::default()), settings, store)?
        .build();
    let listen = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, args.identity.tcp_port);
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: listen,
    }))
    .await?;
    let mut offered = Vec::new();
    loop {
        let Some(event) = core.next_event().await else {
            anyhow::bail!("serve event stream ended before ServingStarted");
        };
        args.served.take(&core, &event).await?;
        note_offer(&event, &held, began, &mut offered);
        match event {
            CoreEvent::Serve(ServeEvent::ServingStarted { .. }) => break,
            CoreEvent::Serve(ServeEvent::ServingFailed { reason }) => {
                anyhow::bail!("the serve listener never bound: {reason:?}");
            }
            _ => {}
        }
    }
    let _shared = args.served.share_at_start(&mut core).await?;
    crate::node::connect(&core, &server).await?;

    let deadline = began + Duration::from_secs(args.max_seconds);
    let mut parts_tick = args.report_parts_every_ms.map(|ms| {
        let mut ticker = tokio::time::interval(Duration::from_millis(ms.max(1)));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker
    });
    loop {
        tokio::select! {
            biased;
            () = tokio::time::sleep_until(deadline) => break,
            () = async {
                match parts_tick.as_mut() {
                    Some(ticker) => { ticker.tick().await; }
                    None => std::future::pending().await,
                }
            } => print_parts_tick(&core),
            event = core.next_event() => {
                let Some(event) = event else {
                    anyhow::bail!("the event stream ended before the run's deadline");
                };
                args.served.take(&core, &event).await?;
                note_offer(&event, &held, began, &mut offered);
            }
        }
    }
    println!("download reopen_deadline_reached at_unix_ms={}", unix_ms());
    core.shutdown().await;
    Ok(())
}

/// The verified bytes the store holds for each queued or paused download,
/// by file hash — what its Offer Check reads again.
fn held_bytes(repo: &DurableDownloadRepository) -> Result<BTreeMap<FileHash, u64>> {
    let mut held = BTreeMap::new();
    for record in repo.list_resumable()? {
        let bytes = repo
            .verified_parts(record.id())?
            .iter()
            .map(|part| part.len)
            .sum();
        println!(
            "download reopening id={} state={:?} file_hash={} verified_bytes={bytes}",
            record.id().as_u64(),
            record.lifecycle(),
            record.file_hash().to_hex_upper(),
        );
        held.insert(record.file_hash(), bytes);
    }
    Ok(held)
}

/// The first `PartialOffered` of each held download since the reopen: how
/// long its Offer Check took at most, against the bytes it read.
fn note_offer(
    event: &CoreEvent,
    held: &BTreeMap<FileHash, u64>,
    began: tokio::time::Instant,
    offered: &mut Vec<FileHash>,
) {
    let CoreEvent::Serve(ServeEvent::PartialOffered { file_hash }) = event else {
        return;
    };
    if offered.contains(file_hash) {
        return;
    }
    offered.push(*file_hash);
    println!(
        "download reoffered file_hash={} after_ms={} verified_bytes={} at_unix_ms={}",
        file_hash.to_hex_upper(),
        began.elapsed().as_millis(),
        held.get(file_hash).copied().unwrap_or(0),
        unix_ms()
    );
}
