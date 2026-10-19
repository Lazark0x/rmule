//! The `download` commands on a download the Durable Store already holds:
//! resume one in a run of its own, mark one paused with no core running,
//! and list the ones a run could resume with what each has verified.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use rmule_core::run_log::Level;
use rmule_core::{
    CoreCommand, CoreConfig, CoreEvent, DownloadCommand as CoreDownloadCommand, DownloadEvent,
    DownloadId, DownloadLifecycle, DownloadRepository, DurableDownloadRepository,
};
use rmule_primitives::ServerEndpoint;

use super::open_store;
use crate::cli::DownloadIdentityArgs;

#[derive(Debug, Args)]
pub(crate) struct DownloadResumeArgs {
    /// Data directory holding the Durable Store (`rmule.redb`), created when
    /// absent.
    #[arg(long)]
    data_dir: PathBuf,
    /// Durable download id to resume.
    #[arg(long)]
    download_id: u64,
    /// Optional eD2k server endpoint override as `host:port`.
    #[arg(long)]
    server: Option<String>,
    /// The **Dial Window** (ADR-0116): roads the downloads open per 5 s
    /// (`CoreConfig::peer_connections.dials_per_window`, default 20).
    #[arg(long)]
    dials_per_window: Option<u32>,
    /// The **Connection Ceiling** (ADR-0116): connections the downloads hold
    /// at once, asking and transferring
    /// (`CoreConfig::peer_connections.max_connections`, default 500), never
    /// more than the process's open-descriptor limit leaves room for.
    #[arg(long)]
    max_connections: Option<usize>,
    /// The **Streaming Window**'s width `N` in parts
    /// (`CoreConfig::streaming_window_parts`, ADR-0112); `0` for none.
    #[arg(long)]
    streaming_window: Option<u32>,
    #[command(flatten)]
    identity: DownloadIdentityArgs,
}

#[derive(Debug, Args)]
pub(crate) struct DownloadPauseArgs {
    /// Data directory holding the Durable Store (`rmule.redb`), created when
    /// absent.
    #[arg(long)]
    data_dir: PathBuf,
    /// Durable download id to mark paused.
    #[arg(long)]
    download_id: u64,
}

#[derive(Debug, Args)]
pub(crate) struct DownloadStatusArgs {
    /// Data directory holding the Durable Store (`rmule.redb`), created when
    /// absent.
    #[arg(long)]
    data_dir: PathBuf,
}

pub(crate) async fn resume(args: DownloadResumeArgs) -> Result<()> {
    let server_override = args
        .server
        .as_deref()
        .map(ServerEndpoint::parse_host_port)
        .transpose()
        .with_context(|| format!("parse server override {:?}", args.server))?;
    let store = open_store(&args.data_dir)?;
    let download_id = DownloadId::from_u64(args.download_id);
    // The server this run connects to: the override, or the one the download
    // was recorded against as its source hint.
    let server = match &server_override {
        Some(server) => server.clone(),
        None => DurableDownloadRepository::new(std::sync::Arc::clone(&store))
            .load_download(download_id)
            .with_context(|| format!("load download {}", args.download_id))?
            .source_hint()
            .cloned()
            .context("the download records no server; name one with --server")?,
    };
    let mut config = CoreConfig::default();
    if let Some(dials) = args.dials_per_window {
        config.peer_connections.dials_per_window = dials;
    }
    if let Some(connections) = args.max_connections {
        config.peer_connections.max_connections = connections;
    }
    super::hold_to_descriptors(&mut config);
    if let Some(parts) = args.streaming_window {
        config.streaming_window_parts = parts;
    }
    let mut core = args
        .identity
        .core_builder(
            config,
            args.identity.settings(rmule_core::CoreSettings::default()),
            store,
        )?
        .build();
    // The operator's word, given on the command line (ADR-0095).
    crate::node::connect(&core, &server).await?;
    core.send(CoreCommand::Download(CoreDownloadCommand::ResumeDownload {
        download_id,
    }))
    .await?;

    while let Some(event) = core.next_event().await {
        println!("{}", event.record().render(Level::Full));
        match event {
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => return Ok(()),
            CoreEvent::Download(DownloadEvent::DownloadCancelled { .. }) => {
                anyhow::bail!("download cancelled")
            }
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                anyhow::bail!("download failed: {reason}")
            }
            _ => {}
        }
    }

    anyhow::bail!("download event stream ended before resume completion")
}

pub(crate) fn pause(args: DownloadPauseArgs) -> Result<()> {
    let store = open_store(&args.data_dir)?;
    let repo = DurableDownloadRepository::new(store);
    let download_id = DownloadId::from_u64(args.download_id);
    repo.set_lifecycle(download_id, DownloadLifecycle::Paused)?;
    println!("download paused id={}", download_id.as_u64());
    Ok(())
}

pub(crate) fn status(args: DownloadStatusArgs) -> Result<()> {
    let store = open_store(&args.data_dir)?;
    let repo = DurableDownloadRepository::new(store);
    let records = repo.list_resumable()?;
    println!("# resumable downloads in {}", args.data_dir.display());
    if records.is_empty() {
        println!("# no resumable downloads");
        return Ok(());
    }
    for record in records {
        let parts = repo.verified_parts(record.id())?;
        let verified_bytes: u64 = parts.iter().map(|part| part.len).sum();
        println!(
            "download id={} state={:?} file_hash={} size={} verified_parts={} verified_bytes={} final_path={}",
            record.id().as_u64(),
            record.lifecycle(),
            record.file_hash().to_hex_upper(),
            record.file_size(),
            parts.len(),
            verified_bytes,
            record.paths().final_path().display()
        );
    }
    Ok(())
}
