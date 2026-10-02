//! The `natt-buddy-transfer-*` halves of the buddy driver: a file
//! crosses the buddy-coordinated path, and **nothing about the target is
//! handed to the requester**.
//!
//! The target shares the file only once its buddy is held, so its source
//! publish is aMule's firewalled type-3 row naming that buddy, with rmule's
//! connect options — uTP NAT-T included — in `TAG_ENCRYPTION`. The requester
//! is given the ed2k link and nothing else: its download asks Kad for sources,
//! the mesh serves it the row, the row becomes a Low-ID candidate carrying the
//! buddy, and the admission rule, the rendezvous, the punch, the claim and the
//! transfer are the shipped path end to end.
//!
//! That road arms the rendezvous itself, on the download's own clock, so the
//! requester's first-dial watch is armed before `StartDownload` and rides the
//! whole download ([`super::first_dial`]).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use rmule_core::{Core, CoreCommand, DownloadCommand as CoreDownloadCommand};
use rmule_primitives::{ClientIdentity, Ed2kLink, ServerEndpoint};

use super::first_dial;
use super::row::{self, BuddyRow};

/// Share `path` now that the buddy is held, so the publish it triggers names
/// the buddy — a file shared before the recruit landed would have gone out as
/// the direct row a firewalled node cannot be reached by. The returned share
/// keeps the file shared while it lives.
///
/// # Errors
/// If the file cannot be shared.
pub(super) async fn publish(
    core: &mut Core,
    path: &Path,
    row: &mut BuddyRow,
) -> Result<crate::share::ScratchShare> {
    let share = crate::share::share_files(core, &[path.to_path_buf()], |event| {
        row::observe(event, row);
    })
    .await?;
    row.published = true;
    println!("rmule-natt-buddy-published path={}", path.display());
    Ok(share)
}

/// What the requester's download needs that the rendezvous half does not.
pub(super) struct DownloadPlan {
    /// The ed2k file link — the one fact the requester is handed.
    pub(super) link: String,
    /// Where the fetched file lands.
    pub(super) output: PathBuf,
    /// The `--server` endpoint every body names; nothing answers it.
    pub(super) server: ServerEndpoint,
    /// Our identity, as the serve activity carries it.
    pub(super) identity: ClientIdentity,
    /// How long the download is given once it starts.
    pub(super) window: Duration,
}

/// Start the download and run the window until it ends, watching for the
/// first dial throughout, then take the output's size and hash off the disk.
///
/// # Errors
/// If the link does not parse or a command cannot be sent. A download that
/// never finds a source or never completes is a **row**.
pub(super) async fn download(
    core: &mut Core,
    plan: DownloadPlan,
    row: &mut BuddyRow,
) -> Result<()> {
    let Ed2kLink::File(file) =
        Ed2kLink::parse(&plan.link).with_context(|| format!("parse ed2k link {}", plan.link))?
    else {
        anyhow::bail!("--file must be an ed2k *file* link, got {}", plan.link);
    };
    let mut watch = first_dial::Watch::armed();
    core.send(CoreCommand::Download(CoreDownloadCommand::StartDownload {
        file,
        source_hint: Some(plan.server),
        credentials: plan.identity.into(),
        output_path: plan.output.clone(),
    }))
    .await?;
    row.download_started = true;
    println!("rmule-natt-buddy-download started");

    let deadline = tokio::time::Instant::now() + plan.window;
    while !row.download_completed && row.download_failure.is_empty() {
        let Some(event) = first_dial::next_event(core, deadline, &mut watch, row).await? else {
            break;
        };
        println!("{event}");
        row::observe(&event, row);
    }
    // A file on a local bridge completes well inside one poll interval of the
    // dial that carried it (runs `1790170318`, `1790171432`: 0.65 s and 0.54 s),
    // so the last reading is owed now, not at the next interval.
    watch.read(core, row).await?;
    if row.download_completed {
        row.output_bytes = std::fs::metadata(&plan.output).map_or(0, |meta| meta.len());
        let handle = std::fs::File::open(&plan.output)
            .with_context(|| format!("open {}", plan.output.display()))?;
        let summary = rmule_primitives::FileHashSummary::digest_reader(handle)
            .with_context(|| format!("hash {}", plan.output.display()))?;
        row.output_ed2k_hash = summary.file_hash().to_hex_upper();
    }
    Ok(())
}
