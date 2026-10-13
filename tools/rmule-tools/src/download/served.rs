//! The levers a bench pulls on a download's own share (ADR-0113, ADR-0115)
//! beyond what `download start` does by default: the upload slots, the Temp
//! Directory, the download directory's first-share confirm, whole files shared
//! beside the downloads, a run that keeps serving after its downloads end, a
//! wall-clock stamp on every event line, and two gate files — one that pauses
//! every download mid-run, one that ends the run — so a harness decides the
//! moment from what it has seen rather than from a guessed delay.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::Args;
use rmule_core::run_log::Level;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, CoreSettings, DownloadCommand, DownloadId,
    ScanCommand, ScanEvent,
};

use crate::share::{ScratchShare, share_files};

/// The levers `download start` and `download reopen` share.
#[derive(Debug, Args)]
pub(crate) struct ServedArgs {
    /// Upload slots (`CoreConfig::upload_slot_budget`); unset keeps the
    /// core's. `1` queues every asker after the first slot holder.
    #[arg(long)]
    pub(crate) upload_slots: Option<usize>,
    /// The **Temp Directory** (ADR-0115): part files live here and the
    /// completion move carries each finished file into the download
    /// directory. Unset, a part file lies beside its final path.
    #[arg(long)]
    pub(crate) temp_dir: Option<PathBuf>,
    /// Answer the download directory's first-share confirm yes (ADR-0101),
    /// so a finished download's row is offered and the directory's scan rules
    /// it. Unset, the confirm stays unanswered and nothing under it is shared.
    #[arg(long)]
    pub(crate) share_download_dir: bool,
    /// A whole file to share beside the downloads from the start, from one
    /// throwaway directory; repeat for several.
    #[arg(long = "share")]
    pub(crate) share: Vec<PathBuf>,
    /// Keep serving once every download has ended, until the run's deadline:
    /// a peer mid-upload when a download completes is served on.
    #[arg(long)]
    pub(crate) linger: bool,
    /// End every printed event line with ` at_unix_ms=<ms>`, the wall clock
    /// it was printed at, so a bench can lay it beside a capture taken on the
    /// same host. Events met during a share's first pass print unstamped.
    #[arg(long)]
    pub(crate) stamp_events: bool,
}

impl ServedArgs {
    /// `config` with the upload slots these levers name.
    pub(crate) fn config(&self, config: CoreConfig) -> CoreConfig {
        match self.upload_slots {
            Some(upload_slot_budget) => CoreConfig {
                upload_slot_budget,
                ..config
            },
            None => config,
        }
    }

    /// `settings` with the Temp Directory these levers name.
    pub(crate) fn settings(&self, settings: CoreSettings) -> CoreSettings {
        CoreSettings {
            temp_dir: self.temp_dir.clone().or(settings.temp_dir),
            ..settings
        }
    }

    /// Share the `--share` files, when there are any, and hold until the
    /// directory's first pass has shared them all.
    ///
    /// # Errors
    /// As [`share_files`].
    pub(crate) async fn share_at_start(&self, core: &mut Core) -> Result<Option<ScratchShare>> {
        if self.share.is_empty() {
            return Ok(None);
        }
        share_files(core, &self.share, |_| {}).await.map(Some)
    }

    /// Print `event` as its record, stamped when asked, and answer the
    /// download directory's first-share confirm when asked to.
    ///
    /// # Errors
    /// If the core no longer takes commands.
    pub(crate) async fn take(&self, core: &Core, event: &CoreEvent) -> Result<()> {
        let line = event.record().render(Level::Full);
        if self.stamp_events {
            println!("{line} at_unix_ms={}", unix_ms());
        } else {
            println!("{line}");
        }
        if let CoreEvent::Scan(ScanEvent::ConsentRequested {
            dir, adding: false, ..
        }) = event
            && self.share_download_dir
        {
            core.send(CoreCommand::Scan(ScanCommand::Answer {
                dir: dir.clone(),
                share: true,
            }))
            .await?;
        }
        Ok(())
    }
}

/// The gate files only `download start` watches.
#[derive(Debug, Args)]
pub(crate) struct GateArgs {
    /// Pause every download once this path exists (looked for each second).
    /// The run keeps serving: a Partial Share stays offered while paused
    /// (ADR-0113 §"A paused download").
    #[arg(long)]
    pub(crate) pause_gate: Option<PathBuf>,
    /// Once the pause has been asked for, share this whole file too, so the
    /// share trigger re-announces while the downloads are paused; repeat for
    /// several.
    #[arg(long, requires = "pause_gate")]
    pub(crate) share_after_pause: Vec<PathBuf>,
    /// End the run, as its deadline would, once this path exists.
    #[arg(long)]
    pub(crate) stop_gate: Option<PathBuf>,
}

/// What the gates said at one look.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Gate {
    /// Nothing new.
    Shut,
    /// The pause gate appeared: pause now, once.
    Pause,
    /// The stop gate appeared: end the run.
    Stop,
}

/// The gates of one run and whether the pause has fired.
pub(crate) struct Gates {
    pause: Option<PathBuf>,
    stop: Option<PathBuf>,
    paused: bool,
    ticker: Option<tokio::time::Interval>,
}

impl Gates {
    /// The gates `args` names; with none, [`Self::tick`] never resolves.
    pub(crate) fn new(args: &GateArgs) -> Self {
        let ticker = (args.pause_gate.is_some() || args.stop_gate.is_some()).then(|| {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker
        });
        Self {
            pause: args.pause_gate.clone(),
            stop: args.stop_gate.clone(),
            paused: false,
            ticker,
        }
    }

    /// The next look's moment; pending forever when no gate is set.
    pub(crate) async fn tick(&mut self) {
        match self.ticker.as_mut() {
            Some(ticker) => {
                ticker.tick().await;
            }
            None => std::future::pending().await,
        }
    }

    /// Look at the gates: the stop gate wins, and the pause fires once.
    pub(crate) fn look(&mut self) -> Gate {
        if self.stop.as_deref().is_some_and(Path::exists) {
            return Gate::Stop;
        }
        if !self.paused && self.pause.as_deref().is_some_and(Path::exists) {
            self.paused = true;
            return Gate::Pause;
        }
        Gate::Shut
    }
}

/// Pause each of `ids`, say so, then share `after` (when any) beside them.
///
/// # Errors
/// If the core no longer takes commands, or the share fails.
pub(crate) async fn pause_then_share(
    core: &mut Core,
    ids: &[u64],
    after: &[PathBuf],
    shared: &mut Option<ScratchShare>,
) -> Result<()> {
    for &id in ids {
        core.send(CoreCommand::Download(DownloadCommand::PauseDownload {
            download_id: DownloadId::from_u64(id),
        }))
        .await?;
    }
    let listed: Vec<String> = ids.iter().map(u64::to_string).collect();
    println!(
        "download paused_at_gate ids={} at_unix_ms={}",
        listed.join(","),
        unix_ms()
    );
    if after.is_empty() {
        return Ok(());
    }
    match shared {
        // Placed in the directory already shared: its watch shares it.
        Some(share) => {
            for file in after {
                share.add(file)?;
            }
        }
        None => *shared = Some(share_files(core, after, |_| {}).await?),
    }
    println!("download shared_after_pause files={}", after.len());
    Ok(())
}

/// The wall clock in Unix milliseconds.
pub(crate) fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis())
}

#[cfg(test)]
mod tests {
    use super::{Gate, GateArgs, Gates};

    /// The stop gate ends the run even when the pause gate is also there,
    /// and the pause fires once however long its file stays.
    #[tokio::test]
    async fn the_stop_gate_wins_and_the_pause_fires_once() {
        let dir = tempfile::tempdir().unwrap();
        let pause = dir.path().join("pause");
        let stop = dir.path().join("stop");
        let mut gates = Gates::new(&GateArgs {
            pause_gate: Some(pause.clone()),
            share_after_pause: Vec::new(),
            stop_gate: Some(stop.clone()),
        });
        assert_eq!(gates.look(), Gate::Shut);
        std::fs::write(&pause, b"").unwrap();
        assert_eq!(gates.look(), Gate::Pause);
        assert_eq!(gates.look(), Gate::Shut);
        std::fs::write(&stop, b"").unwrap();
        assert_eq!(gates.look(), Gate::Stop);
    }
}
