//! The actor's ledger of what is running (ADR-0093): the at-most-one serve
//! activity, the **Download Set**, the searches, the directory scans, and the
//! finish notice each sends back when its task ends. The ledger offers each
//! activity's start, stop, death and retire; each value owns its own stop.
//! Every decision about them is the actor's.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use rmule_primitives::FileHash;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::adapters::RuntimeServerUdpTransport;
use crate::download::StopReason;
use crate::server_capabilities::SharedServerCapabilities;

use super::{DownloadId, SearchId};

mod search;
mod serve;

pub(super) use search::{ActiveSearch, SearchLevers, Searches, WaitingLegs, WaitingSearch};
pub(super) use serve::ServeActivity;

/// How long a retire waits for a search or a download task it has signalled
/// before aborting it, and quit for the Registry Check's thread before
/// leaving it: none holds anything that must reach the disk, so the bound
/// only keeps a wedged task from holding the actor or the exit.
pub(super) const JOIN_GRACE: Duration = Duration::from_secs(2);

/// Join `handle` within [`JOIN_GRACE`], aborting it past that. `true` when
/// the task ended inside the grace.
pub(super) async fn join_or_abort<T>(handle: JoinHandle<T>) -> bool {
    let abort = handle.abort_handle();
    let joined = tokio::time::timeout(JOIN_GRACE, handle).await.is_ok();
    if !joined {
        abort.abort();
    }
    joined
}

/// Wall-clock unix seconds for the `clients.met` edge (`nLastSeen` stamping and
/// the 150-day expiry) — the same saturating shape the store edges use.
pub(super) fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
        })
}

/// The live activities the core actor manages (ADR-0031). The actor owns a
/// *set* — the **Download Set**, the searches held side by side, the directory
/// scans and an optional serve activity — so the serve listener joins without
/// reshaping the select loop. The **Kad Activity** is held beside it, as the
/// actor's own `kad`, since its value is generic in the Kad channel this
/// ledger does not name.
///
/// Generic in the serve adapter because the serve activity *borrows* it: it is
/// handed over at the start and handed back when the activity ends,
/// so the ledger is where its type shows through.
pub(super) struct Activities<L> {
    /// Every search running or waiting whole, and their one retire.
    pub(super) searches: Searches,
    /// The **Download Set**: every download with a live run, by id. Membership
    /// is liveness — a download enters at its start and leaves at its one
    /// retire (ADR-0093).
    downloads: HashMap<DownloadId, ActiveDownload>,
    /// The run number the next download run is given; never reused.
    next_download_run: u64,
    /// The downloads attach found running and has yet to start, in store
    /// order: one leaves per restore pace (ADR-0094). Not in the Download Set
    /// until then — a pause, cancel or resume reaches one here.
    restoring: VecDeque<DownloadId>,
    /// The **Source Seeds** attach loaded for each download in `restoring`
    /// (ADR-0109), handed to its run when it starts.
    remembered: HashMap<DownloadId, Vec<crate::download::source_seeds::SourceSeed>>,
    /// The serve activity, while one runs.
    serve: Option<ServeActivity<L>>,
    /// A **Download Directory Scan** per scanned directory of the **Shared
    /// Directory List** (ADR-0101, "Shared Directories"), by its directory.
    scans: std::collections::BTreeMap<std::path::PathBuf, ScanActivity>,
}

impl<L> Default for Activities<L> {
    /// Nothing running — derivable but for the adapter parameter, which is
    /// only ever inside an `Option` and so needs no `Default` of its own.
    fn default() -> Self {
        Self {
            searches: Searches::default(),
            downloads: HashMap::new(),
            next_download_run: 0,
            restoring: VecDeque::new(),
            remembered: HashMap::new(),
            serve: None,
            scans: std::collections::BTreeMap::new(),
        }
    }
}

impl<L> Activities<L> {
    /// Nothing running yet, and the downloads attach found running waiting
    /// their restore with the **Source Seeds** loaded for each.
    pub(super) fn restoring(
        restoring: VecDeque<DownloadId>,
        remembered: HashMap<DownloadId, Vec<crate::download::source_seeds::SourceSeed>>,
    ) -> Self {
        Self {
            restoring,
            remembered,
            ..Self::default()
        }
    }

    /// The run number for a download run about to start.
    pub(super) const fn take_download_run(&mut self) -> u64 {
        let run = self.next_download_run;
        self.next_download_run = run.wrapping_add(1);
        run
    }

    /// Start: hold `active` as `download_id`'s live run.
    pub(super) fn download_started(&mut self, download_id: DownloadId, active: ActiveDownload) {
        self.downloads.insert(download_id, active);
    }

    /// `download_id`'s live run, while the set holds one.
    pub(super) fn download(&self, download_id: DownloadId) -> Option<&ActiveDownload> {
        self.downloads.get(&download_id)
    }

    /// Whether `download_id` has a live run.
    pub(super) fn has_download(&self, download_id: DownloadId) -> bool {
        self.downloads.contains_key(&download_id)
    }

    /// Stop or death: take `download_id`'s run out for its retire.
    pub(super) fn take_download(&mut self, download_id: DownloadId) -> Option<ActiveDownload> {
        self.downloads.remove(&download_id)
    }

    /// Every live run, by download.
    pub(super) fn downloads(&self) -> impl Iterator<Item = (DownloadId, &ActiveDownload)> {
        self.downloads.iter().map(|(id, active)| (*id, active))
    }

    /// Whether the Download Set holds no live run.
    pub(super) fn downloads_idle(&self) -> bool {
        self.downloads.is_empty()
    }

    /// Whether attach left a download waiting its restore.
    pub(super) fn restore_pending(&self) -> bool {
        !self.restoring.is_empty()
    }

    /// The next download attach found running, with the **Source Seeds**
    /// loaded for it; it leaves the restore queue.
    pub(super) fn next_restoring(
        &mut self,
    ) -> Option<(DownloadId, Vec<crate::download::source_seeds::SourceSeed>)> {
        let download_id = self.restoring.pop_front()?;
        Some((
            download_id,
            self.remembered.remove(&download_id).unwrap_or_default(),
        ))
    }

    /// Take `download_id` out of the restore queue, with its seeds; `None`
    /// when it was not waiting. Its seeds leave with it either way.
    pub(super) fn take_restoring(
        &mut self,
        download_id: DownloadId,
    ) -> Option<Vec<crate::download::source_seeds::SourceSeed>> {
        let seeds = self.remembered.remove(&download_id);
        let at = self.restoring.iter().position(|id| *id == download_id)?;
        self.restoring.remove(at);
        Some(seeds.unwrap_or_default())
    }

    /// The serve activity, while one runs: its presence is "serving".
    pub(super) const fn serving(&self) -> Option<&ServeActivity<L>> {
        self.serve.as_ref()
    }

    /// Start: hold `serve` as the one serve activity.
    pub(super) fn serve_started(&mut self, serve: ServeActivity<L>) {
        debug_assert!(self.serve.is_none(), "one serve activity at a time");
        self.serve = Some(serve);
    }

    /// Stop: take the serve activity out for its retire.
    pub(super) const fn take_serve(&mut self) -> Option<ServeActivity<L>> {
        self.serve.take()
    }

    /// Start: hold `scan` as its directory's scan.
    pub(super) fn scan_started(&mut self, scan: ScanActivity) {
        self.scans.insert(scan.dir.clone(), scan);
    }

    /// The scan of `dir`, while one runs.
    pub(super) fn scan(&self, dir: &std::path::Path) -> Option<&ScanActivity> {
        self.scans.get(dir)
    }

    /// The scan of `dir`, for what the actor learns about it.
    pub(super) fn scan_mut(&mut self, dir: &std::path::Path) -> Option<&mut ScanActivity> {
        self.scans.get_mut(dir)
    }

    /// The scan start `generation` made, while the ledger holds it: a
    /// worker's message from a retired scan finds none.
    pub(super) fn scan_of(&self, generation: u64) -> Option<&ScanActivity> {
        self.scans
            .values()
            .find(|scan| scan.generation == generation)
    }

    /// Every running scan, by directory.
    pub(super) fn scans(&self) -> impl Iterator<Item = &ScanActivity> {
        self.scans.values()
    }

    /// Stop or death: take the scan of `dir` out for its retire.
    pub(super) fn take_scan(&mut self, dir: &std::path::Path) -> Option<ScanActivity> {
        self.scans.remove(dir)
    }

    /// Quit: take every scan out for its retire.
    pub(super) fn take_scans(&mut self) -> Vec<ScanActivity> {
        std::mem::take(&mut self.scans).into_values().collect()
    }

    /// Death: take the serve activity of `generation` out for its retire. A
    /// bump for an activity a stop already retired names a generation the
    /// ledger no longer holds and takes nothing, so it never takes a
    /// successor's live task.
    pub(super) fn take_ended_serve(&mut self, generation: u64) -> Option<ServeActivity<L>> {
        self.serve.take_if(|serve| serve.generation() == generation)
    }
}

/// What `StartSearch` needs from the bound server-UDP surface (ADR-0051):
/// the send half for the sweep and the capability store its variant selection
/// reads (ADR-0052). The `0x99` answers need nothing per search: **Search
/// Attribution** hands them out (ADR-0034).
pub(super) struct GlobalSearchContext {
    pub(super) seal: crate::server_udp::ServerUdpSeal<Arc<RuntimeServerUdpTransport>>,
    pub(super) capabilities: SharedServerCapabilities,
    /// When each server last received a search datagram, across every sweep.
    pub(super) pacer: crate::search::UdpSearchPacer,
}

/// The server-UDP front (ADR-0051): the search context `StartSearch` reads,
/// and the tasks spawned on the one bound server-UDP socket at core start — the
/// engine, the status-ping sweep, the callback relay, the answer forwarder and
/// the global source discovery. It has no stop and no death transition; quit
/// retires it (ADR-0093), because its tasks hold the server list's store view
/// and a task left running would keep the Durable Store open after shutdown.
pub(super) struct ServerUdpFront {
    pub(super) search: GlobalSearchContext,
    pub(super) tasks: Vec<JoinHandle<()>>,
}

pub(super) struct ActiveDownload {
    /// Which run of this download this is: its finish notice carries it, so
    /// a notice from a run a stop already retired never retires the run a
    /// later start or resume put under the same id.
    pub(super) run: u64,
    /// The file this run holds — the key of its **File-Known Predicate**
    /// entry, returned at its retire.
    pub(super) file_hash: FileHash,
    pub(super) stop_tx: watch::Sender<StopReason>,
    pub(super) handle: JoinHandle<()>,
    /// Where a later link's sources for this file join the run (ADR-0089).
    pub(super) later_links: crate::download::LaterLinkSources,
    /// The run's latest **Source Seeds** ranking (ADR-0109), which the actor
    /// writes every ten minutes and at Quit.
    pub(super) seeds: watch::Receiver<Vec<crate::download::source_seeds::SourceSeed>>,
    /// The run's **Completion Gate** (ADR-0115): a Pause or Cancel closes it,
    /// or is refused once the finished file is in place.
    pub(super) completion: std::sync::Arc<crate::download::CompletionGate>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FinishedActivity {
    /// A download run ended: the download and which run of it.
    Download(DownloadId, u64),
    /// A search ended on its own: the search and which run of it.
    Search(SearchId, u64),
}

/// A running **Download Directory Scan** (ADR-0102): the blocking worker and
/// everything its start handed it, all returned at its one retire. Its
/// progress cell is installed on the diagnostics state for the same span.
/// A scan's stop flag, raised as well when the ledger lets go of it without
/// a stop (the actor dropped without a quit), so a watching worker never
/// outlives its activity and never holds the runtime's blocking pool open.
pub(super) struct ScanStop(pub(super) Arc<std::sync::atomic::AtomicBool>);

impl ScanStop {
    pub(super) fn raise(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Drop for ScanStop {
    fn drop(&mut self) {
        self.raise();
    }
}

/// What kind of **Shared Directory List** entry a scan serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ScanRole {
    /// The download directory, entry 0.
    DownloadDirectory,
    /// A directory the operator added.
    Added,
    /// A directory being added, waiting for the operator's confirm; a yes
    /// replaces these listed directories.
    Adding {
        /// The listed directories under it.
        replaces: Vec<std::path::PathBuf>,
    },
}

pub(super) struct ScanActivity {
    /// Which start this is; a worker's messages carry it, so one from a
    /// retired scan moves nothing.
    pub(super) generation: u64,
    /// The directory scanned.
    pub(super) dir: std::path::PathBuf,
    /// Raised at its stop; the worker sees it between reads and between
    /// waits.
    pub(super) stop: ScanStop,
    /// The disclosure guard's reply half while the worker may wait on it.
    /// Dropped at stop, which frees a worker still waiting.
    pub(super) consent_tx: Option<std::sync::mpsc::Sender<bool>>,
    /// Whether the directory's answer is on record: at the start, or since
    /// the first pass finished.
    pub(super) answered: bool,
    /// The first pass finished but the watch did not hold; the worker has
    /// returned, and a start for the same directory runs a fresh pass.
    pub(super) unwatched: bool,
    /// The directory itself is not there; the worker waits for it.
    pub(super) missing: bool,
    /// What kind of list entry the scan serves.
    pub(super) role: ScanRole,
    /// Where the worker says how far it has come.
    pub(super) progress: crate::directory_scan::ProgressCell,
    /// The worker, on the blocking pool.
    pub(super) handle: JoinHandle<()>,
}

/// How long a scan's retire waits for its worker after raising its stop
/// flag. The flag is read between reads of at most a mebibyte, so this
/// bounds a wedged disk, not a large file.
const SCAN_STOP_GRACE: Duration = Duration::from_secs(5);

impl ScanActivity {
    /// The scan's own stop, whatever ended it: raise its flag, free a worker
    /// waiting on the disclosure guard, and join it within
    /// [`SCAN_STOP_GRACE`]. A worker that already returned joins at once.
    pub(super) async fn stop(self) {
        self.stop.raise();
        drop(self.consent_tx);
        // A blocking task cannot be aborted; past the grace it is left to see
        // its flag, and its messages name a generation the ledger no longer
        // holds.
        if tokio::time::timeout(SCAN_STOP_GRACE, self.handle)
            .await
            .is_err()
        {
            tracing::warn!(dir = %self.dir.display(), "scan worker did not stop within its grace");
        }
    }
}

#[cfg(test)]
mod tests;
