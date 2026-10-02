//! The actor's ledger of what is running: the at-most-one serve activity, the
//! **Download Set** and the searches in flight, and the finish notice each sends back when
//! its task ends. Bookkeeping only — every decision about them is the actor's.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddrV4;
use std::sync::Arc;

use rmule_primitives::FileHash;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::adapters::RuntimeServerUdpTransport;
use crate::download::StopReason;
use crate::serve::ServeOutcome;
use crate::server_capabilities::SharedServerCapabilities;

use super::{DownloadId, SearchId};

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
/// *set* — the **Download Set**, the searches held side by side, and an optional serve
/// activity — so the serve listener joins without reshaping the select loop.
///
/// Generic in the serve adapter because the serve activity *borrows* it: it is
/// handed over at the start and handed back when the activity ends,
/// so the ledger is where its type shows through.
pub(super) struct Activities<L> {
    /// Every search still running, by id — any number at once.
    pub(super) searches: HashMap<SearchId, ActiveSearch>,
    /// The keyword searches asked for while no server session existed, in the
    /// order asked (ADR-0095, "Connecting is the operator's act"): each is
    /// started the moment the operator's connect brings a session up. A
    /// cancel reaches one here; Quit drops them unsent.
    pub(super) waiting_searches: Vec<WaitingSearch>,
    /// The **Download Set**: every download with a live run, by id. Membership
    /// is liveness — a download enters at its start and leaves at its one
    /// retire (ADR-0093).
    pub(super) downloads: HashMap<DownloadId, ActiveDownload>,
    /// The run number the next download run is given; never reused.
    pub(super) next_download_run: u64,
    /// The downloads attach found running and has yet to start, in store
    /// order: one leaves per restore pace (ADR-0094). Not in the Download Set
    /// until then — a pause, cancel or resume reaches one here.
    pub(super) restoring: VecDeque<DownloadId>,
    /// The **Source Seeds** attach loaded for each download in `restoring`
    /// (ADR-0109), handed to its run when it starts.
    pub(super) remembered: HashMap<DownloadId, Vec<crate::download::source_seeds::SourceSeed>>,
    pub(super) serve: Option<ServeActivity<L>>,
    /// A **Download Directory Scan** per scanned directory of the **Shared
    /// Directory List** (ADR-0101, "Shared Directories"), by its directory.
    pub(super) scans: std::collections::BTreeMap<std::path::PathBuf, ScanActivity>,
}

impl<L> Default for Activities<L> {
    /// Nothing running — derivable but for the adapter parameter, which is
    /// only ever inside an `Option` and so needs no `Default` of its own.
    fn default() -> Self {
        Self {
            searches: HashMap::new(),
            waiting_searches: Vec::new(),
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
    /// The run number for a download run about to start.
    pub(super) const fn take_download_run(&mut self) -> u64 {
        let run = self.next_download_run;
        self.next_download_run = run.wrapping_add(1);
        run
    }
}

/// A keyword search waiting for a server session or Kad, neither of which
/// exists: everything its start needs.
pub(super) struct WaitingSearch {
    pub(super) search_id: SearchId,
    pub(super) query: rmule_primitives::KeywordQuery,
}

pub(super) struct ActiveSearch {
    pub(super) cancel_tx: watch::Sender<bool>,
    pub(super) handle: JoinHandle<()>,
    /// Where `SearchCommand::MoreResults` reaches the search's task
    /// (ADR-0036).
    pub(super) more_tx: tokio::sync::mpsc::Sender<()>,
    /// The global UDP sweep's task (ADR-0051), when the server-UDP socket is
    /// bound. Aborted on search end — a sweep for a dead search would only
    /// solicit answers nobody consumes.
    pub(super) global_sweep: Option<JoinHandle<()>>,
    /// The legs that wait, and what sending them needs (ADR-0034).
    pub(super) waiting: WaitingLegs,
}

/// A running keyword search's legs that wait (ADR-0034, "The legs are
/// independent"): the server leg and its sweep for a session, the Kad
/// leg for Kad to run. The actor sends each on its arrival; the task drops
/// its receiver once the leg can no longer run for it.
#[derive(Default)]
pub(super) struct WaitingLegs {
    /// What the search asks, for the legs sent late.
    pub(super) query: Option<rmule_primitives::KeywordQuery>,
    /// Held only while the operator's Server Intent stands; dropped when it
    /// ends, which settles the leg.
    pub(super) server: Option<tokio::sync::oneshot::Sender<crate::search::SentServerLeg>>,
    pub(super) kad: Option<tokio::sync::oneshot::Sender<crate::search::KadKeywordLeg>>,
}

impl ActiveSearch {
    /// End this search's global-UDP participation: stop its sweep, which would
    /// only solicit answers no longer its own.
    pub(super) fn stop_global(&mut self) {
        if let Some(sweep) = self.global_sweep.take() {
            sweep.abort();
        }
    }
}

/// What `StartSearch` needs from the bound server-UDP surface (ADR-0051):
/// the send half for the sweep and the capability store its variant selection
/// reads (ADR-0052). The `0x99` answers need nothing per search: **Search
/// Attribution** hands them out (ADR-0034).
pub(super) struct GlobalSearchContext {
    pub(super) transport: Arc<RuntimeServerUdpTransport>,
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FinishedActivity {
    /// A download run ended: the download and which run of it.
    Download(DownloadId, u64),
    Search(SearchId),
}

/// A running serve activity: the spawned `ServeTask` plus the channels to
/// stop it and to notify it the share set changed (re-announce).
pub(super) struct ServeActivity<L> {
    /// Which start this is: the value the task's end bumps `serve_ended` to
    /// (ADR-0093), so a stale bump never retires a successor.
    pub(super) generation: u64,
    pub(super) stop_tx: watch::Sender<bool>,
    pub(super) share_changed_tx: mpsc::Sender<()>,
    /// The task, whose *result* is the serve adapter. One serve
    /// adapter exists per core and the activity holds it for its life, so the
    /// only place it can come back from is here — awaiting this handle is how
    /// the actor takes it back, and why serving is restartable at all.
    pub(super) handle: JoinHandle<ServeOutcome<L>>,
    /// The address the listener actually bound — the one a peer dials to reach
    /// us, and so the one an outbound callback must name. aMule reads the same
    /// fact from `thePrefs::GetPort()` when it writes its own `0x95` body. The
    /// *requested* address is never stored: with port 0 the OS chooses, and a
    /// `0x95` naming the requested 0 would be a dead invitation.
    ///
    /// A plain value, not a shared cell: the actor binds before it spawns the
    /// task, so this activity exists only once the bind is a fact
    /// and there is no window in which it could be unknown.
    pub(super) bound: SocketAddrV4,
}

impl<L> ServeActivity<L> {
    /// The actually-bound listener port — the one route 2 invites a dial to.
    pub(super) fn bound_listen_port(&self) -> u16 {
        self.bound.port()
    }
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
    /// Raised at stop; the worker sees it between reads and between waits.
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
