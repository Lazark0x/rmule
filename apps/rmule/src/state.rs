//! The pure UI-state spine (ADR-0069 §Dataflow): lifecycle *edges* fold
//! immediately, byte *levels* land wholesale on the data tick
//! (latest-state-wins), and time is injected, never read — the whole UI core
//! tests without a terminal, tokio, or a live core.
//!
//! The spine carries the facts every view draws on (connection, download
//! rows, levels, rates, the status-bar info feed); each view extends the fold
//! with its own vocabulary.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Instant;

use rmule_core::diagnostics::DiagnosticsSnapshot;
use rmule_core::{CoreEvent, DownloadId, RelatedSearchRefusal, SearchId};
use rmule_primitives::{FileHash, PeerEndpoint, ServerEndpoint};

use crate::action::Action;
use crate::bridge::BridgeSnapshot;
use crate::rates::TransferRates;
use crate::words::{Sentence, app as app_words, reach};

mod download;
mod known_file;
mod log;
mod rate_history;
mod search;
mod serve;
mod server;
pub(crate) mod server_health;
mod session;

pub use crate::words::search::{
    MORE_REFUSED, legs_line, more_ended_words, refusal_text, search_failure_words, skip_words,
};
pub use crate::words::serve::withheld_words;
pub use crate::words::units::seconds;
pub(crate) use crate::words::units::server_label;
pub use download::{
    DownloadRow, DownloadStatus, FAILURE_NOT_RECORDED, NO_NETWORK_WAIT, download_failure_words,
    integrity_fault_words, lifecycle_words, part_fault_words, release_words, restart_failed_again,
    retirement_words,
};
pub use known_file::{KnownFileMark, KnownFileMarks};
pub use log::LogLine;
pub use rate_history::RateSample;
pub use search::{MoreEnded, SearchPane, SearchStatus};
pub use serve::{
    PARTIAL_RANK, ScanConsent, SharedRow, SharedUnder, UploadPeer, UploadState, withheld_rank,
};
pub use server::{Ed2kConnection, Reconnect};
pub use session::SessionConfig;

/// Which step of attaching the core failed — why a run is UI-only. What the
/// store or the web client said is for the Run Log; the operator reads the
/// step, worded by [`crate::words::app`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachFailure {
    /// Neither `RMULE_DATA` nor `HOME` names a data directory.
    NoDataDir,
    /// The Durable Store would not open.
    OpenStore,
    /// The port-mapping secret could not be read or made.
    PortMapSecret,
    /// The server list could not be read.
    Servers,
    /// The preferences could not be read.
    Preferences,
    /// The HTTP client for list updates could not be built.
    HttpClient,
}

/// The single-writer UI state (ADR-0069): one owner mutates it through
/// [`UiState::apply`]; components hold view state only.
#[derive(Debug)]
pub struct UiState {
    /// Whether an eD2k server session exists, and what it yielded — the
    /// status bar's first verdict.
    pub ed2k: Ed2kConnection,
    /// Endpoint of the live eD2k session, edge-mirrored from
    /// [`rmule_core::ServerConnectionEvent`] so command gates react the instant a connect
    /// lands (the level twin, `diagnostics.connected_server`, trails by a
    /// data tick). Single writer: `fold_server_connection` (+ `CoreClosed`).
    pub connected_server: Option<ServerEndpoint>,
    /// A lost session core is re-making: the server, the next attempt
    /// and its delay as core scheduled it. `None` once it is re-made or core
    /// stops trying.
    pub reconnect: Option<Reconnect>,
    /// Every download core has told us about, in id order — the Transfers
    /// table's rows.
    pub downloads: BTreeMap<DownloadId, DownloadRow>,
    /// Shared-file registry as the UI knows it (spec §3.5), folded from the
    /// serve share-set and upload events.
    pub shared: BTreeMap<FileHash, SharedRow>,
    /// The **Partial Shares** core says are offered now (ADR-0113): a
    /// download's own offer, never a registry row, named by its download.
    pub partial_shares: BTreeSet<FileHash>,
    /// Upload-side peers (slot holders + queue waiters), keyed by endpoint.
    pub upload_peers: BTreeMap<PeerEndpoint, UploadPeer>,
    /// The **File History** as core last answered it — the registry's entries
    /// and the cancelled downloads, the Known-File Marks' durable half.
    /// `None` until the first answer: no mark is drawn from what has not been
    /// read.
    pub file_history: Option<rmule_core::file_history::FileHistory>,
    /// Every search of the run keyed by [`SearchId`] — the results and status
    /// of each **Held Search**; the Searches view keeps the rest.
    pub searches: BTreeMap<SearchId, SearchPane>,
    /// Every **Related-Files Search** core refused before it started, by the
    /// id the Search tab gave it: a refused search has no pane.
    pub refused_searches: BTreeMap<SearchId, RelatedSearchRefusal>,
    /// Latest levels wholesale; superseded, never merged.
    pub diagnostics: DiagnosticsSnapshot,
    /// Bridge-synthesized rates from the same tick as `diagnostics`.
    pub rates: TransferRates,
    /// Session-rate history for the Statistics graphs: one
    /// [`RateSample`] per data tick, capped at 600 samples — ten minutes at
    /// the 1 Hz tick — with the oldest dropped. A stopped core simply stops appending — the graph freezes on
    /// what was actually observed instead of inventing a tail.
    pub rate_history: VecDeque<RateSample>,
    /// When the last data tick was folded in; `None` before the first one,
    /// which is how the views tell "idle" from "nothing observed yet".
    pub last_snapshot_at: Option<Instant>,
    /// Status-bar info feed (spec §3.1 segment 1): the last notable core
    /// fact, newest wins. Flash timing is chrome's concern, not state's.
    pub notable: Option<Sentence>,
    /// Flips false when the core's event stream ends, so the UI renders a
    /// stopped core honestly instead of freezing silently.
    pub core_alive: bool,
    /// The Networks log pane feed (spec §3.4): every core event, rendered
    /// compact by `log::line` in [`UiState::apply`] *before* the fold, capped
    /// at 200 lines (oldest drops). `CoreClosed` appends "core stopped".
    pub log: VecDeque<LogLine>,
    /// Session config for real command construction; `None` degrades.
    pub session: Option<SessionConfig>,
    /// The durable preferences as the config store holds them: what the
    /// Settings tab renders, and where the Networks list-update form reads its
    /// `server.met` mirror. Loaded at startup and folded forward by each
    /// committed edit, so it is always the *stored* value — which for a
    /// restart-shaped knob is the honest one to show, the running session
    /// still being on the value it started with.
    pub preferences: crate::config::Preferences,
    /// A server.met update is in flight: raised by
    /// `ServerListUpdateStarted`, lowered by either terminal edge.
    ///
    /// The one thing the *list* edges cannot be read off the level for — the
    /// list is republished whole every tick, so "the list changed" is
    /// invisible, and "a fetch is running" has no level at all. The Servers
    /// tab uses it twice: to grey *Update from URL* with its reason before
    /// core has to reject it, and to keep the per-row edges of a bulk merge
    /// out of the status feed (see `server::fold_list`).
    pub server_list_updating: bool,
    /// The disclosure questions open now, oldest first (ADR-0101): core
    /// found files under the download directory, or the operator is adding
    /// a directory, and nothing under it is shared until the operator
    /// answers. Each is cleared by its directory's next scan edge.
    pub scan_consents: Vec<ScanConsent>,
    /// How many disclosure questions core has raised this run.
    pub scan_questions: u64,
    /// Why this run has no core: `Some` on a UI-only run, where the core
    /// failed to attach and nothing the operator asks for can be sent.
    pub ui_only: Option<AttachFailure>,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            ed2k: Ed2kConnection::Disconnected,
            connected_server: None,
            reconnect: None,
            downloads: BTreeMap::new(),
            shared: BTreeMap::new(),
            partial_shares: BTreeSet::new(),
            upload_peers: BTreeMap::new(),
            searches: BTreeMap::new(),
            refused_searches: BTreeMap::new(),
            file_history: None,
            diagnostics: DiagnosticsSnapshot::default(),
            rates: TransferRates::default(),
            rate_history: VecDeque::new(),
            last_snapshot_at: None,
            notable: None,
            core_alive: true,
            log: VecDeque::new(),
            session: None,
            preferences: crate::config::Preferences::default(),
            server_list_updating: false,
            scan_consents: Vec::new(),
            scan_questions: 0,
            ui_only: None,
        }
    }
}

impl UiState {
    /// The one write path: route a bus action into the pure fold/apply pair.
    /// Returns whether anything visible changed (the render dirty hint).
    pub fn apply(&mut self, action: Action, now: Instant) -> bool {
        match action {
            Action::Core(event) => {
                // Spec §3.4: log every core event (compact) before folding it.
                // `apply` owns `now`, so the fold path itself stays time-free —
                // this is the sanctioned place for time-stamped side data.
                // The File History is a level the app asked for, not an
                // edge: logging each answer would fill the pane with polling.
                // Each restored run's seeds are said once for all of them, by
                // attach's own line (ADR-0109), and reach the Run Log alone.
                if !matches!(
                    event,
                    CoreEvent::FileHistory { .. }
                        | CoreEvent::Download(rmule_core::DownloadEvent::SeedsDialled { .. })
                ) {
                    self.push_log(crate::words::event::log_line(&event), now);
                }
                fold(self, event);
                // The log pane repaints on any core event, so the frame is
                // dirty regardless of the fold's finer spine-level hint.
                true
            }
            Action::Snapshot(frame) => self.apply_snapshot(frame, now),
            Action::CoreClosed => {
                self.push_log(app_words::CORE_STOPPED, now);
                self.core_alive = false;
                self.connected_server = None;
                self.reconnect = None;
                note(self, app_words::CORE_STOPPED)
            }
            // An app-learned fact: same two surfaces a core event's
            // would reach, since the app owns no log of its own.
            Action::Note(text) => {
                self.push_log(text.clone(), now);
                note(self, text)
            }
            Action::ForgetSearch(search_id) => {
                let pane = self.searches.remove(&search_id).is_some();
                self.refused_searches.remove(&search_id).is_some() || pane
            }
            // Chrome/input/outbound arms belong to `ChromeState`/the app
            // loop, never to the core-facing state.
            Action::Input(_)
            | Action::SwitchView(_)
            | Action::CycleView(_)
            | Action::ToggleHelp
            | Action::DismissOverlay
            | Action::ScrollHelp(_)
            | Action::Flash(_)
            | Action::Command(_)
            | Action::Commands(_)
            | Action::Actions(_)
            | Action::CopyLink(_)
            | Action::Preference(_)
            | Action::ConfirmDownloadDir(_)
            | Action::SearchRelated(_)
            | Action::StartKad
            | Action::Preview(_)
            | Action::Quit => false,
        }
    }

    /// Replace the level set (latest-state-wins) and stamp the injected
    /// observation time. `diagnostics.kad` arrives here too: the sync
    /// accessor reports it in full (ADR-0028).
    pub fn apply_snapshot(&mut self, frame: BridgeSnapshot, now: Instant) -> bool {
        self.push_rate_sample(&frame.rates, now);
        server_health::log_edges(self, &frame.diagnostics, now);
        let more_before = self.diagnostics.search_more_results;
        let more_after = frame.diagnostics.search_more_results;
        self.diagnostics = frame.diagnostics;
        search::fold_more(self, more_before, more_after);
        self.rates = frame.rates;
        self.last_snapshot_at = Some(now);
        server::count_down(self, now);
        true
    }

    /// The server an activity command should name: the live connection's
    /// endpoint first — the operator may have connected via the Servers tab
    /// to a server the startup config never named — else the configured one.
    /// Core dials neither (ADR-0095): an activity rides the operator's session
    /// or waits for one, so the name is only what the download row records.
    #[must_use]
    pub fn active_server(&self) -> Option<ServerEndpoint> {
        self.connected_server.clone().or_else(|| {
            self.session
                .as_ref()
                .and_then(|session| session.server.clone())
        })
    }
}

/// Fold one lifecycle edge. Pure; returns the render dirty hint.
pub fn fold(state: &mut UiState, event: CoreEvent) -> bool {
    match event {
        CoreEvent::Download(event) => download::fold(state, event),
        CoreEvent::Serve(event) => serve::fold(state, event),
        CoreEvent::Scan(event) => serve::fold_scan(state, event),
        CoreEvent::Search(event) => search::fold(state, event),
        CoreEvent::SecuredIdentityMismatch { .. } => note(state, reach::IDENTITY_MISMATCH_NOTE),
        CoreEvent::CommandRejected { reason } => note(state, app_words::command_rejected(&reason)),
        // A routing verdict, not a spine mutation — its whole UI footprint
        // is the log pane line `apply` already pushed. A risen NAT-T tunnel
        // is the same shape of fact: the peer it carries reaches the spine as
        // an ordinary serve or download edge.
        CoreEvent::PeerReachRouted { .. } | CoreEvent::NattTunnelRisen { .. } => false,
        // A refused peer hello (ADR-0050): one peer's frame, not a state of
        // this node — its log line is its whole footprint, and the count
        // rides the diagnostics tick.
        CoreEvent::PeerHelloRefused { .. } => false,
        // The one client-UDP socket never bound at core start (ADR-0057):
        // Kad, the reask surface and NAT-T are all off for the
        // rest of this session. Named plainly rather than left to the log
        // pane's compact line, since it is the answer to "why is Kad off"
        // an operator who never scrolled back would otherwise never see.
        CoreEvent::ClientUdpBindFailed { port, kind } => {
            note(state, reach::client_udp_bind_failed(port, kind))
        }
        // A pair that came up without a family it selected. The
        // same reason the total failure above is noted rather than left to
        // the log pane: "why is Kad off" is a question an operator who never
        // scrolled back would otherwise never see answered.
        CoreEvent::SocketBoundWithoutFamily { half_bound } => {
            note(state, reach::half_bound(&half_bound))
        }
        CoreEvent::ServerList(event) => server::fold_list(state, event),
        CoreEvent::ServerConnection(event) => server::fold_connection(state, event),
        // Levels ride the bridge's data tick ([`Action::Snapshot`]), Kad facts
        // included; the TUI never sends `DumpDiagnostics`. The event stays in
        // core for mpsc-only tooling (ADR-0028), so this exhaustive match
        // names it and folds nothing.
        CoreEvent::DiagnosticsSnapshot { .. } => false,
        CoreEvent::FileHistory { history } => serve::fold_history(state, history),
        // The Kad node died mid-session — an operator-relevant
        // "why is Kad off" fact, the same posture as the two socket notes
        // above, not something the data-tick snapshot alone would explain.
        CoreEvent::KadStopped { reason } => note(state, crate::words::kad::stopped(reason)),
        // Quit's progress is the status bar's, reduced by the app.
        CoreEvent::Quitting { .. } => false,
        // A login step is evidence for the log pane and the Run Log; no
        // level moves with it.
        CoreEvent::ServerLogin { .. } => false,
        // A failed buddy dial is evidence the same way; the buddy's state is
        // the level, and the dial left it where it was.
        CoreEvent::BuddyDialFailed { .. } => false,
        // So is a late Kad helper test: the TCP verdict is the level, and a
        // test that no longer counts leaves it where it was.
        CoreEvent::KadHelperTestLate { .. } => false,
        // So is a release that left a router port standing: the mapping rows
        // are the level, and the log pane says why the port was left alone.
        CoreEvent::MappingReleaseKept { .. } => false,
        // Our own posture: the Settings tab holds the value, the log pane the
        // line `apply` pushed.
        CoreEvent::ObfuscationPolicyAtStart { .. } | CoreEvent::ObfuscationPolicyChanged { .. } => {
            false
        }
    }
}

fn note(state: &mut UiState, text: Sentence) -> bool {
    state.notable = Some(text);
    true
}

#[cfg(test)]
mod tests;
