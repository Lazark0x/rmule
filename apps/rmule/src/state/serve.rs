//! The share set and upload-side peers the Shared Files view reads, and the
//! fold arms that maintain them.
//!
//! The share set is the **Shared File Registry** as core's File History last
//! read it — seeded by the answer to the ask sent at attach, so a file shared
//! in an earlier run is a row from the first frame that has the answer, and
//! re-read after every share edge. An edge opens or closes a row at once; the
//! next answer fills in where the file lies and its size. Per-file counts
//! are not kept here: the slot holders are the upload peers below, and the
//! serve counters are levels the view joins at render.
//!
//! A row whose file is not readable now is a **Withheld Row** (ADR-0106,
//! "The registry against the disk"): kept, drawn with why and since when, and
//! offered to nobody until core says it is readable again.
//!
//! An upload peer is either holding a slot for one file or waiting in the
//! queue at a rank; the two states are exclusive, and a re-queue releases the
//! slot it held.

use std::path::{Path, PathBuf};

use rmule_core::diagnostics::ClientSoftware;
use rmule_core::file_history::{FileHistory, HistoryPart};
use rmule_core::{DirectoryOffer, ScanEvent, ServeEvent, Withheld, WithheldReason};
use rmule_primitives::{FileHash, PeerEndpoint};

use super::{UiState, note};
use crate::words::serve as words;

/// One shared file's row (spec §3.5 shared table): the registry's facts about
/// it, as far as core has told them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedRow {
    /// The file's content identity — the row's key.
    pub file_hash: FileHash,
    /// Where the registry holds the file; `None` for a row a share edge
    /// opened since the last File History answer.
    pub path: Option<PathBuf>,
    /// The file's exact size, known with the path.
    pub file_size: Option<u64>,
    /// Why nothing is offered for it now, and since when rmule noticed;
    /// `None` while it is offered.
    pub withheld: Option<Withheld>,
}

impl SharedRow {
    fn new(file_hash: FileHash) -> Self {
        Self {
            file_hash,
            path: None,
            file_size: None,
            withheld: None,
        }
    }

    /// The name the file is shared under: the last component of its path,
    /// the registry's own naming rule. `None` until the path is known.
    #[must_use]
    pub fn name(&self) -> Option<String> {
        self.path
            .as_deref()
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned())
    }
}

/// Make the share set what the registry holds, as `history` read it: a row
/// per entry with its path and size, and no row the registry no longer holds.
/// A File History answer. A part core could not read keeps what the last
/// answer held, and the operator is told the marks may be missing or out
/// of date.
pub(super) fn fold_history(state: &mut UiState, mut history: FileHistory) -> bool {
    if let Some(last) = state.file_history.take() {
        for part in &history.unread {
            match part {
                HistoryPart::Shared => history.shared.clone_from(&last.shared),
                HistoryPart::Had => history.had.clone_from(&last.had),
                HistoryPart::Cancelled => history.cancelled.clone_from(&last.cancelled),
            }
        }
    }
    if !history.unread.contains(&HistoryPart::Shared) {
        seed_shared(state, &history);
    }
    let unread = history.unread.clone();
    state.file_history = Some(history);
    if unread.is_empty() {
        true
    } else {
        note(state, words::history_unread(&unread))
    }
}

fn seed_shared(state: &mut UiState, history: &FileHistory) {
    state.shared = history
        .shared
        .iter()
        .map(|fact| {
            let row = SharedRow {
                file_hash: fact.identity.file_hash,
                path: Some(fact.path.clone()),
                file_size: Some(fact.identity.file_size),
                withheld: fact.withheld,
            };
            (fact.identity.file_hash, row)
        })
        .collect();
}

/// A row's place in the State column's order: offered first, then a
/// Partial Share ([`PARTIAL_RANK`]), then the withheld ones from the
/// likeliest to come back by itself (a moved file, a changed one being hashed
/// again) to the least (an unplugged volume, a file that will not open, a
/// folder the guards refuse). A rank, never the order of the words.
#[must_use]
pub const fn withheld_rank(withheld: Option<WithheldReason>) -> u64 {
    match withheld {
        None => 0,
        Some(WithheldReason::Missing) => 2,
        Some(WithheldReason::Changed) => 3,
        Some(WithheldReason::FolderMissing) => 4,
        Some(WithheldReason::Unreadable(_)) => 5,
        Some(WithheldReason::Refused) => 6,
    }
}

/// A Partial Share's place in the State column's order: after the offered
/// rows, before the withheld ones.
pub const PARTIAL_RANK: u64 = 1;

/// One upload-side peer's UI facts (spec §3.5 upload-peers pane). Per-peer
/// speed is a level joined at render; the rest arrives on the grant and queue
/// edges.
#[derive(Clone, Debug)]
pub struct UploadPeer {
    /// Who — also the map key, since core identifies upload peers by endpoint.
    pub peer: PeerEndpoint,
    /// Serving or waiting.
    pub state: UploadState,
    /// The client its hello named; `None` when core held no hello for it.
    pub software: Option<ClientSoftware>,
}

/// An upload peer is either being served a file from a held slot, or waiting
/// in the upload queue at a given rank.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadState {
    /// Holding a slot and being served.
    Uploading {
        /// Which shared file the held slot is serving.
        file: FileHash,
    },
    /// Waiting for one.
    Queued {
        /// Place in the upload queue, as core last reported it.
        rank: u16,
        /// The shared file it waits for — the last one it asked about.
        file: FileHash,
    },
}

/// How much of the share set lies under one directory, from the registry
/// rows the last File History answer placed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SharedUnder {
    /// Rows whose path lies under the directory.
    pub files: usize,
    /// Their total size; `None` while a row's size is not yet known.
    pub bytes: Option<u64>,
}

impl UiState {
    /// The shared files under `dir`. A row a share edge opened before the
    /// next File History answer has no path yet and is counted under no
    /// directory.
    #[must_use]
    pub fn shared_under(&self, dir: &Path) -> SharedUnder {
        let rows: Vec<&SharedRow> = self
            .shared
            .values()
            .filter(|row| {
                row.path
                    .as_deref()
                    .is_some_and(|path| path.starts_with(dir))
            })
            .collect();
        SharedUnder {
            files: rows.len(),
            bytes: rows.iter().map(|row| row.file_size).sum(),
        }
    }
}

/// A disclosure question, held until core's next edge for its directory:
/// the download directory's first share, or a directory being added
/// (ADR-0101, "Shared Directories").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanConsent {
    /// The directory asked about.
    pub dir: PathBuf,
    /// What it would offer.
    pub offer: DirectoryOffer,
    /// Whether the operator is adding it; else it is the download
    /// directory's first share.
    pub adding: bool,
    /// The listed directories a yes replaces.
    pub replaces: Vec<PathBuf>,
    /// Which question of the run this is: core can ask again about a
    /// directory whose answer it could not record, and the answer to the
    /// first is not an answer to the second.
    pub asked: u64,
}

/// The directory a scan edge is about.
fn scan_dir(event: &ScanEvent) -> &Path {
    use ScanEvent as S;
    match event {
        S::ConsentRequested { dir, .. }
        | S::Finished { dir, .. }
        | S::Declined { dir }
        | S::WatchUnavailable { dir, .. }
        | S::WatchInterrupted { dir, .. }
        | S::WatchRestored { dir }
        | S::PathUnwatched { dir, .. }
        | S::LeftoverParts { dir, .. }
        | S::FileNotHashed { dir, .. }
        | S::Unlistable { dir }
        | S::DirectoryAdded { dir, .. }
        | S::DirectoryRefused { dir, .. }
        | S::DownloadDirectoryRefused { dir, .. }
        | S::DirectoryRemoved { dir, .. }
        | S::DirectoryMissing { dir, .. }
        | S::DirectoryReturned { dir } => dir,
    }
}

/// Fold one scan edge (ADR-0101): a question is queued for the views to
/// ask, the directory's next edge settles it, and every edge is a
/// status-feed fact.
pub(super) fn fold_scan(state: &mut UiState, event: ScanEvent) -> bool {
    let line = crate::words::scan::line(&event);
    let dir = scan_dir(&event).to_path_buf();
    state.scan_consents.retain(|consent| consent.dir != dir);
    if let ScanEvent::ConsentRequested {
        dir,
        offer,
        adding,
        replaces,
    } = event
    {
        state.scan_questions += 1;
        state.scan_consents.push(ScanConsent {
            dir,
            offer,
            adding,
            replaces,
            asked: state.scan_questions,
        });
    }
    note(state, line)
}

pub(super) fn fold(state: &mut UiState, event: ServeEvent) -> bool {
    use ServeEvent as E;
    match event {
        // Share-set lifecycle owns the shared-table row; the status-feed notes
        // are unchanged.
        E::FileShared { file_hash } => {
            state
                .shared
                .entry(file_hash)
                .or_insert_with(|| SharedRow::new(file_hash))
                .withheld = None;
            note(state, words::FILE_SHARED)
        }
        E::FileUnshared { file_hash } => {
            state.shared.remove(&file_hash);
            note(state, words::FILE_UNSHARED)
        }
        E::FileWithheld {
            file_hash,
            reason,
            since,
        } => {
            if let Some(row) = state.shared.get_mut(&file_hash) {
                row.withheld = Some(Withheld { reason, since });
            }
            note(state, words::withheld(reason))
        }
        E::FileOffered { file_hash } => {
            if let Some(row) = state.shared.get_mut(&file_hash) {
                row.withheld = None;
            }
            note(state, words::OFFERED)
        }
        E::PartialOffered { file_hash } => {
            state.partial_shares.insert(file_hash);
            note(state, words::PARTIAL_OFFERED)
        }
        E::PartialWithdrawn { file_hash, cause } => {
            state.partial_shares.remove(&file_hash);
            note(state, words::partial_withdrawn(cause))
        }
        E::SharesUnwatched => note(state, words::UNWATCHED),
        E::ShareRejected { reason } => note(state, words::share_rejected(reason)),
        E::ServingStarted { listen_addr } => {
            note(state, words::serving_started(listen_addr.port()))
        }
        // The listener never came up, so there is no serving state to change —
        // the note is the operator's only sight of it, and it names the cause
        // so a held port reads differently from a missing adapter.
        E::ServingFailed { reason } => note(state, words::serving_failed(reason)),
        // The reason is the operator's only sight of a listener that died
        // unbidden, which reads nothing like the stop they asked for.
        E::ServingStopped { reason } => note(state, words::serving_stopped(reason)),
        E::FilesAnnounced { file_count } => note(state, words::announced(file_count)),
        E::FilesWithheld { file_count, reason } => {
            note(state, words::shares_withheld(file_count, reason))
        }
        // Upload queue/slot texture: the peers pane state plus the per-file
        // uploading-now tally.
        E::UploadSlotGranted {
            peer,
            file_hash,
            software,
        } => {
            set_upload_state(
                state,
                peer,
                UploadState::Uploading { file: file_hash },
                software,
            );
            true
        }
        E::PeerQueued {
            peer,
            rank,
            file_hash,
            software,
        } => {
            set_upload_state(
                state,
                peer,
                UploadState::Queued {
                    rank,
                    file: file_hash,
                },
                software,
            );
            true
        }
        // A refused peer holds neither a slot nor a queue rank, so no
        // upload-peer row is created; the refusal is a status-feed note only.
        E::UploadQueueFull { .. } => note(state, words::QUEUE_FULL),
        // Likewise: the per-address cap admits nobody, so there is no row to
        // open — and the peer was never even answered, so the note is the
        // operator's only sight of it.
        E::UploadAddressCapReached { .. } => note(state, words::ADDRESS_CAP),
        // Likewise for the Low-ID abuse guard: nothing was answered and no row
        // opens, so the note carries the whole fact — and it names the guard,
        // because "refused" alone would read as a queue that is full.
        E::UploadLowIdAbuseRefused { .. } => note(state, words::LOW_ID_ABUSE),
        // The waiter keeps its rank and its row; it was only left unanswered,
        // so the note is the whole fact.
        E::ReaskPingMalformed { .. } => note(state, words::REASK_MALFORMED),
        // The connection is closed on it; what that frees arrives as its own
        // events, so the note is the whole fact.
        E::NameAskMalformed { .. } => note(state, words::NAME_ASK_MALFORMED),
        E::UploadSlotReleased { peer } => release_peer(state, peer),
        // A wait-list entry that left without ever holding a slot (purged or
        // cancelled): the same row removal as a release, since it held only
        // a queue rank.
        E::WaiterLeft { peer, .. } => release_peer(state, peer),
        // A source-exchange answer is not an upload request: the Requests
        // column reads core's per-file counter instead, so this edge's whole
        // footprint is its log line.
        E::SourcesServed { .. } => false,
    }
}

/// Move `peer` to `next`. Tolerant of edge order like the download fold's
/// [`row_mut`](super::download::row_mut).
fn set_upload_state(
    state: &mut UiState,
    peer: PeerEndpoint,
    next: UploadState,
    software: Option<ClientSoftware>,
) {
    state.upload_peers.insert(
        peer,
        UploadPeer {
            peer,
            state: next,
            software,
        },
    );
}

/// Drop `peer` from the upload set. Returns whether a peer was removed.
fn release_peer(state: &mut UiState, peer: PeerEndpoint) -> bool {
    state.upload_peers.remove(&peer).is_some()
}

impl UiState {
    /// The download a Partial Share of `file_hash` belongs to: the one
    /// whose name and size the Shared Files table lists it under. `None` for
    /// a hash core offers in part for no download this state knows.
    #[must_use]
    pub fn partial_download(&self, file_hash: FileHash) -> Option<&super::DownloadRow> {
        self.partial_shares.contains(&file_hash).then_some(())?;
        self.downloads
            .values()
            .find(|row| row.file_hash == Some(file_hash))
    }

    /// Peers holding an upload slot for `file_hash` right now — the Shared
    /// Files table's Uploading column, read off the upload peers so a grant
    /// that lands before the file's row does is still counted.
    #[must_use]
    pub fn uploading_now(&self, file_hash: FileHash) -> usize {
        self.upload_peers
            .values()
            .filter(|peer| peer.state == UploadState::Uploading { file: file_hash })
            .count()
    }
}

#[cfg(test)]
mod tests;
