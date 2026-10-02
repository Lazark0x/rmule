//! What the sources pane lists for a download: each worker slot, then each
//! source whose dial ended before its hello and that no slot holds now
//! (ADR-0110, "The cause is the source's, not the slot's"). A slot still
//! holding such a peer says the cause in its own Phase cell.

use rmule_core::DownloadId;
use rmule_core::diagnostics::{
    ClientSoftware, DownloadDiagnostics, SourceDialEnd, WorkerEntry, WorkerPhase, WorkerSlot,
};
use rmule_primitives::PeerEndpoint;

use crate::state::UiState;
use crate::words::download::{REMEMBERED, dial_end_words};

/// What a source row is across frames: a slot by its peer (and its slot, for
/// a slot that holds no peer yet), or a source whose dial ended by its peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::views::transfers) enum SourceKey {
    /// A worker slot.
    Slot(Option<PeerEndpoint>, WorkerSlot),
    /// A source no slot holds, whose last dial ended before its hello.
    Ended(PeerEndpoint),
}

/// One row of the sources pane.
#[derive(Clone, Copy)]
pub(in crate::views::transfers) enum SourceRow<'a> {
    /// A worker slot, with its peer's **Dial End** while it holds that peer.
    Slot(&'a WorkerEntry, Option<&'a SourceDialEnd>),
    /// A source no slot holds, and why its dial ended.
    Ended(PeerEndpoint, &'a SourceDialEnd),
}

/// The download's source rows, slots first in slot order, then the ended
/// dials by peer.
pub(in crate::views::transfers) fn source_rows(diag: &DownloadDiagnostics) -> Vec<SourceRow<'_>> {
    let slots = diag.workers.values().map(|worker| {
        let ended = worker
            .peer_endpoint()
            .and_then(|peer| diag.dial_ends.get(&peer));
        SourceRow::Slot(worker, ended)
    });
    let ended = diag
        .dial_ends
        .iter()
        .filter(|(peer, _)| {
            !diag
                .workers
                .values()
                .any(|worker| worker.peer_endpoint() == Some(**peer))
        })
        .map(|(peer, end)| SourceRow::Ended(*peer, end));
    slots.chain(ended).collect()
}

impl SourceRow<'_> {
    /// The row's identity across frames.
    pub(in crate::views::transfers) fn key(&self) -> SourceKey {
        match self {
            Self::Slot(worker, _) => SourceKey::Slot(worker.peer_endpoint(), worker.slot()),
            Self::Ended(peer, _) => SourceKey::Ended(*peer),
        }
    }

    /// The peer, when the row has one.
    pub(in crate::views::transfers) fn peer(&self) -> Option<PeerEndpoint> {
        match self {
            Self::Slot(worker, _) => worker.peer_endpoint(),
            Self::Ended(peer, _) => Some(*peer),
        }
    }

    /// The Source cell: the peer's address, and — for a peer dialed from the
    /// download's **Source Seeds** (ADR-0109) — the `remembered` mark.
    pub(in crate::views::transfers) fn source_label(&self) -> String {
        let address = self
            .peer()
            .map_or_else(|| "—".to_string(), crate::words::units::address);
        let remembered = match self {
            Self::Slot(worker, _) => worker.remembered(),
            Self::Ended(_, end) => end.remembered,
        };
        if remembered {
            format!("{address} · {REMEMBERED}")
        } else {
            address
        }
    }

    /// The client the peer named in its hello; a source whose dial ended
    /// never said hello.
    pub(in crate::views::transfers) fn software(&self) -> Option<&ClientSoftware> {
        match self {
            Self::Slot(worker, _) => worker.software(),
            Self::Ended(..) => None,
        }
    }

    /// The Phase cell: why the dial to the peer ended before its hello, when
    /// it did, else the slot's phase.
    pub(in crate::views::transfers) fn phase_cell(&self) -> String {
        match self {
            Self::Slot(_, Some(end)) | Self::Ended(_, end) => dial_end_words(end.cause).to_string(),
            Self::Slot(worker, None) => phase_label(worker.phase()),
        }
    }

    /// How far the source has got, bytes arriving first: the Phase column's
    /// rank, counted from the one the operator reaches for. A source whose
    /// dial ended comes last.
    pub(in crate::views::transfers) const fn phase_rank(&self) -> u64 {
        match self {
            Self::Slot(worker, _) => match worker.phase() {
                WorkerPhase::ReceivingPart { .. } => 0,
                WorkerPhase::VerifyingPart { .. } => 1,
                WorkerPhase::RequestingPart { .. } => 2,
                WorkerPhase::RequestingHashSet => 3,
                WorkerPhase::WaitingForSlot => 4,
                WorkerPhase::HandshakingPeer => 5,
                WorkerPhase::Connecting => 6,
                WorkerPhase::Idle => 7,
                WorkerPhase::Releasing => 8,
                WorkerPhase::Retired { .. } => 9,
                WorkerPhase::ShutDown => 10,
            },
            Self::Ended(..) => 11,
        }
    }

    /// The row's receive rate in bytes per second: the slot's, differenced
    /// from its `bytes_received`; nothing for a source no slot holds.
    pub(in crate::views::transfers) fn bps(&self, id: DownloadId, state: &UiState) -> f64 {
        match self {
            Self::Slot(worker, _) => state
                .rates
                .source_bps
                .get(&(id, worker.slot()))
                .copied()
                .unwrap_or(0.0),
            Self::Ended(..) => 0.0,
        }
    }
}

fn phase_label(phase: &WorkerPhase) -> String {
    match phase {
        WorkerPhase::Idle => "idle".to_string(),
        WorkerPhase::Connecting => "connecting".to_string(),
        WorkerPhase::HandshakingPeer => "handshake".to_string(),
        WorkerPhase::WaitingForSlot => "queued".to_string(),
        WorkerPhase::RequestingHashSet => "hashset".to_string(),
        WorkerPhase::RequestingPart { part_index } => format!("req p{part_index}"),
        WorkerPhase::ReceivingPart { part_index, .. } => format!("recv p{part_index}"),
        WorkerPhase::VerifyingPart { part_index } => format!("verify p{part_index}"),
        WorkerPhase::Releasing => "releasing".to_string(),
        WorkerPhase::Retired { .. } => "retired".to_string(),
        WorkerPhase::ShutDown => "shutdown".to_string(),
    }
}
