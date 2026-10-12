//! The brain's half of **Source Seeds** (ADR-0109, "Source Seeds"): which
//! worker facts earn a peer its class, which candidates came from a seed, and
//! the ranking the runner publishes for the core actor to write, and how many
//! of the seeds this run dialled answered.

use std::collections::HashSet;

use rmule_primitives::PeerEndpoint;

use crate::adapters::PeerWorkerEvent;
use crate::download::source_seeds::{SeedHello, SeedRank, SourceSeed};
use crate::service::DownloadEvent;

use super::{Decision, DownloadState};

/// The run's seed dials until they are reported: each pooled seed is
/// unsettled until its hello is read (answered) or it leaves both the pool
/// and the workers without one.
#[derive(Debug)]
pub(super) struct SeedDials {
    written: usize,
    dialled: usize,
    unsettled: HashSet<PeerEndpoint>,
    answered: usize,
}

impl SeedDials {
    /// `None` when the last run wrote no seed under a day old: nothing to
    /// report.
    pub(super) fn new(written: usize) -> Option<Self> {
        (written > 0).then(|| Self {
            written,
            dialled: 0,
            unsettled: HashSet::new(),
            answered: 0,
        })
    }
}

impl DownloadState {
    /// The seeds the ingest gate let into the pool are the ones this run
    /// dials: each is unsettled until it answers or ends.
    pub(super) fn seed_dials_admit(&mut self, endpoints: impl IntoIterator<Item = PeerEndpoint>) {
        if let Some(dials) = &mut self.seed_dials {
            dials.unsettled.extend(endpoints);
            dials.dialled = dials.unsettled.len();
        }
    }

    /// Fold one worker fact into the seed ledger: a block earns
    /// [`SeedRank::Received`], a queue rank or a slot [`SeedRank::Ranked`],
    /// and a hello names the peer's hash.
    pub(super) fn note_seed_fact(&mut self, peer: PeerEndpoint, event: &PeerWorkerEvent) {
        match event {
            PeerWorkerEvent::BlockReceived { .. } => self.seeds.earned(peer, SeedRank::Received),
            PeerWorkerEvent::Queued { .. } | PeerWorkerEvent::SlotGranted => {
                self.seeds.earned(peer, SeedRank::Ranked);
            }
            PeerWorkerEvent::Identity(identity) => {
                if let Some(dials) = &mut self.seed_dials
                    && dials.unsettled.remove(&peer)
                {
                    dials.answered += 1;
                }
                self.seeds.named(
                    peer,
                    SeedHello {
                        user_hash: identity.user_hash(),
                        crypt: Some(identity.crypt_stance()),
                    },
                );
            }
            _ => {}
        }
    }

    /// Settle each seed dial that left both the pool and the workers with no
    /// hello, and report the dials once every one has settled — or when `out`
    /// ends the run first, since nothing settles after it. The report goes
    /// before the run's end: the runner enacts nothing past it.
    pub(super) fn settle_seed_dials(&mut self, out: &mut Vec<Decision>) {
        let Some(dials) = &mut self.seed_dials else {
            return;
        };
        dials
            .unsettled
            .retain(|&peer| self.sources.is_pooled_or_live(peer));
        let end = out
            .iter()
            .position(|decision| matches!(decision, Decision::Fail(_) | Decision::Finalize));
        if !dials.unsettled.is_empty() && end.is_none() {
            return;
        }
        let report = Decision::Emit(DownloadEvent::SeedsDialled {
            download_id: self.download_id,
            written: dials.written,
            dialled: dials.dialled,
            answered: dials.answered,
        });
        self.seed_dials = None;
        out.insert(end.unwrap_or(out.len()), report);
    }

    /// Whether the seeds moved since the last call — a peer became
    /// dialable, reached a better class, or its hello named it — clearing it.
    pub(crate) fn take_seeds_moved(&mut self) -> bool {
        self.seeds.take_moved()
    }

    /// Whether `peer`'s record entered this run from a seed at that endpoint —
    /// its seed origin rides the record (ADR-0109).
    pub(crate) fn is_remembered(&self, peer: PeerEndpoint) -> bool {
        self.sources.is_remembered(peer)
    }

    /// This run's seeds, best first: every directly dialable peer that sent
    /// bytes, granted a rank, or is held now and not spent — never one the
    /// download distrusts — with the hash and crypt stance its hello named,
    /// else its record's: without the stance a `required` policy could not
    /// dial it again (ADR-0109, "Source Seeds").
    pub(crate) fn source_seeds(&self) -> Vec<SourceSeed> {
        self.seeds
            .ranking(|peer| self.sources.holds(peer) && !self.sources.is_spent(peer))
            .into_iter()
            .map(|(endpoint, rank)| {
                let record = self.peer_crypt(endpoint);
                let hello = self.seeds.hello(endpoint);
                SourceSeed {
                    endpoint,
                    user_hash: hello
                        .map(|hello| hello.user_hash)
                        .or_else(|| record.user_hash()),
                    crypt: hello
                        .and_then(|hello| hello.crypt)
                        .or_else(|| record.stated_stance()),
                    rank,
                }
            })
            .filter(|seed| !self.sources.distrusts(seed.user_hash))
            .collect()
    }
}
