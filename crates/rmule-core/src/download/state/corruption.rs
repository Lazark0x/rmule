//! What a corrupt part does to its writers (ADR-0117 §1), one rule whichever
//! evidence showed it: a Trusted AICH Root's cells, a verified refetch's, or a
//! failure the **Failed Cells** compare. A failed part blames nobody by itself.
//! Cells proved corrupt are charged in the **Corruption Ledger**, a proven
//! sender past stock's limit is convicted, and a source the evidence points to
//! is **Set Aside** from the part. Nothing else moves a source, so a bad seed
//! cannot take an honest one with it.

use std::cmp::Reverse;
use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

use rmule_peer::PartIndex;
use rmule_primitives::{PeerEndpoint, UserHash};

use crate::assembly::{KEPT_ATTEMPTS, PartAssembly, Verdict};
use crate::service::{DownloadEvent, PeerRetirementReason};

use super::{Decision, DownloadState};

/// The sources **Set Aside** from one part.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct SetAside {
    /// Those its evidence proved: they stay out whoever is left.
    proven: BTreeSet<PeerEndpoint>,
    /// Those a repeated failure points to: a proof clears them, and the last
    /// worker holding the part is never one of them.
    suspected: BTreeSet<PeerEndpoint>,
}

impl SetAside {
    /// Whether `peer` is set aside.
    pub(super) fn holds(&self, peer: PeerEndpoint) -> bool {
        self.proven.contains(&peer) || self.suspected.contains(&peer)
    }
}

impl DownloadState {
    /// `part_index`, assembled as `assembled`, failed its check with nothing to
    /// name its corrupt cells: it is fetched again, its failure is compared
    /// with the part's Failed Cells and settled, and the attempt joins them.
    pub(super) fn refetch_rootless(
        &mut self,
        now: Instant,
        part_index: PartIndex,
        assembled: &PartAssembly,
        out: &mut Vec<Decision>,
    ) {
        self.scheduler.failed(part_index);
        self.moved.insert(part_index);
        // The lane read every cell of a part that failed; a part it did not
        // read shows nothing.
        let Some(attempt) = assembled.attempt() else {
            self.reassign_workers(now, out);
            return;
        };
        let writers = attempt.writers().len();
        let kept = self.failed_cells.entry(part_index).or_default();
        let verdict = attempt.names(kept.last());
        kept.push(attempt);
        if kept.len() > KEPT_ATTEMPTS {
            kept.remove(0);
        }
        let user_hashes = user_hashes(self.failed_cells.get(&part_index).map(Vec::as_slice));
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        out.push(Decision::Emit(DownloadEvent::PartCorrupt {
            download_id: self.download_id,
            part_index: part_index.value(),
            writers: count(writers),
            named: count(verdict.named()),
        }));
        self.settle(
            now,
            part_index,
            &verdict,
            &HashMap::new(),
            &user_hashes,
            out,
        );
        self.reassign_workers(now, out);
    }

    /// `part_index` verified as `assembled`: each writer's cells count good,
    /// nobody stays set aside from it, and its bytes judge the Failed Cells
    /// it kept (ADR-0117 §1).
    pub(super) fn part_verified(
        &mut self,
        now: Instant,
        part_index: PartIndex,
        assembled: &PartAssembly,
        out: &mut Vec<Decision>,
    ) {
        for (writer, bytes) in assembled.shares() {
            self.ledger.credit(writer, bytes);
        }
        self.set_aside.remove(&part_index);
        let Some(failed) = self.failed_cells.remove(&part_index) else {
            return;
        };
        if let Some(attempt) = assembled.attempt() {
            let verdict = attempt.disproves(&failed);
            let convicted = self.charge(&verdict, &HashMap::new(), out);
            self.convict(now, &convicted, &user_hashes(Some(&failed)), out);
        }
    }

    /// `peer`'s worker ended: a recovery ask it held is never answered, so
    /// its part takes the rootless path rather than waiting for good
    /// (ADR-0038).
    pub(super) fn recovery_unanswered(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        out: &mut Vec<Decision>,
    ) {
        let mut parts: Vec<PartIndex> = self
            .awaiting_recovery
            .iter()
            .filter(|(_, (asked, _))| *asked == peer)
            .map(|(&part_index, _)| part_index)
            .collect();
        parts.sort_unstable();
        for part_index in parts {
            if let Some((_, assembled)) = self.awaiting_recovery.remove(&part_index) {
                self.refetch_rootless(now, part_index, &assembled, out);
            }
        }
    }

    /// Act on what a failure of `part_index` showed: charge it, set aside
    /// whom it points to, and convict. `good` is what the same judgement
    /// proved good, by writer.
    pub(super) fn settle(
        &mut self,
        now: Instant,
        part_index: PartIndex,
        verdict: &Verdict,
        good: &HashMap<PeerEndpoint, u64>,
        user_hashes: &HashMap<PeerEndpoint, UserHash>,
        out: &mut Vec<Decision>,
    ) {
        let convicted = self.charge(verdict, good, out);
        self.set_aside_writers(part_index, verdict, &convicted, out);
        self.convict(now, &convicted, user_hashes, out);
    }

    /// Write `verdict` into the ledger and judge each sender it charged:
    /// those past the limit, and for the rest stock's report line
    /// (`CorruptionBlackBox.cpp:229-238`).
    fn charge(
        &mut self,
        verdict: &Verdict,
        good: &HashMap<PeerEndpoint, u64>,
        out: &mut Vec<Decision>,
    ) -> BTreeSet<PeerEndpoint> {
        self.ledger.charge(verdict);
        let mut convicted = BTreeSet::new();
        for &sender in verdict.charged.keys() {
            let more = good.get(&sender).copied().unwrap_or(0);
            let standing = self.ledger.standing(sender, more);
            if standing.convicted() {
                convicted.insert(sender);
            } else {
                out.push(Decision::Emit(DownloadEvent::BadDataCounted {
                    download_id: self.download_id,
                    peer: sender,
                    bad_bytes: standing.bad,
                    total_bytes: standing.total,
                }));
            }
        }
        convicted
    }

    /// Set aside whom `verdict` points to on `part_index`, and say each one
    /// newly out. A proof explains the failure, so it clears the suspicions.
    fn set_aside_writers(
        &mut self,
        part_index: PartIndex,
        verdict: &Verdict,
        convicted: &BTreeSet<PeerEndpoint>,
        out: &mut Vec<Decision>,
    ) {
        let aside = self.set_aside.entry(part_index).or_default();
        let before = aside.clone();
        if verdict.proven.is_empty() {
            aside.suspected.extend(&verdict.suspected);
        } else {
            aside.suspected.clear();
            aside.proven.extend(&verdict.proven - convicted);
        }
        self.reopen_set_aside();
        let Some(aside) = self.set_aside.get(&part_index) else {
            return;
        };
        let proven = aside.proven.iter().map(|&peer| (peer, true));
        let suspected = aside.suspected.iter().map(|&peer| (peer, false));
        for (peer, proven) in proven.chain(suspected) {
            if !before.holds(peer) {
                out.push(Decision::Emit(DownloadEvent::SourceSetAside {
                    download_id: self.download_id,
                    peer,
                    part_index: part_index.value(),
                    proven,
                }));
            }
        }
    }

    /// The last granted worker holding a part is never set aside on suspicion
    /// alone: the suspect with the most verified bytes is asked again, so the
    /// part narrows to one writer at worst and that writer's attempt settles
    /// it. Read at every handout, since the worker left open may end.
    pub(super) fn reopen_set_aside(&mut self) {
        if self
            .set_aside
            .values()
            .all(|aside| aside.suspected.is_empty())
        {
            return;
        }
        let granted: Vec<PeerEndpoint> = self
            .worker_slots
            .keys()
            .copied()
            .filter(|&worker| self.slot_asks.granted(worker))
            .collect();
        for (&part_index, aside) in &mut self.set_aside {
            if aside.suspected.is_empty() {
                continue;
            }
            let holders = granted.iter().copied().filter(|&worker| {
                self.sources
                    .worker_parts(worker)
                    .is_some_and(|parts| parts.has(part_index))
            });
            let holders: Vec<PeerEndpoint> = holders.collect();
            if holders.iter().all(|&worker| aside.holds(worker)) {
                let kept = holders
                    .into_iter()
                    .filter(|worker| aside.suspected.contains(worker))
                    .max_by_key(|&worker| (self.ledger.good(worker), Reverse(worker)));
                if let Some(kept) = kept {
                    aside.suspected.remove(&kept);
                }
            }
        }
    }

    /// `convicted` leave as stock's ban sends them: the address across the
    /// node (`CorruptionBlackBox.cpp:217-225`), and for this file the User
    /// Hash each wrote under, so a sender whose worker ended is distrusted too.
    fn convict(
        &mut self,
        now: Instant,
        convicted: &BTreeSet<PeerEndpoint>,
        user_hashes: &HashMap<PeerEndpoint, UserHash>,
        out: &mut Vec<Decision>,
    ) {
        for &sender in convicted {
            out.push(Decision::BanSender { peer: sender });
            match user_hashes.get(&sender) {
                Some(&user_hash) => self.distrust_hash(sender, user_hash, out),
                None => self.distrust(sender, out),
            }
            self.retire(
                now,
                sender,
                PeerRetirementReason::PartVerificationFailed,
                out,
            );
        }
    }
}

/// The User Hash each writer of `attempts` wrote under, the latest hello's.
fn user_hashes(attempts: Option<&[crate::assembly::Attempt]>) -> HashMap<PeerEndpoint, UserHash> {
    attempts
        .into_iter()
        .flatten()
        .flat_map(|attempt| attempt.user_hashes())
        .map(|(&writer, &user_hash)| (writer, user_hash))
        .collect()
}
