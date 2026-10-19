//! A part that failed its check and no root names its corrupt cells (ADR-0117
//! §1): no Trusted AICH Root, a recovery answer that names no cell, or none at
//! all (ADR-0038). Its bytes are dropped and it is fetched again; the failure
//! is compared with the part's **Failed Cells**, and once the part verifies its
//! bytes prove the old copies that differ. Only a writer the evidence names is
//! retired, and only a proven one distrusted (ADR-0090 invariant 4).

use std::time::Instant;

use rmule_primitives::PeerEndpoint;

use crate::assembly::{Attempt, PartAssembly, Verdict};
use crate::service::{DownloadEvent, PeerRetirementReason};

use super::{Decision, DownloadState};

impl DownloadState {
    /// `part_index`, assembled as `assembled`, failed its check with nothing to
    /// name its corrupt cells: it is fetched again. The writers its failure
    /// names against the part's Failed Cells are retired, the proven ones
    /// distrusted, and the attempt becomes the part's Failed Cells.
    pub(super) fn refetch_rootless(
        &mut self,
        now: Instant,
        part_index: u32,
        assembled: &PartAssembly,
        out: &mut Vec<Decision>,
    ) {
        self.scheduler.failed(part_index);
        let attempt = assembled.attempt();
        let kept = self.failed_cells.remove(&part_index);
        let verdict = attempt.names(kept.as_ref());
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        out.push(Decision::Emit(DownloadEvent::PartCorrupt {
            download_id: self.download_id,
            part_index,
            writers: count(attempt.writers().len()),
            named: count(verdict.named.len()),
        }));
        let evidence: Vec<&Attempt> = std::iter::once(&attempt).chain(kept.as_ref()).collect();
        self.convict(now, &verdict, &evidence, out);
        self.failed_cells.insert(part_index, attempt);
        self.reassign_workers(now, out);
    }

    /// `part_index` verified as `assembled`: its Failed Cells, if it kept any,
    /// are judged by its bytes. The writers of a cell that differs are
    /// retired, and its sole writer distrusted (ADR-0117 §1).
    pub(super) fn judge_failed_cells(
        &mut self,
        now: Instant,
        part_index: u32,
        assembled: &PartAssembly,
        out: &mut Vec<Decision>,
    ) {
        let Some(failed) = self.failed_cells.remove(&part_index) else {
            return;
        };
        let verdict = assembled.attempt().disproves(&failed);
        self.convict(now, &verdict, &[&failed], out);
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
        let mut parts: Vec<u32> = self
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

    /// Distrust `verdict`'s proven writers — by the User Hash the first of
    /// `evidence` to hold one recorded when it wrote, so a writer whose worker
    /// ended is distrusted too — and retire every named writer still working.
    fn convict(
        &mut self,
        now: Instant,
        verdict: &Verdict,
        evidence: &[&Attempt],
        out: &mut Vec<Decision>,
    ) {
        for &writer in &verdict.proven {
            match evidence
                .iter()
                .find_map(|attempt| attempt.user_hash(writer))
            {
                Some(user_hash) => self.distrust_hash(writer, user_hash, out),
                None => self.distrust(writer, out),
            }
        }
        for &writer in &verdict.named {
            self.retire(
                now,
                writer,
                PeerRetirementReason::PartVerificationFailed,
                out,
            );
        }
    }
}
