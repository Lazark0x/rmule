//! The AICH leg (ADR-0038): the secure trusted-root vote a peer's proposed
//! root joins, and the recovery answer that repairs a part whose MD4 hash
//! failed. Trust is a tally over masked proposing IPs, exactly as aMule's
//! `SHAHashSet` counts it.

use std::collections::HashSet;
use std::time::Instant;

use crate::service::{DownloadEvent, PeerRetirementReason};
use rmule_primitives::{AichHashSet, AichRootHash, EMBLOCKSIZE, PeerEndpoint};

use super::{Decision, DownloadState};

/// eMule secure-AICH trust thresholds (aMule `SHAHashSet.cpp`
/// `MINUNIQUEIPS_TOTRUST` / `MINPERCENTAGE_TOTRUST`): a proposed AICH root is
/// trusted once ≥10 distinct IPs proposed it and it holds ≥92% of all proposing
/// IPs (ADR-0038).
const MIN_UNIQUE_IPS_TO_TRUST: usize = 10;
const MIN_PERCENTAGE_TO_TRUST: usize = 92;

/// The unique-IP key for trusted-set voting: aMule masks an IPv4 address to
/// its 20 most significant bits (`dwIP &= 0x00F0FFFF`) so a single subnet
/// cannot stuff the vote; `Ipv4Addr` → `u32` is big-endian (network order).
/// An IPv6 proposer is keyed by its /64 — the prefix one delegation hands a
/// host, the same anti-stuffing intent (no implementation pins a finer rule).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum AichVoter {
    V4(u32),
    V6(u64),
}

fn masked_ip(peer: PeerEndpoint) -> AichVoter {
    match peer {
        PeerEndpoint::V4(ep) => AichVoter::V4(u32::from(ep.ip) & 0x00F0_FFFF),
        PeerEndpoint::V6(ep) => AichVoter::V6((ep.ip.to_bits() >> 64) as u64),
    }
}

impl DownloadState {
    /// Trusted-set vote (ADR-0038, eMule secure AICH): tally `peer`'s proposed
    /// AICH master `root` by its masked IP and commit it as the trusted root
    /// once a root clears the agreement thresholds — enabling recovery for a
    /// download whose link carried no `h=`. A root already in force (from the
    /// link or an earlier commit) short-circuits the tally.
    pub(super) fn on_aich_file_hash_proposal(&mut self, peer: PeerEndpoint, root: AichRootHash) {
        if self.trusted_aich_root.is_some() {
            return;
        }
        self.aich_root_votes
            .entry(root)
            .or_default()
            .insert(masked_ip(peer));

        let total_ips: usize = self.aich_root_votes.values().map(HashSet::len).sum();
        if let Some((best_root, ips)) = self
            .aich_root_votes
            .iter()
            .map(|(r, ips)| (*r, ips.len()))
            .max_by_key(|&(_, ips)| ips)
            && ips >= MIN_UNIQUE_IPS_TO_TRUST
            && ips * 100 >= total_ips * MIN_PERCENTAGE_TO_TRUST
        {
            self.trusted_aich_root = Some(best_root);
        }
    }
    /// Resume after a peer answered our `OP_AICHREQUEST` for `part_index`
    /// (ADR-0038). Verify the recovery data against the trusted root; if it
    /// localizes corrupt blocks, retire only those blocks' provenance-named
    /// contributors, truncate the shared assembly to the earliest corrupt
    /// block, return the part to pending (re-streaming from there reuses the
    /// contiguous prefix), and reassign idle workers. Malformed/untrusted
    /// recovery data — or a clean part whose MD4 still failed (root/file
    /// mismatch) — falls back to ADR-0029 retire-all.
    pub(super) fn on_aich_answer(
        &mut self,
        now: Instant,
        part_index: u32,
        recovery_data: &[u8],
        out: &mut Vec<Decision>,
    ) {
        let Some(mut assembled) = self.awaiting_recovery.remove(&part_index) else {
            return; // stale or duplicate answer
        };
        let Some(root) = self.trusted_aich_root else {
            self.retire_all_contributors(now, &assembled, out);
            return;
        };
        let part = crate::planning::part_plan(self.file_size, part_index);
        let bad_blocks = match AichHashSet::verify_part(
            self.file_size,
            part.offset,
            assembled.bytes(),
            recovery_data,
            root,
        ) {
            Ok(blocks) if !blocks.is_empty() => blocks,
            _ => {
                self.retire_all_contributors(now, &assembled, out);
                return;
            }
        };

        // Honest attribution: retire only the peers that delivered a corrupt
        // block (deduped, slot-ordered).
        let mut bad: Vec<(usize, PeerEndpoint)> = bad_blocks
            .iter()
            .filter_map(|&b| assembled.contributor_of_block(b as usize))
            .filter_map(|c| self.worker_slots.get(&c).map(|slot| (slot.as_usize(), c)))
            .collect();
        bad.sort_unstable_by_key(|&(slot, _)| slot);
        bad.dedup_by_key(|&mut (_, c)| c);

        // Truncate to the earliest corrupt block and return the part to pending;
        // the existing resume-from-prefix-end re-streams from the corruption on.
        let earliest = bad_blocks.iter().copied().min().expect("non-empty");
        assembled.truncate(u64::from(earliest) * EMBLOCKSIZE);
        self.assembly.insert(part_index, assembled);
        self.scheduler.repend_part(part_index);

        for (_, contributor) in bad {
            // The recovery pinned the corrupt blocks on it.
            self.distrust(contributor, out);
            out.push(Decision::Emit(DownloadEvent::PeerRetired {
                download_id: self.download_id,
                peer: contributor,
                reason: PeerRetirementReason::PartVerificationFailed,
            }));
            self.release(
                now,
                contributor,
                PeerRetirementReason::PartVerificationFailed,
                out,
            );
        }
        // Hand the re-pended part to a still-connected idle worker (slot order),
        // then backfill. Redundant with `release`'s own reassign when a bad
        // contributor was retired, but covers the case where none still are.
        self.reassign_workers(now, out);
    }
}
