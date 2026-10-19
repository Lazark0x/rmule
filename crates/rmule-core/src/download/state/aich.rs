//! The AICH leg (ADR-0038): the secure trusted-root vote a peer's proposed
//! root joins, and the recovery answer that repairs a part whose MD4 hash
//! failed. Trust is a tally over masked proposing IPs, exactly as aMule's
//! `SHAHashSet` counts it.

use std::collections::HashSet;
use std::time::Instant;

use crate::KadAichRoot;
use crate::service::{DownloadEvent, PeerRetirementReason};
use rmule_kad::KadAichRootReport;
use rmule_primitives::{AichHashSet, AichRootHash, PeerEndpoint};

use super::{Decision, DownloadState};

/// eMule secure-AICH trust thresholds (aMule `SHAHashSet.cpp`
/// `MINUNIQUEIPS_TOTRUST` / `MINPERCENTAGE_TOTRUST`): a proposed AICH root is
/// trusted once ≥10 distinct IPs proposed it and it holds ≥92% of all proposing
/// IPs (ADR-0038).
const MIN_UNIQUE_IPS_TO_TRUST: usize = 10;
const MIN_PERCENTAGE_TO_TRUST: usize = 92;

/// Where a download's AICH root stands (ADR-0038's root authority): the
/// link's `h=`, then a **Qualified Kad Root**, then the peer vote, then none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AichRootAuthority {
    /// No root: the peer vote may commit one.
    Rootless,
    /// The link's `h=`: trusted, and the vote does not run.
    Link(AichRootHash),
    /// The Qualified Kad Root the download was started from: trusted, and the
    /// vote still runs and may contest it.
    Kad(AichRootHash),
    /// The vote's root: committed with no root in force, or agreeing with the
    /// Kad root.
    Voted(AichRootHash),
    /// The vote committed a root other than the Kad root: neither is trusted,
    /// and the vote is over.
    Contested,
}

impl AichRootAuthority {
    /// The authority a run starts under: the link's `h=` above the Kad root
    /// its record keeps (or the contest that ended it), else none.
    pub(crate) const fn at_start(link: Option<AichRootHash>, kad: Option<KadAichRoot>) -> Self {
        match (link, kad) {
            (Some(root), _) => Self::Link(root),
            (None, Some(KadAichRoot::Trusted(root))) => Self::Kad(root),
            (None, Some(KadAichRoot::Contested)) => Self::Contested,
            (None, None) => Self::Rootless,
        }
    }

    /// The **Trusted AICH Root**, if any.
    pub(crate) const fn trusted(self) -> Option<AichRootHash> {
        match self {
            Self::Link(root) | Self::Kad(root) | Self::Voted(root) => Some(root),
            Self::Rootless | Self::Contested => None,
        }
    }

    /// Whether the peer vote still runs: with no root, or a Kad root it may
    /// contest.
    pub(crate) const fn vote_runs(self) -> bool {
        matches!(self, Self::Rootless | Self::Kad(_))
    }
}

/// The **Qualified Kad Root** of a Kad keyword result (ADR-0038): its one
/// AICH root, when the result carries exactly one and at least a third of the
/// file's `publishers` reported it, and at least `MIN_UNIQUE_IPS_TO_TRUST` of
/// them. The third is eMule's rule (`SearchList.cpp:785-803`), stated exactly
/// rather than in its integer division; the floor is the peer vote's, because
/// both counts are the storer's word.
pub(crate) fn qualified_kad_root(
    reports: &[KadAichRootReport],
    publishers: Option<u8>,
) -> Option<AichRootHash> {
    let [report] = reports else {
        return None;
    };
    let publishers = usize::from(publishers?);
    let popularity = usize::from(report.popularity);
    (publishers > 0 && popularity >= MIN_UNIQUE_IPS_TO_TRUST && popularity * 3 >= publishers)
        .then_some(report.root)
}

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
    /// AICH master `root` by its masked IP and commit it once a root clears
    /// the agreement thresholds — enabling recovery for a download whose link
    /// carried no `h=`. The vote runs only while the download is rootless or
    /// holds a Kad root: a commit agreeing with the Kad root keeps it, and one
    /// naming another root leaves the download trusting neither, durably and
    /// in the Run Log.
    pub(super) fn on_aich_file_hash_proposal(
        &mut self,
        peer: PeerEndpoint,
        root: AichRootHash,
        out: &mut Vec<Decision>,
    ) {
        if !self.aich_root.vote_runs() {
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
            self.aich_root = match self.aich_root {
                AichRootAuthority::Kad(kad_root) if kad_root != best_root => {
                    out.push(Decision::ContestKadAichRoot);
                    out.push(Decision::Emit(DownloadEvent::KadAichRootContested {
                        download_id: self.download_id,
                        kad_root,
                        voted_root: best_root,
                    }));
                    AichRootAuthority::Contested
                }
                _ => AichRootAuthority::Voted(best_root),
            };
        }
    }
    /// Resume after a peer answered our `OP_AICHREQUEST` for `part_index`
    /// (ADR-0038). Verify the recovery data against the trusted root; if it
    /// localizes corrupt blocks, drop exactly those blocks from the part's
    /// Arrived Ranges, retire the workers that wrote into them (distrusting a
    /// block's sole writer), and hand the dropped blocks to workers with room
    /// (ADR-0117). Malformed/untrusted
    /// recovery data — or a clean part whose MD4 still failed (root/file
    /// mismatch) — leaves the part to its refetch (ADR-0117 §1).
    pub(super) fn on_aich_answer(
        &mut self,
        now: Instant,
        part_index: u32,
        recovery_data: &[u8],
        out: &mut Vec<Decision>,
    ) {
        let Some((_, mut assembled)) = self.awaiting_recovery.remove(&part_index) else {
            return; // stale or duplicate answer
        };
        let Some(root) = self.aich_root.trusted() else {
            self.refetch_rootless(now, part_index, &assembled, out);
            return;
        };
        let part = crate::planning::part_plan(self.file_size, part_index);
        let bad_blocks = match AichHashSet::verify_part(
            self.file_size,
            part.offset,
            &assembled.bytes(),
            recovery_data,
            root,
        ) {
            Ok(blocks) if !blocks.is_empty() => blocks,
            _ => {
                self.refetch_rootless(now, part_index, &assembled, out);
                return;
            }
        };

        // Honest attribution: retire only the peers that delivered a corrupt
        // block (deduped, slot-ordered).
        let mut bad: Vec<(usize, PeerEndpoint)> = bad_blocks
            .iter()
            .flat_map(|&b| assembled.writers_of_block(b as usize).iter().copied())
            .filter_map(|c| self.worker_slots.get(&c).map(|slot| (slot.as_usize(), c)))
            .collect();
        bad.sort_unstable_by_key(|&(slot, _)| slot);
        bad.dedup_by_key(|&mut (_, c)| c);
        // A corrupt block's sole writer is its proven sender (ADR-0090).
        let proven: HashSet<PeerEndpoint> = bad_blocks
            .iter()
            .filter_map(|&b| match assembled.writers_of_block(b as usize) {
                [sole] => Some(*sole),
                _ => None,
            })
            .collect();

        // Forget exactly the corrupt blocks; their bytes are fetched again.
        assembled.drop_blocks(&bad_blocks);
        self.assembly.insert(part_index, assembled);
        self.scheduler.failed(part_index);

        for (_, contributor) in bad {
            if proven.contains(&contributor) {
                self.distrust(contributor, out);
            }
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
        // Hand the dropped blocks to still-connected workers with room (slot
        // order), then backfill. Redundant with `release`'s own reassign when
        // a bad contributor was retired, but covers the case where none still
        // are.
        self.reassign_workers(now, out);
    }
}
