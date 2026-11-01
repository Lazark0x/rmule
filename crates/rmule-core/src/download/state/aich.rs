//! The AICH leg (ADR-0038): the secure trusted-root vote a peer's proposed
//! root joins, and the recovery answer that repairs a part whose MD4 hash
//! failed. Trust is a tally over masked proposing IPs, as aMule's
//! `SHAHashSet` counts it.

use rmule_peer::PartIndex;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use crate::KadAichRoot;
use crate::service::{DownloadEvent, PeerRetirementReason};
use rmule_kad::KadAichRootReport;
use rmule_primitives::{AichRootHash, PeerEndpoint};

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

    /// Whether each peer's root is still wanted: the vote reads it, and a
    /// recovery ask goes only to a peer stating the trusted root.
    pub(crate) const fn wants_roots(self) -> bool {
        !matches!(self, Self::Contested)
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

/// The unique-IP key for trusted-set voting: aMule keeps an IPv4 address's 20
/// most significant bits so a single subnet cannot stuff the vote. Its
/// `dwIP &= 0x00F0FFFF` (`SHAHashSet.cpp:451`) reads so on a network-order word
/// in a little-endian host; `Ipv4Addr` → `u32` is big-endian, so the bits to
/// keep here are the high ones. An IPv6 proposer is keyed by its /64 — the prefix one delegation hands a
/// host, the same anti-stuffing intent (no implementation pins a finer rule).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum AichVoter {
    V4(u32),
    V6(u64),
}

pub(super) fn masked_ip(peer: PeerEndpoint) -> AichVoter {
    match peer {
        PeerEndpoint::V4(ep) => AichVoter::V4(u32::from(ep.ip) >> 12),
        PeerEndpoint::V6(ep) => AichVoter::V6((ep.ip.to_bits() >> 64) as u64),
    }
}

/// The voters a vote keeps, first come: enough for any swarm's ten-and-92 %,
/// and a bound on what proposals can hold.
pub(super) const MAX_VOTERS: usize = 1024;

/// The trusted-set tally (ADR-0038): each voter's one standing vote, and how
/// many stand behind each root.
#[derive(Debug, Default)]
pub(super) struct AichVote {
    pub(super) ballots: HashMap<AichVoter, AichRootHash>,
    pub(super) tally: HashMap<AichRootHash, usize>,
}

impl AichVote {
    /// `voter` states `root`, its vote moving there; whether `root` now clears
    /// the agreement thresholds. Only the root just voted can cross them: a
    /// moved vote leaves the total alone, and a new voter raises it.
    pub(super) fn cast(&mut self, voter: AichVoter, root: AichRootHash) -> bool {
        if self.ballots.len() >= MAX_VOTERS && !self.ballots.contains_key(&voter) {
            return false;
        }
        match self.ballots.insert(voter, root) {
            Some(held) if held == root => {}
            Some(held) => {
                self.withdraw(held);
                *self.tally.entry(root).or_default() += 1;
            }
            None => *self.tally.entry(root).or_default() += 1,
        }
        let ips = self.tally.get(&root).copied().unwrap_or(0);
        ips >= MIN_UNIQUE_IPS_TO_TRUST && ips * 100 >= self.ballots.len() * MIN_PERCENTAGE_TO_TRUST
    }

    fn withdraw(&mut self, root: AichRootHash) {
        if let Some(ips) = self.tally.get_mut(&root) {
            *ips -= 1;
            if *ips == 0 {
                self.tally.remove(&root);
            }
        }
    }
}

impl DownloadState {
    /// Trusted-set vote (ADR-0038, eMule secure AICH): `peer`'s masked IP
    /// states AICH master `root`, moving any vote it held, and the root
    /// commits once it clears the agreement thresholds — enabling recovery for a download whose link
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
        self.aich_stated.insert(peer, root);
        if !self.aich_root.vote_runs() {
            return;
        }
        if self.aich_root_votes.cast(masked_ip(peer), root) {
            self.aich_root_votes = AichVote::default();
            self.aich_root = match self.aich_root {
                AichRootAuthority::Kad(kad_root) if kad_root != root => {
                    out.push(Decision::ContestKadAichRoot);
                    out.push(Decision::Emit(DownloadEvent::KadAichRootContested {
                        download_id: self.download_id,
                        kad_root,
                        voted_root: root,
                    }));
                    AichRootAuthority::Contested
                }
                _ => AichRootAuthority::Voted(root),
            };
        }
    }
    /// Who to ask for `root`'s recovery data at `now`, `completing` having
    /// finished the part: a connected worker stating `root`, with no recovery
    /// ask of ours out and past the peer's clock (ADR-0107 invariant 14), the
    /// peer asked longest ago first, so asks spread as stock's random pick
    /// spreads them (3.1.0 `PartFile.cpp:3994-4047`).
    pub(super) fn recovery_asker(
        &self,
        now: Instant,
        root: AichRootHash,
        completing: Option<PeerEndpoint>,
    ) -> Option<PeerEndpoint> {
        self.connected_workers()
            .into_iter()
            .filter(|peer| self.aich_stated.get(peer) == Some(&root))
            .filter(|peer| {
                !self
                    .awaiting_recovery
                    .values()
                    .any(|(asked, _)| asked == peer)
            })
            .filter_map(|peer| {
                let place = self.sources.dial_place(peer)?;
                (!self.standings.clock_holds(&place, now)).then(|| {
                    (
                        self.standings.last_ask(&place),
                        Some(peer) != completing,
                        peer,
                    )
                })
            })
            .min_by_key(|&(asked, other, _)| (asked, other))
            .map(|(.., peer)| peer)
    }

    /// Resume after a peer answered our `OP_AICHREQUEST` for `part_index`
    /// (ADR-0038): the lane judges the recovery data against the bytes in the
    /// file. An answer with no root left to judge it by leaves the part to its
    /// refetch.
    pub(super) fn on_aich_answer(
        &mut self,
        now: Instant,
        part_index: PartIndex,
        recovery_data: Vec<u8>,
        out: &mut Vec<Decision>,
    ) {
        if !self.awaiting_recovery.contains_key(&part_index) {
            return; // stale or duplicate answer
        }
        match self.aich_root.trusted() {
            Some(root) => out.push(Decision::CheckRecovery {
                part_index,
                root,
                recovery_data,
            }),
            None => self.on_recovery_checked_into(now, part_index, None, out),
        }
    }

    /// The lane judged a recovery answer for `part_index`: `bad_blocks` are
    /// the corrupt blocks it localizes, none when the data was malformed or
    /// named none. Drop exactly those blocks from the part's Arrived Ranges,
    /// retire the workers that wrote into them (distrusting a block's sole
    /// writer), and hand the dropped blocks to workers with room (ADR-0117).
    /// Malformed or untrusted recovery data — or a clean part whose MD4 still
    /// failed (root/file mismatch) — leaves the part to its refetch
    /// (ADR-0117 §1).
    pub(crate) fn on_recovery_checked(
        &mut self,
        now: Instant,
        part_index: PartIndex,
        bad_blocks: Option<Vec<u16>>,
    ) -> Vec<Decision> {
        let mut out = Vec::new();
        self.on_recovery_checked_into(now, part_index, bad_blocks, &mut out);
        out
    }

    fn on_recovery_checked_into(
        &mut self,
        now: Instant,
        part_index: PartIndex,
        bad_blocks: Option<Vec<u16>>,
        out: &mut Vec<Decision>,
    ) {
        let Some((_, mut assembled)) = self.awaiting_recovery.remove(&part_index) else {
            return; // its asker ended, and the part took its refetch
        };
        self.moved.insert(part_index);
        let bad_blocks = match bad_blocks {
            Some(blocks) if !blocks.is_empty() => blocks,
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
