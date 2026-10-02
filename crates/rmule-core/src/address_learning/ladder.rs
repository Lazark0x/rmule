//! One ladder: the remembered **Address Observation**s for one value kind,
//! and the per-tier rules that turn them into at most one holdable value per
//! rung (ADR-0084).
//!
//! A ladder keeps raw observations, never a derived verdict, so every rule is
//! re-evaluated against the caller's `now` and nothing has to be invalidated
//! on a timer. Each tier's rule answers the same two questions — *what would
//! this tier hold?* and *when does that holding lapse?* — which is what lets
//! one pass produce both the fresh verdict and the stale last-known value.
//!
//! The ladder is generic over the observed value so the address ladder (one
//! per **Address Family**) and the port ladder (one per socket role) share the
//! quorum, freshness and disagreement machinery rather than growing two
//! copies of it — the outcome ADR-0084 wrote the store to prevent.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::ConfidenceTier;

/// The sliding window a Kad self-check report and a peer's vote stay fresh
/// for. kno's aMule constant (`PublicIPv6Corroboration.h`, 30 × 60 × 1000 ms),
/// preferred over the IPv6 spec's 300 s because hellos from distinct peers
/// arrive minutes apart on a quiet client: a few-minute window expires the
/// first vote before the third arrives and the quorum never forms.
pub(super) const OBSERVATION_WINDOW: Duration = Duration::from_secs(30 * 60);

/// Distinct observers that must agree before the [`KadCheck`] rung holds —
/// two, under either [`KadAgreement`].
///
/// [`KadCheck`]: ConfidenceTier::KadCheck
pub(super) const KAD_AGREEMENT: usize = 2;

/// Which earlier [`KadCheck`] reports may back the newest one. aMule applies
/// two different rules to the two things a Kad node tells us about
/// ourselves, and each ladder keeps its own.
///
/// [`KadCheck`]: ConfidenceTier::KadCheck
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum KadAgreement {
    /// Only an unbroken run of agreeing reports backs the newest; the first
    /// disagreement ends the run. The address rule (`0x58`).
    #[default]
    Consecutive,
    /// Any earlier report inside the window that names the same value backs
    /// it — the **Extern Kad Port** rule, aMule `CPrefs::SetExternKadPort`
    /// (`Prefs.cpp:305-316` at kno `ab483654`), which scans *every* port the
    /// round heard: 5000, 6000, 5000 adopts 5000.
    AnyEarlier,
}

/// Distinct observers that must agree before the [`PeerVote`] rung holds
/// (kno's threshold 3: "two is one dual-homed host, one host that reconnected
/// from a new lease, or one attacker holding a second socket — none of which
/// is a second opinion").
///
/// [`PeerVote`]: ConfidenceTier::PeerVote
pub(super) const PEER_QUORUM: usize = 3;

/// Observers one quorum tier remembers. Deliberately above the quorum itself
/// so one expiry does not unseat an otherwise-agreed value
/// (`PUBLIC_IPV6_CORROBORATION_MAX_OBSERVERS`).
pub(super) const OBSERVERS_REMEMBERED: usize = 8;

/// What one rung would hold, and when that holding lapses.
///
/// `expires` is `None` for a rung that never ages out on its own — an operator
/// override, or a server assignment while its session lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Rung<T> {
    /// The rung's tier — its place on the family's ladder.
    pub(super) tier: ConfidenceTier,
    /// The value this tier would hold.
    pub(super) value: T,
    /// When the holding lapses, or `None` while it cannot.
    pub(super) expires: Option<Instant>,
}

impl<T> Rung<T> {
    /// Whether this rung still holds at `now`.
    pub(super) fn is_fresh(&self, now: Instant) -> bool {
        self.expires.is_none_or(|expires| expires > now)
    }
}

/// One remembered observation.
#[derive(Clone, Copy, Debug)]
struct Entry<T> {
    tier: ConfidenceTier,
    value: T,
    /// The observer's own address — the quorum key. Never a user hash: a hash
    /// costs nothing to invent.
    observer: Option<IpAddr>,
    at: Instant,
    /// A port-mapping grant's lease; the only source whose lifetime the source
    /// itself states.
    lease: Option<Duration>,
    /// When the session that produced this observation ended — the two server
    /// tiers only.
    /// An ended session stops being *fresh* but keeps its last-known value, so
    /// a reconnect never blanks the UDP crypt key mid-reask.
    ended: Option<Instant>,
}

/// The remembered observations for one value kind.
#[derive(Debug)]
pub(super) struct Ladder<T> {
    entries: Vec<Entry<T>>,
    agreement: KadAgreement,
}

impl<T> Default for Ladder<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            agreement: KadAgreement::default(),
        }
    }
}

impl<T> Ladder<T> {
    /// An empty ladder whose [`KadCheck`](ConfidenceTier::KadCheck) rung
    /// follows `agreement`.
    pub(super) fn with_agreement(agreement: KadAgreement) -> Self {
        Self {
            entries: Vec::new(),
            agreement,
        }
    }
}

impl<T: Copy + PartialEq> Ladder<T> {
    /// Record one observation, applying the tier's own memory rule: the
    /// single-valued tiers keep only their newest observation, the quorum
    /// tiers keep the last [`OBSERVERS_REMEMBERED`] and at most one vote per
    /// observer.
    pub(super) fn record(
        &mut self,
        tier: ConfidenceTier,
        value: T,
        observer: Option<IpAddr>,
        at: Instant,
        lease: Option<Duration>,
    ) {
        match tier {
            // One current value each: a newer assignment, grant or override
            // replaces the older outright.
            ConfidenceTier::Override
            | ConfidenceTier::Server
            | ConfidenceTier::LowIdReport
            | ConfidenceTier::MappingGrant => {
                self.entries.retain(|entry| entry.tier != tier);
            }
            // One vote per observer: a peer that votes twice has still voted
            // once, or the quorum would be one host's to forge.
            ConfidenceTier::PeerVote => {
                self.entries
                    .retain(|entry| entry.tier != tier || entry.observer != observer);
            }
            // Consecutive reports are the rule itself — keep the sequence.
            ConfidenceTier::KadCheck => {}
            // The interface set is replaced wholesale by a refresh; it is
            // never a remembered point observation.
            ConfidenceTier::Interface => return,
        }
        self.entries.push(Entry {
            tier,
            value,
            observer,
            at,
            lease,
            ended: None,
        });
        self.prune(tier);
    }

    /// Withdraw everything `tier` observed — the source has *contradicted*
    /// itself rather than merely aged out (a re-assignment down to Low ID says
    /// we hold no public address at all, so the old one must not survive as a
    /// stale last-known and re-arm a crypt key the peer cannot reproduce).
    pub(super) fn withdraw(&mut self, tier: ConfidenceTier) {
        self.entries.retain(|entry| entry.tier != tier);
    }

    /// Mark `tier`'s session ended at `at`: it stops being fresh but keeps its
    /// value as the stale last-known.
    pub(super) fn end_session(&mut self, tier: ConfidenceTier, at: Instant) {
        for entry in &mut self.entries {
            if entry.tier == tier && entry.ended.is_none() {
                entry.ended = Some(at);
            }
        }
    }

    /// Every fresh [`KadCheck`](ConfidenceTier::KadCheck) report still held,
    /// as (observer, value): the raw material of the **Own Mapping**
    /// (ADR-0091's amendment), which asks whether two observers
    /// *disagree* — a question the two-agree rung throws away.
    pub(super) fn kad_reports(&self, now: Instant) -> Vec<(IpAddr, T)> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.tier == ConfidenceTier::KadCheck && entry.at + OBSERVATION_WINDOW > now
            })
            .filter_map(|entry| entry.observer.map(|observer| (observer, entry.value)))
            .collect()
    }

    /// Whether any observation is remembered at all.
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every rung this ladder can offer, in no particular order — the caller's
    /// family decides the ranking, because the same tier sits at different
    /// heights on the IPv4 and IPv6 ladders.
    pub(super) fn rungs(&self) -> Vec<Rung<T>> {
        [
            self.single(ConfidenceTier::Override),
            self.single(ConfidenceTier::Server),
            self.single(ConfidenceTier::LowIdReport),
            self.single(ConfidenceTier::MappingGrant),
            self.two_agree(),
            self.quorum(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// A single-valued tier's rung: its newest observation, expiring when its
    /// session ended or its lease runs out.
    fn single(&self, tier: ConfidenceTier) -> Option<Rung<T>> {
        let entry = self.newest(tier)?;
        let expires = match (entry.ended, entry.lease) {
            (Some(ended), _) => Some(ended),
            (None, Some(lease)) => Some(entry.at + lease),
            (None, None) => None,
        };
        Some(Rung {
            tier,
            value: entry.value,
            expires,
        })
    }

    /// The [`KadCheck`] rung under aMule's two-agree rule: the newest report
    /// is the candidate and each older report that *agrees* adds its
    /// observer; [`KAD_AGREEMENT`] distinct observers hold it. Under
    /// [`KadAgreement::Consecutive`] the first disagreement ends the search,
    /// under [`KadAgreement::AnyEarlier`] it is skipped. The window slides
    /// with the newest report.
    ///
    /// [`KadCheck`]: ConfidenceTier::KadCheck
    fn two_agree(&self) -> Option<Rung<T>> {
        let mut reports = self
            .entries
            .iter()
            .rev()
            .filter(|entry| entry.tier == ConfidenceTier::KadCheck);
        let newest = reports.next()?;
        let mut observers: Vec<IpAddr> = newest.observer.into_iter().collect();
        for report in reports {
            if report.value != newest.value {
                match self.agreement {
                    KadAgreement::Consecutive => break,
                    KadAgreement::AnyEarlier => continue,
                }
            }
            if let Some(observer) = report.observer
                && !observers.contains(&observer)
            {
                observers.push(observer);
            }
        }
        (observers.len() >= KAD_AGREEMENT).then_some(Rung {
            tier: ConfidenceTier::KadCheck,
            value: newest.value,
            expires: Some(newest.at + OBSERVATION_WINDOW),
        })
    }

    /// The [`PeerVote`] rung: the value [`PEER_QUORUM`] distinct observers
    /// name, expiring when the quorum would drop below the threshold — that
    /// is, when the `PEER_QUORUM`th-newest supporting vote leaves the window.
    /// The best-supported value wins a tie, then the most recent.
    ///
    /// [`PeerVote`]: ConfidenceTier::PeerVote
    fn quorum(&self) -> Option<Rung<T>> {
        let votes: Vec<&Entry<T>> = self
            .entries
            .iter()
            .filter(|entry| entry.tier == ConfidenceTier::PeerVote)
            .collect();
        let mut best: Option<Rung<T>> = None;
        let mut best_support = 0usize;
        for candidate in &votes {
            let mut supporting: Vec<Instant> = votes
                .iter()
                .filter(|vote| vote.value == candidate.value)
                .map(|vote| vote.at)
                .collect();
            if supporting.len() < PEER_QUORUM {
                continue;
            }
            supporting.sort_unstable();
            supporting.reverse();
            let lapses = supporting[PEER_QUORUM - 1] + OBSERVATION_WINDOW;
            let better = match &best {
                None => true,
                Some(held) => {
                    supporting.len() > best_support
                        || (supporting.len() == best_support
                            && held.expires.is_some_and(|held| held < lapses))
                }
            };
            if better {
                best_support = supporting.len();
                best = Some(Rung {
                    tier: ConfidenceTier::PeerVote,
                    value: candidate.value,
                    expires: Some(lapses),
                });
            }
        }
        best
    }

    fn newest(&self, tier: ConfidenceTier) -> Option<&Entry<T>> {
        self.entries.iter().rev().find(|entry| entry.tier == tier)
    }

    /// Keep a quorum tier's memory bounded at [`OBSERVERS_REMEMBERED`],
    /// dropping the oldest first.
    fn prune(&mut self, tier: ConfidenceTier) {
        if !matches!(tier, ConfidenceTier::KadCheck | ConfidenceTier::PeerVote) {
            return;
        }
        let excess = self
            .entries
            .iter()
            .filter(|entry| entry.tier == tier)
            .count()
            .saturating_sub(OBSERVERS_REMEMBERED);
        let mut to_drop = excess;
        self.entries.retain(|entry| {
            if to_drop > 0 && entry.tier == tier {
                to_drop -= 1;
                return false;
            }
            true
        });
    }
}
