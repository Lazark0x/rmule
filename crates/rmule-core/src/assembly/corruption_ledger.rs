//! The **Corruption Ledger** (ADR-0117 §1): per file and per sender, the bytes
//! proved good and bad, as stock's black box counts them
//! (`CorruptionBlackBox.cpp:168-171`, `:191-241`). A corrupt cell charges each
//! of its writers `EMBLOCKSIZE`; a verified part credits each writer its share.
//! A sender is proven by bytes it alone wrote, and a proven sender past stock's
//! limit is convicted. It lives in memory for the run, as stock's maps do, and
//! never forgets inside one: a repeat offender runs out of good bytes to hide
//! behind.

use std::collections::HashMap;

use rmule_primitives::{EMBLOCKSIZE, PeerEndpoint};

use super::Verdict;

/// `CBB_BANTHRESHOLD`: the share of a sender's bytes, in percent, that may be
/// corrupt (`CorruptionBlackBox.cpp:38`).
const LIMIT_PERCENT: u64 = 32;

/// What the ledger holds of one sender.
#[derive(Clone, Copy, Debug, Default)]
struct Sender {
    good: u64,
    bad: u64,
    proven: bool,
}

/// One sender's count, as it is judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Standing {
    /// The bytes proved corrupt.
    pub(crate) bad: u64,
    /// The bytes proved corrupt or good.
    pub(crate) total: u64,
    proven: bool,
}

impl Standing {
    /// Whether this sender is proven and past stock's limit
    /// (`CorruptionBlackBox.cpp:207-209`).
    pub(crate) fn convicted(self) -> bool {
        self.proven && self.bad.saturating_mul(100) / self.total.max(1) > LIMIT_PERCENT
    }
}

/// The ledger of one download.
#[derive(Clone, Debug, Default)]
pub(crate) struct CorruptionLedger {
    senders: HashMap<PeerEndpoint, Sender>,
}

impl CorruptionLedger {
    /// `sender` wrote `bytes` of a verified part.
    pub(crate) fn credit(&mut self, sender: PeerEndpoint, bytes: u64) {
        self.senders.entry(sender).or_default().good += bytes;
    }

    /// What `verdict` proved is written down.
    pub(crate) fn charge(&mut self, verdict: &Verdict) {
        for (&sender, &cells) in &verdict.charged {
            let entry = self.senders.entry(sender).or_default();
            entry.bad += cells * EMBLOCKSIZE;
            entry.proven |= verdict.proven.contains(&sender);
        }
    }

    /// The bytes proved good of `sender`.
    pub(crate) fn good(&self, sender: PeerEndpoint) -> u64 {
        self.senders.get(&sender).map_or(0, |sender| sender.good)
    }

    /// `sender`'s count, with `good` more bytes a judgement has just proved.
    pub(crate) fn standing(&self, sender: PeerEndpoint, good: u64) -> Standing {
        let held = self.senders.get(&sender).copied().unwrap_or_default();
        Standing {
            bad: held.bad,
            total: held.bad + held.good + good,
            proven: held.proven,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_primitives::Ipv4Endpoint;
    use std::net::Ipv4Addr;

    fn peer(n: u8) -> PeerEndpoint {
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, n), 4662))
    }

    /// `cells` of `writers` proved corrupt, one call per cell.
    fn charged(ledger: &mut CorruptionLedger, writers: &[PeerEndpoint], cells: u32) {
        let mut verdict = Verdict::default();
        for _ in 0..cells {
            verdict.charge(writers);
        }
        ledger.charge(&verdict);
    }

    /// Stock's arithmetic, to the cell: the division truncates as
    /// `int nCorruptPercentage` does, so 33 of 101 reads 32 % and stays, and
    /// 34 of 102 reads 33 % and goes.
    #[test]
    fn a_proven_sender_is_convicted_only_past_stocks_limit() {
        let mut ledger = CorruptionLedger::default();
        charged(&mut ledger, &[peer(1)], 33);
        ledger.credit(peer(1), 68 * EMBLOCKSIZE);
        assert!(!ledger.standing(peer(1), 0).convicted());
        charged(&mut ledger, &[peer(1)], 1);
        assert!(ledger.standing(peer(1), 0).convicted());
        assert!(!ledger.standing(peer(1), 2 * EMBLOCKSIZE).convicted());
    }

    /// Stock's ratio alone would ban a writer whose only cells were shared
    /// with the bad one: with no cell of its own proved, none convicts it.
    #[test]
    fn a_writer_that_only_shared_corrupt_cells_is_never_convicted() {
        let mut ledger = CorruptionLedger::default();
        charged(&mut ledger, &[peer(1), peer(2)], 9);
        let standing = ledger.standing(peer(2), 0);
        assert_eq!(standing.bad, standing.total);
        assert!(!standing.convicted());
    }

    /// Every cell counts toward one file-wide figure, so a source below the
    /// limit that keeps sending bad cells crosses it.
    #[test]
    fn a_repeat_offender_runs_out_of_good_bytes() {
        let mut ledger = CorruptionLedger::default();
        ledger.credit(peer(1), 20 * EMBLOCKSIZE);
        charged(&mut ledger, &[peer(1)], 1);
        let mut more = 0;
        while !ledger.standing(peer(1), 0).convicted() {
            charged(&mut ledger, &[peer(1)], 1);
            more += 1;
        }
        assert_eq!(more, 9, "ten bad cells against twenty good reads 33 %");
    }
}
