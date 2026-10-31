//! The per-endpoint **CAPS Negotiation** rows, each with when it was last
//! touched and when its last CAPS answer left.
//!
//! The rows live inside the **Tunnel Registry**: a row an unidentified source
//! made leaves with that source's charge on the **Unidentified Allowance**
//! (ADR-0091, security rule 10), and idle rows age on the caller's tick, never
//! per frame.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rmule_peer::natt::{CapsNegotiation, HelloNattClaim};
use rmule_primitives::PeerEndpoint;

use super::keys::{KEY_FRAME_INTERVAL, LEARNED_HASH_TTL};

/// How long an endpoint's row is kept once nothing has touched it — the
/// learned-hash window, so a negotiation never outlives the key that would
/// obfuscate the tunnel it chose. Every bound the negotiation itself keeps
/// (the 1500 ms legacy window, the 120 s QUIC blacklist) is shorter, so a
/// pruned row is one that would have answered from its seed.
const NEGOTIATION_IDLE_TTL: Duration = LEARNED_HASH_TTL;

/// One endpoint's negotiation.
struct NegotiationRow {
    negotiation: CapsNegotiation,
    touched: Instant,
    answered_at: Option<Instant>,
}

/// The endpoint → negotiation table.
#[derive(Default)]
pub(super) struct NegotiationTable {
    rows: HashMap<PeerEndpoint, NegotiationRow>,
}

impl std::fmt::Debug for NegotiationTable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NegotiationTable")
            .field("rows", &self.rows.len())
            .finish()
    }
}

impl NegotiationTable {
    /// `peer`'s negotiation, seeded from `seed` when it has none, and touched.
    pub(super) fn touch(
        &mut self,
        peer: PeerEndpoint,
        seed: HelloNattClaim,
        now: Instant,
    ) -> &mut CapsNegotiation {
        let row = self.rows.entry(peer).or_insert_with(|| NegotiationRow {
            negotiation: CapsNegotiation::new(seed),
            touched: now,
            answered_at: None,
        });
        row.touched = now;
        &mut row.negotiation
    }

    /// `peer`'s negotiation, if it has one.
    pub(super) fn get(&self, peer: PeerEndpoint) -> Option<&CapsNegotiation> {
        self.rows.get(&peer).map(|row| &row.negotiation)
    }

    /// Whether a CAPS answer to `peer` is due, and record it if so: one per
    /// [`KEY_FRAME_INTERVAL`], the same bound on what a claimed address can
    /// make us emit. Only a row that exists can be due; [`Self::touch`] made
    /// it for the frame being answered.
    pub(super) fn claim_answer(&mut self, peer: PeerEndpoint, now: Instant) -> bool {
        let Some(row) = self.rows.get_mut(&peer) else {
            return false;
        };
        let due = row
            .answered_at
            .is_none_or(|at| now.saturating_duration_since(at) >= KEY_FRAME_INTERVAL);
        if due {
            row.answered_at = Some(now);
        }
        due
    }

    /// Drop `peer`'s row.
    pub(super) fn forget(&mut self, peer: PeerEndpoint) {
        self.rows.remove(&peer);
    }

    /// Drop rows idle past [`NEGOTIATION_IDLE_TTL`].
    pub(super) fn prune(&mut self, now: Instant) {
        self.rows
            .retain(|_, row| now.saturating_duration_since(row.touched) < NEGOTIATION_IDLE_TTL);
    }

    /// How many endpoints hold a row.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.rows.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_primitives::Ipv4Endpoint;

    use super::*;

    fn endpoint(last: u8) -> PeerEndpoint {
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, last), 4672))
    }

    /// A row idle past the window goes at the tick; one still in use is kept,
    /// however old it is.
    #[test]
    fn an_idle_negotiation_row_is_pruned_and_a_touched_one_is_kept() {
        let now = Instant::now();
        let mut table = NegotiationTable::default();
        for last in 1..=100 {
            table.touch(endpoint(last), HelloNattClaim::default(), now);
        }
        let later = now + NEGOTIATION_IDLE_TTL;
        table.touch(
            endpoint(1),
            HelloNattClaim::default(),
            later - Duration::from_secs(1),
        );
        table.prune(later);
        assert_eq!(table.len(), 1, "the idle rows went");
        assert!(table.get(endpoint(1)).is_some(), "the touched row stayed");
    }
}
