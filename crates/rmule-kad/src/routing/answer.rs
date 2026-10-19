//! The routing table's judgement of a lookup answer's rows (ADR-0064): a walk
//! dials a row only when the table would take it. aMule passes a returned
//! contact to its search only when the routing zone stored it or would accept
//! it (`ProcessKademlia2Response`, `KademliaUDPListener.cpp:741-750`, through
//! `CRoutingZone::IsAcceptableContact`, `RoutingZone.cpp:897-916`). rmule's
//! walk stores no answer row, so the rows an answer has already let through
//! count against the next as if stored: one answer cannot hand a walk more
//! rows of one address or one /24 than the table would hold.

use super::caps::AdmissionTally;
use super::{KadAdmissionCap, KadContact, KadRoutingTable};

/// The rows of one lookup answer let through so far, counted by address and
/// by /24 as stored contacts are. One per answer, judged in row order.
#[derive(Debug, Default)]
pub(crate) struct KadAnswerTally(AdmissionTally);

/// Why the table would not take a lookup-answer row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KadAnswerRefusal {
    /// The row speaks Kad version 1 or older.
    Kad1,
    /// The table holds the row's ID at another UDP port, or verified at
    /// another IP.
    ContradictsStored,
    /// The row would break a table-wide admission cap.
    Cap(KadAdmissionCap),
}

impl KadRoutingTable {
    /// Judge one lookup-answer row as aMule's `IsAcceptableContact` does: a
    /// Kad1 row never; a row naming a stored ID only at that contact's UDP
    /// port, and at its IP once it is verified; any other row only within the
    /// one-per-address and ten-per-/24 caps, counting the table and `passed`.
    /// A row let through by the caps is added to `passed`.
    pub(crate) fn judge_answer_row(
        &self,
        passed: &mut KadAnswerTally,
        row: &KadContact,
    ) -> Result<(), KadAnswerRefusal> {
        if row.version() <= 1 {
            return Err(KadAnswerRefusal::Kad1);
        }
        let endpoint = row.endpoint();
        if let Some(stored) = self.get(row.id()) {
            let moved_verified = stored.verified() && stored.endpoint().ip() != endpoint.ip();
            if moved_verified || stored.endpoint().udp_port() != endpoint.udp_port() {
                return Err(KadAnswerRefusal::ContradictsStored);
            }
            return Ok(());
        }
        if let Some(cap) = self.admission.answer_refusal(&passed.0, endpoint.ip()) {
            return Err(KadAnswerRefusal::Cap(cap));
        }
        passed.0.count(endpoint.ip());
        Ok(())
    }
}
