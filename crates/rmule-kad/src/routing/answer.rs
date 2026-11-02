//! The routing table's judgement of a lookup-answer row it did not store
//! (ADR-0064). aMule stores each row its routing zone takes, unverified, and
//! hands its search the rows it stored or would accept
//! (`ProcessKademlia2Response`, `KademliaUDPListener.cpp:742-750`, through
//! `CRoutingZone::IsAcceptableContact`, `RoutingZone.cpp:897-916`). This is the
//! "would accept" half; the node stores a row before it asks.

use super::{KadAdmissionCap, KadContact, KadRoutingTable};

/// Why the table would not accept a lookup-answer row.
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
    /// one-per-address and ten-per-/24 caps the table holds now.
    pub(crate) fn accepts_answer_row(&self, row: &KadContact) -> Result<(), KadAnswerRefusal> {
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
        match self.admission.table_refusal(endpoint.ip()) {
            Some(cap) => Err(KadAnswerRefusal::Cap(cap)),
            None => Ok(()),
        }
    }
}
