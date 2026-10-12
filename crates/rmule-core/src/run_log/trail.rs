//! The **Reachability Trail** (ADR-0075): the levels core holds about its own
//! reachability — the connected server and the server list's health, the port
//! mappings, the addresses Address Learning holds for us, the Kad verdicts
//! with our own buddy's state, and the NAT-T own mapping — written into the
//! Run Log as records each time one moves, in order with the events around
//! them.
//!
//! Each level is read from its one owner when that owner's change notice
//! wakes ([`sources`]), and a level's records are written only when they
//! differ from the ones last written for it: a wake that moved nothing of a
//! level writes nothing, and a level that moved writes its record once. Every
//! field is ours or the operator's own list's — an own address, a port, a
//! verdict, a server endpoint — so a level's records read the same at both
//! levels, and they are written at lean, where a field lean withholds could
//! only be dropped.

mod reach;
mod server_health;
mod sources;
#[cfg(test)]
mod tests;

use rmule_peer::natt::OwnMapping;
use rmule_primitives::ServerEndpoint;

use crate::diagnostics::{AddressDiagnostics, BuddyState, KadFirewallVerdict, KadUdpVerdict};
use crate::port_mapping::MappingDiagnostics;

use super::Record;

pub(crate) use server_health::ServerLevel;
pub(crate) use sources::{TrailSources, spawn};

/// The Kad half of the trail's Kad level: the TCP and UDP verdicts while a
/// node runs, `None` while none does.
type KadVerdicts = Option<(KadFirewallVerdict, KadUdpVerdict)>;

/// Each level's records as last written, so a level that has not moved
/// writes nothing.
#[derive(Default)]
pub(crate) struct Trail {
    server: Option<Vec<Record>>,
    mappings: Option<Vec<Record>>,
    addresses: Option<Vec<Record>>,
    kad: Option<Vec<Record>>,
    natt: Option<Vec<Record>>,
    health: server_health::HealthTrail,
}

impl Trail {
    /// The connected server's record, when it moved.
    pub(crate) fn server(&mut self, connected: Option<&ServerEndpoint>) -> Vec<Record> {
        moved(&mut self.server, vec![reach::server(connected)])
    }

    /// The port mappings' records, when one moved.
    pub(crate) fn mappings(&mut self, rows: &[MappingDiagnostics]) -> Vec<Record> {
        moved(&mut self.mappings, reach::mappings(rows))
    }

    /// The own addresses' records, when one moved.
    pub(crate) fn addresses(&mut self, rows: &[AddressDiagnostics]) -> Vec<Record> {
        moved(&mut self.addresses, reach::addresses(rows))
    }

    /// The Kad verdicts' and own buddy's record, when one moved.
    pub(crate) fn kad(&mut self, verdicts: KadVerdicts, buddy: BuddyState) -> Vec<Record> {
        moved(&mut self.kad, vec![reach::kad(verdicts, buddy)])
    }

    /// The NAT-T own mapping's record, when it moved.
    pub(crate) fn natt(&mut self, mapping: Option<OwnMapping>) -> Vec<Record> {
        moved(&mut self.natt, vec![reach::natt(mapping)])
    }

    /// The server list's health edges and moved grant words.
    pub(crate) fn server_health(&mut self, level: &ServerLevel) -> Vec<Record> {
        self.health.observe(level)
    }
}

/// `records` if they differ from `last`, which then holds them; nothing
/// otherwise.
fn moved(last: &mut Option<Vec<Record>>, records: Vec<Record>) -> Vec<Record> {
    if last.as_ref() == Some(&records) {
        return Vec::new();
    }
    *last = Some(records.clone());
    records
}
