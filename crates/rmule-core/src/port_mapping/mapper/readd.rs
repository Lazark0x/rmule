//! The **epoch re-add** (ADR-0086, RFC 6887 §8.5): a gateway that reports an
//! epoch reset has lost every mapping it held for us, so the mapper re-adds
//! the whole held set, one mapping per spacing. The answers settle as
//! renewals do, and the last one to land fires the reachability recheck.

use std::time::{Duration, Instant};

use super::{MappingCommand, PortMapper};

/// How far apart mappings are re-added after a gateway epoch reset. A router
/// that just rebooted is the worst moment to send it a burst.
const READD_SPACING: Duration = Duration::from_millis(100);

impl PortMapper {
    /// A gateway epoch reset: every mapping we hold is gone from the router,
    /// so queue them all for re-add. Idempotent while a re-add round is
    /// already running — the gateway rebooted once, and each of its answers
    /// carries the same verdict until the tracker re-anchors.
    pub(super) fn queue_readds(&mut self, now: Instant) {
        if self.leases.is_empty()
            || !self.readd_queue.is_empty()
            || !self.readd_outstanding.is_empty()
        {
            return;
        }
        self.readd_queue = self.leases.keys().copied().collect();
        self.readd_succeeded = false;
        self.next_readd_at = Some(now);
    }

    /// Emit one queued re-add per [`READD_SPACING`]. A router that just
    /// rebooted is the worst possible moment to send it a burst.
    pub(super) fn drain_readds(&mut self, now: Instant) {
        let Some(due) = self.next_readd_at else {
            return;
        };
        if now < due {
            return;
        }
        let Some(mapping) = self.readd_queue.pop_front() else {
            self.next_readd_at = None;
            return;
        };
        if let Some(lease) = self.leases.get(&mapping) {
            self.commands.push_back(MappingCommand::Map {
                protocol: lease.protocol,
                mapping,
                suggested_external_port: mapping.internal_port,
                lease: self.config.lease,
            });
            self.readd_outstanding.insert(mapping);
        }
        self.next_readd_at = if self.readd_queue.is_empty() {
            None
        } else {
            Some(now + READD_SPACING)
        };
    }
}
