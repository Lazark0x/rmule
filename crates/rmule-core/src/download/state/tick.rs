//! The brain's clock-in (ADR-0026): the runner hands it `now` at the instant
//! [`DownloadState::next_wake`] named, and [`DownloadState::on_tick`] runs what
//! has fallen due by then — the spent endpoints' period turn (ADR-0090), the
//! **Hash-Set Deadline** (ADR-0026), the callback roads' deadlines earliest
//! first (ADR-0039, ADR-0091), the purges, the reask sweep over every
//! queue standing (ADR-0057), and a fill the **Connection Budget** refused
//! once its Dial Window turns (ADR-0116). Each sits on the record or block it governs, so a road or a
//! standing that ends by any route takes its clock with it.

use std::time::Instant;

use super::{Decision, DownloadState};
use crate::download::source_book::{PurgeKind, Purged};
use crate::service::{DownloadEvent, PurgedSource, SourcePurgeReason};

impl DownloadState {
    /// Run everything due at `now`.
    pub(crate) fn on_tick(&mut self, now: Instant) -> Vec<Decision> {
        self.sources.turn_spent(now);
        self.sources.clean_up_asks(now);
        let mut out = Vec::new();
        self.hash_set_deadline(now, &mut out);
        while let Some((key, deadline)) = self.sources.take_due_deadline(now) {
            out.extend(self.expire(now, key, deadline));
        }
        // aMule purges before it reasks the same source (stock 2.3.3
        // `PartFile.cpp:1406-1463`).
        if let Some((kind, purged)) = self
            .sources
            .purge(now, &self.callback_capability, self.dial)
        {
            out.push(Decision::Emit(DownloadEvent::SourcePurged {
                download_id: self.download_id,
                source: match purged {
                    Purged::Endpoint(peer) => PurgedSource::Endpoint(peer),
                    Purged::LowId(key) => PurgedSource::LowId {
                        low_id: key.low_id,
                        server: key.server,
                    },
                },
                reason: match kind {
                    PurgeKind::LowToLow => SourcePurgeReason::LowToLow,
                    PurgeKind::NoNeededParts => SourcePurgeReason::NoNeededParts,
                    PurgeKind::QueueFull => SourcePurgeReason::QueueFull,
                },
            }));
        }
        // aMule asks no queued source while connected to no network (stock
        // 2.3.3 `PartFile.cpp:1460`, `:1475`); the capability sample that
        // connects us runs the sweep.
        if self.callback_capability.connected() {
            self.reask_sweep(now, &mut out);
        }
        if self.started && self.budget_wake.is_some_and(|turn| turn <= now) {
            self.budget_wake = None;
            self.fill(now, &mut out);
        }
        out
    }

    /// The earliest instant anything the brain holds falls due, for the runner
    /// to sleep until; `None` while nothing is timed.
    pub(crate) fn next_wake(&self) -> Option<Instant> {
        [
            self.sources.next_spent_turn(),
            self.sources.next_asks_cleanup(),
            self.slot_asks.next_deadline(),
            self.sources.next_deadline(),
            self.callback_capability
                .connected()
                .then(|| self.sources.next_reask(self.reask_gates()))
                .flatten(),
            self.sources
                .next_purge(&self.callback_capability, self.dial),
            self.budget_wake,
        ]
        .into_iter()
        .flatten()
        .min()
    }
}
