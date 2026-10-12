//! Transfer-rate synthesis (ADR-0069 §Dataflow): core exposes byte *levels* —
//! monotonic byte counters (ADR-0077) plus the per-worker `bytes_received` a
//! receiving slot carries — and never a rate. The bridge differences those
//! levels across data ticks and smooths each with a time-aware EMA. Pure and
//! explicit-time (`KadNode` discipline): [`RateSynthesizer::observe`] takes
//! `now`, nothing here reads a clock.
//!
//! # Which level feeds which meter
//!
//! | meter | differenced from | why that level |
//! |---|---|---|
//! | [`TransferRates::down_total_bps`] / [`TransferRates::up_total_bps`] | `SessionCounters` | process-lifetime and independent of row lifetime, so bytes that land while a transfer is tearing down still register. Summing the per-row averages instead would lose them, and would lag the rows' own smoothing by a second layer of EMA. |
//! | [`TransferRates::download_bps`] | `DownloadDiagnostics::received_bytes` | one monotonic total per download, counting every worker. The per-slot levels below deliberately under-count each part's tail, which is fine for a per-peer meter and wrong for the download's own. |
//! | [`TransferRates::download_avg_bps`] | `DownloadDiagnostics::received_bytes` | the same total over a plain [`ETA_WINDOW`] window rather than an EMA (ADR-0071, "Download ETA"): an estimate of hours must not swing on one slow second, which a meter tuned to answer within seconds does. |
//! | [`TransferRates::upload_bps`] | `UploadDiagnostics::bytes_sent` | one monotonic total per peer holding an upload slot; the row retires with the slot, and so does its meter. |
//! | [`TransferRates::source_bps`] | `WorkerPhase::ReceivingPart::bytes_received` | the only per-peer *download* signal core has. It restarts at every part, so its meter treats a rollover as "the bytes now in the new part" rather than a negative swing. |
//! | [`TransferRates::kad`] | `KadRuntimeDiagnostics::traffic` | the Kad node's wire bytes and datagrams, each way. Both ride the snapshot like every other level, so their meters difference tick to tick; a node that stops takes its meters with it. |
//!
//! # Session totals are not copied here
//!
//! Rates are derived at the edge; the totals they are derived *from* are core
//! facts and stay where core put them. A consumer wanting lifetime bytes (the
//! Statistics view) reads `UiState::diagnostics.session` — one hop, one copy,
//! nothing that can drift out of step with the meters above.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use rmule_core::DownloadId;
use rmule_core::diagnostics::{
    DiagnosticsSnapshot, KadRuntimeDiagnostics, WorkerPhase, WorkerSlot,
};
use rmule_primitives::PeerEndpoint;

/// Smoothed rates for one data tick, served alongside the snapshot.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TransferRates {
    /// Per-download receive rate, bytes/sec — the Transfers **Speed** column.
    pub download_bps: BTreeMap<DownloadId, f64>,
    /// Per-download receive rate averaged over the last [`ETA_WINDOW`],
    /// bytes/sec — what the Transfers **ETA** divides by. No entry until the
    /// download's run has one measured interval; 0 once its Speed meter
    /// reads a stall.
    pub download_avg_bps: BTreeMap<DownloadId, f64>,
    /// Per-worker-slot receive rate, bytes/sec — the sources pane's per-peer
    /// **Speed**. Keyed by slot rather than by peer: the slot is the identity
    /// a download's diagnostics are indexed by, and one peer may hold slots in
    /// several downloads at once.
    pub source_bps: BTreeMap<(DownloadId, WorkerSlot), f64>,
    /// Per-peer send rate, bytes/sec — the Shared view's upload-peers
    /// **Speed**. A peer with no upload slot has no entry, so the view renders
    /// an honest `—` rather than a zero it did not measure.
    pub upload_bps: BTreeMap<PeerEndpoint, f64>,
    /// Every byte arriving from peers, bytes/sec — the status bar's ▼.
    pub down_total_bps: f64,
    /// Every byte served to peers, bytes/sec — the status bar's ▲.
    pub up_total_bps: f64,
    /// The Kad node's wire rates, `None` while no node runs — the Kad panel's
    /// Received and Sent rows.
    pub kad: Option<KadRates>,
}

/// The Kad node's traffic rates, each way: wire bytes/sec, and datagrams/sec
/// by the same means — differenced echo to echo, since datagram
/// counts ride the same slower cadence as the bytes they came with.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct KadRates {
    /// Wire bytes the demux handed the node.
    pub in_bps: f64,
    /// Wire bytes the node sent.
    pub out_bps: f64,
    /// Datagrams the demux handed the node.
    pub dgrams_in_bps: f64,
    /// Datagrams the node wrote to the bind.
    pub dgrams_out_bps: f64,
}

/// How far back the ETA's averaged speed reaches (ADR-0071, "Download ETA").
pub const ETA_WINDOW: Duration = Duration::from_secs(60);

/// A monotonic counter's readings over the last [`ETA_WINDOW`], plus the one
/// reading at or before the window's start, so the average spans the whole
/// window once the run is that old, and the whole run until then.
struct Window {
    readings: VecDeque<(Instant, u64)>,
}

impl Window {
    fn started(level: u64, at: Instant) -> Self {
        Self {
            readings: VecDeque::from([(at, level)]),
        }
    }

    /// Fold a reading and return the bytes per second across the window, or
    /// `None` while no interval has passed. A reading no later than the last
    /// one folds nothing, as in [`Meter::advance`].
    fn observe(&mut self, level: u64, now: Instant, window: Duration) -> Option<f64> {
        if self.readings.back().is_none_or(|(at, _)| now > *at) {
            self.readings.push_back((now, level));
        }
        let start = now.checked_sub(window);
        while let (Some(start), Some((second, _))) = (start, self.readings.get(1)) {
            if *second > start {
                break;
            }
            self.readings.pop_front();
        }
        let (first_at, first_level) = *self.readings.front()?;
        let (last_at, last_level) = *self.readings.back()?;
        let span = last_at.saturating_duration_since(first_at);
        (span > Duration::ZERO)
            .then(|| last_level.saturating_sub(first_level) as f64 / span.as_secs_f64())
    }
}

/// One tracked byte counter: the level last read, the instant it was read at,
/// the time-aware exponential average of its deltas, and the last instant the
/// counter moved.
///
/// An average fed zeros only approaches zero, so a counter that stopped would
/// read a fading rate for many time constants. A meter whose counter has not
/// moved for a whole time constant reads 0 outright (ADR-0071, "Download ETA").
#[derive(Clone, Copy)]
struct Meter {
    level: u64,
    bps: f64,
    at: Instant,
    moved_at: Instant,
}

impl Meter {
    /// A first sighting: remembers the level, reports nothing. No interval
    /// exists yet, so any rate would be invented.
    fn started(level: u64, at: Instant) -> Self {
        Self {
            level,
            bps: 0.0,
            at,
            moved_at: at,
        }
    }

    /// Whether the counter stood still for the whole last time constant.
    fn stalled(&self, now: Instant, tau: Duration) -> bool {
        now.saturating_duration_since(self.moved_at) >= tau
    }

    /// Fold a monotonic counter's new reading. Levels never go backwards
    /// (ADR-0077), so `saturating_sub` reports zero rather than a negative
    /// rate if one ever appears to.
    fn observe(&mut self, level: u64, now: Instant, tau: Duration) -> f64 {
        self.advance(level.saturating_sub(self.level), level, now, tau)
    }

    /// Fold an interval the counter did not move through: the average decays
    /// toward zero without forgetting where the level stood.
    fn idle(&mut self, now: Instant, tau: Duration) -> f64 {
        let level = self.level;
        self.advance(0, level, now, tau)
    }

    /// Fold `delta` bytes moved since the last read, and remember `level` as
    /// the new reading. A zero-length interval folds *nothing* — not even the
    /// level — so two reads at the same instant cannot lose the bytes between
    /// this read and the next one.
    fn advance(&mut self, delta: u64, level: u64, now: Instant, tau: Duration) -> f64 {
        let dt = now.saturating_duration_since(self.at);
        if dt > Duration::ZERO {
            let instantaneous = delta as f64 / dt.as_secs_f64();
            let alpha = 1.0 - (-dt.as_secs_f64() / tau.as_secs_f64()).exp();
            self.bps += alpha * (instantaneous - self.bps);
            self.level = level;
            self.at = now;
            if delta > 0 {
                self.moved_at = now;
            }
            if self.stalled(now, tau) {
                self.bps = 0.0;
            }
        }
        self.bps
    }
}

/// A worker slot's meter, plus the part its remembered level belongs to. The
/// level restarts at every part, so the part is what tells a rollover apart
/// from a stall.
struct SlotMeter {
    part_index: u32,
    meter: Meter,
}

impl SlotMeter {
    fn started(part_index: u32, bytes_received: u64, at: Instant) -> Self {
        Self {
            part_index,
            meter: Meter::started(bytes_received, at),
        }
    }

    /// Fold this slot's level. A slot filling a part it was not filling last
    /// tick restarted its count, so the bytes it holds now *are* the bytes it
    /// moved — never a negative swing, never a whole-part spike.
    fn observe(
        &mut self,
        part_index: u32,
        bytes_received: u64,
        now: Instant,
        tau: Duration,
    ) -> f64 {
        // A zero-length interval folds nothing ([`Meter::advance`]), so the
        // remembered part must not move either.
        if now <= self.meter.at {
            return self.meter.bps;
        }
        let delta = if self.part_index == part_index {
            bytes_received.saturating_sub(self.meter.level)
        } else {
            bytes_received
        };
        self.part_index = part_index;
        self.meter.advance(delta, bytes_received, now, tau)
    }
}

/// One download's meters: its own receive total, plus a meter per worker slot.
struct DownloadTracker {
    received: Meter,
    window: Window,
    slots: BTreeMap<WorkerSlot, SlotMeter>,
}

impl DownloadTracker {
    fn started(received_bytes: u64, at: Instant) -> Self {
        Self {
            received: Meter::started(received_bytes, at),
            window: Window::started(received_bytes, at),
            slots: BTreeMap::new(),
        }
    }
}

/// The two process-lifetime meters behind the status bar's ▼/▲.
struct SessionMeters {
    down: Meter,
    up: Meter,
}

/// Differencing + EMA state across ticks. Owned by the bridge task; tests
/// drive it directly with explicit instants.
pub struct RateSynthesizer {
    tau: Duration,
    downloads: BTreeMap<DownloadId, DownloadTracker>,
    uploads: BTreeMap<PeerEndpoint, Meter>,
    /// `None` until the first snapshot names the session's starting totals —
    /// a bridge attached to a core that has already moved bytes must meter
    /// what happens *next*, not report the backlog as one tick's worth.
    session: Option<SessionMeters>,
    /// The Kad byte meters, `None` while no node runs.
    kad: Option<SessionMeters>,
    /// The Kad datagram-count meters.
    kad_dgrams: Option<SessionMeters>,
}

impl RateSynthesizer {
    /// `tau` is the EMA time constant (spec band 3–5 s): after a step change
    /// the smoothed rate covers ~63% of the gap per `tau` elapsed.
    #[must_use]
    pub fn new(tau: Duration) -> Self {
        debug_assert!(tau > Duration::ZERO, "EMA time constant must be positive");
        Self {
            tau,
            downloads: BTreeMap::new(),
            uploads: BTreeMap::new(),
            session: None,
            kad: None,
            kad_dgrams: None,
        }
    }

    /// Fold the snapshot's Kad traffic totals, observed at `echoed_at`. A node
    /// that is gone drops its meters, so a restarted one starts fresh; a
    /// first sighting reports zero, as every meter does.
    fn observe_kad(
        &mut self,
        kad: Option<&KadRuntimeDiagnostics>,
        echoed_at: Instant,
    ) -> Option<KadRates> {
        let Some(traffic) = kad.map(|kad| kad.traffic) else {
            self.kad = None;
            self.kad_dgrams = None;
            return None;
        };
        let tau = self.tau;
        let bytes = self.kad.get_or_insert_with(|| SessionMeters {
            down: Meter::started(traffic.bytes_in, echoed_at),
            up: Meter::started(traffic.bytes_out, echoed_at),
        });
        let dgrams = self.kad_dgrams.get_or_insert_with(|| SessionMeters {
            down: Meter::started(traffic.datagrams_in, echoed_at),
            up: Meter::started(traffic.datagrams_out, echoed_at),
        });
        Some(KadRates {
            in_bps: bytes.down.observe(traffic.bytes_in, echoed_at, tau),
            out_bps: bytes.up.observe(traffic.bytes_out, echoed_at, tau),
            dgrams_in_bps: dgrams.down.observe(traffic.datagrams_in, echoed_at, tau),
            dgrams_out_bps: dgrams.up.observe(traffic.datagrams_out, echoed_at, tau),
        })
    }

    /// Fold one snapshot observed at `now` into the meters and return the
    /// smoothed rates. Any row's first observation reports 0 (no interval
    /// exists yet); a row absent from `snapshot` loses its meter, so a later
    /// re-add starts fresh instead of differencing against a stale level.
    pub fn observe(&mut self, snapshot: &DiagnosticsSnapshot, now: Instant) -> TransferRates {
        let tau = self.tau;
        self.downloads
            .retain(|id, _| snapshot.downloads.contains_key(id));
        self.uploads
            .retain(|peer, _| snapshot.uploads.contains_key(peer));

        let mut rates = TransferRates::default();

        for (id, diag) in &snapshot.downloads {
            let tracker = self
                .downloads
                .entry(*id)
                .or_insert_with(|| DownloadTracker::started(diag.received_bytes, now));
            let bps = tracker.received.observe(diag.received_bytes, now, tau);
            rates.download_bps.insert(*id, bps);
            if let Some(avg) = tracker.window.observe(diag.received_bytes, now, ETA_WINDOW) {
                // A run that stopped estimates nothing: the window's bytes
                // draining out over a minute would read as an ETA that grows.
                let stalled = tracker.received.stalled(now, tau);
                rates
                    .download_avg_bps
                    .insert(*id, if stalled { 0.0 } else { avg });
            }

            tracker
                .slots
                .retain(|slot, _| diag.workers.contains_key(slot));
            for (slot, worker) in &diag.workers {
                let bps = match *worker.phase() {
                    WorkerPhase::ReceivingPart {
                        part_index,
                        bytes_received,
                    } => match tracker.slots.get_mut(slot) {
                        Some(meter) => meter.observe(part_index, bytes_received, now, tau),
                        None => {
                            tracker
                                .slots
                                .insert(*slot, SlotMeter::started(part_index, bytes_received, now));
                            0.0
                        }
                    },
                    // Off the wire this tick. A rate that stopped is a falling
                    // rate, not a missing one, so the meter decays in place —
                    // and a slot that never received has nothing to report.
                    _ => match tracker.slots.get_mut(slot) {
                        Some(meter) => meter.meter.idle(now, tau),
                        None => continue,
                    },
                };
                rates.source_bps.insert((*id, *slot), bps);
            }
        }

        for (peer, upload) in &snapshot.uploads {
            let meter = self
                .uploads
                .entry(*peer)
                .or_insert_with(|| Meter::started(upload.bytes_sent, now));
            let bps = meter.observe(upload.bytes_sent, now, tau);
            rates.upload_bps.insert(*peer, bps);
        }

        let session = self.session.get_or_insert_with(|| SessionMeters {
            down: Meter::started(snapshot.session.down_bytes_total, now),
            up: Meter::started(snapshot.session.up_bytes_total, now),
        });
        rates.down_total_bps = session
            .down
            .observe(snapshot.session.down_bytes_total, now, tau);
        rates.up_total_bps = session
            .up
            .observe(snapshot.session.up_bytes_total, now, tau);
        rates.kad = self.observe_kad(snapshot.kad.as_ref(), now);

        rates
    }
}

/// Bytes/sec → the rate text every meter renders: the status bar's ▼/▲, the
/// downloads **Speed** column, the sources pane, the upload-peers pane. One
/// definition, so no two meters can disagree about unit or precision.
#[must_use]
pub fn format_rate(bps: f64) -> String {
    format!("{:.1} KB/s", bps / 1024.0)
}

#[cfg(test)]
mod tests;
