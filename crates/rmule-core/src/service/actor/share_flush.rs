//! The **Share Totals** flush: the all-time serve figures of every
//! file whose counters moved, written to the Durable Store once a minute and
//! once more at Quit.
//!
//! The bound: a crash loses at most [`SHARE_FLUSH_INTERVAL`] of counting, and
//! however busy the uploads, the store sees one transaction a minute — never
//! one per block. aMule saves `known.met` every thirty minutes and at
//! shutdown (`amule-2.3.3/src/amule.cpp:1246-1249`, `:1427`); the interval is
//! tighter because one small transaction costs nothing here.

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::diagnostics::DiagnosticsState;
use crate::store::registry::DurableSharedFileRegistry;
use crate::store::share_totals::DurableShareTotals;

/// How often the moved figures are written.
pub(super) const SHARE_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// The periodic flush, running on its own task until [`ShareFlush::finish`].
pub(super) struct ShareFlush {
    flusher: Flusher,
    stop: mpsc::Sender<()>,
    periodic: JoinHandle<()>,
}

impl ShareFlush {
    /// Seed the diagnostics with the stored totals and start the periodic
    /// flush. `None` when the store cannot be read: a flush then would write
    /// this run's figures over totals it never saw, so nothing is written and
    /// the all-time figures read as this run's.
    pub(super) fn start(
        registry: &DurableSharedFileRegistry,
        diagnostics: &DiagnosticsState,
    ) -> Option<Self> {
        let seam = registry.share_totals();
        let stored = match seam.load() {
            Ok(stored) => stored,
            Err(error) => {
                tracing::warn!(%error, "share totals unreadable; all-time figures not kept this run");
                return None;
            }
        };
        diagnostics.seed_share_totals(stored);
        let flusher = Flusher {
            seam,
            diagnostics: diagnostics.clone(),
        };
        let (stop, mut stopped) = mpsc::channel::<()>(1);
        let task_flusher = flusher.clone();
        let periodic = tokio::spawn(async move {
            let mut tick = tokio::time::interval(SHARE_FLUSH_INTERVAL);
            tick.tick().await; // nothing has moved at start
            loop {
                tokio::select! {
                    _ = tick.tick() => task_flusher.flush(),
                    _ = stopped.recv() => return,
                }
            }
        });
        Some(Self {
            flusher,
            stop,
            periodic,
        })
    }

    /// Quit's flush: stop the periodic task, wait for it — so no flush of
    /// older figures can land after this one — then write what moved since.
    pub(super) async fn finish(self) {
        drop(self.stop);
        let _ = self.periodic.await;
        self.flusher.flush();
    }
}

/// One flush: every moved file's all-time figures, in one transaction.
#[derive(Clone)]
struct Flusher {
    seam: DurableShareTotals,
    diagnostics: DiagnosticsState,
}

impl Flusher {
    fn flush(&self) {
        let moved = self.diagnostics.take_share_flush();
        if let Err(error) = self.seam.record(&moved) {
            tracing::warn!(%error, files = moved.len(), "share totals flush failed; retried next time");
            self.diagnostics
                .restore_share_flush(moved.into_iter().map(|(file_hash, _)| file_hash));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use rmule_primitives::{FileHash, Ipv4Endpoint, PeerEndpoint};

    use super::*;
    use crate::diagnostics::ShareTotals;
    use crate::store::open_durable_store;

    const BLOCK: u64 = 10_240;

    fn peer() -> PeerEndpoint {
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 4662))
    }

    /// A busy upload writes nothing until the interval is up, then its whole
    /// count in one flush — a crash in between loses at most that interval.
    #[tokio::test(start_paused = true)]
    async fn a_busy_upload_is_flushed_once_an_interval_not_per_block() {
        let dir = tempfile::tempdir().unwrap();
        let registry = DurableSharedFileRegistry::new(open_durable_store(dir.path()).unwrap());
        let diagnostics = DiagnosticsState::new();
        let _flush = ShareFlush::start(&registry, &diagnostics).expect("the store reads");
        let file = FileHash::from_bytes([3; 16]);
        diagnostics.count_upload_request(file);
        diagnostics.count_upload_accept(file);
        for _ in 0..1_000 {
            diagnostics.add_sent_bytes(peer(), file, BLOCK);
        }

        tokio::time::sleep(SHARE_FLUSH_INTERVAL - Duration::from_secs(1)).await;
        assert!(
            registry.share_totals().load().unwrap().is_empty(),
            "nothing is written inside the interval"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        // Let the periodic task run the tick it just woke for.
        tokio::task::yield_now().await;
        assert_eq!(
            registry.share_totals().load().unwrap().get(&file).copied(),
            Some(ShareTotals {
                requests: 1,
                accepted: 1,
                transferred: 1_000 * BLOCK,
            })
        );
    }

    /// What a run counted is there after a restart, as the all-time figure,
    /// and the next run counts on top of it.
    #[tokio::test]
    async fn the_all_time_figures_outlive_a_restart_and_keep_counting() {
        let dir = tempfile::tempdir().unwrap();
        let file = FileHash::from_bytes([4; 16]);
        let start_run = || {
            let registry = DurableSharedFileRegistry::new(open_durable_store(dir.path()).unwrap());
            let diagnostics = DiagnosticsState::new();
            let flush = ShareFlush::start(&registry, &diagnostics).expect("the store reads");
            (diagnostics, flush)
        };
        {
            let (diagnostics, flush) = start_run();
            diagnostics.count_upload_request(file);
            diagnostics.add_sent_bytes(peer(), file, BLOCK);
            flush.finish().await;
        }
        let (diagnostics, _flush) = start_run();
        let before = diagnostics.snapshot().shared_files[&file];
        assert_eq!((before.requests, before.transferred), (0, 0), "a new run");
        assert_eq!(
            before.all_time,
            ShareTotals {
                requests: 1,
                accepted: 0,
                transferred: BLOCK,
            }
        );
        diagnostics.count_upload_request(file);
        assert_eq!(
            diagnostics.snapshot().shared_files[&file].all_time.requests,
            2
        );
    }

    /// A file whose read failed mid-minute is withheld and its peer released
    /// (ADR-0106, "The registry against the disk"): what was counted before
    /// stays counted, is written once at the interval, and a later flush with
    /// nothing moved writes it again neither doubled nor dropped. The totals
    /// are keyed by the file's hash, not by the offer.
    #[tokio::test(start_paused = true)]
    async fn a_file_withheld_mid_minute_is_flushed_once_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let registry = DurableSharedFileRegistry::new(open_durable_store(dir.path()).unwrap());
        let diagnostics = DiagnosticsState::new();
        let _flush = ShareFlush::start(&registry, &diagnostics).expect("the store reads");
        let file = FileHash::from_bytes([5; 16]);
        diagnostics.count_upload_request(file);
        diagnostics.count_upload_accept(file);
        diagnostics.add_sent_bytes(peer(), file, BLOCK);
        // The read fails: the slot is released, and the file leaves the offer.
        diagnostics.close_upload(peer());
        // A second asker is told the file is not here: its request counts.
        diagnostics.count_upload_request(file);

        let expected = ShareTotals {
            requests: 2,
            accepted: 1,
            transferred: BLOCK,
        };
        for _ in 0..2 {
            tokio::time::sleep(SHARE_FLUSH_INTERVAL + Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
            assert_eq!(
                registry.share_totals().load().unwrap().get(&file).copied(),
                Some(expected),
            );
        }
        assert_eq!(
            diagnostics.snapshot().shared_files[&file].all_time,
            expected
        );
    }
}
