//! A watch that fails while running (ADR-0100, "A watch that fails while
//! running is re-established"): the lost watch is dropped, a new one is asked
//! for a bounded number of times on the starter's clock, and the first round
//! of the new watch examines the whole directory, because events were lost
//! meanwhile. The operator is told once when the watch is lost and once when
//! it is back; if it never comes back the scan ends unwatched.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::super::{ProgressCell, ScanPhase, ScanReport, set_phase};
use super::{DirectoryWatch, TICK, WatchFault};

/// When each re-establishment is tried, counted from the one before: five
/// attempts over some twelve minutes. A watch lost to a passing cause (a
/// volume remounted, a backend restarted) is back within seconds; one lost for
/// good stops costing anything after the last.
pub(crate) const REWATCH_DELAYS: [Duration; 5] = [
    Duration::from_secs(1),
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(120),
    Duration::from_secs(600),
];

/// Where a scan gets a watch, and its clock while it has none.
pub(crate) trait WatchStarter {
    /// Start watching `root` and everything under it, or say why not.
    ///
    /// # Errors
    /// Why the watch could not start.
    fn start(&mut self, root: &Path) -> Result<Box<dyn DirectoryWatch>, WatchFault>;

    /// Let `max` pass with nothing watched. The only wait of an outage, so a
    /// test moves its clock without sleeping.
    fn pause(&mut self, max: Duration);
}

/// How an outage ended.
pub(crate) enum Rewatch {
    /// A new watch runs.
    Back(Box<dyn DirectoryWatch>),
    /// The stop flag was raised during the outage.
    Stopped,
    /// Every attempt failed; the last one's reason.
    GaveUp(WatchFault),
}

/// The watch over `root` was lost for `reason`: tell the operator, then try
/// [`REWATCH_DELAYS`] until a new watch starts, the stop flag is raised, or
/// every attempt has failed.
pub(crate) fn rewatch(
    starter: &mut dyn WatchStarter,
    root: &Path,
    reason: WatchFault,
    stop: &AtomicBool,
    progress: &ProgressCell,
    report: &mut dyn FnMut(ScanReport),
) -> Rewatch {
    tracing::warn!(dir = %root.display(), ?reason, "download directory watch lost; re-establishing");
    report(ScanReport::WatchInterrupted(reason));
    let mut last = reason;
    for (attempt, delay) in (1..).zip(REWATCH_DELAYS) {
        set_phase(
            progress,
            root,
            ScanPhase::Rewatching {
                reason: last,
                attempt,
            },
        );
        if !pause(starter, delay, stop) {
            return Rewatch::Stopped;
        }
        match starter.start(root) {
            Ok(watch) => {
                tracing::info!(dir = %root.display(), attempt, "download directory watched again");
                report(ScanReport::WatchRestored);
                return Rewatch::Back(watch);
            }
            Err(reason) => last = reason,
        }
    }
    Rewatch::GaveUp(last)
}

/// Let `delay` pass in slices, so a raised stop flag is seen within one
/// [`TICK`]. False when it was.
pub(crate) fn pause(starter: &mut dyn WatchStarter, delay: Duration, stop: &AtomicBool) -> bool {
    let mut waited = Duration::ZERO;
    while waited < delay {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        let slice = (delay - waited).min(TICK);
        starter.pause(slice);
        waited += slice;
    }
    !stop.load(Ordering::Relaxed)
}
