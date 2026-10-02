//! A watch that fails while running (ADR-0100, "A watch that fails while
//! running is re-established"): a failure about one path leaves the rest
//! watched; a lost watch is re-established on the starter's clock, the whole
//! directory is examined once it is back, and the outage is told once.

use super::*;
use crate::directory_scan::watch::REWATCH_DELAYS;

/// The `attempt`th start's refusal, told apart from the others by its OS
/// error number.
fn refused(attempt: usize) -> WatchFault {
    WatchFault::Io {
        kind: io::ErrorKind::Other,
        os_code: i32::try_from(attempt).ok(),
    }
}

fn count(harness: &Harness, wanted: impl Fn(&ScanReport) -> bool) -> usize {
    harness
        .reports
        .borrow()
        .iter()
        .filter(|(_, report)| wanted(report))
        .count()
}

fn path_failed(path: &str) -> WatchSignal {
    WatchSignal::PathFailed {
        path: PathBuf::from(path),
        reason: WatchFault::Limit,
    }
}

#[test]
fn a_watch_error_about_one_path_leaves_the_rest_watched() {
    let harness = Harness::new(World::new(), Vec::new());
    let watch = harness.watch(
        vec![
            step(ms(1_000), |dir| {
                dir.dir("/dl/sub");
                dir.file("/dl/sub/inside.bin", b"inside", 2);
                vec![moved("/dl/sub"), path_failed("/dl/sub")]
            }),
            step(ms(2_000), |_| vec![path_failed("/dl/sub")]),
            step(ms(3_000), |dir| {
                dir.file("/dl/later.bin", b"later", 3);
                vec![moved("/dl/later.bin")]
            }),
        ],
        ms(20_000),
    );
    let mut watch = Some(Box::new(watch) as Box<dyn DirectoryWatch>);
    let mut starts = 0;
    let end = scan(&harness, Consent::Given, || {
        starts += 1;
        Ok(watch.take().expect("one start"))
    });
    assert_eq!(end, ScanEnd::Stopped, "the watch was never lost");
    assert_eq!(starts, 1);
    let mut shared: Vec<PathBuf> = harness.shares().into_iter().map(|(_, e)| e.path).collect();
    shared.sort();
    assert_eq!(
        shared,
        [
            PathBuf::from("/dl/later.bin"),
            PathBuf::from("/dl/sub/inside.bin")
        ]
    );
    assert_eq!(
        count(
            &harness,
            |report| matches!(report, ScanReport::PathUnwatched { path, .. } if path == Path::new("/dl/sub"))
        ),
        1,
        "told once per path"
    );
    assert_eq!(
        count(&harness, |report| matches!(
            report,
            ScanReport::WatchInterrupted(_)
        )),
        0
    );
}

#[test]
fn a_lost_watch_is_re_established_and_what_changed_meanwhile_is_found() {
    let harness = Harness::new(World::new(), Vec::new());
    let first = harness.watch(
        vec![step(ms(1_000), |_| {
            vec![WatchSignal::Failed(WatchFault::Stopped)]
        })],
        ms(60_000),
    );
    let mut first = Some(Box::new(first) as Box<dyn DirectoryWatch>);
    let mut starts = 0;
    let mut phase_at_second_start = None;
    let end = scan(&harness, Consent::Given, || {
        starts += 1;
        match starts {
            1 => Ok(first.take().unwrap()),
            2 => {
                phase_at_second_start = harness.progress.lock().unwrap().clone().map(|d| d.phase);
                // A file arrives while nothing watches: no event will say so.
                harness
                    .world
                    .with(|dir| dir.file("/dl/during.bin", b"during", 5));
                Err(WatchFault::Backend)
            }
            _ => Ok(Box::new(harness.watch(Vec::new(), ms(60_000)))),
        }
    });
    assert_eq!(end, ScanEnd::Stopped);
    assert_eq!(starts, 3);
    assert_eq!(
        phase_at_second_start,
        Some(ScanPhase::Rewatching {
            reason: WatchFault::Stopped,
            attempt: 1
        })
    );
    let shares = harness.shares();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].1.path, PathBuf::from("/dl/during.bin"));
    // Lost at 1 s; tried at 2 s and 7 s; examined and still five seconds on.
    let back = ms(1_000) + REWATCH_DELAYS[0] + REWATCH_DELAYS[1];
    assert!(shares[0].0 >= back, "shared at {:?}", shares[0].0);
    assert_eq!(
        count(&harness, |report| matches!(
            report,
            ScanReport::WatchInterrupted(_)
        )),
        1,
        "the outage is told once, not once per attempt"
    );
    assert_eq!(
        count(&harness, |report| matches!(
            report,
            ScanReport::WatchRestored
        )),
        1
    );
}

#[test]
fn a_watch_that_never_comes_back_ends_unwatched_after_the_last_attempt() {
    let harness = Harness::new(World::new(), Vec::new());
    let first = harness.watch(
        vec![step(ms(1_000), |_| {
            vec![WatchSignal::Failed(WatchFault::Stopped)]
        })],
        ms(3_600_000),
    );
    let mut first = Some(Box::new(first) as Box<dyn DirectoryWatch>);
    let mut starts = 0;
    let end = scan(&harness, Consent::Given, || {
        starts += 1;
        match first.take() {
            Some(watch) => Ok(watch),
            None => Err(refused(starts)),
        }
    });
    assert_eq!(end, ScanEnd::Unwatched(refused(1 + REWATCH_DELAYS.len())));
    assert_eq!(starts, 1 + REWATCH_DELAYS.len());
    let outage: Duration = REWATCH_DELAYS.iter().sum();
    assert_eq!(
        ms(harness.elapsed.load(Ordering::SeqCst)),
        ms(1_000) + outage
    );
    assert_eq!(
        count(&harness, |report| matches!(
            report,
            ScanReport::WatchInterrupted(_)
        )),
        1
    );
    assert_eq!(
        count(&harness, |report| matches!(
            report,
            ScanReport::WatchRestored
        )),
        0
    );
}
