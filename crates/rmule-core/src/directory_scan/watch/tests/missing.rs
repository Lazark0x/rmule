//! A shared directory that is not there (ADR-0101, "Shared Directories"):
//! waited for at start and passed over unread once it is back, and found
//! gone while watched without a single row joining the Had Set.

use super::*;

fn missing_reports(harness: &Harness) -> Vec<ScanReport> {
    harness
        .reports
        .borrow()
        .iter()
        .map(|(_, report)| report.clone())
        .filter(|report| {
            matches!(
                report,
                ScanReport::RootMissing { .. }
                    | ScanReport::RootReturned
                    | ScanReport::Finished(_)
                    | ScanReport::Gone { .. }
                    | ScanReport::Unshare(_)
                    | ScanReport::Held { .. }
            )
        })
        .collect()
}

#[test]
fn a_directory_missing_at_start_is_waited_for_and_passed_over_unread_once_back() {
    let world = World::new();
    let stamp = world.with(|dir| dir.file("/dl/film.mkv", b"film bytes", 7));
    let mut shared = row("/dl/film.mkv", stamp, 0);
    shared.file_hash = hash_of(b"film bytes");
    world.with(|dir| dir.remove(ROOT));
    let harness = Harness::new(world, vec![shared]);
    // A minute and a half in, the volume is back as it was.
    *harness.on_pause.borrow_mut() = Some((
        ms(90_000),
        Box::new(|dir: &mut Scripted| {
            *dir = Scripted::new();
            dir.file("/dl/film.mkv", b"film bytes", 7);
            Vec::new()
        }),
    ));
    let mut phase_at_start = None;
    let end = scan(&harness, Consent::Given, || {
        phase_at_start = harness.progress.lock().unwrap().clone().map(|p| p.phase);
        Err(WatchFault::Backend)
    });
    assert_eq!(end, ScanEnd::Unwatched(WatchFault::Backend));
    let reports = missing_reports(&harness);
    assert!(matches!(reports[0], ScanReport::RootMissing { .. }));
    assert_eq!(reports[1], ScanReport::RootReturned);
    assert!(
        matches!(reports[2], ScanReport::Finished(s) if s.trusted == 1 && s.hashed == 0),
        "{reports:?}"
    );
    assert_eq!(
        reports.len(),
        3,
        "nothing gone, nothing unshared: {reports:?}"
    );
    assert_eq!(harness.world.opens(), 0, "re-validated without a read");
    assert_eq!(phase_at_start, Some(ScanPhase::StartingWatch));
    let waited = harness.elapsed.load(Ordering::SeqCst);
    assert!(
        (90_000..=120_000).contains(&waited),
        "looked for once a minute: {waited} ms"
    );
}

#[test]
fn a_directory_gone_while_watched_is_missing_and_none_of_its_rows_is_had() {
    let world = World::new();
    let stamp = world.with(|dir| dir.file("/dl/film.mkv", b"film bytes", 7));
    let mut shared = row("/dl/film.mkv", stamp, 0);
    shared.file_hash = hash_of(b"film bytes");
    let harness = Harness::new(world, vec![shared]);
    let watch = harness.watch(
        vec![step(ms(2_000), |dir| {
            dir.remove(ROOT);
            vec![moved(ROOT), moved("/dl/film.mkv")]
        })],
        ms(30_000),
    );
    let mut watch = Some(Box::new(watch) as Box<dyn DirectoryWatch>);
    let end = scan(&harness, Consent::Given, || Ok(watch.take().unwrap()));
    assert_eq!(
        end,
        ScanEnd::Stopped,
        "stopped while it waited for the directory"
    );
    let reports = missing_reports(&harness);
    assert!(matches!(reports[0], ScanReport::Finished(_)));
    assert!(
        matches!(reports[1], ScanReport::RootMissing { .. }),
        "{reports:?}"
    );
    assert_eq!(
        reports.len(),
        2,
        "no row gone, held or unshared: {reports:?}"
    );
    assert!(matches!(
        harness.progress.lock().unwrap().clone().unwrap().phase,
        ScanPhase::Missing { .. }
    ));
}
