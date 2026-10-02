//! What the watch cannot read (ADR-0106, "One look, five answers"): a
//! subfolder that cannot be listed hides nothing it rules on.

use super::*;

#[test]
fn a_subfolder_sealed_while_watched_withholds_its_rows_and_never_sends_them_to_the_had_set() {
    let world = World::new();
    let stamp = world.with(|dir| {
        dir.dir("/dl/Movies");
        dir.file("/dl/Movies/film.mkv", b"film", 1)
    });
    let harness = Harness::new(world, vec![row("/dl/Movies/film.mkv", stamp, 7)]);
    harness.run(
        vec![
            step(ms(1_000), |dir| {
                dir.sealed.insert(PathBuf::from("/dl/Movies"));
                vec![WatchSignal::Lost]
            }),
            step(ms(3_000), |dir| {
                dir.file("/dl/new.bin", b"new bytes", 2);
                vec![moved("/dl/new.bin")]
            }),
        ],
        ms(20_000),
    );
    assert_eq!(harness.shares().len(), 1, "the rounds ran");
    let file_hash = FileHash::from_bytes([7; 16]);
    assert!(harness.reports.borrow().iter().any(|(_, report)| *report
        == ScanReport::Unreadable {
            file_hash,
            path: PathBuf::from("/dl/Movies/film.mkv"),
            kind: io::ErrorKind::PermissionDenied,
        }));
    assert!(harness.gones().is_empty(), "{:?}", harness.reports.borrow());
    assert!(harness.unshares().is_empty());
}

/// The paths reported not hashed, in order.
fn not_hashed(harness: &Harness) -> Vec<(PathBuf, io::ErrorKind)> {
    harness
        .reports
        .borrow()
        .iter()
        .filter_map(|(_, report)| match report {
            ScanReport::NotHashed { path, kind, .. } => Some((path.clone(), *kind)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_new_file_that_will_not_open_is_told_once_and_shared_once_it_opens() {
    let harness = Harness::new(World::new(), Vec::new());
    harness.run(
        vec![
            step(ms(1_000), |dir| {
                dir.file("/dl/locked.bin", b"locked", 1);
                dir.denied.insert(PathBuf::from("/dl/locked.bin"));
                vec![moved("/dl/locked.bin")]
            }),
            // Touched again while still locked: examined, settles, fails.
            step(ms(10_000), |_| vec![moved("/dl/locked.bin")]),
            step(ms(20_000), |dir| {
                dir.denied.clear();
                vec![moved("/dl/locked.bin")]
            }),
        ],
        ms(30_000),
    );
    assert_eq!(
        not_hashed(&harness),
        [(
            PathBuf::from("/dl/locked.bin"),
            io::ErrorKind::PermissionDenied
        )],
        "told once, not at every try"
    );
    let shares = harness.shares();
    assert_eq!(shares.len(), 1, "shared once it opens");
    assert!(shares[0].0 >= ms(20_000));
    assert_eq!(harness.world.opens(), 3);
}

#[test]
fn a_file_told_unreadable_is_told_again_when_it_is_deleted_recreated_and_fails_again() {
    let harness = Harness::new(World::new(), Vec::new());
    harness.run(
        vec![
            step(ms(1_000), |dir| {
                dir.file("/dl/locked.bin", b"locked", 1);
                dir.denied.insert(PathBuf::from("/dl/locked.bin"));
                vec![moved("/dl/locked.bin")]
            }),
            step(ms(10_000), |dir| {
                dir.remove("/dl/locked.bin");
                vec![moved("/dl/locked.bin")]
            }),
            step(ms(20_000), |dir| {
                dir.file("/dl/locked.bin", b"locked again", 2);
                vec![moved("/dl/locked.bin")]
            }),
        ],
        ms(30_000),
    );
    let told = not_hashed(&harness);
    assert_eq!(told.len(), 2, "told for each file that failed: {told:?}");
}
