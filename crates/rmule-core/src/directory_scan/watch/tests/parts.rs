//! Part files in the watch (ADR-0100, "Part files are known by their download
//! rows"): a leftover is told once per scan, however often it is examined, and
//! a part file a new download starts writing is skipped from the round that
//! learns its row.

use super::*;

fn leftovers(harness: &Harness) -> Vec<Vec<PathBuf>> {
    harness
        .reports
        .borrow()
        .iter()
        .filter_map(|(_, report)| match report {
            ScanReport::LeftoverParts(paths) => Some(paths.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn a_leftover_is_told_once_across_the_pass_and_every_round() {
    let world = World::new();
    world.with(|dir| dir.file("/dl/old.iso.part", b"half a file", 1));
    let harness = Harness::new(world, Vec::new());
    *harness.parts.borrow_mut() = PartFiles::of([(PathBuf::from("/dl/old.iso.part"), false)]);
    let watch = harness.watch(
        vec![
            step(ms(1_000), |_| vec![WatchSignal::Lost]),
            step(ms(8_000), |_| vec![WatchSignal::Lost]),
        ],
        ms(15_000),
    );
    let mut watch = Some(Box::new(watch) as Box<dyn DirectoryWatch>);
    let end = scan(&harness, Consent::Given, || Ok(watch.take().unwrap()));
    assert_eq!(end, ScanEnd::Stopped);
    assert_eq!(
        leftovers(&harness),
        [vec![PathBuf::from("/dl/old.iso.part")]]
    );
    assert_eq!(harness.world.opens(), 0);
}

#[test]
fn a_part_file_a_new_download_writes_is_never_hashed() {
    let world = World::new();
    let harness = Harness::new(world, Vec::new());
    // The download's row is written before its part file appears.
    *harness.parts.borrow_mut() = PartFiles::of([(PathBuf::from("/dl/new.bin.part"), true)]);
    harness.run(
        vec![step(ms(1_000), |dir| {
            dir.file("/dl/new.bin.part", b"first part", 2);
            dir.file("/dl/mine.part", b"the operator's", 2);
            vec![moved("/dl/new.bin.part"), moved("/dl/mine.part")]
        })],
        ms(20_000),
    );
    let shares = harness.shares();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].1.path, PathBuf::from("/dl/mine.part"));
    assert_eq!(harness.world.opens(), 1);
}

#[test]
fn a_completing_downloads_copy_and_its_destination_are_never_hashed() {
    let world = World::new();
    let harness = Harness::new(world, Vec::new());
    // The row is `Completing`: its destination is the download's own until
    // the row is `Completed` (ADR-0115).
    *harness.parts.borrow_mut() = PartFiles::of([(PathBuf::from("/dl/film.mkv"), true)]);
    harness.run(
        vec![
            step(ms(1_000), |dir| {
                dir.file("/dl/.film.mkv.completing", b"half the copy", 2);
                vec![moved("/dl/.film.mkv.completing")]
            }),
            step(ms(2_000), |dir| {
                dir.file("/dl/.film.mkv.completing", b"the whole copy", 3);
                vec![moved("/dl/.film.mkv.completing")]
            }),
            step(ms(3_000), |dir| {
                dir.rename("/dl/.film.mkv.completing", "/dl/film.mkv");
                vec![moved("/dl/.film.mkv.completing"), moved("/dl/film.mkv")]
            }),
            // Events lost after the swap: the whole directory is examined.
            step(ms(10_000), |_| vec![WatchSignal::Lost]),
        ],
        ms(20_000),
    );
    assert!(harness.shares().is_empty());
    assert_eq!(
        harness.world.opens(),
        0,
        "neither the copy nor the file is read"
    );
}
