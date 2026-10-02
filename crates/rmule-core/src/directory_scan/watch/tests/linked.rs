//! A download directory that is itself a symlink (ADR-0100, "A linked
//! directory"): the watch lists it through the link, and never takes the
//! link for an empty directory.

use super::*;

#[test]
fn a_linked_download_directory_keeps_its_rows_through_every_round() {
    let world = World::new();
    let stamp = world.with(|dir| {
        dir.link(ROOT);
        dir.file("/dl/kept.bin", b"kept", 1)
    });
    let harness = Harness::new(world, vec![row("/dl/kept.bin", stamp, 7)]);
    harness.run(
        vec![
            step(ms(1_000), |dir| {
                dir.file("/dl/new.bin", b"new bytes", 2);
                vec![moved("/dl/new.bin")]
            }),
            step(ms(8_000), |_| vec![WatchSignal::Lost]),
        ],
        ms(20_000),
    );
    let shares = harness.shares();
    assert_eq!(shares.len(), 1, "the rounds ran: the new file is shared");
    assert_eq!(shares[0].1.path, PathBuf::from("/dl/new.bin"));
    assert!(harness.gones().is_empty(), "{:?}", harness.reports.borrow());
    assert!(harness.unshares().is_empty());
    assert!(
        !harness
            .reports
            .borrow()
            .iter()
            .any(|(_, report)| matches!(report, ScanReport::Held { .. })),
        "the kept row is never held"
    );
}
