//! The watch and the Had Set (ADR-0105, "The Had Set"): a row found gone
//! moves to its content elsewhere under the directory — a spare copy hashed
//! before, or a candidate of its size hashed after — and leaves as gone only
//! when neither turns out to be it.

use super::*;
use crate::directory_scan::whereabouts::MOVE_HOLD;

/// A registry row for `bytes` at `path`, with its real hash, so a copy the
/// watch hashes is recognised as the same content.
fn real_row(world: &World, path: &str, bytes: &'static [u8]) -> SharedFileEntry {
    let stamp = world.with(|dir| dir.file(path, bytes, 1));
    let mut entry = row(path, stamp, 0);
    entry.file_hash = hash_of(bytes);
    entry
}

#[test]
fn a_rename_whose_new_path_is_hashed_first_moves_the_row_to_the_spare_copy() {
    let world = World::new();
    let original = real_row(&world, "/dl/draft.txt", b"contents");
    let harness = Harness::new(world, vec![original]);
    harness.run(
        vec![
            // The new path is seen and hashed while the old one still stands…
            step(ms(1_000), |dir| {
                dir.file("/dl/final.txt", b"contents", 1);
                vec![moved("/dl/final.txt")]
            }),
            // …and the old path's going is seen only later.
            step(ms(12_000), |dir| {
                dir.remove("/dl/draft.txt");
                vec![moved("/dl/draft.txt")]
            }),
        ],
        ms(20_000),
    );
    assert!(harness.gones().is_empty());
    assert!(harness.unshares().is_empty());
    assert!(
        harness.shares().is_empty(),
        "the copy was recorded, not shared"
    );
    let moves = harness.moves();
    assert_eq!(moves.len(), 1);
    assert!(
        moves[0].0 >= ms(12_000),
        "the row moves to the copy when the original goes"
    );
    assert_eq!(moves[0].1, PathBuf::from("/dl/final.txt"));
    assert_eq!(harness.world.opens(), 1, "the spare is not read twice");
    assert_eq!(harness.rows.borrow().len(), 1);
    assert!(
        harness.spares.borrow().is_empty(),
        "the path that holds the row is no spare"
    );
}

#[test]
fn a_spare_copy_that_changed_since_it_was_hashed_is_not_where_the_row_goes() {
    let world = World::new();
    let original = real_row(&world, "/dl/draft.txt", b"contents");
    let harness = Harness::new(world, vec![original.clone()]);
    harness.run(
        vec![
            step(ms(1_000), |dir| {
                dir.file("/dl/copy.txt", b"contents", 1);
                vec![moved("/dl/copy.txt")]
            }),
            // Rewritten with no event the watch sees, then the original goes.
            step(ms(10_000), |dir| {
                dir.file("/dl/copy.txt", b"rewritten", 9);
                Vec::new()
            }),
            step(ms(11_000), |dir| {
                dir.remove("/dl/draft.txt");
                vec![moved("/dl/draft.txt")]
            }),
        ],
        ms(13_000),
    );
    assert_eq!(harness.gones(), [original.file_hash]);
    assert!(harness.shares().is_empty());
}

#[test]
fn a_held_row_whose_candidate_is_other_content_leaves_once_it_is_hashed() {
    let world = World::new();
    let original = real_row(&world, "/dl/draft.txt", b"contents");
    let harness = Harness::new(world, vec![original.clone()]);
    harness.run(
        vec![step(ms(1_000), |dir| {
            dir.remove("/dl/draft.txt");
            dir.file("/dl/other.txt", b"elsewise", 1);
            vec![moved("/dl/draft.txt"), moved("/dl/other.txt")]
        })],
        ms(20_000),
    );
    let shares = harness.shares();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].1.path, PathBuf::from("/dl/other.txt"));
    let gone_at = harness
        .reports
        .borrow()
        .iter()
        .find_map(|(at, report)| matches!(report, ScanReport::Gone { .. }).then_some(*at))
        .expect("the row leaves");
    assert!(
        gone_at >= shares[0].0,
        "held until the candidate was hashed"
    );
    assert_eq!(harness.gones(), [original.file_hash]);
}

#[test]
fn a_gone_row_with_no_file_of_its_size_leaves_in_the_round_that_saw_it() {
    let world = World::new();
    let original = real_row(&world, "/dl/draft.txt", b"contents");
    let harness = Harness::new(world, vec![original.clone()]);
    harness.run(
        vec![step(ms(1_000), |dir| {
            dir.remove("/dl/draft.txt");
            dir.file("/dl/longer.txt", b"a longer file", 1);
            vec![moved("/dl/draft.txt"), moved("/dl/longer.txt")]
        })],
        ms(20_000),
    );
    let reports = harness.reports.borrow();
    let (gone_at, _) = reports
        .iter()
        .find(|(_, report)| matches!(report, ScanReport::Gone { .. }))
        .expect("the row leaves");
    assert!(*gone_at < ms(6_000), "not held: nothing could be it");
}

#[test]
fn a_held_row_is_withheld_at_once_and_leaves_at_the_bound_when_its_candidate_never_settles() {
    let world = World::new();
    let original = real_row(&world, "/dl/draft.txt", b"contents");
    let harness = Harness::new(world, vec![original.clone()]);
    let mut script = vec![step(ms(1_000), |dir| {
        dir.remove("/dl/draft.txt");
        vec![moved("/dl/draft.txt")]
    })];
    // A file of the row's size, rewritten every two seconds: it never
    // holds still, so it is never hashed.
    script.extend((0..40_u64).map(|round| {
        step(ms(500 + round * 2_000), move |dir| {
            dir.file("/dl/busy.log", b"12345678", round + 10);
            vec![moved("/dl/busy.log")]
        })
    }));
    script.sort_by_key(|(at, _)| *at);
    harness.run(script, ms(70_000));
    let reports = harness.reports.borrow();
    let at = |wanted: fn(&ScanReport) -> bool| {
        reports
            .iter()
            .find_map(|(at, report)| wanted(report).then_some(*at))
    };
    let held = at(|report| matches!(report, ScanReport::Held { .. })).expect("the row is held");
    assert!(
        held < ms(3_000),
        "held, and so withheld, as soon as it is found gone"
    );
    let gone = at(|report| matches!(report, ScanReport::Gone { .. })).expect("the hold is bounded");
    assert!(
        gone >= held + MOVE_HOLD && gone < held + MOVE_HOLD + ms(1_000),
        "held {held:?}, gone {gone:?}"
    );
    assert!(harness.shares().is_empty());
    drop(reports);
    assert_eq!(harness.gones(), [original.file_hash]);
}

#[test]
fn a_held_row_whose_file_comes_back_is_let_go_without_a_ruling() {
    let world = World::new();
    let original = real_row(&world, "/dl/draft.txt", b"contents");
    let harness = Harness::new(world, vec![original]);
    let mut script = vec![
        step(ms(1_000), |dir| {
            dir.remove("/dl/draft.txt");
            vec![moved("/dl/draft.txt")]
        }),
        // Put back as it was, while a file of its size never settles.
        step(ms(4_000), |dir| {
            dir.file("/dl/draft.txt", b"contents", 1);
            vec![moved("/dl/draft.txt")]
        }),
    ];
    script.extend((0..30_u64).map(|round| {
        step(ms(500 + round * 2_000), move |dir| {
            dir.file("/dl/busy.log", b"12345678", round + 10);
            vec![moved("/dl/busy.log")]
        })
    }));
    script.sort_by_key(|(at, _)| *at);
    harness.run(script, ms(50_000));
    assert!(
        harness.gones().is_empty(),
        "the file came back: nothing left"
    );
}
