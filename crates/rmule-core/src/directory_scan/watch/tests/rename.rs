//! A rename in the watch (ADR-0100, "A rename carries its hash when the
//! file's identity proves it"): carried in the round that examines the new
//! path, with nothing to settle and nothing read; read after settling when
//! the identity refuses.

use super::*;

/// A shared file at `/dl/draft.txt` whose identity the harness knows.
fn identified(harness: &Harness) -> SharedFileEntry {
    let stamp = harness
        .world
        .with(|dir| dir.file("/dl/draft.txt", b"contents", 1));
    let identity = harness
        .world
        .with(|dir| dir.identify("/dl/draft.txt", 11, 1));
    let mut entry = row("/dl/draft.txt", stamp, 0);
    entry.file_hash = hash_of(b"contents");
    harness.rows.borrow_mut().push(entry.clone());
    harness
        .identities
        .borrow_mut()
        .insert(entry.file_hash, identity);
    entry
}

fn held_or_gone(harness: &Harness) -> bool {
    harness
        .reports
        .borrow()
        .iter()
        .any(|(_, report)| matches!(report, ScanReport::Held { .. } | ScanReport::Gone { .. }))
}

#[test]
fn a_rename_inside_the_directory_is_carried_in_the_round_that_sees_it() {
    let harness = Harness::new(World::new(), Vec::new());
    identified(&harness);
    harness.run(
        vec![step(ms(3_000), |dir| {
            dir.rename("/dl/draft.txt", "/dl/final.txt");
            vec![moved("/dl/draft.txt"), moved("/dl/final.txt")]
        })],
        ms(20_000),
    );
    let moves = harness.moves();
    assert_eq!(moves.len(), 1);
    assert_eq!(moves[0].1, PathBuf::from("/dl/final.txt"));
    assert!(
        moves[0].0 < ms(3_000) + ms(5_000),
        "carried without waiting for stillness: {:?}",
        moves[0].0
    );
    assert_eq!(harness.world.opens(), 0);
    assert!(!held_or_gone(&harness));
    assert!(harness.shares().is_empty());
    assert_eq!(
        harness.rows.borrow()[0].path,
        PathBuf::from("/dl/final.txt")
    );
}

#[test]
fn a_rename_whose_new_path_arrives_first_ends_as_a_move_with_no_read() {
    let harness = Harness::new(World::new(), Vec::new());
    identified(&harness);
    harness.run(
        vec![
            step(ms(3_000), |dir| {
                dir.rename("/dl/draft.txt", "/dl/final.txt");
                vec![moved("/dl/final.txt")]
            }),
            step(ms(8_000), |_| vec![moved("/dl/draft.txt")]),
        ],
        ms(20_000),
    );
    assert_eq!(harness.world.opens(), 0);
    assert!(!held_or_gone(&harness));
    assert_eq!(
        harness
            .moves()
            .into_iter()
            .map(|(_, to)| to)
            .collect::<Vec<_>>(),
        [PathBuf::from("/dl/final.txt")]
    );
    assert_eq!(
        harness.rows.borrow()[0].path,
        PathBuf::from("/dl/final.txt")
    );
    assert!(harness.spares.borrow().is_empty());
}

#[test]
fn a_rename_the_identity_refuses_is_read_once_it_is_still() {
    let harness = Harness::new(World::new(), Vec::new());
    identified(&harness);
    harness.run(
        vec![step(ms(3_000), |dir| {
            dir.rename("/dl/draft.txt", "/dl/other-volume.txt");
            // Another filesystem: another device.
            let mut identity = dir.identities[Path::new("/dl/other-volume.txt")];
            identity.device = 2;
            dir.identities
                .insert(PathBuf::from("/dl/other-volume.txt"), identity);
            vec![moved("/dl/draft.txt"), moved("/dl/other-volume.txt")]
        })],
        ms(20_000),
    );
    assert!(harness.moves().is_empty());
    assert_eq!(harness.world.opens(), 1);
    let shares = harness.shares();
    assert_eq!(shares.len(), 1);
    assert!(
        shares[0].0 >= ms(3_000) + ms(5_000),
        "read after it settled"
    );
}
