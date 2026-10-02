//! A row whose folder is reached through a symlink (ADR-0100, "One look,
//! five answers"): the folder is there when its path leads to a directory.

use super::*;

#[test]
fn a_file_gone_from_a_linked_folder_is_gone_not_a_folder_missing() {
    let world = World::new();
    world.with(|dir| dir.link("/music"));
    let song = shared(&world, "/music/song.mp3", b"song", 1);
    let outcome = run(
        &world,
        vec![song],
        Vec::new(),
        vec![step(secs(10), |dir| {
            dir.remove("/music/song.mp3");
            (vec![moved("/music/song.mp3")], Vec::new())
        })],
        secs(15),
        None,
    );
    assert!(
        outcome
            .at(&CheckReport::Gone {
                file_hash: hash(1),
                path: "/music/song.mp3".into(),
            })
            .is_some(),
        "{:?}",
        outcome.rulings()
    );
    assert!(!outcome.has_row(1));
}
