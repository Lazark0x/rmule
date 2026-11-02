//! A **Withheld Row** is offered again only once its file opens (ADR-0106), whichever look finds
//! it back.

use super::*;

/// A row stored before the gate stays, kept from every offer, for what its
/// size is and not for what its path holds.
#[test]
fn a_stored_row_past_the_size_limit_is_withheld_at_the_start_look_and_stays() {
    let world = World::new();
    world.with(|dir| dir.dir("/vm"));
    let size = rmule_primitives::MAX_ED2K_FILE_SIZE + 1;
    let stamp = world.with(|dir| dir.sized("/vm/disk.img", size, 1));
    let outcome = run(
        &world,
        vec![row("/vm/disk.img", stamp, 1)],
        Vec::new(),
        Vec::new(),
        secs(90),
        None,
    );
    assert_eq!(outcome.reason(1), Some(WithheldReason::PastSizeLimit));
    assert!(
        !outcome.rulings().contains(&CheckReport::Offer(hash(1))),
        "{:?}",
        outcome.rulings()
    );
}

#[test]
fn a_row_withheld_as_unreadable_is_not_offered_again_by_a_notice_that_names_it() {
    let world = World::new();
    world.with(|dir| dir.dir("/music"));
    let song = shared(&world, "/music/song.mp3", b"song", 1);
    let other = shared(&world, "/music/other.mp3", b"other", 2);
    let outcome = run(
        &world,
        vec![song, other],
        Vec::new(),
        vec![
            step(secs(3), |dir| {
                dir.denied.insert(PathBuf::from("/music/song.mp3"));
                (Vec::new(), vec![CheckInput::ReadFailed(hash(1))])
            }),
            step(secs(10), |dir| {
                dir.remove("/music/other.mp3");
                (
                    vec![moved("/music/song.mp3"), moved("/music/other.mp3")],
                    Vec::new(),
                )
            }),
        ],
        secs(20),
        None,
    );
    assert!(
        !outcome.has_row(2),
        "the notices were looked at: {:?}",
        outcome.rulings()
    );
    assert!(
        !outcome.rulings().contains(&CheckReport::Offer(hash(1))),
        "{:?}",
        outcome.rulings()
    );
    assert_eq!(
        outcome.reason(1),
        Some(WithheldReason::Unreadable(io::ErrorKind::PermissionDenied))
    );
}
