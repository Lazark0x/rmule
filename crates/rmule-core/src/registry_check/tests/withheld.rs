//! A **Withheld Row** is offered again only once its file opens (ADR-0106,
//! "Rechecked"), whichever look finds it back.

use super::*;

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
