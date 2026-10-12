//! A row withheld under a refused folder (ADR-0101) is left alone: neither
//! the minute's recheck nor a notice that names it looks at it, so nothing is
//! proposed for it again and again, until the actor says the refusal lifted.

use super::*;

#[test]
fn a_row_withheld_as_refused_is_looked_at_only_once_the_refusal_lifts() {
    let world = World::new();
    world.with(|dir| dir.dir("/home"));
    let film = shared(&world, "/home/film.mkv", b"film", 1);
    let lift = RECHECK * 2 + secs(5);
    let outcome = run_on(
        &world,
        Registry {
            rows: vec![film],
            held: vec![(hash(1), WithheldReason::Refused)],
            ..Registry::default()
        },
        Vec::new(),
        vec![
            step(secs(10), |_| (vec![moved("/home/film.mkv")], Vec::new())),
            step(lift, |_| {
                (Vec::new(), vec![CheckInput::RefusalLifted(hash(1))])
            }),
        ],
        lift + secs(2),
        None,
    );
    let offered = outcome
        .at(&CheckReport::Offer(hash(1)))
        .expect("looked at once the refusal lifted, and offered");
    assert!(
        offered >= lift && offered < lift + secs(1),
        "at the lift, not at a recheck: {offered:?}"
    );
    assert_eq!(
        outcome.rulings(),
        vec![CheckReport::StartLookDone, CheckReport::Offer(hash(1))],
        "nothing proposed for it while refused"
    );
    assert_eq!(
        world.with(|dir| dir.opens()),
        1,
        "opened once, at the lift, and never while refused"
    );
}
