//! The file behind the Run Log: how it is bounded and how it fails.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc;

use super::super::{FILE_NAME, PREDECESSOR_NAME, RunLogFailure};
use super::{LogFile, Sink};

/// One event, in the file by the time this returns.
fn land(log: &mut LogFile, event: &[u8]) {
    log.write_all(event).expect("write");
    log.drain();
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("log file")
}

#[test]
fn a_write_past_the_cap_moves_the_log_aside_and_keeps_one_predecessor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut log = LogFile::open(dir.path(), 10, mpsc::channel().0).expect("open");
    let current = dir.path().join(FILE_NAME);
    let predecessor = dir.path().join(PREDECESSOR_NAME);

    land(&mut log, b"first\n");
    assert!(!predecessor.exists());

    land(&mut log, b"second\n");
    assert_eq!(read(&predecessor), "first\n");
    assert_eq!(read(&current), "second\n");

    land(&mut log, b"third\n");
    assert_eq!(read(&predecessor), "second\n");
    assert_eq!(read(&current), "third\n");
}

#[test]
fn a_later_run_appends_and_counts_what_the_earlier_one_left() {
    let dir = tempfile::tempdir().expect("tempdir");
    let current = dir.path().join(FILE_NAME);
    let mut early = LogFile::open(dir.path(), 10, mpsc::channel().0).expect("open");
    land(&mut early, b"early\n");

    let mut later = LogFile::open(dir.path(), 10, mpsc::channel().0).expect("reopen");
    land(&mut later, b"ok\n");
    assert_eq!(read(&current), "early\nok\n");

    land(&mut later, b"over\n");
    assert_eq!(read(&dir.path().join(PREDECESSOR_NAME)), "early\nok\n");
    assert_eq!(read(&current), "over\n");
}

#[test]
fn an_event_larger_than_the_cap_lands_whole() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut log = LogFile::open(dir.path(), 4, mpsc::channel().0).expect("open");
    land(&mut log, b"much longer than four\n");
    assert_eq!(read(&dir.path().join(FILE_NAME)), "much longer than four\n");
    assert!(!dir.path().join(PREDECESSOR_NAME).exists());
}

/// A log directory that goes away under a run is told once and the writes
/// after it say nothing more.
#[test]
fn a_write_that_fails_is_told_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (tell, told) = mpsc::channel();
    let mut sink = Sink::open(dir.path(), 1 << 20, tell).expect("open");
    sink.file = File::open(dir.path().join(FILE_NAME)).expect("read-only handle");
    assert!(sink.append(b"one\n").is_err());
    assert!(sink.append(b"two\n").is_err());
    assert!(matches!(told.try_recv(), Ok(RunLogFailure::Write { .. })));
    assert!(told.try_recv().is_err(), "told once");
}

/// A rotation that cannot rename leaves the log growing, not ended.
#[test]
fn a_failed_rotation_keeps_the_log_going_and_is_told() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (tell, told) = mpsc::channel();
    let mut log = LogFile::open(dir.path(), 10, tell).expect("open");
    // A directory in the predecessor's place makes the rename fail.
    std::fs::create_dir(dir.path().join(PREDECESSOR_NAME)).expect("blocker");
    std::fs::write(dir.path().join(PREDECESSOR_NAME).join("keep"), b"x").expect("occupied");
    land(&mut log, b"first\n");
    land(&mut log, b"second\n");
    assert_eq!(read(&dir.path().join(FILE_NAME)), "first\nsecond\n");
    assert!(matches!(told.try_recv(), Ok(RunLogFailure::Rotate { .. })));
}

/// A refusal is paid for once per cap of growth: the writes after a failed
/// rotation do not try the rename again until the file has grown by another
/// cap, and the rotation that then succeeds is the ordinary one.
#[test]
fn a_failed_rotation_is_not_tried_again_on_every_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut log = LogFile::open(dir.path(), 10, mpsc::channel().0).expect("open");
    let blocker = dir.path().join(PREDECESSOR_NAME);
    std::fs::create_dir(&blocker).expect("blocker");
    std::fs::write(blocker.join("keep"), b"x").expect("occupied");
    land(&mut log, b"first\n");
    land(&mut log, b"second\n");

    // The way is clear again, but the failed try is not repeated while the
    // file has grown by less than a cap.
    std::fs::remove_file(blocker.join("keep")).expect("clear");
    std::fs::remove_dir(&blocker).expect("clear");
    land(&mut log, b"third\n");
    assert!(!blocker.exists(), "no retry before another cap of growth");
    assert_eq!(read(&dir.path().join(FILE_NAME)), "first\nsecond\nthird\n");

    // A cap's worth later it is tried again, and lands.
    land(&mut log, b"fourth\n");
    assert_eq!(read(&blocker), "first\nsecond\nthird\n");
    assert_eq!(read(&dir.path().join(FILE_NAME)), "fourth\n");
}

/// The whole point of the lane: with nothing taking lines off it, as with a
/// hard-mounted disk gone away, a caller still returns, and what it could
/// not queue is counted.
#[test]
fn a_stalled_disk_never_holds_the_thread_that_logged() {
    let (mut log, entries) = LogFile::with_room(2);
    for _ in 0..5 {
        log.write_all(b"line\n").expect("write");
    }
    assert_eq!(log.dropped.load(Ordering::Relaxed), 3);

    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Sink::open(dir.path(), 1 << 20, mpsc::channel().0).expect("open");
    let dropped = Arc::clone(&log.dropped);
    drop(log);
    sink.run(&entries, &dropped);
    assert_eq!(
        read(&dir.path().join(FILE_NAME)),
        "run_log.dropped lines=3\nline\nline\n"
    );
}

/// A run's last words are what a defect's reader wants: leaving waits for
/// them.
#[test]
fn a_drain_returns_with_everything_queued_in_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut log = LogFile::open(dir.path(), 1 << 20, mpsc::channel().0).expect("open");
    for _ in 0..1000 {
        log.write_all(b"line\n").expect("write");
    }
    log.drain();
    assert_eq!(read(&dir.path().join(FILE_NAME)).lines().count(), 1000);
}
