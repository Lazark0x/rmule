//! The Registry Check against a scripted directory, a scripted folder watch
//! whose clock moves only when the worker waits, and a stand-in for the actor
//! that applies each ruling to a registry and a withheld set, as the actor
//! does.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use rmule_primitives::FileHash;

use super::{
    CheckInput, CheckReport, CheckSeams, FolderWatch, RECHECK, WithheldReason, WithheldRows,
    run_check,
};
use crate::directory_scan::WatchFault;
use crate::directory_scan::scripted::{self, Scripted, Timeline, World, moved, row};
use crate::directory_scan::{FileStamp, WatchBatch, WatchSignal};
use crate::registry::SharedFileEntry;

/// What happens at one instant: the directory changes, the OS reports, and
/// the actor or the serve side tells the worker something.
type Step = scripted::Step<(Vec<WatchSignal>, Vec<CheckInput>)>;

fn secs(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

fn step(
    at: Duration,
    change: impl FnOnce(&mut Scripted) -> (Vec<WatchSignal>, Vec<CheckInput>) + Send + 'static,
) -> (Duration, Step) {
    (at, Box::new(change))
}

/// A folder watch playing a script, keeping every set it was asked to cover.
struct ScriptedWatch {
    timeline: Timeline<(Vec<WatchSignal>, Vec<CheckInput>)>,
    inputs: Sender<CheckInput>,
    covered: Arc<Mutex<Vec<BTreeSet<PathBuf>>>>,
    refuse: Option<WatchFault>,
}

impl FolderWatch for ScriptedWatch {
    fn wait(&mut self, max: Duration) -> WatchBatch {
        let (now, reported) = self.timeline.wait(max);
        let (signals, inputs) = reported.unwrap_or_default();
        for input in inputs {
            self.inputs.send(input).unwrap();
        }
        WatchBatch { now, signals }
    }

    fn cover(&mut self, folders: &BTreeSet<PathBuf>) -> Result<(), WatchFault> {
        self.covered.lock().unwrap().push(folders.clone());
        self.refuse.map_or(Ok(()), Err)
    }
}

/// The actor's side: the registry and the withheld set every ruling lands
/// in, and each ruling with the instant it came.
struct Actor {
    rows: Vec<SharedFileEntry>,
    withheld: WithheldRows,
    log: Vec<(Duration, CheckReport)>,
}

struct Run {
    actor: Actor,
    covered: Vec<BTreeSet<PathBuf>>,
}

impl Run {
    fn rulings(&self) -> Vec<CheckReport> {
        self.actor
            .log
            .iter()
            .map(|(_, report)| report.clone())
            .collect()
    }

    fn at(&self, wanted: &CheckReport) -> Option<Duration> {
        self.actor
            .log
            .iter()
            .find(|(_, report)| report == wanted)
            .map(|(at, _)| *at)
    }

    fn reason(&self, tag: u8) -> Option<WithheldReason> {
        self.actor.withheld.get(hash(tag)).map(|held| held.reason)
    }

    fn has_row(&self, tag: u8) -> bool {
        self.actor.rows.iter().any(|row| row.file_hash == hash(tag))
    }
}

fn hash(tag: u8) -> FileHash {
    FileHash::from_bytes([tag; FileHash::BYTE_LEN])
}

fn run(
    world: &World,
    rows: Vec<SharedFileEntry>,
    first: Vec<CheckInput>,
    script: Vec<(Duration, Step)>,
    until: Duration,
    refuse: Option<WatchFault>,
) -> Run {
    run_joining(world, rows, Vec::new(), first, script, until, refuse)
}

/// [`run`], with rows that join the registry at their instant, as a share
/// the actor makes while the check runs.
fn run_joining(
    world: &World,
    rows: Vec<SharedFileEntry>,
    joining: Vec<(Duration, SharedFileEntry)>,
    first: Vec<CheckInput>,
    script: Vec<(Duration, Step)>,
    until: Duration,
    refuse: Option<WatchFault>,
) -> Run {
    let stop = Arc::new(AtomicBool::new(false));
    let elapsed = Arc::new(AtomicU64::new(0));
    let covered = Arc::new(Mutex::new(Vec::new()));
    let (inputs_tx, inputs) = mpsc::channel();
    for input in first {
        inputs_tx.send(input).unwrap();
    }
    let mut watch = ScriptedWatch {
        timeline: Timeline {
            world: world.clone(),
            start: Instant::now(),
            elapsed: Arc::clone(&elapsed),
            script: script.into(),
            until,
            stop: Arc::clone(&stop),
        },
        inputs: inputs_tx,
        covered: Arc::clone(&covered),
        refuse,
    };
    let actor = Mutex::new(Actor {
        rows,
        withheld: WithheldRows::before_start_look(),
        log: Vec::new(),
    });
    let withheld = actor.lock().unwrap().withheld.clone();
    let joining = Mutex::new(joining);
    let mut rows_now = || {
        let at = Duration::from_millis(elapsed.load(Ordering::SeqCst));
        let mut actor = actor.lock().unwrap();
        let mut joining = joining.lock().unwrap();
        while joining.first().is_some_and(|(when, _)| *when <= at) {
            let (_, row) = joining.remove(0);
            actor.rows.push(row);
        }
        Some(actor.rows.clone())
    };
    let mut report = |report: CheckReport| {
        let at = Duration::from_millis(elapsed.load(Ordering::SeqCst));
        let mut actor = actor.lock().unwrap();
        match &report {
            CheckReport::Offer(file_hash) => {
                actor.withheld.lift(*file_hash);
            }
            CheckReport::Withhold { file_hash, reason } => {
                actor
                    .withheld
                    .withhold(*file_hash, *reason, SystemTime::UNIX_EPOCH);
            }
            CheckReport::Unshare(file_hash) | CheckReport::Gone { file_hash, .. } => {
                let file_hash = *file_hash;
                actor.rows.retain(|row| row.file_hash != file_hash);
                actor.withheld.lift(file_hash);
            }
            CheckReport::StartLookDone => actor.withheld.looked(),
            CheckReport::WatchUnavailable(_) => {}
        }
        actor.log.push((at, report));
    };
    run_check(
        CheckSeams {
            source: world,
            watch: &mut watch,
            rows: &mut rows_now,
            inputs: &inputs,
            report: &mut report,
        },
        &withheld,
        &stop,
    );
    let covered = covered.lock().unwrap().clone();
    Run {
        actor: actor.into_inner().unwrap(),
        covered,
    }
}

/// A row for a file written into the world at `path`.
fn shared(world: &World, path: &str, bytes: &[u8], tag: u8) -> SharedFileEntry {
    let stamp = world.with(|dir| dir.file(path, bytes, 1));
    row(path, stamp, tag)
}

#[test]
fn the_start_look_offers_what_it_finds_readable_and_withholds_the_rest_without_ruling() {
    let world = World::new();
    world.with(|dir| dir.dir("/music"));
    let kept = shared(&world, "/music/kept.mp3", b"kept", 1);
    let changed = shared(&world, "/music/changed.mp3", b"before", 2);
    world.with(|dir| dir.file("/music/changed.mp3", b"after!!", 2));
    let gone = shared(&world, "/music/gone.mp3", b"gone", 3);
    world.with(|dir| dir.remove("/music/gone.mp3"));
    let unplugged = row(
        "/Volumes/Backup/film.mkv",
        FileStamp {
            size: 9,
            modified: SystemTime::UNIX_EPOCH,
        },
        4,
    );
    let outcome = run(
        &world,
        vec![kept, changed, gone, unplugged],
        Vec::new(),
        Vec::new(),
        secs(2),
        None,
    );
    assert_eq!(outcome.reason(1), None);
    assert_eq!(outcome.reason(2), Some(WithheldReason::Changed));
    assert_eq!(outcome.reason(3), Some(WithheldReason::Missing));
    assert_eq!(outcome.reason(4), Some(WithheldReason::FolderMissing));
    assert_eq!(
        outcome.actor.rows.len(),
        4,
        "the start look rules on nothing: a scan may yet claim the row"
    );
    assert!(outcome.rulings().contains(&CheckReport::StartLookDone));
    assert_eq!(
        world.with(|dir| dir.opens()),
        0,
        "the start look opens nothing"
    );
}

#[test]
fn a_row_missing_at_start_is_ruled_on_at_the_first_recheck_unless_the_scan_owns_it() {
    let world = World::new();
    world.with(|dir| dir.dir("/music"));
    let outside = shared(&world, "/music/gone.mp3", b"gone", 1);
    let inside = shared(&world, "/dl/gone.bin", b"gone", 2);
    world.with(|dir| {
        dir.remove("/music/gone.mp3");
        dir.remove("/dl/gone.bin");
    });
    let outcome = run(
        &world,
        vec![outside, inside],
        vec![CheckInput::ScanOwns([PathBuf::from("/dl")].into())],
        Vec::new(),
        RECHECK + secs(2),
        None,
    );
    let left = outcome
        .at(&CheckReport::Gone {
            file_hash: hash(1),
            path: "/music/gone.mp3".into(),
        })
        .expect("the outside row leaves and joins the Had Set");
    assert!(left >= RECHECK, "ruled at the first recheck, not at start");
    assert!(!outcome.has_row(1));
    assert!(outcome.has_row(2), "the scan rules on its own rows");
    assert_eq!(outcome.reason(2), Some(WithheldReason::Missing));
}

#[test]
fn an_outside_share_that_vanishes_while_running_leaves_within_seconds() {
    let world = World::new();
    world.with(|dir| dir.dir("/music"));
    let song = shared(&world, "/music/song.mp3", b"song", 1);
    let other = shared(&world, "/music/other.mp3", b"other", 2);
    let outcome = run(
        &world,
        vec![song, other],
        Vec::new(),
        vec![step(secs(10), |dir| {
            dir.remove("/music/song.mp3");
            (vec![moved("/music/song.mp3")], Vec::new())
        })],
        secs(15),
        None,
    );
    let left = outcome
        .at(&CheckReport::Gone {
            file_hash: hash(1),
            path: "/music/song.mp3".into(),
        })
        .expect("the vanished share leaves");
    assert!(
        left >= secs(11) && left < secs(12),
        "a second of quiet after the notice: {left:?}"
    );
    assert!(outcome.has_row(2));
    assert!(
        outcome
            .covered
            .iter()
            .all(|folders| folders.contains(Path::new("/music"))),
        "the share's folder is watched: {:?}",
        outcome.covered
    );
}

#[test]
fn a_folder_gone_is_withheld_until_it_returns_and_never_joins_the_had_set() {
    let world = World::new();
    world.with(|dir| {
        dir.dir("/Volumes");
        dir.dir("/Volumes/Backup");
    });
    let film = shared(&world, "/Volumes/Backup/film.mkv", b"film", 1);
    world.with(|dir| dir.remove("/Volumes/Backup"));
    let outcome = run(
        &world,
        vec![film],
        Vec::new(),
        vec![step(RECHECK * 2 + secs(30), |dir| {
            dir.dir("/Volumes/Backup");
            dir.file("/Volumes/Backup/film.mkv", b"film", 1);
            (Vec::new(), Vec::new())
        })],
        RECHECK * 4,
        None,
    );
    assert!(outcome.has_row(1), "an unmounted volume is not a deletion");
    assert!(
        !outcome
            .rulings()
            .iter()
            .any(|ruling| matches!(ruling, CheckReport::Gone { .. })),
    );
    let back = outcome
        .at(&CheckReport::Offer(hash(1)))
        .expect("offered again once the volume returns");
    assert!(
        back >= RECHECK * 3,
        "at the first recheck after it returned"
    );
    assert_eq!(outcome.reason(1), None);
}

#[test]
fn a_failed_read_withholds_or_rules_on_the_row_by_what_the_path_holds() {
    let world = World::new();
    world.with(|dir| {
        dir.dir("/music");
        dir.dir("/Volumes");
        dir.dir("/Volumes/Backup");
    });
    let denied = shared(&world, "/music/denied.mp3", b"denied", 1);
    let gone = shared(&world, "/music/gone.mp3", b"gone", 2);
    let shorter = shared(&world, "/music/shorter.mp3", b"longer", 3);
    let unplugged = shared(&world, "/Volumes/Backup/film.mkv", b"film", 4);
    let flaky = shared(&world, "/music/flaky.mp3", b"flaky", 5);
    let outcome = run(
        &world,
        vec![denied, gone, shorter, unplugged, flaky],
        Vec::new(),
        vec![step(secs(3), |dir| {
            dir.denied.insert(PathBuf::from("/music/denied.mp3"));
            dir.remove("/music/gone.mp3");
            dir.file("/music/shorter.mp3", b"short", 1);
            dir.remove("/Volumes/Backup");
            (
                Vec::new(),
                (1..=5)
                    .map(|tag| CheckInput::ReadFailed(hash(tag)))
                    .collect(),
            )
        })],
        secs(5),
        None,
    );
    assert!(matches!(
        outcome.reason(1),
        Some(WithheldReason::Unreadable(_))
    ));
    assert!(outcome.has_row(1), "present but unreadable is never Had");
    assert!(outcome.rulings().contains(&CheckReport::Gone {
        file_hash: hash(2),
        path: "/music/gone.mp3".into(),
    }));
    assert!(
        outcome.rulings().contains(&CheckReport::Unshare(hash(3))),
        "a shorter file changed: it leaves, not Had"
    );
    assert_eq!(outcome.reason(4), Some(WithheldReason::FolderMissing));
    assert!(
        matches!(outcome.reason(5), Some(WithheldReason::Unreadable(_))),
        "a file that looks right but failed a read is withheld"
    );
}

#[test]
fn a_read_failure_under_the_scanned_directory_is_withheld_for_the_scan_to_rule_on() {
    let world = World::new();
    let clip = shared(&world, "/dl/clip.mkv", b"clip", 1);
    let outcome = run(
        &world,
        vec![clip],
        vec![CheckInput::ScanOwns([PathBuf::from("/dl")].into())],
        vec![step(secs(3), |dir| {
            dir.remove("/dl/clip.mkv");
            (Vec::new(), vec![CheckInput::ReadFailed(hash(1))])
        })],
        secs(5),
        None,
    );
    assert!(outcome.has_row(1), "the scan looks for it elsewhere first");
    assert_eq!(outcome.reason(1), Some(WithheldReason::Missing));
}

#[test]
fn an_unreadable_row_is_offered_again_once_it_opens() {
    let world = World::new();
    world.with(|dir| dir.dir("/music"));
    let song = shared(&world, "/music/song.mp3", b"song", 1);
    let outcome = run(
        &world,
        vec![song],
        Vec::new(),
        vec![
            step(secs(3), |dir| {
                dir.denied.insert(PathBuf::from("/music/song.mp3"));
                (Vec::new(), vec![CheckInput::ReadFailed(hash(1))])
            }),
            step(secs(30), |dir| {
                dir.denied.clear();
                (Vec::new(), Vec::new())
            }),
        ],
        RECHECK + secs(2),
        None,
    );
    let withheld = outcome
        .rulings()
        .iter()
        .position(|ruling| matches!(ruling, CheckReport::Withhold { .. }));
    let offered = outcome
        .rulings()
        .iter()
        .position(|ruling| *ruling == CheckReport::Offer(hash(1)));
    assert!(
        withheld.is_some() && offered > withheld,
        "{:?}",
        outcome.rulings()
    );
    assert_eq!(outcome.reason(1), None);
}

#[test]
fn a_folder_watch_that_cannot_start_is_said_once_and_the_rest_still_holds() {
    let world = World::new();
    world.with(|dir| dir.dir("/music"));
    let song = shared(&world, "/music/song.mp3", b"song", 1);
    let outcome = run(
        &world,
        vec![song],
        Vec::new(),
        vec![step(secs(3), |dir| {
            dir.remove("/music/song.mp3");
            (Vec::new(), vec![CheckInput::ReadFailed(hash(1))])
        })],
        RECHECK * 2 + secs(1),
        Some(WatchFault::Limit),
    );
    let told = outcome
        .rulings()
        .iter()
        .filter(|ruling| matches!(ruling, CheckReport::WatchUnavailable(_)))
        .count();
    assert_eq!(told, 1);
    assert!(!outcome.has_row(1), "the serve read still finds it gone");
}

#[test]
fn a_declined_download_directory_leaves_every_row_to_the_check() {
    let world = World::new();
    world.with(|dir| dir.dir("/music"));
    let outside = shared(&world, "/music/gone.mp3", b"gone", 1);
    let inside = shared(&world, "/dl/gone.bin", b"gone", 2);
    world.with(|dir| {
        dir.remove("/music/gone.mp3");
        dir.remove("/dl/gone.bin");
    });
    // A declined directory is never scanned, so no scan owns it.
    let outcome = run(
        &world,
        vec![outside, inside],
        Vec::new(),
        Vec::new(),
        RECHECK + secs(2),
        None,
    );
    assert!(
        !outcome.has_row(1) && !outcome.has_row(2),
        "both ruled gone"
    );
    assert!(
        outcome
            .rulings()
            .iter()
            .filter(|ruling| matches!(ruling, CheckReport::Gone { .. }))
            .count()
            == 2
    );
}

#[test]
fn a_file_shared_into_a_new_folder_is_looked_at_once_its_folder_is_watched() {
    let world = World::new();
    world.with(|dir| dir.dir("/music"));
    let song = shared(&world, "/music/song.mp3", b"song", 1);
    world.with(|dir| dir.dir("/films"));
    let film = shared(&world, "/films/film.mkv", b"film", 2);
    let outcome = run_joining(
        &world,
        vec![song],
        vec![(secs(3), film)],
        Vec::new(),
        vec![step(secs(3), |dir| {
            // Shared, then gone before its folder's watch began: no notice
            // ever names it.
            dir.remove("/films/film.mkv");
            (Vec::new(), vec![CheckInput::RowsChanged])
        })],
        secs(6),
        None,
    );
    assert!(
        outcome
            .covered
            .iter()
            .any(|folders| folders.contains(Path::new("/films")))
    );
    assert!(outcome.rulings().contains(&CheckReport::Gone {
        file_hash: hash(2),
        path: "/films/film.mkv".into(),
    }));
}

mod linked;
mod withheld;
