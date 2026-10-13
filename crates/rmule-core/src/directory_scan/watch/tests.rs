//! The watch against a scripted directory and a scripted watch whose clock
//! moves only when the loop waits: stillness, coalescing, change, vanish,
//! rename, skipped names, lost events, and the watch's lifetime inside the
//! scan. Every open and every look at a path is counted at the seam.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmule_primitives::{FileHash, FileHashSummary};

use super::super::scripted::{self, ROOT, Scripted, Timeline, World, known, moved, row};
use super::super::{
    Consent, EntryKind, FileIdentity, Known, Memory, PartFiles, ProgressCell, ScanEnd, ScanPhase,
    ScanReport, ScanSeams, SpareCopy, run_scan,
};
use super::{
    DirectoryWatch, WatchBatch, WatchEnd, WatchFault, WatchSeams, WatchSignal, WatchStarter,
    watch_loop,
};
use crate::registry::SharedFileEntry;

type Step = scripted::Step<Vec<WatchSignal>>;

fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

/// A watch that plays a script; dropping it is recorded.
struct ScriptedWatch {
    timeline: Timeline<Vec<WatchSignal>>,
    dropped: Arc<AtomicBool>,
}

impl DirectoryWatch for ScriptedWatch {
    fn wait(&mut self, max: Duration) -> WatchBatch {
        let (now, signals) = self.timeline.wait(max);
        WatchBatch {
            now,
            signals: signals.unwrap_or_default(),
        }
    }
}

impl Drop for ScriptedWatch {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

struct Harness {
    world: World,
    rows: RefCell<Vec<SharedFileEntry>>,
    stop: Arc<AtomicBool>,
    elapsed: Arc<AtomicU64>,
    dropped: Arc<AtomicBool>,
    progress: ProgressCell,
    /// Each report with the scripted time it was made at.
    reports: RefCell<Vec<(Duration, ScanReport)>>,
    rounds: AtomicUsize,
    memory: RefCell<Memory>,
    /// The part files the download rows name.
    parts: RefCell<PartFiles>,
    /// The spare copies as the actor would hold them.
    spares: RefCell<Vec<SpareCopy>>,
    /// Each row's identity as the actor would hold it.
    identities: RefCell<HashMap<FileHash, FileIdentity>>,
    /// The instant scripted time counts from, for every watch and pause.
    base: Instant,
    /// When the stop flag is raised, as the last watch was told.
    until: Cell<Duration>,
    /// A change to the world made the first time a pause reaches its time.
    on_pause: RefCell<Option<(Duration, Step)>>,
}

impl Harness {
    fn new(world: World, rows: Vec<SharedFileEntry>) -> Self {
        Self {
            world,
            rows: RefCell::new(rows),
            stop: Arc::new(AtomicBool::new(false)),
            elapsed: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(Mutex::new(None)),
            reports: RefCell::new(Vec::new()),
            rounds: AtomicUsize::new(0),
            memory: RefCell::new(Memory::default()),
            parts: RefCell::new(PartFiles::default()),
            spares: RefCell::new(Vec::new()),
            identities: RefCell::new(HashMap::new()),
            base: Instant::now(),
            until: Cell::new(Duration::MAX),
            on_pause: RefCell::new(None),
        }
    }

    fn watch(&self, script: Vec<(Duration, Step)>, until: Duration) -> ScriptedWatch {
        self.until.set(until);
        ScriptedWatch {
            timeline: Timeline {
                world: self.world.clone(),
                start: self.base,
                elapsed: Arc::clone(&self.elapsed),
                script: script.into(),
                until,
                stop: Arc::clone(&self.stop),
            },
            dropped: Arc::clone(&self.dropped),
        }
    }

    /// The registry as the actor would hold it: the rows, with every report
    /// applied as it arrives.
    fn rows_now(&self) -> Option<Known> {
        self.rounds.fetch_add(1, Ordering::SeqCst);
        Some(self.known())
    }

    fn known(&self) -> Known {
        Known {
            parts: self.parts.borrow().clone(),
            spares: self.spares.borrow().clone(),
            identities: self.identities.borrow().clone(),
            ..known(&self.rows.borrow())
        }
    }

    fn report(&self, report: ScanReport) {
        match &report {
            // Keyed by content, as the registry is: a share at a new path
            // moves the row.
            ScanReport::Share(entry) => {
                let mut rows = self.rows.borrow_mut();
                rows.retain(|r| r.file_hash != entry.file_hash);
                rows.push(entry.clone());
            }
            ScanReport::Unshare(hash) => {
                self.rows.borrow_mut().retain(|r| r.file_hash != *hash);
                self.spares.borrow_mut().retain(|s| s.file_hash != *hash);
            }
            ScanReport::Moved {
                file_hash,
                from,
                to,
            } => {
                for row in self.rows.borrow_mut().iter_mut() {
                    if row.file_hash == *file_hash && row.path == *from {
                        row.path.clone_from(&to.path);
                        row.modified = Some(to.stamp.modified);
                        match to.identity {
                            Some(identity) => {
                                self.identities.borrow_mut().insert(*file_hash, identity)
                            }
                            None => self.identities.borrow_mut().remove(file_hash),
                        };
                    }
                }
                self.spares.borrow_mut().retain(|s| s.path != to.path);
            }
            ScanReport::Spare(spare) => {
                let mut spares = self.spares.borrow_mut();
                spares.retain(|s| s.path != spare.path);
                spares.push(spare.clone());
            }
            ScanReport::SpareLeft(path) => self.spares.borrow_mut().retain(|s| s.path != *path),
            ScanReport::Gone { file_hash, path } => {
                self.rows
                    .borrow_mut()
                    .retain(|r| r.file_hash != *file_hash || r.path != *path);
                self.spares
                    .borrow_mut()
                    .retain(|s| s.file_hash != *file_hash);
            }
            ScanReport::Identified {
                file_hash,
                identity,
                ..
            } => {
                self.identities.borrow_mut().insert(*file_hash, *identity);
            }
            ScanReport::Held { .. }
            | ScanReport::Unreadable { .. }
            | ScanReport::NotHashed { .. }
            | ScanReport::LeftoverParts(_)
            | ScanReport::WatchInterrupted(_)
            | ScanReport::WatchRestored
            | ScanReport::PathUnwatched { .. }
            | ScanReport::RootMissing { .. }
            | ScanReport::RootReturned
            | ScanReport::SetAsideLeft(_)
            | ScanReport::Finished(_) => {}
        }
        let at = ms(self.elapsed.load(Ordering::SeqCst));
        self.reports.borrow_mut().push((at, report));
    }

    fn run(&self, script: Vec<(Duration, Step)>, until: Duration) -> WatchEnd {
        let mut watch = self.watch(script, until);
        let seams = WatchSeams {
            source: &self.world,
            watch: &mut watch,
            rows: &mut || self.rows_now(),
            report: &mut |report| self.report(report),
        };
        let known_at_start = self.known();
        watch_loop(
            seams,
            Path::new(ROOT),
            &known_at_start,
            &self.stop,
            &self.progress,
            &mut self.memory.borrow_mut(),
        )
    }

    fn shares(&self) -> Vec<(Duration, SharedFileEntry)> {
        self.reports
            .borrow()
            .iter()
            .filter_map(|(at, report)| match report {
                ScanReport::Share(entry) => Some((*at, entry.clone())),
                _ => None,
            })
            .collect()
    }

    /// Each row moved unread, with where it went.
    fn moves(&self) -> Vec<(Duration, PathBuf)> {
        self.reports
            .borrow()
            .iter()
            .filter_map(|(at, report)| match report {
                ScanReport::Moved { to, .. } => Some((*at, to.path.clone())),
                _ => None,
            })
            .collect()
    }

    fn unshares(&self) -> Vec<(Duration, FileHash)> {
        self.reports
            .borrow()
            .iter()
            .filter_map(|(at, report)| match report {
                ScanReport::Unshare(hash) => Some((*at, *hash)),
                _ => None,
            })
            .collect()
    }

    /// The rows reported gone, by content.
    fn gones(&self) -> Vec<FileHash> {
        self.reports
            .borrow()
            .iter()
            .filter_map(|(_, report)| match report {
                ScanReport::Gone { file_hash, .. } => Some(*file_hash),
                _ => None,
            })
            .collect()
    }

    fn rounds(&self) -> usize {
        self.rounds.load(Ordering::SeqCst)
    }
}

fn step(
    at: Duration,
    change: impl FnOnce(&mut Scripted) -> Vec<WatchSignal> + Send + 'static,
) -> (Duration, Step) {
    (at, Box::new(change))
}

fn hash_of(bytes: &[u8]) -> FileHash {
    FileHashSummary::digest_bytes(bytes).file_hash()
}

#[test]
fn a_file_that_appears_is_shared_once_it_has_held_still_for_five_seconds() {
    let harness = Harness::new(World::new(), Vec::new());
    let end = harness.run(
        vec![step(ms(1_000), |dir| {
            dir.file("/dl/new.mkv", b"new bytes", 10);
            vec![moved("/dl/new.mkv")]
        })],
        ms(20_000),
    );
    assert_eq!(end, WatchEnd::Stopped);
    let shares = harness.shares();
    assert_eq!(shares.len(), 1);
    let (at, entry) = &shares[0];
    assert!(
        *at >= ms(6_000),
        "shared at {at:?}, before five still seconds"
    );
    assert_eq!(entry.path, PathBuf::from("/dl/new.mkv"));
    assert_eq!(entry.file_hash, hash_of(b"new bytes"));
    assert_eq!(harness.world.opens(), 1);
}

#[test]
fn a_file_still_growing_is_hashed_only_after_it_settles() {
    let harness = Harness::new(World::new(), Vec::new());
    let mut script = vec![step(ms(1_000), |dir| {
        dir.file("/dl/copy.iso", b"a", 1);
        vec![moved("/dl/copy.iso")]
    })];
    // Grows every two seconds for eight seconds; only some growth is
    // reported, so the clock's own re-stamp must see the rest.
    for (index, second) in [3_u64, 5, 7, 9].into_iter().enumerate() {
        let bytes = vec![b'a'; index + 2];
        let report = second % 4 == 1;
        script.push(step(ms(second * 1_000), move |dir| {
            dir.file("/dl/copy.iso", &bytes, second);
            if report {
                vec![moved("/dl/copy.iso")]
            } else {
                Vec::new()
            }
        }));
    }
    let end = harness.run(script, ms(30_000));
    assert_eq!(end, WatchEnd::Stopped);
    let shares = harness.shares();
    assert_eq!(shares.len(), 1, "hashed once, when it settled");
    assert!(shares[0].0 >= ms(14_000), "shared at {:?}", shares[0].0);
    assert_eq!(shares[0].1.file_hash, hash_of(b"aaaaa"));
    assert_eq!(harness.world.opens(), 1);
}

#[test]
fn a_file_that_never_holds_still_is_never_hashed_and_shows_as_settling() {
    let harness = Harness::new(World::new(), Vec::new());
    let script = (1..=20_u64)
        .map(|second| {
            step(ms(second * 1_000), move |dir| {
                dir.file("/dl/app.log", &vec![b'x'; second as usize], second);
                vec![moved("/dl/app.log")]
            })
        })
        .collect();
    harness.run(script, ms(21_000));
    assert!(harness.shares().is_empty());
    assert_eq!(harness.world.opens(), 0);
    let progress = harness.progress.lock().unwrap().clone().unwrap();
    assert_eq!(progress.phase, ScanPhase::Watching { settling: 1 });
}

#[test]
fn a_burst_of_a_thousand_files_is_one_examination_round() {
    let harness = Harness::new(World::new(), Vec::new());
    let names: Vec<String> = (0..1_000).map(|i| format!("/dl/f{i:04}.bin")).collect();
    let (first, second) = (names.clone(), names.clone());
    let script = vec![
        step(ms(3_000), move |dir| {
            first
                .iter()
                .map(|name| {
                    dir.file(name, name.as_bytes(), 1);
                    moved(name)
                })
                .collect()
        }),
        // The same files reported again (a close after the write).
        step(ms(3_300), move |_| {
            second.iter().map(|name| moved(name)).collect()
        }),
    ];
    harness.run(script, ms(20_000));
    assert_eq!(harness.shares().len(), 1_000);
    assert_eq!(harness.world.opens(), 1_000, "each file hashed once");
    // The watch's first round lists the root without a look; then one
    // round examines the burst, each path once, and one hashes it.
    assert_eq!(harness.world.looks(), 1_000);
    assert_eq!(harness.rounds(), 3);
}

#[test]
fn a_changed_file_leaves_at_once_and_is_hashed_as_new_once_still() {
    let world = World::new();
    let stamp = world.with(|dir| dir.file("/dl/a.bin", b"old", 1));
    let harness = Harness::new(world, vec![row("/dl/a.bin", stamp, 7)]);
    harness.run(
        vec![step(ms(1_000), |dir| {
            dir.file("/dl/a.bin", b"rewritten", 2);
            vec![moved("/dl/a.bin")]
        })],
        ms(20_000),
    );
    let unshares = harness.unshares();
    assert_eq!(unshares.len(), 1);
    assert_eq!(unshares[0].1, FileHash::from_bytes([7; 16]));
    assert!(unshares[0].0 < ms(3_000), "dropped at {:?}", unshares[0].0);
    let shares = harness.shares();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].1.file_hash, hash_of(b"rewritten"));
}

#[test]
fn a_vanished_file_leaves_the_registry_unread_and_is_gone() {
    let world = World::new();
    let stamp = world.with(|dir| dir.file("/dl/a.bin", b"gone soon", 1));
    let harness = Harness::new(world, vec![row("/dl/a.bin", stamp, 7)]);
    harness.run(
        vec![step(ms(1_000), |dir| {
            dir.remove("/dl/a.bin");
            vec![moved("/dl/a.bin")]
        })],
        ms(10_000),
    );
    assert_eq!(harness.gones(), [FileHash::from_bytes([7; 16])]);
    assert!(harness.unshares().is_empty());
    assert!(harness.shares().is_empty());
    assert_eq!(harness.world.opens(), 0);
}

#[test]
fn a_renamed_file_is_hashed_again_and_its_row_moves() {
    let world = World::new();
    let stamp = world.with(|dir| dir.file("/dl/draft.txt", b"contents", 1));
    let mut old = row("/dl/draft.txt", stamp, 0);
    old.file_hash = hash_of(b"contents");
    let harness = Harness::new(world, vec![old]);
    harness.run(
        vec![step(ms(1_000), |dir| {
            dir.remove("/dl/draft.txt");
            dir.file("/dl/final.txt", b"contents", 1);
            vec![moved("/dl/draft.txt"), moved("/dl/final.txt")]
        })],
        ms(20_000),
    );
    // Held while the new path settled, then moved: never unshared, never gone.
    assert!(harness.unshares().is_empty());
    assert!(harness.gones().is_empty());
    let shares = harness.shares();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].1.path, PathBuf::from("/dl/final.txt"));
    // The Hash Trust Rule keys on the path: same size and time, read again.
    assert_eq!(harness.world.opens(), 1);
    assert_eq!(harness.rows.borrow().len(), 1);
}

#[test]
fn events_for_skipped_names_cost_no_work() {
    let world = World::new();
    let harness = Harness::new(world, Vec::new());
    *harness.parts.borrow_mut() = PartFiles::of([(PathBuf::from("/dl/film.mkv.part"), true)]);
    harness.run(
        vec![step(ms(3_000), |dir| {
            dir.file("/dl/.hidden", b"x", 1);
            dir.dir("/dl/.cache");
            dir.file("/dl/.cache/inside.bin", b"x", 1);
            dir.file("/dl/film.mkv.part", b"x", 1);
            dir.entry("/dl/link.bin", EntryKind::Symlink);
            vec![
                moved("/dl/.hidden"),
                moved("/dl/.cache/inside.bin"),
                moved("/dl/film.mkv.part"),
                moved("/dl/link.bin"),
                moved("/elsewhere/outside.bin"),
            ]
        })],
        ms(20_000),
    );
    assert!(harness.reports.borrow().is_empty());
    assert_eq!(harness.world.opens(), 0);
    // The symlink alone: the first round lists the root without a look.
    assert_eq!(harness.world.looks(), 1);
}

#[test]
fn a_lost_event_is_covered_by_examining_the_whole_directory() {
    let harness = Harness::new(World::new(), Vec::new());
    harness.run(
        vec![step(ms(1_000), |dir| {
            dir.dir("/dl/sub");
            dir.file("/dl/sub/unreported.bin", b"quiet", 1);
            vec![WatchSignal::Lost]
        })],
        ms(20_000),
    );
    let shares = harness.shares();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].1.path, PathBuf::from("/dl/sub/unreported.bin"));
}

/// Scripted watch starts, and an outage's clock: a pause moves the
/// harness's time and raises the stop flag once it reaches the last watch's
/// end.
struct Starter<'h, F> {
    harness: &'h Harness,
    starts: F,
}

impl<F: FnMut() -> Result<Box<dyn DirectoryWatch>, WatchFault>> WatchStarter for Starter<'_, F> {
    fn start(&mut self, _root: &Path) -> Result<Box<dyn DirectoryWatch>, WatchFault> {
        (self.starts)()
    }

    fn pause(&mut self, max: Duration) {
        let millis = max.as_millis() as u64;
        let elapsed = self.harness.elapsed.fetch_add(millis, Ordering::SeqCst) + millis;
        let due = matches!(&*self.harness.on_pause.borrow(), Some((at, _)) if ms(elapsed) >= *at);
        if due && let Some((_, change)) = self.harness.on_pause.borrow_mut().take() {
            self.harness.world.with(|dir| drop(change(dir)));
        }
        if ms(elapsed) >= self.harness.until.get() {
            self.harness.stop.store(true, Ordering::SeqCst);
        }
    }
}

/// Run the whole scan — pass, then watch — with a scripted watch start.
fn scan(
    harness: &Harness,
    consent: Consent,
    starts: impl FnMut() -> Result<Box<dyn DirectoryWatch>, WatchFault>,
) -> ScanEnd {
    run_scan(
        ScanSeams {
            source: &harness.world,
            watcher: &mut Starter { harness, starts },
            rows: &mut || harness.rows_now(),
            report: &mut |report| harness.report(report),
            turn: crate::directory_scan::HashTurn::default(),
            missing_look: crate::CoreConfig::default().missing_directory_look,
        },
        Path::new(ROOT),
        consent,
        &harness.stop,
        &harness.progress,
    )
}

#[test]
fn a_declined_directory_is_never_watched() {
    let world = World::new();
    world.with(|dir| dir.file("/dl/private.doc", b"secret", 1));
    let harness = Harness::new(world, Vec::new());
    let mut starts = 0;
    let end = scan(&harness, Consent::Ask(Box::new(|_| false)), || {
        starts += 1;
        Err(WatchFault::Backend)
    });
    assert_eq!(end, ScanEnd::Declined);
    assert_eq!(starts, 0);
}

#[test]
fn the_watch_starts_after_the_first_pass_and_a_stop_drops_it() {
    let world = World::new();
    world.with(|dir| dir.file("/dl/present.bin", b"present", 1));
    let harness = Harness::new(world, Vec::new());
    let watch = harness.watch(
        vec![step(ms(1_000), |dir| {
            dir.file("/dl/later.bin", b"later", 2);
            vec![moved("/dl/later.bin")]
        })],
        ms(10_000),
    );
    let mut watch = Some(Box::new(watch) as Box<dyn DirectoryWatch>);
    let end = scan(&harness, Consent::Given, || Ok(watch.take().unwrap()));
    assert_eq!(end, ScanEnd::Stopped);
    assert!(
        harness.dropped.load(Ordering::SeqCst),
        "the stop dropped the watch"
    );
    let reports = harness.reports.borrow();
    assert!(matches!(&reports[0].1, ScanReport::Share(e) if e.path.ends_with("present.bin")));
    assert!(matches!(&reports[1].1, ScanReport::Finished(s) if s.hashed == 1));
    assert!(matches!(&reports[2].1, ScanReport::Share(e) if e.path.ends_with("later.bin")));
}

#[test]
fn the_first_pass_is_reported_before_the_watch_starts() {
    let world = World::new();
    world.with(|dir| dir.file("/dl/present.bin", b"present", 1));
    let harness = Harness::new(world, Vec::new());
    let mut seen_at_start = None;
    let end = scan(&harness, Consent::Given, || {
        let finished = harness
            .reports
            .borrow()
            .iter()
            .any(|(_, report)| matches!(report, ScanReport::Finished(s) if s.hashed == 1));
        let phase = harness.progress.lock().unwrap().clone().unwrap().phase;
        seen_at_start = Some((finished, phase));
        Err(WatchFault::Backend)
    });
    assert_eq!(end, ScanEnd::Unwatched(WatchFault::Backend));
    assert_eq!(
        seen_at_start,
        Some((true, ScanPhase::StartingWatch)),
        "a slow watch start holds back neither the pass's report nor an honest phase"
    );
}

#[test]
fn a_watch_that_cannot_start_leaves_the_pass_standing_and_says_why() {
    let world = World::new();
    world.with(|dir| dir.file("/dl/present.bin", b"present", 1));
    let harness = Harness::new(world, Vec::new());
    let end = scan(&harness, Consent::Given, || Err(WatchFault::Limit));
    assert_eq!(end, ScanEnd::Unwatched(WatchFault::Limit));
    assert_eq!(harness.shares().len(), 1, "the first pass holds");
    assert_eq!(
        harness.progress.lock().unwrap().clone().unwrap().phase,
        ScanPhase::Unwatched {
            reason: WatchFault::Limit
        }
    );
}

mod had;
mod linked;
mod missing;
mod parts;
mod rename;
mod rewatch;
mod unreadable;
