//! The completion move against real files in two directories, its rename
//! and delete answered by seams where a test needs a second volume or a
//! program holding the file, and the actor's in-place step played by the
//! test: what the disk and the row hold when the run reports, and after.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rmule_primitives::{ED2K_PART_SIZE, Ed2kFileLink};
use tokio::sync::mpsc;

use super::copy::copy_path;
use super::fs::{CompletionFs, OsCompletionFs, Refusal};
use super::{CompletionGate, FinalFileInPlace, Recovered, StopAnswer, complete, recover};
use crate::diagnostics::DiagnosticsState;
use crate::download::runner::test_context::{Held, runner_context};
use crate::download::runner::{RunnerContext, StopReason};
use crate::error::{DownloadFailure, StorageIntegrityFault};
use crate::hashing::part_hash_of;
use crate::service::{CompletionStep, CoreEvent, DownloadEvent, DownloadId};
use crate::storage::DownloadRepository;
use crate::{DownloadLifecycle, DownloadPaths, VerifiedPartRecord};

/// A download whose every part is verified, its part file in `temp/` and
/// its destination in `dl/`.
struct Finished {
    runner: RunnerContext<(), ()>,
    held: Held,
    id: DownloadId,
    file: Ed2kFileLink,
    paths: DownloadPaths,
    bytes: Vec<u8>,
    _dir: tempfile::TempDir,
}

fn bytes(len: u64) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

fn finished(len: u64, fs: Arc<dyn CompletionFs>) -> Finished {
    finished_at(len, fs, |dir| {
        DownloadPaths::new(dir.join("dl/film.mkv"), dir.join("temp/film.mkv.part"))
    })
}

/// [`finished`] at the paths `place` chooses under the test's directory.
fn finished_at(
    len: u64,
    fs: Arc<dyn CompletionFs>,
    place: impl FnOnce(&Path) -> DownloadPaths,
) -> Finished {
    let (mut runner, held) = runner_context((), (), DiagnosticsState::default());
    Arc::get_mut(&mut runner.rt)
        .expect("the runtime is the test's alone")
        .completion_fs = fs;
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("temp")).unwrap();
    std::fs::create_dir_all(dir.path().join("dl")).unwrap();
    let bytes = bytes(len);
    let file = rmule_testkit::file_link("film.mkv", &bytes);
    let paths = place(dir.path());
    std::fs::write(paths.part_path(), &bytes).unwrap();
    let store = &runner.rt.store;
    let id = store.create_download(&file, None, &paths).unwrap().id();
    store.set_lifecycle(id, DownloadLifecycle::Active).unwrap();
    for (index, part) in bytes.chunks(ED2K_PART_SIZE as usize).enumerate() {
        let part_index = u32::try_from(index).unwrap();
        store
            .record_verified_part(
                id,
                VerifiedPartRecord {
                    part_index,
                    offset: u64::from(part_index) * ED2K_PART_SIZE,
                    len: part.len() as u64,
                    part_hash: part_hash_of(part),
                },
            )
            .unwrap();
    }
    runner.rt.diagnostics.ensure_download(
        id,
        file.file_hash,
        crate::DownloadMetadata::from_link(&file),
    );
    Finished {
        runner,
        held,
        id,
        file,
        paths,
        bytes,
        _dir: dir,
    }
}

impl Finished {
    fn lifecycle(&self) -> DownloadLifecycle {
        self.runner
            .rt
            .store
            .load_download(self.id)
            .unwrap()
            .lifecycle()
    }

    fn final_path(&self) -> PathBuf {
        self.runner
            .rt
            .store
            .load_download(self.id)
            .unwrap()
            .paths()
            .final_path()
            .to_path_buf()
    }

    fn events(&mut self) -> Vec<DownloadEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.held.evt_rx.try_recv() {
            if let CoreEvent::Download(event) = event {
                events.push(event);
            }
        }
        events
    }

    fn step(&self) -> Option<CompletionStep> {
        self.runner
            .rt
            .diagnostics
            .snapshot()
            .downloads
            .get(&self.id)
            .and_then(|row| row.completion)
            .map(|progress| progress.step)
    }
}

/// The steps the run told as `Completing` events.
fn told(events: &[DownloadEvent]) -> Vec<CompletionStep> {
    events
        .iter()
        .filter_map(|event| match event {
            DownloadEvent::Completing { step, .. } => Some(*step),
            _ => None,
        })
        .collect()
}

fn completed_at(events: &[DownloadEvent]) -> Option<&Path> {
    events.iter().find_map(|event| match event {
        DownloadEvent::DownloadCompleted { final_path, .. } => Some(final_path.as_path()),
        _ => None,
    })
}

/// Play the actor once: take the report, let `look` see the disk and the
/// row as the run left them, and answer `written`.
async fn answer(
    rx: &mut mpsc::Receiver<FinalFileInPlace>,
    written: bool,
    look: impl FnOnce(&FinalFileInPlace),
) {
    let report = rx.recv().await.expect("the run reports its file in place");
    look(&report);
    report.written.send(written).unwrap();
}

/// Renames across directories answer `CrossesDevices`, as across two
/// volumes; `before` runs first, as a program writing the part file would.
struct TwoVolumes {
    before: Box<dyn Fn(&Path) + Send + Sync>,
}

impl CompletionFs for TwoVolumes {
    fn rename_exclusive(&self, from: &Path, to: &Path) -> Result<(), Refusal> {
        if from.parent() == to.parent() {
            return OsCompletionFs.rename_exclusive(from, to);
        }
        (self.before)(from);
        Err(Refusal::CrossesDevices)
    }

    fn remove(&self, path: &Path) -> Result<(), Refusal> {
        OsCompletionFs.remove(path)
    }
}

/// The first `held` renames answer the Windows sharing violation, as while
/// a player holds the file; every one after it is the system's.
struct HeldFor {
    held: usize,
    renames: AtomicUsize,
}

impl CompletionFs for HeldFor {
    fn rename_exclusive(&self, from: &Path, to: &Path) -> Result<(), Refusal> {
        if self.renames.fetch_add(1, Ordering::SeqCst) < self.held {
            return Err(Refusal::InUse { os_code: 32 });
        }
        OsCompletionFs.rename_exclusive(from, to)
    }

    fn remove(&self, path: &Path) -> Result<(), Refusal> {
        OsCompletionFs.remove(path)
    }
}

#[tokio::test]
async fn on_one_volume_the_part_file_is_renamed_into_place_before_the_row_is_written() {
    let mut leg = finished(300_000, Arc::new(OsCompletionFs));
    let destination = leg.paths.final_path().to_path_buf();
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    let (result, ()) = tokio::join!(
        complete(&leg.runner, leg.id, &leg.file, Vec::new()),
        answer(&mut rx, true, |report| {
            assert_eq!(report.path, destination);
            assert_eq!(std::fs::read(&destination).unwrap(), leg.bytes);
            assert!(
                !leg.paths.part_path().exists(),
                "a rename takes the part file"
            );
            assert_eq!(leg.lifecycle(), DownloadLifecycle::Completing);
        }),
    );
    result.unwrap();
    assert_eq!(leg.lifecycle(), DownloadLifecycle::Completed);
    let events = leg.events();
    assert_eq!(completed_at(&events), Some(destination.as_path()));
    assert!(
        told(&events).is_empty(),
        "a rename neither waits nor copies"
    );
}

#[tokio::test]
async fn a_taken_destination_completes_under_the_first_free_numbered_name() {
    let mut leg = finished(300_000, Arc::new(OsCompletionFs));
    std::fs::write(leg.paths.final_path(), b"the operator's own file").unwrap();
    let numbered = leg.paths.final_path().with_file_name("film (1).mkv");
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    let (result, ()) = tokio::join!(
        complete(&leg.runner, leg.id, &leg.file, Vec::new()),
        answer(&mut rx, true, |report| assert_eq!(report.path, numbered)),
    );
    result.unwrap();
    assert_eq!(leg.final_path(), numbered, "the row names where it landed");
    assert_eq!(std::fs::read(&numbered).unwrap(), leg.bytes);
    assert_eq!(
        std::fs::read(leg.paths.final_path()).unwrap(),
        b"the operator's own file"
    );
    assert_eq!(completed_at(&leg.events()), Some(numbered.as_path()));
}

/// The first rename finds a file another program wrote at its target after
/// the move named it, as in the window between naming and landing; every
/// rename is the system's exclusive one.
struct CameToStand {
    renames: AtomicUsize,
}

impl CompletionFs for CameToStand {
    fn rename_exclusive(&self, from: &Path, to: &Path) -> Result<(), Refusal> {
        if self.renames.fetch_add(1, Ordering::SeqCst) == 0 {
            std::fs::write(to, b"a file that came to stand there").unwrap();
        }
        OsCompletionFs.rename_exclusive(from, to)
    }

    fn remove(&self, path: &Path) -> Result<(), Refusal> {
        OsCompletionFs.remove(path)
    }
}

/// A file created at the destination between its naming and the rename is
/// never replaced: the rename itself refuses, and the move lands under the
/// next free name, stored first.
#[tokio::test]
async fn a_file_that_comes_to_stand_at_the_destination_is_kept_and_the_move_numbers() {
    let fs = Arc::new(CameToStand {
        renames: AtomicUsize::new(0),
    });
    let mut leg = finished(300_000, fs);
    let named = leg.paths.final_path().to_path_buf();
    let numbered = named.with_file_name("film (1).mkv");
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    let (result, ()) = tokio::join!(
        complete(&leg.runner, leg.id, &leg.file, Vec::new()),
        answer(&mut rx, true, |report| assert_eq!(report.path, numbered)),
    );
    result.unwrap();
    assert_eq!(leg.final_path(), numbered);
    assert_eq!(std::fs::read(&numbered).unwrap(), leg.bytes);
    assert_eq!(
        std::fs::read(&named).unwrap(),
        b"a file that came to stand there"
    );
}

/// A move whose stored destination a past move numbered, that name taken
/// since: the next free name counts from the Download Name, as aMule's
/// does, never on from the number.
#[tokio::test]
async fn a_move_numbered_once_counts_its_next_free_name_from_the_download_name() {
    let mut leg = finished(300_000, Arc::new(OsCompletionFs));
    let placed = leg.paths.final_path().to_path_buf();
    let first = placed.with_file_name("film (1).mkv");
    let second = placed.with_file_name("film (2).mkv");
    std::fs::write(&placed, b"the operator's own file").unwrap();
    std::fs::write(&first, b"a file that came to stand there").unwrap();
    leg.runner.rt.store.set_completing(leg.id, &first).unwrap();
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    let (result, ()) = tokio::join!(
        complete(&leg.runner, leg.id, &leg.file, Vec::new()),
        answer(&mut rx, true, |report| assert_eq!(report.path, second)),
    );
    result.unwrap();
    assert_eq!(leg.final_path(), second);
    assert_eq!(std::fs::read(&second).unwrap(), leg.bytes);
    assert_eq!(
        std::fs::read(&first).unwrap(),
        b"a file that came to stand there"
    );
}

#[tokio::test(start_paused = true)]
async fn across_volumes_the_copy_lands_whole_and_the_part_goes_only_once_the_row_is_written() {
    let fs = TwoVolumes {
        before: Box::new(|_| {}),
    };
    let mut leg = finished(ED2K_PART_SIZE + 5_000, Arc::new(fs));
    let destination = leg.paths.final_path().to_path_buf();
    let part = leg.paths.part_path().to_path_buf();
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    let actor = async {
        // The registry refuses the first write: the run keeps the part file
        // and reports again on its backoff.
        answer(&mut rx, false, |report| {
            assert_eq!(std::fs::read(&report.path).unwrap(), leg.bytes);
            assert!(
                part.exists(),
                "the part file stays until the row is written"
            );
            assert!(!copy_path(&destination).exists());
        })
        .await;
        answer(&mut rx, true, |_| {
            assert!(part.exists());
            assert_eq!(leg.step(), Some(CompletionStep::WaitingForStore));
        })
        .await;
    };
    let (result, ()) = tokio::join!(complete(&leg.runner, leg.id, &leg.file, Vec::new()), actor);
    result.unwrap();
    assert!(!part.exists(), "the part file goes once the row is written");
    assert_eq!(std::fs::read(&destination).unwrap(), leg.bytes);
    assert_eq!(leg.lifecycle(), DownloadLifecycle::Completed);
    let events = leg.events();
    assert_eq!(
        told(&events),
        [
            CompletionStep::QueuedForCopy,
            CompletionStep::Copying,
            CompletionStep::WaitingForStore
        ]
    );
    assert_eq!(completed_at(&events), Some(destination.as_path()));
}

/// Across a copy the Served Download names the part file until the swap and
/// the finished file, with its own identity, from it on; it stays offered
/// through the step and only the actor's end withdraws it (ADR-0113).
#[tokio::test]
async fn the_served_download_moves_to_the_finished_file_at_the_swap_and_stays_offered() {
    use crate::served_downloads::{BytesAt, PartialEnd, ServedDownloads};

    let fs = TwoVolumes {
        before: Box::new(|_| {}),
    };
    let mut leg = finished(ED2K_PART_SIZE + 5_000, Arc::new(fs));
    let cell = ServedDownloads::default();
    let record = leg.runner.rt.store.load_download(leg.id).unwrap();
    let set = leg.file.part_hash_set.as_ref().unwrap().hashes().to_vec();
    assert!(cell.install(&record, &set));
    let hash = leg.file.file_hash;
    leg.runner.served = cell.hand_to_run(hash, leg.runner.run);
    let before = cell.served(hash).unwrap();
    assert_eq!(before.bytes_at, BytesAt::PartFile);
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    let actor = async {
        let report = rx.recv().await.unwrap();
        let served = cell.served(hash).unwrap();
        assert_eq!(served.bytes_at, BytesAt::FinalFile);
        assert_eq!(served.final_path, report.path);
        assert_eq!(
            served.identity.map(|identity| identity.key),
            Some(crate::file_key::FileKey::at(&report.path).unwrap()),
            "a copy's identity is its own"
        );
        assert_eq!(cell.offered(), [hash], "offered through the swap");
        cell.take_back(hash, report.run);
        assert!(cell.end(report.download_id, PartialEnd::Completed));
        report.written.send(true).unwrap();
    };
    let (result, ()) = tokio::join!(complete(&leg.runner, leg.id, &leg.file, Vec::new()), actor);
    result.unwrap();
    assert!(cell.offered().is_empty());
}

#[tokio::test]
async fn a_copy_whose_part_file_changed_under_it_lands_nothing_and_repairs() {
    let fs = TwoVolumes {
        before: Box::new(|part: &Path| {
            let mut bytes = std::fs::read(part).unwrap();
            bytes[10] ^= 0xFF;
            std::fs::write(part, bytes).unwrap();
        }),
    };
    let mut leg = finished(ED2K_PART_SIZE + 5_000, Arc::new(fs));
    let result = complete(&leg.runner, leg.id, &leg.file, Vec::new()).await;
    assert_eq!(result, Err(DownloadFailure::PartVerificationFailed));
    assert!(leg.runner.take_repair(), "the run starts over in place");
    assert_eq!(leg.lifecycle(), DownloadLifecycle::Active);
    assert!(!leg.paths.final_path().exists());
    assert!(!copy_path(leg.paths.final_path()).exists());
    let held: Vec<u32> = leg
        .runner
        .rt
        .store
        .verified_parts(leg.id)
        .unwrap()
        .iter()
        .map(|part| part.part_index)
        .collect();
    assert_eq!(held, [1], "the part that changed is fetched again");
    assert!(
        leg.events()
            .iter()
            .any(|event| matches!(event, DownloadEvent::DamagedPartsDropped { .. }))
    );
}

/// A run whose finished file did not hash holds its part file again to
/// fetch what it lost, and its Hole Probe stays the one it ran: the probe
/// and its notice come once per run (ADR-0111).
#[tokio::test]
async fn a_run_that_repairs_a_finished_file_holds_its_part_file_again_without_a_second_probe() {
    use std::io::{Seek, SeekFrom, Write};

    use crate::download::persist::hold_part_file;

    let leg = finished(ED2K_PART_SIZE + 5_000, Arc::new(OsCompletionFs));
    hold_part_file(&leg.runner, leg.id).await.unwrap();
    let verdict =
        |leg: &Finished| leg.runner.rt.diagnostics.snapshot().downloads[&leg.id].hole_verdict;
    let probed = verdict(&leg);
    assert!(probed.is_some(), "the run's probe ran");
    // A probe run again here would answer that its file cannot be made.
    std::fs::create_dir(
        leg.paths
            .part_path()
            .with_file_name(".film.mkv.part.holeprobe"),
    )
    .unwrap();
    let mut part = std::fs::OpenOptions::new()
        .write(true)
        .open(leg.paths.part_path())
        .unwrap();
    part.seek(SeekFrom::Start(10)).unwrap();
    part.write_all(&[!leg.bytes[10]]).unwrap();
    drop(part);

    let result = complete(&leg.runner, leg.id, &leg.file, Vec::new()).await;
    assert_eq!(result, Err(DownloadFailure::PartVerificationFailed));
    assert!(leg.runner.take_repair(), "the run starts over in place");
    hold_part_file(&leg.runner, leg.id).await.unwrap();
    assert!(leg.runner.part_file.lock().await.is_some(), "held again");
    assert_eq!(verdict(&leg), probed, "the probe is not run again");
}

#[tokio::test(start_paused = true)]
async fn a_file_a_program_holds_waits_for_its_release_and_then_completes() {
    let fs = HeldFor {
        held: 2,
        renames: AtomicUsize::new(0),
    };
    let mut leg = finished(300_000, Arc::new(fs));
    let started = tokio::time::Instant::now();
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    let (result, ()) = tokio::join!(
        complete(&leg.runner, leg.id, &leg.file, Vec::new()),
        answer(&mut rx, true, |_| {}),
    );
    result.unwrap();
    assert!(
        started.elapsed() >= std::time::Duration::from_secs(3),
        "retried after 1 s, then 2 s"
    );
    assert_eq!(leg.lifecycle(), DownloadLifecycle::Completed);
    assert_eq!(told(&leg.events()), [CompletionStep::WaitingForRelease]);
}

#[tokio::test(start_paused = true)]
async fn a_pause_while_the_file_is_held_stops_the_move_and_one_after_it_landed_is_refused() {
    let fs = HeldFor {
        held: usize::MAX,
        renames: AtomicUsize::new(0),
    };
    let leg = finished(300_000, Arc::new(fs));
    let pause = async {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert_eq!(leg.step(), Some(CompletionStep::WaitingForRelease));
        assert_eq!(leg.runner.completion.stop().await, StopAnswer::Stopped);
        leg.held._stop_tx.send(StopReason::Pause).unwrap();
    };
    let (result, ()) = tokio::join!(complete(&leg.runner, leg.id, &leg.file, Vec::new()), pause);
    assert_eq!(result, Err(DownloadFailure::Paused));
    assert_eq!(std::fs::read(leg.paths.part_path()).unwrap(), leg.bytes);
    assert!(!leg.paths.final_path().exists());

    let mut leg = finished(300_000, Arc::new(OsCompletionFs));
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    let actor = async {
        let report = rx.recv().await.unwrap();
        assert_eq!(leg.runner.completion.stop().await, StopAnswer::InPlace);
        report.written.send(true).unwrap();
    };
    let (result, ()) = tokio::join!(complete(&leg.runner, leg.id, &leg.file, Vec::new()), actor);
    result.unwrap();
}

#[tokio::test]
async fn a_pause_while_the_copy_waits_its_turn_leaves_the_part_file_and_no_copy() {
    let fs = TwoVolumes {
        before: Box::new(|_| {}),
    };
    let mut leg = finished(300_000, Arc::new(fs));
    let turn = Arc::clone(&leg.runner.rt.copy_turn)
        .acquire_owned()
        .await
        .unwrap();
    let mut events = std::mem::replace(&mut leg.held.evt_rx, mpsc::channel(1).1);
    let pause = async {
        while let Some(event) = events.recv().await {
            if let CoreEvent::Download(DownloadEvent::Completing {
                step: CompletionStep::QueuedForCopy,
                ..
            }) = event
            {
                break;
            }
        }
        assert_eq!(leg.runner.completion.stop().await, StopAnswer::Stopped);
        leg.held._stop_tx.send(StopReason::Pause).unwrap();
    };
    let (result, ()) = tokio::join!(complete(&leg.runner, leg.id, &leg.file, Vec::new()), pause);
    drop(turn);
    assert_eq!(result, Err(DownloadFailure::Paused));
    assert_eq!(std::fs::read(leg.paths.part_path()).unwrap(), leg.bytes);
    assert!(!copy_path(leg.paths.final_path()).exists());
    assert!(!leg.paths.final_path().exists());
}

/// A Pause that stops the move after it let the held part file go leaves
/// the Served Download checked against the file's length and time too, as
/// any pause does: a part file that changes while paused is never read
/// (ADR-0113, "A paused download").
#[tokio::test]
async fn a_part_file_that_changes_after_a_pause_stopped_its_copy_is_never_read() {
    use crate::content::{CheckedReadError, ContentFileStore};
    use crate::download::runner::served;
    use crate::served_downloads::ServedDownloads;

    let fs = TwoVolumes {
        before: Box::new(|_| {}),
    };
    let mut leg = finished(ED2K_PART_SIZE + 5_000, Arc::new(fs));
    let cell = ServedDownloads::default();
    let record = leg.runner.rt.store.load_download(leg.id).unwrap();
    let set = leg.file.part_hash_set.as_ref().unwrap().hashes().to_vec();
    assert!(cell.install(&record, &set));
    let hash = leg.file.file_hash;
    leg.runner.served = cell.hand_to_run(hash, leg.runner.run);
    crate::download::persist::hold_part_file(&leg.runner, leg.id)
        .await
        .unwrap();
    served::lease_started(&leg.runner, leg.id).await;
    let turn = Arc::clone(&leg.runner.rt.copy_turn)
        .acquire_owned()
        .await
        .unwrap();
    let mut events = std::mem::replace(&mut leg.held.evt_rx, mpsc::channel(1).1);
    let pause = async {
        while let Some(event) = events.recv().await {
            if let CoreEvent::Download(DownloadEvent::Completing {
                step: CompletionStep::QueuedForCopy,
                ..
            }) = event
            {
                break;
            }
        }
        assert_eq!(leg.runner.completion.stop().await, StopAnswer::Stopped);
        leg.held._stop_tx.send(StopReason::Pause).unwrap();
    };
    let (result, ()) = tokio::join!(complete(&leg.runner, leg.id, &leg.file, Vec::new()), pause);
    drop(turn);
    assert_eq!(result, Err(DownloadFailure::Paused));
    served::let_go(&leg.runner).await;
    cell.take_back(hash, leg.runner.run);

    let (path, check) = cell.served(hash).unwrap().read_target();
    assert_eq!(path, leg.paths.part_path());
    let read = ContentFileStore::read_checked(&path, &check, 0, 64).await;
    assert_eq!(
        read.unwrap(),
        leg.bytes[..64],
        "the file the move let go reads"
    );
    let mut grown = leg.bytes.clone();
    grown.extend_from_slice(b"appended while paused");
    std::fs::write(leg.paths.part_path(), &grown).unwrap();
    let read = ContentFileStore::read_checked(&path, &check, 0, 64).await;
    assert!(
        matches!(read, Err(CheckedReadError::Changed)),
        "a part file of another length is not read: {read:?}"
    );
}

#[tokio::test]
async fn attach_resolves_a_completing_row_by_what_is_on_disk() {
    // Part file there, destination absent: it moves again, a leftover copy
    // deleted first.
    let mut leg = finished(300_000, Arc::new(OsCompletionFs));
    std::fs::write(copy_path(leg.paths.final_path()), b"half").unwrap();
    let (result, reported) = recovered_to_end(&mut leg, false).await;
    result.unwrap();
    assert_eq!(reported.as_deref(), Some(leg.paths.final_path()));
    assert!(!copy_path(leg.paths.final_path()).exists());
    assert_eq!(std::fs::read(leg.paths.final_path()).unwrap(), leg.bytes);
    assert_eq!(leg.lifecycle(), DownloadLifecycle::Completed);

    // Both there, the registry holding the file at the destination: in
    // place, so its part file goes and nothing is read.
    let mut leg = finished(300_000, Arc::new(OsCompletionFs));
    std::fs::write(leg.paths.final_path(), &leg.bytes).unwrap();
    let (result, reported) = recovered_to_end(&mut leg, true).await;
    result.unwrap();
    assert_eq!(reported.as_deref(), Some(leg.paths.final_path()));
    assert!(!leg.paths.part_path().exists());
    assert_eq!(leg.lifecycle(), DownloadLifecycle::Completed);

    // Both there, no row, the destination hashing to the file: rmule's own.
    let mut leg = finished(300_000, Arc::new(OsCompletionFs));
    std::fs::write(leg.paths.final_path(), &leg.bytes).unwrap();
    let (result, reported) = recovered_to_end(&mut leg, false).await;
    result.unwrap();
    assert_eq!(reported.as_deref(), Some(leg.paths.final_path()));
    assert!(!leg.paths.part_path().exists());

    // Both there, the destination someone else's: the next free name.
    let mut leg = finished(300_000, Arc::new(OsCompletionFs));
    std::fs::write(leg.paths.final_path(), b"another file").unwrap();
    let numbered = leg.paths.final_path().with_file_name("film (1).mkv");
    let (result, reported) = recovered_to_end(&mut leg, false).await;
    result.unwrap();
    assert_eq!(reported.as_deref(), Some(numbered.as_path()));
    assert_eq!(
        std::fs::read(leg.paths.final_path()).unwrap(),
        b"another file"
    );
    assert_eq!(std::fs::read(&numbered).unwrap(), leg.bytes);

    // Part file gone, destination there: the rename had landed.
    let mut leg = finished(300_000, Arc::new(OsCompletionFs));
    std::fs::rename(leg.paths.part_path(), leg.paths.final_path()).unwrap();
    let (result, reported) = recovered_to_end(&mut leg, false).await;
    result.unwrap();
    assert_eq!(reported.as_deref(), Some(leg.paths.final_path()));
    assert_eq!(leg.lifecycle(), DownloadLifecycle::Completed);

    // Both gone: nothing to complete.
    let mut leg = finished(300_000, Arc::new(OsCompletionFs));
    std::fs::remove_file(leg.paths.part_path()).unwrap();
    let (result, reported) = recovered_to_end(&mut leg, false).await;
    assert_eq!(
        result,
        Err(DownloadFailure::StorageIntegrityFailed(
            StorageIntegrityFault::PartFileMissing
        ))
    );
    assert_eq!(reported, None);
}

/// A Pause that reaches a recovered move while it reads the file a past
/// process copied into place leaves the row `Paused`; the resumed move
/// finds that file its own and finishes there, copying nothing beside it.
#[tokio::test]
async fn a_move_paused_while_recovery_reads_its_landed_copy_finishes_there_on_resume() {
    let mut leg = finished(300_000, Arc::new(OsCompletionFs));
    let destination = leg.paths.final_path().to_path_buf();
    std::fs::write(&destination, &leg.bytes).unwrap();
    let store = Arc::clone(&leg.runner.rt.store);
    store.set_completing(leg.id, &destination).unwrap();
    assert_eq!(leg.runner.completion.stop().await, StopAnswer::Stopped);
    leg.held._stop_tx.send(StopReason::Pause).unwrap();
    let paused = recover(
        &leg.runner,
        leg.id,
        &leg.file,
        Recovered { row_written: false },
    )
    .await;
    assert_eq!(paused, Err(DownloadFailure::Paused));
    store
        .set_lifecycle(leg.id, DownloadLifecycle::Paused)
        .unwrap();

    store
        .set_lifecycle(leg.id, DownloadLifecycle::Active)
        .unwrap();
    leg.runner.completion = Arc::new(CompletionGate::open());
    leg.held._stop_tx.send(StopReason::Active).unwrap();
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    let (result, ()) = tokio::join!(
        complete(&leg.runner, leg.id, &leg.file, Vec::new()),
        answer(&mut rx, true, |report| assert_eq!(report.path, destination)),
    );
    result.unwrap();
    assert_eq!(leg.final_path(), destination);
    assert!(!destination.with_file_name("film (1).mkv").exists());
    assert!(!leg.paths.part_path().exists());
    assert_eq!(leg.lifecycle(), DownloadLifecycle::Completed);
}

/// [`recover`] driven to its end, the actor answering its one report.
async fn recovered_to_end(
    leg: &mut Finished,
    row_written: bool,
) -> (Result<(), DownloadFailure>, Option<PathBuf>) {
    leg.runner
        .rt
        .store
        .set_completing(leg.id, leg.paths.final_path())
        .unwrap();
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    let mut reported = None;
    let run = recover(&leg.runner, leg.id, &leg.file, Recovered { row_written });
    tokio::pin!(run);
    let result = loop {
        tokio::select! {
            result = &mut run => break result,
            Some(report) = rx.recv() => {
                reported = Some(report.path.clone());
                report.written.send(true).unwrap();
            }
        }
    };
    (result, reported)
}

/// A real file held open without delete sharing, as a player holds it on
/// Windows: the rename meets the sharing violation, the move waits, and it
/// completes once the handle closes.
#[cfg(windows)]
#[tokio::test]
async fn a_part_file_held_open_without_delete_sharing_completes_once_its_handle_closes() {
    use std::os::windows::fs::OpenOptionsExt;

    /// `FILE_SHARE_READ`: others may read, not write or delete.
    const SHARE_READ_ONLY: u32 = 0x0000_0001;

    let mut leg = finished(300_000, Arc::new(OsCompletionFs));
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(SHARE_READ_ONLY)
        .open(leg.paths.part_path())
        .unwrap();
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    let mut events = std::mem::replace(&mut leg.held.evt_rx, mpsc::channel(1).1);
    let release = async move {
        loop {
            match events.recv().await {
                Some(CoreEvent::Download(DownloadEvent::Completing {
                    step: CompletionStep::WaitingForRelease,
                    ..
                })) => break,
                Some(_) => {}
                None => panic!("the run ended without waiting for the file"),
            }
        }
        drop(holder);
        answer(&mut rx, true, |_| {}).await;
    };
    let (result, ()) = tokio::join!(
        complete(&leg.runner, leg.id, &leg.file, Vec::new()),
        release
    );
    result.unwrap();
    assert_eq!(std::fs::read(leg.paths.final_path()).unwrap(), leg.bytes);
    assert_eq!(leg.lifecycle(), DownloadLifecycle::Completed);
}

/// A download placed as `film (1).mkv` because `film.mkv` stood then.
fn placed_numbered(len: u64) -> Finished {
    finished_at(len, Arc::new(OsCompletionFs), |dir| {
        DownloadPaths::new(
            dir.join("dl/film (1).mkv"),
            dir.join("temp/film (1).mkv.part"),
        )
        .named("film.mkv")
    })
}

/// Its own name free again at completion, a download placed under a number
/// lands under its own name, as aMule's numbering from the file's name does.
#[tokio::test]
async fn a_download_placed_under_a_number_lands_under_its_own_name_when_free() {
    let mut leg = placed_numbered(300_000);
    let own = leg.paths.final_path().with_file_name("film.mkv");
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    let (result, ()) = tokio::join!(
        complete(&leg.runner, leg.id, &leg.file, Vec::new()),
        answer(&mut rx, true, |report| assert_eq!(report.path, own)),
    );
    result.unwrap();
    assert_eq!(leg.final_path(), own);
    assert_eq!(std::fs::read(&own).unwrap(), leg.bytes);
}

/// Its own name and its placed number both taken at completion, a download
/// placed under a number takes the next number of its own name, never a
/// number on the number (`film (1) (1).mkv`).
#[tokio::test]
async fn a_download_placed_under_a_number_never_stacks_a_second_one() {
    let mut leg = placed_numbered(300_000);
    let placed = leg.paths.final_path().to_path_buf();
    let own = placed.with_file_name("film.mkv");
    let next = placed.with_file_name("film (2).mkv");
    std::fs::write(&own, b"the operator's own file").unwrap();
    std::fs::write(&placed, b"a file that came to stand there").unwrap();
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    let (result, ()) = tokio::join!(
        complete(&leg.runner, leg.id, &leg.file, Vec::new()),
        answer(&mut rx, true, |report| assert_eq!(report.path, next)),
    );
    result.unwrap();
    assert_eq!(leg.final_path(), next);
    assert_eq!(std::fs::read(&next).unwrap(), leg.bytes);
    assert_eq!(
        std::fs::read(&placed).unwrap(),
        b"a file that came to stand there"
    );
}
