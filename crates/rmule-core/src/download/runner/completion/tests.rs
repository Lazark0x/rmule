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
use super::{FinalFileInPlace, Recovered, StopAnswer, complete, recover};
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
    let (mut runner, held) = runner_context((), (), DiagnosticsState::default());
    Arc::get_mut(&mut runner.rt)
        .expect("the runtime is the test's alone")
        .completion_fs = fs;
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("temp")).unwrap();
    std::fs::create_dir_all(dir.path().join("dl")).unwrap();
    let bytes = bytes(len);
    let file = rmule_testkit::file_link("film.mkv", &bytes);
    let paths = DownloadPaths::new(
        dir.path().join("dl/film.mkv"),
        dir.path().join("temp/film.mkv.part"),
    );
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
    fn rename(&self, from: &Path, to: &Path) -> Result<(), Refusal> {
        if from.parent() == to.parent() {
            return OsCompletionFs.rename(from, to);
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
    fn rename(&self, from: &Path, to: &Path) -> Result<(), Refusal> {
        if self.renames.fetch_add(1, Ordering::SeqCst) < self.held {
            return Err(Refusal::InUse { os_code: 32 });
        }
        OsCompletionFs.rename(from, to)
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
