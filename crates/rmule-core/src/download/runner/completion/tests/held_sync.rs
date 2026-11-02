//! The sync before the rename, which nothing rechecks after it.

use super::*;

/// The first `held` syncs answer the Windows sharing violation. The rename
/// counts what the disk had taken before it.
struct SyncHeldFor {
    held: usize,
    syncs: AtomicUsize,
}

impl CompletionFs for SyncHeldFor {
    fn rename_exclusive(&self, from: &Path, to: &Path) -> Result<(), Refusal> {
        assert!(
            self.syncs.load(Ordering::SeqCst) > self.held,
            "the rename landed bytes no sync had taken"
        );
        OsCompletionFs.rename_exclusive(from, to)
    }

    fn remove(&self, path: &Path) -> Result<(), Refusal> {
        OsCompletionFs.remove(path)
    }

    fn sync_file(&self, _path: &Path) -> std::io::Result<()> {
        if self.syncs.fetch_add(1, Ordering::SeqCst) < self.held {
            return Err(std::io::Error::from_raw_os_error(32));
        }
        Ok(())
    }

    fn sync_refusal(&self, _error: &std::io::Error) -> Refusal {
        Refusal::InUse { os_code: 32 }
    }
}

/// A `Completed` file is never rechecked, so a program holding the file must
/// not get bytes past the sync: the move waits it out as the rename does.
#[tokio::test(start_paused = true)]
async fn a_sync_refused_by_a_program_holding_the_file_waits_as_the_rename_does() {
    let fs = SyncHeldFor {
        held: 2,
        syncs: AtomicUsize::new(0),
    };
    let mut leg = finished(300_000, Arc::new(fs));
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    let (result, ()) = tokio::join!(
        complete(&leg.runner, leg.id, &leg.file, Vec::new()),
        answer(&mut rx, true, |_| {}),
    );
    result.unwrap();
    assert_eq!(leg.lifecycle(), DownloadLifecycle::Completed);
    assert_eq!(told(&leg.events()), [CompletionStep::WaitingForRelease]);
}
