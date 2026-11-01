//! The order the rename road puts a finished file on the disk.

use super::*;

/// Records the order of a move's syncs and its rename.
#[derive(Default)]
struct Synced {
    steps: parking_lot::Mutex<Vec<&'static str>>,
}

impl Synced {
    fn step(&self, step: &'static str) {
        self.steps.lock().push(step);
    }
}

impl CompletionFs for Synced {
    fn rename_exclusive(&self, from: &Path, to: &Path) -> Result<(), Refusal> {
        self.step("rename");
        OsCompletionFs.rename_exclusive(from, to)
    }

    fn remove(&self, path: &Path) -> Result<(), Refusal> {
        OsCompletionFs.remove(path)
    }

    fn sync_file(&self, _path: &Path) -> std::io::Result<()> {
        self.step("file");
        Ok(())
    }

    fn sync_directory(&self, _directory: &Path) -> std::io::Result<()> {
        self.step("directory");
        Ok(())
    }
}

/// Nothing rechecks a `Completed` file, so the rename road leaves the disk
/// holding it as the copy road does (ADR-0115, step 3).
#[tokio::test]
async fn the_rename_road_syncs_the_file_before_it_and_the_directory_after() {
    let fs = Arc::new(Synced::default());
    let mut leg = finished(300_000, Arc::clone(&fs) as Arc<dyn CompletionFs>);
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    let (result, ()) = tokio::join!(
        complete(&leg.runner, leg.id, &leg.file, Vec::new()),
        answer(&mut rx, true, |_| {}),
    );
    result.unwrap();
    assert_eq!(
        *fs.steps.lock(),
        ["file", "rename", "directory"],
        "the bytes before the name, the name before the row"
    );
}
