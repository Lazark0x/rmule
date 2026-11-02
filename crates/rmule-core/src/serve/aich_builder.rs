//! The enactor of an AICH build (ADR-0038): the build runs on a task of its
//! own, so the serve loop goes on while it reads a file end to end, and its
//! end comes back to the loop as one more input. The [`ServeState`] decides
//! what is built and when; this holds only the stop flag of the one build out.
//!
//! [`ServeState`]: super::state::ServeState

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rmule_primitives::FileHash;
use tokio::sync::mpsc;

use super::state::AichBuilt;
use crate::content::ContentFileStore;

/// A build's end, on its way to the serve loop.
#[derive(Debug)]
pub(super) struct AichLanded {
    pub(super) file_hash: FileHash,
    pub(super) built: AichBuilt,
}

/// Starts builds and tells the one out to stop. Dropped with the serve loop,
/// it tells the build to stop, so no serve stop leaves a file being read.
pub(super) struct AichBuilder {
    landed_tx: mpsc::Sender<AichLanded>,
    stop: Arc<AtomicBool>,
}

impl AichBuilder {
    /// A builder saying each build's end on `landed_tx`. Builds run one at a
    /// time, so a channel of one never makes a build wait.
    pub(super) fn new(landed_tx: mpsc::Sender<AichLanded>) -> Self {
        Self {
            landed_tx,
            stop: Arc::default(),
        }
    }

    /// Build the tree of the `file_size`-byte file at `path` away from the
    /// serve loop.
    pub(super) fn start(&mut self, file_hash: FileHash, path: PathBuf, file_size: u64) {
        let stop = Arc::new(AtomicBool::new(false));
        self.stop = Arc::clone(&stop);
        let landed_tx = self.landed_tx.clone();
        tokio::spawn(async move {
            let built = match ContentFileStore::aich_tree(&path, file_size, &stop).await {
                Ok(tree) => AichBuilt::Tree(tree),
                Err(_) if stop.load(Ordering::Relaxed) => AichBuilt::Stopped,
                Err(error) => {
                    tracing::warn!(%error, path = %path.display(), "serve read failed; the file is no longer offered");
                    AichBuilt::Unreadable
                }
            };
            // The loop that would read this is gone: nothing is owed to it.
            let _ = landed_tx.send(AichLanded { file_hash, built }).await;
        });
    }

    /// Tell the build out to stop, before its next block.
    pub(super) fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for AichBuilder {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A pipe at `path`, open both ways so neither end's open waits for the other:
/// a build reading it parks until the test writes, however fast the machine.
/// Dropped by any way out of a test, it ends the read.
#[cfg(all(test, unix))]
pub(super) fn parked_file(path: &std::path::Path) -> std::fs::File {
    let made = std::process::Command::new("mkfifo").arg(path).status();
    assert!(made.unwrap().success());
    std::fs::File::options()
        .read(true)
        .write(true)
        .open(path)
        .unwrap()
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Write as _;
    use std::time::Duration;

    use rmule_primitives::EMBLOCKSIZE;

    use super::*;

    /// The file stays open and most of it is never written, so only the stop
    /// can end this build.
    #[tokio::test]
    async fn a_stop_ends_a_build_before_it_reads_on() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");
        let mut pipe = parked_file(&path);
        let (landed_tx, mut landed_rx) = mpsc::channel(1);
        let mut builder = AichBuilder::new(landed_tx);
        let file_hash = FileHash::from_bytes([0x51; FileHash::BYTE_LEN]);

        builder.start(file_hash, path, 2 * EMBLOCKSIZE);
        builder.stop();
        // Wakes a read parked since before the stop.
        pipe.write_all(&[0]).unwrap();

        let landed = tokio::time::timeout(Duration::from_secs(5), landed_rx.recv())
            .await
            .expect("a stopped build ends")
            .unwrap();
        assert_eq!(landed.file_hash, file_hash);
        assert!(matches!(landed.built, AichBuilt::Stopped));
    }
}
