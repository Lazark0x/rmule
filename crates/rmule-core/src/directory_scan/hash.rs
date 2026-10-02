//! Hash one found file into a registry entry, through the seam and the one
//! ED2K digest core has (`FileHashSummary::digest_reader`), stoppable
//! between reads. Every scan takes the one [`HashTurn`] before
//! it reads a file, so one file is read at a time across every shared
//! directory (ADR-0101, "Shared Directories").

use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use rmule_primitives::FileHashSummary;

use super::{DirectorySource, FoundFile};
use crate::registry::{ShareSource, SharedFileEntry};

/// The most one read takes, so a raised stop flag is seen within one
/// mebibyte of it rather than one part.
const READ_CAP: usize = 1 << 20;

/// The longest a scan waits for its turn before it looks at its stop flag.
const TURN_TICK: Duration = Duration::from_millis(250);

/// The one turn to read a file that every scan of a core shares: transfers
/// keep the disk, so hashing is one file at a time whatever the number of
/// shared directories.
#[derive(Clone, Debug, Default)]
pub(crate) struct HashTurn(Arc<(Mutex<bool>, Condvar)>);

impl HashTurn {
    /// Wait for the turn, looking at `stop` every [`TURN_TICK`]; `None` once
    /// it is raised. The turn is given back when the guard drops.
    fn take(&self, stop: &AtomicBool) -> Option<TurnGuard<'_>> {
        let (taken, freed) = &*self.0;
        let mut held = taken.lock().expect("hash turn");
        while *held {
            if stop.load(Ordering::Relaxed) {
                return None;
            }
            held = freed.wait_timeout(held, TURN_TICK).expect("hash turn").0;
        }
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        *held = true;
        Some(TurnGuard(self))
    }
}

/// The turn, held.
struct TurnGuard<'a>(&'a HashTurn);

impl Drop for TurnGuard<'_> {
    fn drop(&mut self) {
        let (taken, freed) = &*(self.0).0;
        *taken.lock().expect("hash turn") = false;
        freed.notify_one();
    }
}

/// The entry for `file`, or `None` when its size or time moved while it was
/// read — a file still being written, which the watch picks up once it holds
/// still. The stamp the entry carries is the one taken before the read, so
/// the trust rule never vouches for bytes it did not see.
///
/// # Errors
/// The open's or a read's I/O error; a stop surfaces as an error too, and the
/// caller tells the two apart by the flag.
pub(super) fn hash_file(
    source: &dyn DirectorySource,
    file: &FoundFile,
    stop: &AtomicBool,
    turn: &HashTurn,
) -> io::Result<Option<SharedFileEntry>> {
    let Some(_turn) = turn.take(stop) else {
        return Err(io::Error::other("hash stopped"));
    };
    let summary = digest_stoppable(source.open(&file.path)?, stop)?;
    if source.stamp(&file.path)? != file.stamp || summary.file_size() != file.stamp.size {
        return Ok(None);
    }
    Ok(Some(SharedFileEntry {
        file_hash: summary.file_hash(),
        file_size: summary.file_size(),
        name: file
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        path: file.path.clone(),
        source: ShareSource::DownloadDirectory,
        part_hashes: summary
            .part_hash_set()
            .map(|set| set.hashes().to_vec())
            .unwrap_or_default(),
        modified: Some(file.stamp.modified),
    }))
}

/// The ED2K identity of everything `reader` yields, read at most
/// [`READ_CAP`] at a time with `stop` checked before each read. Blocking.
///
/// # Errors
/// A read's I/O error; a stop surfaces as an error too, and the caller tells
/// the two apart by the flag.
fn digest_stoppable(reader: impl Read, stop: &AtomicBool) -> io::Result<FileHashSummary> {
    FileHashSummary::digest_reader(Stoppable {
        inner: reader,
        stop,
    })
}

/// A reader that fails once the stop flag is up, never reads more than
/// [`READ_CAP`] at once.
struct Stoppable<'a, R> {
    inner: R,
    stop: &'a AtomicBool,
}

impl<R: Read> Read for Stoppable<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.stop.load(Ordering::Relaxed) {
            return Err(io::Error::other("hash stopped"));
        }
        let cap = buf.len().min(READ_CAP);
        self.inner.read(&mut buf[..cap])
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    use super::HashTurn;

    /// One file is read at a time across every scan: a second scan waits
    /// while the turn is held, takes it once it is given back, and a stop
    /// frees a scan still waiting.
    #[test]
    fn the_turn_is_held_by_one_scan_at_a_time_and_a_stop_frees_a_waiter() {
        let turn = HashTurn::default();
        let never = AtomicBool::new(false);
        let held = turn.take(&never).expect("free");
        let (took_tx, took_rx) = mpsc::channel();
        let waiter = {
            let turn = turn.clone();
            std::thread::spawn(move || {
                let never = AtomicBool::new(false);
                let _held = turn.take(&never).expect("given back");
                took_tx.send(()).unwrap();
            })
        };
        assert!(
            took_rx.recv_timeout(Duration::from_millis(400)).is_err(),
            "no second read while the turn is held"
        );
        drop(held);
        took_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the waiter takes the turn once it is given back");
        waiter.join().unwrap();

        let _held = turn.take(&never).expect("free again");
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stopped = {
            let (turn, stop) = (turn.clone(), std::sync::Arc::clone(&stop));
            std::thread::spawn(move || turn.take(&stop).is_none())
        };
        stop.store(true, Ordering::Relaxed);
        assert!(stopped.join().unwrap(), "a stop frees a scan still waiting");
    }
}
