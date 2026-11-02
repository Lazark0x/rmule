//! The enactor of a block read (ADR-0031): each read runs on a task of its own
//! and its end comes back to the loop as one more input, so a slow disk stalls
//! the blocks behind it and no peer's answer. The [`ServeState`] decides what
//! is read and when; this holds only the turns, which go first asked first.
//!
//! [`ServeState`]: super::state::ServeState

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rmule_primitives::PeerEndpoint;
use tokio::sync::{Semaphore, mpsc};

use super::state::{BlockRead, ReadFrom};
use crate::content::{CheckedReadError, ContentFileStore};
use crate::served_downloads::{ReadTarget, ServedDownloads};

/// Reads out across all flows. A blocking read cannot be cancelled, so this is
/// also how many a dead mount can hold. Not measured.
const READS_AT_ONCE: usize = 8;

/// How a read ended.
#[derive(Debug)]
pub(super) enum ReadEnd {
    Bytes(Vec<u8>),
    /// A registry row's file would not be read.
    Failed,
    /// A Served Download's file is not the one `target` named.
    Changed {
        target: Option<ReadTarget>,
    },
    /// A Served Download's paths would not be read, or `None`: its entry has
    /// ended.
    Unreadable {
        target: Option<ReadTarget>,
    },
}

/// A read's end, on its way to the serve loop.
#[derive(Debug)]
pub(super) struct ReadLanded {
    pub(super) peer: PeerEndpoint,
    pub(super) flow: u64,
    pub(super) block: BlockRead,
    pub(super) end: ReadEnd,
}

/// One read a flow asked.
pub(super) struct FlowRead {
    pub(super) peer: PeerEndpoint,
    pub(super) flow: u64,
    pub(super) from: ReadFrom,
    pub(super) block: BlockRead,
}

/// Starts reads, [`READS_AT_ONCE`] at a time.
pub(super) struct BlockReader {
    landed_tx: mpsc::Sender<ReadLanded>,
    turns: Arc<Semaphore>,
    /// The Served Downloads a read of one takes its target from at its turn.
    served: ServedDownloads,
}

impl BlockReader {
    /// A reader saying each read's end on `landed_tx`.
    pub(super) fn new(landed_tx: mpsc::Sender<ReadLanded>, served: ServedDownloads) -> Self {
        Self {
            landed_tx,
            turns: Arc::new(Semaphore::new(READS_AT_ONCE)),
            served,
        }
    }

    /// Read away from the serve loop. A read whose flow is over by its turn,
    /// as `ended_through` says, is not started.
    pub(super) fn start(&self, read: FlowRead, ended_through: Arc<AtomicU64>) {
        let turns = Arc::clone(&self.turns);
        let landed_tx = self.landed_tx.clone();
        let served = self.served.clone();
        tokio::spawn(async move {
            let FlowRead {
                peer,
                flow,
                from,
                block,
            } = read;
            let Ok(_turn) = turns.acquire_owned().await else {
                return;
            };
            if ended_through.load(Ordering::Relaxed) >= flow {
                return;
            }
            let end = read_block(from, block, &served).await;
            // The loop that would read this is gone: nothing is owed to it.
            let _ = landed_tx
                .send(ReadLanded {
                    peer,
                    flow,
                    block,
                    end,
                })
                .await;
        });
    }
}

async fn read_block(from: ReadFrom, block: BlockRead, served: &ServedDownloads) -> ReadEnd {
    let len = block.end - block.start;
    if let ReadFrom::Row(path) = from {
        return match ContentFileStore::read_range(&path, block.start, len).await {
            Ok(bytes) => ReadEnd::Bytes(bytes),
            Err(error) => {
                tracing::warn!(%error, ?block, path = %path.display(), "serve read failed; the file is no longer offered");
                ReadEnd::Failed
            }
        };
    }
    // Aimed here, at the read's turn and not at the ask: a swap or a Pause
    // may have moved the entry while the block waited (ADR-0113).
    let Some(target) = served.read_target(block.file_hash) else {
        return ReadEnd::Unreadable { target: None };
    };
    match ContentFileStore::read_checked(&target, block.start, len).await {
        Ok(bytes) => ReadEnd::Bytes(bytes),
        // A Served Download's bytes: read only through a handle proven to be
        // the file its range was read from (ADR-0113).
        Err(CheckedReadError::Changed) => {
            tracing::warn!(?block, path = %target.path.display(), "a checked read found another file than its download's");
            ReadEnd::Changed {
                target: Some(target),
            }
        }
        Err(CheckedReadError::Unreadable(error)) => {
            tracing::warn!(%error, ?block, path = %target.path.display(), "a checked read could not read its download's file");
            ReadEnd::Unreadable {
                target: Some(target),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::time::{Duration, SystemTime};

    use rmule_primitives::FileHash;

    use super::*;
    use crate::file_key::FileKey;
    use crate::served_downloads::PartFileIdentity;
    use crate::served_downloads::leased::{Leased, leased};

    /// The disk can hold a read long after it was decided: it is checked as
    /// the entry stands when its turn comes, so a Pause meanwhile counts.
    #[tokio::test]
    async fn a_read_waiting_for_its_turn_is_checked_as_the_entry_stands_at_the_turn() {
        let dir = tempfile::tempdir().unwrap();
        let file_hash = FileHash::from_bytes([0x44; FileHash::BYTE_LEN]);
        let Leased {
            cell,
            lease,
            record,
            ..
        } = leased(file_hash, dir.path().join("a.bin"));
        let part = record.paths().part_path();
        std::fs::write(part, [0xA7; 300]).unwrap();
        let held = File::open(part).unwrap();
        let key = FileKey::of_open(&held).unwrap();
        lease.record_identity(PartFileIdentity::while_written(key));

        let (landed_tx, mut landed_rx) = mpsc::channel(1);
        let reader = BlockReader::new(landed_tx, cell);
        let turns = Arc::clone(&reader.turns)
            .acquire_many_owned(READS_AT_ONCE as u32)
            .await
            .unwrap();
        let read = FlowRead {
            peer: "203.0.113.9:4000".parse().unwrap(),
            flow: 1,
            from: ReadFrom::Download,
            block: BlockRead {
                file_hash,
                start: 0,
                end: 100,
            },
        };
        reader.start(read, Arc::new(AtomicU64::new(0)));
        tokio::task::yield_now().await;

        let at_rest = PartFileIdentity::at_rest(key, &held.metadata().unwrap()).unwrap();
        lease.record_identity(at_rest);
        File::options()
            .write(true)
            .open(part)
            .unwrap()
            .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(86_400))
            .unwrap();
        drop(turns);

        let landed = landed_rx.recv().await.unwrap();
        assert!(matches!(landed.end, ReadEnd::Changed { .. }));
    }
}
