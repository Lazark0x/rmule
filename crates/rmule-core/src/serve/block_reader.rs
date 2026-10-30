//! The enactor of a block read (ADR-0031): each read runs on a task of its own
//! and its end comes back to the loop as one more input, so a slow disk stalls
//! the blocks behind it and no peer's answer. The [`ServeState`] decides what
//! is read and when; this holds only the turns, which go first asked first.
//!
//! [`ServeState`]: super::state::ServeState

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rmule_primitives::PeerEndpoint;
use tokio::sync::{Semaphore, mpsc};

use super::state::BlockRead;
use crate::content::{CheckedReadError, ContentFileStore};
use crate::served_downloads::{PartFileIdentity, ReadCheck};

/// Reads out across all flows. A blocking read cannot be cancelled, so this is
/// also how many a dead mount can hold. Not measured.
const READS_AT_ONCE: usize = 8;

/// How a read ended.
#[derive(Debug)]
pub(super) enum ReadEnd {
    Bytes(Vec<u8>),
    /// A registry row's file would not be read.
    Failed,
    /// A Served Download's file is not the one `checked` named.
    Changed {
        checked: Option<PartFileIdentity>,
    },
    /// A Served Download's paths would not be read.
    Unreadable {
        checked: Option<PartFileIdentity>,
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
    pub(super) path: PathBuf,
    pub(super) block: BlockRead,
    pub(super) check: Option<ReadCheck>,
}

/// Starts reads, [`READS_AT_ONCE`] at a time.
pub(super) struct BlockReader {
    landed_tx: mpsc::Sender<ReadLanded>,
    turns: Arc<Semaphore>,
}

impl BlockReader {
    /// A reader saying each read's end on `landed_tx`.
    pub(super) fn new(landed_tx: mpsc::Sender<ReadLanded>) -> Self {
        Self {
            landed_tx,
            turns: Arc::new(Semaphore::new(READS_AT_ONCE)),
        }
    }

    /// Read away from the serve loop. A read whose flow is over by its turn,
    /// as `ended_through` says, is not started.
    pub(super) fn start(&self, read: FlowRead, ended_through: Arc<AtomicU64>) {
        let turns = Arc::clone(&self.turns);
        let landed_tx = self.landed_tx.clone();
        tokio::spawn(async move {
            let FlowRead {
                peer,
                flow,
                path,
                block,
                check,
            } = read;
            let Ok(_turn) = turns.acquire_owned().await else {
                return;
            };
            if ended_through.load(Ordering::Relaxed) >= flow {
                return;
            }
            let end = read_block(&path, block, check).await;
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

async fn read_block(path: &std::path::Path, block: BlockRead, check: Option<ReadCheck>) -> ReadEnd {
    let len = block.end - block.start;
    let Some(check) = check else {
        return match ContentFileStore::read_range(path, block.start, len).await {
            Ok(bytes) => ReadEnd::Bytes(bytes),
            Err(error) => {
                tracing::warn!(%error, ?block, path = %path.display(), "serve read failed; the file is no longer offered");
                ReadEnd::Failed
            }
        };
    };
    match ContentFileStore::read_checked(path, &check, block.start, len).await {
        Ok(bytes) => ReadEnd::Bytes(bytes),
        // A Served Download's bytes: read only through a handle proven to be
        // the file its range was read from (ADR-0113).
        Err(CheckedReadError::Changed) => {
            tracing::warn!(?block, path = %path.display(), "a download's part file changed; its parts are no longer offered");
            ReadEnd::Changed {
                checked: check.identity,
            }
        }
        Err(CheckedReadError::Unreadable(error)) => {
            tracing::warn!(%error, ?block, path = %path.display(), "a download's part file could not be read; its parts are no longer offered");
            ReadEnd::Unreadable {
                checked: check.identity,
            }
        }
    }
}
