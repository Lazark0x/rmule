//! What the serve loop hands one link's task: an answer as it stands, or a
//! block to send. Only a block can come too late: its flow may have ended, and
//! a block for deflate is deflated on the blocking pool, awaited by the task of
//! the one connection it serves, so it holds neither an async worker nor the
//! serve loop, and that connection's blocks keep their order (ADR-0031).

use std::sync::atomic::{AtomicU64, Ordering};

use rmule_peer::{ServerCommand, deflate_block};

use super::state::BlockRead;
use crate::adapters::ServeOutput;
use crate::content::on_pool;

/// One entry of a **Link Outbox**.
#[derive(Debug)]
pub(super) enum LinkOutput {
    /// Send this as it is, ahead of the blocks.
    Ready(ServeOutput),
    /// Send this block, behind the one before it.
    Block(LinkBlock),
}

impl From<ServeOutput> for LinkOutput {
    fn from(output: ServeOutput) -> Self {
        Self::Ready(output)
    }
}

/// `block` of `flow`, whose `bytes` these are, with `deflate` deflated if that
/// is smaller.
#[derive(Debug)]
pub(super) struct LinkBlock {
    pub(super) flow: u64,
    pub(super) block: BlockRead,
    pub(super) bytes: Vec<u8>,
    pub(super) deflate: bool,
}

impl LinkBlock {
    /// What goes down the connection, or nothing for a block of a flow
    /// `ended_through` covers. Off the async runtime for a block to deflate.
    pub(super) async fn ready(self, ended_through: &AtomicU64) -> Option<ServeOutput> {
        let Self {
            flow,
            block,
            bytes,
            deflate,
        } = self;
        if ended_through.load(Ordering::Relaxed) >= flow {
            return None;
        }
        let command = if deflate {
            deflated(block, bytes, deflate_block).await
        } else {
            ServerCommand::SendBlock {
                file_hash: block.file_hash,
                start: block.start,
                end: block.end,
                bytes,
            }
        };
        Some(ServeOutput::Server(command))
    }
}

/// `block` as `deflate` leaves it, on the blocking pool: the stream when it
/// makes one that `nBlockSize`'s `u32` can name, else `bytes` plain.
async fn deflated(
    block: BlockRead,
    bytes: Vec<u8>,
    deflate: impl FnOnce(&[u8]) -> Option<Vec<u8>> + Send + 'static,
) -> ServerCommand {
    let BlockRead {
        file_hash,
        start,
        end,
    } = block;
    on_pool(
        move || match deflate(&bytes).filter(|stream| u32::try_from(stream.len()).is_ok()) {
            Some(stream) => ServerCommand::SendDeflatedBlock {
                file_hash,
                start,
                end,
                stream,
            },
            None => ServerCommand::SendBlock {
                file_hash,
                start,
                end,
                bytes,
            },
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use rmule_primitives::FileHash;

    use super::*;

    fn block() -> BlockRead {
        BlockRead {
            file_hash: FileHash::from_bytes([0x61; FileHash::BYTE_LEN]),
            start: 0,
            end: 4,
        }
    }

    /// The test's runtime has one worker, and the deflate parks until this
    /// task runs again: inline, it would hold the worker, give up and go plain.
    #[tokio::test(flavor = "current_thread")]
    async fn a_deflate_leaves_the_async_worker_free() {
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let task = tokio::spawn(deflated(block(), vec![1; 4], move |_| {
            go_rx
                .recv_timeout(Duration::from_secs(5))
                .ok()
                .map(|()| vec![9])
        }));

        tokio::task::yield_now().await;
        let _ = go_tx.send(());

        assert!(
            matches!(
                task.await.unwrap(),
                ServerCommand::SendDeflatedBlock { stream, .. } if stream == [9]
            ),
            "the worker went on while the block deflated",
        );
    }

    #[tokio::test]
    async fn a_block_of_an_ended_flow_goes_no_further() {
        let output = |flow| LinkBlock {
            flow,
            block: block(),
            bytes: vec![1; 4],
            deflate: true,
        };
        let ended_through = AtomicU64::new(2);

        assert!(output(2).ready(&ended_through).await.is_none());
        assert!(output(3).ready(&ended_through).await.is_some());
    }

    #[tokio::test]
    async fn a_block_that_does_not_shrink_goes_plain() {
        let sent = deflated(block(), vec![1; 4], |_| None).await;
        assert!(matches!(sent, ServerCommand::SendBlock { bytes, .. } if bytes == [1; 4]));
    }
}
