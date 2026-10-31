//! What a driver owes the socket: the bytes the session framed, in order, and
//! the clock on how long the peer may leave them unread.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

/// How long a socket owed bytes may move none before the connection ends:
/// aMule's `CONNECTION_TIMEOUT` (`protocol/ed2k/Constants.h:34`), which ends a
/// client socket that moved none for that long (`ClientTCPSocket.cpp:226`). A
/// write that takes a byte re-arms it, and so does a reading of the socket's
/// send side past the last one: a slow reader drains a full socket for longer
/// than this with no write taken. Unlike aMule's clock this one hears nothing
/// the peer sends, because a peer that asks and never reads has not moved the
/// socket that is stuck (ADR-0031).
pub const WRITE_STALL_BOUND: Duration = Duration::from_secs(40);

/// Unwritten bytes past which the driver stops reading: more than a whole
/// request's three blocks, framed, so a block in hand never stops the read.
const READ_PAUSE_BYTES: usize = 1 << 20;

/// The byte queue of one connection.
#[derive(Default)]
pub(super) struct Outgoing {
    chunks: VecDeque<Arc<[u8]>>,
    /// How far into the front chunk the socket has taken.
    written: usize,
    /// The bytes left, across every chunk.
    unwritten: usize,
    /// A write since the last flush: an obfuscated stream may hold the tail
    /// of what it said it took.
    unflushed: bool,
    stall_at: Option<Instant>,
}

impl Outgoing {
    /// Queue one chunk behind the rest.
    pub(super) fn push(&mut self, bytes: Arc<[u8]>) {
        if bytes.is_empty() {
            return;
        }
        if self.is_idle() {
            self.stall_at = Some(Instant::now() + WRITE_STALL_BOUND);
        }
        self.unwritten += bytes.len();
        self.chunks.push_back(bytes);
        self.unflushed = true;
    }

    /// Nothing is owed: every byte handed over is in the kernel.
    pub(super) fn is_idle(&self) -> bool {
        self.chunks.is_empty() && !self.unflushed
    }

    /// Whether the driver may read on.
    pub(super) fn has_room(&self) -> bool {
        self.unwritten < READ_PAUSE_BYTES
    }

    /// When a write that moves nothing more ends the connection.
    pub(super) fn stall_at(&self) -> Option<Instant> {
        self.stall_at
    }

    /// One step: as much of the front chunk as the socket takes, or the flush
    /// when no chunk is left. Cancel-safe: nothing here changes until the
    /// socket has answered, and the next step offers it the same bytes.
    pub(super) async fn advance<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let Some(chunk) = self.chunks.front() else {
            writer.flush().await?;
            self.unflushed = false;
            self.stall_at = None;
            return Ok(());
        };
        let taken = writer.write(&chunk[self.written..]).await?;
        if taken == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        self.written += taken;
        self.unwritten -= taken;
        if self.written == chunk.len() {
            self.chunks.pop_front();
            self.written = 0;
        }
        self.stall_at = Some(Instant::now() + WRITE_STALL_BOUND);
        Ok(())
    }
}
