//! What a driver owes the socket: the bytes the session framed, in order, and
//! the clock on how long the peer may leave them unread.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use rmule_os::tcp_send::{SendProgress, send_progress};
use tokio::io::{AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
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

/// How long after a byte is taken the stall clock reads the socket for the
/// count [`WRITE_STALL_BOUND`] compares against. A socket that keeps taking
/// bytes never reaches it, so the hot path pays no call, and a socket that
/// stuck at once ends at the bound rather than a bound later.
const FIRST_READING_AFTER: Duration = Duration::from_secs(1);

/// Unwritten bytes past which the driver stops reading: more than a whole
/// request's three blocks, framed, so a block in hand never stops the read.
const READ_PAUSE_BYTES: usize = 1 << 20;

/// A stream the driver can ask how far its written bytes have got, which is
/// what the [`WRITE_STALL_BOUND`] hears on a socket that takes no write. A
/// stream above a socket answers for that socket, so the crypt layer and
/// every other wrapper pass the question down. One with no kernel under it
/// answers `None`, the default, and the bound then counts writes alone.
pub trait SendSide {
    /// One reading of the send side, or `None` when there is none to take.
    fn send_progress(&self) -> Option<SendProgress> {
        None
    }
}

impl SendSide for TcpStream {
    fn send_progress(&self) -> Option<SendProgress> {
        send_progress(self)
    }
}

impl SendSide for DuplexStream {}

impl<S: SendSide + ?Sized> SendSide for Box<S> {
    fn send_progress(&self) -> Option<SendProgress> {
        (**self).send_progress()
    }
}

/// The clock on a socket owed bytes that takes none.
#[derive(Clone, Copy)]
enum StallClock {
    /// A byte was just taken, and nothing has been read since.
    Armed {
        /// When the first reading is taken.
        reading_at: Instant,
        /// When a socket that moved nothing ends the connection.
        bound_at: Instant,
    },
    /// Waiting out the bound against the last reading.
    Watching {
        bound_at: Instant,
        /// What the socket said last, `None` when it said nothing.
        last: Option<SendProgress>,
    },
}

impl StallClock {
    fn armed() -> Self {
        let now = Instant::now();
        Self::Armed {
            reading_at: now + FIRST_READING_AFTER,
            bound_at: now + WRITE_STALL_BOUND,
        }
    }

    const fn look_at(self) -> Instant {
        match self {
            Self::Armed { reading_at, .. } => reading_at,
            Self::Watching { bound_at, .. } => bound_at,
        }
    }

    /// Hear the socket at [`look_at`](Self::look_at): the clock to run on, or
    /// `None` when the socket is stuck. No reading never counts as movement.
    fn heard(self, reading: Option<SendProgress>) -> Option<Self> {
        match (self, reading) {
            (Self::Armed { bound_at, .. }, last) => Some(Self::Watching { bound_at, last }),
            (
                Self::Watching {
                    last: Some(last), ..
                },
                Some(now),
            ) if now.is_past(last) => Some(Self::Watching {
                bound_at: Instant::now() + WRITE_STALL_BOUND,
                last: reading,
            }),
            (Self::Watching { .. }, _) => None,
        }
    }
}

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
    stall: Option<StallClock>,
}

impl Outgoing {
    /// Queue one chunk behind the rest.
    pub(super) fn push(&mut self, bytes: Arc<[u8]>) {
        if bytes.is_empty() {
            return;
        }
        if self.is_idle() {
            self.stall = Some(StallClock::armed());
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

    /// When the stall clock next wants to hear the socket.
    pub(super) fn look_at(&self) -> Option<Instant> {
        self.stall.map(StallClock::look_at)
    }

    /// Hear the socket at [`look_at`](Self::look_at), with what it said.
    /// `true` when it is stuck, which ends the connection.
    pub(super) fn is_stuck(&mut self, reading: Option<SendProgress>) -> bool {
        self.stall = self.stall.and_then(|clock| clock.heard(reading));
        self.stall.is_none()
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
            self.stall = None;
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
        self.stall = Some(StallClock::armed());
        Ok(())
    }
}
