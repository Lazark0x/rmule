//! The first byte of accepted sockets, read beside the accept and not in it.
//! Under an obfuscation policy a socket is not a peer until that byte says
//! what it speaks (ADR-0042), and a socket may stay silent for the whole hello
//! wait: read in line, one silent connect would hold up every inbound link and
//! the server's port test behind it. So each read is its own task, and a held
//! socket costs a file descriptor and a task, which [`UNIDENTIFIED_SOCKET_BOUND`]
//! bounds.

use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use rmule_primitives::PeerEndpoint;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::task::{AbortHandle, JoinSet};

use crate::peer::PeerNetError;

/// Most accepted sockets held at once with no byte read from them. A client
/// speaks a round trip after its connect, stock aMule's hello being first on
/// the wire, so a socket that outlives this many arrivals is no client's. Past
/// it the longest silent socket is let go: refusing the newest instead would
/// hand this many silent connects the whole port.
pub const UNIDENTIFIED_SOCKET_BOUND: usize = 64;

/// A socket that spoke, or closed before speaking (`first_byte` of `None`).
pub(super) struct FirstRead {
    pub(super) stream: TcpStream,
    pub(super) peer: PeerEndpoint,
    pub(super) first_byte: Option<u8>,
}

/// The reads under way, oldest first.
#[derive(Default)]
pub(super) struct FirstReads {
    reading: JoinSet<Result<FirstRead, PeerNetError>>,
    oldest_first: VecDeque<AbortHandle>,
}

impl FirstReads {
    /// Read `stream`'s first byte for at most `wait`, letting the longest
    /// silent socket go when the bound is reached.
    pub(super) fn start(&mut self, stream: TcpStream, peer: PeerEndpoint, wait: Duration) {
        self.oldest_first.retain(|read| !read.is_finished());
        if self.oldest_first.len() >= UNIDENTIFIED_SOCKET_BOUND
            && let Some(longest_silent) = self.oldest_first.pop_front()
        {
            tracing::debug!("inbound sockets unidentified at the bound; closing the oldest");
            longest_silent.abort();
        }
        let read = self.reading.spawn(read_first_byte(stream, peer, wait));
        self.oldest_first.push_back(read);
    }

    /// The next read to finish. Pending while none is under way; cancel-safe.
    pub(super) async fn next(&mut self) -> Result<FirstRead, PeerNetError> {
        loop {
            match self.reading.join_next().await {
                Some(Ok(read)) => return read,
                // Let go at the bound.
                Some(Err(_)) => {}
                None => std::future::pending::<()>().await,
            }
        }
    }
}

async fn read_first_byte(
    mut stream: TcpStream,
    peer: PeerEndpoint,
    wait: Duration,
) -> Result<FirstRead, PeerNetError> {
    let mut first = [0u8; 1];
    let read = tokio::time::timeout(wait, stream.read(&mut first))
        .await
        .map_err(|_| PeerNetError::Accept {
            source: io::Error::new(io::ErrorKind::TimedOut, "peer silent before handshake"),
        })?
        .map_err(|source| PeerNetError::Accept { source })?;
    Ok(FirstRead {
        stream,
        peer,
        first_byte: (read == 1).then_some(first[0]),
    })
}
