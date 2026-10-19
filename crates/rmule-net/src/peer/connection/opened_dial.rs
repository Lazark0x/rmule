//! A peer dial up to its hello: the TCP connect and, for an obfuscated dial,
//! the crypt handshake, each under its own deadline, with no byte of the
//! hello sent. The hello is a separate step so a dial the peer's own link may
//! overtake can still be let go unheard (ADR-0107 invariant 7): the far side
//! keeps the socket it reads rmule's `OP_HELLO` on (`ClientList.cpp:400-403`).

use std::time::Duration;

use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{PeerEndpoint, UserHash};
use tokio::net::TcpStream;

use super::Connection;
use crate::driver::{CryptStream, DriverError};
use crate::peer::obfuscation::PeerObfuscationTransport;
use crate::peer::{ConnectOptions, PeerNetError};

/// A dial whose socket is up — and, when obfuscated, whose crypt handshake
/// the peer answered — but whose hello has not gone out. [`hello`](Self::hello)
/// sends it; dropping the dial closes the socket with nothing said.
pub struct OpenedDial {
    pub(super) peer: PeerEndpoint,
    pub(super) stream: OpenedStream,
    pub(super) options: ConnectOptions,
}

impl OpenedDial {
    /// Where the dial reached the peer.
    #[must_use]
    pub const fn peer(&self) -> PeerEndpoint {
        self.peer
    }

    /// Send our hello as `ctx` and drive the session: the dial is a live
    /// [`Connection`] from here on.
    #[must_use]
    pub fn hello(self, ctx: PeerHandshakeContext) -> Connection {
        let Self {
            peer,
            stream,
            options,
        } = self;
        let session = Connection::dialing_session(peer, ctx, &options);
        match stream {
            OpenedStream::Plain(stream) => Connection::spawn(session, stream, options, peer),
            OpenedStream::Obfuscated(crypt) => Connection::spawn(session, crypt, options, peer),
        }
    }
}

/// The byte stream an opened dial carries: plain TCP, or the crypt layer
/// above it once the handshake is answered.
pub(super) enum OpenedStream {
    Plain(TcpStream),
    Obfuscated(CryptStream<TcpStream, PeerObfuscationTransport>),
}

/// Connect to `peer` inside `connect_timeout` and, toward a User Hash, run the
/// crypt handshake inside `crypt_timeout`: eagerly, so a peer that does not
/// answer it in kind surfaces here as a failed dial rather than a later
/// protocol violation on the session, and a peer that never answers ends the
/// dial as aMule's socket timeout ends it (`ClientTCPSocket.cpp:201-222`).
pub(super) async fn open_stream(
    peer: PeerEndpoint,
    connect_timeout: Duration,
    crypt_timeout: Duration,
    toward: Option<UserHash>,
) -> Result<OpenedStream, PeerNetError> {
    // The dial takes whatever family the endpoint carries (ADR-0085).
    let addr = std::net::SocketAddr::new(peer.ip(), peer.port());
    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| DriverError::ConnectTimeout)?
        .map_err(|source| PeerNetError::Connect { source })?;
    let Some(target) = toward else {
        return Ok(OpenedStream::Plain(stream));
    };
    let mut crypt = CryptStream::new(stream, PeerObfuscationTransport::initiator(target));
    tokio::time::timeout(crypt_timeout, crypt.complete_handshake())
        .await
        .map_err(|_| PeerNetError::CryptUnanswered)??;
    Ok(OpenedStream::Obfuscated(crypt))
}
