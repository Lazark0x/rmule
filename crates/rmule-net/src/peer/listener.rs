//! Inbound peer listener: binds the advertised eD2k listen port as a **Family
//! Pair** (ADR-0085 amending ADR-0031 — two listeners, one accept pump) and
//! yields accepted peer `Connection`s. Pull model — the caller (core) owns the
//! accept loop; this type owns sockets, not policy.
use std::io;
use std::net::{SocketAddr, SocketAddrV4};

use crate::driver::CryptStream;
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{PeerEndpoint, is_plaintext_marker};
use tokio::io::AsyncReadExt;

use crate::family::{FamilyBinds, FamilySelection, TcpFamilyPair};
use crate::peer::inbound::{InboundSource, PushBack};
use crate::peer::obfuscation::{AwaitedTesters, ObfuscationPolicy, PeerObfuscationTransport};
use crate::peer::{ConnectOptions, Connection, PeerNetError};

/// What one accept admitted, told apart where the byte-0 discrimination
/// decides it (ADR-0046 "Test Connections") so no reader downstream can take
/// a test for a peer.
pub enum Admitted {
    /// An ordinary peer connection: obfuscated, or plain where the policy
    /// admits plain.
    Peer(Connection),
    /// A **Test Connection**: a plain dial under
    /// [`ObfuscationPolicy::Required`] from an address the caller's
    /// [`AwaitedTesters`] awaits a reachability test from. It may finish the
    /// hello exchange the test needs and is served nothing else.
    TestConnection(Connection),
}

/// The bound listen sockets — one per **Address Family**, behind one accept
/// pump. Holds no per-peer state: each accept hands back a fully driven
/// [`Connection`] and the caller decides what to do with it.
pub struct PeerListener {
    inner: TcpFamilyPair,
}

impl PeerListener {
    /// Bind the local listen port in both **Address Families**. Pass port 0 to
    /// let the OS choose; both families then share the resolved port, read back
    /// via [`local_port`](Self::local_port).
    ///
    /// # Errors
    /// [`PeerNetError::Bind`] only when no family bound at all.
    pub async fn bind_port(port: u16, selection: FamilySelection) -> Result<Self, PeerNetError> {
        TcpFamilyPair::bind(port, selection)
            .await
            .map(|inner| Self { inner })
            .map_err(|source| PeerNetError::Bind { source })
    }

    /// Bind one literal IPv4 address — a loopback listener, where the address
    /// itself is the point and there is no second family to pair with.
    ///
    /// # Errors
    /// [`PeerNetError::Bind`] if that address could not be bound.
    pub async fn bind(addr: SocketAddrV4) -> Result<Self, PeerNetError> {
        TcpFamilyPair::bind_literal(SocketAddr::V4(addr))
            .await
            .map(|inner| Self { inner })
            .map_err(|source| PeerNetError::Bind { source })
    }

    /// The actually-bound port (resolved if 0 was requested) — the port that
    /// must be advertised to the eD2k server at login, true in both families.
    #[must_use]
    pub const fn local_port(&self) -> u16 {
        self.inner.local_port()
    }

    /// What the pair's binds did — which families came up, and why any other
    /// did not.
    #[must_use]
    pub const fn binds(&self) -> &FamilyBinds {
        self.inner.binds()
    }

    /// Await and accept one inbound peer connection, returning it as a
    /// bidirectional `Connection` driven from the dialer's hello. Pull
    /// model: the caller loops over `accept` and owns backpressure.
    /// `options.connect_timeout` is unused on this path (the TCP
    /// connection already exists); `hello_timeout` bounds the wait for the
    /// dialer's hello.
    ///
    /// # Errors
    /// [`PeerNetError::Accept`] on an accept or handshake-read failure, and
    /// [`PeerNetError::PlaintextRefused`] when policy requires obfuscation and
    /// the dialer opened in plaintext.
    pub async fn accept(
        &self,
        ctx: PeerHandshakeContext,
        options: ConnectOptions,
    ) -> Result<Connection, PeerNetError> {
        match self.admit(|| (ctx, options), None).await? {
            Admitted::Peer(connection) => Ok(connection),
            Admitted::TestConnection(connection) => Err(PeerNetError::PlaintextRefused {
                peer: connection.peer_endpoint(),
            }),
        }
    }

    /// Accept one inbound connection, reading the handshake context and
    /// options only once a TCP connection has arrived — a listener that waits
    /// long between peers would otherwise answer with whatever was true when
    /// it *began* waiting, a Kad node started meanwhile, say, missing from the
    /// hello's `CT_EMULE_UDPPORTS` — and admitting a plain dial
    /// under [`ObfuscationPolicy::Required`] as an [`Admitted::TestConnection`]
    /// when `awaited` awaits a test from its address (ADR-0046).
    ///
    /// # Errors
    /// As [`accept`](Self::accept); `PlaintextRefused` only for a plain dial
    /// under `Required` that `awaited` does not await.
    pub async fn accept_with(
        &self,
        fresh: impl FnOnce() -> (PeerHandshakeContext, ConnectOptions),
        awaited: &dyn AwaitedTesters,
    ) -> Result<Admitted, PeerNetError> {
        self.admit(fresh, Some(awaited)).await
    }

    async fn admit(
        &self,
        fresh: impl FnOnce() -> (PeerHandshakeContext, ConnectOptions),
        awaited: Option<&dyn AwaitedTesters>,
    ) -> Result<Admitted, PeerNetError> {
        let (stream, peer) = InboundSource::accept(self)
            .await
            .map_err(|source| PeerNetError::Accept { source })?;
        let (ctx, options) = fresh();

        // No obfuscation configured: plaintext accept, no byte-0 read.
        let Some(config) = options.obfuscation else {
            return Ok(Admitted::Peer(Connection::from_accepted(
                stream, peer, ctx, options,
            )));
        };

        // Obfuscation enabled: byte-0 discrimination (ADR-0042). Read the first
        // byte and push it back (bounded by `hello_timeout` so a silent peer
        // cannot hang accept); a known plaintext protocol marker is plaintext,
        // anything else is an obfuscated handshake.
        let mut stream = stream;
        let mut first = [0u8; 1];
        let read = tokio::time::timeout(options.hello_timeout, stream.read(&mut first))
            .await
            .map_err(|_| PeerNetError::Accept {
                source: io::Error::new(io::ErrorKind::TimedOut, "peer silent before handshake"),
            })?
            .map_err(|source| PeerNetError::Accept { source })?;
        let obfuscated = read == 1 && !is_plaintext_marker(first[0]);
        // A peer that closed before its first byte pushes nothing back; the
        // driver then sees the same end of stream the read did.
        let stream = PushBack::new(stream, (read == 1).then_some(first[0]));

        if obfuscated {
            tracing::debug!(
                %peer,
                first_byte = format_args!("{:#04x}", first[0]),
                policy = ?config.policy,
                "inbound peer connection: obfuscated opener; handshake keyed on our user hash"
            );
            let transport = PeerObfuscationTransport::responder(ctx.identity.user_hash());
            let stream = CryptStream::new(stream, transport);
            return Ok(Admitted::Peer(Connection::from_accepted(
                stream, peer, ctx, options,
            )));
        }
        let first_byte = (read == 1).then_some(first[0]);
        if config.policy != ObfuscationPolicy::Required {
            tracing::debug!(
                %peer,
                ?first_byte,
                policy = ?config.policy,
                "inbound peer connection: plain opener, admitted"
            );
            return Ok(Admitted::Peer(Connection::from_accepted(
                stream, peer, ctx, options,
            )));
        }
        // Required, and the dialer opened plain: refused unless it is a test
        // this node is awaiting (aMule `EncryptedStreamSocket.cpp:377-397`),
        // which is then marked so it can be served nothing.
        if awaited.is_some_and(|testers| testers.awaits_test_from(peer.ip())) {
            tracing::debug!(
                %peer,
                ?first_byte,
                "inbound peer connection: plain opener under Required from an awaited tester — \
                 admitted as a Test Connection"
            );
            Ok(Admitted::TestConnection(Connection::from_accepted(
                stream, peer, ctx, options,
            )))
        } else {
            tracing::debug!(
                %peer,
                ?first_byte,
                "inbound peer connection: plain opener under Required from an address no test \
                 is awaited from — refused"
            );
            Err(PeerNetError::PlaintextRefused { peer })
        }
    }
}

impl InboundSource for PeerListener {
    type Stream = tokio::net::TcpStream;

    async fn accept(&self) -> io::Result<(Self::Stream, PeerEndpoint)> {
        self.inner.accept().await
    }
}
