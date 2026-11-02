//! Inbound peer listener: binds the advertised eD2k listen port as a **Family
//! Pair** (ADR-0085 amending ADR-0031 — two listeners, one accept pump) and
//! yields accepted peer `Connection`s. Pull model — the caller (core) owns the
//! accept loop; this type owns sockets, not policy.
use std::net::{SocketAddr, SocketAddrV4};

use crate::driver::CryptStream;
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::is_plaintext_marker;
use tokio::sync::Mutex;

use crate::family::{FamilyBinds, FamilySelection, TcpFamilyPair};
use crate::peer::first_read::{FirstRead, FirstReads};
use crate::peer::inbound::PushBack;
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
    /// The accepted sockets not heard from yet. Here and not in an accept's
    /// future, so one socket's silence holds up no other and a cancelled
    /// accept loses none.
    first_reads: Mutex<FirstReads>,
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
            .map(Self::over)
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
            .map(Self::over)
            .map_err(|source| PeerNetError::Bind { source })
    }

    fn over(inner: TcpFamilyPair) -> Self {
        Self {
            inner,
            first_reads: Mutex::default(),
        }
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
    /// dialer's hello. Cancel-safe: a socket whose first byte is awaited stays
    /// with the listener for the next accept.
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
        match self.admit(|| (ctx.clone(), options.clone()), None).await? {
            Admitted::Peer(connection) => Ok(connection),
            Admitted::TestConnection(connection) => Err(PeerNetError::PlaintextRefused {
                peer: connection.peer_endpoint(),
            }),
        }
    }

    /// Accept one inbound connection, reading the handshake context and
    /// options only once a socket is ready to be admitted — a listener that
    /// waits long between peers would otherwise answer with whatever was true
    /// when it *began* waiting, a Kad node started meanwhile, say, missing from
    /// the hello's `CT_EMULE_UDPPORTS` — and admitting a plain dial
    /// under [`ObfuscationPolicy::Required`] as an [`Admitted::TestConnection`]
    /// when `awaited` awaits a test from its address (ADR-0046).
    ///
    /// # Errors
    /// As [`accept`](Self::accept); `PlaintextRefused` only for a plain dial
    /// under `Required` that `awaited` does not await.
    pub async fn accept_with(
        &self,
        fresh: impl Fn() -> (PeerHandshakeContext, ConnectOptions),
        awaited: &dyn AwaitedTesters,
    ) -> Result<Admitted, PeerNetError> {
        self.admit(fresh, Some(awaited)).await
    }

    async fn admit(
        &self,
        fresh: impl Fn() -> (PeerHandshakeContext, ConnectOptions),
        awaited: Option<&dyn AwaitedTesters>,
    ) -> Result<Admitted, PeerNetError> {
        let mut first_reads = self.first_reads.lock().await;
        loop {
            tokio::select! {
                accepted = self.inner.accept() => {
                    let (stream, peer) =
                        accepted.map_err(|source| PeerNetError::Accept { source })?;
                    let (ctx, options) = fresh();
                    // No obfuscation configured: plaintext accept, no byte-0 read.
                    if options.obfuscation.is_none() {
                        return Ok(Admitted::Peer(Connection::from_accepted(
                            stream, peer, ctx, options,
                        )));
                    }
                    first_reads.start(stream, peer, options.hello_timeout);
                }
                read = first_reads.next() => {
                    let (ctx, options) = fresh();
                    return discriminate(read?, ctx, options, awaited);
                }
            }
        }
    }
}

/// Byte-0 discrimination (ADR-0042) of a socket whose first byte was read: a
/// known plaintext protocol marker is plaintext, anything else is an obfuscated
/// handshake.
fn discriminate(
    read: FirstRead,
    ctx: PeerHandshakeContext,
    options: ConnectOptions,
    awaited: Option<&dyn AwaitedTesters>,
) -> Result<Admitted, PeerNetError> {
    let FirstRead {
        stream,
        peer,
        first_byte,
    } = read;
    // A peer that closed before its first byte pushes nothing back; the
    // driver then sees the same end of stream the read did.
    let stream = PushBack::new(stream, first_byte);
    let Some(config) = options.obfuscation else {
        return Ok(Admitted::Peer(Connection::from_accepted(
            stream, peer, ctx, options,
        )));
    };

    if let Some(byte) = first_byte.filter(|byte| !is_plaintext_marker(*byte)) {
        tracing::debug!(
            %peer,
            first_byte = format_args!("{byte:#04x}"),
            policy = ?config.policy,
            "inbound peer connection: obfuscated opener; handshake keyed on our user hash"
        );
        let transport = PeerObfuscationTransport::responder(ctx.identity.user_hash());
        let stream = CryptStream::new(stream, transport);
        return Ok(Admitted::Peer(Connection::from_accepted(
            stream, peer, ctx, options,
        )));
    }
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
