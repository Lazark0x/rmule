//! The public handle for one live peer conversation, dialed or accepted: it
//! spawns the driver (and capture) tasks and exposes the session as a command
//! sender plus an event receiver. Teardown — cooperative `shutdown` with a
//! grace period, abort on drop — is the harness's
//! [`SpawnHandles`].

use rmule_peer::{
    ConnectionCommand, ConnectionEvent, PeerCommand, PeerEvent, PeerHandshakeContext, PeerIdentity,
    PeerSession,
};
use rmule_primitives::{OutboundCrypt, PeerEndpoint, UserHash};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::Instrument;

use crate::driver::{
    ChannelCaps, CryptStream, DriverError, SpawnCapture, SpawnHandles, run_capture,
    spawn_connection,
};
use crate::peer::capture::{PeerCaptureFormat, event_to_toml};
use crate::peer::driver::PeerDriven;
use crate::peer::obfuscation::{ObfuscationPolicy, PeerObfuscationTransport, crypt_advertisement};
use crate::peer::{ConnectOptions, PeerNetError};

/// Which side of a stream this session is on — and therefore which side's
/// hello goes first.
///
/// For a TCP link the role *is* the constructor: `connect` dials, the listener
/// accepts. A NAT-T **Tunnel** (ADR-0091) needs it said out loud, because the
/// stream arrives already open and the role is a fact about which side punched
/// first — never a bit somebody set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerStreamRole {
    /// We opened the stream: our `OP_HELLO` goes first.
    Dialer,
    /// The peer opened it: we wait for the peer's hello and answer.
    Responder,
}

/// The stream shape a **callback dial-back** hands the serve pipeline: an
/// `AsyncRead + AsyncWrite` the admit seam can own outright, whether the bytes
/// ride plaintext TCP or a [`CryptStream`] above it.
///
/// A trait object rather than a generic return type, because the obfuscation
/// decision is a *runtime* reading of one requester's connect-options: one call
/// site dials, and what comes back differs per requester. Everything above this
/// line — the serve pipeline, the capture tap, `PeerSession` — then sees
/// plaintext bytes exactly as it does for an obfuscated *inbound* connection,
/// because the crypt layer is below the stream, not beside it.
pub trait DialedStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<S> DialedStream for S where S: AsyncRead + AsyncWrite + Unpin + Send {}

/// Public handle for one live peer conversation — dialed via
/// [`Self::connect`] or accepted via [`PeerListener`](crate::peer::PeerListener).
/// One peer per connection (ADR-0026): multi-peer scheduling is rmule-core's,
/// which holds many `Connection`s rather than asking one to carry many peers.
pub struct Connection {
    peer: PeerEndpoint,
    handles: SpawnHandles<PeerDriven, PeerNetError>,
}

impl Connection {
    /// Open a TCP connection to `peer`, drive the sans-I/O peer session,
    /// and surface events through `next_event`. Returns once TCP is up
    /// (or `connect_timeout` elapsed); hello timeout fires as a
    /// `ConnectionEvent::Disconnected { reason: HelloTimeout }`.
    ///
    /// Whether the dial is obfuscated is aMule's outbound rule
    /// ([`PeerCrypt::outbound`](rmule_primitives::PeerCrypt::outbound),
    /// ADR-0049), meeting the peer's stated stance
    /// ([`ConnectOptions::peer_crypt`]) with ours
    /// ([`ConnectOptions::obfuscation`]).
    ///
    /// # Errors
    /// [`PeerNetError::CryptIncompatible`] — before any socket — when a side
    /// that requires obfuscation meets one that cannot provide it, or the
    /// peer's hash to key it is not in hand;
    /// [`DriverError::ConnectTimeout`] / [`PeerNetError::Connect`] for a dial
    /// that does not come up; the crypt handshake's error when an obfuscated
    /// dial is not answered in kind — required or merely requested, there is
    /// no plaintext retry (ADR-0049), as aMule configures its
    /// socket once per `Connect`.
    pub async fn connect(
        peer: PeerEndpoint,
        ctx: PeerHandshakeContext,
        options: ConnectOptions,
    ) -> Result<Self, PeerNetError> {
        let ours = ObfuscationPolicy::stance_of(options.obfuscation.map(|config| config.policy));
        let crypt = options.peer_crypt.outbound(ours);
        if crypt == OutboundCrypt::Incompatible {
            return Err(PeerNetError::CryptIncompatible);
        }
        // The dial takes whatever family the endpoint carries (ADR-0085).
        let addr = std::net::SocketAddr::new(peer.ip(), peer.port());
        let stream = tokio::time::timeout(options.connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| DriverError::ConnectTimeout)?
            .map_err(|source| PeerNetError::Connect { source })?;
        let session = Self::dialing_session(peer, ctx, &options);

        let OutboundCrypt::Obfuscated { toward, .. } = crypt else {
            return Ok(Self::spawn(session, stream, options, peer));
        };

        // Drive the crypt handshake eagerly so a peer that does not answer it
        // surfaces here as a failed dial rather than a later protocol
        // violation on the session.
        let mut crypt = CryptStream::new(stream, PeerObfuscationTransport::initiator(toward));
        crypt.complete_handshake().await?;
        Ok(Self::spawn(session, crypt, options, peer))
    }

    /// Open a TCP stream to `peer` and hand it back **undriven** — no session,
    /// no hello, no driver task — obfuscating it toward `obfuscate_toward`'s
    /// **User Hash** when one is given.
    ///
    /// The seam a **callback dial-back** needs (ADR-0061 routes 2/4).
    /// Such a dial is not a conversation this caller will hold:
    /// the requester asked us to connect so that *it* can ask *us* for a file,
    /// so the connection belongs to the serve pipeline the moment it is open.
    /// Core therefore opens the stream here and hands it to the accept path's
    /// admit seam as the dialer's side, which answers it with the very
    /// handshake context and per-accept options an accepted socket gets —
    /// rather than building a second, differently-configured session beside it.
    ///
    /// Obfuscation belongs *here* rather than at that admit seam because the
    /// crypt handshake is the **dialer's** act: the initiator sends the first
    /// bytes, and it must do so before any session exists. `admit` keeps taking
    /// an already-open stream, and ADR-0042's byte-0 discrimination stays
    /// exactly where it is — on the accept side, reading whatever the wire
    /// carries. The key is the **target's** User Hash, never ours
    /// ([`PeerObfuscationTransport::initiator`]), which for a callback is the
    /// requester's hash out of its own `0x95` body.
    ///
    /// There is no plaintext re-dial when the crypt handshake fails, as with
    /// [`connect`](Self::connect): the requester told us its own crypt stance
    /// in the request it is now waiting on, so a peer that then cannot
    /// complete the handshake is not a peer to re-dial. aMule makes the same
    /// one-shot decision (`CUpDownClient::Connect`, `BaseClient.cpp#L1610` —
    /// the socket is configured once and a failure simply ends it).
    ///
    /// # Errors
    /// [`DriverError::ConnectTimeout`] when the connect outlives
    /// `connect_timeout`, [`PeerNetError::Connect`] for a refused or
    /// unreachable peer, and the crypt handshake's own I/O error when an
    /// obfuscated dial is not answered in kind.
    pub async fn dial_stream(
        peer: PeerEndpoint,
        connect_timeout: std::time::Duration,
        obfuscate_toward: Option<UserHash>,
    ) -> Result<Box<dyn DialedStream>, PeerNetError> {
        let addr = std::net::SocketAddr::new(peer.ip(), peer.port());
        let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| DriverError::ConnectTimeout)?
            .map_err(|source| PeerNetError::Connect { source })?;
        let Some(target) = obfuscate_toward else {
            return Ok(Box::new(stream));
        };
        // Eagerly, so a requester that cannot speak obfuscation surfaces as a
        // failed dial rather than as a doomed stream occupying a serve slot.
        let mut crypt = CryptStream::new(stream, PeerObfuscationTransport::initiator(target));
        crypt.complete_handshake().await?;
        Ok(Box::new(crypt))
    }

    /// The reusable **peer-TCP dial surface** (ADR-0058 firewall dial-back;
    /// ADR-0061 buddy / callback relays): dial `peer`, drive the eD2k handshake,
    /// and hand back the live connection the moment the peer identifies — paired
    /// with its proven [`PeerIdentity`]. Handshake events up to `Identified`
    /// are consumed here; everything after flows through [`Self::next_event`] as
    /// usual, so a caller either delivers a one-shot packet and
    /// [`shuts down`](Self::shutdown) (the firewall-check ack) or keeps driving
    /// the session (a relay entering a transfer).
    ///
    /// A refused dial is reported, never silent-panics: a TCP connect that never
    /// comes up surfaces [`connect`](Self::connect)'s error, and a peer that
    /// drops before completing its hello surfaces
    /// [`PeerNetError::HandshakeIncomplete`]. aMule treats a refused firewall
    /// dial-back as silent (`CClientList::RequestTCP`), so its caller drops the
    /// error rather than reacting.
    pub async fn connect_identified(
        peer: PeerEndpoint,
        ctx: PeerHandshakeContext,
        options: ConnectOptions,
    ) -> Result<(Self, PeerIdentity), PeerNetError> {
        let mut conn = Self::connect(peer, ctx, options).await?;
        loop {
            match conn.next_event().await {
                Some(PeerEvent::Connection(ConnectionEvent::Identified { identity })) => {
                    return Ok((conn, identity));
                }
                Some(PeerEvent::Connection(ConnectionEvent::Disconnected { reason })) => {
                    return Err(PeerNetError::HandshakeIncomplete(reason));
                }
                // Pre-identification chatter (our `HelloSent`, etc.): keep
                // draining until the peer proves who it is or the link drops.
                Some(_) => continue,
                // The driver task ended without ever surfacing a terminal event.
                None => return Err(DriverError::DriverDied.into()),
            }
        }
    }

    /// The outbound session a dial builds: `new_outbound` plus every
    /// advertisement the options carry.
    fn dialing_session(
        peer: PeerEndpoint,
        ctx: PeerHandshakeContext,
        options: &ConnectOptions,
    ) -> PeerSession {
        let mut session = PeerSession::new_outbound(peer, ctx);
        if let Some(config) = &options.secure_ident {
            session = session.with_secure_ident(config.clone());
        }
        if let Some(config) = &options.obfuscation {
            session = session.with_crypt_advertisement(crypt_advertisement(config.policy));
        }
        if let Some(ports) = options.udp_ports {
            session = session.with_udp_ports_advertisement(ports);
        }
        if let Some(address) = options.ipv6 {
            session = session.with_ipv6_advertisement(address);
        }
        if let Some(buddy) = options.serving_buddy {
            session = session.with_serving_buddy_advertisement(buddy);
        }
        if options.direct_udp_callback {
            session = session.with_direct_udp_callback_advertisement();
        }
        if let Some(nibble) = options.source_exchange_capture_override {
            session = session.with_source_exchange_capture_override(nibble);
        }
        if let Some(level) = options.extended_requests_capture_override {
            session = session.with_extended_requests_capture_override(level);
        }
        session
    }

    /// Drive a peer session over an **already-open stream** that is not a
    /// `TcpStream` — the ADR-0091 NAT-T **Tunnel** seam.
    ///
    /// This is the whole point of the tunnel being an `AsyncRead + AsyncWrite`:
    /// the session, the driver, the capture tap and — when the caller wraps the
    /// stream in one first — `CryptStream` are the same code that runs over TCP.
    /// Nothing below this line knows a punched UDP path is carrying it.
    ///
    /// `role` decides which side's hello opens the conversation, and with it
    /// which trigger the `HelloTimeout` has (ours unanswered vs. the peer's
    /// never arriving).
    pub fn over_stream<S>(
        stream: S,
        peer: PeerEndpoint,
        role: PeerStreamRole,
        ctx: PeerHandshakeContext,
        options: ConnectOptions,
    ) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        match role {
            PeerStreamRole::Dialer => Self::spawn(
                Self::dialing_session(peer, ctx, &options),
                stream,
                options,
                peer,
            ),
            PeerStreamRole::Responder => Self::from_accepted(stream, peer, ctx, options),
        }
    }

    /// Wrap an accepted inbound TCP stream in a bidirectional peer
    /// `Connection`. The session is built with `new_inbound` (we await the
    /// dialer's hello and reply), and the same driver as `connect` runs it:
    /// `start()` is an idempotent no-op for an inbound session, and the
    /// hello deadline applies the inverted-trigger `HelloTimeout` to the
    /// `AwaitingHello` state — so one driver serves both roles with no
    /// role branch here.
    pub(crate) fn from_accepted<S>(
        stream: S,
        peer: PeerEndpoint,
        ctx: PeerHandshakeContext,
        options: ConnectOptions,
    ) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut session = PeerSession::new_inbound(peer, ctx);
        if let Some(config) = &options.secure_ident {
            session = session.with_secure_ident(config.clone());
        }
        if let Some(config) = &options.obfuscation {
            session = session.with_crypt_advertisement(crypt_advertisement(config.policy));
        }
        if let Some(ports) = options.udp_ports {
            session = session.with_udp_ports_advertisement(ports);
        }
        if let Some(address) = options.ipv6 {
            session = session.with_ipv6_advertisement(address);
        }
        if let Some(buddy) = options.serving_buddy {
            session = session.with_serving_buddy_advertisement(buddy);
        }
        if options.direct_udp_callback {
            session = session.with_direct_udp_callback_advertisement();
        }
        Self::spawn(session, stream, options, peer)
    }

    fn spawn<S>(
        session: PeerSession,
        stream: S,
        options: ConnectOptions,
        peer: PeerEndpoint,
    ) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let peer_label = peer.to_string();
        let span = tracing::info_span!("peer_connection", peer = %peer_label);
        let capture_mode = options.capture_mode;
        let capture = options.capture_dir.as_ref().map(|dir| {
            let dir = dir.clone();
            SpawnCapture::<PeerDriven> {
                event_toml: event_to_toml,
                sink: Box::new(move |frames, events, finalize| {
                    Box::pin(async move {
                        let format = PeerCaptureFormat::new(peer_label, capture_mode);
                        let _ = run_capture(dir, format, frames, events, finalize).await;
                    })
                }),
            }
        });
        let (ended_tx, ended_rx) = tokio::sync::oneshot::channel::<()>();
        let handles = spawn_connection(
            stream,
            PeerDriven::new(session),
            ChannelCaps::default(),
            Some(options.hello_timeout),
            capture,
            move |driver| {
                async move {
                    let outcome = driver.await.map_err(PeerNetError::from);
                    drop(ended_tx);
                    outcome
                }
                .instrument(span)
            },
        );
        if let Some(follow) = options.ipv6_follow {
            tokio::spawn(follow_ipv6(follow, handles.commands.downgrade(), ended_rx));
        }
        Self { peer, handles }
    }

    /// The endpoint this link runs against — what was dialed, or what the
    /// listener accepted. Fixed at construction; the hello never revises it.
    #[must_use]
    pub const fn peer_endpoint(&self) -> PeerEndpoint {
        self.peer
    }

    /// A cloneable command sender into this connection's driver — the handle a
    /// caller **holds** to keep sending over this live link while someone else
    /// drives its events (rmule-core's buddy slot holds the accepted buddy's
    /// sender so ADR-0061 relays and pongs ride the *persistent* inbound link,
    /// aMule's `buddy->GetSocket()`). The driver serializes commands from every
    /// sender in arrival order; a send fails once the driver stops, which is
    /// the held handle's natural end-of-life signal.
    #[must_use]
    pub fn command_sender(&self) -> mpsc::Sender<PeerCommand> {
        self.handles.commands.clone()
    }

    /// Await this connection's next event. `None` once the driver has stopped
    /// and the stream is drained — the paired `Disconnected` has arrived by
    /// then, so the end is never silent.
    pub async fn next_event(&mut self) -> Option<PeerEvent> {
        self.handles.events.recv().await
    }

    /// Forward a command to the driver's session. Returns
    /// [`DriverError::Closed`] if the driver has already shut down and the
    /// channel is closed.
    pub async fn send(&self, command: PeerCommand) -> Result<(), PeerNetError> {
        self.handles
            .commands
            .send(command)
            .await
            .map_err(|_| DriverError::Closed.into())
    }

    /// Cooperative tear-down: send `Disconnect` and await the driver (then
    /// the capture writer) up to the harness's
    /// [`SHUTDOWN_GRACE`](crate::driver::SHUTDOWN_GRACE); a driver that does
    /// not exit in time is reported as `DriverDied` and aborted.
    pub async fn shutdown(self) -> Result<(), PeerNetError> {
        self.handles.shutdown().await
    }
}

/// Hand the session our Advertised IPv6 on every wake, until the link ends
/// (ADR-0087). Commands go through a weak sender, so following never keeps a
/// link open that its owners have let go.
async fn follow_ipv6(
    mut follow: crate::peer::Ipv6Follow,
    commands: mpsc::WeakSender<PeerCommand>,
    mut ended: tokio::sync::oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut ended => return,
            changed = follow.changed.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
        let Some(address) = (follow.read)() else {
            continue;
        };
        let Some(commands) = commands.upgrade() else {
            return;
        };
        let announce = PeerCommand::Connection(ConnectionCommand::AnnounceIpv6Change(address));
        if commands.send(announce).await.is_err() {
            return;
        }
    }
}
