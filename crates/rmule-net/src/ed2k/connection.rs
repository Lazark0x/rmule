//! The public handle for one live eD2k server session: dial or wrap a stream,
//! spawn the driver (and capture) tasks behind it, and expose the session as a
//! command sender plus an event receiver. Teardown — cooperative `shutdown`
//! with a grace period, abort on drop — is the harness's
//! [`SpawnHandles`].

use rmule_ed2k::{Ed2kCommand, Ed2kEvent, Ed2kSession};
use rmule_primitives::{Capabilities, ClientIdentity, CryptStance, ServerEndpoint};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::Instrument;

use crate::driver::{
    ChannelCaps, CryptStream, DriverError, SpawnCapture, SpawnHandles, run_capture,
    spawn_connection,
};
use crate::ed2k::capture::{Ed2kCaptureFormat, event_to_toml};
use crate::ed2k::driver::Ed2kDriven;
use crate::ed2k::{ConnectOptions, Ed2kNetError, ServerObfuscationTransport};

/// Public handle for one live eD2k session.
pub struct Connection {
    handles: SpawnHandles<Ed2kDriven, Ed2kNetError>,
    /// The address this session actually reached, when it was dialed rather
    /// than wrapped around a caller-supplied stream.
    resolved: Option<std::net::SocketAddr>,
}

impl Connection {
    /// Open a TCP connection to `endpoint` and start the session driver
    /// with default [`ConnectOptions`].
    pub async fn connect(
        endpoint: ServerEndpoint,
        identity: ClientIdentity,
    ) -> Result<Self, Ed2kNetError> {
        Self::connect_with_options(endpoint, identity, ConnectOptions::default()).await
    }

    /// Open a TCP connection with caller-supplied timeouts and capture
    /// directory. Returns once TCP is up — and, for an obfuscated dial, once
    /// the crypt handshake completed — or the connect timeout has elapsed;
    /// login outcome and any later `LoginTimeout` arrive as [`Ed2kEvent`]s on
    /// [`Self::next_event`].
    ///
    /// With [`ConnectOptions::obfuscated_port`] set, the dial goes to that
    /// port and the server form of the crypt handshake runs before the login
    /// (ADR-0042), bounded by the connect timeout; it is one attempt, and its
    /// failure is [`Ed2kNetError::CryptHandshake`] or the dial's own.
    pub async fn connect_with_options(
        endpoint: ServerEndpoint,
        identity: ClientIdentity,
        options: ConnectOptions,
    ) -> Result<Self, Ed2kNetError> {
        let port = options.obfuscated_port.unwrap_or_else(|| endpoint.port());
        // A-first with one AAAA fallback (ADR-0087 §4.7): a HighID *is* the
        // packed public IPv4, so preferring AAAA on a dual-stack server costs
        // one for nothing.
        let (stream, resolved) =
            crate::ed2k::resolve::connect_server(endpoint.host(), port, options.connect_timeout)
                .await
                .map_err(|error| match error.kind() {
                    std::io::ErrorKind::TimedOut => Ed2kNetError::from(DriverError::ConnectTimeout),
                    _ => Ed2kNetError::from(error),
                })?;
        // The login's `CT_SERVER_FLAGS` advertises our crypt stance
        // (ADR-0047); no obfuscation config keeps the crypt lights dark.
        let crypt_stance = options
            .obfuscation
            .map_or(CryptStance::disabled(), |config| {
                config.policy.crypt_stance()
            });
        let mut session = Ed2kSession::new(endpoint, identity)
            .with_capabilities(Capabilities::shipped(crypt_stance));
        if let Some(address) = options.advertised_ipv6 {
            session = session.with_ipv6_advertisement(address);
        }
        if let Some(ports) = options.udp_ports {
            session = session.with_udp_ports_advertisement(ports);
        }
        if options.obfuscated_port.is_none() {
            return Ok(Self::spawn_with_options(session, stream, options).with_resolved(resolved));
        }
        // Driven eagerly, so a server that does not take obfuscation on that
        // port surfaces here, as a failed dial, rather than as a later
        // disconnect the login would misread.
        let mut crypt = CryptStream::new(stream, ServerObfuscationTransport::client());
        match tokio::time::timeout(options.connect_timeout, crypt.complete_handshake()).await {
            Ok(Ok(())) => {
                Ok(Self::spawn_with_options(session, crypt, options).with_resolved(resolved))
            }
            Ok(Err(error)) => Err(Ed2kNetError::CryptHandshake(error)),
            Err(_) => Err(Ed2kNetError::CryptHandshake(std::io::Error::from(
                std::io::ErrorKind::TimedOut,
            ))),
        }
    }

    /// Tag this connection with the address it reached.
    fn with_resolved(mut self, resolved: std::net::SocketAddr) -> Self {
        self.resolved = Some(resolved);
        self
    }

    /// The address this session actually reached, or `None` when the caller
    /// brought its own stream.
    ///
    /// A consumer reads this for exactly one reason: **which family the session
    /// runs over**. `OP_SERVERIDENT`'s `CT_MOD_YOUR_IP` is a statement about
    /// IPv6 connectivity, so a reflection arriving over an IPv4 session must be
    /// ignored rather than adopted (ADR-0087 §4.3), and only the layer that
    /// dialed knows which it was.
    #[must_use]
    pub const fn resolved_addr(&self) -> Option<std::net::SocketAddr> {
        self.resolved
    }

    /// Spawn a driver over an arbitrary async byte stream using default
    /// options (no login timeout, no capture). Public for tests and
    /// alternative transports.
    pub fn spawn_with_stream<S>(session: Ed2kSession, stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let handles = spawn_connection(
            stream,
            Ed2kDriven::new(session),
            ChannelCaps::default(),
            None,
            None,
            |driver| async move { driver.await.map_err(Ed2kNetError::from) },
        );
        Self {
            handles,
            resolved: None,
        }
    }

    /// Spawn a driver with the provided [`ConnectOptions`] applied
    /// (login timeout, optional capture). Public for tests that bring
    /// their own stream.
    pub fn spawn_with_options<S>(session: Ed2kSession, stream: S, options: ConnectOptions) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let endpoint = session.endpoint();
        let identity = session.identity();
        let endpoint_label = format!("{}:{}", endpoint.host(), endpoint.port());
        let identity_summary = format!(
            "nickname={} tcp_port={} protocol_version={}",
            identity.nickname().to_display_string(),
            identity.tcp_port(),
            identity.protocol_version()
        );
        let span = tracing::info_span!("ed2k_session", server = %endpoint_label);
        let capture = options.capture_dir.as_ref().map(|dir| {
            let dir = dir.clone();
            SpawnCapture::<Ed2kDriven> {
                event_toml: event_to_toml,
                sink: Box::new(move |frames, events, finalize| {
                    Box::pin(async move {
                        let format = Ed2kCaptureFormat {
                            endpoint: endpoint_label,
                            identity_summary,
                        };
                        let _ = run_capture(dir, format, frames, events, finalize).await;
                    })
                }),
            }
        });
        let handles = spawn_connection(
            stream,
            Ed2kDriven::new(session),
            ChannelCaps::default(),
            Some(options.login_timeout),
            capture,
            move |driver| async move { driver.await.map_err(Ed2kNetError::from) }.instrument(span),
        );
        Self {
            handles,
            resolved: None,
        }
    }

    /// Queue an [`Ed2kCommand`] for the session.
    pub async fn send(&self, command: Ed2kCommand) -> Result<(), Ed2kNetError> {
        self.handles
            .commands
            .send(command)
            .await
            .map_err(|_| DriverError::Closed.into())
    }

    /// Receive the next [`Ed2kEvent`], or `None` once the driver has
    /// dropped its send half.
    pub async fn next_event(&mut self) -> Option<Ed2kEvent> {
        self.handles.events.recv().await
    }

    /// Cooperative tear-down: send `Disconnect` and await the driver (then
    /// the capture writer) up to the harness's
    /// [`SHUTDOWN_GRACE`](crate::driver::SHUTDOWN_GRACE); a driver that does
    /// not exit in time is reported as `DriverDied` and aborted.
    pub async fn shutdown(self) -> Result<(), Ed2kNetError> {
        self.handles.shutdown().await
    }
}
