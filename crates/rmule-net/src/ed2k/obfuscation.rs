//! Server obfuscation runtime adapter (ADR-0042). Bridges rmule-ed2k's sans-I/O
//! [`ServerObfuscation`] DH handshake to the [`ObfuscationTransport`] trait that
//! `CryptStream` drives — the same adapter pattern as the peer form. rmule is
//! only ever the *client* to eD2k servers, so only [`client`](ServerObfuscationTransport::client)
//! is used in production; [`server`](ServerObfuscationTransport::server) exists
//! for the loopback test. Per-connection CSPRNG entropy is drawn here.

use crate::driver::{HandshakeProgress, ObfuscationTransport, random_marker, random_padding};
use rmule_ed2k::{ServerObfuscation, ServerObfuscationStep};

/// Runtime adapter: an [`ObfuscationTransport`] backed by rmule-ed2k's
/// [`ServerObfuscation`] Diffie-Hellman handshake.
pub struct ServerObfuscationTransport {
    inner: ServerObfuscation,
    initial: Vec<u8>,
}

impl ServerObfuscationTransport {
    /// Client side — the role rmule uses in production (it dials servers). The
    /// opening `[marker][G^A][padlen][pad]` is emitted from
    /// [`initial_output`](ObfuscationTransport::initial_output).
    #[must_use]
    pub fn client() -> Self {
        // The opening's plain padding is clamped to aMule's 15 bytes by the
        // state machine; the reply block's is the shared draw.
        let (inner, initial) =
            ServerObfuscation::client(random_marker(), &random_padding(), &random_padding());
        Self { inner, initial }
    }

    /// Server side — for the loopback test and symmetry.
    #[must_use]
    pub fn server() -> Self {
        Self {
            inner: ServerObfuscation::server(&random_padding()),
            initial: Vec::new(),
        }
    }
}

impl ObfuscationTransport for ServerObfuscationTransport {
    fn initial_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.initial)
    }
    fn feed_handshake(&mut self, input: &[u8]) -> HandshakeProgress {
        match self.inner.feed(input) {
            ServerObfuscationStep::NeedMore { write } => HandshakeProgress::NeedMore { write },
            ServerObfuscationStep::Done { write, leftover } => {
                HandshakeProgress::Done { write, leftover }
            }
            ServerObfuscationStep::Failed => HandshakeProgress::Failed,
        }
    }
    fn transform_outgoing(&mut self, buf: &mut [u8]) {
        self.inner.transform_send(buf);
    }
    fn transform_incoming(&mut self, buf: &mut [u8]) {
        self.inner.transform_recv(buf);
    }
}
