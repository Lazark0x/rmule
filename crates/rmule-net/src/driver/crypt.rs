//! Transport-layer protocol obfuscation (ADR-0042): a byte-0-discriminated RC4
//! stream wrapper that sits *below* the packet codec, so the driver and session
//! above it see only decrypted bytes.
//!
//! [`CryptStream`] is protocol- and cipher-agnostic — it drives an injected
//! [`ObfuscationTransport`] through the handshake, then transforms every byte —
//! so this module owns only the stream, while the peer (user-hash) and server
//! (Diffie-Hellman) handshakes stay with their protocols. It plugs into the
//! `spawn_connection` seam in place of a bare `TcpStream`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use rmule_primitives::{CryptStance, is_plaintext_marker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Longest random padding tail rmule appends to a handshake message. `[pending]`
/// (eMule's `GetCryptTCPPaddingLength`); any value interoperates because the
/// peer reads the length byte.
const MAX_PADDING: usize = 16;

/// Draw a marker byte that is *not* a plaintext protocol byte, so a peer's
/// byte-0 discrimination reads the connection as obfuscated. The per-connection
/// entropy both obfuscation adapters feed to their handshake, drawn here
/// (where I/O lives) so the sans-I/O protocol crates stay deterministic.
#[must_use]
pub fn random_marker() -> u8 {
    loop {
        let mut byte = [0u8; 1];
        OsRng.fill_bytes(&mut byte);
        if !is_plaintext_marker(byte[0]) {
            return byte[0];
        }
    }
}

/// Draw a random padding tail of `0..=MAX_PADDING` bytes for a handshake
/// message. Shared by both obfuscation adapters (see [`random_marker`]).
#[must_use]
pub fn random_padding() -> Vec<u8> {
    let len = OsRng.gen_range(0..=MAX_PADDING);
    let mut padding = vec![0u8; len];
    OsRng.fill_bytes(&mut padding);
    padding
}

/// The sans-I/O obfuscation handshake plus stream transform that [`CryptStream`]
/// drives. Implemented by the peer and server forms in the protocol crates via
/// runtime adapters; `CryptStream` never names RC4 or a protocol.
pub trait ObfuscationTransport {
    /// Bytes to send immediately on connect, before any inbound — the
    /// initiator's opening. Empty for a responder.
    fn initial_output(&mut self) -> Vec<u8>;
    /// Feed inbound handshake bytes.
    fn feed_handshake(&mut self, input: &[u8]) -> HandshakeProgress;
    /// Encrypt outgoing app bytes in place (post-handshake).
    fn transform_outgoing(&mut self, buf: &mut [u8]);
    /// Decrypt incoming app bytes in place (post-handshake).
    fn transform_incoming(&mut self, buf: &mut [u8]);
}

/// Progress of an [`ObfuscationTransport`] handshake.
pub enum HandshakeProgress {
    /// Need more inbound bytes before the handshake resolves. `write` is any
    /// bytes to send back first — empty for a one-shot responder, but the server
    /// DH form sends its `[G^B][enc]` here and then awaits the client's reply.
    NeedMore {
        /// Bytes to send back before awaiting the rest.
        write: Vec<u8>,
    },
    /// Handshake authenticated. `write` is bytes to send back (a responder's
    /// reply, or empty); `leftover` is post-handshake app bytes already received
    /// in this feed, already decrypted.
    Done {
        /// Bytes to write back to the peer (responder reply, or empty).
        write: Vec<u8>,
        /// Decrypted app bytes that trailed the handshake in the same read.
        leftover: Vec<u8>,
    },
    /// Handshake failed to authenticate; the connection must drop.
    Failed,
}

/// The stance toward protocol obfuscation for one connection (ADR-0042), shared
/// by the peer and server runtime modules. `Disabled` is the *absence* of a config
/// (`ConnectOptions::obfuscation == None`), so this enum carries only the three
/// active states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObfuscationPolicy {
    /// Accept obfuscated inbound (peer) / connect plaintext (server); never
    /// initiate obfuscation.
    Supported,
    /// Initiate obfuscation when possible. A failed server connect falls back
    /// to plaintext; a failed peer dial does not (ADR-0049).
    Requested,
    /// Obfuscated only; refuse plaintext (reject inbound / no outbound fallback).
    Required,
}

impl ObfuscationPolicy {
    /// The registry [`CryptStance`] this policy advertises (ADR-0047) — the
    /// one policy→stance ladder every advert surface reads (peer-hello
    /// `MiscOptions2`, server-login `CT_SERVER_FLAGS`). `supports` is always
    /// lit: any active policy means rmule accepts the crypt layer.
    #[must_use]
    pub fn crypt_stance(self) -> CryptStance {
        let (requests, requires) = match self {
            Self::Supported => (false, false),
            Self::Requested => (true, false),
            Self::Required => (true, true),
        };
        CryptStance::new(true, requests, requires)
    }

    /// The stance a connection runs under when its policy is `policy` —
    /// [`CryptStance::disabled`] when obfuscation is off (`None`).
    #[must_use]
    pub fn stance_of(policy: Option<Self>) -> CryptStance {
        policy.map_or_else(CryptStance::disabled, Self::crypt_stance)
    }
}

/// Per-connection obfuscation configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObfuscationConfig {
    /// The connection's [`ObfuscationPolicy`].
    pub policy: ObfuscationPolicy,
}

const READ_CHUNK: usize = 8192;

enum Phase {
    Handshaking { started: bool },
    Established,
    Failed,
}

/// An `AsyncRead + AsyncWrite` adapter that runs an [`ObfuscationTransport`]
/// handshake below the session, then transparently streams. Constructed around
/// an accepted/dialed `TcpStream` (or any `AsyncRead + AsyncWrite + Unpin`).
pub struct CryptStream<S, H> {
    inner: S,
    transport: H,
    phase: Phase,
    /// Ciphertext queued for `inner`: handshake output, plus the encrypted tail
    /// of a partial app write (the stream cipher can't re-encrypt, so unwritten
    /// ciphertext must be buffered rather than dropped).
    out_buf: Vec<u8>,
    out_pos: usize,
    /// Decrypted handshake leftover awaiting the first reader.
    in_plain: Vec<u8>,
    in_pos: usize,
}

impl<S, H> CryptStream<S, H> {
    /// Wrap `inner`, driving `transport` through the obfuscation handshake on
    /// the first read or write.
    pub fn new(inner: S, transport: H) -> Self {
        Self {
            inner,
            transport,
            phase: Phase::Handshaking { started: false },
            out_buf: Vec::new(),
            out_pos: 0,
            in_plain: Vec::new(),
            in_pos: 0,
        }
    }
}

impl<S, H> CryptStream<S, H>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: ObfuscationTransport,
{
    /// Flush queued ciphertext to `inner`.
    fn flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out_buf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out_buf[self.out_pos..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => self.out_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.out_buf.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// Drive the handshake to completion. Both `poll_read` and `poll_write` call
    /// this first; it reads and writes `inner` as the handshake needs.
    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.phase {
                Phase::Established => return Poll::Ready(Ok(())),
                Phase::Failed => return Poll::Ready(Err(handshake_failed())),
                Phase::Handshaking { started } => {
                    if !started {
                        let opening = self.transport.initial_output();
                        self.out_buf.extend_from_slice(&opening);
                        self.phase = Phase::Handshaking { started: true };
                    }
                    ready!(self.flush_out(cx))?;
                    let mut tmp = [0u8; READ_CHUNK];
                    let mut rb = ReadBuf::new(&mut tmp);
                    ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
                    let filled = rb.filled();
                    if filled.is_empty() {
                        self.phase = Phase::Failed;
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    match self.transport.feed_handshake(filled) {
                        HandshakeProgress::NeedMore { write } => {
                            self.out_buf.extend_from_slice(&write);
                            ready!(self.flush_out(cx))?;
                            continue;
                        }
                        HandshakeProgress::Done { write, leftover } => {
                            self.out_buf.extend_from_slice(&write);
                            self.in_plain.extend_from_slice(&leftover);
                            self.phase = Phase::Established;
                            ready!(self.flush_out(cx))?;
                            return Poll::Ready(Ok(()));
                        }
                        HandshakeProgress::Failed => {
                            self.phase = Phase::Failed;
                            return Poll::Ready(Err(handshake_failed()));
                        }
                    }
                }
            }
        }
    }

    /// Drive the obfuscation handshake to completion eagerly, before any app
    /// I/O. A dialer calls this so it can detect a crypt failure (e.g. a server
    /// that does not speak obfuscation) and fall back to a plaintext connection.
    pub async fn complete_handshake(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| self.poll_handshake(cx)).await
    }
}

fn handshake_failed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "obfuscation handshake failed")
}

impl<S, H> AsyncRead for CryptStream<S, H>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: ObfuscationTransport + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_handshake(cx))?;
        // Deliver decrypted handshake leftover before touching the socket.
        if this.in_pos < this.in_plain.len() {
            let avail = &this.in_plain[this.in_pos..];
            let n = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..n]);
            this.in_pos += n;
            if this.in_pos >= this.in_plain.len() {
                this.in_plain.clear();
                this.in_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        let start = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        let fresh = &mut buf.filled_mut()[start..];
        this.transport.transform_incoming(fresh);
        Poll::Ready(Ok(()))
    }
}

impl<S, H> AsyncWrite for CryptStream<S, H>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: ObfuscationTransport + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_handshake(cx))?;
        // Backpressure: drain any queued ciphertext before accepting more.
        ready!(this.flush_out(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut enc = data.to_vec();
        this.transport.transform_outgoing(&mut enc);
        this.out_buf.extend_from_slice(&enc);
        // The cipher consumed all of `data`; report it consumed and flush what
        // we can. Any unwritten ciphertext stays queued for the next flush.
        if let Poll::Ready(Err(e)) = this.flush_out(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.flush_out(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.flush_out(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A stateless XOR "obfuscation" with role-swapped keys — enough to exercise
    /// `CryptStream`'s handshake driving, buffering, and transform without the
    /// real RC4/DH (which live in the protocol crates). Asymmetric on purpose:
    /// send and recv keys differ, so a flipped direction fails to decrypt.
    const SYNC: u8 = 0x5e;

    struct XorTransport {
        send_key: u8,
        recv_key: u8,
        initiator: bool,
    }
    impl XorTransport {
        fn initiator() -> Self {
            Self {
                send_key: 0xA1,
                recv_key: 0xB2,
                initiator: true,
            }
        }
        fn responder() -> Self {
            Self {
                send_key: 0xB2,
                recv_key: 0xA1,
                initiator: false,
            }
        }
    }
    impl ObfuscationTransport for XorTransport {
        fn initial_output(&mut self) -> Vec<u8> {
            if self.initiator {
                vec![SYNC ^ self.send_key]
            } else {
                Vec::new()
            }
        }
        fn feed_handshake(&mut self, input: &[u8]) -> HandshakeProgress {
            if input.is_empty() {
                return HandshakeProgress::NeedMore { write: Vec::new() };
            }
            if input[0] ^ self.recv_key != SYNC {
                return HandshakeProgress::Failed;
            }
            let write = if self.initiator {
                Vec::new()
            } else {
                vec![SYNC ^ self.send_key]
            };
            let mut leftover = input[1..].to_vec();
            self.transform_incoming(&mut leftover);
            HandshakeProgress::Done { write, leftover }
        }
        fn transform_outgoing(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b ^= self.send_key;
            }
        }
        fn transform_incoming(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b ^= self.recv_key;
            }
        }
    }

    #[tokio::test]
    async fn handshakes_and_round_trips_both_directions() {
        let (a, b) = tokio::io::duplex(4096);
        let mut client = CryptStream::new(a, XorTransport::initiator());
        let mut server = CryptStream::new(b, XorTransport::responder());

        let client_task = tokio::spawn(async move {
            client.write_all(b"ping from client").await.unwrap();
            client.flush().await.unwrap();
            let mut buf = [0u8; 16];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong from server");
        });
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping from client");
            server.write_all(b"pong from server").await.unwrap();
            server.flush().await.unwrap();
        });
        client_task.await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_key_fails_the_handshake() {
        let (a, b) = tokio::io::duplex(4096);
        let mut client = CryptStream::new(a, XorTransport::initiator());
        // Responder with mismatched keys: the sync byte won't authenticate.
        let mut server = CryptStream::new(
            b,
            XorTransport {
                send_key: 0x00,
                recv_key: 0x00,
                initiator: false,
            },
        );
        let client_task = tokio::spawn(async move {
            let _ = client.write_all(b"hello").await;
        });
        let mut buf = [0u8; 4];
        let err = server.read_exact(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // Drop the server so its duplex half closes; the client's await-reply
        // then sees EOF instead of hanging.
        drop(server);
        let _ = client_task.await;
    }
}
