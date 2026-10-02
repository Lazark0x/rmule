//! Server (client-to-server) protocol obfuscation handshake — the sans-I/O byte
//! state machine that agrees an RC4 key by Diffie-Hellman before the eD2k login
//! (ADR-0042).
//!
//! Unlike the peer form (user-hash-keyed, two messages), the client and server
//! share no prior secret, so they agree one by 768-bit DH across **three**
//! messages:
//! - client → server: `[marker:1][G^A:96]`
//! - server → client: `[G^B:96][enc: sync:4 ‖ methods:1 ‖ pref:1 ‖ padlen:1 ‖ pad]`
//! - client → server: `[enc: sync:4 ‖ selected:1 ‖ padlen:1 ‖ pad]`
//!
//! rmule is only ever the *client* to eD2k servers, so it sends no trailing
//! random bytes after `G^A` (aMule's optional 0–15 rand is `[pending]`); the
//! server role exists for the loopback test and symmetry. The DH primitive and
//! key derivation live in `rmule-primitives`; the async transport (`CryptStream`)
//! and the runtime adapter are `rmule-net`. Byte
//! layouts are `[pending]` until a server interop run confirms them.

use rmule_primitives::{
    DH_PRIME_SIZE, ENM_OBFUSCATION, MAGICVALUE_SYNC, ObfuscationDhKeypair, ObfuscationKeys,
    ObfuscationRole, derive_server_keys,
};

/// Client's first message length: marker(1) + `G^A`(96).
const CLIENT_HELLO_LEN: usize = 1 + DH_PRIME_SIZE;
/// Server encrypted block header: sync(4) + methods(1) + preferred(1) + padlen(1).
const SERVER_HEADER_LEN: usize = 7;
/// Client reply encrypted header: sync(4) + selected(1) + padlen(1).
const CLIENT_HEADER_LEN: usize = 6;

/// The padding length is a single wire byte, so it can never express more than
/// 255 bytes of filler. The framer clamps to this so the emitted length byte
/// and the padding it prefixes can never desync (a truncated `len() as u8`
/// would shift the peer's block-length scan and corrupt the handshake).
const MAX_PADDING_LEN: usize = u8::MAX as usize;

/// Outcome of feeding handshake bytes to a [`ServerObfuscation`].
#[derive(Debug)]
pub enum ServerObfuscationStep {
    /// Not enough bytes yet. `write` is any bytes to send first — empty for the
    /// client, but the server sends `[G^B][enc]` here and then awaits the reply.
    NeedMore {
        /// Bytes to send before waiting for more — empty for the client,
        /// `[G^B][enc]` for the server.
        write: Vec<u8>,
    },
    /// Handshake complete. `write` is the client's reply (empty for the server);
    /// `leftover` is post-handshake app bytes already decrypted in this feed.
    Done {
        /// The reply to send, empty for the server side.
        write: Vec<u8>,
        /// Application bytes that arrived in the same feed, already
        /// decrypted — the caller must consume these before reading more.
        leftover: Vec<u8>,
    },
    /// The handshake did not authenticate (sync mismatch — DH secrets differ).
    Failed,
}

/// Sans-I/O server obfuscation handshake, one per connection.
pub struct ServerObfuscation {
    flow: Flow,
    keypair: ObfuscationDhKeypair,
    keys: Option<ObfuscationKeys>,
    /// This side's padding for the encrypted block it sends.
    padding: Vec<u8>,
    raw: Vec<u8>,
    dec: Vec<u8>,
}

enum Flow {
    ClientAwaitServerHello,
    ClientReadServerEnc,
    ServerAwaitClientHello,
    ServerAwaitClientReply,
    Done,
    Failed,
}

impl ServerObfuscation {
    /// Build the client (dialer) side. Returns `self` plus the opening
    /// `[marker][G^A]`; `padding` is this side's padding for its reply block.
    #[must_use]
    pub fn client(marker: u8, padding: &[u8]) -> (Self, Vec<u8>) {
        let keypair = ObfuscationDhKeypair::generate();
        let mut opening = Vec::with_capacity(CLIENT_HELLO_LEN);
        opening.push(marker);
        opening.extend_from_slice(&keypair.public());
        let this = Self {
            flow: Flow::ClientAwaitServerHello,
            keypair,
            keys: None,
            padding: padding.to_vec(),
            raw: Vec::new(),
            dec: Vec::new(),
        };
        (this, opening)
    }

    /// Build the server (accepter) side. `padding` is this side's padding for
    /// the `[G^B][enc]` block it sends.
    #[must_use]
    pub fn server(padding: &[u8]) -> Self {
        Self {
            flow: Flow::ServerAwaitClientHello,
            keypair: ObfuscationDhKeypair::generate(),
            keys: None,
            padding: padding.to_vec(),
            raw: Vec::new(),
            dec: Vec::new(),
        }
    }

    /// Feed inbound bytes through the DH handshake state machine.
    pub fn feed(&mut self, input: &[u8]) -> ServerObfuscationStep {
        match self.flow {
            Flow::Failed | Flow::Done => ServerObfuscationStep::Failed,
            Flow::ClientAwaitServerHello => {
                self.raw.extend_from_slice(input);
                if self.raw.len() < DH_PRIME_SIZE {
                    return ServerObfuscationStep::NeedMore { write: Vec::new() };
                }
                let mut peer_public = [0u8; DH_PRIME_SIZE];
                peer_public.copy_from_slice(&self.raw[..DH_PRIME_SIZE]);
                let secret = self.keypair.agree(&peer_public);
                self.keys = Some(derive_server_keys(&secret, ObfuscationRole::Initiator));
                let mut rest = self.raw.split_off(DH_PRIME_SIZE);
                self.raw.clear();
                self.decrypt_into_dec(&mut rest);
                self.flow = Flow::ClientReadServerEnc;
                self.parse_server_block()
            }
            Flow::ClientReadServerEnc => {
                let mut chunk = input.to_vec();
                self.decrypt_into_dec(&mut chunk);
                self.parse_server_block()
            }
            Flow::ServerAwaitClientHello => {
                self.raw.extend_from_slice(input);
                if self.raw.len() < CLIENT_HELLO_LEN {
                    return ServerObfuscationStep::NeedMore { write: Vec::new() };
                }
                let mut peer_public = [0u8; DH_PRIME_SIZE];
                peer_public.copy_from_slice(&self.raw[1..CLIENT_HELLO_LEN]);
                let secret = self.keypair.agree(&peer_public);
                self.keys = Some(derive_server_keys(&secret, ObfuscationRole::Responder));
                let write = self.build_server_hello();
                // Discard the client's trailing rand (aMule sends 0-15; rmule
                // sends none) and reset the buffers for the client's reply.
                self.raw.clear();
                self.dec.clear();
                self.flow = Flow::ServerAwaitClientReply;
                ServerObfuscationStep::NeedMore { write }
            }
            Flow::ServerAwaitClientReply => {
                let mut chunk = input.to_vec();
                self.decrypt_into_dec(&mut chunk);
                self.parse_client_reply()
            }
        }
    }

    /// Encrypt app bytes we send (post-handshake).
    pub fn transform_send(&mut self, buf: &mut [u8]) {
        if let Some(keys) = self.keys.as_mut() {
            keys.send.apply(buf);
        }
    }

    /// Decrypt app bytes we receive (post-handshake).
    pub fn transform_recv(&mut self, buf: &mut [u8]) {
        if let Some(keys) = self.keys.as_mut() {
            keys.recv.apply(buf);
        }
    }

    fn decrypt_into_dec(&mut self, chunk: &mut [u8]) {
        if let Some(keys) = self.keys.as_mut() {
            keys.recv.apply(chunk);
        }
        self.dec.extend_from_slice(chunk);
    }

    /// Client: parse the server's encrypted block; on completion, build the reply.
    fn parse_server_block(&mut self) -> ServerObfuscationStep {
        match self.scan(SERVER_HEADER_LEN) {
            Scan::NeedMore => ServerObfuscationStep::NeedMore { write: Vec::new() },
            Scan::BadSync => {
                self.flow = Flow::Failed;
                ServerObfuscationStep::Failed
            }
            Scan::Complete(total) => {
                let leftover = self.dec[total..].to_vec();
                let write = self.build_client_reply();
                self.flow = Flow::Done;
                ServerObfuscationStep::Done { write, leftover }
            }
        }
    }

    /// Server: parse the client's encrypted reply.
    fn parse_client_reply(&mut self) -> ServerObfuscationStep {
        match self.scan(CLIENT_HEADER_LEN) {
            Scan::NeedMore => ServerObfuscationStep::NeedMore { write: Vec::new() },
            Scan::BadSync => {
                self.flow = Flow::Failed;
                ServerObfuscationStep::Failed
            }
            Scan::Complete(total) => {
                let leftover = self.dec[total..].to_vec();
                self.flow = Flow::Done;
                ServerObfuscationStep::Done {
                    write: Vec::new(),
                    leftover,
                }
            }
        }
    }

    /// Validate the sync magic and, once the padding length byte is readable,
    /// compute the full encrypted-block length.
    fn scan(&self, header_len: usize) -> Scan {
        if self.dec.len() >= 4 && self.dec[..4] != MAGICVALUE_SYNC.to_le_bytes() {
            return Scan::BadSync;
        }
        if self.dec.len() < header_len {
            return Scan::NeedMore;
        }
        let padding_len = self.dec[header_len - 1] as usize;
        let total = header_len + padding_len;
        if self.dec.len() < total {
            Scan::NeedMore
        } else {
            Scan::Complete(total)
        }
    }

    /// Server's `[G^B][enc: sync ‖ methods ‖ pref ‖ padlen ‖ pad]`.
    fn build_server_hello(&mut self) -> Vec<u8> {
        let public = self.keypair.public();
        let padding = &self.padding[..self.padding.len().min(MAX_PADDING_LEN)];
        let mut out = Vec::with_capacity(DH_PRIME_SIZE + SERVER_HEADER_LEN + padding.len());
        out.extend_from_slice(&public);
        let mut block = Vec::with_capacity(SERVER_HEADER_LEN + padding.len());
        block.extend_from_slice(&MAGICVALUE_SYNC.to_le_bytes());
        block.push(ENM_OBFUSCATION);
        block.push(ENM_OBFUSCATION);
        block.push(padding.len() as u8);
        block.extend_from_slice(padding);
        if let Some(keys) = self.keys.as_mut() {
            keys.send.apply(&mut block);
        }
        out.append(&mut block);
        out
    }

    /// Client's `[enc: sync ‖ selected ‖ padlen ‖ pad]`.
    fn build_client_reply(&mut self) -> Vec<u8> {
        let padding = &self.padding[..self.padding.len().min(MAX_PADDING_LEN)];
        let mut block = Vec::with_capacity(CLIENT_HEADER_LEN + padding.len());
        block.extend_from_slice(&MAGICVALUE_SYNC.to_le_bytes());
        block.push(ENM_OBFUSCATION);
        block.push(padding.len() as u8);
        block.extend_from_slice(padding);
        if let Some(keys) = self.keys.as_mut() {
            keys.send.apply(&mut block);
        }
        block
    }
}

/// Which stage the incremental header scan reached.
enum Scan {
    NeedMore,
    BadSync,
    /// The full encrypted block is `total` decrypted bytes.
    Complete(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_handshake_completes_and_streams_cross_decrypt() {
        let (mut client, opening) = ServerObfuscation::client(0x80, &[1, 2, 3]);
        assert_eq!(opening.len(), CLIENT_HELLO_LEN, "opening is marker + G^A");
        let mut server = ServerObfuscation::server(&[9, 9]);

        // msg1 client → server: server replies [G^B][enc] and awaits the reply
        let server_hello = match server.feed(&opening) {
            ServerObfuscationStep::NeedMore { write } => write,
            other => panic!("server should NeedMore with a write, got {other:?}"),
        };
        assert!(
            server_hello.len() > DH_PRIME_SIZE,
            "server hello is G^B + enc block"
        );

        // msg2 server → client: client completes and replies [enc]
        let client_reply = match client.feed(&server_hello) {
            ServerObfuscationStep::Done { write, leftover } => {
                assert!(leftover.is_empty());
                write
            }
            other => panic!("client should complete, got {other:?}"),
        };
        assert!(
            !client_reply.is_empty(),
            "client answers with an encrypted reply"
        );

        // msg3 client → server: server completes
        assert!(matches!(
            server.feed(&client_reply),
            ServerObfuscationStep::Done { .. }
        ));

        // client → server app stream
        let mut a = b"client to server".to_vec();
        let plain_a = a.clone();
        client.transform_send(&mut a);
        assert_ne!(a, plain_a, "app bytes are encrypted");
        server.transform_recv(&mut a);
        assert_eq!(a, plain_a, "server decrypts client app stream");

        // server → client app stream
        let mut b = b"server to client".to_vec();
        let plain_b = b.clone();
        server.transform_send(&mut b);
        client.transform_recv(&mut b);
        assert_eq!(b, plain_b, "client decrypts server app stream");
    }

    #[test]
    fn corrupt_dh_public_fails_the_sync() {
        let (mut client, opening) = ServerObfuscation::client(0x80, &[]);
        let mut server = ServerObfuscation::server(&[]);
        let mut server_hello = match server.feed(&opening) {
            ServerObfuscationStep::NeedMore { write } => write,
            other => panic!("expected NeedMore, got {other:?}"),
        };
        // Corrupt a byte of G^B → the client agrees a different secret → the
        // encrypted sync no longer decrypts to MAGICVALUE_SYNC.
        server_hello[40] ^= 0xFF;
        assert!(matches!(
            client.feed(&server_hello),
            ServerObfuscationStep::Failed
        ));
    }

    #[test]
    fn oversized_padding_is_clamped_so_the_handshake_still_completes() {
        // Padding is caller-supplied; a length past the one-byte wire field
        // must be clamped, else `padlen` truncates while the full padding is
        // written and the peer's block scan desyncs. 300 bytes on both sides.
        let (mut client, opening) = ServerObfuscation::client(0x80, &[0xCD; 300]);
        let mut server = ServerObfuscation::server(&[0xAB; 300]);

        let server_hello = match server.feed(&opening) {
            ServerObfuscationStep::NeedMore { write } => write,
            other => panic!("server should NeedMore, got {other:?}"),
        };
        let client_reply = match client.feed(&server_hello) {
            ServerObfuscationStep::Done { write, leftover } => {
                assert!(leftover.is_empty());
                write
            }
            other => panic!("client should complete, got {other:?}"),
        };
        assert!(matches!(
            server.feed(&client_reply),
            ServerObfuscationStep::Done { .. }
        ));

        // The clamp preserved frame integrity: app bytes still cross-decrypt.
        let mut msg = b"post-clamp stream".to_vec();
        let plain = msg.clone();
        client.transform_send(&mut msg);
        server.transform_recv(&mut msg);
        assert_eq!(msg, plain, "handshake stayed in sync through the clamp");
    }
}
