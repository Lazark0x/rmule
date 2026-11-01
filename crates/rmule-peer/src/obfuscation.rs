//! Peer (client-to-client) protocol obfuscation handshake — the sans-I/O byte
//! state machine that establishes an RC4-obfuscated stream before the peer
//! hello (ADR-0042).
//!
//! The crypto primitives (RC4, key derivation, magics) are `rmule-primitives`;
//! the async transport (`CryptStream`) and the runtime adapter that feeds this
//! live in `rmule-net`. This type stays runtime-
//! agnostic — it consumes and produces bytes, nothing more. Byte layouts and
//! magic values are `[pending]` until a captured decrypt vector confirms them.
//!
//! Wire (`docs/reference/notes/obfuscation.md`):
//! - initiator → responder: `[marker:1][rk:4][enc: sync:4 ‖ methods:1 ‖ pref:1 ‖ padlen:1 ‖ pad]`
//! - responder → initiator: `[enc: sync:4 ‖ selected:1 ‖ padlen:1 ‖ pad]`
//!
//! The RC4 stream is *continuous*: the same send/recv streams that encrypt the
//! handshake block carry the app bytes after it, so the handshake decrypts
//! incrementally into a plaintext accumulator and the app transforms just
//! continue the stream.

use rmule_primitives::{
    ENM_OBFUSCATION, HandshakeScan, MAGICVALUE_SYNC, ObfuscationHandshake, ObfuscationRole,
    ObfuscationStream, UserHash,
    derive_peer_keys,
};

/// Encrypted opening header before `PaddingLen` is known: sync(4) + methods(1)
/// + preferred(1) + padding_len(1).
const OPENING_HEADER_LEN: usize = 7;
/// Encrypted reply header: sync(4) + selected(1) + padding_len(1).
const REPLY_HEADER_LEN: usize = 6;

/// Outcome of feeding handshake bytes to a [`PeerObfuscation`].
#[derive(Debug)]
pub enum PeerObfuscationStep {
    /// Not enough bytes yet; the caller feeds more when they arrive.
    NeedMore,
    /// Handshake complete. `write` is the responder's reply (empty for the
    /// initiator); `leftover` is any post-handshake app bytes that arrived in
    /// the same feed, already decrypted.
    Done {
        /// Bytes to send back — the responder's reply, or empty.
        write: Vec<u8>,
        /// App bytes that trailed the handshake in the same feed, already
        /// decrypted.
        leftover: Vec<u8>,
        /// The keyed streams, for every byte from here on.
        stream: ObfuscationStream,
    },
    /// The handshake did not authenticate (sync mismatch — wrong key/hash) or
    /// was otherwise malformed. The caller drops the connection.
    Failed,
}

/// Sans-I/O peer obfuscation handshake, one per connection.
pub struct PeerObfuscation {
    flow: Flow,
    /// Responder key basis until the initiator's random key arrives.
    own_hash: UserHash,
    /// The responder's reply padding, consumed when it replies.
    reply_padding: Vec<u8>,
    /// Undecrypted inbound (only holds the marker+rk prefix for a responder
    /// before keys exist).
    raw: Vec<u8>,
}

enum Flow {
    /// Responder before the initiator's random key has arrived.
    ResponderAwaitKey,
    /// Responder with keys, reading the encrypted opening.
    ResponderReadOpening(ObfuscationHandshake),
    /// Initiator, awaiting the responder's encrypted reply.
    InitiatorAwaitReply(ObfuscationHandshake),
    /// Done or failed: nothing more is read.
    Ended,
}

impl PeerObfuscation {
    /// Build the dialer side. Derives keys from the *target* peer's **User
    /// Hash**, returns `self` plus the opening bytes to send. Entropy (`marker`,
    /// `random_key`, `padding`) is injected so the type stays deterministic and
    /// sans-I/O; the runtime adapter supplies CSPRNG material. `marker` must not
    /// be a plaintext protocol byte.
    #[must_use]
    pub fn initiate(
        target: UserHash,
        marker: u8,
        random_key: [u8; 4],
        padding: &[u8],
    ) -> (Self, Vec<u8>) {
        let mut keys = derive_peer_keys(&target, random_key, ObfuscationRole::Initiator);
        // opening block: sync(4) ‖ methods(1) ‖ preferred(1) ‖ padlen(1) ‖ pad
        let mut block = Vec::with_capacity(OPENING_HEADER_LEN + padding.len());
        block.extend_from_slice(&MAGICVALUE_SYNC.to_le_bytes());
        block.push(ENM_OBFUSCATION);
        block.push(ENM_OBFUSCATION);
        block.push(padding.len() as u8);
        block.extend_from_slice(padding);
        keys.send.apply(&mut block);
        let mut opening = Vec::with_capacity(5 + block.len());
        opening.push(marker);
        opening.extend_from_slice(&random_key);
        opening.append(&mut block);
        let this = Self {
            flow: Flow::InitiatorAwaitReply(ObfuscationHandshake::keyed(keys)),
            own_hash: target,
            reply_padding: Vec::new(),
            raw: Vec::new(),
        };
        (this, opening)
    }

    /// Build the accepter side. Keys are derived once the initiator's random
    /// key arrives in [`feed`](Self::feed); `reply_padding` is this side's
    /// padding for its reply.
    #[must_use]
    pub fn respond(own: UserHash, reply_padding: &[u8]) -> Self {
        Self {
            flow: Flow::ResponderAwaitKey,
            own_hash: own,
            reply_padding: reply_padding.to_vec(),
            raw: Vec::new(),
        }
    }

    /// Feed inbound bytes through the handshake state machine.
    pub fn feed(&mut self, input: &[u8]) -> PeerObfuscationStep {
        match std::mem::replace(&mut self.flow, Flow::Ended) {
            Flow::Ended => PeerObfuscationStep::Failed,
            Flow::ResponderAwaitKey => {
                self.raw.extend_from_slice(input);
                if self.raw.len() < 5 {
                    self.flow = Flow::ResponderAwaitKey;
                    return PeerObfuscationStep::NeedMore;
                }
                let rk = [self.raw[1], self.raw[2], self.raw[3], self.raw[4]];
                let mut handshake = ObfuscationHandshake::keyed(derive_peer_keys(
                    &self.own_hash,
                    rk,
                    ObfuscationRole::Responder,
                ));
                let mut rest = self.raw.split_off(5);
                self.raw.clear();
                handshake.absorb(&mut rest);
                self.parse_opening(handshake)
            }
            Flow::ResponderReadOpening(mut handshake) => {
                handshake.absorb(&mut input.to_vec());
                self.parse_opening(handshake)
            }
            Flow::InitiatorAwaitReply(mut handshake) => {
                handshake.absorb(&mut input.to_vec());
                self.parse_reply(handshake)
            }
        }
    }

    /// Responder: parse the decrypted opening; on completion, build the reply.
    fn parse_opening(&mut self, mut handshake: ObfuscationHandshake) -> PeerObfuscationStep {
        match handshake.scan(OPENING_HEADER_LEN) {
            HandshakeScan::NeedMore => {
                self.flow = Flow::ResponderReadOpening(handshake);
                PeerObfuscationStep::NeedMore
            }
            HandshakeScan::BadSync => PeerObfuscationStep::Failed,
            HandshakeScan::Complete(total) => {
                let leftover = handshake.leftover(total);
                let write = self.build_reply(&mut handshake);
                PeerObfuscationStep::Done {
                    write,
                    leftover,
                    stream: handshake.into_stream(),
                }
            }
        }
    }

    /// Initiator: parse the decrypted reply; no bytes to write back.
    fn parse_reply(&mut self, handshake: ObfuscationHandshake) -> PeerObfuscationStep {
        match handshake.scan(REPLY_HEADER_LEN) {
            HandshakeScan::NeedMore => {
                self.flow = Flow::InitiatorAwaitReply(handshake);
                PeerObfuscationStep::NeedMore
            }
            HandshakeScan::BadSync => PeerObfuscationStep::Failed,
            HandshakeScan::Complete(total) => PeerObfuscationStep::Done {
                write: Vec::new(),
                leftover: handshake.leftover(total),
                stream: handshake.into_stream(),
            },
        }
    }

    /// Responder reply block: sync(4) ‖ selected(1) ‖ padlen(1) ‖ pad, encrypted
    /// in place with the send stream (which continues into the app stream).
    fn build_reply(&self, handshake: &mut ObfuscationHandshake) -> Vec<u8> {
        let mut block = Vec::with_capacity(REPLY_HEADER_LEN + self.reply_padding.len());
        block.extend_from_slice(&MAGICVALUE_SYNC.to_le_bytes());
        block.push(ENM_OBFUSCATION);
        block.push(self.reply_padding.len() as u8);
        block.extend_from_slice(&self.reply_padding);
        handshake.transform_send(&mut block);
        block
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_primitives::is_plaintext_marker;

    fn done(step: PeerObfuscationStep) -> (Vec<u8>, Vec<u8>, ObfuscationStream) {
        match step {
            PeerObfuscationStep::Done {
                write,
                leftover,
                stream,
            } => (write, leftover, stream),
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn handshake_completes_and_streams_cross_decrypt_both_directions() {
        let hash = UserHash::from_bytes([0x5a; 16]); // the target/responder hash, known to both
        let rk = [0x11, 0x22, 0x33, 0x44];

        let (mut init, opening) = PeerObfuscation::initiate(hash, 0x9f, rk, &[1, 2, 3]);
        assert!(
            !is_plaintext_marker(opening[0]),
            "marker avoids plaintext bytes"
        );
        assert_eq!(&opening[1..5], &rk, "random key is sent in the clear");

        let mut resp = PeerObfuscation::respond(hash, &[9, 9]);
        let (reply, resp_leftover, mut resp_stream) = done(resp.feed(&opening));
        assert!(resp_leftover.is_empty());
        assert!(
            !reply.is_empty(),
            "responder answers with an encrypted reply"
        );

        let (init_write, init_leftover, mut init_stream) = done(init.feed(&reply));
        assert!(init_write.is_empty() && init_leftover.is_empty());

        // initiator → responder
        let mut a = b"hello from initiator".to_vec();
        let plain_a = a.clone();
        init_stream.transform_send(&mut a);
        assert_ne!(a, plain_a, "app bytes are encrypted");
        resp_stream.transform_recv(&mut a);
        assert_eq!(a, plain_a, "responder decrypts initiator app stream");

        // responder → initiator
        let mut b = b"hello from responder".to_vec();
        let plain_b = b.clone();
        resp_stream.transform_send(&mut b);
        init_stream.transform_recv(&mut b);
        assert_eq!(b, plain_b, "initiator decrypts responder app stream");
    }

    #[test]
    fn responder_rejects_wrong_user_hash() {
        let (_, opening) =
            PeerObfuscation::initiate(UserHash::from_bytes([1; 16]), 0x80, [5, 6, 7, 8], &[]);
        let mut resp = PeerObfuscation::respond(UserHash::from_bytes([2; 16]), &[]);
        assert!(
            matches!(resp.feed(&opening), PeerObfuscationStep::Failed),
            "sync fails to authenticate under the wrong hash"
        );
    }

    #[test]
    fn responder_buffers_a_split_opening() {
        let hash = UserHash::from_bytes([7; 16]);
        let (_, opening) = PeerObfuscation::initiate(hash, 0x80, [1, 2, 3, 4], &[0xaa; 5]);
        let mut resp = PeerObfuscation::respond(hash, &[]);

        let mid = opening.len() / 2;
        assert!(matches!(
            resp.feed(&opening[..mid]),
            PeerObfuscationStep::NeedMore
        ));
        assert!(matches!(
            resp.feed(&opening[mid..]),
            PeerObfuscationStep::Done { .. }
        ));
    }

    #[test]
    fn app_bytes_trailing_the_opening_surface_as_leftover() {
        let hash = UserHash::from_bytes([3; 16]);
        let rk = [1, 1, 1, 1];
        let (_, mut opening) = PeerObfuscation::initiate(hash, 0x80, rk, &[]);
        // initiator pipelines an app byte immediately after the opening: its
        // send stream, run on past the opening block
        let mut keys = derive_peer_keys(&hash, rk, ObfuscationRole::Initiator);
        keys.send.apply(&mut opening[5..].to_vec());
        let mut app = b"X".to_vec();
        keys.send.apply(&mut app);
        opening.extend_from_slice(&app);

        let mut resp = PeerObfuscation::respond(hash, &[]);
        let (_reply, leftover, _) = done(resp.feed(&opening));
        assert_eq!(leftover, b"X", "trailing app byte decrypts as leftover");
    }
}
