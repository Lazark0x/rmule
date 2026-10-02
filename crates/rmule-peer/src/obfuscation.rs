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
    ENM_OBFUSCATION, MAGICVALUE_SYNC, ObfuscationKeys, ObfuscationRole, UserHash, derive_peer_keys,
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
    },
    /// The handshake did not authenticate (sync mismatch — wrong key/hash) or
    /// was otherwise malformed. The caller drops the connection.
    Failed,
}

/// Sans-I/O peer obfuscation handshake, one per connection.
pub struct PeerObfuscation {
    flow: Flow,
    keys: Option<ObfuscationKeys>,
    /// Responder key basis until the initiator's random key arrives.
    own_hash: UserHash,
    /// The responder's reply padding, consumed when it replies.
    reply_padding: Vec<u8>,
    /// Undecrypted inbound (only holds the marker+rk prefix for a responder
    /// before keys exist).
    raw: Vec<u8>,
    /// Decrypted handshake bytes accumulated so far.
    dec: Vec<u8>,
}

enum Flow {
    /// Responder before the initiator's random key has arrived.
    ResponderAwaitKey,
    /// Responder with keys, reading the encrypted opening.
    ResponderReadOpening,
    /// Initiator, awaiting the responder's encrypted reply.
    InitiatorAwaitReply,
    Done,
    Failed,
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
            flow: Flow::InitiatorAwaitReply,
            keys: Some(keys),
            own_hash: target,
            reply_padding: Vec::new(),
            raw: Vec::new(),
            dec: Vec::new(),
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
            keys: None,
            own_hash: own,
            reply_padding: reply_padding.to_vec(),
            raw: Vec::new(),
            dec: Vec::new(),
        }
    }

    /// Feed inbound bytes through the handshake state machine.
    pub fn feed(&mut self, input: &[u8]) -> PeerObfuscationStep {
        match self.flow {
            Flow::Failed | Flow::Done => PeerObfuscationStep::Failed,
            Flow::ResponderAwaitKey => {
                self.raw.extend_from_slice(input);
                if self.raw.len() < 5 {
                    return PeerObfuscationStep::NeedMore;
                }
                let rk = [self.raw[1], self.raw[2], self.raw[3], self.raw[4]];
                self.keys = Some(derive_peer_keys(
                    &self.own_hash,
                    rk,
                    ObfuscationRole::Responder,
                ));
                let mut rest = self.raw.split_off(5);
                self.raw.clear();
                self.decrypt_into_dec(&mut rest);
                self.flow = Flow::ResponderReadOpening;
                self.parse_opening()
            }
            Flow::ResponderReadOpening => {
                let mut chunk = input.to_vec();
                self.decrypt_into_dec(&mut chunk);
                self.parse_opening()
            }
            Flow::InitiatorAwaitReply => {
                let mut chunk = input.to_vec();
                self.decrypt_into_dec(&mut chunk);
                self.parse_reply()
            }
        }
    }

    /// Encrypt app bytes we send, continuing the send stream past the handshake.
    pub fn transform_send(&mut self, buf: &mut [u8]) {
        if let Some(keys) = self.keys.as_mut() {
            keys.send.apply(buf);
        }
    }

    /// Decrypt app bytes we receive, continuing the recv stream.
    pub fn transform_recv(&mut self, buf: &mut [u8]) {
        if let Some(keys) = self.keys.as_mut() {
            keys.recv.apply(buf);
        }
    }

    /// Decrypt a chunk with the recv stream and append the plaintext to `dec`.
    fn decrypt_into_dec(&mut self, chunk: &mut [u8]) {
        if let Some(keys) = self.keys.as_mut() {
            keys.recv.apply(chunk);
        }
        self.dec.extend_from_slice(chunk);
    }

    /// Responder: parse the decrypted opening; on completion, build the reply.
    fn parse_opening(&mut self) -> PeerObfuscationStep {
        match self.handshake_len(OPENING_HEADER_LEN) {
            HeaderScan::NeedMore => PeerObfuscationStep::NeedMore,
            HeaderScan::BadSync => {
                self.flow = Flow::Failed;
                PeerObfuscationStep::Failed
            }
            HeaderScan::Complete(total) => {
                let leftover = self.dec[total..].to_vec();
                let write = self.build_reply();
                self.flow = Flow::Done;
                PeerObfuscationStep::Done { write, leftover }
            }
        }
    }

    /// Initiator: parse the decrypted reply; no bytes to write back.
    fn parse_reply(&mut self) -> PeerObfuscationStep {
        match self.handshake_len(REPLY_HEADER_LEN) {
            HeaderScan::NeedMore => PeerObfuscationStep::NeedMore,
            HeaderScan::BadSync => {
                self.flow = Flow::Failed;
                PeerObfuscationStep::Failed
            }
            HeaderScan::Complete(total) => {
                let leftover = self.dec[total..].to_vec();
                self.flow = Flow::Done;
                PeerObfuscationStep::Done {
                    write: Vec::new(),
                    leftover,
                }
            }
        }
    }

    /// Validate the sync magic and, once the padding length byte (the last byte
    /// of the fixed header) is readable, compute the full handshake length.
    fn handshake_len(&self, header_len: usize) -> HeaderScan {
        if self.dec.len() >= 4 && self.dec[..4] != MAGICVALUE_SYNC.to_le_bytes() {
            return HeaderScan::BadSync;
        }
        if self.dec.len() < header_len {
            return HeaderScan::NeedMore;
        }
        let padding_len = self.dec[header_len - 1] as usize;
        let total = header_len + padding_len;
        if self.dec.len() < total {
            HeaderScan::NeedMore
        } else {
            HeaderScan::Complete(total)
        }
    }

    /// Responder reply block: sync(4) ‖ selected(1) ‖ padlen(1) ‖ pad, encrypted
    /// in place with the send stream (which continues into the app stream).
    fn build_reply(&mut self) -> Vec<u8> {
        let mut block = Vec::with_capacity(REPLY_HEADER_LEN + self.reply_padding.len());
        block.extend_from_slice(&MAGICVALUE_SYNC.to_le_bytes());
        block.push(ENM_OBFUSCATION);
        block.push(self.reply_padding.len() as u8);
        block.extend_from_slice(&self.reply_padding);
        if let Some(keys) = self.keys.as_mut() {
            keys.send.apply(&mut block);
        }
        block
    }
}

/// Which stage the incremental header scan reached.
enum HeaderScan {
    NeedMore,
    BadSync,
    /// The full handshake message is `total` decrypted bytes long.
    Complete(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_primitives::is_plaintext_marker;

    fn done(step: PeerObfuscationStep) -> (Vec<u8>, Vec<u8>) {
        match step {
            PeerObfuscationStep::Done { write, leftover } => (write, leftover),
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
        let (reply, resp_leftover) = done(resp.feed(&opening));
        assert!(resp_leftover.is_empty());
        assert!(
            !reply.is_empty(),
            "responder answers with an encrypted reply"
        );

        let (init_write, init_leftover) = done(init.feed(&reply));
        assert!(init_write.is_empty() && init_leftover.is_empty());

        // initiator → responder
        let mut a = b"hello from initiator".to_vec();
        let plain_a = a.clone();
        init.transform_send(&mut a);
        assert_ne!(a, plain_a, "app bytes are encrypted");
        resp.transform_recv(&mut a);
        assert_eq!(a, plain_a, "responder decrypts initiator app stream");

        // responder → initiator
        let mut b = b"hello from responder".to_vec();
        let plain_b = b.clone();
        resp.transform_send(&mut b);
        init.transform_recv(&mut b);
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
        let (mut init, mut opening) = PeerObfuscation::initiate(hash, 0x80, rk, &[]);
        // initiator pipelines an app byte immediately after the opening
        let mut app = b"X".to_vec();
        init.transform_send(&mut app);
        opening.extend_from_slice(&app);

        let mut resp = PeerObfuscation::respond(hash, &[]);
        let (_reply, leftover) = done(resp.feed(&opening));
        assert_eq!(leftover, b"X", "trailing app byte decrypts as leftover");
    }
}
