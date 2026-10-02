//! Protocol obfuscation crypto primitives: the RC4 stream cipher and the
//! MD5-based peer (user-hash-keyed) key derivation that establish an eMule
//! obfuscated stream (ADR-0042).
//!
//! This is the crypto *primitive* layer only — the shared RC4 core plus the
//! peer key derivation. The transport wrapper (`CryptStream`) lives in
//! `rmule-net`; the handshake state machines live in `rmule-peer`
//! (peer) and `rmule-ed2k` (server); the 768-bit Diffie-Hellman for the server
//! form is a separate primitive. Byte layouts and magic values are
//! pinned `[pending]` in `docs/reference/notes/obfuscation.md` until a
//! captured decrypt vector confirms them.

use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Encoding, U768};
use md5::{Digest, Md5};
use rand::RngCore;
use rand::rngs::OsRng;

use crate::UserHash;

/// RC4 key-derivation magic for the requester→responder (peer initiator) /
/// client→server direction. `[pending]` (aMule `EncryptedStreamSocket.h`).
pub const MAGICVALUE_REQUESTER: u8 = 34;

/// RC4 key-derivation magic for the responder→requester / server→client
/// direction. `[pending]` (aMule `EncryptedStreamSocket.h`).
pub const MAGICVALUE_SERVER: u8 = 203;

/// Encrypted in the handshake so both ends confirm they derived matching keys.
/// `[pending]` (aMule `EncryptedStreamSocket.h`).
pub const MAGICVALUE_SYNC: u32 = 0x835E_6FC4;

/// The only defined encryption method (obfuscation). `[pending]`.
pub const ENM_OBFUSCATION: u8 = 0;

/// RC4 keystream bytes discarded after keying (the eMule RC4-drop1024 convention).
const RC4_DISCARD: usize = 1024;

/// Whether `byte` is a known plaintext eD2k/eMule TCP protocol marker
/// (`OP_EDONKEYPROT` `0xE3` / `OP_EMULEPROT` `0xC5` / `OP_PACKEDPROT` `0xD4`).
/// The byte-0 discrimination rule: a marker means plaintext, anything else
/// means an obfuscated handshake.
#[must_use]
pub const fn is_plaintext_marker(byte: u8) -> bool {
    matches!(byte, 0xE3 | 0xC5 | 0xD4)
}

/// Which side of an obfuscated connection we are — decides which magic keys the
/// send vs receive stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObfuscationRole {
    /// The dialer (peer initiator / client): sends with `MAGICVALUE_REQUESTER`.
    Initiator,
    /// The accepter (peer responder / server): sends with `MAGICVALUE_SERVER`.
    Responder,
}

/// An RC4 keystream generator wrapping RustCrypto `rc4` (ADR-0012). Applies the
/// keystream in place; `with_drop_1024` constructs it already advanced past the
/// drop-1024 prefix.
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Key an RC4 stream from `key` (1..=256 bytes), no keystream discard.
    ///
    /// # Panics
    /// Panics if `key` is empty or longer than 256 bytes. Obfuscation keys are
    /// always a 16-byte MD5 digest, so this cannot fire in normal use.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        assert!(
            !key.is_empty() && key.len() <= 256,
            "RC4 key length must be 1..=256"
        );
        let mut s = [0u8; 256];
        for (idx, slot) in s.iter_mut().enumerate() {
            *slot = idx as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    /// Key an RC4 stream and discard the first 1024 keystream bytes (the eMule
    /// RC4-drop1024 convention).
    #[must_use]
    pub fn with_drop_1024(key: &[u8]) -> Self {
        let mut cipher = Self::new(key);
        let mut discard = [0u8; RC4_DISCARD];
        cipher.apply(&mut discard);
        cipher
    }

    /// XOR the keystream into `buf` in place, advancing the stream.
    pub fn apply(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
            *byte ^= self.s[k as usize];
        }
    }
}

/// The paired RC4 streams for one obfuscated connection.
pub struct ObfuscationKeys {
    /// Encrypts bytes we send.
    pub send: Rc4,
    /// Decrypts bytes we receive.
    pub recv: Rc4,
}

/// Derive the peer (client-to-client) obfuscation key pair from the target's
/// **User Hash**, the 4-byte random key exchanged in the clear, and our role.
/// `send = RC4-drop1024(MD5(user_hash ‖ send_magic ‖ random_key))`, where the
/// initiator sends with `MAGICVALUE_REQUESTER` and the responder with
/// `MAGICVALUE_SERVER` (`docs/reference/notes/obfuscation.md`).
#[must_use]
pub fn derive_peer_keys(
    user_hash: &UserHash,
    random_key: [u8; 4],
    role: ObfuscationRole,
) -> ObfuscationKeys {
    let (send_magic, recv_magic) = match role {
        ObfuscationRole::Initiator => (MAGICVALUE_REQUESTER, MAGICVALUE_SERVER),
        ObfuscationRole::Responder => (MAGICVALUE_SERVER, MAGICVALUE_REQUESTER),
    };
    ObfuscationKeys {
        send: derive_peer_stream(user_hash, send_magic, random_key),
        recv: derive_peer_stream(user_hash, recv_magic, random_key),
    }
}

/// One peer RC4 stream: `RC4-drop1024(MD5(user_hash ‖ magic ‖ random_key))`.
fn derive_peer_stream(user_hash: &UserHash, magic: u8, random_key: [u8; 4]) -> Rc4 {
    let mut hasher = Md5::new();
    hasher.update(user_hash.as_bytes());
    hasher.update([magic]);
    hasher.update(random_key);
    Rc4::with_drop_1024(&hasher.finalize())
}

/// eMule's Diffie-Hellman shared-secret / public-value size in bytes
/// (`PRIMESIZE_BYTES`), for the server obfuscation form. `[pending]`
/// [aMule `EncryptedStreamSocket.cpp`].
pub const DH_PRIME_SIZE: usize = 96;

/// eMule's hardcoded 768-bit DH prime (`dh768_p`), big-endian, generator 2.
/// `[pending]` (aMule `EncryptedStreamSocket.cpp` @`377ec8d9`) — a public
/// constant reproduced under the same evidence gate as every other byte fact
/// (the server interop confirms it).
const DH768_P: [u8; DH_PRIME_SIZE] = [
    0xF2, 0xBF, 0x52, 0xC5, 0x5F, 0x58, 0x7A, 0xDD, 0x53, 0x71, 0xA9, 0x36, 0xE8, 0x86, 0xEB, 0x3C,
    0x62, 0x17, 0xA3, 0x3E, 0xC3, 0x4C, 0xB4, 0x0D, 0xC7, 0x3A, 0x41, 0xA6, 0x43, 0xAF, 0xFC, 0xE7,
    0x21, 0xFC, 0x28, 0x63, 0x66, 0x53, 0x5B, 0xDB, 0xCE, 0x25, 0x9F, 0x22, 0x86, 0xDA, 0x4A, 0x91,
    0xB2, 0x07, 0xCB, 0xAA, 0x52, 0x55, 0xD4, 0xF6, 0x1C, 0xCE, 0xAE, 0xD4, 0x5A, 0xD5, 0xE0, 0x74,
    0x7D, 0xF7, 0x78, 0x18, 0x28, 0x10, 0x5F, 0x34, 0x0F, 0x76, 0x23, 0x87, 0xF8, 0x8B, 0x28, 0x91,
    0x42, 0xFB, 0x42, 0x68, 0x8F, 0x05, 0x15, 0x0F, 0x54, 0x8B, 0x5F, 0x43, 0x6A, 0xF7, 0x0D, 0xF3,
];

/// An ephemeral Diffie-Hellman keypair over `dh768_p` for the server
/// obfuscation handshake (ADR-0042). Public value and agreed secret are 96-byte
/// big-endian, matching eMule's `Encode(buf, PRIMESIZE_BYTES)`.
pub struct ObfuscationDhKeypair {
    private: U768,
}

impl ObfuscationDhKeypair {
    /// Generate a fresh keypair from a random 768-bit exponent.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; DH_PRIME_SIZE];
        OsRng.fill_bytes(&mut bytes);
        Self {
            private: U768::from_be_slice(&bytes),
        }
    }

    /// This side's public value `g^a mod p`, 96-byte big-endian.
    #[must_use]
    pub fn public(&self) -> [u8; DH_PRIME_SIZE] {
        dh_modpow(&U768::from_u8(2), &self.private).to_be_bytes()
    }

    /// The agreed shared secret `peer^a mod p` = `g^(ab) mod p`.
    #[must_use]
    pub fn agree(&self, peer_public: &[u8; DH_PRIME_SIZE]) -> [u8; DH_PRIME_SIZE] {
        let peer = U768::from_be_slice(peer_public);
        dh_modpow(&peer, &self.private).to_be_bytes()
    }
}

/// `base^exponent mod dh768_p`, the modular exponentiation behind the DH
/// public value and shared secret. `dh768_p` is odd (prime), so Montgomery
/// residue arithmetic applies.
fn dh_modpow(base: &U768, exponent: &U768) -> U768 {
    let modulus = U768::from_be_slice(&DH768_P);
    let params = DynResidueParams::new(&modulus);
    DynResidue::new(base, params).pow(exponent).retrieve()
}

/// Derive the server (client↔server) obfuscation key pair from the agreed DH
/// secret and our role: `send = RC4-drop1024(MD5(secret ‖ send_magic))`. There
/// is no random key (unlike the peer form) — the DH secret is the whole basis.
/// The client is the [`Initiator`](ObfuscationRole::Initiator).
#[must_use]
pub fn derive_server_keys(secret: &[u8; DH_PRIME_SIZE], role: ObfuscationRole) -> ObfuscationKeys {
    let (send_magic, recv_magic) = match role {
        ObfuscationRole::Initiator => (MAGICVALUE_REQUESTER, MAGICVALUE_SERVER),
        ObfuscationRole::Responder => (MAGICVALUE_SERVER, MAGICVALUE_REQUESTER),
    };
    ObfuscationKeys {
        send: derive_server_stream(secret, send_magic),
        recv: derive_server_stream(secret, recv_magic),
    }
}

/// One server RC4 stream: `RC4-drop1024(MD5(secret ‖ magic))`.
fn derive_server_stream(secret: &[u8; DH_PRIME_SIZE], magic: u8) -> Rc4 {
    let mut hasher = Md5::new();
    hasher.update(secret);
    hasher.update([magic]);
    Rc4::with_drop_1024(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keystream(mut c: Rc4, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        c.apply(&mut buf);
        buf
    }

    #[test]
    fn rc4_matches_published_test_vector() {
        // Canonical RC4 KAT: key "Key", plaintext "Plaintext" =>
        // ciphertext BB F3 16 E8 D9 40 AF 0A D3.
        let mut data = b"Plaintext".to_vec();
        Rc4::new(b"Key").apply(&mut data);
        assert_eq!(
            data,
            vec![0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]
        );
    }

    #[test]
    fn drop_1024_skips_exactly_1024_keystream_bytes() {
        let key = b"secret-key-material";
        let undropped = keystream(Rc4::new(key), RC4_DISCARD + 16);
        let dropped = keystream(Rc4::with_drop_1024(key), 16);
        assert_eq!(&undropped[RC4_DISCARD..], &dropped[..]);
    }

    #[test]
    fn peer_keys_cross_decrypt_both_directions() {
        // The absolute-direction anchor is a captured decrypt vector; here we prove the
        // role-swap is self-consistent: each side's send stream decrypts at the
        // other side's recv stream. A non-swapped responder would fail this.
        let uh = UserHash::from_bytes([7u8; 16]);
        let rk = [1u8, 2, 3, 4];
        let init = derive_peer_keys(&uh, rk, ObfuscationRole::Initiator);
        let resp = derive_peer_keys(&uh, rk, ObfuscationRole::Responder);

        let plain = b"the quick brown fox".to_vec();

        let mut a = plain.clone();
        let mut s = init.send;
        s.apply(&mut a);
        assert_ne!(a, plain, "encrypt changed bytes");
        let mut r = resp.recv;
        r.apply(&mut a);
        assert_eq!(a, plain, "responder.recv decrypts initiator.send");

        let mut b = plain.clone();
        let mut s2 = resp.send;
        s2.apply(&mut b);
        let mut r2 = init.recv;
        r2.apply(&mut b);
        assert_eq!(b, plain, "initiator.recv decrypts responder.send");
    }

    #[test]
    fn peer_send_and_recv_use_distinct_magics() {
        // Asymmetry: within one role, send (magic 34) and recv (magic 203) must
        // differ. A symmetric loopback reusing one key would hide a flipped
        // direction; this guards against it.
        let uh = UserHash::from_bytes([9u8; 16]);
        let init = derive_peer_keys(&uh, [9, 8, 7, 6], ObfuscationRole::Initiator);
        assert_ne!(keystream(init.send, 32), keystream(init.recv, 32));
    }

    #[test]
    fn byte0_only_known_markers_are_plaintext() {
        for b in [0xE3u8, 0xC5, 0xD4] {
            assert!(is_plaintext_marker(b), "{b:#04x} is a plaintext marker");
        }
        for b in [0x00u8, 0x01, 0xE4, 0xE5, 0xCB, 0x22, 0xFF] {
            assert!(!is_plaintext_marker(b), "{b:#04x} is not plaintext");
        }
    }

    #[test]
    fn dh_round_trip_agrees_a_shared_secret() {
        let a = ObfuscationDhKeypair::generate();
        let b = ObfuscationDhKeypair::generate();
        let s_ab = a.agree(&b.public());
        let s_ba = b.agree(&a.public());
        assert_eq!(s_ab, s_ba, "both sides agree the same DH secret");
        assert_ne!(s_ab, a.public(), "the secret is not merely a public value");
    }

    #[test]
    fn server_keys_cross_decrypt_between_roles() {
        // Same asymmetry discipline as the peer keys: the client (initiator)
        // send stream must decrypt at the server (responder) recv stream, and
        // the two streams within a role must differ (34 vs 203).
        let secret = [0x42u8; DH_PRIME_SIZE];
        let client = derive_server_keys(&secret, ObfuscationRole::Initiator);
        let server = derive_server_keys(&secret, ObfuscationRole::Responder);

        let plain = b"server obfuscation payload".to_vec();
        let mut buf = plain.clone();
        let mut client_send = client.send;
        client_send.apply(&mut buf);
        assert_ne!(buf, plain, "encrypt changed bytes");
        let mut server_recv = server.recv;
        server_recv.apply(&mut buf);
        assert_eq!(buf, plain, "server.recv decrypts client.send");

        // Distinctness (magic 34 vs 203), from a fresh derivation.
        let fresh = derive_server_keys(&secret, ObfuscationRole::Initiator);
        assert_ne!(
            keystream(fresh.send, 32),
            keystream(fresh.recv, 32),
            "a role's send and recv streams differ"
        );
    }
}
