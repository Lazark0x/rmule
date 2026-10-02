//! Secure User Identification crypto primitive: the RSA keypair, signing, and
//! verification that prove a peer owns the **User Hash** it claims (ADR-0041).
//!
//! This is the crypto *primitive* layer only. The protocol packets, the
//! challenge/response state machine, and the signing-input assembly live in
//! `rmule-peer`; at-rest key storage lives in `rmule-core`. The scheme is
//! *honored, not strengthened*: 384-bit RSA with RSASSA-PKCS1v15 / SHA-1
//! (CryptoPP `RSASSA_PKCS1v15_SHA_Signer`, confirmed against the 2026-07-06
//! captured aMule signature — the spec-derived note first said MD5), because
//! eMule stores a peer public key in an 80-byte buffer (`MAXPUBKEYSIZE`) that
//! a stronger key would overflow, silently breaking SUI. Pinned in
//! `docs/reference/notes/secure-ident.md`.

use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;

use crate::error::{PrimitiveError, Result};

/// eMule's Secure User Identification RSA key size, in bits. Honored rather than
/// strengthened: eMule stores a peer public key in an 80-byte buffer
/// (`MAXPUBKEYSIZE`), so a larger key overflows it and SUI silently fails
/// (ADR-0041).
pub const SUI_RSA_KEY_BITS: usize = 384;

/// Our own long-lived Secure User Identification keypair. Generated once and
/// persisted by the application layer; used to sign a peer's challenge.
///
/// `Clone` lets the application share one keypair across peer sessions via
/// `Arc`. Equality compares the keys (used only for config equality in tests);
/// `Debug` is redacted so a private key never lands in a log line.
#[derive(Clone)]
pub struct SecureIdentKey {
    private: RsaPrivateKey,
}

impl PartialEq for SecureIdentKey {
    fn eq(&self, other: &Self) -> bool {
        self.private == other.private
    }
}

impl Eq for SecureIdentKey {}

impl core::fmt::Debug for SecureIdentKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecureIdentKey(<redacted>)")
    }
}

impl SecureIdentKey {
    /// Generate a fresh 384-bit keypair from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, SUI_RSA_KEY_BITS)
            .map_err(|_| PrimitiveError::KeyGenerationFailed)?;
        Ok(Self { private })
    }

    /// Serialize the keypair to PKCS#1 DER for at-rest persistence by the
    /// application layer. The at-rest format is rmule's own choice — only the
    /// wire public key (`public_key_der`) must match eMule's encoding.
    #[must_use]
    pub fn to_der(&self) -> Vec<u8> {
        self.private
            .to_pkcs1_der()
            .expect("PKCS#1 DER encoding of a valid RSA private key is infallible")
            .as_bytes()
            .to_vec()
    }

    /// Reload a keypair from its PKCS#1 DER bytes.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let private =
            RsaPrivateKey::from_pkcs1_der(der).map_err(|_| PrimitiveError::InvalidPrivateKey)?;
        Ok(Self { private })
    }

    /// Sign `message` with RSASSA-PKCS1v15 / SHA-1. Deterministic — the same key
    /// and message always produce the same bytes, which is what lets a captured
    /// `(key, message, signature)` triple be a reproducible fixture.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signing_key = SigningKey::<Sha1>::new(self.private.clone());
        signing_key.sign(message).to_vec()
    }

    /// The DER encoding of the public half, as carried in `OP_PUBLICKEY`:
    /// X.509 `SubjectPublicKeyInfo` — what CryptoPP's `DEREncode` emits and
    /// what a real aMule sent on the wire (captured 2026-07-06, 76 bytes for a
    /// 384-bit key, within `MAXPUBKEYSIZE` 80). The spec-derived note first
    /// assumed bare PKCS#1; the capture corrected it.
    #[must_use]
    pub fn public_key_der(&self) -> Vec<u8> {
        RsaPublicKey::from(&self.private)
            .to_public_key_der()
            .expect("SPKI DER encoding of a valid RSA public key is infallible")
            .into_vec()
    }
}

/// A peer's Secure User Identification public key, decoded from `OP_PUBLICKEY`
/// and used to verify that peer's signatures.
pub struct SecureIdentPublicKey {
    public: RsaPublicKey,
}

impl SecureIdentPublicKey {
    /// Decode a peer public key from its X.509 `SubjectPublicKeyInfo` DER
    /// bytes — the wire format a real aMule sends (captured 2026-07-06).
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let public =
            RsaPublicKey::from_public_key_der(der).map_err(|_| PrimitiveError::InvalidPublicKey)?;
        Ok(Self { public })
    }

    /// Re-encode this public key to `SubjectPublicKeyInfo` DER.
    #[must_use]
    pub fn to_der(&self) -> Vec<u8> {
        self.public
            .to_public_key_der()
            .expect("SPKI DER encoding of a valid RSA public key is infallible")
            .into_vec()
    }

    /// Verify an RSASSA-PKCS1v15 / SHA-1 `signature` over `message`. Returns
    /// `false` for a bad signature, a wrong key, or malformed signature bytes —
    /// never panics.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let verifying_key = VerifyingKey::<Sha1>::new(self.public.clone());
        match Signature::try_from(signature) {
            Ok(signature) => verifying_key.verify(message, &signature).is_ok(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keypair_signs_and_verifies_a_message() {
        let key = SecureIdentKey::generate().expect("generate 384-bit keypair");
        let message = b"secure ident challenge bytes";
        let signature = key.sign(message);
        let public_key =
            SecureIdentPublicKey::from_der(&key.public_key_der()).expect("decode our own DER key");
        assert!(
            public_key.verify(message, &signature),
            "a fresh signature must verify under its own public key"
        );
    }

    #[test]
    fn verify_rejects_tampering_wrong_key_and_garbage() {
        let key = SecureIdentKey::generate().expect("keypair");
        let message = b"authentic challenge";
        let signature = key.sign(message);
        let public_key = SecureIdentPublicKey::from_der(&key.public_key_der()).expect("der");

        assert!(
            !public_key.verify(b"a different challenge", &signature),
            "a signature must not verify over a tampered message"
        );

        let other = SecureIdentKey::generate().expect("second keypair");
        let other_public = SecureIdentPublicKey::from_der(&other.public_key_der()).expect("der");
        assert!(
            !other_public.verify(message, &signature),
            "a signature must not verify under a different peer's key"
        );

        assert!(
            !public_key.verify(message, b"not a signature"),
            "malformed signature bytes must be rejected, not panic"
        );

        // Sanity: the genuine signature still verifies (the negatives above are
        // not passing because verify is vacuously false).
        assert!(public_key.verify(message, &signature));
    }

    #[test]
    fn public_key_der_fits_emules_80_byte_buffer() {
        // eMule stores a peer public key in MAXPUBKEYSIZE = 80 bytes; a 384-bit
        // key must fit or SUI silently fails on the peer side (ADR-0041). This is
        // the interop claim the whole honor-384 decision rests on.
        let key = SecureIdentKey::generate().expect("keypair");
        let der = key.public_key_der();
        assert!(
            der.len() <= 80,
            "384-bit PKCS#1 public key DER is {} bytes; must fit MAXPUBKEYSIZE = 80",
            der.len()
        );
    }

    #[test]
    fn keypair_der_round_trips_preserving_identity() {
        // The application layer persists and reloads the keypair. A
        // reloaded key must be the *same* key: because RSASSA-PKCS1v15 is
        // deterministic, it reproduces the same signature bytes, and its public
        // half still verifies.
        let key = SecureIdentKey::generate().expect("keypair");
        let reloaded = SecureIdentKey::from_der(&key.to_der()).expect("reload keypair from DER");

        let message = b"round-trip challenge";
        assert_eq!(
            key.sign(message),
            reloaded.sign(message),
            "a reloaded keypair must reproduce identical deterministic signatures"
        );

        let public =
            SecureIdentPublicKey::from_der(&reloaded.public_key_der()).expect("reloaded pub key");
        assert!(public.verify(message, &reloaded.sign(message)));

        assert!(
            SecureIdentKey::from_der(b"not a private key").is_err(),
            "garbage DER must be rejected, not panic"
        );
    }
}
