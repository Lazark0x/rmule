//! Real-aMule captured evidence (2026-07-06, `amule-direct-sui` interop run
//! `1783346034`, Ubuntu `amule-daemon`, throwaway container identities): one
//! coherent V1 Secure User Identification exchange, promoted as golden
//! vectors. Because RSASSA-PKCS1v15 is deterministic, the captured triple is a
//! forever-reproducible byte-compat assertion — no live aMule in the loop.
//!
//! Two spec-derived assumptions died against these bytes:
//! - CryptoPP `DEREncode` emits X.509 `SubjectPublicKeyInfo` (76 bytes for a
//!   384-bit key), **not** bare PKCS#1.
//! - The scheme is PKCS1v15 + **SHA-1** (`RSASSA_PKCS1v15_SHA_Signer`), not
//!   the spec note's MD5.

use rmule_primitives::{SecureIdentKey, SecureIdentPublicKey};

/// aMule's `OP_PUBLICKEY` body (length prefix stripped).
const AMULE_KEY_SPKI: &[u8] = include_bytes!("../fixtures/amule_sui_public_key_spki.bin");
/// rmule's own wire key from the same exchange — the verifier key aMule
/// folded into its signing input.
const RMULE_KEY_SPKI: &[u8] = include_bytes!("../fixtures/rmule_sui_public_key_spki.bin");
/// aMule's `OP_SIGNATURE` body (length prefix stripped; V1 — no kind byte).
const AMULE_SIGNATURE: &[u8] = include_bytes!("../fixtures/amule_sui_signature.bin");
/// The SUI Challenge rmule sent in `OP_SECIDENTSTATE`, little-endian wire bytes.
const RMULE_CHALLENGE_LE: [u8; 4] = [0x48, 0xD3, 0xE4, 0xE6];

#[test]
fn real_amule_public_key_parses_as_a_wire_key() {
    let key = SecureIdentPublicKey::from_der(AMULE_KEY_SPKI)
        .expect("aMule's captured SubjectPublicKeyInfo key must parse");
    // Re-encoding reproduces the captured bytes exactly — same DER flavor.
    assert_eq!(key.to_der(), AMULE_KEY_SPKI);
}

#[test]
fn rmule_wire_key_is_spki_shaped_like_amules() {
    let key = SecureIdentKey::generate().unwrap();
    let der = key.public_key_der();
    // Same AlgorithmIdentifier (rsaEncryption + NULL params) as the capture —
    // the fixed 15-byte sequence at offset 2 of a 384-bit RSA SPKI.
    assert_eq!(
        &der[2..17],
        &AMULE_KEY_SPKI[2..17],
        "rmule's wire key must carry the SPKI AlgorithmIdentifier"
    );
    assert!(der.len() <= 80, "must still fit MAXPUBKEYSIZE");
    SecureIdentPublicKey::from_der(&der).expect("round-trips through the wire parser");
}

/// The golden vector: aMule's real V1 signature over
/// `[rmule's wire key ‖ challenge (u32-le)]` verifies under aMule's real key —
/// pinning the signing-input layout, the hash (SHA-1), and the padding at
/// byte level.
#[test]
fn real_amule_v1_signature_verifies() {
    let key = SecureIdentPublicKey::from_der(AMULE_KEY_SPKI).expect("aMule key");
    let mut input = RMULE_KEY_SPKI.to_vec();
    input.extend_from_slice(&RMULE_CHALLENGE_LE);
    assert!(
        key.verify(&input, AMULE_SIGNATURE),
        "the captured aMule signature must verify over [verifier key ‖ challenge]"
    );
}

/// Guard against a vacuous fixture: flip one byte anywhere and the
/// verification must fail.
#[test]
fn a_byte_flip_breaks_the_captured_vector() {
    let key = SecureIdentPublicKey::from_der(AMULE_KEY_SPKI).expect("aMule key");
    let mut input = RMULE_KEY_SPKI.to_vec();
    input.extend_from_slice(&RMULE_CHALLENGE_LE);

    let mut flipped_input = input.clone();
    flipped_input[10] ^= 0x01;
    assert!(!key.verify(&flipped_input, AMULE_SIGNATURE));

    let mut flipped_sig = AMULE_SIGNATURE.to_vec();
    flipped_sig[10] ^= 0x01;
    assert!(!key.verify(&input, &flipped_sig));
}
