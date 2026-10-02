//! Peer obfuscation captured decrypt-vector (ADR-0042): a real aMule
//! 2.3.3 obfuscated-handshake reply, captured live via the interop harness, that
//! rmule decrypts to `MAGICVALUE_SYNC` with no live aMule in the loop. This is the
//! *absolute-direction* anchor — it pins the `MAGICVALUE_SERVER` (203) responder
//! magic against aMule's real bytes, which a rmule↔rmule loopback cannot.
//!
//! Capture provenance: rmule (`ed2k peer transfer capture --obfuscation required`)
//! dialed a crypt-enabled aMule 2.3.3 in the `amule-direct-obfs` harness; the full
//! obfuscated session (hello + Secure User Identification) completed through the
//! crypt layer. `amule_obfs_responder_reply.bin` (36 bytes) is
//! `[aMule user hash 16][rmule random key 4][aMule encrypted reply 16]`. rmule sent
//! the random key in the clear; aMule (the responder) encrypted its reply with
//! `RC4-drop1024(MD5(user_hash ‖ 203 ‖ random_key))`, which is exactly rmule's
//! *receive* key as the initiator.

use rmule_primitives::{MAGICVALUE_SYNC, ObfuscationRole, UserHash, derive_peer_keys};

const FIXTURE: &[u8] = include_bytes!("../fixtures/amule_obfs_responder_reply.bin");

fn parts() -> (UserHash, [u8; 4], Vec<u8>) {
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&FIXTURE[0..16]);
    let mut random_key = [0u8; 4];
    random_key.copy_from_slice(&FIXTURE[16..20]);
    (
        UserHash::from_bytes(hash),
        random_key,
        FIXTURE[20..].to_vec(),
    )
}

#[test]
fn real_amule_reply_decrypts_to_magicvalue_sync() {
    let (user_hash, random_key, reply) = parts();
    // As the initiator, rmule's receive key decrypts the responder's stream:
    // RC4-drop1024(MD5(user_hash ‖ MAGICVALUE_SERVER ‖ random_key)).
    let mut keys = derive_peer_keys(&user_hash, random_key, ObfuscationRole::Initiator);
    let mut plain = reply.clone();
    keys.recv.apply(&mut plain);

    assert_eq!(
        &plain[0..4],
        &MAGICVALUE_SYNC.to_le_bytes(),
        "real aMule reply decrypts to MAGICVALUE_SYNC — 203 responder direction confirmed"
    );
    // The byte after the sync is the selected encryption method (ENM_OBFUSCATION = 0).
    assert_eq!(
        plain[4], 0,
        "aMule selected the only defined method, ENM_OBFUSCATION"
    );
}

#[test]
fn a_one_byte_flip_breaks_the_decrypt_vector() {
    // Vacuity guard: the assertion is not trivially satisfiable — corrupting one
    // captured ciphertext byte makes the decrypt no longer yield the sync magic.
    let (user_hash, random_key, mut reply) = parts();
    reply[0] ^= 0x01;
    let mut keys = derive_peer_keys(&user_hash, random_key, ObfuscationRole::Initiator);
    keys.recv.apply(&mut reply);
    assert_ne!(
        &reply[0..4],
        &MAGICVALUE_SYNC.to_le_bytes(),
        "a flipped ciphertext byte must not still decrypt to the sync magic"
    );
}
