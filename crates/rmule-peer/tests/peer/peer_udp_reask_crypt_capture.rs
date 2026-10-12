//! Obfuscated peer-UDP source-reask capture (genuine stock aMule 2.3.3, interop
//! flow L `peer-udp-reask` with both sides crypt-armed, run `1785247757`). The
//! `0x90` is aMule's own datagram — the first counterparty
//! peer-UDP crypt bytes rmule has seen; the `0x91` is rmule's egress answer on
//! the same tcpdump, kept as the honest record of the send-gate gap the run
//! exposed. Provenance, every precondition, and the root cause live alongside in
//! `meta.toml`. Counterparty and own bytes only — nothing here is fabricated.

use crate::fixture::{AMULE_SENDER_IP, FILE_HASH, RMULE_USER_HASH, load};
use rmule_peer::{ReaskAck, ReaskFilePing};
use rmule_primitives::{
    ClientDecryptKeys, DatagramKeyFamily, DatagramSenderAddress, FileHash, UserHash,
    decrypt_datagram_client, is_udp_plaintext_marker, marker_family,
};

const FIXTURE_DIR: &str = "fixtures/peer_udp_reask/captured/amule-233-crypt-reask-20260728/";

fn our_keys() -> ClientDecryptKeys<'static> {
    static OURS: UserHash = UserHash::from_bytes(RMULE_USER_HASH);
    ClientDecryptKeys {
        user_hash: Some(&OURS),
        sender: DatagramSenderAddress::V4(AMULE_SENDER_IP),
        ..ClientDecryptKeys::default()
    }
}

/// aMule obfuscated its reask, and the datagram decrypts under the ed2k client
/// key rmule derives from its *own* user hash plus the sender's IP — the
/// ADR-0046 receive path against real counterparty bytes. The recovered
/// plaintext is a whole `OP_REASKFILEPING` for the file rmule serves.
#[test]
fn amules_obfuscated_reask_decrypts_under_our_ed2k_key_and_is_a_v4_on_file_ping() {
    let bytes = load(FIXTURE_DIR, "reask_ping_0x90_obfuscated.bin");

    // It really is obfuscated: the leading byte is not one of the plaintext
    // protocol markers a receiver passes through untouched.
    assert!(
        !is_udp_plaintext_marker(bytes[0]),
        "a plaintext marker would mean aMule declined to obfuscate: 0x{:02X}",
        bytes[0]
    );
    // Read the marker as the MASKED field it is. aMule draws
    // `GetRandomUint8() | 0x01`, leaving bit 1 random, so it emits `..01` or
    // `..11`; rmule's primitive always emits `..01`. Both fold onto the same key
    // family, so only the family is a fact about the wire.
    assert_eq!(marker_family(bytes[0]), DatagramKeyFamily::Ed2kUserHash);
    assert_eq!(
        bytes[0] & 0x03,
        3,
        "this capture happens to carry the `3` alias rmule never emits — the \
         reason an exact-byte marker comparison would flake against a live aMule",
    );

    let decrypted =
        decrypt_datagram_client(&bytes, &our_keys()).expect("aMule's datagram decrypts for us");
    assert_eq!(decrypted.family, DatagramKeyFamily::Ed2kUserHash);
    assert_eq!(
        (decrypted.receiver_verify_key, decrypted.sender_verify_key),
        (None, None),
        "the ed2k family carries no Kad verify-key trailer",
    );

    // The recovered plaintext is exactly what the plaintext sibling capture
    // (`amule-233-peer-udp-reask-20260727`) recorded on the wire: a v4 reask.
    let ping = ReaskFilePing::decode_udp(&decrypted.payload, 4)
        .expect("the decrypted payload is a v4 reask ping");
    assert_eq!(ping.file_hash, FileHash::from_bytes(FILE_HASH));
    let part_status = ping
        .part_status
        .as_ref()
        .expect("a v4 reask ping carries the part status");
    assert_eq!(
        part_status.part_count(),
        5,
        "the 40 MiB file spans 5 ED2K parts",
    );
    assert_eq!(ping.complete_sources, Some(1));
    assert_eq!(ping.encode_udp(), decrypted.payload);
}

/// Vacuity guard: the decrypt is not a rubber stamp. One flipped ciphertext byte
/// corrupts the RC4-covered sync word and the datagram is rejected — so the test
/// above cannot pass by accepting garbage. The same holds for the two key
/// inputs: a wrong receiver hash or a wrong sender IP derives a different key
/// and validates nothing.
#[test]
fn a_corrupted_datagram_or_a_wrong_key_input_decrypts_to_nothing() {
    let bytes = load(FIXTURE_DIR, "reask_ping_0x90_obfuscated.bin");

    let mut flipped = bytes.clone();
    flipped[4] ^= 0x01; // inside the encrypted region, over the sync word
    assert!(
        decrypt_datagram_client(&flipped, &our_keys()).is_none(),
        "a flipped ciphertext byte must fail the sync-word check",
    );

    let stranger = UserHash::from_bytes([0x43; 16]);
    let wrong_hash = ClientDecryptKeys {
        user_hash: Some(&stranger),
        ..our_keys()
    };
    assert!(
        decrypt_datagram_client(&bytes, &wrong_hash).is_none(),
        "aMule keyed the send on OUR user hash; another node's hash must not open it",
    );

    let wrong_ip = ClientDecryptKeys {
        sender: DatagramSenderAddress::V4([172, 18, 0, 4]),
        ..our_keys()
    };
    assert!(
        decrypt_datagram_client(&bytes, &wrong_ip).is_none(),
        "the sender IP is key material — the slot-holder's address must not open it",
    );
}

/// rmule's own egress, 2.0 ms after the inbound ping: the reply matrix answered
/// with the corrected v4 form (full part status, not the rank-only shape the
/// 2026-07-27 capture exposed) — but **in the clear**, while the counterparty
/// obfuscated. The cause is pinned on the wire in `meta.toml`: rmule learns its
/// public IP only from the `OP_IDCHANGE` public-IP extension, the interop
/// Lugdunum sends the 8-byte form, so the send gate's `public_ip_known()` stayed
/// false. aMule cleared the same gate off its `m_localip` fallback. These bytes
/// are the provenance-true record of that asymmetry.
#[test]
fn rmules_ack_carried_the_corrected_v4_part_status_but_went_out_plaintext() {
    let bytes = load(FIXTURE_DIR, "reask_ack_0x91_plaintext.bin");
    assert_eq!(bytes, [0xC5, 0x91, 0x05, 0x00, 0x1F, 0x01, 0x00]);
    assert!(
        is_udp_plaintext_marker(bytes[0]),
        "rmule's answer rode as plaintext OP_EMULEPROT",
    );

    let ack = ReaskAck::decode_udp(&bytes, 4).expect("the v4 ack shape decodes");
    let part_status = ack
        .part_status
        .as_ref()
        .expect("the corrected ack carries our availability");
    assert_eq!(part_status.part_count(), 5);
    assert_eq!(ack.rank, 1);
    assert_eq!(ack.encode_udp(), bytes);
}
