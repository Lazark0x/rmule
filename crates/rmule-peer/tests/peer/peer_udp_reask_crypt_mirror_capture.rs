//! The **mirror** of `peer_udp_reask_crypt_capture.rs`: interop flow L re-run
//! after `875b1d3`, with rmule's peer-UDP crypt
//! **send** gate open. In the first crypt run rmule decrypted aMule's obfuscated
//! `0x90` and answered in the clear, because its send gate wants our own public
//! IP and the interop Lugdunum sends the short 8-byte `OP_IDCHANGE`. Here the
//! same short IDCHANGE opens the gate, because a High-ID `client_id` IS our
//! public address.
//!
//! **Evidence discipline (ADR-0045).** rmule's own obfuscated `0x91` is
//! STIMULUS — it proves only that rmule emitted it, and that it is well-formed
//! under the key its recipient derives. The counterparty signal that aMule
//! decoded it is the **absence of aMule's TCP full-ask fallback** on a deadline
//! aMule sets for itself, which is negative evidence with bounds; `meta.toml`
//! states those bounds, and states why the positive signal (a second `0x90`)
//! never came due. Nothing here is fabricated.

use crate::fixture::{AMULE_SENDER_IP, AMULE_USER_HASH, FILE_HASH, RMULE_USER_HASH, load};
use rmule_peer::peer_udp::crypt::PeerUdpCryptTarget;
use rmule_peer::{ReaskAck, ReaskFilePing};
use rmule_primitives::{
    ClientDecryptKeys, ClientEncryptKey, CryptStance, DatagramKeyFamily, DatagramNonce,
    DatagramSenderAddress, FileHash, Ipv4Endpoint, PeerEndpoint, UserHash, decrypt_datagram_client,
    encrypt_datagram_client, is_udp_plaintext_marker, marker_family,
};
use std::net::Ipv4Addr;

const FIXTURE_DIR: &str = "fixtures/peer_udp_reask/captured/amule-233-crypt-reask-mirror-20260728/";

/// **rmule's own** address, and the whole point of the mirror run. rmule learned it from
/// the High-ID `client_id` of a short `OP_IDCHANGE` that carried no public-IP
/// extension at all; it is the `sender_ip` half of the key on rmule's ack.
const RMULE_SENDER_IP: [u8; 4] = [172, 18, 0, 3];

/// The key that opens a datagram **aMule** sent us: our hash, its address.
fn keys_for_amules_send() -> ClientDecryptKeys<'static> {
    static OURS: UserHash = UserHash::from_bytes(RMULE_USER_HASH);
    ClientDecryptKeys {
        user_hash: Some(&OURS),
        sender: DatagramSenderAddress::V4(AMULE_SENDER_IP),
        ..ClientDecryptKeys::default()
    }
}

/// The key that opens a datagram **rmule** sent aMule: aMule's hash, our
/// address. Deriving it is the recipient's-eye view — this is precisely the
/// computation the real aMule performed on the wire.
fn keys_for_rmules_send() -> ClientDecryptKeys<'static> {
    static THEIRS: UserHash = UserHash::from_bytes(AMULE_USER_HASH);
    ClientDecryptKeys {
        user_hash: Some(&THEIRS),
        sender: DatagramSenderAddress::V4(RMULE_SENDER_IP),
        ..ClientDecryptKeys::default()
    }
}

/// **The mirror run's result.** rmule's `OP_REASKACK` left the socket obfuscated, and it
/// opens under exactly the key aMule would derive for it: aMule's own user hash
/// plus rmule's public IP. That IP is the fix — rmule held no public-IP
/// extension this run, only a High-ID `client_id`.
///
/// These are rmule's OWN bytes, so this asserts that the send gate opened and
/// that what it emitted is well-formed and recipient-decodable — nothing about
/// what aMule then did with it. That signal is `meta.toml`'s
/// `[finding.no_tcp_full_ask_fallback]`, which is not assertable from bytes.
#[test]
fn rmules_ack_went_out_obfuscated_keyed_on_our_high_id_address() {
    let bytes = load(FIXTURE_DIR, "reask_ack_0x91_obfuscated.bin");

    // Not plaintext: the first crypt run's ack was the visible `c5 91 05 00 1f 01 00`,
    // and a plaintext marker here would mean the gate was still shut.
    assert!(
        !is_udp_plaintext_marker(bytes[0]),
        "rmule's ack rode in the clear — the send gate did not open: 0x{:02X}",
        bytes[0],
    );
    assert_eq!(marker_family(bytes[0]), DatagramKeyFamily::Ed2kUserHash);

    let decrypted = decrypt_datagram_client(&bytes, &keys_for_rmules_send())
        .expect("rmule's ack opens under the key aMule derives for it");
    assert_eq!(decrypted.family, DatagramKeyFamily::Ed2kUserHash);

    // The packet inside is byte-for-byte the one the first crypt run sent in the
    // clear: the layer changed, the payload did not.
    assert_eq!(
        decrypted.payload,
        [0xC5, 0x91, 0x05, 0x00, 0x1F, 0x01, 0x00]
    );
    let ack = ReaskAck::decode_udp(&decrypted.payload, 4).expect("the v4 ack shape decodes");
    let part_status = ack
        .part_status
        .as_ref()
        .expect("the v4 ack carries our availability");
    assert_eq!(part_status.part_count(), 5);
    assert_eq!(ack.rank, 1);
    assert_eq!(ack.encode_udp(), decrypted.payload);
}

/// Vacuity guard for the ack: our own public IP is load-bearing key material,
/// not decoration. Swap it for the address rmule would have keyed on if it had
/// taken the *counterparty's* IP, or corrupt the ciphertext, and nothing opens.
/// Without this the test above could pass on a datagram keyed any which way.
#[test]
fn the_acks_key_really_is_our_own_address() {
    let bytes = load(FIXTURE_DIR, "reask_ack_0x91_obfuscated.bin");

    let their_ip = ClientDecryptKeys {
        sender: DatagramSenderAddress::V4(AMULE_SENDER_IP),
        ..keys_for_rmules_send()
    };
    assert!(
        decrypt_datagram_client(&bytes, &their_ip).is_none(),
        "the ack is keyed on OUR address; the recipient's must not open it",
    );

    let stranger = UserHash::from_bytes([0x43; 16]);
    let wrong_hash = ClientDecryptKeys {
        user_hash: Some(&stranger),
        ..keys_for_rmules_send()
    };
    assert!(
        decrypt_datagram_client(&bytes, &wrong_hash).is_none(),
        "rmule keyed the send on the RECIPIENT's user hash; a stranger's must not open it",
    );

    let mut flipped = bytes.clone();
    flipped[4] ^= 0x01; // inside the encrypted region, over the sync word
    assert!(
        decrypt_datagram_client(&flipped, &keys_for_rmules_send()).is_none(),
        "a flipped ciphertext byte must fail the sync-word check",
    );
}

/// The inbound half, kept so the fixture holds the whole exchange: aMule's
/// first obfuscated reask, the datagram rmule answered. This direction was
/// already proven in `amule-233-crypt-reask-20260728`; reproducing it
/// here confirms the mirror run reproduced the same consume behaviour, and pins
/// this run's own marker literal — a *different* byte from the first crypt run's `0xE7`, in the
/// same family, which is why the marker is only ever asserted as a family.
#[test]
fn the_inbound_reask_this_run_answered_is_the_same_v4_shape_with_a_new_marker() {
    let bytes = load(FIXTURE_DIR, "reask_ping_0x90_obfuscated.bin");
    assert_eq!(marker_family(bytes[0]), DatagramKeyFamily::Ed2kUserHash);
    assert_eq!(
        bytes[0] & 0x03,
        3,
        "this run drew the `3` alias (0x0B); the first run drew 0xE7 — same family, different byte",
    );

    let decrypted = decrypt_datagram_client(&bytes, &keys_for_amules_send())
        .expect("aMule's reask decrypts under our own key");
    let ping = ReaskFilePing::decode_udp(&decrypted.payload, 4)
        .expect("the decrypted payload is a v4 reask ping");
    assert_eq!(ping.file_hash, FileHash::from_bytes(FILE_HASH));
    assert_eq!(
        ping.part_status
            .as_ref()
            .expect("a v4 reask ping carries the part status")
            .part_count(),
        5,
    );
    assert_eq!(ping.complete_sources, Some(1));
}

/// The send gate's verdict on each crypt run's facts is the layer rmule's ack
/// actually rode. Both runs had the same two stances — rmule supporting the
/// layer, aMule supporting and requesting it — and differed only in whether
/// rmule knew its own public address. Without it (the sibling run) the ack left
/// plaintext; with it (this run) the gate keys on that address, and sealing the
/// plaintext ack under that key with the run's own nonce (the marker and seed
/// travel in the clear, padding is off) rebuilds the captured datagram byte for
/// byte.
#[test]
fn the_send_gate_reads_each_runs_facts_as_the_ack_rode() {
    let amule = PeerUdpCryptTarget::new(
        UserHash::from_bytes(AMULE_USER_HASH),
        CryptStance::new(true, true, false),
    );
    let rmule_supported = CryptStance::new(true, false, false);
    let to_amule = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::from(AMULE_SENDER_IP), 4672));

    let sibling_ack = load(
        "fixtures/peer_udp_reask/captured/amule-233-crypt-reask-20260728/",
        "reask_ack_0x91_plaintext.bin",
    );
    assert_eq!(
        amule.obfuscation_sender(rmule_supported, to_amule, None, None),
        None
    );
    assert!(is_udp_plaintext_marker(sibling_ack[0]));

    let sender = amule
        .obfuscation_sender(
            rmule_supported,
            to_amule,
            Some(Ipv4Addr::from(RMULE_SENDER_IP)),
            None,
        )
        .expect("this run's facts open the gate");
    assert_eq!(sender, DatagramSenderAddress::V4(RMULE_SENDER_IP));
    let captured = load(FIXTURE_DIR, "reask_ack_0x91_obfuscated.bin");
    let nonce = DatagramNonce {
        marker_byte: captured[0],
        random_key: u16::from_le_bytes([captured[1], captured[2]]),
        padding: Vec::new(),
    };
    let key = ClientEncryptKey::Ed2k {
        user_hash: &amule.user_hash,
        sender,
    };
    assert_eq!(
        encrypt_datagram_client(&sibling_ack, &key, &nonce),
        captured
    );
}
