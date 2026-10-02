//! The genuine **challenge-keyed crypt-pong** from `andrey23127/ed2k-server`
//! @ `eacf7f1`: an obfuscated `0x97` answering rmule's raw
//! `[challenge u32 LE][padding]` crypt-ping on the server's TCP+12 listener
//! (ed2ksrv capture, 2026-08-02).
//!
//! This is what retires the `[pending]` marker on
//! `rmule_core::server_udp::encode_crypt_ping`. The eNode verdict stated the
//! gap exactly — "no independent server in the bench implements a
//! challenge-keyed server-UDP path" — so rmule's pre-key-learned crypt-ping
//! variant (aMule's `CryptPingReplyPending` form) had a decoder and an emitter
//! but no counterparty. This server has that path, and the bytes below are its
//! reply. Note the contrast with `captured_enode_crypt.rs`: eNode's crypt-pong
//! is keyed on a **serverKey learned from a prior plain advert**, whereas this
//! one is keyed on the **challenge rmule itself minted**, which is the whole
//! distinction the `[pending]` marker was about.
//!
//! Provenance, topology and the 20/20 answer rate live in `meta.toml`.

use rmule_ed2k::GlobServStatRes;
use rmule_primitives::{ServerCryptDirection, decrypt_datagram_server};

/// The challenge rmule minted for this exchange. It is not stored anywhere as a
/// bare number on purpose — it is read back out of the *decrypted* reply, whose
/// echo of it is the anti-spoof gate. `challenge_keyed_pong_decrypts_under_the_echoed_challenge`
/// then feeds that value back as the RC4 key, so the two files are cross-checked
/// against each other rather than against a hand-copied constant.
fn echoed_challenge() -> u32 {
    GlobServStatRes::decode_udp(&load("crypt_ping_0x97_plain.bin"))
        .expect("decode decrypted 0x97")
        .challenge()
}

/// One packet slice of the `ed2ksrv-crypt-ping-20260802` capture.
fn load(name: &str) -> Vec<u8> {
    crate::fixture::captured("ed2ksrv-crypt-ping-20260802", name)
}

/// The headline, and the one assertion that ratifies the emitter: the raw
/// datagram is genuinely encrypted, and it decrypts — under the challenge
/// **rmule chose**, in the server→client direction — into exactly the plaintext
/// stored beside it.
///
/// The key is lifted from the decrypted file's own echoed challenge, so neither
/// file can be corrupted without the test failing: damage the ciphertext and
/// RC4 yields garbage that no longer equals the plaintext; damage the plaintext
/// and the challenge read out of it changes, so the key is wrong and the
/// decryption diverges. There is no third file holding the answer.
#[test]
fn challenge_keyed_pong_decrypts_under_the_echoed_challenge() {
    let raw = load("crypt_ping_0x97_raw.bin");
    assert_ne!(
        raw.first(),
        Some(&0xE3),
        "a crypt-pong is obfuscated, not a plain eD2k frame — a 0xE3 first byte \
         would mean the server answered in the clear and the row is unproven"
    );
    assert!(
        GlobServStatRes::decode_udp(&raw).is_err(),
        "the raw datagram must NOT decode as a plaintext 0x97"
    );

    let plaintext =
        decrypt_datagram_server(&raw, echoed_challenge(), ServerCryptDirection::FromServer)
            .expect("the crypt-pong must decrypt under the challenge rmule minted");
    assert_eq!(
        plaintext,
        load("crypt_ping_0x97_plain.bin"),
        "decrypting the captured ciphertext must reproduce the captured plaintext"
    );
}

/// The decrypted inner frame is a well-formed `0x97` that echoes our challenge
/// and advertises the obfuscation capability the crypt path implies. The echo
/// is what makes the reply *ours* rather than a replayed or spoofed datagram.
#[test]
fn decrypted_pong_is_a_status_reply_that_echoes_our_challenge() {
    let plain = load("crypt_ping_0x97_plain.bin");
    let res = GlobServStatRes::decode_udp(&plain).expect("decode decrypted 0x97");

    // Re-derive the challenge straight off the wire bytes rather than through
    // the accessor, so a decoder that silently dropped the field could not make
    // the echo assertion pass vacuously.
    let on_the_wire = u32::from_le_bytes([plain[2], plain[3], plain[4], plain[5]]);
    assert_eq!(
        res.challenge(),
        on_the_wire,
        "the decoded challenge must be the bytes at the 0x97 challenge offset"
    );

    let flags = res.udp_flags().expect("the reply carries SRV_UDPFLG");
    assert!(
        flags.supports_udp_obfuscation(),
        "a server that answers a crypt-ping advertises UDP obfuscation (flags 0x{:X})",
        flags.bits()
    );
    assert_eq!(
        res.obfuscation_udp_port(),
        Some(4675),
        "advertised obfuscated UDP port (the server's TCP+14 listener)"
    );
}

/// The plain-ping control leg, captured in the same probe run against TCP+4.
/// It proves the two surfaces agree about the server's advertised capabilities,
/// so the crypt leg above cannot be a differently-configured listener answering
/// — and it is the sibling comparison that shows the crypt reply's *content* is
/// ordinary while only its framing is obfuscated.
#[test]
fn plain_advert_and_crypt_pong_agree_on_capabilities() {
    let plain_leg =
        GlobServStatRes::decode_udp(&load("plain_ping_0x97.bin")).expect("decode plain 0x97");
    let crypt_leg = GlobServStatRes::decode_udp(&load("crypt_ping_0x97_plain.bin"))
        .expect("decode decrypted 0x97");

    assert_eq!(
        plain_leg.udp_flags().map(|f| f.bits()),
        crypt_leg.udp_flags().map(|f| f.bits()),
        "the two listeners must advertise the same SRV_UDPFLG"
    );
    assert_eq!(
        plain_leg.obfuscation_udp_port(),
        crypt_leg.obfuscation_udp_port(),
        "the two listeners must advertise the same obfuscated UDP port"
    );
    assert_ne!(
        plain_leg.challenge(),
        crypt_leg.challenge(),
        "the legs were separate exchanges with independently minted challenges — \
         equal challenges would mean one file is a copy of the other"
    );
}
