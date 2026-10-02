//! Genuine eNode server-UDP status replies (petermrg/eNode @59b81f7, an
//! unmodified independent Node.js eD2k server), captured for the crypt-ping
//! leg. The headline is eNode's **encrypted
//! `0x97` crypt-pong** — the receive half of server-UDP obfuscation that the
//! emulated Lugdunum eserver only advertises but never speaks (`crypt_ping_answered=false`).
//! These are the counterparty's own reply bytes (ADR-0045 admissible);
//! provenance + the RC4 scheme live alongside in `meta.toml`.

use rmule_ed2k::GlobServStatRes;
use rmule_primitives::{ServerCryptDirection, decrypt_datagram_server};

/// eNode's advertised UDP server key (`conf.udp.serverKey`) — the RC4 base key
/// for both crypt directions, captured independently in the plain advert below.
const SERVER_KEY: u32 = 0x1234_5678;

/// One packet slice of the `enode-server-udp-crypt-20260727` capture.
fn load(name: &str) -> Vec<u8> {
    crate::fixture::captured("enode-server-udp-crypt-20260727", name)
}

/// The plain advert (control leg): eNode announces UDP obfuscation and the
/// serverKey its crypt layer is keyed under — the precondition the crypt-pong
/// builds on. Proven independently of the encrypted reply.
#[test]
fn plain_advert_announces_udp_obfuscation_and_server_key() {
    let res =
        GlobServStatRes::decode_udp(&load("status_res_0x97_plain.bin")).expect("decode plain 0x97");
    let flags = res.udp_flags().expect("advert carries SRV_UDPFLG");
    assert!(
        flags.supports_udp_obfuscation(),
        "eNode advertises UDP_OBFUSCATION (flags 0x{:x})",
        flags.bits()
    );
    assert_eq!(
        res.obfuscation_udp_port(),
        Some(4677),
        "advertised obf UDP port"
    );
    assert_eq!(
        res.server_udp_key(),
        Some(SERVER_KEY),
        "advertised serverKey"
    );
}

/// The headline: eNode's obfuscated `0x97` crypt-pong. The raw datagram is not a
/// plaintext eD2k frame (its first byte is a crypt marker, not `0xE3`), and a
/// direct decode fails — proving the bytes are genuinely encrypted. It decrypts
/// under the advertised serverKey into a well-formed `0x97` that echoes the exact
/// challenge rmule's obfuscated crypt-ping carried: `crypt_ping_answered = TRUE`,
/// the receive half Lugdunum never delivers.
#[test]
fn encrypted_crypt_pong_decrypts_to_valid_status() {
    let raw = load("status_res_0x97_crypt.bin");
    assert_ne!(
        raw.first(),
        Some(&0xE3),
        "crypt-pong is obfuscated, not a plain eD2k frame"
    );
    assert!(
        GlobServStatRes::decode_udp(&raw).is_err(),
        "raw crypt-pong must not parse as plaintext 0x97 (it is encrypted)"
    );

    let plaintext = decrypt_datagram_server(&raw, SERVER_KEY, ServerCryptDirection::FromServer)
        .expect("crypt-pong decrypts under the advertised serverKey");
    let res =
        GlobServStatRes::decode_udp(&plaintext).expect("decrypted crypt-pong is a valid 0x97");

    assert_eq!(
        res.challenge(),
        0x55AA_0042,
        "crypt-pong echoes the obfuscated request's anti-spoof challenge"
    );
    assert_eq!(
        res.server_udp_key(),
        Some(SERVER_KEY),
        "crypt-pong carries the serverKey"
    );
    assert!(
        res.udp_flags()
            .expect("crypt-pong body carries SRV_UDPFLG")
            .supports_udp_obfuscation(),
        "crypt-pong body carries the UDP-obfuscation advert"
    );
}
