//! ADR-0058's UDP self-check, **stock aMule 2.3.3 as the requester** (interop
//! flow `natt-udp-selfcheck-amule`, runs `1790147257`
//! plaintext and `1790148195` with `AMULE_KAD_CRYPT=1`). aMule, firewalled
//! behind a gateway that forwards its Kad port, dialed a fresh rmule UDP
//! Firewall Helper and sent `OP_FWCHECKUDPREQ` (`0xA7`); the helper answered
//! `KADEMLIA2_FIREWALLUDP` (`0x62`), and aMule's own debug log read
//! `New Kad Firewallstate (UDP): Open, using intern port` off it.
//!
//! The `0xA7` frames are aMule's bytes. The `0x62` datagrams are the rmule
//! helper's, captured on the gateway's WAN tap and **accepted by aMule** — in
//! the crypt run keyed on the verify key the `0xA7` carried, which is the
//! documentation-derived KAT meeting the wire. Provenance lives in
//! `meta.toml`.

use std::net::Ipv4Addr;

use rmule_kad::KadNodeEndpoint;
use rmule_primitives::session::drain;
use rmule_primitives::{
    ClientDecryptKeys, ClientEncryptKey, DatagramKeyFamily, DatagramNonce, decrypt_datagram_client,
    encrypt_datagram_client,
};
use rmule_testkit::kad_node::{datagrams, node};

use crate::fixture::le_u16;

const FIXTURE_DIR: &str = "fixtures/firewalled/captured/amule-233-udp-firewall-check-20260923/";

/// aMule's address as every helper saw it: the gateway's WAN side.
const AMULE_PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(45, 55, 200, 4);

/// aMule's Kad UDP port — intern and, through the pinned gateway, extern.
const AMULE_KAD_PORT: u16 = 4672;

fn load(name: &str) -> Vec<u8> {
    crate::fixture::captured(FIXTURE_DIR, name)
}

/// The `0xA7` body out of aMule's eD2k-framed packet: `0xC5`, a 4-byte
/// little-endian size, the opcode, then intern port, extern port and the
/// verify key aMule holds for the helper's IP (`BaseClient.cpp:2937-2939`, aMule 2.3.3).
fn fwcheck_body(frame: &[u8]) -> &[u8] {
    assert_eq!(frame[0], 0xC5, "OP_EMULEPROT");
    assert_eq!(frame[5], 0xA7, "OP_FWCHECKUDPREQ");
    let size = u32::from_le_bytes(frame[1..5].try_into().unwrap()) as usize;
    assert_eq!(size, frame.len() - 5, "the size counts the opcode and body");
    &frame[6..]
}

fn verify_key(body: &[u8]) -> u32 {
    u32::from_le_bytes(body[4..8].try_into().unwrap())
}

#[test]
fn amules_request_names_its_forwarded_port_twice_and_a_verify_key() {
    for name in [
        "fwcheckudpreq_0xa7_plain.bin",
        "fwcheckudpreq_0xa7_crypt.bin",
    ] {
        let frame = load(name);
        let body = fwcheck_body(&frame);
        assert_eq!(body.len(), 8, "{name}: intern + extern + key");
        assert_eq!(le_u16(&body[0..2]), AMULE_KAD_PORT, "{name}: intern port");
        assert_eq!(
            le_u16(&body[2..4]),
            AMULE_KAD_PORT,
            "{name}: the extern port two pongs agreed on, equal to the intern one \
             behind a gateway that pins it"
        );
        assert_ne!(
            verify_key(body),
            0,
            "{name}: aMule always sends its verify key, crypt armed or not"
        );
    }
}

#[test]
fn amules_request_draws_the_plain_0x62_it_accepted() {
    // The plaintext run's helper had no obfuscation armed, so it answered in
    // the clear whatever key the `0xA7` carried — and aMule, crypt off,
    // accepted exactly these bytes.
    let frame = load("fwcheckudpreq_0xa7_plain.bin");
    let mut helper = node();
    helper.consume_udp_firewall_request(AMULE_PUBLIC_IP, fwcheck_body(&frame), false);
    assert_eq!(
        datagrams(&drain(|| helper.poll_output())),
        vec![(
            KadNodeEndpoint::new(AMULE_PUBLIC_IP, AMULE_KAD_PORT),
            load("firewalludp_0x62_plain.bin"),
        )],
        "one 0x62 (intern == extern), unbiased, naming port 4672"
    );
}

#[test]
fn the_keyed_0x62_opens_under_the_key_amules_request_carried() {
    let key = verify_key(fwcheck_body(&load("fwcheckudpreq_0xa7_crypt.bin")));
    let opened = decrypt_datagram_client(
        &load("firewalludp_0x62_keyed.bin"),
        &ClientDecryptKeys {
            receiver_verify_key: Some(key),
            ..ClientDecryptKeys::default()
        },
    )
    .expect("the captured 0x62 decrypts under aMule's own verify key for the helper");
    assert_eq!(opened.family, DatagramKeyFamily::KadVerifyKey);
    assert_eq!(opened.payload, load("firewalludp_0x62_plain.bin"));
    assert_eq!(
        opened.receiver_verify_key,
        Some(key),
        "the trailer echoes the key the 0xA7 carried"
    );
}

#[test]
fn rmule_reencrypts_the_keyed_0x62_byte_for_byte() {
    // The captured datagram's own random inputs — marker, per-packet key seed,
    // no padding — and the helper's sender key read out of its trailer; with
    // those, rmule's encoder must write the bytes aMule accepted.
    let captured = load("firewalludp_0x62_keyed.bin");
    let key = verify_key(fwcheck_body(&load("fwcheckudpreq_0xa7_crypt.bin")));
    let opened = decrypt_datagram_client(
        &captured,
        &ClientDecryptKeys {
            receiver_verify_key: Some(key),
            ..ClientDecryptKeys::default()
        },
    )
    .expect("decrypts");
    let rebuilt = encrypt_datagram_client(
        &opened.payload,
        &ClientEncryptKey::KadVerify {
            verify_key: key,
            receiver_verify_key: key,
            sender_verify_key: opened.sender_verify_key.expect("Kad trailer"),
        },
        &DatagramNonce {
            marker_byte: captured[0],
            random_key: le_u16(&captured[1..3]),
            padding: Vec::new(),
        },
    );
    assert_eq!(rebuilt, captured);
}
