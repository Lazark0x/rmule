//! Kad firewall self-check **requester** capture (genuine stock aMule 2.3.3,
//! interop flow `kad-firewalled-buddy --requester-capture`, run `1785103574`).
//! The mirror of the responder fixture: here rmule (its ADR-0058
//! self-check armed) emitted its OWN `0x53 KADEMLIA_FIREWALLED2_REQ` toward a
//! NON-firewalled aMule contact, and the aMule answered `0x58
//! KADEMLIA_FIREWALLED_RES` carrying rmule's observed external IP — a leg once
//! recorded "undriven live", now driven and captured.
//!
//! These are rmule's + the counterparty's genuine wire bytes (ADR-0045). The
//! `0x58` in particular pins the observed-IP byte order: aMule writes it
//! LOW-OCTET-FIRST (`WriteUInt32` / reversed dotted octets), which this capture
//! corrected rmule's `0x58` handler to match. Provenance lives in `meta.toml`.

const FIXTURE_DIR: &str =
    "fixtures/firewalled/captured/amule-233-firewall-selfcheck-requester-20260727/";

use crate::fixture::{KAD_PROTO, OP_FIREWALLED_RES, OP_FIREWALLED2_REQ, OP_HELLO_RES, le_u16};

/// rmule's own eD2k TCP port in the swarm (harness `KAD_TCP_PORT` = 4662).
const RMULE_TCP_PORT: u16 = 4662;

fn load(name: &str) -> Vec<u8> {
    crate::fixture::captured(FIXTURE_DIR, name)
}

/// rmule's own `0x53` firewall self-check, emitted live toward the aMule contact
/// on the hello exchange: it names rmule's TCP port (for the connect-back test),
/// rmule's 16-byte User Hash, and its connect-options. This is the requester
/// emission its parity row needed and the byte-for-byte twin of the deterministic golden.
#[test]
fn rmule_firewall_check_names_our_port_hash_and_options() {
    let f = load("firewall_check_0x53.bin");
    // proto | opcode | tcp_port(2) | user_hash(16) | connect_options(1)
    assert_eq!(f.len(), 21, "0x53 is proto+opcode + 2 + 16 + 1");
    assert_eq!(f[0], KAD_PROTO);
    assert_eq!(f[1], OP_FIREWALLED2_REQ);
    assert_eq!(
        le_u16(&f[2..4]),
        RMULE_TCP_PORT,
        "the check names rmule's own TCP port for the connect-back",
    );
    // rmule's User Hash (harness default 0x77*16): the identity aMule keys its
    // dial-back's crypt/verify on.
    assert_eq!(&f[4..20], &[0x77u8; 16], "rmule's 16-byte User Hash");
    // connect-options 0x00: rmule advertises no Kad crypt and no direct UDP
    // callback, so the dial-back is a plaintext handshake (SELF_KAD_CONNECT_OPTIONS).
    assert_eq!(f[20], 0x00, "rmule's connect-options byte");
}

/// aMule's `0x58` answering rmule's check: it echoes rmule's observed external
/// IP. The body is the IP LOW-OCTET-FIRST — aMule's `WriteUInt32` (reversed
/// dotted octets), the same convention as Kad contact IPs. rmule was at
/// 203.0.113.3, so the on-wire body is `03 71 00 cb`, NOT `cb 00 71 03`.
#[test]
fn amule_firewall_response_carries_our_ip_low_octet_first() {
    let f = load("firewalled_res_0x58.bin");
    // proto | opcode | observed_ip(4, low-octet-first)
    assert_eq!(f.len(), 6, "0x58 is proto+opcode + a four-byte IP");
    assert_eq!(f[0], KAD_PROTO);
    assert_eq!(f[1], OP_FIREWALLED_RES);
    // The raw on-wire body: reversed dotted octets of 203.0.113.3.
    assert_eq!(
        &f[2..6],
        &[0x03, 0x71, 0x00, 0xCB],
        "aMule writes the observed IP low-octet-first (WriteUInt32)",
    );
    // Read back low-octet-first (reverse the four bytes) => rmule's real IP.
    let octets = [f[5], f[4], f[3], f[2]];
    assert_eq!(
        octets,
        [203, 0, 113, 3],
        "reversed, the 0x58 body is rmule's own external IP 203.0.113.3",
    );
}

/// aMule's `HELLO_RES` advertising its contact: KadID, TCP port 4662, Kad
/// version 8. Version 8 (> 6) is what gates rmule's emission to the extended
/// `0x53` rather than the legacy two-byte `0x50`.
#[test]
fn amule_hello_res_advertises_a_v8_contact() {
    let f = load("hello_res_0x19.bin");
    assert!(
        f.len() >= 21,
        "hello_res carries at least proto+opcode+id+port+ver"
    );
    assert_eq!(f[0], KAD_PROTO);
    assert_eq!(f[1], OP_HELLO_RES);
    // proto(1) opcode(1) kad_id(16) tcp_port(2) version(1)
    assert_eq!(le_u16(&f[18..20]), RMULE_TCP_PORT, "aMule's TCP port 4662");
    assert_eq!(
        f[20], 8,
        "Kad version 8 — the > 6 gate that selects the extended 0x53 check",
    );
}
