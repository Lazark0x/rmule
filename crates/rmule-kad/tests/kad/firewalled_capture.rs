//! Firewalled-counterparty Kad capture (genuine stock aMule 2.3.3, interop flow
//! K `kad-firewalled-buddy`, run `1785031705`). While the aMule ran TCP+UDP-
//! firewalled (its Kad ports iptables-DROPped), it sent rmule its firewall self-
//! check request `0x53 KADEMLIA_FIREWALLED2_REQ` — the ADR-0058 reachability
//! precursor to ADR-0061 buddy recruitment. These are the
//! counterparty's own datagrams; the tests assert their wire layout so a
//! regression in the fixtures (or a mis-harvest) is caught. Provenance +
//! disposition live alongside in `meta.toml`.

const FIXTURE_DIR: &str = "fixtures/firewalled/captured/amule-233-firewalled-kad-20260726/";

use crate::fixture::{AMULE_TCP_PORT, KAD_PROTO, OP_FIREWALLED2_REQ, OP_HELLO_RES, le_u16};

fn load(name: &str) -> Vec<u8> {
    crate::fixture::captured(FIXTURE_DIR, name)
}

/// The firewalled aMule's `0x53` firewall self-check request: it names its own
/// TCP port (for the connect-back test) plus a 16-byte check id. rmule answers
/// `0x58` (the ADR-0058 responder) — captured in the same run's tap.
#[test]
fn firewalled2_req_names_amule_tcp_port_and_check_id() {
    let f = load("firewalled2_req_0x53.bin");
    // proto | opcode | tcp_port(2) | check_id(16) | trailer(1)
    assert_eq!(f.len(), 21, "0x53 request is proto+opcode + 2 + 16 + 1");
    assert_eq!(f[0], KAD_PROTO);
    assert_eq!(f[1], OP_FIREWALLED2_REQ);
    assert_eq!(
        le_u16(&f[2..4]),
        AMULE_TCP_PORT,
        "the check names the port rmule should connect back to",
    );
    let check_id = &f[4..20];
    assert_eq!(check_id.len(), 16, "16-byte firewall-check id");
    assert!(
        check_id.iter().any(|&b| b != 0),
        "a real check id is not all-zero",
    );
}

/// The firewalled aMule's `0x19` HELLO_RES advertises its contact: KadID, TCP
/// port, Kad version.
#[test]
fn firewalled_hello_res_advertises_contact() {
    let f = load("hello_res_0x19.bin");
    assert_eq!(f[0], KAD_PROTO);
    assert_eq!(f[1], OP_HELLO_RES);
    // proto | opcode | kad_id(16) | tcp_port(2) | version(1) | tags…
    let kad_id = &f[2..18];
    assert_eq!(
        kad_id, [0x55u8; 16],
        "the harness-pinned firewalled aMule id"
    );
    assert_eq!(le_u16(&f[18..20]), AMULE_TCP_PORT, "advertised TCP port");
    assert_eq!(f[20], 8, "Kad version 8 (aMule 2.3.3)");
}

/// The `0x53` user hash field is aMule's `WriteUInt128`: four little-endian
/// words. An eMule-family user hash carries two marker bytes —
/// `hash[5] == 14` and `hash[14] == 111` (aMule `Preferences.cpp:1081-1082`) —
/// and in this genuine request they sit at wire offsets 6 and 13, each
/// four-byte group reversed. Read in raw order, the hash handed to the
/// dial-back as its obfuscation key is another client's; read as aMule wrote
/// it, the markers land where aMule put them.
#[test]
fn a_genuine_0x53_names_its_user_hash_in_write_uint128_word_order() {
    use rmule_kad::KadEvent;
    use rmule_primitives::session::drain;
    use rmule_testkit::kad_node::{T0, endpoint, events, node};

    let datagram = load("firewalled2_req_0x53.bin");
    let mut node = node();
    node.handle_datagram(T0, endpoint(2, 4674), &datagram);
    let user_hash = events(&drain(|| node.poll_output()))
        .into_iter()
        .find_map(|event| match event {
            KadEvent::DialBackRequested { user_hash, .. } => user_hash,
            _ => None,
        })
        .expect("a v7+ 0x53 asks for a dial-back naming its user hash");
    let hash = user_hash.as_bytes();
    assert_eq!(
        (hash[5], hash[14]),
        (14, 111),
        "the aMule user-hash markers, once the WriteUInt128 words are undone"
    );
}
