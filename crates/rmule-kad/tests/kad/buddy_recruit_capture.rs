//! Buddy-recruitment capture from a firewalled stock aMule 2.3.3 (interop flow M `kad-core-buddy`,
//! run `1785262206`). The counterparty reached its
//! firewalled verdicts, ran its `BuddySearch` onto rmule, and — after rmule's
//! `0x5A` — **dialed the serve listener and spoke eD2k on it**. That second leg is
//! the point: it only exists because the Kad node ran inside the Core that owns
//! the listener, so the port the `0x5A` advertised is a port something is bound
//! to. Provenance, preconditions and the two documented absences live alongside
//! in `meta.toml`.

const FIXTURE_DIR: &str = "fixtures/buddy/captured/amule-233-findbuddy-req-20260728/";

use crate::fixture::{
    AMULE_TCP_PORT, ED2K_PROTO, KAD_PROTO, OP_FINDBUDDY_REQ, OP_FINDBUDDY_RES, OP_HELLO, le_u16,
};

/// The firewalled aMule's harness-pinned Kad ID.
const AMULE_KAD_ID: [u8; 16] = [0x33; 16];
/// rmule's pinned Kad ID — `~AMULE_KAD_ID`, so it IS the FindBuddy target.
const RMULE_KAD_ID: [u8; 16] = [0xCC; 16];
/// rmule's serve listener port — what the Core-pumped Kad node advertises.
const RMULE_SERVE_PORT: u16 = 4663;

fn load(name: &str) -> Vec<u8> {
    crate::fixture::captured(FIXTURE_DIR, name)
}

/// The counterparty's recruitment request. Its `buddyID` is the search target
/// `~ownKadID` (aMule `ClientList.cpp:697`), which aMule re-derives from the
/// echo before it will act on an answer — so a responder that does not sit at
/// that ID is never asked in the first place.
#[test]
fn findbuddy_req_targets_the_inverted_kad_id_and_names_the_firewalled_port() {
    let f = load("findbuddy_req_0x51.bin");
    assert_eq!(f.len(), 36, "0x51 is proto+opcode + buddyID + hash + port");
    assert_eq!(f[0], KAD_PROTO);
    assert_eq!(f[1], OP_FINDBUDDY_REQ);

    assert_eq!(
        &f[2..18],
        &RMULE_KAD_ID,
        "the buddyID is the FindBuddy target ~aMuleKadID, which rmule is pinned to",
    );
    let inverted: Vec<u8> = f[2..18].iter().map(|b| !b).collect();
    assert_eq!(
        inverted, AMULE_KAD_ID,
        "aMule's own check: buddyID ^ all-ones must equal its Kad ID",
    );

    let client_hash = &f[18..34];
    assert!(
        client_hash.iter().any(|&b| b != 0),
        "a real client hash is not all-zero",
    );
    assert_eq!(
        le_u16(&f[34..36]),
        AMULE_TCP_PORT,
        "the requester names the TCP port it cannot be reached on",
    );
}

/// rmule's answer — stimulus, not evidence, but the field the counterparty acts
/// on. It advertises the **serve listener's** port, which is the whole seam
/// under test: `serve.rs::kad_enable_config` takes `tcp_port` from the bound
/// listener, so what Kad advertises and what accepts connections are one port.
#[test]
fn findbuddy_res_echoes_the_buddy_id_and_advertises_the_serve_listener() {
    let f = load("findbuddy_res_0x5a.bin");
    assert_eq!(f.len(), 36);
    assert_eq!(f[0], KAD_PROTO);
    assert_eq!(f[1], OP_FINDBUDDY_RES);
    assert_eq!(
        &f[2..18],
        &load("findbuddy_req_0x51.bin")[2..18],
        "the buddyID is echoed verbatim; aMule discards an answer that fails its XOR check",
    );
    assert_eq!(
        le_u16(&f[34..36]),
        RMULE_SERVE_PORT,
        "the advertised port is the serve listener, not a Kad-only port",
    );
}

/// The second leg, and the reason the Core-Pumped Stimulus Node exists: having
/// read that port out of the `0x5A`, the counterparty dialed it and sent its
/// `OP_HELLO`. Against a Kad-UDP-only stimulus this frame cannot exist.
#[test]
fn the_buddy_link_hello_identifies_the_counterparty_over_peer_tcp() {
    let f = load("buddy_link_hello_0x01.bin");
    assert_eq!(f[0], ED2K_PROTO, "the buddy link speaks eD2k, not Kad");
    let size = u32::from_le_bytes([f[1], f[2], f[3], f[4]]) as usize;
    assert_eq!(
        size,
        f.len() - 5,
        "the eD2k size prefix covers opcode + body",
    );
    assert_eq!(f[5], OP_HELLO);
    assert_eq!(
        f[6], 16,
        "hash-size byte precedes the user hash in OP_HELLO"
    );

    // The identity the accept path matches to attach the held buddy link.
    // It is the `0x51`'s client hash word-swapped — the documented Kad-ID /
    // eD2k-hash relation, which is why one recruit can be recognised on both
    // surfaces.
    let hello_hash = &f[7..23];
    let kad_hash = &load("findbuddy_req_0x51.bin")[18..34];
    let word_swapped: Vec<u8> = kad_hash
        .chunks_exact(4)
        .flat_map(|word| word.iter().rev().copied())
        .collect();
    assert_eq!(
        hello_hash, word_swapped,
        "the buddy link's user hash is the recruit's client hash, word-swapped",
    );

    assert_eq!(
        le_u16(&f[27..29]),
        AMULE_TCP_PORT,
        "the hello re-advertises the same firewalled TCP port",
    );
}
