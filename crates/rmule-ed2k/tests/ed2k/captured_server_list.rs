//! Genuine **non-empty** `OP_SERVERLIST 0x32` from `andrey23127/ed2k-server`
//! @ `eacf7f1`, drawn by rmule's `OP_GETSERVERLIST 0x14` over a live logged-in
//! session (ed2ksrv capture, 2026-08-02).
//!
//! What makes this fixture worth having is the **entry list being populated**.
//! Every prior live `0x14` drew either nothing or an ident alone, because the
//! only benched server's known-servers table was empty and no seeding path
//! filled it (see `lugdunum-server-ident-20260729/meta.toml`). Two gossiping
//! instances of this server supply the live server-to-server exchange the row
//! always needed, so the assertions below are on real peer entries rather than
//! on a well-formed empty list. Provenance + topology live in `meta.toml`.

use std::net::Ipv4Addr;

use rmule_ed2k::{GetServerList, ServerList};
use rmule_primitives::{Ipv4Endpoint, Packet, PacketProtocol};

/// The sibling instance the emitting server had gossiped with and verified —
/// the one entry its client-facing list can contain (it never advertises
/// itself).
const GOSSIP_PEER: Ipv4Endpoint = Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 20), 4661);

fn decode_captured_list() -> ServerList {
    let bytes = load("server_list_0x32.bin");
    let packet = Packet::decode_exact(&bytes).expect("frame decode");
    assert_eq!(
        packet.protocol(),
        PacketProtocol::Edonkey,
        "plain 0xE3 frame"
    );
    ServerList::decode_packet(&packet).expect("decode genuine 0x32")
}

/// One packet slice of the `ed2ksrv-serverlist-20260802` capture.
fn load(name: &str) -> Vec<u8> {
    crate::fixture::captured("ed2ksrv-serverlist-20260802", name)
}

/// The genuine `0x32` decodes into rmule's typed projection with the
/// counterparty's actual peer in it. This is the assertion the row was blocked
/// on: `server_list_accepts_zero_entries` already covers the empty shape, so a
/// captured list that decoded to nothing would prove nothing new — hence both
/// the exact entry and the exact count are pinned, and either an empty or a
/// differently-populated list fails here.
#[test]
fn decodes_genuine_ed2ksrv_server_list_with_the_gossip_peer() {
    let list = decode_captured_list();
    assert_eq!(
        list.servers(),
        &[GOSSIP_PEER],
        "the captured table must hold exactly the gossip peer 203.0.113.20:4661 — \
         an empty list means the capture regressed to the pre-gossip shape the \
         0x32 row was blocked on for"
    );
}

/// The genuine bytes round-trip through rmule's encoder byte-for-byte — the
/// emit shape is honest against a real server's own serialization of a
/// *populated* list, not just against rmule's own encoder.
#[test]
fn genuine_ed2ksrv_server_list_round_trips_byte_exact() {
    let bytes = load("server_list_0x32.bin");
    assert_eq!(
        decode_captured_list().encode_packet().encode(),
        bytes,
        "re-encode mismatch — encoder not byte-faithful against genuine bytes"
    );
}

/// The stimulus is pinned so the reaction stays attributable: the request that
/// drew the `0x32` is the exact 6-byte `OP_GETSERVERLIST` frame rmule's session
/// command emits. Stimulus, never evidence (ADR-0045). Asserted against the
/// *emitter* rather than a byte literal, because emitter drift is the only
/// thing this pin can usefully catch — a captured file cannot move.
#[test]
fn stimulus_frame_is_the_session_get_server_list() {
    assert_eq!(
        load("get_server_list_0x14.bin"),
        GetServerList.encode_packet().encode(),
        "the drawn 0x32 is no longer attributable — rmule's OP_GETSERVERLIST has \
         drifted from the frame that actually drew it"
    );
}
