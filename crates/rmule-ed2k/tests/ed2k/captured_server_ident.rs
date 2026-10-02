//! Genuine Lugdunum eserver 17.15 `OP_SERVERIDENT 0x41`, drawn by rmule's
//! `OP_GETSERVERLIST 0x14` over a live logged-in session (capture-ceiling
//! effort, 2026-07-29). The counterparty frame is the server's own identity
//! serialization; the control runs (welcome bursts with no request) carry no
//! `0x41`, which is what makes it the *reaction* evidence for the `0x14`
//! emit row. Provenance + the honest `0x32`-absence note live alongside in
//! `meta.toml`.

use rmule_ed2k::{GetServerList, ServerIdent};
use rmule_primitives::{Packet, PacketProtocol};

/// One packet slice of the `lugdunum-server-ident-20260729` capture.
fn load(name: &str) -> Vec<u8> {
    crate::fixture::captured("lugdunum-server-ident-20260729", name)
}

/// The genuine `0x41` decodes into rmule's typed `ServerIdentity` projection
/// (ADR-0068 graceful consume): hash + advertised endpoint + the two string
/// tags Lugdunum sends, nothing dropped.
#[test]
fn decodes_genuine_lugdunum_server_ident() {
    let bytes = load("server_ident_0x41.bin");
    let packet = Packet::decode_exact(&bytes).expect("frame decode");
    assert_eq!(
        packet.protocol(),
        PacketProtocol::Edonkey,
        "plain 0xE3 frame"
    );

    let ident = ServerIdent::decode_packet(&packet).expect("decode genuine 0x41");
    // Vacuity guards: the identity must actually carry the counterparty's
    // strings — an empty projection would pass a weaker assert.
    let identity = ident.identity();
    let hash = identity.server_hash.expect("server hash present");
    assert_eq!(
        hash,
        rmule_primitives::ServerHash::from_bytes([
            0x06, 0x75, 0xbe, 0x3c, 0x2b, 0xad, 0xbb, 0x6c, 0xf4, 0x78, 0xb3, 0x02, 0xd3, 0x5e,
            0x50, 0x9e,
        ]),
        "Lugdunum's own server hash"
    );
    assert_eq!(
        identity.name.as_ref().map(ToString::to_string).as_deref(),
        Some("rmule-interop"),
        "ST_SERVERNAME"
    );
    assert_eq!(
        identity
            .description
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("eserver 17.15"),
        "ST_DESCRIPTION"
    );
    assert_eq!(ident.advertised().port, 4661, "advertised TCP port");
}

/// The genuine bytes round-trip through rmule's encoder byte-for-byte — the
/// emit shape is honest against the counterparty's own serialization.
#[test]
fn genuine_server_ident_round_trips_byte_exact() {
    let bytes = load("server_ident_0x41.bin");
    let packet = Packet::decode_exact(&bytes).expect("frame decode");
    let ident = ServerIdent::decode_packet(&packet).expect("decode genuine 0x41");
    assert_eq!(
        ident.encode_packet().encode(),
        bytes,
        "re-encode mismatch — encoder not byte-faithful against genuine bytes"
    );
}

/// The stimulus is pinned so the reaction stays attributable: the request that
/// drew the `0x41` is the exact 6-byte `OP_GETSERVERLIST` frame rmule's
/// session command emits. Stimulus, never evidence (ADR-0045).
#[test]
fn stimulus_frame_is_the_session_get_server_list() {
    let bytes = load("get_server_list_0x14.bin");
    // Against the *emitter*, not against a byte literal. A literal would agree
    // with itself forever while `Ed2kCommand::RequestServerList` drifted out from
    // under it (`session.rs` builds the frame with this same expression) — and
    // emitter drift is the only thing this pin can usefully catch, since a
    // captured file cannot move.
    assert_eq!(
        bytes,
        GetServerList.encode_packet().encode(),
        "the drawn 0x41 is no longer attributable — rmule's OP_GETSERVERLIST has \
         drifted from the frame that actually drew it"
    );
}
