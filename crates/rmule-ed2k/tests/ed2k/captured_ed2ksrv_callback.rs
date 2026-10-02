//! The genuine server-relayed **LowID callback** from `andrey23127/ed2k-server`
//! @ `eacf7f1`: an `OP_CALLBACKREQUESTED 0x35` delivered *to the LowID target*
//! in answer to a High-ID rmule session's `OP_CALLBACKREQUEST 0x1C`, plus the
//! `OP_CALLBACK_FAIL 0x36` the same server returns for an unallocated id
//! (ed2ksrv capture, 2026-08-02).
//!
//! This is the leg the row's LIMIT-EXEMPT ruling was written for. Correctness was already
//! proven in-process (`peer_callback.rs`'s loopback); what never existed was a
//! counterparty that would actually *relay*, because Lugdunum never surfaces a
//! LowID source. These are that counterparty's own bytes, so the assertions
//! below are about the relay's real content — the requester's dial-back
//! endpoint — rather than about rmule's encoder talking to itself.
//!
//! The direction is the substance: a `0x35` seen by the *requester* would be
//! the wrong frame. It is pushed down the **target's** session, which is why
//! the fixture comes from the LowID side's `s2c.bin` while the `0x1C` beside it
//! comes from the High-ID side's `c2s.bin`. Provenance + topology in `meta.toml`.

use std::net::Ipv4Addr;

use rmule_ed2k::{CallbackFailed, CallbackRequest, IdChange, PeerCallback};
use rmule_primitives::{ClientId, Packet, PacketProtocol};

/// The requester's dial-back endpoint as the server relayed it: the address the
/// server observed the `0x1C` arrive from, and the TCP port that session's login
/// *advertised* (not its ephemeral source port).
const REQUESTER_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 30);
const REQUESTER_PORT: u16 = 4662;

/// The LowID the server's monotonic counter assigned the target, and the id the
/// `0x1C` therefore carried.
const TARGET_LOW_ID: u32 = 2;

/// An id the server had never allocated (its counter had reached 2), chosen far
/// above the registrant count so it stays bogus for the life of the process.
const BOGUS_LOW_ID: u32 = 99_999;

/// One packet slice of the capture where the relay succeeded.
fn relay(name: &str) -> Vec<u8> {
    crate::fixture::captured("ed2ksrv-callback-relay-20260802", name)
}

/// One packet slice of the capture where the callback was refused.
fn fail(name: &str) -> Vec<u8> {
    crate::fixture::captured("ed2ksrv-callback-fail-20260802", name)
}

fn decode(bytes: &[u8]) -> Packet {
    let packet = Packet::decode_exact(bytes).expect("frame decode");
    assert_eq!(
        packet.protocol(),
        PacketProtocol::Edonkey,
        "plain 0xE3 frame"
    );
    packet
}

/// The headline: the relayed `0x35` decodes to the **requester's** dial-back
/// endpoint. That payload is the entire point of the callback — a LowID client
/// cannot be dialled, so the server hands it the address to dial *out* to. An
/// empty, truncated or differently-addressed frame fails here.
#[test]
fn relayed_callback_carries_the_requesters_dial_back_endpoint() {
    let callback = PeerCallback::decode_packet(&decode(&relay("peer_callback_0x35.bin")))
        .expect("decode genuine 0x35");
    assert_eq!(
        callback.peer.ip, REQUESTER_IP,
        "the relay must carry the requester's server-observed address"
    );
    assert_eq!(
        callback.peer.port, REQUESTER_PORT,
        "the relay must carry the port the requester's login advertised, \
         not the ephemeral port its TCP session came from"
    );
}

/// The relay's 6-byte payload round-trips through rmule's encoder byte for
/// byte. rmule emits `0x35` on its own server surface, so this pins the emit
/// shape against a real server's serialization rather than against rmule's own.
#[test]
fn relayed_callback_round_trips_byte_exact() {
    let bytes = relay("peer_callback_0x35.bin");
    let callback = PeerCallback::decode_packet(&decode(&bytes)).expect("decode genuine 0x35");
    assert_eq!(
        callback.encode_packet().encode(),
        bytes,
        "re-encode mismatch — encoder not byte-faithful against genuine bytes"
    );
}

/// The two `OP_IDCHANGE` frames from the same sitting prove the topology the
/// relay needed, and they are the `LowID / HighID handling` row's own
/// counterparty bytes: one client below the LowID ceiling, one whose id **is**
/// its address. The pairing matters — `callback.rs:34-40` drops a LowID
/// requester's `0x1C` in silence, so a run that failed to earn High-ID could
/// not tell "relayed" from "refused", and the `0x35` above would prove nothing.
#[test]
fn both_id_classes_were_assigned_in_the_relay_sitting() {
    let target = IdChange::decode_packet(&decode(&relay("target_id_change_0x40.bin")))
        .expect("decode target 0x40");
    assert_eq!(
        target.client_id,
        ClientId::from_u32(TARGET_LOW_ID),
        "the callback target held the LowID the 0x1C addressed"
    );
    assert!(
        target.client_id.is_low_id(),
        "target id {} must be below the LowID ceiling",
        target.client_id.as_u32()
    );

    let requester = IdChange::decode_packet(&decode(&relay("requester_id_change_0x40.bin")))
        .expect("decode requester 0x40");
    assert!(
        !requester.client_id.is_low_id(),
        "the requester had to hold a High ID or the server drops the 0x1C in silence"
    );
    assert_eq!(
        requester.client_id,
        ClientId::from_u32(u32::from_le_bytes(REQUESTER_IP.octets())),
        "a High ID *is* the client's own address — and it is exactly the address \
         the relayed 0x35 handed the target"
    );
}

/// The stimulus is pinned so the reaction stays attributable: the frame that
/// drew the relay is the exact `OP_CALLBACKREQUEST` rmule's session command
/// emits for that LowID. Stimulus, never evidence (ADR-0045) — asserted against
/// the *emitter*, because emitter drift is the only thing this pin can catch.
#[test]
fn relay_stimulus_is_the_session_callback_request() {
    assert_eq!(
        relay("callback_request_0x1c.bin"),
        CallbackRequest::new(ClientId::from_u32(TARGET_LOW_ID))
            .encode_packet()
            .encode(),
        "the relayed 0x35 is no longer attributable — rmule's OP_CALLBACKREQUEST \
         has drifted from the frame that actually drew it"
    );
}

/// The other branch of the same server arm: an id the server never allocated
/// draws `OP_CALLBACK_FAIL 0x36` instead of a relay. rmule's decode is
/// `tolerate_body`, so what this pins is that the genuine frame really is the
/// **empty-payload** form — a 6-byte packet with nothing after the opcode.
#[test]
fn absent_target_draws_an_empty_bodied_callback_fail() {
    let bytes = fail("callback_fail_0x36.bin");
    let packet = decode(&bytes);
    assert!(
        packet.payload().is_empty(),
        "this server's 0x36 carries no body (callback.rs:51); got {} bytes",
        packet.payload().len()
    );
    CallbackFailed::decode_packet(&packet).expect("decode genuine 0x36");
    assert_eq!(
        CallbackFailed.encode_packet().encode(),
        bytes,
        "re-encode mismatch — rmule's 0x36 emit has drifted from the genuine frame"
    );
}

/// The fail branch's stimulus, pinned for the same reason as the relay's: the
/// answer is only attributable to "target not connected" if the id asked for
/// really was one the server had never allocated.
#[test]
fn fail_stimulus_asked_for_an_unallocated_low_id() {
    assert_eq!(
        fail("callback_request_0x1c.bin"),
        CallbackRequest::new(ClientId::from_u32(BOGUS_LOW_ID))
            .encode_packet()
            .encode(),
        "the drawn 0x36 is no longer attributable — the emitted OP_CALLBACKREQUEST \
         has drifted from the frame that actually drew it"
    );
}
