//! The genuine **server-coordinated punch refusal** from
//! `andrey23127/ed2k-server` @ `4da4774`: the `OP_LOWID_HOLEPUNCH_FAIL 0x62`
//! it sent the asker of an `OP_LOWID_HOLEPUNCH_REQUEST 0x60` naming a Low ID
//! no client held (ADR-0091's second Rendezvous coordinator, 2026-10-18).
//!
//! The punch flows never drew this frame — both of their targets were
//! connected — so until this capture the `0x62` decoder rested on vectors
//! written from the server's source. Provenance and the server tap's timing
//! in `meta.toml`.

use rmule_ed2k::{HolepunchFail, HolepunchFailReason, ServerPacket};
use rmule_primitives::{ClientId, Packet, PacketProtocol};

const CAPTURE: &str = "ed2ksrv-holepunch-fail-20261018";

/// The Low ID the probe's request named, held by no client on the server;
/// its four bytes differ, so the target's byte order is read off the frame.
const GHOST_LOW_ID: u32 = 0x00FE_DCBA;

/// The refusal names the target the request asked for and reads reason `1`,
/// target not connected — the one reason asking again could change — and
/// re-encodes to the server's bytes.
#[test]
fn the_refusal_names_the_asked_target_as_not_connected() {
    let bytes = crate::fixture::captured(CAPTURE, "holepunch_fail_0x62.bin");
    let packet = Packet::decode_exact(&bytes).expect("frame decode");
    assert_eq!(
        packet.protocol(),
        PacketProtocol::Edonkey,
        "plain 0xE3 frame"
    );

    let ServerPacket::HolepunchFail(from_umbrella) =
        ServerPacket::decode(&packet).expect("the server-packet umbrella decodes 0x62")
    else {
        panic!("the umbrella did not route 0x62 to HolepunchFail");
    };
    let fail = HolepunchFail::decode_packet(&packet).expect("decode genuine 0x62");
    assert_eq!(from_umbrella, fail, "umbrella and direct decode agree");

    assert_eq!(fail.target, ClientId::from_u32(GHOST_LOW_ID));
    assert_eq!(fail.reason, HolepunchFailReason::TargetNotConnected);
    assert!(!fail.reason.is_permanent());
    assert_eq!(
        fail.encode_packet().encode(),
        bytes,
        "re-encoding reproduces the server's bytes"
    );
}
