//! The golden vector from the NAT bench (ADR-0091 / ADR-0092
//! `natt-caps-utp`): kno's aMule answering an rmule uTP `ST_SYN` inside the
//! eMuleAI NAT-T envelope.
//!
//! One frame, and what it settles is that the `0xB2` envelope's uTP arm
//! interoperates: a second implementation read a `0xB2 0x00` datagram, handed
//! the payload to its own libutp, and that libutp answered. rmule's `ST_SYN` is
//! stimulus; this is the packet that completed the handshake.
//!
//! **Single-oracle** (ADR-0045 as amended): kno's fork is the only pinned body
//! carrying uTP under `0xB2`. Provenance in
//! `fixtures/natt/captured/amule-kno-utp-state-20260921/meta.toml`.

use rmule_peer::natt::{NattFrame, NattFrameType, natt_frame_type};

/// kno's aMule `ab483654` answering rmule's uTP dial, bench run `1790026955`.
const UTP_STATE: &[u8] = include_bytes!(
    "../fixtures/natt/captured/amule-kno-utp-state-20260921/utp_state_answer_0xb2_0x00.bin"
);

/// The counterparty framed its answer the way the dialect says — and the
/// payload it wrapped is a BEP-29 `ST_STATE`, which is a SYN having been
/// answered rather than merely received.
#[test]
fn knos_amule_answers_a_utp_syn_inside_the_natt_envelope() {
    assert_eq!(
        natt_frame_type(UTP_STATE),
        Some(NattFrameType::Utp),
        "a `0xB2 0x00` envelope, read by the type byte rather than by position",
    );

    let NattFrame::Utp(packet) = NattFrame::decode(UTP_STATE).expect("the captured frame decodes")
    else {
        panic!("the envelope's uTP arm is what the counterparty used");
    };
    assert_eq!(
        packet.len(),
        20,
        "a bare BEP-29 header: an `ST_STATE` carries no payload",
    );

    // BEP-29's first byte is `(type << 4) | version`. `0x2` is `ST_STATE`.
    assert_eq!(packet[0] >> 4, 0x2, "ST_STATE — the answer to our ST_SYN");
    assert_eq!(packet[0] & 0x0F, 1, "BEP-29 version 1");
    assert_eq!(
        u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]),
        0,
        "the first answer has no round trip to difference against yet",
    );
    assert_eq!(
        u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]),
        0x0010_0000,
        "kno's libutp advertised a 1 MiB receive window",
    );
}
