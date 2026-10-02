//! The Kad datagram envelope: what decodes, what is truncated, and which
//! malformed deflate stream is a typed inflate error rather than a panic.

use std::io::Write;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use rmule_kad::{
    KadDecoded, KadEnvelope, KadEnvelopeDecodeError, KadProtocol, MAX_INFLATED_KAD_PAYLOAD,
    decode_exact,
};

fn deflate(payload: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(payload).expect("in-memory deflate");
    encoder.finish().expect("in-memory deflate")
}

#[test]
fn empty_datagram_is_truncated() {
    assert_eq!(
        decode_exact(&[]),
        Err(KadEnvelopeDecodeError::Truncated { len: 0 })
    );
}

#[test]
fn one_byte_datagram_is_truncated_because_opcode_is_absent() {
    assert_eq!(
        decode_exact(&[0xE4]),
        Err(KadEnvelopeDecodeError::Truncated { len: 1 })
    );
}

#[test]
fn plain_envelope_with_empty_payload_decodes() {
    let KadDecoded::Plain(envelope) = decode_exact(&[0xE4, 0x11]).unwrap() else {
        panic!("expected a plain Kad envelope");
    };
    assert_eq!(envelope.protocol(), KadProtocol::Plain);
    assert_eq!(envelope.opcode(), 0x11);
    assert!(envelope.payload().is_empty());
}

#[test]
fn plain_envelope_with_payload_decodes() {
    let KadDecoded::Plain(envelope) = decode_exact(&[0xE4, 0x34, 0xaa, 0xbb]).unwrap() else {
        panic!("expected a plain Kad envelope");
    };
    assert_eq!(envelope.protocol(), KadProtocol::Plain);
    assert_eq!(envelope.opcode(), 0x34);
    assert_eq!(envelope.payload(), &[0xaa, 0xbb]);
}

#[test]
fn unsupported_protocol_byte_is_reported() {
    assert_eq!(
        decode_exact(&[0xD4, 0x34, 0x00]),
        Err(KadEnvelopeDecodeError::UnsupportedProtocol(0xD4))
    );
}

#[test]
fn packed_kad_without_opcode_is_truncated() {
    assert_eq!(
        decode_exact(&[0xE5]),
        Err(KadEnvelopeDecodeError::Truncated { len: 1 })
    );
}

#[test]
fn packed_datagram_decodes_to_its_plain_equivalent() {
    let payload = vec![0x0b, 0xaa, 0xbb, 0xcc, 0xdd];
    let mut packed = vec![0xE5, 0x21];
    packed.extend_from_slice(&deflate(&payload));

    let KadDecoded::Packed(envelope) = decode_exact(&packed).unwrap() else {
        panic!("expected a packed Kad envelope");
    };

    // The decoded envelope is the LOGICAL plain packet: same opcode, inflated
    // payload, protocol restored to plain — exactly what the plain twin decodes to.
    let KadDecoded::Plain(plain_twin) =
        decode_exact(&[&[0xE4, 0x21][..], &payload].concat()).unwrap()
    else {
        panic!("expected a plain Kad envelope");
    };
    assert_eq!(envelope, plain_twin);
    assert_eq!(envelope.protocol(), KadProtocol::Plain);
    assert_eq!(envelope.opcode(), 0x21);
    assert_eq!(envelope.payload(), payload.as_slice());
}

#[test]
fn packed_kad_with_zero_length_payload_is_a_typed_inflate_error() {
    assert_eq!(
        decode_exact(&[0xE5, 0x34]),
        Err(KadEnvelopeDecodeError::PackedPayloadInflate)
    );
}

#[test]
fn malformed_deflate_stream_is_a_typed_inflate_error() {
    assert_eq!(
        decode_exact(&[0xE5, 0x34, 0x00, 0x01, 0x02, 0x03]),
        Err(KadEnvelopeDecodeError::PackedPayloadInflate)
    );
}

#[test]
fn truncated_deflate_stream_is_a_typed_inflate_error() {
    let mut packed = vec![0xE5, 0x34];
    let full = deflate(&[0x42; 512]);
    packed.extend_from_slice(&full[..full.len() / 2]);

    assert_eq!(
        decode_exact(&packed),
        Err(KadEnvelopeDecodeError::PackedPayloadInflate)
    );
}

#[test]
fn trailing_bytes_after_the_deflate_stream_are_a_typed_inflate_error() {
    let mut packed = vec![0xE5, 0x34];
    packed.extend_from_slice(&deflate(&[0x42; 16]));
    packed.push(0x99);

    assert_eq!(
        decode_exact(&packed),
        Err(KadEnvelopeDecodeError::PackedPayloadInflate)
    );
}

#[test]
fn packed_payload_inflating_above_the_cap_is_rejected() {
    let mut packed = vec![0xE5, 0x34];
    packed.extend_from_slice(&deflate(&vec![0u8; MAX_INFLATED_KAD_PAYLOAD + 1]));

    assert_eq!(
        decode_exact(&packed),
        Err(KadEnvelopeDecodeError::PackedPayloadTooLarge {
            cap: MAX_INFLATED_KAD_PAYLOAD,
        })
    );
}

#[test]
fn packed_payload_inflating_to_exactly_the_cap_decodes() {
    let payload = vec![0u8; MAX_INFLATED_KAD_PAYLOAD];
    let mut packed = vec![0xE5, 0x34];
    packed.extend_from_slice(&deflate(&payload));

    let KadDecoded::Packed(envelope) = decode_exact(&packed).unwrap() else {
        panic!("expected a packed Kad envelope");
    };
    assert_eq!(envelope.payload().len(), MAX_INFLATED_KAD_PAYLOAD);
}

#[test]
fn plain_envelope_round_trips_through_encode() {
    let envelope = KadEnvelope::plain(0x34, vec![0xaa, 0xbb]);

    let bytes = envelope.encode();
    assert_eq!(bytes, vec![0xE4, 0x34, 0xaa, 0xbb]);

    let KadDecoded::Plain(decoded) = decode_exact(&bytes).unwrap() else {
        panic!("expected a plain Kad envelope");
    };
    assert_eq!(decoded, envelope);
}
