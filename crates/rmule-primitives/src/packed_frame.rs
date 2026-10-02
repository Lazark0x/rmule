//! Symmetric packed-frame (`0xD4`/`OP_PACKEDPROT`) codec shared by every eD2k
//! surface that zlib-compresses a [`Packet`] payload (ADR-0053): the eD2k
//! server surface (`rmule-ed2k`) and the eD2k peer surface (`rmule-peer`).
//! One mechanism beside [`Packet`]; per-surface policy
//! (decompressed-size cap, post-inflate protocol attribution, emit gating)
//! stays in the calling crate.
//!
//! `flate2` is a private dependency of this crate — its types never appear
//! in this module's public signatures (ADR-0053).

use std::io::{Read, Write};

use flate2::Compression;
use flate2::bufread::ZlibDecoder;
use flate2::write::ZlibEncoder;

use crate::{Packet, PacketProtocol};

/// Typed reason a packed (`0xD4`) frame's zlib payload could not be inflated
/// into its logical plain [`Packet`].
///
/// Carried by every per-surface compressed-frame skip event (eD2k server,
/// eD2k peer). `#[non_exhaustive]` so new evidence can add reasons (e.g.
/// truncated payload) without breaking downstream matchers.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// `ZlibDecoder` rejected the compressed payload (invalid header, CRC
    /// mismatch, premature EOF).
    InflateFailed,
    /// Decompressed bytes would exceed the caller-supplied `cap`.
    DecompressedSizeLimitExceeded {
        /// Effective ceiling at the time the limit was exceeded.
        limit: usize,
    },
}

/// Inflate one packed (`0xD4`) frame into its logical plain [`Packet`],
/// re-attributed to `target_protocol` with the same opcode.
///
/// `packet` must already have been recognised as
/// [`PacketProtocol::PackedEd2k`] by the framing layer; asserted in debug
/// builds. `cap` is a flat decompressed-byte ceiling, ratio-independent —
/// each surface picks its own (`rmule-ed2k`'s server cap is 250 000). Nested
/// `0xD4` is impossible by construction: `target_protocol` may never be
/// [`PacketProtocol::PackedEd2k`], asserted in debug builds.
pub fn inflate(
    packet: &Packet,
    cap: usize,
    target_protocol: PacketProtocol,
) -> Result<Packet, SkipReason> {
    debug_assert_eq!(packet.protocol(), PacketProtocol::PackedEd2k);
    debug_assert_ne!(target_protocol, PacketProtocol::PackedEd2k);

    // `.take(cap + 1)` lets the decoder produce one byte past the ceiling so
    // we can distinguish "exactly at the limit" (accepted) from "would
    // overflow" (rejected) without a second read.
    let mut inflated = Vec::new();
    ZlibDecoder::new(packet.payload())
        .take((cap + 1) as u64)
        .read_to_end(&mut inflated)
        .map_err(|_| SkipReason::InflateFailed)?;

    if inflated.len() > cap {
        return Err(SkipReason::DecompressedSizeLimitExceeded { limit: cap });
    }

    Ok(Packet::new(target_protocol, packet.opcode(), inflated))
}

/// Zlib-compress `packet`'s payload at `Compression::best()` (aMule's
/// `Z_BEST_COMPRESSION`) and re-wrap it as a packed (`0xD4`) frame with the
/// same opcode, iff the compressed body is strictly smaller than the plain
/// payload; otherwise returns `packet` unchanged — mirroring aMule's
/// stay-plain fallback.
#[must_use]
pub fn pack_if_smaller(packet: Packet) -> Packet {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(packet.payload())
        .expect("in-memory zlib encode cannot fail");
    let compressed = encoder.finish().expect("in-memory zlib encode cannot fail");

    if compressed.len() < packet.payload().len() {
        Packet::new(PacketProtocol::PackedEd2k, packet.opcode(), compressed)
    } else {
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zlib_bytes(input: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }

    // --- inflate ---

    #[test]
    fn inflates_to_the_caller_supplied_target_protocol_and_same_opcode() {
        let compressed = zlib_bytes(b"\x03\x00hi!");
        let packed = Packet::new(PacketProtocol::PackedEd2k, 0x38, compressed);

        let inflated = inflate(&packed, 250_000, PacketProtocol::Edonkey).expect("inflate");

        assert_eq!(inflated.protocol(), PacketProtocol::Edonkey);
        assert_eq!(inflated.opcode(), 0x38);
        assert_eq!(inflated.payload(), b"\x03\x00hi!");
    }

    #[test]
    fn target_protocol_is_caller_chosen_not_hardcoded() {
        // Peer policy re-attributes to `Emule`, distinct from server policy's
        // `Edonkey` — proves `target_protocol` genuinely drives the output
        // instead of a constant left over from the eD2k-server-only
        // pre-ADR-0053 implementation.
        let compressed = zlib_bytes(b"peer payload");
        let packed = Packet::new(PacketProtocol::PackedEd2k, 0x82, compressed);

        let inflated = inflate(&packed, 50_000, PacketProtocol::Emule).expect("inflate");

        assert_eq!(inflated.protocol(), PacketProtocol::Emule);
    }

    #[test]
    fn invalid_zlib_payload_maps_to_inflate_failed() {
        let packed = Packet::new(PacketProtocol::PackedEd2k, 0x38, vec![0, 1, 2]);
        assert_eq!(
            inflate(&packed, 250_000, PacketProtocol::Edonkey),
            Err(SkipReason::InflateFailed)
        );
    }

    #[test]
    fn oversized_decompressed_payload_maps_to_limit_exceeded() {
        let too_large = vec![b'x'; 251];
        let packed = Packet::new(PacketProtocol::PackedEd2k, 0x38, zlib_bytes(&too_large));
        assert_eq!(
            inflate(&packed, 250, PacketProtocol::Edonkey),
            Err(SkipReason::DecompressedSizeLimitExceeded { limit: 250 })
        );
    }

    #[test]
    fn decompressed_payload_exactly_at_cap_is_accepted() {
        // The `take(cap + 1)` shape must distinguish "exactly at the limit"
        // from "would overflow" — this is the boundary the shape exists for.
        let exact = vec![b'x'; 250];
        let packed = Packet::new(PacketProtocol::PackedEd2k, 0x38, zlib_bytes(&exact));

        let inflated = inflate(&packed, 250, PacketProtocol::Edonkey).expect("inflate at cap");

        assert_eq!(inflated.payload().len(), 250);
    }

    // --- pack_if_smaller ---

    #[test]
    fn pack_if_smaller_round_trips_through_inflate() {
        let payload = vec![b'a'; 4_096]; // highly compressible
        let plain = Packet::new(PacketProtocol::Edonkey, 0x40, payload.clone());

        let packed = pack_if_smaller(plain);

        assert_eq!(packed.protocol(), PacketProtocol::PackedEd2k);
        assert_eq!(packed.opcode(), 0x40);
        let inflated = inflate(&packed, payload.len(), PacketProtocol::Edonkey).expect("inflate");
        assert_eq!(inflated.payload(), payload.as_slice());
    }

    #[test]
    fn pack_if_smaller_falls_back_to_plain_when_compression_does_not_shrink() {
        // A short, already-dense payload: zlib's header/checksum overhead
        // means the compressed form is never smaller.
        let payload = vec![1u8, 2, 3];
        let plain = Packet::new(PacketProtocol::Edonkey, 0x40, payload);

        let result = pack_if_smaller(plain.clone());

        assert_eq!(result, plain, "incompressible input stays plain, unchanged");
    }
}
