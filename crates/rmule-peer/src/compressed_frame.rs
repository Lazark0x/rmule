//! The packed-frame (`0xD4`) boundary for peer packets: the decompressed-size
//! budget an inbound frame may claim, and the skip reasons an over-budget or
//! undecodable one resolves to.
//!
//! The peer ceiling is aMule's unpack *default*, which its client socket takes
//! unchanged; the 5x wider server ceiling belongs to `rmule_ed2k` alone. A
//! skipped frame is non-terminal — it costs the frame, not the connection.

use rmule_primitives::{Packet, PacketProtocol};

pub use rmule_primitives::SkipReason as CompressedFrameSkipReason;

/// Decompressed-size ceiling for inbound peer packed (`0xD4`) frames.
///
/// aMule's unpack budget *default* — `UnPackPacket(uint32 uMaxDecompressedSize
/// = 50000)` (`Packet.h#L60`) — which is exactly what the peer socket takes:
/// `CClientTCPSocket::PacketReceived` calls `packet->UnPackPacket()` with no
/// argument (`ClientTCPSocket.cpp#L1982`). The 5× wider 250 000 is the *server*
/// socket's alone, passed explicitly at `ServerSocket.cpp#L678` and mirrored by
/// `rmule_ed2k::SERVER_COMPRESSED_FRAME_LIMIT`. The gap between the two crates
/// is aMule's own; widening this one to match the server would be a divergence,
/// not parity. Future Kad work picks its own ceiling likewise.
pub const PEER_COMPRESSED_FRAME_LIMIT: usize = 50_000;

/// Payload-size gate above which a peer answer is pack-attempted (ADR-0053,
/// hosted here). aMule packs an `OP_ANSWERSOURCES` / `OP_ANSWERSOURCES2` reply
/// whose body exceeds 354 bytes (`CKnownFile::CreateSrcInfoPacket` /
/// `CPartFile::CreateSrcInfoPacket` @4e8f2b3c); the source-exchange serve path
/// (ADR-0055) is the only in-scope emitter and consumes this constant rather
/// than redefining the policy. A body at or below the threshold is never
/// packed.
pub const PEER_PACK_THRESHOLD: usize = 354;

/// Pack-attempt one outbound peer frame whose payload exceeds
/// [`PEER_PACK_THRESHOLD`] (ADR-0053). Above the threshold the shared
/// [`rmule_primitives::pack_if_smaller`] mechanism zlib-packs the body and
/// re-wraps it as `0xD4` **iff** that actually shrinks it — otherwise it stays
/// plain (aMule's own fallback). At or below the threshold the packet is
/// returned untouched, so a small answer never carries zlib overhead.
///
/// Peer policy (this threshold) over the shared mechanism, the emit twin of
/// [`inflate_peer_packet`]'s consume policy.
#[must_use]
pub(crate) fn pack_peer_frame_if_over_threshold(packet: Packet) -> Packet {
    if packet.payload().len() > PEER_PACK_THRESHOLD {
        rmule_primitives::pack_if_smaller(packet)
    } else {
        packet
    }
}

/// Inflate one inbound packed `0xD4` peer frame into its logical
/// `OP_EMULEPROT` [`Packet`].
///
/// `packet` must already have been recognised as
/// [`PacketProtocol::PackedEd2k`] by the framing layer; this is asserted
/// in debug builds. Returns a typed [`CompressedFrameSkipReason`] when
/// inflation fails or the decompressed payload would exceed
/// [`PEER_COMPRESSED_FRAME_LIMIT`] — both are non-terminal at the session
/// level (see [`crate::NoticeEvent::CompressedFrameSkipped`]). Re-attributes
/// to [`PacketProtocol::Emule`] unconditionally — aMule sets `OP_EMULEPROT`
/// after unpack regardless of the packed frame's logical origin
/// (`Packet.cpp#L301`).
///
/// Peer policy (this cap, `Emule` re-attribution) over the shared
/// [`rmule_primitives::inflate`] mechanism (ADR-0053).
pub(crate) fn inflate_peer_packet(packet: &Packet) -> Result<Packet, CompressedFrameSkipReason> {
    rmule_primitives::inflate(packet, PEER_COMPRESSED_FRAME_LIMIT, PacketProtocol::Emule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;

    fn zlib_bytes(input: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn inflates_packed_peer_packet_payload_to_emule_protocol() {
        let compressed = zlib_bytes(b"\x03\x00hi!");
        let packed = Packet::new(PacketProtocol::PackedEd2k, 0x82, compressed);

        let inflated = inflate_peer_packet(&packed).expect("inflate");

        assert_eq!(inflated.protocol(), PacketProtocol::Emule);
        assert_eq!(inflated.opcode(), 0x82);
        assert_eq!(inflated.payload(), b"\x03\x00hi!");
    }

    #[test]
    fn invalid_zlib_payload_maps_to_inflate_failed() {
        let packed = Packet::new(PacketProtocol::PackedEd2k, 0x82, vec![0, 1, 2]);
        assert_eq!(
            inflate_peer_packet(&packed),
            Err(CompressedFrameSkipReason::InflateFailed)
        );
    }

    #[test]
    fn oversized_decompressed_payload_maps_to_limit_exceeded() {
        let too_large = vec![b'x'; PEER_COMPRESSED_FRAME_LIMIT + 1];
        let packed = Packet::new(PacketProtocol::PackedEd2k, 0x82, zlib_bytes(&too_large));
        assert_eq!(
            inflate_peer_packet(&packed),
            Err(CompressedFrameSkipReason::DecompressedSizeLimitExceeded {
                limit: PEER_COMPRESSED_FRAME_LIMIT
            })
        );
    }

    #[test]
    fn a_payload_exactly_at_the_pack_threshold_is_never_packed() {
        // 354 bytes is *not* "over" the threshold — highly compressible, yet
        // the gate (strictly `> 354`) keeps it plain. Proves the boundary is
        // the size test, not the compressibility of the body.
        let payload = vec![b'a'; PEER_PACK_THRESHOLD];
        let plain = Packet::new(PacketProtocol::Emule, 0x82, payload.clone());

        let result = pack_peer_frame_if_over_threshold(plain);

        assert_eq!(result.protocol(), PacketProtocol::Emule, "stays plain 0x82");
        assert_eq!(result.opcode(), 0x82);
        assert_eq!(result.payload(), payload.as_slice());
    }

    #[test]
    fn a_payload_one_byte_over_the_pack_threshold_is_pack_attempted() {
        // 355 bytes crosses the gate; a run of identical bytes compresses well,
        // so the shared mechanism re-wraps it as a `0xD4` packed frame with the
        // same opcode.
        let payload = vec![b'a'; PEER_PACK_THRESHOLD + 1];
        let plain = Packet::new(PacketProtocol::Emule, 0x82, payload);

        let result = pack_peer_frame_if_over_threshold(plain);

        assert_eq!(
            result.protocol(),
            PacketProtocol::PackedEd2k,
            "over-threshold compressible answer is packed"
        );
        assert_eq!(result.opcode(), 0x82, "the opcode rides through the pack");
    }

    #[test]
    fn decompressed_payload_exactly_at_the_peer_cap_is_accepted() {
        // Pins the real production ceiling (50 000), not an arbitrary cap —
        // the boundary this surface's own policy promises, distinct from
        // the shape-proving boundary test in `rmule_primitives::packed_frame`.
        let exact = vec![b'x'; PEER_COMPRESSED_FRAME_LIMIT];
        let packed = Packet::new(PacketProtocol::PackedEd2k, 0x82, zlib_bytes(&exact));

        let inflated = inflate_peer_packet(&packed).expect("inflate at cap");

        assert_eq!(inflated.payload().len(), PEER_COMPRESSED_FRAME_LIMIT);
    }
}
