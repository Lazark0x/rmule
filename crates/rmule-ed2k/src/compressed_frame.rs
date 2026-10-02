//! The packed-frame (`0xD4`) boundary for server packets: the
//! decompressed-size budget an inbound frame may claim, and the skip reasons
//! an over-budget or undecodable one resolves to.
//!
//! The budget mirrors aMule's *server* socket, five times the ceiling its
//! client socket takes (`rmule_peer`'s). A skipped frame costs the frame, not
//! the session.

use rmule_primitives::{Packet, PacketProtocol};

pub use rmule_primitives::SkipReason as CompressedFrameSkipReason;

/// Decompressed-size ceiling for inbound eD2k server compressed frames.
///
/// Mirrors aMule's server TCP unpack budget in `ServerSocket.cpp:592-608`.
/// Acts as a compatibility limit for this protocol surface — peer
/// transfer and future Kad work pick their own ceilings.
pub const SERVER_COMPRESSED_FRAME_LIMIT: usize = 250_000;

/// Inflate one inbound packed `0xD4` server frame into its logical
/// plain-eDonkey [`Packet`].
///
/// `packet` must already have been recognised as
/// [`PacketProtocol::PackedEd2k`] by the framing layer; this is asserted
/// in debug builds. Returns a typed [`CompressedFrameSkipReason`] when
/// inflation fails or the decompressed payload would exceed
/// [`SERVER_COMPRESSED_FRAME_LIMIT`] — both are non-terminal at the
/// session level (see [`crate::Ed2kEvent::CompressedFrameSkipped`]).
///
/// Server policy (this cap, `Edonkey` re-attribution) over the shared
/// [`rmule_primitives::inflate`] mechanism (ADR-0053).
pub(crate) fn inflate_server_packet(packet: &Packet) -> Result<Packet, CompressedFrameSkipReason> {
    rmule_primitives::inflate(
        packet,
        SERVER_COMPRESSED_FRAME_LIMIT,
        PacketProtocol::Edonkey,
    )
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
    fn inflates_packed_server_packet_payload_to_plain_edonkey_packet() {
        let compressed = zlib_bytes(b"\x03\x00hi!");
        let packed = Packet::new(PacketProtocol::PackedEd2k, 0x38, compressed);

        let inflated = inflate_server_packet(&packed).expect("inflate");

        assert_eq!(inflated.protocol(), PacketProtocol::Edonkey);
        assert_eq!(inflated.opcode(), 0x38);
        assert_eq!(inflated.payload(), b"\x03\x00hi!");
    }

    #[test]
    fn invalid_zlib_payload_maps_to_inflate_failed() {
        let packed = Packet::new(PacketProtocol::PackedEd2k, 0x38, vec![0, 1, 2]);
        assert_eq!(
            inflate_server_packet(&packed),
            Err(CompressedFrameSkipReason::InflateFailed)
        );
    }

    #[test]
    fn oversized_decompressed_payload_maps_to_limit_exceeded() {
        let too_large = vec![b'x'; SERVER_COMPRESSED_FRAME_LIMIT + 1];
        let packed = Packet::new(PacketProtocol::PackedEd2k, 0x38, zlib_bytes(&too_large));
        assert_eq!(
            inflate_server_packet(&packed),
            Err(CompressedFrameSkipReason::DecompressedSizeLimitExceeded {
                limit: SERVER_COMPRESSED_FRAME_LIMIT
            })
        );
    }
}
