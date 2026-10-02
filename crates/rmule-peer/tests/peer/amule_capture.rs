//! Real-aMule captured evidence (2026-06-23): a single `OP_COMPRESSEDPART`
//! frame produced by Ubuntu `amule-daemon` uploading a 64 KiB file to rmule
//! over the `amule-serves-rmule-downloads` interop harness. aMule compressed
//! the whole file to 579 zlib bytes *because rmule advertised data-compression*
//! — proving rmule's decode + inflate against real aMule bytes, not just
//! spec-derived fixtures. The 609-byte frame is a promoted minimal datagram.

use std::io::Read;

use flate2::read::ZlibDecoder;
use rmule_peer::PeerPacket;
use rmule_primitives::Packet;

const CAPTURED: &[u8] = include_bytes!("../fixtures/amule_compressed_part.bin");

#[test]
fn real_amule_compressed_part_decodes_and_inflates_to_source() {
    let (packet, consumed) = Packet::decode(CAPTURED).expect("frame decodes");
    assert_eq!(consumed, CAPTURED.len(), "fixture is exactly one frame");

    let cp = match PeerPacket::decode(&packet).expect("packet decodes") {
        PeerPacket::CompressedPart(cp) => cp,
        other => panic!("expected CompressedPart, got {other:?}"),
    };
    assert_eq!(cp.start, 0);
    // Single-packet block: nBlockSize equals this packet's compressed length.
    assert_eq!(cp.compressed_block_len as usize, cp.compressed_chunk.len());

    let mut inflated = Vec::new();
    ZlibDecoder::new(&cp.compressed_chunk[..])
        .read_to_end(&mut inflated)
        .expect("real aMule zlib stream inflates");

    // The harness shares a `(offset + i) % 251` sawtooth; aMule packed the
    // whole 64 KiB file into this one compressed part.
    let expected: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(inflated, expected);
}
