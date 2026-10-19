//! A served block crosses as aMule's uploader cuts it (ADR-0031): plain, a
//! run of `OP_SENDINGPART` of about 10 KiB whose ranges tile the block;
//! compressed, a run of `OP_COMPRESSEDPART` sharing the block's start and the
//! stream's total length. A stock downloader restarts its download timeout
//! only on a whole packet (`DownloadClient.cpp:848`), so one block-sized
//! packet starves a slow link. A requesting rmule session takes either run
//! back as the block.

use rmule_peer::{
    Hello, MiscOptions1, PartRanges, PeerCommand, PeerEvent, PeerOpcode, PeerOutput, PeerPacket,
    PeerSession, RequesterCommand, RequesterEvent, ServerCommand,
};
use rmule_primitives::session::drain;
use rmule_primitives::{FileHash, Packet, PartHash, UserHash};
use rmule_testkit::peer_session::*;

/// `EMBLOCKSIZE`: the block a stock downloader asks for.
const BLOCK: usize = 184_320;

/// A served block's bytes: varied, and over a sixteen-symbol alphabet, so the
/// zlib stream shrinks to about half and still spans several packets.
fn block_bytes() -> Vec<u8> {
    let mut x: u32 = 0x9E37_79B9;
    (0..BLOCK)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            b'a' + (x >> 28) as u8
        })
        .collect()
}

/// An inbound session past the hello, holding a granted slot for `file`;
/// `compresses` is whether the peer advertised data compression.
fn serving(file: FileHash, compresses: bool) -> PeerSession {
    let mut s = PeerSession::new_inbound(peer(), ctx());
    let mut body = answer_body(UserHash::from_bytes([0x55; 16]));
    if compresses {
        body.tags.push(MiscOptions1::rmule_advertised().to_tag());
    }
    s.handle_bytes(&Hello::new(body).encode_packet().encode());
    let _ = drain(|| s.poll_output());
    s.handle_command(PeerCommand::Server(ServerCommand::GrantSlot {
        file_hash: file,
    }));
    let _ = drain(|| s.poll_output());
    s
}

/// Every write `server` makes for one `SendBlock` of `bytes` at `start`.
fn serve(server: &mut PeerSession, file: FileHash, start: u64, bytes: &[u8]) -> Vec<PeerOutput> {
    server.handle_command(PeerCommand::Server(ServerCommand::SendBlock {
        file_hash: file,
        start,
        end: start + bytes.len() as u64,
        bytes: bytes.to_vec(),
        compressible: true,
    }));
    drain(|| server.poll_output())
}

fn decoded(outputs: &[PeerOutput]) -> Vec<(Packet, PeerPacket)> {
    writes(outputs)
        .into_iter()
        .map(|p| {
            let decoded = PeerPacket::decode(&p).expect("a served frame decodes");
            (p, decoded)
        })
        .collect()
}

#[test]
fn a_full_block_goes_out_as_eighteen_sending_parts_that_tile_it() {
    let file = file_hash(0xB1);
    let start = 2 * BLOCK as u64;
    let block = block_bytes();
    let mut server = serving(file, false);

    let packets = decoded(&serve(&mut server, file, start, &block));

    assert_eq!(
        packets.len(),
        18,
        "aMule cuts 184,320 bytes into 18 packets"
    );
    let mut at = start;
    let mut carried = Vec::new();
    for (_, packet) in &packets {
        let PeerPacket::SendingPart(sp) = packet else {
            panic!("a plain block is sent as OP_SENDINGPART, got {packet:?}");
        };
        assert_eq!(sp.file_hash, file);
        assert_eq!(
            (sp.start, sp.end),
            (at, at + 10_240),
            "ranges tile in order"
        );
        at = sp.end;
        carried.extend_from_slice(&sp.data);
    }
    assert_eq!(at, start + BLOCK as u64, "the last range ends the block");
    assert!(carried == block, "the packets carry the block");
}

/// aMule picks each plain packet's width on that packet's own offsets
/// (`UploadClient.cpp:307`): in the block of a large file that crosses 4 GiB,
/// only the packets reaching past `0xFFFFFFFF` ride `OP_SENDINGPART_I64`.
#[test]
fn a_block_across_4_gib_widens_only_the_packets_past_it() {
    let file = file_hash(0xB2);
    // Part 441's block 26 straddles 4 GiB: 441 × 9,728,000 + 26 × 184,320.
    let start: u64 = 4_294_840_320;
    let mut server = serving(file, false);

    let packets = decoded(&serve(&mut server, file, start, &block_bytes()));

    assert_eq!(packets.len(), 18);
    let mut at = start;
    for (wire, packet) in &packets {
        let (sp_start, sp_end) = match packet {
            PeerPacket::SendingPart(sp) => (sp.start, sp.end),
            other => panic!("a plain block is sent as OP_SENDINGPART, got {other:?}"),
        };
        assert_eq!(sp_start, at);
        at = sp_end;
        let wide = PeerOpcode::SendingPartI64;
        assert_eq!(
            (wire.protocol(), wire.opcode()) == (wide.protocol(), wide.as_u8()),
            sp_end > u64::from(u32::MAX),
            "packet {sp_start}..{sp_end}"
        );
    }
    assert_eq!(at, start + BLOCK as u64);
}

#[test]
fn a_compressed_block_goes_out_as_a_run_sharing_its_start_and_total() {
    let file = file_hash(0xB3);
    let start = BLOCK as u64;
    let block = block_bytes();
    let mut server = serving(file, true);

    let packets = decoded(&serve(&mut server, file, start, &block));

    let chunks: Vec<_> = packets
        .iter()
        .map(|(_, packet)| match packet {
            PeerPacket::CompressedPart(cp) => cp,
            other => panic!("a compressible block is sent as OP_COMPRESSEDPART, got {other:?}"),
        })
        .collect();
    let total: usize = chunks.iter().map(|cp| cp.compressed_chunk.len()).sum();
    assert!(
        chunks.len() > 1,
        "a {total}-byte stream spans several packets"
    );
    assert_eq!(chunks.len(), total / 10_240, "aMule's count for the stream");
    for cp in &chunks {
        assert_eq!(cp.file_hash, file);
        assert_eq!(cp.start, start, "every packet names the block's start");
        assert_eq!(
            cp.compressed_block_len as usize, total,
            "and the stream's total"
        );
        assert!((10_240..20_480).contains(&cp.compressed_chunk.len()));
    }
    let stream: Vec<u8> = chunks
        .iter()
        .flat_map(|cp| cp.compressed_chunk.iter().copied())
        .collect();
    let mut inflated = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::ZlibDecoder::new(&stream[..]),
        &mut inflated,
    )
    .unwrap();
    assert!(inflated == block, "the stream inflates to the block");
}

/// A requesting rmule session driven to `Downloading` for `file`, asking
/// for the block at `start`.
fn downloading(file: FileHash, start: u64) -> PeerSession {
    let mut client = identified_session();
    let ranges = PartRanges::new([(start, start + BLOCK as u64), (0, 0), (0, 0)]).unwrap();
    client.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: file,
        file_size: 1_000_000,
        ranges,
    }));
    client.handle_bytes(&reqfilename_answer(file, "x"));
    client.handle_bytes(&file_status(file, 1, &[0x01]));
    client.handle_bytes(&hashset_answer(file, &[PartHash::from_bytes([0; 16])]));
    client.handle_bytes(&acceptuploadreq());
    let _ = drain(|| client.poll_output());
    client
}

#[test]
fn a_requester_assembles_a_served_block_from_either_run() {
    let start = BLOCK as u64;
    let block = block_bytes();
    for compresses in [false, true] {
        let file = file_hash(0xB4);
        let mut server = serving(file, compresses);
        let wire: Vec<u8> = serve(&mut server, file, start, &block)
            .iter()
            .filter_map(|o| match o {
                PeerOutput::Write(frame) => Some(frame.iter().copied()),
                _ => None,
            })
            .flatten()
            .collect();
        let mut client = downloading(file, start);

        client.handle_bytes(&wire);

        let out = drain(|| client.poll_output());
        let mut at = start;
        let mut assembled = Vec::new();
        for event in events(&out) {
            if let PeerEvent::Requester(RequesterEvent::PartReceived {
                file_hash,
                offset,
                bytes,
            }) = event
            {
                assert_eq!(
                    (*file_hash, *offset),
                    (file, at),
                    "compressed: {compresses}"
                );
                at += bytes.len() as u64;
                assembled.extend_from_slice(bytes);
            }
        }
        assert!(assembled == block, "compressed: {compresses}");
    }
}
