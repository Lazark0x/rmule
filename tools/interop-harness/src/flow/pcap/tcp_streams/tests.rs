//! The frame walk against a captured link where one segment carried three
//! frames, and against synthetic segments packed, split, reordered,
//! retransmitted and cut by a hole.

use super::{Ed2kFrame, tcp_streams_in};

/// rmule's side of its peer link to emule-qt in bench run `1790612092`
/// (`ipv6-extsx-emit`, `tap-wan.pcap`), filtered by header only
/// (`src host 45.55.200.6 and src port 4662 and dst host 45.55.200.3`).
const RUN_1790612092: &[u8] =
    include_bytes!("../../../../tests/fixtures/extsx-emit-1790612092/rmule-to-emuleqt.bin");

/// The 111-byte `OP_ANSWERSOURCES2` that run reported absent sits behind the
/// signature packet and `0x93` in one 204-byte segment; the walk reads it.
#[test]
fn the_captured_answer_sharing_a_segment_is_walked_out() {
    let streams = tcp_streams_in(RUN_1790612092, "run 1790612092").unwrap();
    assert_eq!(streams.len(), 1);
    let stream = &streams[0];
    assert!(stream.opens_plain() && !stream.gapped);
    let opcodes: Vec<(u8, u8)> = stream
        .ed2k_frames()
        .iter()
        .map(|frame| (frame.protocol, frame.opcode))
        .collect();
    assert_eq!(
        opcodes,
        [
            (0xE3, 0x4C),
            (0xC5, 0x87),
            (0xC5, 0x85),
            (0xC5, 0x86),
            (0xC5, 0x93),
            (0xC5, 0x84),
            (0xC5, 0x9D),
            (0xC5, 0x60),
        ]
    );
    let answer = stream
        .ed2k_frames()
        .into_iter()
        .find(|frame| frame.opcode == 0x84)
        .unwrap();
    assert_eq!(answer.bytes.len(), 111);
    assert_eq!(answer.source.to_string(), "45.55.200.6:4662");
}

const CLIENT: [u8; 4] = [45, 55, 200, 17];
const SERVER: [u8; 4] = [45, 55, 200, 42];

/// One Ethernet/IPv4/TCP frame from `CLIENT:51734` to `SERVER:4662`.
fn segment(seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0_u8; 12];
    frame.extend_from_slice(&[0x08, 0x00]);
    let total = (20 + 20 + payload.len()) as u16;
    frame.extend_from_slice(&[0x45, 0, total.to_be_bytes()[0], total.to_be_bytes()[1]]);
    frame.extend_from_slice(&[0x1c, 0x2d, 0x40, 0x00, 64, 6, 0, 0]);
    frame.extend_from_slice(&CLIENT);
    frame.extend_from_slice(&SERVER);
    frame.extend_from_slice(&51734_u16.to_be_bytes());
    frame.extend_from_slice(&4662_u16.to_be_bytes());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    frame.extend_from_slice(payload);
    frame
}

/// A classic little-endian microsecond pcap of `frames`, one per second.
fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for word in [0xa1b2_c3d4_u32, 0x0004_0002, 0, 0, 65535, 1] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    for (second, frame) in frames.iter().enumerate() {
        let len = frame.len() as u32;
        for word in [1_790_000_000 + second as u32, 0, len, len] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(frame);
    }
    bytes
}

fn frame(protocol: u8, opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![protocol];
    frame.extend_from_slice(&(body.len() as u32 + 1).to_le_bytes());
    frame.push(opcode);
    frame.extend_from_slice(body);
    frame
}

/// Two frames packed into one segment, one frame split across two segments
/// that arrive out of order, and a retransmission: every frame is read once,
/// stamped with the segment that completed it.
#[test]
fn packed_split_reordered_and_retransmitted_segments_read_as_frames() {
    let hello = frame(0xE3, 0x01, &[0x10, 0x3a, 0x77, 0xc4, 0x09]);
    let ping = frame(0xC5, 0x9F, &[]);
    let answer = frame(0xC5, 0x84, &(0_u8..40).collect::<Vec<_>>());
    let isn = 0xffff_fff0_u32; // the sequence space wraps mid-stream
    let mut packed = hello.clone();
    packed.extend_from_slice(&ping);
    let data = isn.wrapping_add(1);
    let second = data.wrapping_add(packed.len() as u32);
    let third = second.wrapping_add(17);
    let capture = pcap(&[
        segment(isn, 0x02, &[]),
        segment(data, 0x18, &packed),
        segment(third, 0x18, &answer[17..]),
        segment(second, 0x18, &answer[..17]),
        segment(data, 0x18, &packed),
    ]);

    let streams = tcp_streams_in(&capture, "synthetic").unwrap();
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0].segments, 3);
    let frames = streams[0].ed2k_frames();
    let read: Vec<(u8, u8, usize, f64)> = frames
        .iter()
        .map(
            |Ed2kFrame {
                 protocol,
                 opcode,
                 bytes,
                 at,
                 ..
             }| (*protocol, *opcode, bytes.len(), *at),
        )
        .collect();
    assert_eq!(
        read,
        [
            (0xE3, 0x01, hello.len(), 1_790_000_001.0),
            (0xC5, 0x9F, ping.len(), 1_790_000_001.0),
            (0xC5, 0x84, answer.len(), 1_790_000_002.0),
        ]
    );
    assert_eq!(frames[2].bytes, answer);
}

/// A missing segment ends the stream: the frame it held part of is not
/// invented, and neither is anything after it.
#[test]
fn a_hole_ends_the_walk() {
    let answer = frame(0xC5, 0x84, &[0x5d; 30]);
    let capture = pcap(&[
        segment(700, 0x02, &[]),
        segment(701, 0x18, &answer[..10]),
        segment(701 + 20, 0x18, &answer[20..]),
    ]);
    let streams = tcp_streams_in(&capture, "synthetic").unwrap();
    assert!(streams[0].gapped);
    assert!(streams[0].ed2k_frames().is_empty());
}
