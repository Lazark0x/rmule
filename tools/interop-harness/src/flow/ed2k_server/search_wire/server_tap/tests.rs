//! The server tap's links and timeline over segments that arrive out of order
//! and a client port that a second connection reuses.

use std::net::Ipv4Addr;

use super::{links, offered_origins, write_timeline};

const CLIENT: [u8; 4] = [203, 0, 113, 30];
const SERVER: [u8; 4] = [203, 0, 113, 2];
const CLIENT_PORT: u16 = 51734;
const SERVER_PORT: u16 = 4661;
const SYN: u8 = 0x02;
const FIN_ACK: u8 = 0x11;
const PSH_ACK: u8 = 0x18;

/// One Ethernet/IPv4/TCP frame; `to_server` picks the direction.
fn segment(to_server: bool, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let (source, destination, source_port, destination_port) = if to_server {
        (CLIENT, SERVER, CLIENT_PORT, SERVER_PORT)
    } else {
        (SERVER, CLIENT, SERVER_PORT, CLIENT_PORT)
    };
    let mut frame = vec![0_u8; 12];
    frame.extend_from_slice(&[0x08, 0x00]);
    let total = u16::try_from(40 + payload.len()).unwrap().to_be_bytes();
    frame.extend_from_slice(&[0x45, 0, total[0], total[1]]);
    frame.extend_from_slice(&[0x1c, 0x2d, 0x40, 0x00, 64, 6, 0, 0]);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source_port.to_be_bytes());
    frame.extend_from_slice(&destination_port.to_be_bytes());
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
    for (second, frame) in (0_u32..).zip(frames) {
        let len = u32::try_from(frame.len()).unwrap();
        for word in [1_790_000_000 + second, 0, len, len] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(frame);
    }
    bytes
}

/// An `OP_SEARCHREQUEST` for one keyword.
fn search(word: &str) -> Vec<u8> {
    let mut body = vec![0x01];
    body.extend_from_slice(&u16::try_from(word.len()).unwrap().to_le_bytes());
    body.extend_from_slice(word.as_bytes());
    let mut frame = vec![0xe3];
    frame.extend_from_slice(&u32::try_from(body.len() + 1).unwrap().to_le_bytes());
    frame.push(0x16);
    frame.extend_from_slice(&body);
    frame
}

fn write(frames: &[Vec<u8>]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("server.pcap"), pcap(frames)).unwrap();
    dir
}

/// A search split across two segments that arrive out of order is one
/// timeline line, stamped with the segment that completed it.
#[test]
fn a_search_split_across_reordered_segments_reads_as_one_frame() {
    let request = search("wirekeyword");
    let dir = write(&[
        segment(true, 100, SYN, &[]),
        segment(true, 101 + 9, PSH_ACK, &request[9..]),
        segment(true, 101, PSH_ACK, &request[..9]),
    ]);
    let out = dir.path().join("decoded.txt");
    write_timeline(&dir.path().join("server.pcap"), &out).unwrap();
    assert_eq!(
        std::fs::read_to_string(out).unwrap(),
        "   1.000 203.0.113.30:51734>203.0.113.2:4661 op=0x16 len=14 SEARCH 'wirekeyword'\n"
    );
}

/// A client port reused by a second connection is a second link: each keeps
/// its own searches, and each close lands on the connection it ended.
#[test]
fn a_reused_client_port_is_a_second_link() {
    let (first, second) = (search("first"), search("second"));
    let next = |isn: u32, frame: &[u8]| isn + 1 + u32::try_from(frame.len()).unwrap();
    let dir = write(&[
        segment(true, 1000, SYN, &[]),
        segment(true, 1001, PSH_ACK, &first),
        segment(true, next(1000, &first), FIN_ACK, &[]),
        segment(true, 9000, SYN, &[]),
        segment(true, 9001, PSH_ACK, &second),
        segment(true, 9001, PSH_ACK, &second),
        segment(false, 5000, FIN_ACK, &[]),
    ]);
    let links = links(&dir.path().join("server.pcap"), SERVER_PORT).unwrap();
    let read: Vec<(Ipv4Addr, Vec<f64>, Option<bool>)> = links
        .iter()
        .map(|link| {
            (
                *link.client.ip(),
                link.searches.clone(),
                link.closed_by_server,
            )
        })
        .collect();
    let client = Ipv4Addr::from(CLIENT);
    assert_eq!(
        read,
        [
            (client, vec![1_790_000_001.0], Some(false)),
            (client, vec![1_790_000_004.0], Some(true)),
        ]
    );
}

/// The `OP_OFFERFILES` a stock aMule 2.3.3 sent Lugdunum (flags `0x17F9`,
/// compression granted) for a complete file, verbatim from a retained `search-wire` run's
/// Lugdunum server tap: the entry's ID
/// and port are the complete-file marker, not the client's own.
#[test]
fn a_complete_file_offer_reads_as_the_fb_marker() {
    let mut payload = vec![0x01, 0, 0, 0];
    payload.extend_from_slice(&[
        0xcc, 0x89, 0xb8, 0x4b, 0xa3, 0x73, 0xb4, 0xa4, 0x74, 0x1f, 0x22, 0x5b, 0x9d, 0x47, 0x89,
        0x58, // file hash
        0xfb, 0xfb, 0xfb, 0xfb, 0xfb, 0xfb, // id and port
        0x03, 0, 0, 0, // three tags
        0x82, 0x01, 0x17, 0x00,
    ]);
    payload.extend_from_slice(b"relatedpopular-wire.bin");
    payload.extend_from_slice(&[0x88, 0x02, 0x06, 0x10, 0x89, 0x03, 0x04]);
    let mut frame = vec![0xe3];
    frame.extend_from_slice(&u32::try_from(payload.len() + 1).unwrap().to_le_bytes());
    frame.push(0x15);
    frame.extend_from_slice(&payload);
    let dir = write(&[
        segment(true, 100, SYN, &[]),
        segment(true, 101, PSH_ACK, &frame),
    ]);

    let origins = offered_origins(&dir.path().join("server.pcap"), Ipv4Addr::from(CLIENT)).unwrap();

    assert_eq!(origins, [(1_790_000_001.0, vec![(0xFBFB_FBFB, 0xFBFB)])]);
}
