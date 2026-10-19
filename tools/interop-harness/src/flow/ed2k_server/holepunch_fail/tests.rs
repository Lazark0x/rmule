//! The claims over hand-laid frames: a refusal naming the ghost id as not
//! connected, a server that answers nothing, and a refusal for another asker.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use super::{GHOST_LOW_ID, claims};
use crate::flow::nat::claims::label;
use crate::flow::pcap::Ed2kFrame;

fn server() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 200), 4661))
}

fn probe(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 5), port))
}

fn frame(
    when: f64,
    source: SocketAddr,
    destination: SocketAddr,
    opcode: u8,
    body: &[u8],
) -> Ed2kFrame {
    let mut bytes = vec![0xE3];
    bytes.extend_from_slice(&u32::try_from(body.len() + 1).unwrap().to_le_bytes());
    bytes.push(opcode);
    bytes.extend_from_slice(body);
    Ed2kFrame {
        at: when,
        source,
        destination,
        protocol: 0xE3,
        opcode,
        bytes,
    }
}

fn request(when: f64) -> Ed2kFrame {
    let mut body = GHOST_LOW_ID.to_le_bytes().to_vec();
    body.extend_from_slice(&4672_u16.to_le_bytes());
    frame(when, probe(50_000), server(), 0x60, &body)
}

fn refusal(when: f64, to: SocketAddr, reason: u8) -> Ed2kFrame {
    let mut body = GHOST_LOW_ID.to_le_bytes().to_vec();
    body.push(reason);
    frame(when, server(), to, 0x62, &body)
}

#[test]
fn a_refusal_naming_the_ghost_as_not_connected_passes_and_is_cut_whole() {
    let frames = vec![request(1.0), refusal(1.1, probe(50_000), 1)];
    let (claims, rows, cut) = claims(server(), &frames);
    assert_eq!(label(&claims).0, "PASS", "{claims:#?}");
    assert_eq!((rows.reason, rows.refusal_frame_bytes), (1, 11));
    assert_eq!(cut.map(|f| f.bytes.clone()), Some(frames[1].bytes.clone()));
}

#[test]
fn a_server_that_answers_nothing_fails_and_cuts_nothing() {
    let frames = vec![request(1.0)];
    let (claims, rows, cut) = claims(server(), &frames);
    assert_eq!(label(&claims).0, "FAIL");
    assert_eq!(rows.reason, -1);
    assert!(cut.is_none());
}

/// A refusal sent to another connection answers somebody else's ask, and an
/// unexpected reason is a finding, not a pass.
#[test]
fn only_the_askers_refusal_counts_and_its_reason_is_read() {
    let elsewhere = [request(1.0), refusal(1.1, probe(50_001), 1)];
    let (found, _, cut) = claims(server(), &elsewhere);
    assert!(cut.is_none());
    assert_eq!(label(&found).0, "FAIL");
    let (found, rows, _) = claims(server(), &[request(1.0), refusal(1.1, probe(50_000), 4)]);
    assert_eq!(rows.reason, 4);
    assert_eq!(label(&found).0, "FAIL");
}
