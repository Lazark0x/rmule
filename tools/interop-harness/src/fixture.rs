//! Hand-laid wire records the verdict tests share, one copy.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::flow::pcap::{Ed2kFrame, TcpOpen};

pub(crate) fn at(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(ip, port))
}

pub(crate) fn frame(
    when: f64,
    source: SocketAddr,
    destination: SocketAddr,
    (protocol, opcode): (u8, u8),
    body: &[u8],
) -> Ed2kFrame {
    let mut bytes = vec![protocol];
    bytes.extend_from_slice(&u32::try_from(body.len() + 1).unwrap().to_le_bytes());
    bytes.push(opcode);
    bytes.extend_from_slice(body);
    Ed2kFrame {
        at: when,
        source,
        destination,
        protocol,
        opcode,
        bytes,
    }
}

pub(crate) fn open(when: f64, source: SocketAddr, destination: SocketAddr) -> TcpOpen {
    TcpOpen {
        at: when,
        source,
        destination,
    }
}
