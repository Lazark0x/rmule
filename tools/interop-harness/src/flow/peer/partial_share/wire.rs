//! What the tap on rmule's namespace shows between rmule and the bodies that
//! fetch from it: every answer rmule gave a probe, every slot ask and grant,
//! every block it sent and every reask it answered.
//!
//! Read by a reader of the harness's own, not rmule's: rmule's writers are
//! what the flow tests. A frame is attributed by its direction alone — what
//! rmule sent, what a peer sent — never by which side opened the link,
//! because an uploader dials its queued downloader to grant a slot, and a
//! downloader that holds parts may become rmule's own source on the same
//! link. A packed frame (`0xD4`) is inflated and read as the `0xC5` frame it
//! carries; a compressed block is reassembled from its fragments and
//! inflated before it is compared with the file.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::Result;

use crate::flow::pcap::{records, tcp_capture, udp4_datagrams};

mod frames;

use self::frames::{Fragments, decode, decode_udp, unpacked};

/// A file hash's width on the wire.
const HASH_LEN: usize = 16;

/// A file hash as it sits on the wire.
pub(crate) type Hash = [u8; HASH_LEN];

/// One part status: its count and the parts its bits name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Status {
    /// The part count written; `0` is the complete-file form.
    pub(crate) count: u16,
    /// The parts whose bit is set.
    pub(crate) held: BTreeSet<u32>,
}

/// One thing a frame said, in either direction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Said {
    /// rmule named the file (`0x59`, alone or in a `0x93`).
    Name { hash: Hash, name: String },
    /// rmule wrote a part status (`0x50`, alone or in a `0x93`).
    Status { hash: Hash, status: Status },
    /// rmule answered a hash-set ask with the set.
    HashSet { hash: Hash, parts: Vec<Hash> },
    /// rmule said it has no such file (`0x48`).
    NoFile { hash: Hash },
    /// rmule granted the slot (`0x55`).
    Accept,
    /// rmule queued the peer at `rank` (`0x60`).
    Rank { rank: u16 },
    /// rmule ended the peer's requests (`0x57`).
    OutOfParts,
    /// rmule sent bytes of `hash` from `start`, inflated when compressed.
    Block {
        hash: Hash,
        start: u64,
        bytes: Vec<u8>,
    },
    /// rmule answered a source ask: the source records' first four bytes.
    Sources { hash: Hash, ids: Vec<u32> },
    /// A peer asked rmule for the file's name (alone or bundled).
    NameAsk { hash: Hash, sources_asked: bool },
    /// A peer asked rmule for its part status alone (`0x4F`).
    StatusAsk { hash: Hash },
    /// A peer asked rmule for its hash set.
    HashSetAsk { hash: Hash },
    /// A peer asked rmule for a slot.
    SlotAsk,
    /// A peer asked rmule for byte ranges (end exclusive).
    Request { hash: Hash, ranges: Vec<(u64, u64)> },
    /// A peer asked rmule for sources, standalone.
    SourcesAsk { hash: Hash },
    /// A peer cancelled its transfer (`0x56`).
    Cancel,
}

/// One frame of a link, attributed.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Item {
    /// Capture time, seconds since the epoch.
    pub(crate) at: f64,
    /// The other end of the link.
    pub(crate) peer: SocketAddr,
    /// Whether rmule sent it.
    pub(crate) from_rmule: bool,
    /// What it said.
    pub(crate) said: Said,
}

/// A TCP link's close.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Close {
    pub(crate) at: f64,
    pub(crate) peer: SocketAddr,
    pub(crate) by_rmule: bool,
}

/// One client-UDP datagram between rmule and a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Udp {
    /// A peer's `OP_REASKFILEPING` for `hash`.
    Ping { hash: Hash },
    /// rmule's `OP_REASKACK`: the status it carried, when it carried one,
    /// and the rank.
    Ack { status: Option<Status>, rank: u16 },
    /// rmule's `OP_FILENOTFOUND`.
    NotFound,
    /// rmule's `OP_QUEUEFULL`.
    QueueFull,
}

/// One datagram, attributed.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Datagram {
    pub(crate) at: f64,
    pub(crate) peer: Ipv4Addr,
    pub(crate) said: Udp,
}

/// Everything between rmule and the peers the tap holds.
#[derive(Debug, Default)]
pub(crate) struct Wire {
    pub(crate) items: Vec<Item>,
    pub(crate) closes: Vec<Close>,
    pub(crate) datagrams: Vec<Datagram>,
    /// Links that are not plain eD2k from their first byte, or cut by a hole.
    pub(crate) unread_links: usize,
}

/// Read the tap at `pcap` for rmule at `rmule` and the peers `peers`.
///
/// # Errors
/// If the pcap cannot be read.
pub(crate) fn read(pcap: &Path, rmule: Ipv4Addr, peers: &[Ipv4Addr]) -> Result<Wire> {
    let is_peer = |address: &SocketAddr| match address {
        SocketAddr::V4(v4) => peers.contains(v4.ip()),
        SocketAddr::V6(_) => false,
    };
    let is_rmule = |address: &SocketAddr| address.ip() == std::net::IpAddr::V4(rmule);
    let records = records(pcap)?;
    let capture = tcp_capture(&records)?;
    let mut wire = Wire::default();
    for stream in &capture.streams {
        let (from_rmule, peer) = if is_rmule(&stream.source) && is_peer(&stream.destination) {
            (true, stream.destination)
        } else if is_peer(&stream.source) && is_rmule(&stream.destination) {
            (false, stream.source)
        } else {
            continue;
        };
        if !stream.opens_plain() || stream.gapped {
            wire.unread_links += 1;
        }
        let mut packed_blocks = Fragments::default();
        for frame in stream.ed2k_frames() {
            let Some((protocol, payload)) = unpacked(frame.protocol, frame.payload()) else {
                continue;
            };
            for said in decode(
                protocol,
                frame.opcode,
                &payload,
                from_rmule,
                &mut packed_blocks,
            ) {
                wire.items.push(Item {
                    at: frame.at,
                    peer,
                    from_rmule,
                    said,
                });
            }
        }
    }
    wire.items.sort_by(|a, b| a.at.total_cmp(&b.at));
    for close in &capture.closes {
        if is_rmule(&close.source) && is_peer(&close.destination) {
            wire.closes.push(Close {
                at: close.at,
                peer: close.destination,
                by_rmule: true,
            });
        } else if is_peer(&close.source) && is_rmule(&close.destination) {
            wire.closes.push(Close {
                at: close.at,
                peer: close.source,
                by_rmule: false,
            });
        }
    }
    for datagram in udp4_datagrams(pcap)? {
        let (peer, from_rmule) =
            if *datagram.source.ip() == rmule && peers.contains(datagram.destination.ip()) {
                (*datagram.destination.ip(), true)
            } else if *datagram.destination.ip() == rmule && peers.contains(datagram.source.ip()) {
                (*datagram.source.ip(), false)
            } else {
                continue;
            };
        if let Some(said) = decode_udp(&datagram.payload, from_rmule) {
            wire.datagrams.push(Datagram {
                at: datagram.at,
                peer,
                said,
            });
        }
    }
    Ok(wire)
}

#[cfg(test)]
mod tests;
