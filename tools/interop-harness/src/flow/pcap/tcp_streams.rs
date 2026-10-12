//! Every TCP direction a pcap carries, reassembled into the bytes it delivered,
//! and the eD2k frames walked out of them.
//!
//! A TCP segment is not a frame boundary. A sender that queues two frames
//! writes them in one segment (rmule's `OP_ANSWERSOURCES2` rode behind its
//! signature packet in bench run `1790612092`), and a frame larger than the
//! MSS arrives in several. A BPF predicate on a segment's first payload byte
//! therefore misses the second frame of a shared segment and misreads the
//! continuation of a split one. Here each direction is ordered by sequence
//! number — retransmitted bytes read once, a hole ends the stream — and the
//! `<protocol 1><length 4 LE><opcode 1>` header is walked frame by frame over
//! the result.
//!
//! A stream the tap joined mid-connection (no SYN seen) starts at the lowest
//! sequence number captured; if that is not a frame header the walk yields
//! nothing rather than guessing where a frame begins.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result, bail};

use super::{
    ETHERNET_HEADER_LEN, ETHERTYPE_IPV4, ETHERTYPE_IPV6, IPPROTO_TCP, IPV6_HEADER_LEN, Record,
    Tail, ipv4_packet, parse_records, read_records,
};

/// The eD2k protocol bytes a peer or server TCP frame opens with: `OP_EDONKEYPROT`,
/// `OP_EMULEPROT`, `OP_PACKEDPROT`.
pub(crate) const ED2K_PROTOCOLS: [u8; 3] = [0xE3, 0xC5, 0xD4];

/// The TCP SYN flag bit.
const TCP_SYN: u8 = 0x02;
/// The TCP FIN and RST flag bits: either ends the sender's side.
const TCP_FIN_OR_RST: u8 = 0x05;
/// The TCP ACK flag bit: a SYN without it is the dialing side's.
const TCP_ACK: u8 = 0x10;

/// One direction of one TCP connection, as far as it was delivered without a
/// hole.
#[derive(Clone, Debug)]
pub(crate) struct TcpStream {
    /// The sender.
    pub(crate) source: SocketAddr,
    /// The receiver.
    pub(crate) destination: SocketAddr,
    /// The bytes in sequence order from the stream's start to its first hole.
    pub(crate) bytes: Vec<u8>,
    /// Segments that added bytes to [`bytes`](Self::bytes) — a retransmission
    /// of bytes already delivered does not count.
    pub(crate) segments: u64,
    /// Whether a missing segment cut the stream short.
    pub(crate) gapped: bool,
    /// `(end offset, capture time)` of every segment that added bytes, in
    /// offset order.
    delivered: Vec<(usize, f64)>,
}

/// One eD2k frame, whole, as a reassembled stream delivered it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Ed2kFrame {
    /// Capture time of the segment that delivered the frame's last byte.
    pub(crate) at: f64,
    /// The sender.
    pub(crate) source: SocketAddr,
    /// The receiver.
    pub(crate) destination: SocketAddr,
    /// `0xE3`, `0xC5` or `0xD4`.
    pub(crate) protocol: u8,
    /// The byte after the 4-byte length.
    pub(crate) opcode: u8,
    /// The whole frame, header included.
    pub(crate) bytes: Vec<u8>,
}

/// A FIN or RST one side of a TCP connection sent: that side closed it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TcpClose {
    /// Capture time of the segment.
    pub(crate) at: f64,
    /// The side that closed.
    pub(crate) source: SocketAddr,
    /// The other side.
    pub(crate) destination: SocketAddr,
}

/// A SYN without ACK: one side dialed the other.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TcpOpen {
    /// Capture time of the segment.
    pub(crate) at: f64,
    /// The side that dialed.
    pub(crate) source: SocketAddr,
    /// The side it dialed.
    pub(crate) destination: SocketAddr,
}

/// Every TCP direction of a capture, every FIN or RST and every dial in it.
pub(crate) struct TcpCapture {
    /// The reassembled directions, as [`tcp_streams`] returns them.
    pub(crate) streams: Vec<TcpStream>,
    /// Every FIN or RST segment, in capture order, retransmissions included.
    pub(crate) closes: Vec<TcpClose>,
    /// Every SYN without ACK, in capture order, retransmissions included.
    pub(crate) opens: Vec<TcpOpen>,
}

impl Ed2kFrame {
    /// The bytes after the opcode.
    pub(crate) fn payload(&self) -> &[u8] {
        &self.bytes[6..]
    }
}

impl TcpStream {
    /// Whether the stream opens with an eD2k frame header — a plain eD2k link;
    /// an obfuscated one opens with random-looking key material.
    pub(crate) fn opens_plain(&self) -> bool {
        self.bytes
            .first()
            .is_some_and(|byte| ED2K_PROTOCOLS.contains(byte))
    }

    /// Every whole eD2k frame from the stream's start, stopping at the first
    /// byte that is not a frame header or at a frame the stream holds only part
    /// of.
    pub(crate) fn ed2k_frames(&self) -> Vec<Ed2kFrame> {
        let mut frames = Vec::new();
        let mut at = 0;
        while let Some(header) = self.bytes.get(at..at + 6) {
            if !ED2K_PROTOCOLS.contains(&header[0]) {
                break;
            }
            let length = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
            let end = at + 5 + length;
            let (Some(bytes), true) = (self.bytes.get(at..end), length > 0) else {
                break;
            };
            frames.push(Ed2kFrame {
                at: self.delivered_at(end),
                source: self.source,
                destination: self.destination,
                protocol: header[0],
                opcode: header[5],
                bytes: bytes.to_vec(),
            });
            at = end;
        }
        frames
    }

    /// The bytes after the last whole frame when they do not open with a
    /// frame header — a stream that stopped being eD2k framed — with the
    /// capture time of the segment that delivered their first byte.
    pub(crate) fn unframed_tail(&self) -> Option<(f64, &[u8])> {
        let at: usize = self
            .ed2k_frames()
            .iter()
            .map(|frame| frame.bytes.len())
            .sum();
        let first = self.bytes.get(at)?;
        (!ED2K_PROTOCOLS.contains(first)).then(|| (self.delivered_at(at + 1), &self.bytes[at..]))
    }

    /// Capture time of the segment that delivered the stream's first byte.
    pub(crate) fn opened_at(&self) -> f64 {
        self.delivered.first().map_or(0.0, |(_, at)| *at)
    }

    /// When the byte just before `end` was delivered.
    fn delivered_at(&self, end: usize) -> f64 {
        self.delivered
            .iter()
            .find(|(delivered_end, _)| *delivered_end >= end)
            .map_or(0.0, |(_, at)| *at)
    }
}

/// Every TCP direction in the pcap file `pcap`. A record cut short by the end
/// of the file — a tap stopped mid-write — is left out, as tcpdump leaves it.
///
/// # Errors
/// If the file cannot be read or holds a record this reader refuses.
pub(crate) fn tcp_streams(pcap: &Path) -> Result<Vec<TcpStream>> {
    Ok(reassemble(&read_records(pcap, Tail::Wait)?)?.streams)
}

/// Every TCP direction and every FIN or RST in `records` — for a reader that
/// also walks the same records' UDP datagrams.
///
/// # Errors
/// If a record holds a TCP segment this reader refuses.
pub(crate) fn tcp_capture(records: &[Record]) -> Result<TcpCapture> {
    reassemble(records)
}

/// Every TCP direction in a whole pcap held in memory — `tcpdump -w -`'s
/// stdout. `name` labels errors.
///
/// # Errors
/// As [`tcp_streams`].
pub(crate) fn tcp_streams_in(bytes: &[u8], name: &str) -> Result<Vec<TcpStream>> {
    Ok(reassemble(&parse_records(bytes, Path::new(name), Tail::Refuse)?)?.streams)
}

/// Every eD2k frame in the finished pcap `pcap`, one line each, under a line
/// per TCP direction — for reading a retained run's links by hand.
///
/// # Errors
/// If the file cannot be read or holds a record this reader refuses.
pub fn ed2k_frame_listing(pcap: &Path) -> Result<String> {
    let mut listing = String::new();
    for stream in tcp_streams(pcap)? {
        let frames = stream.ed2k_frames();
        let kind = if stream.opens_plain() {
            "plain"
        } else {
            "not eD2k framed"
        };
        listing.push_str(&format!(
            "{} > {}: {} bytes in {} segments, {kind}{}, {} frames\n",
            stream.source,
            stream.destination,
            stream.bytes.len(),
            stream.segments,
            if stream.gapped { ", cut by a hole" } else { "" },
            frames.len(),
        ));
        for frame in frames {
            listing.push_str(&format!(
                "  {:.6} {:#04x}/{:#04x} {} bytes\n",
                frame.at,
                frame.protocol,
                frame.opcode,
                frame.bytes.len()
            ));
        }
    }
    Ok(listing)
}

/// One TCP segment's addressing, sequence number, flags and payload.
struct Segment {
    source: SocketAddr,
    destination: SocketAddr,
    seq: u32,
    flags: u8,
    payload: Vec<u8>,
}

/// A direction being collected: the sequence number its data starts at, when
/// a SYN named it, and every payload segment seen.
#[derive(Default)]
struct Pending {
    start: Option<u32>,
    segments: Vec<(u32, Vec<u8>, f64)>,
}

fn reassemble(records: &[Record]) -> Result<TcpCapture> {
    let mut order: Vec<(SocketAddr, SocketAddr)> = Vec::new();
    let mut pending: HashMap<(SocketAddr, SocketAddr), Pending> = HashMap::new();
    let mut streams = Vec::new();
    let mut closes = Vec::new();
    let mut opens = Vec::new();
    for record in records {
        let Some(segment) = tcp_segment(&record.frame)? else {
            continue;
        };
        let key = (segment.source, segment.destination);
        if segment.flags & TCP_SYN != 0 && segment.flags & TCP_ACK == 0 {
            opens.push(TcpOpen {
                at: record.at,
                source: segment.source,
                destination: segment.destination,
            });
        }
        if segment.flags & TCP_FIN_OR_RST != 0 {
            closes.push(TcpClose {
                at: record.at,
                source: segment.source,
                destination: segment.destination,
            });
        }
        if !pending.contains_key(&key) {
            order.push(key);
        }
        let direction = pending.entry(key).or_default();
        if segment.flags & TCP_SYN != 0 {
            let start = segment.seq.wrapping_add(1);
            // A SYN on a 4-tuple that already carried data is a new
            // connection reusing the ports; a repeated SYN is not.
            if direction.start != Some(start) && !direction.segments.is_empty() {
                streams.push(finish(key, std::mem::take(direction)));
            }
            direction.start = Some(start);
        }
        if !segment.payload.is_empty() {
            direction
                .segments
                .push((segment.seq, segment.payload, record.at));
        }
    }
    for key in order {
        if let Some(direction) = pending.remove(&key)
            && !direction.segments.is_empty()
        {
            streams.push(finish(key, direction));
        }
    }
    Ok(TcpCapture {
        streams,
        closes,
        opens,
    })
}

/// Order one direction's segments by sequence number and lay them end to end.
fn finish((source, destination): (SocketAddr, SocketAddr), direction: Pending) -> TcpStream {
    let start = direction.start.unwrap_or_else(|| {
        let first = direction.segments[0].0;
        direction
            .segments
            .iter()
            .map(|(seq, ..)| *seq)
            .min_by_key(|seq| seq.wrapping_sub(first) as i32)
            .unwrap_or(first)
    });
    let mut segments: Vec<(i64, Vec<u8>, f64)> = direction
        .segments
        .into_iter()
        .map(|(seq, payload, at)| (i64::from(seq.wrapping_sub(start) as i32), payload, at))
        .collect();
    segments.sort_by(|a, b| a.0.cmp(&b.0).then(a.2.total_cmp(&b.2)));
    let mut stream = TcpStream {
        source,
        destination,
        bytes: Vec::new(),
        segments: 0,
        gapped: false,
        delivered: Vec::new(),
    };
    for (offset, payload, at) in segments {
        let end = offset + payload.len() as i64;
        let delivered = stream.bytes.len() as i64;
        if offset > delivered {
            stream.gapped = true;
            break;
        }
        if end <= delivered {
            continue;
        }
        let fresh = usize::try_from(delivered - offset).unwrap_or(0);
        stream.bytes.extend_from_slice(&payload[fresh..]);
        stream.segments += 1;
        stream.delivered.push((stream.bytes.len(), at));
    }
    stream
}

/// The TCP segment in one Ethernet frame, or `None` for a frame that is not
/// TCP over IPv4 or IPv6.
fn tcp_segment(frame: &[u8]) -> Result<Option<Segment>> {
    let ethertype = frame
        .get(12..14)
        .map(|it| u16::from_be_bytes([it[0], it[1]]))
        .context("frame is shorter than an Ethernet header")?;
    let (source_ip, destination_ip, tcp): (IpAddr, IpAddr, &[u8]) = match ethertype {
        ETHERTYPE_IPV4 => {
            let ip = &frame[ETHERNET_HEADER_LEN..];
            if ip.get(9) != Some(&IPPROTO_TCP) {
                return Ok(None);
            }
            let (ip, ihl) = ipv4_packet(frame, IPPROTO_TCP)?;
            let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
            let address = |at: usize| Ipv4Addr::new(ip[at], ip[at + 1], ip[at + 2], ip[at + 3]);
            (
                address(12).into(),
                address(16).into(),
                ip.get(ihl..total)
                    .context("IP total length runs past the captured frame")?,
            )
        }
        ETHERTYPE_IPV6 => {
            let ip = &frame[ETHERNET_HEADER_LEN..];
            let header = ip
                .get(..IPV6_HEADER_LEN)
                .context("IPv6 header is truncated")?;
            if header[6] != IPPROTO_TCP {
                return Ok(None);
            }
            let payload_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
            let address = |at: usize| {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&header[at..at + 16]);
                Ipv6Addr::from(octets)
            };
            (
                address(8).into(),
                address(24).into(),
                ip.get(IPV6_HEADER_LEN..IPV6_HEADER_LEN + payload_len)
                    .context("IPv6 payload length runs past the captured frame")?,
            )
        }
        _ => return Ok(None),
    };
    let header = tcp.get(..14).context("TCP header is truncated")?;
    let data_offset = usize::from(header[12] >> 4) * 4;
    let Some(payload) = tcp.get(data_offset..) else {
        bail!("the TCP header runs past the segment");
    };
    Ok(Some(Segment {
        source: SocketAddr::new(source_ip, u16::from_be_bytes([header[0], header[1]])),
        destination: SocketAddr::new(destination_ip, u16::from_be_bytes([header[2], header[3]])),
        seq: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
        flags: header[13],
        payload: payload.to_vec(),
    }))
}

#[cfg(test)]
mod tests;
