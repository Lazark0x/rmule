//! Lifting one datagram's **body** out of a capture, byte for byte.
//!
//! A wire row counts; a fixture needs the bytes. `tcpdump` inside the capture
//! sidecar can already select the datagram (the same BPF the row counts with),
//! so the only thing missing is reading the one-packet pcap it writes. That is
//! this module: a minimal classic-pcap reader that returns the UDP payload of
//! the first record, which is exactly what a Kad fixture is — or every
//! record's UDP payload, for a row a filter cannot pick out on its own (a Kad
//! crypt envelope).
//!
//! A TCP link is read the other way: [`tcp_streams()`] reassembles every
//! direction by sequence number and walks eD2k frames out of the delivered
//! bytes, because a sender packs several frames into one segment and splits
//! one frame across several.
//!
//! Deliberately minimal — it understands the shapes the capture sidecar
//! produces (classic pcap, `EN10MB`, IPv4 or IPv6 without extension headers,
//! no VLAN tag, no fragments) and refuses anything else rather than guessing.
//! A guess here would put bytes into a fixture that the wire never carried
//! (ADR-0045).

use std::path::Path;

use anyhow::{Context, Result, bail};

mod tcp_streams;

pub use self::tcp_streams::ed2k_frame_listing;
pub(crate) use self::tcp_streams::{
    ED2K_PROTOCOLS, Ed2kFrame, TcpCapture, TcpOpen, TcpStream, tcp_capture, tcp_streams,
    tcp_streams_in,
};

/// Classic pcap magic, both byte orders (and their nanosecond variants).
const MAGIC_LE: u32 = 0xa1b2_c3d4;
const MAGIC_BE: u32 = 0xd4c3_b2a1;
const MAGIC_NS_LE: u32 = 0xa1b2_3c4d;
const MAGIC_NS_BE: u32 = 0x4d3c_b2a1;

/// Ethernet + IPv4 + UDP/TCP, the encapsulations the sidecar taps.
const LINKTYPE_EN10MB: u32 = 1;
const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
/// The fixed IPv6 header; a packet with extension headers is refused.
const IPV6_HEADER_LEN: usize = 40;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_TCP: u8 = 6;
const UDP_HEADER_LEN: usize = 8;

/// The UDP payload of the first record in `pcap`, or `None` when the file holds
/// no records (the filter matched nothing — an honest absence).
///
/// # Errors
/// If the file cannot be read, is not a classic pcap, or its first record is
/// not the Ethernet/IPv4/UDP shape the sidecar captures.
pub(crate) fn first_udp_payload(pcap: &Path) -> Result<Option<Vec<u8>>> {
    first_frame(pcap)?
        .map(|frame| udp_payload(&frame))
        .transpose()
}

/// Whether a global header's magic says the file's words are byte-swapped.
fn magic_swapped(magic: u32, pcap: &Path) -> Result<bool> {
    match magic {
        MAGIC_LE | MAGIC_NS_LE => Ok(false),
        MAGIC_BE | MAGIC_NS_BE => Ok(true),
        other => bail!(
            "{} is not a classic pcap (magic {other:#010x})",
            pcap.display()
        ),
    }
}

/// The first record's whole captured frame, refusing a truncated one.
fn first_frame(pcap: &Path) -> Result<Option<Vec<u8>>> {
    Ok(frames(pcap)?.into_iter().next())
}

/// The UDP payload of every record in `pcap`, in capture order — for a row
/// whose datagrams must be read before they can be told apart (a Kad crypt
/// envelope carries no plaintext opcode for a BPF filter to key on). Empty
/// when the file holds no records.
///
/// # Errors
/// As [`first_udp_payload`], for any record.
pub(crate) fn udp_payloads(pcap: &Path) -> Result<Vec<Vec<u8>>> {
    frames(pcap)?
        .iter()
        .map(|frame| udp_payload(frame))
        .collect()
}

/// The UDP `(source port, destination port)` of every IPv4 record in `pcap`,
/// in capture order — for a row about *which ports* a burst reached (a Probe Set),
/// which a BPF count cannot compare against another set.
///
/// # Errors
/// As [`first_udp_payload`], for any record.
pub(crate) fn udp4_ports(pcap: &Path) -> Result<Vec<(u16, u16)>> {
    frames(pcap)?
        .iter()
        .map(|frame| {
            let (ip, ihl) = ipv4_packet(frame, IPPROTO_UDP)?;
            let udp = ip.get(ihl..ihl + 4).context("UDP header is truncated")?;
            Ok((
                u16::from_be_bytes([udp[0], udp[1]]),
                u16::from_be_bytes([udp[2], udp[3]]),
            ))
        })
        .collect()
}

/// One IPv4/UDP datagram read whole, with its capture time.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Udp4Datagram {
    /// Capture time, seconds since the epoch.
    pub(crate) at: f64,
    /// The sender.
    pub(crate) source: std::net::SocketAddrV4,
    /// The receiver.
    pub(crate) destination: std::net::SocketAddrV4,
    /// The UDP payload, by the UDP length field.
    pub(crate) payload: Vec<u8>,
}

/// Every IPv4/UDP datagram in `pcap`, in capture order; records of any other
/// shape (TCP, IPv6, a fragment) are passed over — for a tap whose filter
/// takes both TCP and UDP.
///
/// # Errors
/// If the file cannot be read or is not a classic `EN10MB` pcap.
pub(crate) fn udp4_datagrams(pcap: &Path) -> Result<Vec<Udp4Datagram>> {
    Ok(records(pcap)?
        .iter()
        .filter_map(|record| udp4_datagram(record).ok())
        .collect())
}

fn udp4_datagram(record: &Record) -> Result<Udp4Datagram> {
    let (ip, ihl) = ipv4_packet(&record.frame, IPPROTO_UDP)?;
    let address = |at: usize| std::net::Ipv4Addr::new(ip[at], ip[at + 1], ip[at + 2], ip[at + 3]);
    let udp = ip.get(ihl..).context("UDP header is missing")?;
    let word = |at: usize| {
        udp.get(at..at + 2)
            .map(|it| u16::from_be_bytes([it[0], it[1]]))
            .context("UDP header is truncated")
    };
    let payload_len = usize::from(word(4)?)
        .checked_sub(UDP_HEADER_LEN)
        .context("UDP length field is shorter than its own header")?;
    Ok(Udp4Datagram {
        at: record.at,
        source: std::net::SocketAddrV4::new(address(12), word(0)?),
        destination: std::net::SocketAddrV4::new(address(16), word(2)?),
        payload: udp
            .get(UDP_HEADER_LEN..UDP_HEADER_LEN + payload_len)
            .context("the UDP payload runs past the captured frame")?
            .to_vec(),
    })
}

/// One IPv6/UDP datagram read whole: both endpoints and the payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Udp6Datagram {
    /// The IPv6 header's source address.
    pub(crate) source: std::net::Ipv6Addr,
    /// The IPv6 header's destination address.
    pub(crate) destination: std::net::Ipv6Addr,
    /// The UDP source port.
    pub(crate) source_port: u16,
    /// The UDP destination port.
    pub(crate) destination_port: u16,
    /// The UDP payload, by the UDP length field.
    pub(crate) payload: Vec<u8>,
}

/// Every record in `pcap` as an IPv6/UDP datagram — for a row about the
/// *addresses* a datagram carried (a PCP request's source against the client
/// address its payload names), which a BPF count cannot compare.
///
/// # Errors
/// As [`first_udp_payload`], for an Ethernet/IPv6/UDP record with no
/// extension headers.
pub(crate) fn udp6_datagrams(pcap: &Path) -> Result<Vec<Udp6Datagram>> {
    frames(pcap)?
        .iter()
        .map(|frame| udp6_datagram(frame))
        .collect()
}

fn udp6_datagram(frame: &[u8]) -> Result<Udp6Datagram> {
    let ethertype = frame
        .get(12..14)
        .map(|it| u16::from_be_bytes([it[0], it[1]]))
        .context("Ethernet header is truncated")?;
    if ethertype != ETHERTYPE_IPV6 {
        bail!("ethertype {ethertype:#06x} is not IPv6");
    }
    let ip = &frame[ETHERNET_HEADER_LEN..];
    let header = ip
        .get(..IPV6_HEADER_LEN)
        .context("IPv6 header is truncated")?;
    if header[6] != IPPROTO_UDP {
        bail!(
            "next header {} is not UDP (extension headers are refused)",
            header[6]
        );
    }
    let address = |at: usize| {
        let mut octets = [0_u8; 16];
        octets.copy_from_slice(&header[at..at + 16]);
        std::net::Ipv6Addr::from(octets)
    };
    let udp = &ip[IPV6_HEADER_LEN..];
    let word = |at: usize| {
        udp.get(at..at + 2)
            .map(|it| u16::from_be_bytes([it[0], it[1]]))
            .context("UDP header is truncated")
    };
    let payload_len = usize::from(word(4)?)
        .checked_sub(UDP_HEADER_LEN)
        .context("UDP length field is shorter than its own header")?;
    Ok(Udp6Datagram {
        source: address(8),
        destination: address(24),
        source_port: word(0)?,
        destination_port: word(2)?,
        payload: udp
            .get(UDP_HEADER_LEN..UDP_HEADER_LEN + payload_len)
            .context("the UDP payload runs past the captured frame")?
            .to_vec(),
    })
}

/// Every record's whole captured frame, refusing a truncated one.
fn frames(pcap: &Path) -> Result<Vec<Vec<u8>>> {
    Ok(read_records(pcap, Tail::Refuse)?
        .into_iter()
        .map(|record| record.frame)
        .collect())
}

/// One pcap record: when the tap saw it, and its whole captured frame.
pub(crate) struct Record {
    /// Capture time, seconds since the epoch.
    pub(crate) at: f64,
    /// The Ethernet frame.
    pub(crate) frame: Vec<u8>,
}

/// Every whole record in `pcap`, timestamped — including a pcap the tap is
/// still writing, whose last record may be half on disk: that record is left
/// for the next read.
///
/// # Errors
/// If the file cannot be read, is not a classic `EN10MB` pcap, or holds a
/// record snapped short of its frame.
pub(crate) fn records(pcap: &Path) -> Result<Vec<Record>> {
    read_records(pcap, Tail::Wait)
}

/// What a record cut short by the end of the file means.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tail {
    /// The file is finished: a short record is an error.
    Refuse,
    /// The tap is still writing: a short record is not there yet.
    Wait,
}

fn read_records(pcap: &Path, tail: Tail) -> Result<Vec<Record>> {
    let bytes = std::fs::read(pcap).with_context(|| format!("read {}", pcap.display()))?;
    parse_records(&bytes, pcap, tail)
}

/// Every record in a whole pcap's `bytes` — a file's, or a `tcpdump -w -`
/// written to stdout. `pcap` names the source in errors.
fn parse_records(bytes: &[u8], pcap: &Path, tail: Tail) -> Result<Vec<Record>> {
    if bytes.len() < 24 {
        bail!("{} is shorter than a pcap global header", pcap.display());
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let swapped = magic_swapped(magic, pcap)?;
    let fraction_per_second = if matches!(magic, MAGIC_NS_LE | MAGIC_NS_BE) {
        1e9
    } else {
        1e6
    };
    let read_u32 = |chunk: &[u8]| -> u32 {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if swapped { word.swap_bytes() } else { word }
    };

    let linktype = read_u32(&bytes[20..24]);
    if linktype != LINKTYPE_EN10MB {
        bail!(
            "{} has link type {linktype}, not EN10MB — this reader decodes only the \
             sidecar's own encapsulation",
            pcap.display()
        );
    }

    // Each record: `[ts_sec 4][ts_frac 4][caplen 4][origlen 4][bytes caplen]`.
    let mut records = Vec::new();
    let mut at = 24;
    while let Some(header) = bytes.get(at..at + 16) {
        let caplen = read_u32(&header[8..12]) as usize;
        let origlen = read_u32(&header[12..16]) as usize;
        let Some(frame) = bytes.get(at + 16..at + 16 + caplen) else {
            if tail == Tail::Wait {
                break;
            }
            bail!("{}: record claims {caplen} bytes it lacks", pcap.display());
        };
        if caplen != origlen {
            bail!(
                "{}: a record is truncated ({caplen} of {origlen} bytes) — a fixture is never \
                 promoted from a partial datagram",
                pcap.display()
            );
        }
        records.push(Record {
            at: f64::from(read_u32(&header[0..4]))
                + f64::from(read_u32(&header[4..8])) / fraction_per_second,
            frame: frame.to_vec(),
        });
        at += 16 + caplen;
    }
    Ok(records)
}

/// The IPv4 packet inside one Ethernet frame, refusing a fragment, with its
/// header length and the protocol byte checked against `protocol`.
fn ipv4_packet(frame: &[u8], protocol: u8) -> Result<(&[u8], usize)> {
    let ethertype = frame
        .get(12..14)
        .map(|it| u16::from_be_bytes([it[0], it[1]]))
        .context("frame is shorter than an Ethernet header")?;
    if ethertype != ETHERTYPE_IPV4 {
        bail!("frame carries ethertype {ethertype:#06x}, not IPv4");
    }
    let ip = frame
        .get(ETHERNET_HEADER_LEN..)
        .context("frame has no IP header")?;
    let version_ihl = *ip.first().context("IP header is empty")?;
    if version_ihl >> 4 != 4 {
        bail!("not an IPv4 packet");
    }
    let ihl = usize::from(version_ihl & 0x0F) * 4;
    // A fragment carries only part of the datagram, so its payload is not the
    // body — refuse rather than promote half a publish.
    let flags_fragment = ip
        .get(6..8)
        .map(|it| u16::from_be_bytes([it[0], it[1]]))
        .context("IP header is truncated")?;
    if flags_fragment & 0x3FFF != 0 {
        bail!("the captured datagram is an IP fragment");
    }
    if ip.get(9).copied() != Some(protocol) {
        bail!("the captured packet is not IP protocol {protocol}");
    }
    Ok((ip, ihl))
}

/// The UDP payload inside one Ethernet frame.
fn udp_payload(frame: &[u8]) -> Result<Vec<u8>> {
    let (ip, ihl) = ipv4_packet(frame, IPPROTO_UDP)?;
    // The UDP length field, not the frame length: Ethernet pads short frames,
    // and the padding is not part of the datagram.
    let udp = ip
        .get(ihl..)
        .context("IP header length runs past the frame")?;
    let udp_len = udp
        .get(4..6)
        .map(|it| usize::from(u16::from_be_bytes([it[0], it[1]])))
        .context("UDP header is truncated")?;
    let payload_len = udp_len
        .checked_sub(UDP_HEADER_LEN)
        .context("UDP length field is shorter than its own header")?;
    udp.get(UDP_HEADER_LEN..UDP_HEADER_LEN + payload_len)
        .map(<[u8]>::to_vec)
        .context("the UDP payload runs past the captured frame")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PCP MAP request as `portmap-ipv6-pinhole` run `1790023348` captured it
    /// on the gateway's LAN (`tap-lan.pcap`, 22:42:41.353200), IPv6 packet
    /// verbatim behind a zeroed Ethernet header.
    #[test]
    fn a_captured_ipv6_pcp_request_reads_back_with_both_addresses() {
        let packet = "600fe60800441140\
            3fff0ed2000200000000000000000004\
            3fff0ed2000200000000000000000002\
            e71914e700449e01\
            020100000000000c3fff0ed2000200000000000000000004\
            2d8d6ac49374337eeacf2d720600000012361236\
            00000000000000000000000000000000";
        let mut frame = vec![0_u8; 12];
        frame.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        frame.extend(
            (0..packet.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&packet[at..at + 2], 16).expect("hex")),
        );
        let datagram = udp6_datagram(&frame).expect("an IPv6/UDP frame");
        assert_eq!(
            datagram.source,
            "3fff:ed2:2::4".parse::<std::net::Ipv6Addr>().unwrap()
        );
        assert_eq!(
            datagram.destination,
            "3fff:ed2:2::2".parse::<std::net::Ipv6Addr>().unwrap()
        );
        assert_eq!(
            (datagram.source_port, datagram.destination_port),
            (59161, 5351)
        );
        assert_eq!(datagram.payload.len(), 60);
        assert_eq!(&datagram.payload[8..24], &datagram.source.octets());
    }
}
