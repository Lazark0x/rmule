//! The server tap read back as eD2k frames: every TCP frame on the server's
//! links (reassembled per direction, a packed frame inflated) and every plain
//! eD2k UDP datagram, each stamped with the capture time of the segment that
//! completed it.
//!
//! Two readers need them. The leg's **timeline** (`decoded.txt`) prints one
//! line per frame — the query tree a search put on the wire, the names an
//! answer carried — which is what the search findings are read from. And the
//! leg waits on the frames a sharer sent: a sharer's files are searchable only
//! once its `OP_OFFERFILES` frames have named them all, and aMule offers at
//! most 200 files a minute (`SharedFileList.cpp:709-711`, `ED2KREPUBLISHTIME`).

use std::fmt::Write as _;
use std::io::Read as _;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;

use anyhow::{Context, Result};

use crate::flow::pcap::{self, Record};

const OP_EDONKEYPROT: u8 = 0xe3;
const OP_PACKEDPROT: u8 = 0xd4;
const OP_OFFERFILES: u8 = 0x15;
const OP_SEARCHREQUEST: u8 = 0x16;
const OP_QUERY_MORE_RESULT: u8 = 0x21;
const OP_SEARCHRESULT: u8 = 0x33;
const OP_SERVERMESSAGE: u8 = 0x38;
const OP_GLOBSEARCHREQ: u8 = 0x98;
const OP_IDCHANGE: u8 = 0x40;
/// `OP_GLOBSEARCHREQ`, `OP_GLOBSEARCHREQ2`, `OP_GLOBSEARCHREQ3`.
const GLOBAL_SEARCHES: [u8; 3] = [OP_GLOBSEARCHREQ, 0x92, 0x90];
const ETHERTYPE_IPV4: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;

/// One frame the tap saw.
struct Frame {
    at: f64,
    source: SocketAddrV4,
    destination: SocketAddrV4,
    body: Body,
}

enum Body {
    /// A TCP frame: its opcode and its payload, inflated when packed.
    Tcp { opcode: u8, payload: Vec<u8> },
    /// A plain eD2k UDP datagram.
    Udp { opcode: u8, payload: Vec<u8> },
    /// TCP bytes that do not open with a protocol byte: the rest of that
    /// direction's buffer is dropped.
    Unframed { head: Vec<u8> },
    /// A FIN or RST from the source: it closed the connection.
    Closed,
}

/// Write the tap's timeline to `out`: one line per frame, times relative to
/// the first IPv4 record.
///
/// # Errors
/// If the pcap cannot be read or `out` cannot be written.
pub(crate) fn write_timeline(pcap: &Path, out: &Path) -> Result<()> {
    let records = pcap::records(pcap)?;
    let origin = records
        .iter()
        .find(|record| Packet::parse(&record.frame).is_some())
        .map_or(0.0, |record| record.at);
    let mut text = String::new();
    for frame in frames(&records)? {
        if matches!(frame.body, Body::Closed) {
            continue;
        }
        text.push_str(&line(&frame, origin));
        text.push('\n');
    }
    std::fs::write(out, text).with_context(|| format!("write {}", out.display()))
}

/// How many files `sharer` has offered the server so far, summed over its
/// `OP_OFFERFILES` frames.
///
/// # Errors
/// If the pcap cannot be read.
pub(super) fn offered_files(pcap: &Path, sharer: Ipv4Addr) -> Result<u64> {
    Ok(offers(pcap, sharer)?.iter().map(|(_, count)| count).sum())
}

/// Every `OP_OFFERFILES` `sharer` sent the server: its capture time and the
/// file count it names, in order.
///
/// # Errors
/// If the pcap cannot be read.
pub(crate) fn offers(pcap: &Path, sharer: Ipv4Addr) -> Result<Vec<(f64, u64)>> {
    let records = pcap::records(pcap)?;
    Ok(frames(&records)?
        .iter()
        .filter(|frame| *frame.source.ip() == sharer)
        .filter_map(|frame| match &frame.body {
            Body::Tcp { opcode, payload } if *opcode == OP_OFFERFILES => payload
                .get(..4)
                .map(|count| (frame.at, u64::from(le_u32(count)))),
            _ => None,
        })
        .collect())
}

/// The server flags word of the last `OP_IDCHANGE` the server sent
/// `client`; `None` when none was seen or it carried no flags word.
///
/// # Errors
/// If the pcap cannot be read.
pub(crate) fn granted_flags(pcap: &Path, client: Ipv4Addr) -> Result<Option<u32>> {
    let records = pcap::records(pcap)?;
    Ok(frames(&records)?
        .iter()
        .filter(|frame| *frame.destination.ip() == client)
        .filter_map(|frame| match &frame.body {
            Body::Tcp { opcode, payload } if *opcode == OP_IDCHANGE => {
                payload.get(4..8).map(le_u32)
            }
            _ => None,
        })
        .next_back())
}

/// Every plain global search datagram (`0x98`, `0x92` or `0x90`) `client`
/// sent the server: its capture time and opcode, in order.
///
/// # Errors
/// If the pcap cannot be read.
pub(crate) fn global_searches(pcap: &Path, client: Ipv4Addr) -> Result<Vec<(f64, u8)>> {
    let records = pcap::records(pcap)?;
    Ok(frames(&records)?
        .iter()
        .filter(|frame| *frame.source.ip() == client)
        .filter_map(|frame| match &frame.body {
            Body::Udp { opcode, .. } if GLOBAL_SEARCHES.contains(opcode) => {
                Some((frame.at, *opcode))
            }
            _ => None,
        })
        .collect())
}

/// One client's TCP link to the server's `port`: when each search request
/// arrived, and which side closed the link first.
pub(super) struct Link {
    /// The client's end of the link.
    pub(super) client: SocketAddrV4,
    /// Arrival time of each `OP_SEARCHREQUEST`, seconds since the epoch.
    pub(super) searches: Vec<f64>,
    /// `Some(true)` when the server's FIN or RST came first, `Some(false)` when
    /// the client's did, `None` while the link is open.
    pub(super) closed_by_server: Option<bool>,
}

/// Every client link to the server's `port`, in the order each opened. A
/// client port the tap saw reused is one link per connection.
///
/// # Errors
/// If the pcap cannot be read.
pub(super) fn links(pcap: &Path, port: u16) -> Result<Vec<Link>> {
    let records = pcap::records(pcap)?;
    let capture = pcap::tcp_capture(&records)?;
    let mut opened: Vec<(f64, Link)> = capture
        .streams
        .iter()
        .filter(|stream| stream.destination.port() == port)
        .filter_map(|stream| {
            let client = v4(stream.source)?;
            let searches = stream
                .ed2k_frames()
                .iter()
                .filter(|frame| frame.opcode == OP_SEARCHREQUEST)
                .map(|frame| frame.at)
                .collect();
            Some((
                stream.opened_at(),
                Link {
                    client,
                    searches,
                    closed_by_server: None,
                },
            ))
        })
        .collect();
    opened.sort_by(|a, b| a.0.total_cmp(&b.0));
    for close in &capture.closes {
        let (client, from_client) = if close.destination.port() == port {
            (close.source, true)
        } else if close.source.port() == port {
            (close.destination, false)
        } else {
            continue;
        };
        let Some(client) = v4(client) else {
            continue;
        };
        // The connection the close ends: the latest one from that client
        // port opened before it.
        if let Some((_, link)) = opened
            .iter_mut()
            .rfind(|(at, link)| link.client == client && *at <= close.at)
            && link.closed_by_server.is_none()
        {
            link.closed_by_server = Some(!from_client);
        }
    }
    Ok(opened.into_iter().map(|(_, link)| link).collect())
}

/// Every frame of `records`, in capture order: each TCP direction reassembled
/// by the shared reader (reordered and retransmitted segments read once, a
/// connection reusing its ports read as a new stream), every FIN or RST, and
/// every plain eD2k UDP datagram. IPv4 only: the server is tapped on its IPv4
/// bench address.
fn frames(records: &[Record]) -> Result<Vec<Frame>> {
    let capture = pcap::tcp_capture(records)?;
    let mut frames = Vec::new();
    for stream in &capture.streams {
        let (Some(source), Some(destination)) = (v4(stream.source), v4(stream.destination)) else {
            continue;
        };
        for frame in stream.ed2k_frames() {
            let raw = frame.payload().to_vec();
            let payload = if frame.protocol == OP_PACKEDPROT {
                inflate(&raw).unwrap_or(raw)
            } else {
                raw
            };
            frames.push(Frame {
                at: frame.at,
                source,
                destination,
                body: Body::Tcp {
                    opcode: frame.opcode,
                    payload,
                },
            });
        }
        if let Some((at, tail)) = stream.unframed_tail() {
            frames.push(Frame {
                at,
                source,
                destination,
                body: Body::Unframed {
                    head: tail[..8.min(tail.len())].to_vec(),
                },
            });
        }
    }
    for close in &capture.closes {
        let (Some(source), Some(destination)) = (v4(close.source), v4(close.destination)) else {
            continue;
        };
        frames.push(Frame {
            at: close.at,
            source,
            destination,
            body: Body::Closed,
        });
    }
    for record in records {
        let Some(packet) = Packet::parse(&record.frame) else {
            continue;
        };
        if packet.protocol != IPPROTO_UDP {
            continue;
        }
        let Some((source_port, destination_port, data)) = udp_datagram(packet.payload) else {
            continue;
        };
        if data.len() > 1 && data[0] == OP_EDONKEYPROT {
            frames.push(Frame {
                at: record.at,
                source: SocketAddrV4::new(packet.source, source_port),
                destination: SocketAddrV4::new(packet.destination, destination_port),
                body: Body::Udp {
                    opcode: data[1],
                    payload: data[2..].to_vec(),
                },
            });
        }
    }
    // Stable: frames one segment completed keep their stream order.
    frames.sort_by(|a, b| a.at.total_cmp(&b.at));
    Ok(frames)
}

fn v4(address: SocketAddr) -> Option<SocketAddrV4> {
    match address {
        SocketAddr::V4(address) => Some(address),
        SocketAddr::V6(_) => None,
    }
}

fn line(frame: &Frame, origin: f64) -> String {
    let mut line = format!("{:8.3} ", frame.at - origin);
    match &frame.body {
        Body::Tcp { opcode, payload } => {
            let _ = write!(
                line,
                "{}>{} op=0x{opcode:02x} len={}",
                frame.source,
                frame.destination,
                payload.len()
            );
            match *opcode {
                OP_SEARCHREQUEST => match tree(payload, 0) {
                    Ok((text, _)) => {
                        let _ = write!(line, " SEARCH {text}");
                    }
                    Err(why) => {
                        let _ = write!(line, " SEARCH? {} {why}", hex(payload));
                    }
                },
                OP_SEARCHRESULT => {
                    let (names, tail) = result_names(payload);
                    let shown: Vec<String> = names
                        .iter()
                        .take(6)
                        .map(|name| name.as_deref().map_or("None".to_owned(), py_repr))
                        .collect();
                    let _ = write!(
                        line,
                        " RESULTS n={} {tail} names=[{}]",
                        names.len(),
                        shown.join(", ")
                    );
                }
                OP_SERVERMESSAGE => {
                    let text = String::from_utf8_lossy(payload.get(2..).unwrap_or_default());
                    let _ = write!(line, " MSG {}", py_repr(&text));
                }
                OP_QUERY_MORE_RESULT => line.push_str(" QUERY_MORE_RESULT"),
                _ => {}
            }
        }
        Body::Udp { opcode, payload } => {
            let _ = write!(
                line,
                "UDP {}>{} op=0x{opcode:02x} len={}",
                frame.source,
                frame.destination,
                payload.len()
            );
            if *opcode == OP_GLOBSEARCHREQ
                && let Ok((text, _)) = tree(payload, 0)
            {
                let _ = write!(line, " GLOBSEARCH {text}");
            }
        }
        Body::Closed => {
            let _ = write!(line, "{}>{} closed", frame.source, frame.destination);
        }
        Body::Unframed { head } => {
            let _ = write!(
                line,
                "{}>{} unframed {}",
                frame.source,
                frame.destination,
                hex(head)
            );
        }
    }
    line
}

/// A search expression rendered as its tree: `AND('a','b')`, a quoted word, a
/// meta or numeric term with its tag bytes.
fn tree(bytes: &[u8], at: usize) -> Result<(String, usize), &'static str> {
    let kind = *bytes.get(at).ok_or("truncated")?;
    let at = at + 1;
    match kind {
        0 => {
            let operator = *bytes.get(at).ok_or("truncated")?;
            let (left, at) = tree(bytes, at + 1)?;
            let (right, at) = tree(bytes, at)?;
            let name = match operator {
                0 => "AND".to_owned(),
                1 => "OR".to_owned(),
                2 => "NOT".to_owned(),
                other => other.to_string(),
            };
            Ok((format!("{name}({left},{right})"), at))
        }
        1 => {
            let length = usize::from(u16_at(bytes, at)?);
            let word = lossy(slice(bytes, at + 2, length));
            Ok((py_repr(&word), at + 2 + length))
        }
        2 => {
            let length = usize::from(u16_at(bytes, at)?);
            let value = lossy(slice(bytes, at + 2, length));
            let at = at + 2 + length;
            let tag_length = usize::from(u16_at(bytes, at)?);
            let tag = slice(bytes, at + 2, tag_length);
            Ok((
                format!("meta[{}]={}", hex(tag), py_repr(&value)),
                at + 2 + tag_length,
            ))
        }
        3 | 8 => {
            let width = if kind == 3 { 4 } else { 8 };
            let value = slice(bytes, at, width)
                .iter()
                .rev()
                .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
            let at = at + width;
            let operator = *bytes.get(at).ok_or("truncated")?;
            let tag_length = usize::from(u16_at(bytes, at + 1)?);
            let tag = slice(bytes, at + 3, tag_length);
            Ok((
                format!("num[{}] op{operator} {value}", hex(tag)),
                at + 3 + tag_length,
            ))
        }
        other => Ok((format!("?{other}"), bytes.len())),
    }
}

/// The file name of each row of an `OP_SEARCHRESULT`, and what follows the
/// rows (`trailing=<hex>`, or why the walk stopped).
fn result_names(payload: &[u8]) -> (Vec<Option<String>>, String) {
    let mut names = Vec::new();
    match walk_rows(payload, &mut names) {
        Ok(tail) => (names, tail),
        Err(why) => (Vec::new(), format!("err {why}")),
    }
}

fn walk_rows(payload: &[u8], names: &mut Vec<Option<String>>) -> Result<String, &'static str> {
    let count = le_u32(payload.get(..4).ok_or("truncated count")?);
    let mut at = 4;
    for _ in 0..count {
        // Hash, client id, port.
        at += 22;
        let tags = le_u32(payload.get(at..at + 4).ok_or("truncated tag count")?);
        at += 4;
        let mut name = None;
        for _ in 0..tags {
            let mut kind = *payload.get(at).ok_or("truncated tag")?;
            at += 1;
            let tag_name = if kind & 0x80 != 0 {
                let id = *payload.get(at).ok_or("truncated tag")?;
                at += 1;
                kind &= 0x7f;
                vec![id]
            } else {
                let length = usize::from(u16_at(payload, at)?);
                at += 2;
                let tag_name = slice(payload, at, length).to_vec();
                at += length;
                tag_name
            };
            let width = match kind {
                2 => {
                    let length = usize::from(u16_at(payload, at)?);
                    at += 2;
                    length
                }
                0x11..=0x20 => usize::from(kind - 0x10),
                3 | 4 => 4,
                8 => 2,
                5 | 9 => 1,
                0x0b => 8,
                1 => 16,
                7 => {
                    let length = le_u32(payload.get(at..at + 4).ok_or("truncated blob")?) as usize;
                    at += 4 + length;
                    0
                }
                other => return Ok(format!("tagtype?{other:#x}")),
            };
            let value = if kind == 7 {
                &[][..]
            } else {
                slice(payload, at, width)
            };
            at += width;
            if tag_name == [0x01] {
                name = Some(lossy(value));
            }
        }
        names.push(name);
    }
    Ok(format!(
        "trailing={}",
        hex(payload.get(at..).unwrap_or_default())
    ))
}

/// An IPv4 packet inside one Ethernet frame.
struct Packet<'a> {
    protocol: u8,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    payload: &'a [u8],
}

impl<'a> Packet<'a> {
    fn parse(frame: &'a [u8]) -> Option<Self> {
        let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
        if ethertype != ETHERTYPE_IPV4 {
            return None;
        }
        let ip = frame.get(14..)?;
        let header_length = usize::from(ip.first()? & 0x0f) * 4;
        let total = usize::from(u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]));
        let address = |at: usize| -> Option<Ipv4Addr> {
            let octets: [u8; 4] = ip.get(at..at + 4)?.try_into().ok()?;
            Some(Ipv4Addr::from(octets))
        };
        Some(Self {
            protocol: *ip.get(9)?,
            source: address(12)?,
            destination: address(16)?,
            payload: ip.get(header_length..total.min(ip.len()))?,
        })
    }
}

fn udp_datagram(udp: &[u8]) -> Option<(u16, u16, &[u8])> {
    Some((
        u16::from_be_bytes([*udp.first()?, *udp.get(1)?]),
        u16::from_be_bytes([*udp.get(2)?, *udp.get(3)?]),
        udp.get(8..)?,
    ))
}

fn inflate(packed: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(packed)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, &'static str> {
    bytes
        .get(at..at + 2)
        .map(|it| u16::from_le_bytes([it[0], it[1]]))
        .ok_or("truncated length")
}

/// Up to `length` bytes from `at`, fewer where the payload ends first.
fn slice(bytes: &[u8], at: usize, length: usize) -> &[u8] {
    let start = at.min(bytes.len());
    &bytes[start..at.saturating_add(length).min(bytes.len())]
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// A string quoted the way the timeline has always quoted it: single quotes
/// unless the text holds a single quote and no double one, control characters
/// escaped.
fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ if ch == quote => {
                out.push('\\');
                out.push(ch);
            }
            '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{a0}' | '\u{ad}' => {
                let _ = write!(out, "\\x{:02x}", u32::from(ch));
            }
            _ => out.push(ch),
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
mod tests;
