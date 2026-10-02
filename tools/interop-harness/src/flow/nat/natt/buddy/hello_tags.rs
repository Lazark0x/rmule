//! The firewalled target's own hello, read off the Tunnel: the
//! one hello in this topology that a node holding a buddy link sends.
//!
//! The target recruits the buddy and holds the link before the requester is
//! told anything (the Readiness Gate), and the Tunnel the punch raises enters
//! both serve pipelines — the requester dials, so its `OP_HELLO` goes first and
//! the target's `OP_HELLOANSWER` carries the per-accept adverts, which name the
//! buddy while the target is firewalled behind the held link: `CT_EMULE_BUDDYIP`
//! `0xFC` and `CT_EMULE_BUDDYUDP` `0xFD` as aMule writes them
//! (`BaseClient.cpp:1484-1495`), and `CT_EMULE_SERVINGBUDDYIPV6` `0xA0` only for
//! a buddy that claimed an IPv6 — which this IPv4 mesh's buddy never does, so
//! its absence is part of what the row asserts.
//!
//! The requester's own hello names no buddy: it runs no Kad and holds none.
//!
//! The bytes are the uTP payload of the `0xB2 0x00` frames that reached the
//! requester's LAN — after both translations — reassembled by sequence number.
//! This topology arms no peer obfuscation, so the stream is plaintext eD2k.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use rmule_primitives::{Tag, TagValue};

use crate::flow::bench::Bench;
use crate::flow::nat::claims::{Claim, Evidence};
use crate::flow::taps::PerAttachmentTaps;

/// The lifted pcap's file name in the requester's leg directory.
const LIFTED: &str = "target-hello-over-tunnel.pcap";

const OP_EDONKEYPROT: u8 = 0xE3;
const OP_HELLO: u8 = 0x01;
const OP_HELLOANSWER: u8 = 0x4C;
const CT_EMULE_BUDDYIP: u8 = 0xFC;
const CT_EMULE_BUDDYUDP: u8 = 0xFD;
const CT_EMULE_SERVINGBUDDYIPV6: u8 = 0xA0;

/// The three buddy tags of one hello, as the wire carried them.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct BuddyTags {
    /// `CT_EMULE_BUDDYIP`'s four value bytes, in wire order.
    ip: Option<[u8; 4]>,
    /// `CT_EMULE_BUDDYUDP`'s `uint32`.
    udp: Option<u32>,
    /// Whether `CT_EMULE_SERVINGBUDDYIPV6` rode at all.
    ipv6: bool,
}

/// Lift the Tunnel frames that reached the requester off its gateway's LAN
/// tap and read the target's hello out of them — `None` when no hello-type
/// frame could be found (no Tunnel, or a stream this reader cannot walk).
///
/// # Errors
/// If the tap cannot be lifted or the lifted pcap read back.
pub(super) fn lift(
    bench: &Bench,
    requester_gateway: &PerAttachmentTaps,
    requester_lan: &str,
    requester_dir: &Path,
) -> Result<Option<BuddyTags>> {
    requester_gateway.lift(
        &bench.docker,
        "lan",
        &format!("udp and dst host {requester_lan} and udp[8] = 0xb2 and udp[9] = 0x00"),
        LIFTED,
    )?;
    let datagrams = crate::flow::pcap::udp_payloads(&requester_dir.join(LIFTED))?;
    Ok(first_hello_buddy_tags(&utp_stream(&datagrams)))
}

/// The claim, for the flow that reached the Readiness Gate.
pub(super) fn claim(read: Option<&BuddyTags>, buddy_v4: &str, buddy_udp_port: u16) -> Claim {
    let octets = buddy_v4
        .parse::<std::net::Ipv4Addr>()
        .map(|ip| ip.octets())
        .ok();
    let named = read.is_some_and(|tags| {
        tags.ip.is_some() && tags.ip == octets && tags.udp == Some(u32::from(buddy_udp_port))
    });
    // Measured held on `natt-buddy-rendezvous-cone` run `1790229931`.
    Claim::about(
        "the-firewalled-targets-hello-named-its-buddy",
        named && read.is_some_and(|tags| !tags.ipv6),
        Evidence::RmuleOnly,
        match read {
            None => "no hello-type frame found in the target's Tunnel stream on the \
                     requester's LAN tap"
                .to_owned(),
            Some(tags) => format!(
                "the target's hello over the Tunnel carried CT_EMULE_BUDDYIP {:?} and \
                 CT_EMULE_BUDDYUDP {:?} against the buddy's {buddy_v4}:{buddy_udp_port}, and \
                 CT_EMULE_SERVINGBUDDYIPV6 {} — this IPv4 mesh's buddy claims no IPv6, so \
                 the partner tag's absence is the gate working, not a gap.",
                tags.ip,
                tags.udp,
                if tags.ipv6 { "present" } else { "absent" },
            ),
        },
    )
}

/// The in-order payload of the `ST_DATA` packets among `datagrams` (each a
/// whole `0xB2 0x00` frame), one copy per sequence number, in BEP-29 order
/// counted from the first one seen.
fn utp_stream(datagrams: &[Vec<u8>]) -> Vec<u8> {
    const ST_DATA: u8 = 0;
    let mut first = None;
    let mut ordered = BTreeMap::new();
    for datagram in datagrams {
        let Some(packet) = datagram.get(2..) else {
            continue;
        };
        let Some((seq, payload)) = utp_data(packet) else {
            continue;
        };
        if packet[0] >> 4 != ST_DATA || payload.is_empty() {
            continue;
        }
        let origin = *first.get_or_insert(seq);
        ordered.entry(seq.wrapping_sub(origin)).or_insert(payload);
    }
    ordered.into_values().flatten().copied().collect()
}

/// A BEP-29 packet's `seq_nr` and payload, past the 20-byte header and its
/// extension chain.
fn utp_data(packet: &[u8]) -> Option<(u16, &[u8])> {
    let seq = u16::from_be_bytes([*packet.get(16)?, *packet.get(17)?]);
    let mut extension = *packet.get(1)?;
    let mut offset = 20;
    while extension != 0 {
        extension = *packet.get(offset)?;
        offset += 2 + usize::from(*packet.get(offset + 1)?);
    }
    Some((seq, packet.get(offset..)?))
}

/// The buddy tags of the first `OP_HELLO` / `OP_HELLOANSWER` in `stream`.
fn first_hello_buddy_tags(stream: &[u8]) -> Option<BuddyTags> {
    let mut offset = 0;
    while let Some(header) = stream.get(offset..offset + 6) {
        let length = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
        let body = stream.get(offset + 6..offset + 5 + length)?;
        match (header[0], header[5]) {
            // `OP_HELLO` leads with the hash-size byte; the answer does not.
            (OP_EDONKEYPROT, OP_HELLO) => return hello_buddy_tags(body.get(1..)?),
            (OP_EDONKEYPROT, OP_HELLOANSWER) => return hello_buddy_tags(body),
            _ => offset += 5 + length,
        }
    }
    None
}

/// `<hash 16><id 4><port 2><count 4><tags>` — the buddy tags among them.
fn hello_buddy_tags(body: &[u8]) -> Option<BuddyTags> {
    let count = u32::from_le_bytes(body.get(22..26)?.try_into().ok()?);
    let mut offset = 26;
    let mut read = BuddyTags::default();
    for _ in 0..count {
        let (tag, used) = Tag::decode_prefix(body.get(offset..)?).ok()?;
        offset += used;
        match (tag.name().id(), tag.value()) {
            (Some(CT_EMULE_BUDDYIP), TagValue::U32(value)) => read.ip = Some(value.to_le_bytes()),
            (Some(CT_EMULE_BUDDYUDP), TagValue::U32(value)) => read.udp = Some(*value),
            (Some(CT_EMULE_SERVINGBUDDYIPV6), _) => read.ipv6 = true,
            _ => {}
        }
    }
    Some(read)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `0xB2 0x00` frame around one BEP-29 packet of `kind`, with one
    /// selective-ack extension in front of the payload.
    fn frame(kind: u8, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0xB2, 0x00, kind << 4 | 1, 1];
        out.extend_from_slice(&[0; 14]);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&[0, 4, 0xFF, 0xFF, 0xFF, 0xFF]);
        out.extend_from_slice(payload);
        out
    }

    /// A hello answer naming `45.55.200.2:4672`, split across two packets.
    fn answer() -> Vec<u8> {
        let tag = |id: u8, value: u32| {
            Tag::new(
                rmule_primitives::TagName::length_prefixed_id(id),
                TagValue::U32(value),
            )
            .encode()
        };
        let mut body = vec![OP_HELLOANSWER];
        body.extend_from_slice(&[0x42; 16]);
        body.extend_from_slice(&[0; 6]);
        body.extend_from_slice(&2u32.to_le_bytes());
        body.extend(tag(CT_EMULE_BUDDYIP, u32::from_le_bytes([45, 55, 200, 2])));
        body.extend(tag(CT_EMULE_BUDDYUDP, 4672));
        body.extend_from_slice(&[0; 6]);
        let mut frame = vec![OP_EDONKEYPROT];
        frame.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        frame.extend(body);
        frame
    }

    /// Out of order, retransmitted and interleaved with an `ST_STATE`, the
    /// stream still reassembles to the one answer — and the claim reads it.
    #[test]
    fn a_reordered_retransmitted_answer_names_the_buddy() {
        let bytes = answer();
        let (head, tail) = bytes.split_at(20);
        let datagrams = [
            frame(0, 0xFFFF, head),
            frame(2, 0x0000, &[]),
            frame(0, 0x0000, tail),
            frame(0, 0xFFFF, head),
        ];
        let read = first_hello_buddy_tags(&utp_stream(&datagrams));
        assert_eq!(
            read,
            Some(BuddyTags {
                ip: Some([45, 55, 200, 2]),
                udp: Some(4672),
                ipv6: false,
            })
        );
        assert_eq!(claim(read.as_ref(), "45.55.200.2", 4672).outcome, "held");
        assert_ne!(claim(read.as_ref(), "45.55.200.9", 4672).outcome, "held");
        assert_ne!(claim(None, "45.55.200.2", 4672).outcome, "held");
    }
}
