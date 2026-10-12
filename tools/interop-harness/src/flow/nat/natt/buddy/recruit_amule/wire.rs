//! What `natt-buddy-recruit-amule` counts off its two taps.
//!
//! **aMule's own attachment** holds every counterparty statement the flow
//! makes — the `0x5A`, the hello answer, the `OP_BUDDYPONG`, the relayed
//! `OP_CALLBACK` — and the target's half of each exchange as it arrived,
//! after translation. The **target gateway's WAN** holds the one act aMule
//! cannot see: the dial-back toward the walker the relay named.
//!
//! A peer-TCP opcode is read off the link's reassembled eD2k frames under
//! either protocol byte: a frame need not open its segment, and an eMule
//! extension the buddy rendezvous once counted under `0xE3` alone read zero
//! while it sat on the pcap (run `1790068463`).

use std::path::Path;

use anyhow::Result;

use crate::flow::bench::Bench;
use crate::flow::nat::natt::verdict::WireRow;
use crate::flow::nat::natt::{BODY_CLIENT_UDP_PORT, BODY_PEER_TCP_PORT};
use crate::flow::pcap::{Ed2kFrame, TcpStream, tcp_streams};
use crate::flow::peer::udp_reask::tap::OP_HELLO;
use crate::flow::taps::PerAttachmentTaps;
use crate::flow::wire_filter::{OP_EDONKEYPROT, OP_EMULEPROT, WireFilter};

/// The attachment name both taps count their evidence on.
pub(super) const WAN: &str = "wan";

/// Every Kad datagram the target's gateway sent aMule — liveness, and the
/// denominator a missing `0x51` is read against.
pub(super) const KAD_FROM_TARGET: &str = "target-kad-datagrams-to-amule";
/// The target's FINDBUDDY recruit, arriving at aMule.
pub(super) const FINDBUDDY_REQ: &str = "target-findbuddy-req-0x51";
/// aMule's accept.
pub(super) const FINDBUDDY_RES: &str = "amule-findbuddy-res-0x5a";
/// The target's TCP dial to aMule's eD2k port.
pub(super) const BUDDY_SYN: &str = "target-dial-syn-to-amule";
/// aMule's `OP_HELLOANSWER` to the target's gateway.
pub(super) const HELLO_ANSWER: &str = "amule-hello-answer-0x4c";
/// The target's `OP_KAD_FWTCPCHECK_ACK` — a firewall-check dial-back of its
/// own, the one other road a dial to aMule's eD2k port can be on.
pub(super) const FWCHECK_ACK: &str = "target-fwtcpcheck-ack-0xa8";
/// The keepalive and aMule's answer, which it gives only `GetBuddy()`.
pub(super) const BUDDY_PING: &str = "target-buddy-ping-0x9f";
pub(super) const BUDDY_PONG: &str = "amule-buddy-pong-0xa0";
/// The walker's callback request and aMule's relay of it onto the link.
pub(super) const CALLBACK_REQ: &str = "walker-callback-req-0x52";
pub(super) const CALLBACK: &str = "amule-callback-0x99";
/// The target's dial-back toward the walker, on its gateway's WAN.
pub(super) const DIAL_BACK_SYN: &str = "target-dial-back-syn-to-walker";

/// The target's dials to aMule's eD2k port, lifted beside aMule's pcap.
const TARGET_DIALS_PCAP: &str = "target-dials-to-amule.pcap";

/// The three addresses the rows are cut between.
pub(super) struct Hosts<'a> {
    pub(super) amule: &'a str,
    /// The target's gateway WAN address — the target, as the WAN sees it.
    pub(super) gateway: &'a str,
    pub(super) walker: &'a str,
}

/// Which tap answers a row.
#[derive(Clone, Copy)]
enum Tap {
    Amule,
    GatewayWan,
}

/// The rows, each on the one tap that answers it.
fn rows(hosts: &Hosts<'_>) -> Vec<(&'static str, Tap, WireFilter)> {
    let Hosts {
        amule,
        gateway,
        walker,
    } = hosts;
    let (kad, ed2k) = (BODY_CLIENT_UDP_PORT, BODY_PEER_TCP_PORT);
    let kad_opcode = |from: &str, to: &str, opcode: u8| {
        WireFilter::from(format!(
            "udp and src host {from} and dst host {to} and udp[8] = 0xe4 and udp[9] = {opcode:#04x}"
        ))
    };
    let to_amule = format!("src host {gateway} and dst host {amule} and dst port {ed2k}");
    let from_amule = format!("src host {amule} and src port {ed2k} and dst host {gateway}");
    let frames = |link: &str, opcode: u8| {
        WireFilter::ed2k(link.to_owned(), &[OP_EDONKEYPROT, OP_EMULEPROT], opcode)
    };
    let syn = |from: &str, to: &str, port: u16| {
        WireFilter::from(format!(
            "tcp and src host {from} and dst host {to} and dst port {port} \
             and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0"
        ))
    };
    vec![
        (
            KAD_FROM_TARGET,
            Tap::Amule,
            format!("udp and src host {gateway} and dst host {amule} and dst port {kad}").into(),
        ),
        (FINDBUDDY_REQ, Tap::Amule, kad_opcode(gateway, amule, 0x51)),
        (FINDBUDDY_RES, Tap::Amule, kad_opcode(amule, gateway, 0x5a)),
        (BUDDY_SYN, Tap::Amule, syn(gateway, amule, ed2k)),
        (HELLO_ANSWER, Tap::Amule, frames(&from_amule, 0x4c)),
        (FWCHECK_ACK, Tap::Amule, frames(&to_amule, 0xa8)),
        (BUDDY_PING, Tap::Amule, frames(&to_amule, 0x9f)),
        (BUDDY_PONG, Tap::Amule, frames(&from_amule, 0xa0)),
        (CALLBACK_REQ, Tap::Amule, kad_opcode(walker, amule, 0x52)),
        (CALLBACK, Tap::Amule, frames(&from_amule, 0x99)),
        (
            DIAL_BACK_SYN,
            Tap::GatewayWan,
            syn(gateway, walker, super::WALKER_TCP_PORT),
        ),
    ]
}

/// Count every row on its own tap's evidence attachment.
///
/// # Errors
/// If a tap cannot be read back.
pub(super) fn count(
    bench: &Bench,
    amule: &PerAttachmentTaps,
    gateway: &PerAttachmentTaps,
    hosts: &Hosts<'_>,
) -> Result<Vec<WireRow>> {
    rows(hosts)
        .into_iter()
        .map(|(name, tap, filter)| {
            let taps = match tap {
                Tap::Amule => amule,
                Tap::GatewayWan => gateway,
            };
            let packets = taps
                .rows(&bench.docker, &filter)?
                .into_iter()
                .filter(|row| row.attachment == WAN)
                .map(|row| row.packets)
                .sum();
            println!("natt buddy-recruit-amule row {name} = {packets}");
            Ok(WireRow {
                name: name.to_owned(),
                bpf: filter.to_string(),
                packets,
            })
        })
        .collect()
}

/// The client id every plaintext `OP_HELLO` the target sent aMule's eD2k port
/// names, in stream order — the id aMule reads as the target's
/// (`BaseClient.cpp:678`): its buddy dial and any firewall-check dial-back.
/// The segments are lifted to `amule_dir`, so the read stays re-runnable from
/// the run's archive.
///
/// # Errors
/// If the tap cannot be lifted or the lifted pcap read back.
pub(super) fn target_hello_ids(
    bench: &Bench,
    amule: &PerAttachmentTaps,
    hosts: &Hosts<'_>,
    amule_dir: &Path,
) -> Result<Vec<u32>> {
    amule.lift(
        &bench.docker,
        WAN,
        &format!(
            "tcp and src host {} and dst host {} and dst port {BODY_PEER_TCP_PORT}",
            hosts.gateway, hosts.amule
        ),
        TARGET_DIALS_PCAP,
    )?;
    let ids = tcp_streams(&amule_dir.join(TARGET_DIALS_PCAP))?
        .iter()
        .flat_map(TcpStream::ed2k_frames)
        .filter_map(|frame| hello_client_id(&frame))
        .collect::<Vec<_>>();
    println!("natt buddy-recruit-amule target hello ids = {ids:?}");
    Ok(ids)
}

/// An `OP_HELLO`'s client id: the `u32` after the frame header, the
/// hash-size byte (`16`) and the user hash (`BaseClient.cpp:738`, `:1025-1026`).
fn hello_client_id(frame: &Ed2kFrame) -> Option<u32> {
    if frame.protocol != OP_EDONKEYPROT || frame.opcode != OP_HELLO {
        return None;
    }
    match frame.bytes.get(6..6 + 1 + 16 + 4)? {
        [16, .., a, b, c, d] => Some(u32::from_le_bytes([*a, *b, *c, *d])),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use rmule_peer::{Hello, HelloAdvert, PeerHandshakeContext, PeerHelloBody};
    use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, UserHash};

    use super::*;

    /// The id read off an `OP_HELLO` frame is the one rmule's encoder wrote,
    /// whatever the tags after it.
    #[test]
    fn a_hello_frames_client_id_is_read_after_the_hash() {
        let ctx = PeerHandshakeContext {
            identity: ClientIdentity::new(
                UserHash::from_bytes([0x8E; 16]),
                Ed2kText::from_utf8("rmule-natt"),
                4662,
                0x3C,
            ),
            client_id: ClientId::from_u32(1),
            ed2k_client_id: ClientId::from_u32(1),
            public_ip: None,
            connected_server: None,
        };
        let bytes = Hello::new(PeerHelloBody::from_handshake_context(
            &ctx,
            &HelloAdvert::default(),
        ))
        .encode_packet()
        .encode();
        let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 4662));
        let frame = |bytes: Vec<u8>| Ed2kFrame {
            at: 0.0,
            source: endpoint,
            destination: endpoint,
            protocol: bytes[0],
            opcode: bytes[5],
            bytes,
        };
        assert_eq!(hello_client_id(&frame(bytes.clone())), Some(1));

        let mut answer = bytes;
        answer[5] = 0x4C;
        assert_eq!(hello_client_id(&frame(answer)), None, "a hello answer");
    }
}
