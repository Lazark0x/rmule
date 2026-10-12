//! The claims over hand-laid frames and datagrams: the run the flow exists
//! for, a dial at the sharer's old inbound endpoint, an early ping, a ping
//! nobody answers, and a server link no frame can be read on.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use super::{ANSWERED, Addresses, NO_SECOND_CALLBACK, Observed, PINGED, SX_ANSWERED, claims};
use crate::flow::nat::claims::{Claim, label};
use crate::flow::pcap::{Ed2kFrame, TcpOpen, Udp4Datagram};

const RMULE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 70);
const SHARER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 31);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 200), 4661);
const LISTENER_PORT: u16 = 4662;
const LOW_ID: u32 = 5;

fn addresses() -> Addresses {
    Addresses {
        rmule: RMULE,
        rmule_port: LISTENER_PORT,
        sharer: SHARER,
        server: SERVER,
        ed2ksrv_pin: "test".to_owned(),
    }
}

fn at(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(ip, port))
}

fn server() -> SocketAddr {
    SocketAddr::V4(SERVER)
}

fn listener() -> SocketAddr {
    at(RMULE, LISTENER_PORT)
}

fn frame(
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

fn open(when: f64, source: SocketAddr, destination: SocketAddr) -> TcpOpen {
    TcpOpen {
        at: when,
        source,
        destination,
    }
}

fn callback_request(when: f64) -> Ed2kFrame {
    frame(
        when,
        at(RMULE, 50_000),
        server(),
        (0xE3, 0x1C),
        &LOW_ID.to_le_bytes(),
    )
}

fn relay(when: f64) -> Ed2kFrame {
    let mut body = RMULE.octets().to_vec();
    body.extend_from_slice(&LISTENER_PORT.to_le_bytes());
    frame(when, server(), at(SHARER, 41_000), (0xE3, 0x35), &body)
}

fn rank(when: f64, from: u16, rank: u16) -> Ed2kFrame {
    frame(
        when,
        at(SHARER, from),
        listener(),
        (0xC5, 0x60),
        &rank.to_le_bytes(),
    )
}

/// rmule's client-UDP port.
const RMULE_UDP: u16 = 51_152;
/// The sharer's advertised client-UDP port.
const SHARER_UDP: u16 = 4672;

fn datagram(
    when: f64,
    source: SocketAddrV4,
    destination: SocketAddrV4,
    body: &[u8],
) -> Udp4Datagram {
    Udp4Datagram {
        at: when,
        source,
        destination,
        payload: body.to_vec(),
    }
}

/// rmule's `OP_REASKFILEPING` to the sharer's client-UDP endpoint.
fn ping(when: f64) -> Udp4Datagram {
    let mut body = vec![0xC5, 0x90];
    body.extend_from_slice(&[0xAB; 16]);
    datagram(
        when,
        SocketAddrV4::new(RMULE, RMULE_UDP),
        SocketAddrV4::new(SHARER, SHARER_UDP),
        &body,
    )
}

/// The sharer's UDPv4 `OP_REASKACK`: an empty one-part status, then `rank`.
fn ack(when: f64, rank: u16) -> Udp4Datagram {
    let mut body = vec![0xC5, 0x91, 0x01, 0x00, 0x00];
    body.extend_from_slice(&rank.to_le_bytes());
    datagram(
        when,
        SocketAddrV4::new(SHARER, SHARER_UDP),
        SocketAddrV4::new(RMULE, RMULE_UDP),
        &body,
    )
}

/// The sharer's `OP_ANSWERSOURCES2` on its callback link, naming one source.
fn sx_answer(when: f64) -> Ed2kFrame {
    let mut body = vec![4];
    body.extend_from_slice(&[0xAB; 16]);
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&[0; 29]);
    frame(when, at(SHARER, 40_001), listener(), (0xC5, 0x84), &body)
}

/// The run the flow exists for: the sharer is called back, answers rmule's
/// source ask — so aMule's `IsSourceRequestAllowed` is closed — and queues rmule,
/// a later rank refreshes the standing, and 1280 s after that rank rmule
/// pings the sharer at the address it called in from; the sharer answers with
/// its rank, so the 1300 s mark passes with no second callback request.
fn the_run() -> Observed {
    Observed {
        server_frames: vec![
            frame(
                10.0,
                server(),
                at(SHARER, 41_000),
                (0xE3, 0x40),
                &[LOW_ID.to_le_bytes(), SERVER.ip().octets()].concat(),
            ),
            callback_request(100.0),
            relay(100.1),
        ],
        rmule_frames: vec![
            sx_answer(104.9),
            rank(105.0, 40_001, 3),
            rank(400.2, 40_001, 2),
        ],
        obfuscated: Vec::new(),
        rmule_opens: vec![
            open(100.4, at(SHARER, 40_001), listener()),
            open(100.6, at(SHARER, 40_001), listener()),
        ],
        reask_datagrams: vec![ping(1_680.3), ack(1_680.4, 1)],
        sharer_log: "eD2k: Connected to 203.0.113.200 [203.0.113.200:4661] with LowID\n".to_owned(),
        rmule_log: "download.source_reask_acked id=1 peer=203.0.113.31:40001 rank=1\n".to_owned(),
    }
}

/// The claim named `name`.
fn claim<'a>(claims: &'a [Claim], name: &str) -> &'a Claim {
    claims
        .iter()
        .find(|claim| claim.name == name)
        .unwrap_or_else(|| panic!("no claim {name}: {claims:#?}"))
}

#[test]
fn a_called_back_source_is_pinged_and_its_answer_keeps_the_standing_fresh() {
    let (claims, rows) = claims(&addresses(), &the_run());
    assert_eq!(label(&claims).0, "PASS", "{claims:#?}");
    assert_eq!(rows.sharer_id, i64::from(LOW_ID));
    assert_eq!(rows.callback_requests_server_tap, 1);
    assert_eq!(
        rows.dial_backs_rmule_tap, 1,
        "a retransmitted SYN is one dial"
    );
    assert_eq!(rows.old_inbound_endpoint, "203.0.113.31:40001");
    assert_eq!(
        (
            rows.udp_reask_pings_rmule_tap,
            rows.udp_reask_acks_rmule_tap
        ),
        (1, 1)
    );
    assert!(
        (rows.ping_delay_secs - 1_280.1).abs() < 0.01,
        "measured from the last rank: {}",
        rows.ping_delay_secs
    );
}

#[test]
fn a_dial_at_the_sharers_old_inbound_endpoint_fails_the_run() {
    let mut run = the_run();
    run.rmule_opens
        .push(open(1_700.4, at(RMULE, 51_000), at(SHARER, 40_001)));
    let (claims, _) = claims(&addresses(), &run);
    let dialed = claim(&claims, "rmule-dialed-no-endpoint-of-the-sharer");
    assert_eq!(dialed.outcome, "absent", "{}", dialed.note);
    assert_eq!(label(&claims).0, "FAIL");
}

/// With no source answer from the sharer, aMule's source-ask gate stays open
/// and the TCP ask carries the ask instead of a ping (`DownloadClient.cpp:1271`):
/// the precondition claim says why no ping came.
#[test]
fn no_source_answer_is_the_open_source_ask_gate() {
    let mut run = the_run();
    run.rmule_frames.remove(0);
    let (claims, rows) = claims(&addresses(), &run);
    let answered = claim(&claims, SX_ANSWERED);
    assert_eq!(answered.outcome, "absent", "{}", answered.note);
    assert_eq!(rows.sx_answers_rmule_tap, 0);
}

#[test]
fn a_ping_before_the_window_is_not_the_reask_ping() {
    let mut run = the_run();
    run.reask_datagrams = vec![ping(1_200.0), ack(1_200.1, 1)];
    let (claims, _) = claims(&addresses(), &run);
    let pinged = claim(&claims, PINGED);
    assert_eq!(pinged.outcome, "absent", "{}", pinged.note);
}

/// A ping nobody answers falls to the TCP full ask at 1300 s: the second
/// callback request is the standing gone stale, and fails the run.
#[test]
fn an_unanswered_ping_and_a_second_callback_fail_the_run() {
    let mut run = the_run();
    run.reask_datagrams.truncate(1);
    run.server_frames
        .extend([callback_request(1_700.4), relay(1_700.5)]);
    run.rmule_log = "download.source_reasked_over_tcp id=1 peer=203.0.113.31:40001\n".to_owned();
    let (claims, _) = claims(&addresses(), &run);
    assert_eq!(claim(&claims, ANSWERED).outcome, "absent");
    let stale = claim(&claims, NO_SECOND_CALLBACK);
    assert_eq!(stale.outcome, "absent", "{}", stale.note);
    assert_eq!(label(&claims).0, "FAIL");
}

#[test]
fn an_obfuscated_server_link_blocks_the_callback_claims_instead_of_failing_them() {
    let mut run = the_run();
    run.obfuscated.push((at(RMULE, 50_000), server()));
    run.server_frames
        .retain(|frame| frame.opcode != 0x1C && frame.opcode != 0x35);
    let (claims, _) = claims(&addresses(), &run);
    for name in ["the-server-relayed-rmules-callback", NO_SECOND_CALLBACK] {
        assert_eq!(claim(&claims, name).outcome, "blocked", "{name}");
    }
}
