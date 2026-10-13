//! The claims over hand-laid frames: the run the flow exists for, a relay
//! rmule never answered, a downloader that reached rmule's listener directly,
//! a copy that differs, and a dialed link no frame can be read on.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use super::{Addresses, BYTE_EQUAL, DIALED, NO_DIRECT_DIAL, Observed, RELAYED, claims};
use crate::flow::nat::claims::{Claim, label};
use crate::flow::pcap::{Ed2kFrame, TcpOpen};

const RMULE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 70);
const DOWNLOADER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 31);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 200), 4661);
const LISTENER_PORT: u16 = 4663;
const DOWNLOADER_PORT: u16 = 4662;
const LOW_ID: u32 = 3;

fn addresses() -> Addresses {
    Addresses {
        rmule: RMULE,
        rmule_port: LISTENER_PORT,
        downloader: DOWNLOADER,
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

/// rmule's ephemeral end of the link it dials.
fn rmule_end() -> SocketAddr {
    at(RMULE, 51_000)
}

fn requester() -> SocketAddr {
    at(DOWNLOADER, DOWNLOADER_PORT)
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

/// The server's three frames: rmule's Low ID, the downloader's ask, the relay
/// naming the downloader's listener.
fn server_frames() -> Vec<Ed2kFrame> {
    let mut relay = DOWNLOADER.octets().to_vec();
    relay.extend_from_slice(&DOWNLOADER_PORT.to_le_bytes());
    vec![
        frame(
            1.0,
            server(),
            at(RMULE, 50_000),
            (0xE3, 0x40),
            &LOW_ID.to_le_bytes(),
        ),
        frame(
            10.0,
            at(DOWNLOADER, 40_000),
            server(),
            (0xE3, 0x1C),
            &LOW_ID.to_le_bytes(),
        ),
        frame(10.1, server(), at(RMULE, 50_000), (0xE3, 0x35), &relay),
    ]
}

/// The dialed link: rmule's hello first, the downloader's answer and asks,
/// and rmule's parts.
fn link_frames() -> Vec<Ed2kFrame> {
    vec![
        frame(10.3, rmule_end(), requester(), (0xE3, 0x01), &[0x10]),
        frame(10.4, requester(), rmule_end(), (0xE3, 0x4C), &[0x10]),
        frame(10.5, requester(), rmule_end(), (0xE3, 0x58), &[0xAB; 16]),
        frame(10.6, requester(), rmule_end(), (0xE3, 0x54), &[0xAB; 16]),
        frame(10.8, requester(), rmule_end(), (0xE3, 0x47), &[0xAB; 40]),
        frame(10.9, rmule_end(), requester(), (0xE3, 0x46), &[0xCD; 64]),
    ]
}

fn passing() -> Observed {
    Observed {
        server_frames: server_frames(),
        rmule_frames: link_frames(),
        obfuscated: Vec::new(),
        rmule_opens: vec![open(10.2, rmule_end(), requester())],
        downloaded: (true, 4096),
    }
}

fn outcome<'a>(claims: &'a [Claim], name: &str) -> &'a str {
    claims
        .iter()
        .find(|claim| claim.name == name)
        .unwrap_or_else(|| panic!("no claim {name}"))
        .outcome
}

#[test]
fn the_relayed_dial_back_that_carried_the_file_passes() {
    let (claims, rows) = claims(&addresses(), &passing());
    assert_eq!(label(&claims).0, "PASS", "{claims:#?}");
    assert_eq!(rows.rmule_id, i64::from(LOW_ID));
    assert_eq!(rows.relayed_requester, requester().to_string());
    assert!(!rows.relay_carried_crypt_extension);
    assert_eq!(
        (rows.dial_backs_rmule_tap, rows.part_frames_rmule_tap),
        (1, 1)
    );
}

/// A relay rmule never dialed fails the dial and everything after it, and a
/// dial at another endpoint is not the one the relay named.
#[test]
fn a_relay_rmule_never_answered_fails() {
    let seen = Observed {
        rmule_opens: vec![open(10.2, rmule_end(), at(DOWNLOADER, 9_999))],
        rmule_frames: Vec::new(),
        downloaded: (false, -1),
        ..passing()
    };
    let (claims, _) = claims(&addresses(), &seen);
    assert_eq!(outcome(&claims, RELAYED), "held");
    assert_eq!(outcome(&claims, DIALED), "absent");
    assert_eq!(outcome(&claims, BYTE_EQUAL), "absent");
    assert_eq!(label(&claims).0, "FAIL");
}

/// A downloader that reached rmule's listener directly means the forced Low ID
/// did not hold, so the transfer proves nothing about the dial-back.
#[test]
fn a_direct_dial_at_rmules_listener_fails_the_absence() {
    let mut seen = passing();
    seen.rmule_opens
        .push(open(9.0, at(DOWNLOADER, 41_000), at(RMULE, LISTENER_PORT)));
    let (claims, rows) = claims(&addresses(), &seen);
    assert_eq!(outcome(&claims, NO_DIRECT_DIAL), "absent");
    assert_eq!(rows.direct_dials_rmule_tap, 1);
}

#[test]
fn a_copy_that_differs_fails_byte_equality() {
    let seen = Observed {
        downloaded: (false, 4096),
        ..passing()
    };
    let (claims, _) = claims(&addresses(), &seen);
    assert_eq!(outcome(&claims, BYTE_EQUAL), "absent");
}

/// A dialed link that opened obfuscated cannot be read: its two link claims
/// are blocked, never scored against frames nobody could decode.
#[test]
fn an_obfuscated_dialed_link_blocks_its_link_claims() {
    let seen = Observed {
        obfuscated: vec![(rmule_end(), requester())],
        rmule_frames: Vec::new(),
        ..passing()
    };
    let (claims, _) = claims(&addresses(), &seen);
    assert_eq!(
        outcome(&claims, "rmule-spoke-first-on-the-dialed-link"),
        "blocked"
    );
    assert_eq!(label(&claims).0, "OBSERVED");
}
