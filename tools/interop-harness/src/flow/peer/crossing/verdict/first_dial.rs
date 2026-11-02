//! The kno-dials-first leg's claims: kno, knowing rmule from a hello, adds a
//! file rmule shares once no socket to it is open and dials uTP first; rmule
//! expected no Tunnel from it and stays silent; kno's TCP dial carries the file.

use std::net::IpAddr;

use super::{Link, Rows};
use crate::flow::nat::claims::{Claim, Evidence};
use crate::flow::pcap::Udp4Datagram;

/// A uTP `ST_SYN`'s first byte: type 4, version 1.
const UTP_ST_SYN: u8 = 0x41;

/// The leg's claims over rmule's tap.
pub(super) fn claims(
    rows: &Rows,
    datagrams: &[Udp4Datagram],
    (rmule, kno): (IpAddr, IpAddr),
    returned: f64,
    own: Option<&Link>,
) -> Vec<Claim> {
    let from_kno = |datagram: &&Udp4Datagram| {
        IpAddr::V4(*datagram.source.ip()) == kno && IpAddr::V4(*datagram.destination.ip()) == rmule
    };
    let syns: Vec<&Udp4Datagram> = datagrams
        .iter()
        .filter(from_kno)
        .filter(|datagram| datagram.at >= returned && datagram.payload.first() == Some(&UTP_ST_SYN))
        .collect();
    let first_syn = syns.first().map(|datagram| datagram.at);
    let answers = datagrams
        .iter()
        .filter(|datagram| {
            IpAddr::V4(*datagram.source.ip()) == rmule
                && IpAddr::V4(*datagram.destination.ip()) == kno
                && first_syn.is_some_and(|at| datagram.at >= at)
        })
        .count();
    let tcp_after = own.zip(first_syn).map(|(link, at)| link.opened_at - at);
    vec![
        Claim::about(
            "kno-dialed-utp-first",
            first_syn.is_some(),
            Evidence::Captured,
            format!("uTP ST_SYN from kno at rmule's port: {}", syns.len()),
        ),
        Claim::about(
            "rmule-answered-no-tunnel-it-did-not-expect",
            first_syn.is_some() && answers == 0,
            Evidence::Captured,
            format!("datagrams rmule sent kno from the first ST_SYN on: {answers}"),
        ),
        Claim::about(
            "kno-fell-back-to-its-tcp-dial",
            tcp_after.is_some_and(|secs| secs > 0.0),
            Evidence::Captured,
            format!("kno's TCP SYN, seconds past its first ST_SYN: {tcp_after:?}"),
        ),
        Claim::about(
            "the-file-rode-that-link",
            own.is_some_and(|link| link.parts_from_rmule > 0),
            Evidence::Captured,
            format!(
                "OP_SENDINGPART on kno's link: {}; records: {}",
                own.map_or(0, |link| link.parts_from_rmule),
                rows.records.len()
            ),
        ),
    ]
}
