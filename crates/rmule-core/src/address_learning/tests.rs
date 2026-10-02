//! The deterministic tier for ADR-0084, and the fixtures its legs share.
//!
//! Every rule is driven by explicit time, so a thirty-minute window costs a
//! microsecond and a lease expiry is an argument rather than a wait. The legs
//! split along what is being proven, not along which type it lives on:
//! [`ladders`] (which source outranks which), [`quorum`] (what it takes for
//! strangers to be believed, and the filter that stops them), [`verdicts`]
//! (admissibility, ageing, and what disagreement means) and [`advert`] (what
//! rmule ends up claiming on the wire).

mod advert;
mod ladders;
mod quorum;
mod verdicts;

use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_net::family::FamilyBinds;
use rmule_peer::natt::OwnMapping;
use rmule_primitives::Ipv4Endpoint;

use super::ladder::{OBSERVATION_WINDOW, OBSERVERS_REMEMBERED};
use super::store::AddressLearning;
use super::*;
use crate::reachability::{Ipv6Probe, TcpReachability};

pub(super) const TCP_PORT: u16 = 4662;
pub(super) const KAD_PORT: u16 = 4672;

pub(super) fn v4(octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, octet))
}

pub(super) fn v6(last: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last))
}

pub(super) fn observer(octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, octet))
}

pub(super) fn both_families() -> FamilyBinds {
    FamilyBinds {
        bound: vec![AddressFamily::V4, AddressFamily::V6],
        refused: Vec::new(),
    }
}

/// A store whose TCP and Kad roles bound both families, so a verdict only
/// waits on an address.
pub(super) fn bound_store() -> AddressLearning {
    let mut store = AddressLearning::new();
    store.record_bind(SocketRole::Tcp, &both_families(), TCP_PORT);
    store.record_bind(SocketRole::Udp, &both_families(), KAD_PORT);
    store
}

pub(super) fn ipv4(address: IpAddr) -> Ipv4Addr {
    match address {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => unreachable!("an IPv4 fixture"),
    }
}

/// The High ID a server assigns a client it reached at `address` — the id
/// *is* the address, in wire byte order.
pub(super) fn high_id(address: Ipv4Addr) -> rmule_primitives::ClientId {
    rmule_primitives::ClientId::from_u32(u32::from_le_bytes(address.octets()))
}
