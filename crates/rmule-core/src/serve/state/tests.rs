//! The serve brain asserted as plain `Vec<ServeDecision>` values: the share
//! set's answers, the upload queue, data served out, the uploader-side reask,
//! and source exchange. The shared fixtures live here; each area's assertions
//! live in a submodule.

mod reask;
mod sharing;
mod slots;
mod source_exchange;
mod transfer;

use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_peer::{
    BundledAsk, PartIndex, PartRanges, PartStatusTail, ReaskAck, ReaskFilePing,
    file_not_found_datagram, queue_full_datagram,
};
use rmule_primitives::{ClientId, ED2K_PART_SIZE, EMBLOCKSIZE, PartHash, PeerSource};

use crate::adapters::ServeConnEvent;
use crate::registry::ShareSource;

use super::*;

fn peer(port: u16) -> PeerEndpoint {
    PeerSource::new(ClientId::from_u32(0x0100_007F), port)
        .as_peer_endpoint()
        .unwrap()
}

fn hash(byte: u8) -> FileHash {
    FileHash::from_bytes([byte; FileHash::BYTE_LEN])
}

fn user(byte: u8) -> UserHash {
    UserHash::from_bytes([byte; UserHash::BYTE_LEN])
}

fn entry(file_hash: FileHash, file_size: u64, name: &str) -> SharedFileEntry {
    SharedFileEntry {
        file_hash,
        file_size,
        path: format!("/shared/{name}").into(),
        name: name.into(),
        source: ShareSource::Explicit,
        modified: None,
        part_hashes: Vec::new(),
    }
}

/// A state serving `entries` through a queue of `budget` slots (cap 8).
fn serving_state(budget: usize, entries: Vec<SharedFileEntry>) -> ServeState {
    let mut state = ServeState::new(UploadSlotQueue::new(budget, 8));
    let _ = state.on_share_set(
        entries,
        std::time::Instant::now(),
        &std::collections::HashMap::new(),
    );
    state
}

fn no_modifiers() -> HashMap<PeerEndpoint, f64> {
    HashMap::new()
}

fn send(peer: PeerEndpoint, command: ServeConnCommand) -> ServeDecision {
    ServeDecision::Send { peer, command }
}

fn identify(state: &mut ServeState, p: PeerEndpoint, user_hash: UserHash, t: Instant) {
    let decisions = state.on_conn_event(
        t,
        p,
        ServeConnEvent::Identified {
            user_hash,
            client_id: ClientId::from_u32(0x0100_007F),
            connected_server: None,
            tcp_port: 4662,
            udp_port: 0,
            udp_version: 0,
            // aMule 2.3.3's claim: its name asks carry a part status.
            extended_requests_version: 2,
            crypt: crypt_advert(),
            ipv6: None,
            software: nameless_software(),
        },
        &no_modifiers(),
    );
    assert_eq!(decisions, Vec::new(), "identification is bookkeeping only");
}

fn peer_at(ip: [u8; 4], tcp_port: u16) -> PeerEndpoint {
    PeerSource::new(ClientId::from_u32(u32::from_le_bytes(ip)), tcp_port)
        .as_peer_endpoint()
        .unwrap()
}

/// A global-unicast IPv6 peer in one documentation `/64` — the fixture the
/// family-generic reask matrix is asserted against (ADR-0087).
fn v6_peer(last: u16, port: u16) -> PeerEndpoint {
    PeerEndpoint::V6(rmule_primitives::Ipv6Endpoint::new(
        std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, last),
        port,
    ))
}

fn udp(ip: [u8; 4], port: u16) -> PeerEndpoint {
    PeerEndpoint::V4(rmule_primitives::Ipv4Endpoint::new(
        Ipv4Addr::from(ip),
        port,
    ))
}

/// Identify `p` advertising a UDP contact, so its wait-list entry is
/// reask-matchable by IP + port (ADR-0057), and claiming extended requests
/// as aMule 2.3.3 does.
fn identify_udp(
    state: &mut ServeState,
    p: PeerEndpoint,
    user_hash: UserHash,
    udp_port: u16,
    udp_version: u8,
    t: Instant,
) {
    identify_udp_claiming(state, p, user_hash, udp_port, udp_version, 2, t);
}

/// [`identify_udp`] with the hello's extended-requests claim spelled out.
fn identify_udp_claiming(
    state: &mut ServeState,
    p: PeerEndpoint,
    user_hash: UserHash,
    udp_port: u16,
    udp_version: u8,
    extended_requests_version: u8,
    t: Instant,
) {
    let decisions = state.on_conn_event(
        t,
        p,
        ServeConnEvent::Identified {
            user_hash,
            client_id: ClientId::from_u32(0x0100_007F),
            connected_server: None,
            tcp_port: 4662,
            udp_port,
            udp_version,
            extended_requests_version,
            // A crypt-capable peer, as aMule 2.3.3 advertises by default —
            // so a reply to it carries a usable crypt target (ADR-0046).
            crypt: crypt_advert(),
            ipv6: None,
            software: nameless_software(),
        },
        &no_modifiers(),
    );
    assert_eq!(decisions, Vec::new());
}

/// The crypt stance [`identify_udp`] advertises on the peer's behalf.
fn crypt_advert() -> rmule_primitives::CryptStance {
    rmule_primitives::CryptStance::new(true, true, false)
}

/// The crypt target a reply to an [`identify_udp`]-identified peer carries.
fn target_of(user_hash: UserHash) -> Option<PeerUdpCryptTarget> {
    Some(PeerUdpCryptTarget::new(user_hash, crypt_advert()))
}

fn slot_request(
    state: &mut ServeState,
    p: PeerEndpoint,
    file_hash: FileHash,
    t: Instant,
) -> Vec<ServeDecision> {
    state.on_conn_event(
        t,
        p,
        ServeConnEvent::SlotRequested { file_hash },
        &no_modifiers(),
    )
}

/// The `0x90` a UDPv4 downloader of a complete copy writes: the hash, the
/// count-zero status, its complete-source count (stock 2.3.3
/// `DownloadClient.cpp:1280-1291`). The version-gated tail is only read from
/// a UDPv4 waiter; an older one's ping is routed by the hash alone.
fn reask_ping(file_hash: FileHash) -> Vec<u8> {
    ReaskFilePing {
        file_hash,
        part_status: Some(PartBitmap::complete_source_sentinel()),
        complete_sources: Some(0),
    }
    .encode_udp()
}

/// The `0x90` body a pre-UDPv3 client writes — the file hash alone.
fn hash_only_ping(file_hash: FileHash) -> Vec<u8> {
    ReaskFilePing {
        file_hash,
        part_status: None,
        complete_sources: None,
    }
    .encode_udp()
}

/// A holder granted the sole slot, and `waiter` (UDPv4, advertising
/// `udp_port`) queued behind it at rank 1.
fn one_waiter_state(
    file: FileHash,
    file_size: u64,
    waiter: PeerEndpoint,
    udp_port: u16,
    udp_version: u8,
    t: Instant,
) -> ServeState {
    let mut state = serving_state(1, vec![entry(file, file_size, "served.bin")]);
    let _ = slot_request(&mut state, peer_at([10, 0, 0, 1], 4000), file, t);
    identify_udp(&mut state, waiter, user(0x0A), udp_port, udp_version, t);
    let queued = slot_request(&mut state, waiter, file, t);
    assert!(
        matches!(
            queued.as_slice(),
            [
                ServeDecision::CountUploadRequest { .. },
                ServeDecision::Send {
                    command: ServeConnCommand::SetQueueRank { rank: 1 },
                    ..
                },
                ServeDecision::Emit(ServeEvent::PeerQueued { rank: 1, .. }),
            ]
        ),
        "the waiter queued at rank 1: {queued:?}"
    );
    state
}

/// The identification a hello naming no user yields — what these tests'
/// peers, which say nothing about their client, are read as.
fn nameless_software() -> rmule_peer::ClientSoftware {
    rmule_peer::ClientSoftware::from_hello_body(&rmule_peer::PeerHelloBody {
        user_hash: UserHash::from_bytes([0; UserHash::BYTE_LEN]),
        client_id: ClientId::from_u32(0),
        tcp_port: 0,
        tags: Vec::new(),
        connected_server: rmule_primitives::Ipv4Endpoint::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
    })
}
