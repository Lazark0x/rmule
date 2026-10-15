//! Who may open a Tunnel (ADR-0091, security rule 10): an opening packet opens
//! a registry slot only from an IP the front expects — a Punch Expectation,
//! a Peer Roster relation or a standing Dial-Back Claim — and an IPv6 source
//! never.

use super::*;

/// One uTP `ST_SYN` (`(ST_SYN << 4) | version 1`) in its `0xB2` envelope.
fn syn() -> Vec<u8> {
    let mut packet = [0u8; 20];
    packet[0] = 0x41;
    rmule_peer::natt::NattFrame::Utp(&packet).encode()
}

fn slot(harness: &Harness, peer: PeerEndpoint) -> Option<rmule_net::natt::TunnelSlot> {
    harness
        .front
        .registry
        .lock()
        .expect("the registry is never poisoned")
        .slot(peer)
}

/// A stranger's opener opens nothing; the same address opens a slot once an
/// introduction names it, whatever port the opener comes from.
#[tokio::test]
async fn an_opener_opens_a_slot_only_from_an_introduced_address() {
    let mut harness = Harness::new();
    let now = Instant::now();
    let stranger = PeerEndpoint::V4(at(9, 50123));
    harness.front.on_datagram(stranger, syn(), now).await;
    assert_eq!(slot(&harness, stranger), None, "nothing expects it");

    harness
        .front
        .on_command(
            NattCommand::Introduced {
                peer_hash: hash(0x44),
                target: at(9, 31999),
                role: rmule_ed2k::HolepunchRole::Responder,
                burst: false,
                source: rmule_peer::natt::PunchTargetSource::Observed,
            },
            now,
        )
        .await;
    harness.front.on_datagram(stranger, syn(), now).await;
    assert_eq!(
        slot(&harness, stranger),
        Some(rmule_net::natt::TunnelSlot::Opening),
        "the introduction names the address; its NAT picks the port"
    );
}

/// A peer this node already deals with may come back over uTP with no
/// rendezvous, as kno dials every peer whose hello claims it; an IPv6 source
/// opens nothing even then.
#[tokio::test]
async fn a_roster_peer_may_open_and_an_ipv6_source_never_does() {
    let mut harness = Harness::new();
    let now = Instant::now();
    let known = at(12, 4662);
    harness
        .front
        .wiring
        .roster
        .mark_known(crate::peer_roster::PeerRelation::Queued(crate::DownloadId::from_u64(1)), known);
    let from = PeerEndpoint::V4(Ipv4Endpoint::new(known.ip, 4672));
    harness.front.on_datagram(from, syn(), now).await;
    assert_eq!(slot(&harness, from), Some(rmule_net::natt::TunnelSlot::Opening));

    let v6 = PeerEndpoint::V6(rmule_primitives::Ipv6Endpoint::new(
        "2001:db8::7".parse().expect("an address"),
        4672,
    ));
    harness.front.on_datagram(v6, syn(), now).await;
    assert_eq!(slot(&harness, v6), None);
}
