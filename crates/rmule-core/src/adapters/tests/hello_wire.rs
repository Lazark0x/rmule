//! One hello read back off the wire, and a node whose every advert is live
//! Shared by every road that sends a hello, so each one's test
//! reads the same bytes against the same expectation.

use std::net::{IpAddr, Ipv6Addr};

use rmule_net::family::FamilyBinds;
use rmule_net::peer::ObfuscationPolicy;
use rmule_peer::{Hello, PeerHelloBody, PeerIdentity, UdpPortsAdvert};
use rmule_primitives::{AddressFamily, Packet};
use tokio::io::AsyncReadExt;

use crate::adapters::{HelloAdverts, SharedIpv6Advert};
use crate::address_learning::{SharedAddressLearning, SocketRole};
use crate::firewalled::link::SharedFirewalledSlot;
use crate::reachability::SharedIpv6Probe;

/// Our served reask port and our running Kad node's port — distinct, so a
/// hello that swapped the halves would not pass.
const OUR_CLIENT_UDP: u16 = 4672;
const OUR_KAD_UDP: u16 = 4665;

/// Our Known IPv6, as the Advertised Endpoints chooser would report it.
fn our_ipv6() -> Ipv6Addr {
    "3fff:ed2:474::1".parse().expect("an IPv6 literal")
}

/// A node with every advert live — a reask port served, a Kad node running, a
/// Known IPv6, crypt supported — over `slot`, which states the buddy.
pub(crate) fn live_adverts(slot: SharedFirewalledSlot) -> HelloAdverts {
    // The Known IPv6 is learned by the owner, Address Learning, exactly as a
    // live core learns it: a dual-stack listener and the address on an
    // interface (no advert holds a copy to set).
    let addresses = SharedAddressLearning::new();
    addresses.record_bind(
        SocketRole::Tcp,
        &FamilyBinds {
            bound: vec![AddressFamily::V4, AddressFamily::V6],
            refused: Vec::new(),
        },
        4662,
    );
    addresses.refresh_interfaces(&[IpAddr::V6(our_ipv6())]);
    let adverts = HelloAdverts {
        ipv6: SharedIpv6Advert::over(addresses, SharedIpv6Probe::default()),
        firewalled_slot: slot,
        crypt_policy: Some(ObfuscationPolicy::Supported),
        ..HelloAdverts::default()
    };
    adverts.udp_ports.set_serving(OUR_CLIENT_UDP);
    adverts.udp_ports.set_kad(OUR_KAD_UDP);
    adverts
}

/// Read one hello frame off `stream` and decode its body.
pub(crate) async fn read_hello_body(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> PeerHelloBody {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await.expect("hello header");
    let len = u32::from_le_bytes(header[1..].try_into().expect("four bytes")) as usize;
    let mut frame = header.to_vec();
    frame.resize(header.len() + len, 0);
    stream
        .read_exact(&mut frame[header.len()..])
        .await
        .expect("hello body");
    let packet = Packet::decode_exact(&frame).expect("one hello frame");
    Hello::decode_packet(&packet)
        .expect("the hello decodes")
        .into_body()
}

/// The hello states what [`live_adverts`] holds: the exact `CT_EMULE_UDPPORTS`
/// word, and — read as a peer reads them — a Kad-version nibble high enough
/// for a bootstrap hint and a UDP firewall check, the crypt-support bit, and
/// `CT_MOD_IP_V6`.
pub(crate) fn assert_states_live_adverts(body: &PeerHelloBody) {
    assert!(
        body.tags
            .contains(&UdpPortsAdvert::new(OUR_CLIENT_UDP, OUR_KAD_UDP).to_tag()),
        "CT_EMULE_UDPPORTS names our reask and Kad ports (BaseClient.cpp:1482)",
    );
    let us = PeerIdentity::from_hello_body(body);
    assert_eq!(
        us.kad_bootstrap_port(),
        Some(OUR_KAD_UDP),
        "the Kad half rides with a Kad-version nibble above 1",
    );
    assert!(
        us.serves_udp_firewall_checks(),
        "the Kad-version nibble is 6 or more"
    );
    assert!(
        us.crypt_stance().supports(),
        "MiscOptions2 advertises our crypt support"
    );
    assert_eq!(us.peer_ipv6(), Some(our_ipv6()), "CT_MOD_IP_V6");
}
