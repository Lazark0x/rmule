//! A firewalled slot holding a buddy link, driven as the Firewalled Front
//! drives it, and the hello's three buddy tags as a decoded hello carries
//! them — shared by every seam whose hello names the buddy: the accept pump,
//! the download dial, the Kad firewall-check dial-back.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use rmule_kad::KadId;
use rmule_peer::{CT_EMULE_BUDDYIP, CT_EMULE_BUDDYUDP, PeerHelloBody};
use rmule_primitives::{
    CT_EMULE_SERVINGBUDDYIPV6, CryptStance, Ipv4Endpoint, PeerEndpoint, TagValue, UserHash,
};
use tokio::sync::mpsc;

use crate::firewalled::front::{BuddyView, SharedFirewalledFront};
use crate::firewalled::link::{FirewalledSlot, RecruitedBuddy};
use crate::firewalled::recruit::{AdoptOutcome, FindBuddyRes};
use crate::reachability::SharedSelfReach;

/// A slot for our Kad ID `0xAA…`, and the view every hello reads it through.
pub(crate) fn slot() -> (FirewalledSlot, BuddyView) {
    SharedFirewalledFront::detached_slot(KadId::from_bytes([0xAA; KadId::BYTE_LEN]))
}

/// Self Reach with no High ID and Kad unproven — firewalled — over `own`.
pub(crate) fn firewalled(own: crate::own_identity::SharedOwnIdentity) -> SharedSelfReach {
    SharedSelfReach::new(
        crate::KadReachLevel::fixed(false),
        own,
        crate::natt::front::SharedNattFront::default(),
    )
}

/// The buddy a verified `0x5A` names, and the link we hold to it: answering
/// from its Kad UDP port, serving on its eD2k port, its connect-options byte
/// stating no obfuscation. `45.55.200.0/24` is publicly routable, which the
/// acting path's target rule requires of anything it punches at.
pub(crate) fn a_buddy() -> RecruitedBuddy {
    a_buddy_stating(CryptStance::disabled())
}

/// [`a_buddy`], its connect-options byte stating `crypt`.
pub(crate) fn a_buddy_stating(crypt: CryptStance) -> RecruitedBuddy {
    let at = |port| Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), port);
    RecruitedBuddy {
        udp: at(4672),
        tcp: at(4662),
        hash: UserHash::from_bytes([0xBB; UserHash::BYTE_LEN]),
        crypt: Some(crypt),
    }
}

/// Adopt [`a_buddy`] — the front's answer to a verified `0x5A` the Kad
/// pump's walk drew. Our Kad ID is `0xAA…`, so the `0x5A` echoes `0x55…`.
pub(crate) fn adopt(slot: &mut FirewalledSlot) {
    let answer = FindBuddyRes {
        buddy_id: KadId::from_bytes([0x55; KadId::BYTE_LEN]),
        buddy_endpoint: a_buddy().udp,
    };
    assert_eq!(
        slot.adopt_buddy(&answer, a_buddy(), CryptStance::disabled()),
        AdoptOutcome::Adopted
    );
}

/// Hold the link to the adopted buddy, whose hello claimed `claimed`.
pub(crate) fn link(
    slot: &mut FirewalledSlot,
    claimed: Option<Ipv6Addr>,
) -> mpsc::Receiver<rmule_peer::PeerCommand> {
    let (tx, rx) = mpsc::channel(8);
    let remote = PeerEndpoint::V4(a_buddy().tcp);
    assert!(slot.hold_link(a_buddy(), remote, tx, claimed, Instant::now()));
    rx
}

/// Adopt and hold — the whole path to a held link.
pub(crate) fn hold(
    slot: &mut FirewalledSlot,
    claimed: Option<Ipv6Addr>,
) -> mpsc::Receiver<rmule_peer::PeerCommand> {
    adopt(slot);
    link(slot, claimed)
}

/// The three buddy tags of one hello, as the wire carried them.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct BuddyTags {
    /// `CT_EMULE_BUDDYIP`'s four value bytes, in wire order.
    pub(crate) ip: Option<[u8; 4]>,
    /// `CT_EMULE_BUDDYUDP`'s `uint32`.
    pub(crate) udp: Option<u32>,
    /// `CT_EMULE_SERVINGBUDDYIPV6`.
    pub(crate) ipv6: Option<Ipv6Addr>,
}

impl BuddyTags {
    /// What a hello naming [`a_buddy`] carries: its IPv4 octets as aMule
    /// writes them (`BaseClient.cpp:1486`, `GetIP()` in network order, so the
    /// octets on the wire read `45.55.200.2`) and the `0x5A`'s UDP port.
    pub(crate) fn naming_a_buddy(ipv6: Option<Ipv6Addr>) -> Self {
        Self {
            ip: Some([45, 55, 200, 2]),
            udp: Some(4672),
            ipv6,
        }
    }

    /// The buddy tags `body` carries.
    pub(crate) fn of(body: &PeerHelloBody) -> Self {
        let mut read = Self::default();
        for tag in &body.tags {
            match (tag.name().id(), tag.value()) {
                (Some(CT_EMULE_BUDDYIP), TagValue::U32(value)) => {
                    read.ip = Some(value.to_le_bytes());
                }
                (Some(CT_EMULE_BUDDYUDP), TagValue::U32(value)) => read.udp = Some(*value),
                (Some(CT_EMULE_SERVINGBUDDYIPV6), TagValue::Hash(bytes)) => {
                    read.ipv6 = Some(Ipv6Addr::from(*bytes));
                }
                _ => {}
            }
        }
        read
    }
}
