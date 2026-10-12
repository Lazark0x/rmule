//! What the **Kad Pump State** is handed: the core's commands, the node's
//! events, the recruit tick, samples of the sources it reads, the answers to
//! its own effects, room in the node's inbox, and the Firewalled Front's
//! verdict on a buddy it was asked to adopt.
//!
//! A sample is the "latest value the runner handed in" pattern **Download
//! State** already uses: the driver reads each owner when it moves — **Self
//! Reach** on a **Reach Generation**, **Address Learning** on an **Own Address
//! Generation**, the obfuscation policy on its live change — and on the
//! recruit tick, the time edge no write announces (a freshness window
//! lapsing, a buddy link lost on the front's task).

use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_kad::KadId;
use rmule_primitives::Ipv4Endpoint;

use crate::adapters::kad_runtime::KadPumpCommand;
use crate::firewalled::front::AdoptVerdict;
use crate::firewalled::link::BuddySnapshot;
use crate::reachability::{TcpReachability, UdpReachability};

use super::NodeCommand;

/// One input to the Kad Pump State, handed in with the instant it happened.
pub(crate) enum KadPumpInput {
    /// The node is up and the pump is about to take its first step: the
    /// sources as they stand.
    Start(KadPumpSample),
    /// A command the core sent, with the sources as they stand when it
    /// arrived — a publish names the Advertised IPv6 read at its own
    /// advertisement. The driver hands one in only while
    /// [`KadPumpState::takes_commands`](super::KadPumpState::takes_commands).
    /// Boxed: the largest command would double every input's size.
    Command(Box<KadPumpCommand>, KadPumpSample),
    /// An event the node emitted.
    Event(rmule_kad::KadEvent),
    /// The recruit tick, with the sources re-sampled on it.
    Tick(KadPumpSample),
    /// A source moved: a Reach Generation, an Own Address Generation, an
    /// obfuscation policy change, or an Address Learning write this brain
    /// asked for.
    Sampled(KadPumpSample),
    /// What became of a node command this brain asked for.
    Delivered(NodeCommand, Delivery),
    /// The node's inbox has room again, awaited by the driver beside the
    /// node's events while
    /// [`KadPumpState::awaits_room`](super::KadPumpState::awaits_room).
    Room,
    /// What the open-node buddy service decided on a FINDBUDDY this brain
    /// handed it.
    SlotAnswered(SlotAnswer),
    /// The Firewalled Front's verdict on a `0x5A` this brain handed it.
    BuddyVerdict(AdoptVerdict),
    /// The pump is going away.
    Stop,
}

/// The sources the reconciler composes the node's state from, read together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KadPumpSample {
    /// Self Reach's answers.
    pub(crate) reach: ReachSample,
    /// Address Learning's projection.
    pub(crate) own_address: OwnAddressSample,
    /// The firewalled slot's **Buddy Snapshot** as its owner last published
    /// it: the buddy a source publish names (with the held link's `bi6`), and
    /// whether a buddy is held and when the last was lost — the recruit
    /// rule's slot facts.
    pub(crate) buddy: BuddySnapshot,
    /// The one obfuscation policy as it stands (ADR-0046), `None` for none:
    /// the node's datagram crypt, the publish byte's crypt ladder, the buddy
    /// dial's side of the crypt rule and the recruit gate's `Required`
    /// refusal. It changes live, so it is read like every other owner.
    pub(crate) crypt: Option<rmule_net::peer::ObfuscationPolicy>,
    /// The **Advertised IPv6**, settled by its owner at this read (ADR-0087):
    /// what a source publish's `ip6` tag names.
    pub(crate) advertised_ipv6: Option<Ipv6Addr>,
}

/// **Self Reach**, read through its owner's own questions (ADR-0060): no
/// field here composes two families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReachSample {
    /// aMule's `IsFirewalled()` union — Server High ID or Kad TCP open, both
    /// absent. The buddy row reads it.
    pub(crate) firewalled: bool,
    /// The publish byte's direct-UDP-callback bit (`0x08`).
    pub(crate) accepts_direct_udp_callback: bool,
    /// The NAT-T front on this node's bind still runs.
    pub(crate) natt_live: bool,
    /// The Kad TCP verdict, the Kad flag alone — the recruit gate's.
    pub(crate) kad_tcp: TcpReachability,
    /// The Kad UDP verdict — the recruit gate's other half.
    pub(crate) kad_udp: UdpReachability,
}

/// **Address Learning**'s two answers the node caches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnAddressSample {
    /// Our public IPv4, `None` while no verdict holds (never held, or a Low-ID
    /// re-assignment withdrew it, ADR-0084).
    pub(crate) public_ip: Option<Ipv4Addr>,
    /// The UDP role's learned port — the **Extern Kad Port** — with no
    /// fallback to the bound port.
    pub(crate) learned_udp_port: Option<u16>,
}

/// How a node command the driver sent without waiting fared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Delivery {
    /// The node's inbox took it.
    Landed,
    /// The inbox was momentarily full; the node holds what it held, and the
    /// brain waits for room.
    InboxFull,
    /// The node's driver is gone; the pump is about to end with it.
    NodeGone,
}

/// The open-node buddy service's answer to a FINDBUDDY this brain handed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlotAnswer {
    /// The open-node service accepted a firewalled peer's FINDBUDDY: the
    /// `0x5A` is owed to `requester`.
    BuddyServed {
        requester: Ipv4Endpoint,
        buddy_id: KadId,
    },
}
