//! The **Kad Pump State**'s one reconciler: the whole node state the owners'
//! facts call for, and what the running node already holds.
//!
//! The node derives none of these seven facts; each has an owner outside it
//! and the node keeps a cache. After every input the brain composes all seven
//! from its latest samples and its own self-check store, and tells the node
//! only the ones it does not hold — so no input can forget to restate one,
//! and a level a full inbox turned away is restated on the next input rather
//! than lost.
//!
//! - **TCP level** (ADR-0058): a level, not an edge. A fresh store reads
//!   firewalled and never leaves it unaided, and the node is constructed
//!   assume-open, so the start itself tells a firewalled node — without that
//!   the UDP tester's conclude gate never fires.
//! - **Own IPv4** (ADR-0084): the node binds a learned verify key to the IP we
//!   held when we learned it (aMule's `CKadUDPKey`), and aMule re-reads
//!   `GetPublicIP()` on every send. A withdrawn verdict is `0.0.0.0`, the
//!   value the node is armed with when none is known, never the last one.
//! - **Extern Kad Port**: the store's learned port, `0` while none holds.
//!   Every `0x61` observation is answered whether or not the value repeats:
//!   the node's helper gate waits on exactly that answer.
//! - **Publish Connect Options**: [`publish_connect_options`] over our crypt
//!   policy and Self Reach.
//! - **Publish posture**: reachable, or firewalled behind the buddy the slot
//!   names — none, while it holds none (aMule's `PrepareToStop`). It reads
//!   the `IsFirewalled()` union, so a server High ID withdraws the buddy row
//!   exactly as it withdraws the direct-callback bit.
//! - **Datagram crypt** (ADR-0046): obfuscation with its verify keys, or
//!   plaintext, as the one obfuscation policy stands now. The policy changes
//!   live, and the node caches its arming, so this is how it follows: re-armed
//!   whole, before the pump takes another input.
//! - **Advertised IPv6** (ADR-0087): the chooser's verdict, settled at each
//!   read and sampled with every core command, so a publish's own sample
//!   carries the verdict at its advertisement. The node is constructed holding
//!   none.
//!
//! The core's asks wait until no level is on its way or turned away, so every
//! ask reaches a node that holds the whole state the owners call for — a
//! publish never leaves with an `ip6` tag or connect options older than its
//! own sample.

use std::net::Ipv4Addr;

use rmule_net::peer::ObfuscationPolicy;
use rmule_peer::natt::HelloNattClaim;

use super::{KadCryptArm, KadPumpSample, NodeLevel};
use crate::natt::front::RMULE_NATT_CLAIM;
use crate::reachability::TcpReachability;

/// The seven levels, in the order the reconciler tells them.
const KINDS: usize = 7;

impl NodeLevel {
    /// Which of the seven caches this level fills.
    const fn kind(self) -> usize {
        match self {
            Self::TcpFirewalled(_) => 0,
            Self::OwnPublicIp(_) => 1,
            Self::ExternUdpPort(_) => 2,
            Self::PublishConnectOptions(_) => 3,
            Self::PublishPosture(_) => 4,
            Self::DatagramCrypt(_) => 5,
            Self::AdvertisedIpv6(_) => 6,
        }
    }
}

/// What the running node holds, per level, what is on its way to it, and
/// which levels a full inbox turned away.
pub(super) struct NodeLevels {
    told: [Option<NodeLevel>; KINDS],
    /// Asked for and not yet answered: a reconcile that runs while the driver
    /// still carries an earlier batch out must not ask for it twice.
    in_flight: [Option<NodeLevel>; KINDS],
    /// A level turned away is logged once until it lands, not on every input
    /// that retries it.
    deferred: [bool; KINDS],
    /// A `0x61` observation is owed its answer, the same value or not.
    port_answer_owed: bool,
}

impl NodeLevels {
    /// The caches of a node that has just been constructed: it believes it is
    /// open, advertises no IPv6, and holds nothing else it was told.
    pub(super) fn fresh() -> Self {
        let mut told = [None; KINDS];
        for held in [
            NodeLevel::TcpFirewalled(false),
            NodeLevel::AdvertisedIpv6(None),
        ] {
            told[held.kind()] = Some(held);
        }
        Self {
            told,
            in_flight: [None; KINDS],
            deferred: [false; KINDS],
            port_answer_owed: false,
        }
    }

    /// Owe the next reconcile an Extern Kad Port answer, whatever it is.
    pub(super) fn owe_port_answer(&mut self) {
        self.port_answer_owed = true;
    }

    /// The levels `desired` holds that the node neither holds nor has on its
    /// way, in order. An owed port answer is told even when it repeats, once
    /// `desired` was `sampled` after the observation was written.
    pub(super) fn reconcile(
        &mut self,
        desired: [NodeLevel; KINDS],
        sampled: bool,
    ) -> Vec<NodeLevel> {
        let owed = sampled && std::mem::take(&mut self.port_answer_owed);
        let mut tell = Vec::new();
        for level in desired {
            let kind = level.kind();
            let answer = owed && matches!(level, NodeLevel::ExternUdpPort(_));
            if answer || (self.told[kind] != Some(level) && self.in_flight[kind] != Some(level)) {
                self.in_flight[kind] = Some(level);
                tell.push(level);
            }
        }
        tell
    }

    /// The node took `level`.
    pub(super) fn landed(&mut self, level: NodeLevel) {
        let kind = level.kind();
        self.told[kind] = Some(level);
        self.deferred[kind] = false;
        self.settle(level);
    }

    /// `level` never reached the node: it holds what it held, and the next
    /// input restates it. A full inbox is logged; a gone node is not, since
    /// the pump ends with it.
    pub(super) fn refused(&mut self, level: NodeLevel, inbox_full: bool) {
        self.settle(level);
        if inbox_full && !std::mem::replace(&mut self.deferred[level.kind()], true) {
            tracing::warn!(
                ?level,
                "kad command inbox full; level deferred to the next input"
            );
        }
    }

    /// No level is on its way to the node or waits for room: the node holds
    /// every level it was told, the last outcome it heard of.
    pub(super) fn settled(&self) -> bool {
        self.in_flight.iter().all(Option::is_none) && !self.waiting_for_room()
    }

    /// A level a full inbox turned away waits to be restated.
    pub(super) fn waiting_for_room(&self) -> bool {
        self.deferred.contains(&true)
    }

    fn settle(&mut self, level: NodeLevel) {
        let in_flight = &mut self.in_flight[level.kind()];
        if *in_flight == Some(level) {
            *in_flight = None;
        }
    }
}

/// The whole desired node state: the TCP verdict from the self-check store,
/// everything else from the owners' latest samples. `kad_udp_key` is the seed
/// an armed node's verify keys derive from.
pub(super) fn desired(
    tcp: TcpReachability,
    sample: &KadPumpSample,
    kad_udp_key: u32,
) -> [NodeLevel; KINDS] {
    let public_ip = sample
        .own_address
        .public_ip
        .unwrap_or(Ipv4Addr::UNSPECIFIED);
    let natt = if sample.reach.natt_live {
        RMULE_NATT_CLAIM
    } else {
        HelloNattClaim::default()
    };
    let posture = if sample.reach.firewalled {
        rmule_kad::KadPublishPosture::Firewalled {
            buddy: sample
                .buddy
                .publish
                .map(|publish| rmule_kad::KadBuddyContact {
                    buddy_id: publish.buddy_id,
                    buddy_udp: Some(publish.buddy_udp),
                    buddy_ipv6: publish.buddy_ipv6,
                    buddy_udp_ipv6: None,
                }),
        }
    } else {
        rmule_kad::KadPublishPosture::Reachable
    };
    [
        NodeLevel::TcpFirewalled(!tcp.is_reachable()),
        NodeLevel::OwnPublicIp(public_ip),
        NodeLevel::ExternUdpPort(sample.own_address.learned_udp_port.unwrap_or(0)),
        NodeLevel::PublishConnectOptions(publish_connect_options(
            sample.crypt,
            sample.reach.accepts_direct_udp_callback,
            natt,
        )),
        NodeLevel::PublishPosture(posture),
        NodeLevel::DatagramCrypt(KadCryptArm {
            kad_udp_key,
            public_ip,
            sends: sample.crypt.is_some(),
        }),
        NodeLevel::AdvertisedIpv6(sample.advertised_ipv6),
    ]
}

/// The **Publish Connect Options**: the `TAG_ENCRYPTION`
/// byte this node's source publishes state, composed from three facts the
/// caller fetched from their owners — our obfuscation policy, whether the ADR-0060
/// verdicts earn the direct-UDP-callback bit, and the NAT-T transports the
/// front on the Kad node's socket serves (the one socket a punch toward a
/// published row lands on).
///
/// What the byte means depends on who wrote it, and this writes the widest
/// family's form:
///
/// - **aMule** (Fork Pin `ab483654`) `CPrefs::GetMyConnectOptions(true, true)`,
///   `src/kademlia/kademlia/Prefs.cpp:214-233`, at the publish site
///   `src/kademlia/kademlia/Search.cpp:883-884`: four reserved high bits, then
///   direct callback (`IsFirewalled() && Kad running && !IsFirewalledUDP(true)
///   && IsVerified()`) and the crypt ladder — `0x0F` at most.
/// - **eMule 0.70b** (`irwir/eMule@13983526`) `CPrefs::GetMyConnectOptions`
///   delegates (`srchybrid/kademlia/kademlia/Prefs.cpp:461-464`) to the global
///   `::GetMyConnectOptions` (`srchybrid/OtherFunctions.cpp:3855-3871`), which
///   assembles the same four bits — `0x0F` at most; publish site
///   `srchybrid/kademlia/kademlia/Search.cpp:691`.
/// - **eMuleAI** (`a2f05dc8`) delegates the same way
///   (`srchybrid/kademlia/kademlia/Prefs.cpp:486-489`) to a global
///   `::GetMyConnectOptions` (`srchybrid/OtherFunctions.cpp:4122-4147`) that
///   also ORs `0x80` (uTP NAT-T) and `0x40` (QUIC NAT-T) while its NAT-T
///   endpoint is ready; publish site `srchybrid/kademlia/kademlia/Search.cpp:913`.
///
/// An aMule or eMule reader ignores the high bits it reserves; an eMuleAI or
/// rmule reader takes `0x80` as a punchable source. `natt` is what the front
/// serves, not what the build can speak: QUIC stays dark until a live
/// handshake proves it (ADR-0091). The front's liveness is read on every
/// compose, never a bind-time snapshot, and announced by the Reach Generation
/// when it ends.
///
/// Always a byte, zero included: every bit has an owner that answered, so a
/// zero is their joint answer — the one a crypt-less aMule states too — and
/// not a default. Silence belongs to a node with no owners behind it.
pub(super) fn publish_connect_options(
    obfuscation: Option<ObfuscationPolicy>,
    direct_udp_callback: bool,
    natt: HelloNattClaim,
) -> u8 {
    let crypt = rmule_peer::peer_udp::crypt::connect_options_from_stance(
        ObfuscationPolicy::stance_of(obfuscation),
    );
    rmule_peer::natt::NattConnectOptions::advertise(crypt, natt.utp, natt.quic).as_byte()
        | if direct_udp_callback {
            CONNECT_OPT_DIRECT_UDP_CALLBACK
        } else {
            0
        }
}

/// `CONNECT_OPT_DIRECT_UDP_CALLBACK`: this node accepts an
/// `OP_DIRECTCALLBACKREQ` (`0x95`) at its Kad UDP port.
const CONNECT_OPT_DIRECT_UDP_CALLBACK: u8 = 0x08;

/// The Publish Connect Options composition, bit by bit against the three
/// families' `GetMyConnectOptions`.
#[cfg(test)]
mod tests {
    use rmule_net::peer::ObfuscationPolicy;
    use rmule_peer::natt::HelloNattClaim;

    use super::publish_connect_options;

    const NO_NATT: HelloNattClaim = HelloNattClaim {
        utp: false,
        quic: false,
    };
    const UTP: HelloNattClaim = HelloNattClaim {
        utp: true,
        quic: false,
    };

    /// The captured aMule publish (`amule-233-publish-source-req-20260922`)
    /// carries `0x00`: a crypt-less publisher, firewalled behind a buddy (so
    /// no direct callback), with no NAT-T. The same three facts compose the
    /// same byte here — the capture KAT's told input is this function's
    /// output, stated rather than left silent.
    #[test]
    fn a_crypt_less_buddy_publisher_without_natt_composes_the_captured_zero() {
        assert_eq!(publish_connect_options(None, false, NO_NATT), 0x00);
    }

    /// Each owner lights only its own bits: the crypt ladder `0x07`, the
    /// ADR-0060 direct-callback verdict `0x08`, and the served NAT-T
    /// transports `0x80`/`0x40` — never the reserved `0x10` or the
    /// endpoint-hint request `0x20`, which is a rendezvous request, not a
    /// capability.
    #[test]
    fn each_fact_lights_only_its_own_bits() {
        let both = HelloNattClaim {
            utp: true,
            quic: true,
        };
        let requested = Some(ObfuscationPolicy::Requested);
        let required = Some(ObfuscationPolicy::Required);
        for (policy, callback, natt, byte) in [
            (None, false, UTP, 0x80),
            (requested, false, NO_NATT, 0x03),
            (required, false, NO_NATT, 0x07),
            (None, true, NO_NATT, 0x08),
            (requested, false, UTP, 0x83),
            (required, true, UTP, 0x8F),
            (None, false, both, 0xC0),
        ] {
            assert_eq!(
                publish_connect_options(policy, callback, natt),
                byte,
                "{policy:?} callback={callback} {natt:?}"
            );
        }
    }
}
