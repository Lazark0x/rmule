//! The **NAT traversal** flows (ADR-0091/ADR-0092).
//!
//! NAT traversal is the ladder's top rung: two firewalled peers reaching each other
//! by being introduced, punching, and raising a **Tunnel** over the pinhole.
//! What a flow here measures is therefore always one of two things — a
//! counterparty's own `0xB2` bytes (the transport half, which kno's fork is the
//! only pinned body to carry), or an `rmule-only` row where both ends are rmule
//! because no third party has adopted the pairing (ADR-0045's 2026-09-16
//! amendment).
//!
//! Every flow behind a **NAT Gateway** attaches its **NAT Type Proof**, and
//! every negative one additionally runs the **Reflector Probe** in the same
//! run: ADR-0045 makes a punch failure without proven NAT type, the outbound
//! conntrack entry and the counterparty's own zero a *fabricated row*.

pub(crate) mod bench;
pub(crate) mod buddy;
pub(crate) mod legs;
pub(crate) mod punch;
pub(crate) mod verdict;

use anyhow::Result;

pub use self::bench::NattOptions;

/// Which NAT-traversal flow is running.
///
/// One enum and one bench rather than one entry point per row, for the reason
/// `Ipv6Flow` and `PortMapFlow` already have: the topology is shared and only
/// the bodies and the drive sequence differ, so separate copies would let the
/// address plan drift between rows that cite each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NattFlow {
    /// The dialect's three opening frames against kno's aMule: the `CAPS`
    /// probe, the `KEY` frame a dial arms, and a uTP `ST_SYN`.
    CapsUtp,
    /// Two rmule peers behind two **full-cone-pinned** gateways, introduced by
    /// an `ed2ksrv`: `0x60` in, `0x61` to both, punch and Tunnel.
    ServerPunchCone,
    /// The same topology behind two **symmetric** gateways — the honest
    /// negative, with the whole ADR-0045 kit in the same run.
    ServerPunchSymmetric,
    /// **Port prediction**: the requester behind a **symmetric**
    /// gateway, the responder behind a **port-restricted** one, both with
    /// `natt.port_prediction = birthday` and three open Kad observers that
    /// tell each its own mapping. One run is one draw of a probabilistic
    /// pairing; its claims check the draw, not the luck.
    ServerPunchOneSymmetric,
    /// The punch topology again, driven by a real **download**: one Low-ID
    /// rmule fetches a file from another over the Tunnel the introduction's
    /// punch raises. Rung 1 of the ADR-0061 tree, end to end.
    TunnelTransfer,
    /// ADR-0091's **second** Rendezvous coordinator behind two
    /// **full-cone-pinned** gateways: a firewalled target recruits an open
    /// buddy over a live Kad FINDBUDDY walk, and a firewalled requester
    /// reaches it by embedding an `OP_RENDEZVOUS` in a `0x94` addressed to
    /// that buddy.
    BuddyRendezvousCone,
    /// The same topology behind two **restricted** gateways (EIM + ADF).
    BuddyRendezvousRestricted,
    /// The same topology behind two **symmetric** gateways — the honest
    /// negative, with the whole ADR-0045 kit in the same run.
    BuddyRendezvousSymmetric,
    /// The buddy topology driven by a real **download**: the
    /// target publishes a buddy row once its buddy is held, a placed mesh
    /// member stores it, and the requester — handed only the ed2k link —
    /// finds it over Kad and fetches the file over the Tunnel the buddy
    /// coordinates. The `natt-tunnel-transfer` shape on the buddy path, behind two
    /// **full-cone-pinned** gateways.
    BuddyTransferCone,
    /// ADR-0058's **UDP self-check** end to end: a firewalled
    /// target behind a **full-cone-pinned** gateway finds two fresh UDP
    /// Firewall Helpers through its own helper lookup, asks them over peer
    /// TCP, reads its UDP verdict open off their `0x62`, and publishes the
    /// type-6 row with the direct-callback bit to a placed storer.
    UdpSelfCheckCone,
    /// The same self-check behind a gateway that **remaps** the target's Kad
    /// port: `full-cone-pinned` with the public port pinned
    /// away from the client's, so a `0x62` aimed at the intern port dies at
    /// the gateway and only one aimed at the learned **Extern Kad Port**
    /// lands.
    UdpSelfCheckRemapped,
    /// `natt-udp-selfcheck-cone`'s self-check with the firewalled body **stock aMule 2.3.3** on
    /// the debug image: aMule's own UDP verdict against two
    /// fresh rmule helpers, and whatever publish that verdict earns, read off
    /// a sidecar in the storer's netns — the aMule-authored tier of
    /// ADR-0061's type-6 row.
    UdpSelfCheckAmule,
    /// ADR-0061's firewalled half against stock aMule 2.3.3 as the open
    /// buddy: a Core rmule behind a **port-restricted** gateway, holding a
    /// server Low ID, recruits aMule over Kad, holds and pings the link, and
    /// dials back the requester of a callback aMule relays over it.
    BuddyRecruitAmule,
}

impl NattFlow {
    /// Every flow this harness carries, in ADR-0092's order.
    pub const ALL: [Self; 13] = [
        Self::CapsUtp,
        Self::ServerPunchCone,
        Self::ServerPunchSymmetric,
        Self::ServerPunchOneSymmetric,
        Self::TunnelTransfer,
        Self::BuddyRendezvousCone,
        Self::BuddyRendezvousRestricted,
        Self::BuddyRendezvousSymmetric,
        Self::BuddyTransferCone,
        Self::UdpSelfCheckCone,
        Self::UdpSelfCheckRemapped,
        Self::UdpSelfCheckAmule,
        Self::BuddyRecruitAmule,
    ];

    /// The flow's name in every artifact it writes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CapsUtp => "natt-caps-utp",
            Self::ServerPunchCone => "natt-server-punch-cone",
            Self::ServerPunchSymmetric => "natt-server-punch-symmetric",
            Self::ServerPunchOneSymmetric => "natt-server-punch-one-symmetric",
            Self::TunnelTransfer => "natt-tunnel-transfer",
            Self::BuddyRendezvousCone => "natt-buddy-rendezvous-cone",
            Self::BuddyRendezvousRestricted => "natt-buddy-rendezvous-restricted",
            Self::BuddyRendezvousSymmetric => "natt-buddy-rendezvous-symmetric",
            Self::BuddyTransferCone => "natt-buddy-transfer-cone",
            Self::UdpSelfCheckCone => "natt-udp-selfcheck-cone",
            Self::UdpSelfCheckRemapped => "natt-udp-selfcheck-remapped",
            Self::UdpSelfCheckAmule => "natt-udp-selfcheck-amule",
            Self::BuddyRecruitAmule => "natt-buddy-recruit-amule",
        }
    }

    /// Parse a flow name.
    ///
    /// # Errors
    /// If `name` is not one this harness carries. The NAT-traversal rows ADR-0092
    /// lists but this harness cannot yet drive are *absent* from the enum on
    /// purpose: a name that resolved to a flow with no drive sequence would
    /// write a verdict nobody measured.
    pub fn from_name(name: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|flow| flow.name() == name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown NAT-T flow `{name}`; the harness carries {}",
                    Self::ALL.map(Self::name).join(", ")
                )
            })
    }

    /// Whether the flow needs kno's aMule standing up.
    #[must_use]
    pub const fn needs_amule_kno(self) -> bool {
        matches!(self, Self::CapsUtp)
    }

    /// The **NAT Gateway** type this flow stands its peers behind, or `None`
    /// for a row with no translation on the path.
    #[must_use]
    pub const fn nat_type(self) -> Option<crate::nat::NatType> {
        match self {
            Self::CapsUtp => None,
            Self::ServerPunchCone
            | Self::TunnelTransfer
            | Self::BuddyRendezvousCone
            | Self::BuddyTransferCone
            | Self::UdpSelfCheckCone
            | Self::UdpSelfCheckRemapped
            | Self::UdpSelfCheckAmule => Some(crate::nat::NatType::FullConePinned),
            Self::BuddyRendezvousRestricted => Some(crate::nat::NatType::Restricted),
            Self::BuddyRecruitAmule => Some(crate::nat::NatType::PortRestricted),
            Self::ServerPunchSymmetric
            | Self::ServerPunchOneSymmetric
            | Self::BuddyRendezvousSymmetric => Some(crate::nat::NatType::Symmetric),
        }
    }

    /// The two punch peers' gateways, requester first. Every row but the
    /// one-symmetric one stands both peers behind the same type.
    #[must_use]
    pub const fn peer_nat_types(self) -> Option<[crate::nat::NatType; 2]> {
        match (self, self.nat_type()) {
            (Self::ServerPunchOneSymmetric, _) => Some([
                crate::nat::NatType::Symmetric,
                crate::nat::NatType::PortRestricted,
            ]),
            (_, Some(nat_type)) => Some([nat_type, nat_type]),
            (_, None) => None,
        }
    }

    /// Whether the flow stands stock aMule up from the **debug** image
    /// Never built here: `--build-images` would build the
    /// release package under the debug tag, so the image is pre-built by hand.
    #[must_use]
    pub const fn needs_amule_debug(self) -> bool {
        matches!(self, Self::UdpSelfCheckAmule | Self::BuddyRecruitAmule)
    }

    /// Whether the flow needs the `ed2ksrv` coordinator.
    ///
    /// The rendezvous rows deliberately need none: their coordinator *is* the
    /// buddy, and a server on the path would put ADR-0091's preferred
    /// coordinator ahead of the rung being measured. `natt-buddy-recruit-amule`
    /// needs one for another reason: it gives the target the Low ID an open
    /// aMule keeps a buddy for, and coordinates nothing — no punch is asked.
    #[must_use]
    pub const fn needs_ed2ksrv(self) -> bool {
        matches!(
            self,
            Self::ServerPunchCone
                | Self::ServerPunchSymmetric
                | Self::ServerPunchOneSymmetric
                | Self::TunnelTransfer
                | Self::BuddyRecruitAmule
        )
    }

    /// Whether the flow needs the `natprobe` **Reflector Probe** — every row
    /// that stands a gateway up, because every one of them cites a NAT Type
    /// Proof the probe's observation half fills in.
    #[must_use]
    pub const fn needs_natprobe(self) -> bool {
        self.nat_type().is_some()
    }

    /// Whether the flow stands the **buddy rendezvous** topology up rather
    /// than the server-coordinated punch one.
    #[must_use]
    pub const fn is_buddy_rendezvous(self) -> bool {
        matches!(
            self,
            Self::BuddyRendezvousCone
                | Self::BuddyRendezvousRestricted
                | Self::BuddyRendezvousSymmetric
                | Self::BuddyTransferCone
        )
    }
}

/// The peer TCP port every body listens on.
pub(crate) const BODY_PEER_TCP_PORT: u16 = 4662;

/// The client-UDP port every body muxes reask, Kad and NAT-T on (ADR-0057's unified socket).
/// A NAT-T exchange must leave the one advertised bind,
/// so the driver pins the same number on its own side.
pub(crate) const BODY_CLIENT_UDP_PORT: u16 = 4672;

/// The fake-public `/24` index the NAT-traversal WAN takes — `45.55.200.0/24`, the
/// one prefix both aMule and emule-qt admit, so a mixed topology never fails
/// for an address-classification reason while looking like a transport one.
pub(crate) const WAN_SUBNET_INDEX: usize = 2;

/// Run one NAT-traversal flow.
///
/// # Errors
/// If the bench cannot be stood up, a driver never produced a row, or the
/// verdict cannot be written. A counterparty that declines to speak the dialect
/// is **not** an error — that is the row the flow exists to take.
pub fn run_natt(options: NattOptions<'_>) -> Result<()> {
    bench::run(options)
}
