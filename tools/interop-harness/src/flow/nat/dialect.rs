//! The **IPv6 dialect** flows (ADR-0092): `ipv6-hello-tags`,
//! `ipv6-extsx` (with its `ipv6-extsx-kno`, `ipv6-extsx-emit` and `ipv6-download-rung0`
//! siblings), `ipv6-direct-dial-lowid`, `ipv6-kad-tags`, `ipv6-server-sentinel` and
//! `ipv6-udp-key`.
//!
//! Every one stands up the same bench — one dual-stack fake-public WAN, the bodies
//! ADR-0087's evidence table names for the surface under test, a **Capture
//! Sidecar** on the body's own attachment, and rmule driven from a one-shot
//! `rmule-tools ipv6 …` container — and differ in which body they stand up and
//! which sentence they are trying to settle. There is no translation in these
//! flows, so there is no **NAT Gateway** and no **NAT Type Proof**: these rows are
//! about tags, key layouts and route choices, not about address rewriting.
//!
//! **What is evidence here.** The counterparty's own `OP_HELLOANSWER`, its
//! obfuscated reask reply, its login and `OP_SERVERIDENT` burst, and its own
//! log lines. Everything rmule reports about itself is Stimulus (ADR-0045) and
//! is recorded beside those bytes so the two can be read against each other.
//!
//! **Evidence class per surface** is carried in the verdict rather than left to
//! a reader: the hello block and the UDP key have two independent oracles
//! (emule-qt `73fff714` and kno's aMule `ab483654`), while `0x26` and
//! `OP_SERVERLIST`'s trailing v6 block have exactly one (eNode-go), which
//! ADR-0087 already says and every verdict here repeats as a
//! `single-oracle` row.

pub(crate) mod bench;
mod download_rung0;
mod ext_sx;
mod ext_sx_core;
mod ext_sx_emit;
mod ext_sx_kno;
mod hello_surface;
mod kad_tags;
pub(crate) mod legs;
pub(crate) mod verdict;

use anyhow::Result;

pub use self::bench::Ipv6DialectOptions;

/// Which IPv6-dialect flow is running.
///
/// One enum and one bench rather than six entry points, for the reason
/// `PortMapFlow` already has: the topology is the same and only the bodies and
/// the drive sequence differ, so six copies would let the address plan drift
/// between rows that cite each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6Flow {
    /// The `0xAA` claim and the `CT_MOD_IP_V6` round trip, plus the
    /// legacy-safety leg against stock aMule 2.3.3.
    HelloTags,
    /// ExtSX as the IPv6 carrier in source exchange.
    ExtSx,
    /// The same ask put to kno's aMule, ADR-0087's second ExtSX oracle.
    ExtSxKno,
    /// Roles swapped: rmule writes the ExtSX record, emule-qt admits it.
    ExtSxEmit,
    /// An rmule download dials a Low-ID source's ExtSX IPv6 half first.
    DownloadRung0,
    /// rmule's production requester asks stock aMule 2.3.3 for a complete
    /// file's sources.
    ExtSxCore,
    /// Rung 0: a Low-ID peer that named an IPv6 is dialled directly.
    DirectDialLowId,
    /// The Kad `ip6` tag published and parsed.
    KadTags,
    /// A capable server emits a **Sentinel Source** to a capable session.
    ServerSentinel,
    /// The 35-byte client-UDP key decrypts a v6 datagram both ways.
    UdpKey,
    /// Not a dialect row: the three client bodies, each dialled by rmule, dialling
    /// rmule, serving it and served by it, with rmule meeting rmule beside them.
    /// It borrows this bench because the bench already holds them.
    HelloSurface,
}

impl Ipv6Flow {
    /// Every flow, in the order ADR-0092 lists them.
    pub const ALL: [Self; 11] = [
        Self::HelloTags,
        Self::ExtSx,
        Self::ExtSxKno,
        Self::ExtSxEmit,
        Self::DownloadRung0,
        Self::ExtSxCore,
        Self::DirectDialLowId,
        Self::KadTags,
        Self::ServerSentinel,
        Self::UdpKey,
        Self::HelloSurface,
    ];

    /// The flow's name in every artifact it writes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::HelloTags => "ipv6-hello-tags",
            Self::ExtSx => "ipv6-extsx",
            Self::ExtSxKno => "ipv6-extsx-kno",
            Self::ExtSxEmit => "ipv6-extsx-emit",
            Self::DownloadRung0 => "ipv6-download-rung0",
            Self::ExtSxCore => "ipv6-extsx-core",
            Self::DirectDialLowId => "ipv6-direct-dial-lowid",
            Self::KadTags => "ipv6-kad-tags",
            Self::ServerSentinel => "ipv6-server-sentinel",
            Self::UdpKey => "ipv6-udp-key",
            Self::HelloSurface => "peer-hello-surface",
        }
    }

    /// Parse a flow name.
    ///
    /// # Errors
    /// If `name` is not one of the flows.
    pub fn from_name(name: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|flow| flow.name() == name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown IPv6 dialect flow `{name}`; the harness carries {}",
                    Self::ALL.map(Self::name).join(", ")
                )
            })
    }

    /// Whether the flow needs kno's aMule standing up.
    #[must_use]
    pub const fn needs_amule_kno(self) -> bool {
        matches!(
            self,
            Self::HelloTags
                | Self::ExtSxKno
                | Self::DirectDialLowId
                | Self::KadTags
                | Self::UdpKey
                | Self::HelloSurface
        )
    }

    /// Whether the flow needs emule-qt standing up.
    #[must_use]
    pub const fn needs_emuleqt(self) -> bool {
        matches!(
            self,
            Self::HelloTags
                | Self::ExtSx
                | Self::ExtSxEmit
                | Self::DownloadRung0
                | Self::KadTags
                | Self::UdpKey
                | Self::HelloSurface
        )
    }

    /// Whether the flow needs a **stock** aMule 2.3.3 — the legacy oracle of
    /// ADR-0087's last evidence row, whose whole job is to ignore every new tag
    /// and say nothing about it.
    #[must_use]
    pub const fn needs_legacy_amule(self) -> bool {
        matches!(self, Self::HelloTags | Self::ExtSxCore | Self::HelloSurface)
    }

    /// Whether the flow needs the `ed2ksrv` counterparty — the sentinel row's
    /// subject, and the High ID that lets kno publish a source at all in
    /// `ipv6-kad-tags`.
    #[must_use]
    pub const fn needs_ed2ksrv(self) -> bool {
        matches!(
            self,
            Self::ServerSentinel
                | Self::KadTags
                | Self::ExtSxEmit
                | Self::DownloadRung0
                | Self::ExtSxCore
                | Self::HelloSurface
        )
    }
}

/// The peer TCP port every body listens on.
pub(crate) const BODY_PEER_TCP_PORT: u16 = 4662;

/// The client-UDP port every body muxes reask and Kad on.
pub(crate) const BODY_CLIENT_UDP_PORT: u16 = 4672;

/// The eD2k TCP port `ed2ksrv` listens on.
pub(crate) const ED2KSRV_TCP_PORT: u16 = 4661;

/// The fake-public `/24` index the IPv6-dialect WAN takes. Index 2 is
/// `45.55.200.0/24`, the only prefix both aMule and emule-qt admit — indices 0
/// and 1 are the RFC 5737 ranges emule-qt's `isPublicIP()` rejects, so a mixed
/// topology on either would fail for a v4 reason while looking like a v6 one.
pub(crate) const WAN_SUBNET_INDEX: usize = 2;

/// The **Fake-Public v6 Plan** `/64` the WAN takes.
pub(crate) const WAN_V6_NET: u16 = 1;

/// Run one IPv6-dialect flow.
///
/// # Errors
/// If the bench cannot be stood up, a driver never produced a row, or the
/// verdict cannot be written. A counterparty that declines to speak the dialect
/// is **not** an error — that is the row the flow exists to take.
pub fn run_ipv6_dialect(options: Ipv6DialectOptions<'_>) -> Result<()> {
    bench::run(options)
}
