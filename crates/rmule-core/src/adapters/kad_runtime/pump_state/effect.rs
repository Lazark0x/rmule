//! What the **Kad Pump State** asks the world to do. The brain touches
//! nothing itself: the pump's driver carries out each effect in order, and
//! the few whose outcome the brain needs are answered with an input — a node
//! command with `Delivered`, an Address Learning write with `Sampled`, the
//! open-node buddy service's accept with `SlotAnswered`. The Firewalled
//! Front's verdict on a buddy it was asked to adopt comes back later, from
//! its own task, as `BuddyVerdict`.
//!
//! The brain holds where a search or a download hears back — a search's sink,
//! a Callback Walk's retire channel — as an address it never writes to: an
//! effect carries the address, and the driver delivers.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use rmule_kad::{KadId, KadPublishPosture};
use rmule_primitives::{FileHash, Ipv4Endpoint, SearchResult, UserHash};

use super::keyword_subscribers::SearchSink;
use crate::adapters::kad_runtime::CallbackWalkReply;
use crate::address_learning::AddressObservation;
use crate::diagnostics::{KadFirewallCheck, NattRetirement};
use crate::firewalled::link::RecruitedBuddy;
use crate::firewalled::recruit::{FindBuddyRes, RecruitStatus};
use crate::reachability::{TcpReachability, UdpReachability};
use crate::search::KadWalkFact;

/// One thing the driver must do.
#[derive(Debug, PartialEq)]
pub(crate) enum KadPumpEffect {
    /// Tell the node something, without waiting: the pump is the handle's
    /// sole event drainer, so an awaited command could deadlock against a
    /// driver blocked emitting events. Answered with `Delivered`.
    Node(NodeCommand),
    /// A source walk's answer for the discovery task: every row that names a
    /// road, the refusals included.
    Sources {
        file_hash: FileHash,
        answer: crate::kad_sources::KadAnswer,
    },
    /// News for one search riding a keyword walk (ADR-0062), screened by
    /// its own query.
    Search { sink: SearchSink, news: SearchNews },
    /// A Callback Walk that will send no `0x52`, for the download waiting on
    /// it: its candidate retires so. Never stalls the pump: a verdict the
    /// download's full channel turns away leaves the candidate to its slot's
    /// own deadline.
    CallbackWalkRetired {
        reply: CallbackWalkReply,
        reason: NattRetirement,
    },
    /// A write to **Address Learning**, answered with a fresh `Sampled`.
    Address(AddressWrite),
    /// A flood offender the node reported, banned at the peer-TCP surface
    /// (ADR-0064): Kad's own datagram path never consults the ban store.
    Ban { ip: Ipv4Addr, at: Instant },
    /// A write to the Kad family of **Self Reach**.
    Verdict(VerdictWrite),
    /// A write to the Kad half of the **Awaited Testers**.
    Testers(TesterWrite),
    /// A diagnostics write.
    Diagnostics(DiagnosticsWrite),
    /// A `0x5A` our walk drew, for the Firewalled Front — the buddy slot's
    /// one owner — to adopt; its verdict comes back as `BuddyVerdict`.
    AdoptBuddy {
        answer: FindBuddyRes,
        buddy: RecruitedBuddy,
    },
    /// The recruit rule's **Recruit Status**, published for every reader of
    /// the buddy level; stated only when it moved.
    Recruit(RecruitStatus),
    /// Work the driver runs beside the pump's path.
    Spawn(Spawn),
}

/// A command the node is told.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NodeCommand {
    /// A level the node caches from an owner outside it.
    Level(NodeLevel),
    /// One of the core's asks, told one at a time in the order the core sent
    /// them, each once the node holds every level.
    Ask(rmule_kad::KadCommand),
    /// The ADR-0061 FINDBUDDY walk toward `~ourKadID`.
    FindBuddyWalk { target: KadId },
    /// The ADR-0061 `0x5A` answer to a firewalled peer's FINDBUDDY.
    AnswerFindBuddy {
        requester: Ipv4Endpoint,
        buddy_id: KadId,
    },
}

/// The node's caches of facts it never derives: the reconciler's whole
/// desired node state, one level at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NodeLevel {
    /// The injected TCP verdict (ADR-0058): what arms the UDP tester's
    /// conclude gate.
    TcpFirewalled(bool),
    /// The IPv4 the node's verify keys bind to; `0.0.0.0` while none is known.
    OwnPublicIp(Ipv4Addr),
    /// The **Extern Kad Port**; `0` while none is learned.
    ExternUdpPort(u16),
    /// The **Publish Connect Options** byte every source publish states.
    PublishConnectOptions(u8),
    /// Whether the node publishes as reachable, or firewalled behind which
    /// buddy.
    PublishPosture(KadPublishPosture),
    /// The node's Kad-UDP crypt under the one obfuscation policy (ADR-0046):
    /// the verify keys always, and send-obfuscation while the policy is set.
    DatagramCrypt(KadCryptArm),
    /// The **Advertised IPv6** every source publish's `ip6` tag names
    /// (ADR-0087); `None` names none.
    AdvertisedIpv6(Option<Ipv6Addr>),
}

/// The Kad-UDP crypt: the Kad UDP Key the verify keys derive from, and
/// the public IPv4 a learned key binds to — the same address
/// [`NodeLevel::OwnPublicIp`] states, since a re-arm installs the keys whole.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct KadCryptArm {
    /// The **Kad UDP Key**, never transmitted.
    pub(crate) kad_udp_key: u32,
    /// Our public IPv4, `0.0.0.0` while none is known.
    pub(crate) public_ip: Ipv4Addr,
    /// Whether datagrams leave obfuscated: the policy is set. The keys open
    /// what arrives either way.
    pub(crate) sends: bool,
}

/// The key is withheld: a level is logged when a full inbox defers it, and
/// the seed never leaves the node.
impl std::fmt::Debug for KadCryptArm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KadCryptArm")
            .field("public_ip", &self.public_ip)
            .finish_non_exhaustive()
    }
}

impl NodeCommand {
    /// The node command that enacts this one.
    pub(crate) fn command(&self) -> rmule_kad::KadCommand {
        use rmule_kad::KadCommand;
        match *self {
            Self::Level(NodeLevel::TcpFirewalled(firewalled)) => {
                KadCommand::SetTcpReachability { firewalled }
            }
            Self::Level(NodeLevel::OwnPublicIp(public_ip)) => {
                KadCommand::SetOwnPublicIp { public_ip }
            }
            Self::Level(NodeLevel::ExternUdpPort(port)) => KadCommand::SetExternalUdpPort { port },
            Self::Level(NodeLevel::PublishConnectOptions(options)) => {
                KadCommand::SetPublishConnectOptions {
                    options: Some(options),
                }
            }
            Self::Level(NodeLevel::PublishPosture(posture)) => {
                KadCommand::SetPublishPosture { posture }
            }
            Self::Level(NodeLevel::DatagramCrypt(arm)) => KadCommand::SetObfuscation {
                obfuscation: Some(if arm.sends {
                    rmule_kad::KadObfuscation::new(rmule_net::kad::os_datagram_nonce)
                        .with_verify_keys(arm.kad_udp_key, arm.public_ip)
                } else {
                    rmule_kad::KadObfuscation::receive_only(arm.kad_udp_key, arm.public_ip)
                }),
            },
            Self::Level(NodeLevel::AdvertisedIpv6(address)) => {
                KadCommand::SetAdvertisedIpv6 { address }
            }
            Self::Ask(ref command) => command.clone(),
            Self::FindBuddyWalk { target } => KadCommand::FindBuddyWalk { target },
            Self::AnswerFindBuddy {
                requester,
                buddy_id,
            } => KadCommand::AnswerFindBuddy {
                requester: rmule_kad::KadNodeEndpoint::new(requester.ip, requester.port),
                buddy_id,
                // The v7+ connect-options byte advertises our crypt stance;
                // it is not threaded into this pump yet, so the plain form
                // goes (aMule tolerates its absence).
                // `[pending]` the `0x5A` connect-options byte.
                connect_options: None,
            },
        }
    }
}

/// What one search riding a keyword walk hears (ADR-0062).
#[derive(Debug, PartialEq)]
pub(crate) enum SearchNews {
    /// Rows its own query proves: lossy on a full sink by design, since a
    /// slow search must not hold the pump.
    Rows(Vec<SearchResult>),
    /// A fact about the walk: never lost while the search listens.
    Fact(KadWalkFact),
}

/// A write to Address Learning (ADR-0084).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AddressWrite {
    /// One rung of a ladder: a Kad `0x58` address or `0x61` port report.
    Observe(AddressObservation),
    /// An **Extern Port Round** began: forget the UDP role's Kad port reports
    /// (aMule's `FindExternKadPort(true)`).
    ForgetKadPortRound,
}

/// A write to the published Kad verdicts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VerdictWrite {
    /// The ≥2-ack TCP verdict.
    Tcp(TcpReachability),
    /// The UDP tester's verdict.
    Udp(UdpReachability),
    /// What the TCP check has drawn so far.
    TcpCheck(KadFirewallCheck),
    /// aMule's `HasHadContact` latch (ADR-0067), stated once per node.
    Joined,
}

/// A write to the Awaited Testers' Kad half (ADR-0046 "Test Connections").
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TesterWrite {
    /// A helper was asked: its connect-back may dial plain until `until`.
    Asked { helper: Ipv4Addr, until: Instant },
    /// The windows this node opened close, and no others: the cell is shared
    /// across Kad restarts.
    Dropped { helpers: Vec<(Ipv4Addr, Instant)> },
}

/// A write to the diagnostics the snapshot reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DiagnosticsWrite {
    /// The live routing-table size.
    ContactCount(usize),
    /// The node's keyword index size.
    KeywordsStored(usize),
    /// A datagram that opened like Kad and did not decode.
    UndecodableEnvelope,
}

/// Work the driver runs beside the pump's path.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Spawn {
    /// ADR-0058 responder: broker the dial-back the node already answered.
    DialBack {
        requester: Ipv4Endpoint,
        connect_options: Option<u8>,
        user_hash: Option<UserHash>,
    },
    /// ADR-0058 requester, UDP half: dial the engaged helper and send its
    /// `0xA7`.
    UdpFirewallCheck {
        helper: Ipv4Endpoint,
        request: Vec<u8>,
    },
    /// ADR-0061 open-node service: answer a firewalled peer's FINDBUDDY.
    FindBuddy {
        requester: Ipv4Endpoint,
        buddy_id: KadId,
        requester_hash: UserHash,
        requester_tcp_port: u16,
    },
    /// ADR-0061 open-node relay over the held buddy link.
    CallbackRelay {
        requester: Ipv4Endpoint,
        buddy_id: KadId,
        file_hash: FileHash,
        requester_tcp_port: u16,
    },
}
