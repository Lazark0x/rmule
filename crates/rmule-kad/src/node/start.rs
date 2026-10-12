//! The node's one **start-up value**: everything a driver decides before the
//! node handles its first datagram, command, or tick.
//!
//! The node reads no clock and draws no entropy (ADR-0043), so the start
//! instant and every entropy source arrive here. [`KadNode::new`] applies the
//! value in the one order that is correct — admission, join cadence,
//! self-check, then obfuscation with its verify keys — so no caller can arm
//! them out of order or arm keys over a plaintext sender: verify keys exist
//! only inside a [`KadObfuscation`], because the trailer rides inside the
//! crypt header.

use std::net::Ipv4Addr;

use rmule_primitives::DatagramNonce;

use super::{KadContactAdmission, KadNode, KadNodeConfig, VerifyKeyState};
use crate::{KadId, KadInstant};

/// Everything a [`KadNode`] is started with. Build with [`new`](Self::new) —
/// a routing-only node (no join cadence, no self-check, plaintext, admits
/// everything) — and add what the driver wants.
#[derive(Clone, Debug)]
pub struct KadNodeStart {
    config: KadNodeConfig,
    now: KadInstant,
    admission: KadContactAdmission,
    self_lookup: bool,
    small_timer: bool,
    self_check: Option<KadSelfCheck>,
    obfuscation: Option<KadObfuscation>,
}

impl KadNodeStart {
    /// A routing-only start at `now`: the posture every mesh-sim node keeps,
    /// which must still quiesce (no perpetual join wake).
    #[must_use]
    pub fn new(config: KadNodeConfig, now: KadInstant) -> Self {
        Self {
            config,
            now,
            admission: KadContactAdmission::default(),
            self_lookup: false,
            small_timer: false,
            self_check: None,
            obfuscation: None,
        }
    }

    /// The contact-admission verdict, in force before the node handles any
    /// traffic, so no contact intake can precede the IP filter. The default
    /// admits everything.
    #[must_use]
    pub fn admission(mut self, admission: KadContactAdmission) -> Self {
        self.admission = admission;
        self
    }

    /// Run the forced self-lookup schedule (ADR-0067), anchored at the start
    /// instant: the first fires [`SELF_LOOKUP_INITIAL`](KadNode::SELF_LOOKUP_INITIAL)
    /// later, then every [`SELF_LOOKUP_REFRESH`](KadNode::SELF_LOOKUP_REFRESH)
    /// (aMule's `CKademlia::Start`).
    #[must_use]
    pub const fn self_lookup(mut self) -> Self {
        self.self_lookup = true;
        self
    }

    /// Run the small-timer hello pass, anchored at the start instant: the
    /// first pass fires [`SMALL_TIMER_INITIAL`](KadNode::SMALL_TIMER_INITIAL)
    /// later, then every [`SMALL_TIMER_INTERVAL`](KadNode::SMALL_TIMER_INTERVAL),
    /// joined or not. It is what reaches a merged nodes.dat table.
    #[must_use]
    pub const fn small_timer(mut self) -> Self {
        self.small_timer = true;
        self
    }

    /// Run this node's own firewall self-check (ADR-0058 requester), anchored
    /// at the start instant.
    #[must_use]
    pub const fn self_check(mut self, self_check: KadSelfCheck) -> Self {
        self.self_check = Some(self_check);
        self
    }

    /// Obfuscate outbound datagrams (ADR-0046), with optional verify keys.
    #[must_use]
    pub const fn obfuscation(mut self, obfuscation: KadObfuscation) -> Self {
        self.obfuscation = Some(obfuscation);
        self
    }
}

/// The firewall self-check requester (ADR-0058): from the start instant the
/// node emits its own `0x50`/`0x53` checks on hello traffic and projects the
/// reachability lifecycle. It arms the TCP and the UDP half together, as
/// aMule's `CKademlia::Start` and `CUDPFirewallTester::Connected` do.
#[derive(Clone, Copy, Debug, Default)]
pub struct KadSelfCheck {
    udp_helper_target: Option<fn() -> KadId>,
}

impl KadSelfCheck {
    /// A self-check whose UDP half waits for helpers a driver offers.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            udp_helper_target: None,
        }
    }

    /// Let the UDP half find its own helpers: a lookup toward a random
    /// target drawn from `target` (the node draws no entropy), launched on the
    /// first Kad datagram after start and every recheck (aMule
    /// `CSearchManager::FindNodeFWCheckUDP`).
    #[must_use]
    pub const fn with_udp_helper_lookup(mut self, target: fn() -> KadId) -> Self {
        self.udp_helper_target = Some(target);
        self
    }
}

/// Per-datagram UDP send-obfuscation (ADR-0046): outbound datagrams are
/// RC4-encrypted per aMule's key-choice matrix — NodeID-keyed toward a stored
/// v>=6 contact, receiver-key-keyed for handler replies. Receive stays
/// dual-path regardless. `nonce` injects the per-packet entropy (marker byte,
/// key seed, padding) the sans-I/O node cannot draw itself.
///
/// The node is armed with one at start ([`KadNodeStart::obfuscation`]) and
/// re-armed with one, or disarmed, live
/// ([`KadCommand::SetObfuscation`](crate::KadCommand::SetObfuscation)).
#[derive(Clone, Copy, Debug)]
pub struct KadObfuscation {
    /// `None` for a node that opens obfuscated datagrams but sends plaintext.
    nonce: Option<fn() -> DatagramNonce>,
    verify_keys: Option<KadVerifyKeys>,
}

/// Equal when both arm the same verify keys and draw from the same nonce
/// source. A `fn` pointer offers only its address to compare, so that is what
/// [`std::ptr::fn_addr_eq`] compares: the driver's one OS source, or a test's
/// fixed one.
impl PartialEq for KadObfuscation {
    fn eq(&self, other: &Self) -> bool {
        let same_source = match (self.nonce, other.nonce) {
            (Some(ours), Some(theirs)) => std::ptr::fn_addr_eq(ours, theirs),
            (None, None) => true,
            _ => false,
        };
        same_source && self.verify_keys == other.verify_keys
    }
}

impl Eq for KadObfuscation {}

/// Hashes the nonce source's address, agreeing with [`PartialEq`].
impl std::hash::Hash for KadObfuscation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.nonce.map(|nonce| nonce as usize).hash(state);
        self.verify_keys.hash(state);
    }
}

impl KadObfuscation {
    /// Obfuscation without verify keys: no verification fires and no `0x22`
    /// is answered.
    #[must_use]
    pub const fn new(nonce: fn() -> DatagramNonce) -> Self {
        Self {
            nonce: Some(nonce),
            verify_keys: None,
        }
    }

    /// Verify keys with no send-obfuscation: the node sends plaintext and
    /// still opens every datagram keyed on the verify key it handed out. aMule
    /// derives that key whatever its crypt setting and tries it on every
    /// client datagram (`EncryptedDatagramSocket.cpp:187-195`, the receiver-key
    /// family, guarded only by Kad running), so a peer holding our key from an
    /// earlier armed period is still heard after the policy goes off.
    #[must_use]
    pub const fn receive_only(secret: u32, public_ip: Ipv4Addr) -> Self {
        Self {
            nonce: None,
            verify_keys: Some(KadVerifyKeys { secret, public_ip }),
        }
    }

    /// Add the Kad UDP verify-key state (ADR-0046 keys; ADR-0064's verification
    /// cluster activates on it). The secret is caller-supplied: `rmule-core`
    /// passes its persisted **Kad UDP Key**, the way aMule persists
    /// `s_dwKadUDPKey` across restarts.
    #[must_use]
    pub const fn with_verify_keys(mut self, secret: u32, public_ip: Ipv4Addr) -> Self {
        self.verify_keys = Some(KadVerifyKeys { secret, public_ip });
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct KadVerifyKeys {
    secret: u32,
    public_ip: Ipv4Addr,
}

impl KadNode {
    /// A node started per `start`: empty routing table, no outstanding
    /// exchanges, and the start-up value applied in its one correct order.
    ///
    /// The node reads no clock and opens no socket — a driver feeds it
    /// instants, datagrams and commands, and drains its outputs.
    #[must_use]
    pub fn new(start: KadNodeStart) -> Self {
        let KadNodeStart {
            config,
            now,
            admission,
            self_lookup,
            small_timer,
            self_check,
            obfuscation,
        } = start;
        let mut node = Self::unstarted(config);
        node.contact_admission = admission;
        if self_lookup {
            node.next_self_lookup = Some(now + Self::SELF_LOOKUP_INITIAL);
        }
        if small_timer {
            node.next_small_timer = Some(now + Self::SMALL_TIMER_INITIAL);
        }
        if let Some(self_check) = self_check {
            node.firewall = Some(crate::reachability::FirewallSelfCheck::new(now));
            node.udp_firewall = Some(crate::reachability::UdpFirewallTester::new(now));
            node.udp_helper_target = self_check.udp_helper_target;
        }
        node.install_obfuscation(obfuscation);
        node
    }

    /// Install obfuscation, then its verify keys, or neither; a
    /// [receive-only](KadObfuscation::receive_only) value installs the keys
    /// without the send side, since the trailer only rides an obfuscated
    /// send. The start applies it once and
    /// [`KadCommand::SetObfuscation`](crate::KadCommand::SetObfuscation)
    /// again whenever the driver's policy changes, replacing what was armed
    /// whole.
    ///
    /// What the node learned stays: a stored contact's key is kept against a
    /// later re-arm, and our own public IP (the UDP check's "not ourselves"
    /// rule reads it) is kept when keys go.
    pub(super) fn install_obfuscation(&mut self, obfuscation: Option<KadObfuscation>) {
        self.outbound_obfuscation = obfuscation.and_then(|obfuscation| obfuscation.nonce);
        self.verify_keys = None;
        if let Some(KadVerifyKeys { secret, public_ip }) =
            obfuscation.and_then(|obfuscation| obfuscation.verify_keys)
        {
            self.own_public_ip = Some(public_ip);
            self.verify_keys = Some(VerifyKeyState { secret, public_ip });
            self.routing.set_own_public_ip(public_ip);
        }
    }
}
