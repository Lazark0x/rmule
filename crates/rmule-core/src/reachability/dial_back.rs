//! The firewall-check **dial-back broker** (ADR-0058): the core half of the
//! responder, and the registry that bounds its enactments.
//!
//! When the sans-I/O KadNode consumes a `0x50`/`0x53` firewall check it emits a
//! [`KadEvent::DialBackRequested`](rmule_kad::KadEvent) with the requester's TCP
//! endpoint and connect-options; [`broker_dial_back`] turns that into a
//! [`DialBackVerdict`] — dial through the peer-dial infra (ADR-0031/0039) with a
//! version-gated ack, or one of aMule's silent `CClientList::RequestTCP`
//! refusals ([`SelfConnect`](DialBackRefusal::SelfConnect),
//! [`Busy`](DialBackRefusal::Busy)). Only the decision lives here — the dial and
//! the ack send are the caller's enactment — so the module stays sans-I/O and
//! the refusal matrix is provable without a socket.
//!
//! A third refusal lives in the **node**, not here: a requester whose IP has one
//! of our own checks outstanding is declined by
//! `KadNode::dial_back_would_poison_our_own_check`. Its only input
//! is the node's 180 s outstanding-check window, and mirroring that window
//! core-side would be a second copy of state the sans-I/O node already owns —
//! so the guard sits where its input does.
//!
//! This half never reads or writes the verdict store beside it: answering
//! someone else's firewall check says nothing about our own position, which is
//! why the two live in separate files. The one thing it does own is the
//! *liveness* of its own enactments — [`DialBackRegistry`], whose tickets feed
//! the broker's `busy` guard and cap the concurrent outbound dials a datagram
//! flood can provoke.

use std::collections::HashSet;

use rmule_net::peer::ObfuscationPolicy;
use rmule_primitives::{Ipv4Endpoint, OutboundCrypt, PeerCrypt, UserHash};

use rmule_peer::peer_udp::crypt::stance_from_connect_options;

/// One firewall-check dial-back the KadNode responder asked core to broker: the
/// requester's TCP endpoint (its IP as we observed the `0x50`/`0x53` datagram
/// source, its advertised TCP port), its connect-options — `Some` for a v7+
/// `0x53`, `None` for a legacy `0x50`, the version signal that gates the ack
/// form — and, for a v7+ check, its own **User Hash**: the crypt
/// key basis the two-reading rule needs to obfuscate the dial-back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DialBackRequest {
    pub(crate) requester: Ipv4Endpoint,
    pub(crate) connect_options: Option<u8>,
    /// The requester's own User Hash out of a v7+ `0x53` body; `None` for a
    /// legacy `0x50`, which carries no hash and is never obfuscated.
    pub(crate) user_hash: Option<UserHash>,
}

/// The version-gated ack a successful dial-back sends (ADR-0058): a v7+ check
/// is acked with `OP_KAD_FWTCPCHECK_ACK` over the dialed TCP link; a legacy
/// check with a UDP `0x59` (`KADEMLIA_FIREWALLED_ACK_RES`) to the requester's
/// Kad port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FwCheckAck {
    /// v7+ (`0x53`): `OP_KAD_FWTCPCHECK_ACK` over the TCP link just dialed.
    TcpLink,
    /// Legacy (`0x50`): a UDP `0x59` to the requester's Kad port.
    Udp,
}

/// The broker's decision for one dial-back request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DialBackVerdict {
    /// Dial the requester's TCP port through the peer-dial infra and, on
    /// connect success, send `ack`; then drop the session. The dial meets
    /// `requester_crypt` with our own policy by [`PeerCrypt::outbound`] —
    /// obfuscated toward the requester's hash when both support crypt and one
    /// asks, plaintext otherwise. A refused dial *inside* the
    /// enactment (connect failure) is silent, exactly like a guard refusal
    /// here.
    Dial {
        requester: Ipv4Endpoint,
        /// The requester's crypt side as its check stated it: the `0x53`
        /// connect-options through the stance ladder plus the body's User
        /// Hash; [`PeerCrypt::unknown`] for a legacy `0x50`, which states
        /// neither. Never compatible-by-assumption — an incompatible pair is
        /// refused below, before this verdict exists.
        requester_crypt: PeerCrypt,
        ack: FwCheckAck,
    },
    /// Refuse silently — no dial, no reply — matching aMule's guarded
    /// `CClientList::RequestTCP` early returns.
    Refuse { reason: DialBackRefusal },
}

/// Our own listen endpoint, as far as the ADR-0058 self-connect guard can
/// currently tell. Address Learning's IPv4 projection —
/// `own.public_ip()`, the same read the Kad pump samples for the node's own-IPv4
/// level at Kad start, on every Own Address Generation and every recruit tick — is the one
/// source: a second, independently-read copy of the level would only give
/// the guard a chance to disagree with the verify-key state bound to the
/// same value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnListenEndpoint {
    /// The live public IPv4 is known: a self-connect matches exact IP + port.
    Known(Ipv4Endpoint),
    /// No public IPv4 known yet (a fresh node, or one that has not completed
    /// Address Learning): a self-connect matches on port alone, the only
    /// signal available — aMule itself has none finer before its own
    /// `GetPublicIP()` settles.
    PortOnly(u16),
}

impl OwnListenEndpoint {
    /// The guard's current value: `own`'s live Address Learning verdict
    /// paired with our advertised TCP `port`. Re-read at every guard check
    /// (dial-back, `FINDBUDDY_REQ`) rather than cached, since the verdict can
    /// move under a long-lived Kad node.
    pub(crate) fn current(own: &crate::own_identity::SharedOwnIdentity, port: u16) -> Self {
        match own.public_ip() {
            Some(ip) => Self::Known(Ipv4Endpoint::new(ip, port)),
            None => Self::PortOnly(port),
        }
    }

    /// Whether `candidate` is this endpoint, at the guard's current
    /// precision.
    pub(crate) fn matches(&self, candidate: Ipv4Endpoint) -> bool {
        match self {
            Self::Known(endpoint) => candidate == *endpoint,
            Self::PortOnly(port) => candidate.port == *port,
        }
    }
}

/// Why the broker silently refused a dial-back (aMule `RequestTCP` guards).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DialBackRefusal {
    /// The requester endpoint is our own listen endpoint — aMule's
    /// local-IP-and-port self-connect guard, matched exactly once our public
    /// IPv4 is known, on port alone until then ([`OwnListenEndpoint`]).
    SelfConnect,
    /// We are already engaged with that endpoint (aMule's `KadState != KS_NONE`
    /// on the matched client).
    Busy,
    /// The two crypt stances cannot meet (the same [`PeerCrypt::outbound`] reading the `0x95` route
    /// applies): the requester
    /// requires obfuscation and this node does not support it, or this node
    /// requires it and the requester does not support it. This requester is
    /// reachable; this node chose not to reach it, which is why the outcome
    /// is counted apart from the network-shaped refusals above.
    CryptIncompatible,
}

/// The guard context the dial-back broker reads (aMule `RequestTCP`): our own
/// listen endpoint, the endpoints we are already engaged with, and our own
/// obfuscation policy (the two-reading rule's other half) — the three whose
/// inputs are core's. The outstanding-check guard reads node state and is
/// applied there (see the module header).
pub(crate) struct DialBackGuards<'a> {
    pub(crate) own: OwnListenEndpoint,
    pub(crate) busy: &'a HashSet<Ipv4Endpoint>,
    /// **Our own** obfuscation policy (`CoreSettings::obfuscation`, ADR-0046) —
    /// `None` when obfuscation is off entirely, gating the dial-back exactly
    /// as the same-named field on
    /// [`DirectCallbackContext`](crate::firewalled::direct_callback::DirectCallbackContext)
    /// gates the `0x95` route.
    pub(crate) crypt: Option<ObfuscationPolicy>,
}

/// Broker one KadNode dial-back request into a verdict (ADR-0058 responder):
/// apply aMule's silent-refusal guards in order, read the two-reading crypt
/// rule for a v7+ check, else dial plaintext with the version-gated ack. Pure
/// and clock-free — the socket dial and the ack send are the enactment
/// (ADR-0058).
pub(crate) fn broker_dial_back(
    request: &DialBackRequest,
    guards: &DialBackGuards<'_>,
) -> DialBackVerdict {
    if guards.own.matches(request.requester) {
        return DialBackVerdict::Refuse {
            reason: DialBackRefusal::SelfConnect,
        };
    }
    if guards.busy.contains(&request.requester) {
        return DialBackVerdict::Refuse {
            reason: DialBackRefusal::Busy,
        };
    }
    let ack = match request.connect_options {
        // A `0x53` (v7+) carries connect-options; its ack rides the TCP link.
        Some(_) => FwCheckAck::TcpLink,
        // A legacy `0x50` acks over UDP with `0x59`.
        None => FwCheckAck::Udp,
    };
    // A legacy `0x50` carries neither connect-options nor a hash — aMule's own
    // advertised check options (`SELF_KAD_CONNECT_OPTIONS`) are always zero
    // regardless, so there is no crypt fact to read and the dial stays plain.
    let requester_crypt = match request.connect_options {
        Some(connect_options) => PeerCrypt::new(
            stance_from_connect_options(connect_options),
            request.user_hash,
        ),
        None => PeerCrypt::unknown(),
    };
    if requester_crypt.outbound(ObfuscationPolicy::stance_of(guards.crypt))
        == OutboundCrypt::Incompatible
    {
        return DialBackVerdict::Refuse {
            reason: DialBackRefusal::CryptIncompatible,
        };
    }
    DialBackVerdict::Dial {
        requester: request.requester,
        requester_crypt,
        ack,
    }
}

/// How many dial-back enactments may run at once. aMule bounds its responder
/// through client-list mechanics; rmule's enactments are plain spawned tasks,
/// so the registry enforces an explicit budget — a datagram flood of distinct
/// requesters must not fan out into unbounded outbound dials.
pub(super) const MAX_CONCURRENT_DIAL_BACKS: usize = 8;

/// The live half of the broker's `busy` guard (aMule `RequestTCP`'s
/// "already engaged with that client"): the endpoints with a dial-back
/// enactment currently in flight. The pump `begin`s an entry on a `Dial`
/// verdict and hands the [`DialBackTicket`] to the enactment task; the
/// ticket's drop — normal end, connect failure, or panic — retires it, so
/// the set can never leak an endpoint past its task.
#[derive(Clone, Default)]
pub(crate) struct DialBackRegistry {
    engaged: std::sync::Arc<std::sync::Mutex<HashSet<Ipv4Endpoint>>>,
}

impl DialBackRegistry {
    /// Snapshot the engaged endpoints — the broker's `busy` guard feed.
    pub(crate) fn engaged(&self) -> HashSet<Ipv4Endpoint> {
        self.engaged
            .lock()
            .expect("dial-back registry lock")
            .clone()
    }

    /// Claim an enactment slot toward `requester`: `None` when that endpoint
    /// is already engaged or the concurrent budget
    /// ([`MAX_CONCURRENT_DIAL_BACKS`]) is spent — the caller then refuses
    /// silently, exactly like a broker guard.
    pub(crate) fn begin(&self, requester: Ipv4Endpoint) -> Option<DialBackTicket> {
        let mut engaged = self.engaged.lock().expect("dial-back registry lock");
        if engaged.len() >= MAX_CONCURRENT_DIAL_BACKS || !engaged.insert(requester) {
            return None;
        }
        Some(DialBackTicket {
            engaged: std::sync::Arc::clone(&self.engaged),
            requester,
        })
    }
}

/// One claimed dial-back enactment; dropping it retires the engagement.
pub(crate) struct DialBackTicket {
    engaged: std::sync::Arc<std::sync::Mutex<HashSet<Ipv4Endpoint>>>,
    requester: Ipv4Endpoint,
}

impl Drop for DialBackTicket {
    fn drop(&mut self) {
        self.engaged
            .lock()
            .expect("dial-back registry lock")
            .remove(&self.requester);
    }
}
