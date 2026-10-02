//! The core-owned **open-node buddy service** (ADR-0061, execution breakdown 2):
//! the single-slot citizen next to [`Reachability`](crate::reachability) that
//! serves firewalled peers as an open node. It is the serving counterpart of the
//! [`callback`](crate::callback) route chooser — where the chooser routes *us*
//! toward a buddy to reach a LowID peer, this is the node **accepting** buddy
//! recruitment and **relaying** the callbacks a firewalled peer receives through
//! us.
//!
//! aMule keeps one `m_pBuddy` — the relationship is single-slot in both
//! directions (our buddy while we are firewalled, or the client we buddy for).
//! This module owns the open-node half of that slot: the `FINDBUDDY_REQ` refusal
//! matrix, the two **verified** relays, and the ping/pong keepalive.
//!
//! - **Recruitment** ([`consider_findbuddy`](BuddyService::consider_findbuddy),
//!   aMule
//!   [`KademliaUDPListener.cpp#L1425`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1425)
//!   / [`ClientList.cpp#L906`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientList.cpp#L906)):
//!   refuse **silently** when we are TCP-firewalled / UDP-firewalled /
//!   UDP-unverified (an unopen node cannot relay for anyone), when the slot is
//!   already taken, when the requester is a known client or under a
//!   firewall-check collision, or when it is ourselves; else accept, fill the
//!   slot, and answer `0x5A` `<buddyID><ourHash><ourTCPport>`.
//! - **Relays, both verified** ([`relay`](BuddyService::relay)): a Kad
//!   `KADEMLIA_CALLBACK_REQ` (`0x52`) becomes `OP_CALLBACK` (`0x99`) and a
//!   peer-UDP `OP_REASKCALLBACKUDP` (`0x94`) becomes `OP_REASKCALLBACKTCP`
//!   (`0x9A`), each over our buddy's TCP link. **Documented tightening:** aMule
//!   verifies the buddy-ID on the `0x94` relay but not on `0x52` (its own
//!   `// JOHNTODO: Begin filtering bad buddy ID's..`,
//!   [`KademliaUDPListener.cpp#L1489`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1489));
//!   rmule verifies **both** against the registered buddy-ID — the check aMule
//!   intended, unobservable to a compliant requester (it sends the ID it found
//!   the buddy by) and keeping our buddy's TCP link from relaying spoofed
//!   callbacks.
//! - **Keepalive** ([`on_buddy_ping`](BuddyService::on_buddy_ping), aMule
//!   [`ClientTCPSocket.cpp#L1665`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L1665)):
//!   answer `OP_BUDDYPING` with `OP_BUDDYPONG` only for our buddy, refreshing the
//!   link so its session timeout is extended while linked; a ping from anyone
//!   else is refused.
//!
//! Pure and sans-I/O, the [`reachability`](crate::reachability) broker's shape:
//! it decides, and the enactment — the Kad `0x52` / peer-UDP `0x94` consume that
//! feeds it and the **held buddy link** send that carries a relay or a pong —
//! lives in [`buddy_link`](crate::buddy_link), the socket-unification owner
//! that pairs this service with the buddy's persistent inbound peer-TCP
//! connection. Explicit `Instant` only; the keepalive window is the peer-session
//! driver's policy (timeouts are driver-owned, `rmule-peer`'s session doctrine),
//! so the staleness sweep takes it as a parameter.

use std::time::{Duration, Instant};

use rmule_kad::KadId;
use rmule_primitives::{Ipv4Endpoint, PeerEndpoint, UserHash};

/// Our own network position the recruitment gate reads (ADR-0058
/// [`Reachability`](crate::reachability)). We serve as an open-node buddy only
/// when **both** our TCP and UDP surfaces are open — a firewalled or
/// UDP-unverified node cannot relay a third party's callback, so aMule recruits
/// no buddy and answers no `FINDBUDDY_REQ` while unopen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BuddyServePosture {
    /// Our TCP reachability verdict reads Open (ADR-0058 ≥2-ack rule).
    pub(crate) tcp_reachable: bool,
    /// Our UDP self-check verdict.
    pub(crate) udp: BuddyUdpPosture,
}

/// Our UDP surface's self-check verdict, as the recruitment gate distinguishes
/// it (ADR-0058 UDP verdict): only [`Open`](Self::Open) may serve as a buddy —
/// a [`Firewalled`](Self::Firewalled) or not-yet-verified
/// [`Unverified`](Self::Unverified) UDP surface refuses, each with its own
/// reason so the refusal matrix is precise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuddyUdpPosture {
    Open,
    Firewalled,
    Unverified,
}

/// Our identity fields the accept answer (`0x5A`) carries back to the requester:
/// our client hash and advertised TCP port, so it can address our buddy link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BuddyIdentity {
    pub(crate) our_hash: UserHash,
    pub(crate) our_tcp_port: u16,
}

/// One inbound `KADEMLIA_FINDBUDDY_REQ` (`0x51`) as the buddy service reads it —
/// the facts the aMule listener guards on before it accepts a buddy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FindBuddyReq {
    /// The buddy-ID the requester proposes (its own client hash): echoed into
    /// the `0x5A` answer and the id every later relay is verified against.
    pub(crate) buddy_id: KadId,
    /// The requester's eD2k user hash from the `0x51` body — the identity its
    /// later inbound TCP hello carries, so the socket-unification attach can
    /// recognize the buddy's persistent link (aMule attaches the incoming
    /// socket to the already-known client by this hash).
    pub(crate) requester_hash: UserHash,
    /// The requester's endpoint — the buddy TCP link we open and pong on.
    pub(crate) requester: Ipv4Endpoint,
    /// The `0x51` datagram's **observed source** — the requester's UDP
    /// mapping as we see it. An eMule-family client runs Kad and client-UDP on
    /// one socket, so this is the endpoint a NAT-T punch must reach, and what
    /// an `OP_NATT_ENDPOINT_HINT` names (ADR-0091).
    pub(crate) requester_udp: Ipv4Endpoint,
    /// The requester is already a known client (aMule refuses — a client we
    /// already track is reachable without a fresh buddy relay).
    pub(crate) requester_known: bool,
    /// The requester's IP collides with one of our own outstanding firewall
    /// checks (aMule's firewall-check collision guard).
    pub(crate) check_collision: bool,
    /// The requester is ourselves (the self-recruit guard).
    pub(crate) is_self: bool,
}

/// What [`consider_findbuddy`](BuddyService::consider_findbuddy) decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FindBuddyOutcome {
    /// Accepted: the slot is now this requester's, and this `0x5A` answer goes
    /// back to it.
    Accept(FindBuddyAnswer),
    /// Refused silently — no answer, exactly like aMule's guarded early returns.
    Refuse { reason: FindBuddyRefusal },
}

/// The `KADEMLIA_FINDBUDDY_RES` (`0x5A`) answer an accept sends:
/// `<buddyID><ourHash><ourTCPport>` (ADR-0061).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FindBuddyAnswer {
    pub(crate) buddy_id: KadId,
    pub(crate) our_hash: UserHash,
    pub(crate) our_tcp_port: u16,
}

/// Why the service silently refused a `FINDBUDDY_REQ` (aMule's guards, each a
/// distinct row of the refusal matrix).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FindBuddyRefusal {
    /// Our TCP surface is firewalled — we cannot be dialed, so we cannot relay.
    TcpFirewalled,
    /// Our UDP surface is firewalled.
    UdpFirewalled,
    /// Our UDP surface is not yet verified open.
    UdpUnverified,
    /// The single buddy slot is already taken (aMule's one `m_pBuddy`).
    SlotTaken,
    /// The requester is a client we already track.
    KnownClient,
    /// The requester's IP collides with an outstanding firewall check of ours.
    CheckCollision,
    /// The requester is ourselves.
    SelfRequest,
}

/// Which verified relay a callback rides (ADR-0061): the two open-node relays,
/// each carrying its inbound opcode's callback to our buddy's TCP link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayKind {
    /// Kad `KADEMLIA_CALLBACK_REQ` (`0x52`) → `OP_CALLBACK` (`0x99`): a peer
    /// wanting our firewalled buddy to dial it back for a transfer.
    Callback,
    /// peer-UDP `OP_REASKCALLBACKUDP` (`0x94`) → `OP_REASKCALLBACKTCP` (`0x9A`):
    /// a downloader's queue reask relayed to our buddy, which answers over UDP.
    ReaskCallback,
}

/// One inbound relay request the buddy service verifies and forwards — a `0x52`
/// or a `0x94`, reduced to the fields the relay decision reads. The requester's
/// endpoint is taken from the datagram source (not the body) so our buddy can
/// dial or answer it; `forwarded` is the callback payload our buddy consumes,
/// opaque to the relay (aMule forwards it, injecting only the requester's
/// endpoint).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BuddyRelayRequest {
    pub(crate) kind: RelayKind,
    /// The buddy-ID the requester addressed — verified against our slot on
    /// **both** opcodes (the ADR-0061 tightening).
    pub(crate) claimed_buddy_id: KadId,
    /// The requester's endpoint, from the datagram source.
    pub(crate) requester: Ipv4Endpoint,
    /// The callback payload forwarded to our buddy (the file/request context),
    /// opaque here.
    pub(crate) forwarded: Vec<u8>,
}

/// What [`relay`](BuddyService::relay) decided for one inbound relay request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelayVerdict {
    /// Relay the callback to our buddy at `buddy_link` over its TCP link.
    Relay {
        buddy_link: Ipv4Endpoint,
        callback: RelayedCallback,
        /// A `0x52` whose claimed ID matched our registered buddy only under
        /// the other `TAG_BUDDYHASH` spelling (source-derived) —
        /// relayed verbatim, counted apart.
        swapped_spelling: bool,
    },
    /// Refuse the relay silently — no buddy, or the claimed buddy-ID does not
    /// match our registered buddy (the tightening, applied to both opcodes).
    Reject { reason: RelayReject },
}

/// The callback a [`Relay`](RelayVerdict::Relay) carries onto the buddy TCP
/// link: the inbound opcode's kind, the requester endpoint to inject, and the
/// forwarded payload. The `rmule-peer` codec frames it as the `0x99`/`0x9A`
/// packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelayedCallback {
    pub(crate) kind: RelayKind,
    pub(crate) requester: Ipv4Endpoint,
    pub(crate) forwarded: Vec<u8>,
}

/// Why the service silently rejected a relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayReject {
    /// We hold no buddy, so there is no TCP link to relay onto.
    NoBuddy,
    /// The claimed buddy-ID does not match our registered buddy — a spoofed or
    /// stale callback (aMule accepts this on `0x52`; rmule does not).
    BuddyIdMismatch,
}

/// What an inbound `OP_BUDDYPING` produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuddyPingOutcome {
    /// The ping came from our buddy: answer `OP_BUDDYPONG` — the link is
    /// refreshed, its session timeout extended.
    Pong,
    /// The ping came from a client that is not our buddy: refuse (aMule drops).
    NotOurBuddy,
}

/// Our single buddy relationship while the slot is filled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BuddyLink {
    /// The buddy-ID agreed at recruitment — every relay is verified against it.
    buddy_id: KadId,
    /// The buddy's eD2k user hash from the recruit — the identity its inbound
    /// TCP hello carries, matched when the persistent buddy link attaches.
    hash: UserHash,
    /// The buddy's endpoint — where a relay's TCP link goes and the only
    /// IP an `OP_BUDDYPING` is honored from.
    endpoint: Ipv4Endpoint,
    /// The buddy's UDP mapping as observed at recruitment — what an endpoint
    /// hint names (ADR-0091).
    observed_udp: Ipv4Endpoint,
    /// When we last heard from the buddy (recruitment, then each ping/pong):
    /// the keepalive anchor the staleness sweep measures against.
    last_seen: Instant,
}

/// The open-node buddy service: one slot, either empty or holding our buddy.
pub(crate) struct BuddyService {
    slot: Option<BuddyLink>,
}

impl BuddyService {
    /// A fresh service with no buddy.
    pub(crate) fn new() -> Self {
        Self { slot: None }
    }

    /// Whether the single slot is currently filled.
    pub(crate) fn has_buddy(&self) -> bool {
        self.slot.is_some()
    }

    /// Our registered buddy-ID, or `None` when the slot is empty.
    pub(crate) fn buddy_id(&self) -> Option<KadId> {
        self.slot.map(|link| link.buddy_id)
    }

    /// The served buddy as an endpoint hint names it — its user hash and the
    /// UDP mapping observed at recruitment — or `None` when the slot is empty.
    pub(crate) fn hint_subject(&self) -> Option<(UserHash, Ipv4Endpoint)> {
        self.slot.map(|link| (link.hash, link.observed_udp))
    }

    /// Our registered buddy's eD2k user hash, or `None` when the slot is empty
    /// — what the socket-unification attach matches an inbound identified
    /// peer against (aMule's attach-to-already-known-client by hash).
    pub(crate) fn buddy_hash(&self) -> Option<UserHash> {
        self.slot.map(|link| link.hash)
    }

    /// Consider one `FINDBUDDY_REQ` against the refusal matrix and, on accept,
    /// fill the slot and answer `0x5A`. Silent refusals otherwise (aMule's
    /// guarded early returns), each with its precise reason.
    pub(crate) fn consider_findbuddy(
        &mut self,
        req: &FindBuddyReq,
        posture: &BuddyServePosture,
        our: BuddyIdentity,
        now: Instant,
    ) -> FindBuddyOutcome {
        // The refusal matrix, in aMule's guard order: never buddy ourselves;
        // then our own surface must be open (an unopen node cannot relay for a
        // third party); then the one slot must be free; then the requester must
        // be neither a client we already track nor colliding with one of our
        // outstanding firewall checks.
        let refuse = |reason| FindBuddyOutcome::Refuse { reason };
        if req.is_self {
            return refuse(FindBuddyRefusal::SelfRequest);
        }
        if !posture.tcp_reachable {
            return refuse(FindBuddyRefusal::TcpFirewalled);
        }
        match posture.udp {
            BuddyUdpPosture::Open => {}
            BuddyUdpPosture::Firewalled => return refuse(FindBuddyRefusal::UdpFirewalled),
            BuddyUdpPosture::Unverified => return refuse(FindBuddyRefusal::UdpUnverified),
        }
        if self.slot.is_some() {
            return refuse(FindBuddyRefusal::SlotTaken);
        }
        if req.requester_known {
            return refuse(FindBuddyRefusal::KnownClient);
        }
        if req.check_collision {
            return refuse(FindBuddyRefusal::CheckCollision);
        }
        // Accept: the slot is now this requester's, its link fresh at `now`.
        self.slot = Some(BuddyLink {
            buddy_id: req.buddy_id,
            hash: req.requester_hash,
            endpoint: req.requester,
            observed_udp: req.requester_udp,
            last_seen: now,
        });
        FindBuddyOutcome::Accept(FindBuddyAnswer {
            buddy_id: req.buddy_id,
            our_hash: our.our_hash,
            our_tcp_port: our.our_tcp_port,
        })
    }

    /// Verify and forward one inbound relay — the two verified open-node relays.
    /// Reject silently when we hold no buddy, or when the claimed buddy-ID does
    /// not match our registered buddy (the tightening, applied to `0x52` and
    /// `0x94` alike).
    pub(crate) fn relay(&self, req: &BuddyRelayRequest) -> RelayVerdict {
        let Some(link) = self.slot else {
            return RelayVerdict::Reject {
                reason: RelayReject::NoBuddy,
            };
        };
        // The tightening: verify the addressed buddy-ID against our registered
        // buddy on BOTH the 0x52 and the 0x94 relay — aMule checks only 0x94.
        // On the 0x52 either `TAG_BUDDYHASH` spelling is our buddy:
        // a requester of the other family reads the row's tag one
        // per-word swap away. Relayed verbatim, as aMule relays every 0x52;
        // our buddy's own 0x99 check has the last word. The 0x94 keeps the
        // exact match aMule itself applies there.
        let swapped_spelling = if req.claimed_buddy_id == link.buddy_id {
            false
        } else if req.kind == RelayKind::Callback
            && req.claimed_buddy_id.word_swapped() == link.buddy_id
        {
            tracing::info!(
                requester = ?req.requester,
                "0x52 names our buddy in the other TAG_BUDDYHASH spelling \
                 (eMule-family reading); relaying verbatim"
            );
            true
        } else {
            return RelayVerdict::Reject {
                reason: RelayReject::BuddyIdMismatch,
            };
        };
        RelayVerdict::Relay {
            swapped_spelling,
            buddy_link: link.endpoint,
            callback: RelayedCallback {
                kind: req.kind,
                requester: req.requester,
                forwarded: req.forwarded.clone(),
            },
        }
    }

    /// Answer an inbound `OP_BUDDYPING` from `from`: pong and refresh the link
    /// only when `from` is our buddy; otherwise refuse. The match is
    /// **IP-based**: the buddy's persistent TCP link is one *it dialed to us*,
    /// so its source port is an ephemeral one — never the advertised TCP port
    /// the recruit registered. (aMule honors a ping iff the socket's attached
    /// client *is* `m_pBuddy`; the enacted buddy slot additionally requires the
    /// ping to have arrived on the held link itself.)
    pub(crate) fn on_buddy_ping(&mut self, from: PeerEndpoint, now: Instant) -> BuddyPingOutcome {
        match &mut self.slot {
            // The recruited buddy is a Kad contact, so an IPv4 address: a
            // ping from any other family cannot be its.
            Some(link) if from.ip() == std::net::IpAddr::V4(link.endpoint.ip) => {
                link.last_seen = now;
                BuddyPingOutcome::Pong
            }
            _ => BuddyPingOutcome::NotOurBuddy,
        }
    }

    /// Drop the buddy if its link has gone stale — no ping/pong within `timeout`
    /// of `now`. Returns whether a buddy was dropped, freeing the slot. The
    /// keepalive window `timeout` is the peer-session driver's policy.
    pub(crate) fn drop_stale(&mut self, now: Instant, timeout: Duration) -> bool {
        let stale = self
            .slot
            .is_some_and(|link| now.saturating_duration_since(link.last_seen) >= timeout);
        if stale {
            self.slot = None;
        }
        stale
    }

    /// Release the slot on buddy loss (the buddy's TCP link closed) — aMule frees
    /// `m_pBuddy` at once so a fresh recruit can take the slot.
    pub(crate) fn release(&mut self) {
        self.slot = None;
    }
}

#[cfg(test)]
mod tests;
