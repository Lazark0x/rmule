//! The ADR-0061 open-node buddy service: answering a firewalled peer's
//! FINDBUDDY, and relaying a callback over the held buddy link.

use std::time::Instant;

use rmule_kad::KadId;
use rmule_primitives::{FileHash, Ipv4Endpoint, UserHash};

use crate::adapters::peer_transfer::buddy_serve_posture;
use crate::buddy::{BuddyIdentity, FindBuddyOutcome, FindBuddyReq};
use crate::buddy_link::RelayDisposition;
use crate::reachability::OwnListenEndpoint;

/// The buddy slot this node serves from, and who it is.
pub(crate) struct BuddyService {
    /// The enacted buddy slot: recruit decisions and the relay run through it.
    pub(crate) slot: crate::buddy_link::SharedBuddySlot,
    /// Our client hash and advertised TCP port, carried back by an accept.
    pub(crate) identity: BuddyIdentity,
    /// The self-facts the self-recruit guard reads.
    pub(crate) own: crate::own_identity::SharedOwnIdentity,
    /// Our advertised eD2k TCP port.
    pub(crate) own_tcp_port: u16,
}

impl BuddyService {
    /// A firewalled peer asked this node to be its buddy. The accept is the
    /// `0x5A` answer the brain sends the node, never sent from here: the
    /// answer takes the pump's one non-blocking path to the node's inbox.
    pub(super) fn find_buddy_requested(
        &self,
        requester: Ipv4Endpoint,
        buddy_id: KadId,
        requester_hash: UserHash,
        requester_tcp_port: u16,
        reach: &crate::reachability::SharedSelfReach,
    ) -> Option<(Ipv4Endpoint, KadId)> {
        let Self {
            slot: buddy_slot,
            identity: our_buddy_identity,
            own,
            own_tcp_port,
        } = self;
        let (our_buddy_identity, own_tcp_port) = (*our_buddy_identity, *own_tcp_port);
        // ADR-0061 open-node buddy service: a firewalled peer
        // asked us to be its buddy. Apply the core single-slot
        // service's refusal matrix over our live reachability posture
        // and, on accept, command the `0x5A` answer back to the
        // requester's Kad UDP endpoint. The buddy TCP link we register
        // is the requester's *advertised TCP port* (from its `0x51`
        // body), not the datagram source port; its user hash is the
        // identity the accept path attaches the held buddy link on.
        let buddy_tcp = Ipv4Endpoint::new(requester.ip, requester_tcp_port);
        let req = FindBuddyReq {
            buddy_id,
            requester_hash,
            requester: buddy_tcp,
            // The `0x51`'s own source: the UDP mapping a
            // NAT-T endpoint hint names (ADR-0091).
            requester_udp: requester,
            // The known-client + firewall-check-collision feeds are the
            // same ADR-0058 runtime state the dial-back guards await; until
            // they wire, only the self-recruit guard is live.
            // `[pending]` the known-client + collision feeds.
            requester_known: false,
            check_collision: false,
            is_self: OwnListenEndpoint::current(own, own_tcp_port).matches(buddy_tcp),
        };
        let posture = buddy_serve_posture(reach);
        match buddy_slot.consider_findbuddy(&req, &posture, our_buddy_identity, Instant::now()) {
            FindBuddyOutcome::Accept(_answer) => {
                // The v7+ connect-options byte advertises our crypt
                // stance; it is not threaded into this pump yet, so we
                // send the plain form (aMule tolerates its absence).
                // `[pending]` the `0x5A` connect-options byte.
                tracing::debug!(
                    ?buddy_tcp,
                    "kad buddy service: accepted recruit, answering 0x5A (ADR-0061)"
                );
                Some((requester, buddy_id))
            }
            FindBuddyOutcome::Refuse { reason } => {
                tracing::debug!(
                    ?buddy_tcp,
                    ?reason,
                    "kad buddy service: silently refused FINDBUDDY_REQ (ADR-0061)"
                );
                None
            }
        }
    }

    /// A peer asked our firewalled buddy, through this node, to dial it back.
    pub(super) fn callback_relay_requested(
        &self,
        requester: Ipv4Endpoint,
        buddy_id: KadId,
        file_hash: FileHash,
        requester_tcp_port: u16,
    ) {
        let buddy_slot = &self.slot;
        // ADR-0061 open-node relay, over the held buddy link: a
        // peer asked our firewalled buddy to dial it back. The slot
        // verifies the addressed buddy-ID against our registered buddy
        // (the tightening, both relays), frames `OP_CALLBACK` (`0x99`)
        // from the callback's structured fields, and queues it on the
        // buddy's HELD persistent inbound link — never a fresh dial
        // (aMule `buddy->GetSocket()->SendPacket`; absent socket ⇒
        // silent drop). The injected requester endpoint is the `0x52`
        // datagram source IP with the TCP port from its body (aMule
        // `WriteUInt32(ip); WriteUInt16(tcp)`).
        let injected = Ipv4Endpoint::new(requester.ip, requester_tcp_port);
        let disposition = buddy_slot.relay_kad_callback(buddy_id, injected, file_hash);
        match disposition {
            RelayDisposition::Sent => {
                tracing::debug!(
                    ?injected,
                    "kad buddy relay: OP_CALLBACK queued on the held buddy link"
                );
            }
            RelayDisposition::NoHeldLink | RelayDisposition::LinkSendFailed => {
                tracing::debug!(
                    ?injected,
                    ?disposition,
                    "kad buddy relay dropped; no deliverable held buddy link \
                     (aMule's GetSocket() absent drop)"
                );
            }
            RelayDisposition::Rejected(reason) => {
                tracing::debug!(
                    ?injected,
                    ?reason,
                    "kad buddy relay: 0x52 callback rejected (ADR-0061 tightening)"
                );
            }
        }
    }
}
