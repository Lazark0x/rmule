//! The **Side** group of [`PeerEvent`](super::PeerEvent): node-wide services
//! riding the link that neither capability owns — the Kad firewall checks
//! (ADR-0058), the buddy relay (ADR-0061) and the peer's public-IP ask. The
//! session stays Kad-ignorant; its owner bridges each to the subsystem that
//! answers it.

/// A node-wide service the link carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SideEvent {
    /// `OP_KAD_FWTCPCHECK_ACK` (`0xA8`) arrived on this link — a peer we asked to
    /// firewall-check us dialed our TCP port and acked (ADR-0058 requester). The
    /// session stays Kad-ignorant; its owner bridges this to the KadNode's
    /// window-guarded ack consume, keyed on this peer's IP, which counts it
    /// toward the ≥2-ack reachability verdict.
    KadFirewallCheckAck,
    /// `OP_FWCHECKUDPREQ` (`0xA7`) arrived on this link — the peer asks us to
    /// prove its Kad UDP port reachable (ADR-0058, UDP Firewall Helper). The
    /// session stays Kad-ignorant; its owner bridges the opaque body, keyed on
    /// this peer's IP, to the Kad node, which answers `KADEMLIA2_FIREWALLUDP`.
    KadUdpFirewallCheckRequested {
        /// The request body as it arrived.
        request: Vec<u8>,
    },
    /// `OP_BUDDYPING` (`0x9F`) arrived on this link — our firewalled buddy's
    /// keepalive over the buddy TCP link (ADR-0061). The session stays
    /// Kad-ignorant; its owner routes this to the core buddy service's
    /// `on_buddy_ping`, which pongs (`SendBuddyPong`) and refreshes the link only
    /// when the sender is our registered buddy, refusing a stranger.
    BuddyPingReceived,
    /// `OP_CALLBACK` (`0x99`) arrived on this link — our own buddy relayed a
    /// Kad `0x52` and is asking us to dial the requester back (ADR-0061
    /// firewalled-node consume). Wire-silent: the session stays Kad-ignorant,
    /// and its owner runs the buddy-ID XOR check, the Kad-running and
    /// file-known gates, and the dial.
    BuddyCallbackReceived {
        /// The relay as it arrived — the echoed buddy-ID and file hash, and
        /// the requester endpoint the buddy injected.
        callback: crate::buddy::Callback,
    },
    /// `OP_REASKCALLBACKTCP` (`0x9A`) arrived on this link — our own buddy
    /// relayed a peer-UDP `0x94` (ADR-0061), or, when the forwarded tail
    /// carries the `OP_RENDEZVOUS` marker, a rendezvous aimed at us
    /// (ADR-0091's acting path). Wire-silent for the same reason: the answer
    /// leaves by the client-UDP socket, which this session does not own.
    BuddyReaskCallbackReceived {
        /// The injected requester endpoint and the forwarded tail, verbatim.
        relay: crate::buddy::ReaskCallbackTcp,
    },
    /// Respond-by-parity (ADR-0068): `OP_PUBLICIP_REQ` was answered
    /// `OP_PUBLICIP_ANSWER` with the peer's own observed IPv4 — ungated in
    /// aMule, no privacy preference silences it.
    PublicIpAnswered,
    /// Drop-with-counter (ADR-0085): `OP_PUBLICIP_REQ` from an IPv6 peer —
    /// the answer is a 32-bit field, so there is nothing true to reply.
    PublicIpRequestUnanswerable,
}
