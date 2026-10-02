//! The core-owned **NAT traversal** citizen (ADR-0091): what rmule decides
//! around a Rendezvous, as opposed to what the bytes are (`rmule_peer::natt`)
//! or how a Tunnel is raised over the punched path (`rmule_net::natt`).
//!
//! Three decisions and two ledgers, each pure, sans-I/O and explicit-time — the shape of
//! [`callback`](crate::callback) and [`firewalled`](crate::firewalled):
//!
//! - **emit** ([`rendezvous_request`]) — the embedded `OP_RENDEZVOUS` rmule
//!   sends a target's serving buddy when the route tree takes rung 1;
//! - **act** ([`acting`]) — a rendezvous relayed *to us*: is it from our
//!   buddy, is the requester within budget, where is the punch aimed, and is
//!   that somewhere we may aim one;
//! - **relay** ([`relay`]) — a rendezvous we are asked to forward as someone's
//!   buddy: admission, the pending cap, and the per-source limit.
//!
//! Around them, two pieces of bookkeeping: [`requester`] — the rendezvous
//! rmule began, their budgets, and the hint each is waiting on — and
//! [`paths`] — the punched paths a Tunnel is using, their 60 s keepalive and
//! their one PCP `PEER` pin. And [`server_punch`] — the second Rendezvous
//! coordinator, ed2k-server's introduction, which needs neither a sender gate
//! nor the precedence rule because it arrives on our own session and names an
//! endpoint the server observed.
//!
//! [`front`] is where all of it meets a socket: the one task that owns both
//! ledgers, drives `rmule_net::natt`'s demux and engines from the client-UDP
//! front's NAT-T inbox, and hands a risen **Tunnel** to the serve pipeline as
//! the inbound source it is. Everything above it stays pure.
//!
//! The last two hold **separate rate limiters**, and that separation is a
//! security property rather than tidiness (amule#1177 correction 5): one
//! bucket table serving both the relay service rmule gives strangers and the
//! acting path it needs for itself let ~17 spoofed packets a second deny a
//! node its own buddy indefinitely.

use rmule_peer::BUDDY_ID_LEN;
use rmule_peer::natt::{NattConnectOptions, NattTransport, RendezvousBody};
use rmule_primitives::{FileHash, Ipv4Endpoint, PeerEndpoint, UserHash};

use crate::client_udp::ClientUdpSend;

pub(crate) mod acting;
pub(crate) mod front;
pub(crate) mod paths;
pub(crate) mod relay;
pub(crate) mod requester;
pub(crate) mod server_punch;

/// What rmule says about itself in a rendezvous it emits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RendezvousOffer {
    /// Our user hash — what the target looks us up by.
    pub(crate) our_user_hash: UserHash,
    /// Our connect-options byte: crypt stance plus the transports this node
    /// will actually serve right now.
    pub(crate) options: NattConnectOptions,
    /// The file we want from the target, when the attempt has one.
    pub(crate) file_hash: Option<FileHash>,
    /// Our **External Endpoint** for the client-UDP role, when Address
    /// Learning holds one. `None` writes a null claim — legal, and honest:
    /// the buddy observes our real source and injects it into the `0x9A`, and
    /// every conforming reader prefers that observation to this claim anyway.
    pub(crate) claimed_endpoint: Option<Ipv4Endpoint>,
    /// The transport we intend to raise.
    pub(crate) transport: NattTransport,
}

/// Frame the rendezvous toward `buddy_udp` — eMuleAI's **embedded** form, the
/// only one rmule emits: an `OP_REASKCALLBACKUDP` routed by the target's
/// serving-buddy Kad ID, carrying the null-hash marker, `0xA0`, and the body.
///
/// Always plaintext. ADR-0091 sends `0xC5` NAT-T signalling unobfuscated on
/// purpose: the buddy is a stranger whose key we may not hold, and a
/// rendezvous that fails to deobfuscate is indistinguishable from a NAT that
/// did not open — which is how kno's original framing went unnoticed.
///
/// `buddy_udp` is an [`Ipv4Endpoint`] because the buddy is a Kad contact and
/// Kad is IPv4-only end to end; a peer reachable over IPv6 never gets here —
/// rung 0 dialed it directly.
pub(crate) fn rendezvous_request(
    buddy_udp: Ipv4Endpoint,
    buddy_id: [u8; BUDDY_ID_LEN],
    offer: &RendezvousOffer,
) -> ClientUdpSend {
    let datagram = RendezvousBody {
        requester: offer.our_user_hash,
        options: offer.options,
        file_hash: offer.file_hash,
        claimed_endpoint: offer.claimed_endpoint,
        transport_hint: Some(offer.transport),
    }
    .embed(buddy_id)
    .encode_udp();
    ClientUdpSend::plaintext(PeerEndpoint::V4(buddy_udp), datagram)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use rmule_peer::ReaskCallbackUdp;

    use super::*;

    /// Correction 5, as a property rather than a type layout: a stranger
    /// who exhausts the relay service's budget for an address has spent
    /// nothing of the acting path's, which still punches at that address for
    /// the rendezvous our buddy relayed to us.
    #[test]
    fn a_flood_on_the_relay_service_leaves_our_own_path_its_budget() {
        use rmule_peer::natt::{NattConnectOptions, PunchTargetSource};

        let t0 = Instant::now();
        let source = Ipv4Addr::new(45, 55, 200, 7);
        let mut relay = relay::RelayAdmission::default();
        assert_eq!(relay.admit(source, t0), Ok(()));
        assert!(
            relay.admit(source, t0).is_err(),
            "the relay budget is spent"
        );

        let buddy = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4672);
        let verdict = acting::ActingPath::default().consume(
            &RendezvousBody {
                requester: UserHash::from_bytes([0x11; 16]),
                options: NattConnectOptions::from_byte(0x80),
                file_hash: None,
                claimed_endpoint: None,
                transport_hint: None,
            },
            acting::RendezvousCarrier::BuddyTcp {
                link_peer: PeerEndpoint::V4(Ipv4Endpoint::new(buddy.ip, 51123)),
                observed: Ipv4Endpoint::new(source, 5000),
            },
            acting::ActingContext {
                our_buddy: Some(buddy),
                serves_quic: false,
                known_peer: |_| None,
                is_own_interface: |_| false,
            },
            t0,
        );
        assert!(
            matches!(
                verdict,
                acting::ActingVerdict::Punch {
                    target: rmule_peer::natt::PunchTarget {
                        source: PunchTargetSource::Observed,
                        ..
                    },
                    ..
                }
            ),
            "unexpected verdict: {verdict:?}"
        );
    }

    /// What goes out is what a buddy can route and a target can read: a
    /// `0x94` keyed on the buddy ID whose tail decodes as our rendezvous, with
    /// the endpoint-hint request set, addressed to the buddy and carrying no
    /// crypt target — so the send drain cannot obfuscate it.
    #[test]
    fn the_emitted_rendezvous_is_routable_readable_and_never_obfuscated() {
        let buddy_udp = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4672);
        let offer = RendezvousOffer {
            our_user_hash: UserHash::from_bytes([0x11; 16]),
            options: NattConnectOptions::advertise(0x03, true, false),
            file_hash: Some(FileHash::from_bytes([0x22; 16])),
            claimed_endpoint: None,
            transport: NattTransport::Utp,
        };
        let send = rendezvous_request(buddy_udp, [0xBB; 16], &offer);
        assert_eq!(send.to, PeerEndpoint::V4(buddy_udp));
        assert!(send.crypt_target.is_none());

        let relay = ReaskCallbackUdp::decode_udp(&send.datagram).expect("a 0x94");
        assert_eq!(relay.buddy_id, [0xBB; 16]);
        let body = RendezvousBody::from_forwarded(&relay.forwarded)
            .expect("marked as a rendezvous")
            .expect("well-formed");
        assert_eq!(body.requester, offer.our_user_hash);
        assert!(body.options.requests_endpoint_hint());
        assert!(body.options.supports_utp());
        assert_eq!(body.claimed_endpoint, None, "a null claim, not a guess");
        assert_eq!(body.transport_hint, Some(NattTransport::Utp));
    }
}
