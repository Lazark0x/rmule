//! Session-level dispatch for both halves of the ADR-0061 buddy link.
//!
//! **Open node** (we relay for a firewalled client): the two verified relay
//! outputs (`OP_CALLBACK` `0x99`, `OP_REASKCALLBACKTCP` `0x9A`) and the
//! keepalive pong (`OP_BUDDYPONG` `0xA0`) framed over the link, plus an inbound
//! `OP_BUDDYPING` `0x9F` surfacing as `BuddyPingReceived`.
//!
//! **Firewalled node** (our own buddy relays *to* us): the same two
//! opcodes arriving inbound, decoded and surfaced as events, and the
//! `OP_BUDDYPING` we send to keep the link we dialed alive.
//!
//! The verify decisions (buddy-ID match, the our-buddy pong gate, the acting
//! path's carrier rule) are core-side; this proves the session frames exactly
//! what core commands and surfaces exactly what arrived — and that neither
//! happens before the link has identified.

use std::net::Ipv4Addr;

use crate::fixture::identified_session;
use rmule_peer::{
    Callback, ConnectionEvent, NoticeEvent, PeerCommand, PeerEvent, PeerSession, ReaskCallbackTcp,
    SideCommand, SideEvent,
};
use rmule_primitives::session::drain;
use rmule_primitives::{FileHash, Ipv4Endpoint, Packet, PacketProtocol, PeerEndpoint};
use rmule_testkit::peer_session::{ctx, events, peer_at, writes};

fn a_callback() -> Callback {
    Callback {
        buddy_id: [0x7A; 16],
        file_hash: FileHash::from_bytes([0xCD; 16]),
        requester: Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 5), 4662),
    }
}

#[test]
fn the_buddy_relays_and_pong_frame_over_the_link_only_once_identified() {
    // aMule sends a relay only over a fully-connected buddy socket
    // (`buddy->GetSocket()`). Before the buddy link's hello completes — a fresh
    // outbound session that has only sent its own hello — the relay frames nothing.
    let mut fresh = PeerSession::new_outbound(peer_at(55), ctx());
    fresh.start();
    let _ = drain(|| fresh.poll_output());
    fresh.handle_command(PeerCommand::Side(SideCommand::SendBuddyCallback(
        a_callback(),
    )));
    assert!(
        writes(&drain(|| fresh.poll_output()))
            .iter()
            .all(|p| p.opcode() != 0x99),
        "no 0x99 is framed before the buddy link identifies"
    );

    // On an identified buddy link each relay/pong frames its exact packet, verbatim
    // from the `crate::buddy` codec (never round-tripped through the umbrella).
    let mut session = identified_session();

    session.handle_command(PeerCommand::Side(SideCommand::SendBuddyCallback(
        a_callback(),
    )));
    let sent = writes(&drain(|| session.poll_output()));
    let expected = a_callback().encode_packet();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].opcode(), 0x99);
    assert_eq!(sent[0].protocol(), PacketProtocol::Emule);
    assert_eq!(sent[0].payload(), expected.payload());

    let reask = ReaskCallbackTcp {
        requester: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 9), 4662)),
        forwarded: vec![0xDE, 0xAD],
    };
    session.handle_command(PeerCommand::Side(SideCommand::SendReaskCallbackTcp(
        reask.clone(),
    )));
    let sent = writes(&drain(|| session.poll_output()));
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].opcode(), 0x9A);
    assert_eq!(sent[0].payload(), reask.encode_packet().payload());

    session.handle_command(PeerCommand::Side(SideCommand::SendBuddyPong));
    let pong = writes(&drain(|| session.poll_output()));
    assert_eq!(pong.len(), 1);
    assert_eq!(pong[0].opcode(), 0xA0, "OP_BUDDYPONG");
    assert!(pong[0].payload().is_empty(), "the pong is a null keepalive");
}

#[test]
fn an_inbound_buddy_ping_surfaces_as_the_core_decided_event() {
    // The firewalled buddy's keepalive: an inbound OP_BUDDYPING (0x9F) is surfaced
    // as BuddyPingReceived so the owner routes it to the core buddy service's pong
    // gate (answer our buddy, refuse a stranger). The session never auto-pongs, and
    // a keepalive never reads as a protocol violation.
    let mut session = identified_session();
    let ping = Packet::new(PacketProtocol::Emule, 0x9F, Vec::new()).encode();
    session.handle_bytes(&ping);
    let out = drain(|| session.poll_output());
    assert!(
        events(&out).contains(&&PeerEvent::Side(SideEvent::BuddyPingReceived)),
        "the ping surfaces as BuddyPingReceived"
    );
    assert!(
        writes(&out).is_empty(),
        "the session does not auto-pong — the pong is core's decision"
    );
}

#[test]
fn the_relays_our_own_buddy_forwards_surface_decoded_and_wire_silent() {
    // The firewalled-node consume: our buddy forwards a `0x99` and
    // a `0x9A` over the link we dialed. Both decode to their `crate::buddy`
    // codecs and surface as events — the buddy-ID XOR check, the file gate and
    // the answer's route are core's — and neither puts a byte on this link: the
    // `0x99`'s answer is a fresh TCP dial, the `0x9A`'s a client-UDP datagram.
    let mut session = identified_session();
    let callback = a_callback();
    let relay = ReaskCallbackTcp {
        requester: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 9), 5099)),
        forwarded: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    session.handle_bytes(&callback.encode_packet().encode());
    session.handle_bytes(&relay.encode_packet().encode());

    let out = drain(|| session.poll_output());
    let seen = events(&out);
    assert!(
        seen.contains(&&PeerEvent::Side(SideEvent::BuddyCallbackReceived {
            callback: callback.clone()
        })),
        "the 0x99 surfaces decoded: {seen:?}"
    );
    assert!(
        seen.contains(&&PeerEvent::Side(SideEvent::BuddyReaskCallbackReceived {
            relay: relay.clone()
        })),
        "the 0x9A surfaces decoded: {seen:?}"
    );
    assert!(
        writes(&out).is_empty(),
        "neither relay is answered on the buddy link"
    );
}

#[test]
fn a_malformed_relay_parks_as_unknown_rather_than_tearing_the_buddy_link_down() {
    // ADR-0018 liberal receive. The link carries every relay our buddy will ever
    // forward, so one truncated frame must not close it — and the gates that
    // decide anything are core's, which never see an `Unknown`.
    let mut session = identified_session();
    session.handle_bytes(&Packet::new(PacketProtocol::Emule, 0x99, vec![0x01, 0x02]).encode());
    let out = drain(|| session.poll_output());
    assert!(
        events(&out).iter().any(|event| matches!(
            event,
            PeerEvent::Notice(NoticeEvent::UnknownPacket { opcode: 0x99, .. })
        )),
        "a short 0x99 is preserved, not fatal: {:?}",
        events(&out)
    );
    assert!(
        !events(&out).iter().any(|event| matches!(
            event,
            PeerEvent::Connection(ConnectionEvent::Disconnected { .. })
        )),
        "the buddy link stays open"
    );
}

#[test]
fn our_own_buddy_link_is_kept_alive_by_the_ping_we_send() {
    // The firewalled side pings; the open side pongs (aMule `BaseClient.cpp`
    // `SendBuddyPing`). The cadence is the firewalled front's — the session only
    // frames the null packet, and only once the link it dialed has identified.
    let mut fresh = PeerSession::new_outbound(peer_at(55), ctx());
    fresh.start();
    let _ = drain(|| fresh.poll_output());
    fresh.handle_command(PeerCommand::Side(SideCommand::SendBuddyPing));
    assert!(
        writes(&drain(|| fresh.poll_output()))
            .iter()
            .all(|p| p.opcode() != 0x9F),
        "no ping before the buddy link identifies"
    );

    let mut session = identified_session();
    session.handle_command(PeerCommand::Side(SideCommand::SendBuddyPing));
    let sent = writes(&drain(|| session.poll_output()));
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].opcode(), 0x9F, "OP_BUDDYPING");
    assert_eq!(sent[0].protocol(), PacketProtocol::Emule);
    assert!(sent[0].payload().is_empty(), "the ping is a null keepalive");
}
