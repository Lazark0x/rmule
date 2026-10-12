//! What arrives for the front and is answered (`front::inlets`): the held
//! link's relayed `0x9A` and `0x99`, and the client-UDP surface's standalone
//! `0xA0` and `0x95`.

use super::*;

mod direct_callback;
mod relayed_callback;

/// The `0x9A` a buddy relays for an embedded rendezvous: the requester it
/// observed, then the forwarded tail the requester's `0x94` carried.
fn relayed_rendezvous() -> PeerEvent {
    let body = RendezvousBody {
        requester: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
        options: NattConnectOptions::from_byte(0x80),
        file_hash: None,
        claimed_endpoint: None,
        transport_hint: None,
    };
    PeerEvent::Side(SideEvent::BuddyReaskCallbackReceived {
        relay: ReaskCallbackTcp {
            requester: PeerEndpoint::V4(requester()),
            forwarded: body.embed([BUDDY_ID; 16]).forwarded,
        },
    })
}

/// The done-when leg: adopt, dial, hold, and act on a rendezvous relayed
/// over the held link.
#[tokio::test(start_paused = true)]
async fn a_rendezvous_relayed_over_the_held_buddy_link_becomes_a_punch() {
    let mut h = harness();
    let mut side = h.hold().await;

    side.send(relayed_rendezvous()).await;
    // The acting path ruled, and the NAT-T front was asked to punch — with the
    // Responder role, because the requester asked for the introduction and so
    // dials, and with the burst, because nothing has left yet on this path.
    let command = within("the acting punch", h.natt.recv()).await;
    assert!(
        matches!(
            command,
            NattCommand::Introduced {
                target,
                role: rmule_ed2k::HolepunchRole::Responder,
                burst: true,
                ..
            } if target == requester()
        ),
        "unexpected NAT-T command: {command:?}"
    );
    settle().await;
    assert_eq!(h.diagnostics.snapshot().session.acting_punches_total, 1);
    assert_eq!(
        h.buddy.snapshot().state,
        BuddyState::Held,
        "the link the relay rode is the one we dialed"
    );
    assert!(
        side.commands.try_recv().is_err(),
        "the firewalled side never relays back down its own buddy link"
    );
}

/// An ordinary relayed reask re-enters the ADR-0057 reply matrix, addressed to
/// the requester the buddy injected — aMule's own
/// `ProcessPacket(..., OP_REASKFILEPING, destip, destport)`.
#[tokio::test(start_paused = true)]
async fn an_ordinary_relayed_reask_re_enters_the_reply_matrix() {
    let mut h = harness();
    let side = h.hold().await;
    let file = FileHash::from_bytes([0xCD; FileHash::BYTE_LEN]);
    // The tail a `0x94` carried: a UDPv4 `0x90` body — hash, count-zero
    // status, complete-source count (stock 2.3.3 `DownloadClient.cpp:
    // 1278-1291`) — header stripped by the relay. It is re-entered whole, so
    // the serve side reads its status as it reads a direct ping's.
    let forwarded = [file.as_bytes().as_slice(), &[0x00, 0x00, 0x00, 0x00]].concat();
    side.send(PeerEvent::Side(SideEvent::BuddyReaskCallbackReceived {
        relay: ReaskCallbackTcp {
            requester: PeerEndpoint::V4(requester()),
            forwarded: forwarded.clone(),
        },
    }))
    .await;

    let (to, datagram) = within("the injected reask", h.reask.recv()).await;
    assert_eq!(to, PeerEndpoint::V4(requester()));
    let mut expected = vec![PacketProtocol::Emule.as_byte(), 0x90];
    expected.extend_from_slice(&forwarded);
    assert_eq!(
        datagram, expected,
        "the two-byte peer-UDP header the relay stripped is put back"
    );
}

/// A standalone `0xC5 0xA0` from a stranger's endpoint is refused by the
/// carrier gate and counted — the acting path's only other inlet.
#[tokio::test(start_paused = true)]
async fn a_standalone_rendezvous_from_a_stranger_is_refused() {
    let h = quiet_harness();
    h.front
        .send(FirewalledCommand::StandaloneRendezvous {
            from: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 99), 4672)),
            body: Box::new(RendezvousBody {
                requester: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
                options: NattConnectOptions::from_byte(0x80),
                file_hash: None,
                claimed_endpoint: Some(requester()),
                transport_hint: None,
            }),
        })
        .await
        .expect("front running");
    settle().await;
    let session = h.diagnostics.snapshot().session;
    assert_eq!(session.acting_refusals_total, 1);
    assert_eq!(
        session.acting_last_refusal,
        Some(crate::diagnostics::ActingRefusal::NotFromOurBuddy)
    );
}
