//! The accept-side hello's buddy tags — `CT_EMULE_BUDDYIP`, `BUDDYUDP`
//! and `SERVINGBUDDYIPV6` — read off the wire as the
//! session writes it: the firewalled slot's fact, through the per-accept
//! options, into the bytes a peer receives; beside them every other advert
//! the one Hello Adverts read carries.

use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_primitives::{Ipv4Endpoint, PeerEndpoint};

use super::build_accept_options;
use crate::adapters::HelloAdverts;
use crate::adapters::tests::held_buddy::{BuddyTags, a_buddy, adopt, firewalled, hold, link, slot};
use crate::adapters::tests::hello_wire::{
    assert_states_live_adverts, live_adverts, read_hello_body,
};
use crate::firewalled::front::BuddyView;
use rmule_net::peer::{Connection as PeerConnection, PeerStreamRole};
use rmule_peer::PeerHelloBody;

/// The hello a connection built from these connect options writes first on
/// the wire.
async fn first_hello(options: rmule_net::peer::ConnectOptions) -> PeerHelloBody {
    let (ours, mut theirs) = tokio::io::duplex(4096);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4662));
    let _conn = PeerConnection::over_stream(
        ours,
        peer,
        PeerStreamRole::Dialer,
        crate::adapters::tests::dialed_serve_ctx(),
        options,
    );
    read_hello_body(&mut theirs).await
}

/// The buddy tags of the hello this node's accept options write — every other
/// advert live beside them, and stated on every accept.
async fn hello_buddy_tags(adverts: &HelloAdverts) -> BuddyTags {
    let hello = first_hello(build_accept_options(adverts)).await;
    assert_states_live_adverts(&hello);
    BuddyTags::of(&hello)
}

/// The Kad half of the same fact: the `bi6` a source publish would carry
/// under the verdict the pump states.
fn kad_bi6(buddy: &BuddyView, firewalled: bool) -> Option<Ipv6Addr> {
    firewalled
        .then(|| buddy.snapshot().publish)
        .flatten()
        .and_then(|publish| publish.buddy_ipv6)
}

/// The hello names the buddy — `BUDDYIP` + `BUDDYUDP`
/// always, `SERVINGBUDDYIPV6` when it has an IPv6 — exactly while we are
/// firewalled behind a held link, the IPv6 exactly while the source publish
/// names it as `bi6`; all three drop with the link and with a server High ID.
/// An adopted buddy whose link is not up yet is not named: aMule links
/// `m_pBuddy` only at `KS_CONNECTED_BUDDY`.
#[tokio::test]
async fn the_hello_names_the_serving_buddy_exactly_while_the_link_is_held() {
    let buddy_v6: Ipv6Addr = "3fff:ed2:1::8".parse().unwrap();
    let (mut slot, buddy) = slot();
    let adverts = live_adverts(buddy.clone());
    // Self Reach, installed as the actor does: no High ID and
    // Kad unproven — firewalled.
    let own = crate::own_identity::SharedOwnIdentity::default();
    adverts.install_reach(firewalled(own.clone()));
    assert_eq!(
        hello_buddy_tags(&adverts).await,
        BuddyTags::default(),
        "no buddy, no tag"
    );

    // Adopted on the `0x5A`, the dial still in flight: no link, no tags.
    adopt(&mut slot);
    assert_eq!(
        hello_buddy_tags(&adverts).await,
        BuddyTags::default(),
        "dialing"
    );

    let _link = link(&mut slot, Some(buddy_v6));
    assert_eq!(
        hello_buddy_tags(&adverts).await,
        BuddyTags::naming_a_buddy(Some(buddy_v6))
    );
    assert_eq!(
        kad_bi6(&buddy, true),
        Some(buddy_v6),
        "one fact, both halves"
    );

    // A server High ID moves the union to reachable with the link still held:
    // the Kad row goes direct, and the hello stops naming a buddy with it.
    // Read per hello from the owner — no pump sync in between.
    own.set_connected_session(Some(crate::own_identity::ConnectedSession {
        server: None,
        client_id: rmule_primitives::ClientId::from_u32(0x0A00_0001),
    }));
    assert_eq!(hello_buddy_tags(&adverts).await, BuddyTags::default());
    assert_eq!(kad_bi6(&buddy, false), None);
    own.set_connected_session(None);
    assert_eq!(
        hello_buddy_tags(&adverts).await,
        BuddyTags::naming_a_buddy(Some(buddy_v6))
    );

    // The link is lost on the front's task: the very next hello drops all
    // three, with no pump tick in between.
    assert!(slot.on_link_closed(PeerEndpoint::V4(a_buddy().tcp), std::time::Instant::now()));
    assert_eq!(
        hello_buddy_tags(&adverts).await,
        BuddyTags::default(),
        "link lost"
    );

    // An IPv4-only buddy: the IPv4 pair rides, the IPv6 tag does not.
    let _link = hold(&mut slot, None);
    assert_eq!(
        hello_buddy_tags(&adverts).await,
        BuddyTags::naming_a_buddy(None)
    );
    assert_eq!(kad_bi6(&buddy, true), None);
}

/// The hello an inbound dial is answered with names the id the session holds
/// when the peer arrives: a mid-session `OP_IDCHANGE` moves the very next
/// answer, and the server it names is the live session's.
#[tokio::test]
async fn the_listeners_answer_names_the_id_a_mid_session_idchange_assigned() {
    use crate::adapters::{RuntimeServeRuntimeService, ServeRuntimeService};
    use crate::own_identity::ConnectedSession;

    let mut serve = RuntimeServeRuntimeService::new();
    let bound = serve
        .start(
            crate::adapters::tests::dialed_serve_ctx().identity,
            std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .await
        .unwrap();
    let own = serve.session.own_identity().clone();
    let server = Ipv4Endpoint::new(Ipv4Addr::new(10, 1, 2, 3), 4661);
    let login_id = rmule_primitives::ClientId::from_u32(0x0B02_010A);
    let reassigned = rmule_primitives::ClientId::from_u32(0x0C02_010A);
    own.set_connected_session(Some(ConnectedSession {
        server: Some(server),
        client_id: login_id,
    }));

    let dial = || async {
        let (_conn, identity) = PeerConnection::connect_identified(
            PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port())),
            crate::adapters::tests::dialed_serve_ctx(),
            rmule_net::peer::ConnectOptions::default(),
        )
        .await
        .expect("the listener answers");
        (identity.client_id(), identity.connected_server())
    };
    assert_eq!(dial().await, (login_id, Some(server)), "the login's id");

    own.reassign_client_id(reassigned);
    assert_eq!(
        dial().await,
        (reassigned, Some(server)),
        "the id the server assigned last"
    );
}

/// A callback dial-back enters the serve pipeline through the tunnel admit
/// the accept pump installed, so the hello it writes first names the live
/// session's server and the id it holds at the dial.
#[tokio::test]
async fn a_callback_dial_backs_hello_names_the_live_session() {
    use crate::adapters::{RuntimeServeRuntimeService, ServeRuntimeService};
    use crate::own_identity::ConnectedSession;

    let requester = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let requester_addr = PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        requester.local_addr().unwrap().port(),
    ));
    let mut serve = RuntimeServeRuntimeService::new();
    serve
        .start(
            crate::adapters::tests::dialed_serve_ctx().identity,
            std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .await
        .unwrap();
    let server = Ipv4Endpoint::new(Ipv4Addr::new(10, 1, 2, 3), 4661);
    let held = rmule_primitives::ClientId::from_u32(0x0B02_010A);
    serve
        .session
        .own_identity()
        .set_connected_session(Some(ConnectedSession {
            server: Some(server),
            client_id: held,
        }));

    serve
        .tunnel_admit
        .spawn_callback_dial_back(requester_addr, None);
    let (mut socket, _) =
        tokio::time::timeout(std::time::Duration::from_secs(2), requester.accept())
            .await
            .expect("the dial-back arrives")
            .unwrap();
    let hello = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        read_hello_body(&mut socket),
    )
    .await
    .expect("the dial-back's hello arrives");
    assert_eq!(hello.connected_server, server);
    assert_eq!(hello.client_id, held);
}

/// A callback dial-back's hello is the accept pump's: the admit seam builds
/// its options from the same Hello Adverts read, so the dial-back the
/// firewalled front asks for (a `0x95`'s or a `0x99`'s) states our ports, Kad
/// version, IPv6 and crypt support exactly as every other hello does. A
/// dial-back with no key is plaintext, so the hello is the first thing on the
/// wire.
#[tokio::test]
async fn a_callback_dial_backs_hello_states_every_advert() {
    let requester = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let requester_addr = PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        requester.local_addr().unwrap().port(),
    ));
    let admit = super::SharedTunnelAdmit::default();
    // The admit cell keeps only a weak sender, and the admitted connection
    // lives in the receiver's buffer: both are held for the leg.
    let (accept_tx, _accept_rx) = tokio::sync::mpsc::channel(4);
    admit.install_for_test(
        &accept_tx,
        rmule_testkit::peer_session::serverless_ctx(),
        live_adverts(BuddyView::default()),
    );

    admit.spawn_callback_dial_back(requester_addr, None);
    let (mut socket, _) =
        tokio::time::timeout(std::time::Duration::from_secs(2), requester.accept())
            .await
            .expect("the dial-back arrives")
            .unwrap();
    let hello = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        read_hello_body(&mut socket),
    )
    .await
    .expect("the dial-back's hello arrives");
    assert_states_live_adverts(&hello);
}
