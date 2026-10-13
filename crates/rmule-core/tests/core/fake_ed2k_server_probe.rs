//! Probe-unit tests for `FakeEd2kServer`'s High-ID **Back-Connect Probe**
//! (ADR-0040 Correctness Tier), capture-corrected to the bench Lugdunum 17.15
//! semantics: the check is a protocol exchange — the server
//! back-connects the advertised port, sends `OP_HELLO`, and grants High-ID
//! only when an `OP_HELLOANSWER` with the login's user hash comes back within
//! the window. A merely-accepted (mute) port fails the check, exactly as the
//! real server does ("WARNING : No answer from your <port> port"). Includes
//! the serve-adapter regression: `RuntimeServeRuntimeService::start` must
//! answer the check *during* the login (accepting concurrently), or the login
//! lands Low-ID.

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::fixture::identity_with_port;
use crate::fixture::login_and_read_id;
use crate::fixture::{dead_port, free_port};
use rmule_core::{RuntimeServeRuntimeService, ServeRuntimeService};
use rmule_testkit::{FakeEd2kServer, spawn_check_answering_listener};
use tokio::net::TcpListener;

#[tokio::test]
async fn probe_answered_check_grants_high_id() {
    let server = FakeEd2kServer::start().await;

    // A listener that answers the check `OP_HELLO` as the logging-in identity:
    // the exchange completes, so the login earns High-ID.
    let (p, listener) = spawn_check_answering_listener(identity_with_port(0)).await;

    let id = login_and_read_id(server.local_addr(), p).await;
    assert!(
        id.is_high_id(),
        "an answered port check must grant High-ID, got {id:?}"
    );
    listener.abort();
}

#[tokio::test]
async fn probe_mute_accepted_port_assigns_low_id() {
    let server = FakeEd2kServer::start().await;

    // Bind a listener on P that accepts but never answers the check `OP_HELLO`
    // — rmule's posture before its serve listener answered the back-connect.
    // The real Lugdunum fails this check ("No answer from your <port> port"),
    // so the fake must too.
    let peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = peer_listener.local_addr().unwrap().port();
    let listener = tokio::spawn(async move { while peer_listener.accept().await.is_ok() {} });

    let id = login_and_read_id(server.local_addr(), p).await;
    assert!(
        id.is_low_id(),
        "a mute (accepted, unanswered) port must assign Low-ID, got {id:?}"
    );
    listener.abort();
}

#[tokio::test]
async fn probe_unreachable_advertised_port_assigns_low_id() {
    let server = FakeEd2kServer::start().await;

    // Advertise a port nothing listens on: the back-connect is refused.
    let p = dead_port().await;

    let id = login_and_read_id(server.local_addr(), p).await;
    assert!(
        id.is_low_id(),
        "an unreachable advertised port must assign Low-ID, got {id:?}"
    );
}

/// The serve adapter's `start` binds the listener and keeps
/// accepting from its own pump, so a server's port-check `OP_HELLO` arriving
/// while a login is in flight is answered inside the check window and the
/// login earns High-ID. The serve dials no server itself (ADR-0095); the
/// login here is the operator's, made on a raw connection advertising the
/// listener's port.
#[tokio::test]
async fn a_started_serve_answers_the_port_check_of_a_login_in_flight() {
    let server = FakeEd2kServer::start().await;

    // A fixed port with identity.tcp_port == listen port, as production binds
    // (the serve CLI aligns them; see ADR-0040).
    let p = free_port().await;
    let mut serve = RuntimeServeRuntimeService::new();
    let bound = serve
        .start(
            identity_with_port(p),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, p),
        )
        .await
        .expect("serve start");
    assert_eq!(bound.port(), p, "serve bound the requested port");
    assert!(
        server.assigned_ids().await.is_empty(),
        "a serve start logs nobody in"
    );

    let id = login_and_read_id(server.local_addr(), p).await;
    assert!(
        id.is_high_id(),
        "the listener must answer the port check during the login and earn High-ID, got {id:?}"
    );
}

/// The fake holds a login to the dialect's "send both or neither": the
/// `CT_MOD_IP_V6` tag rides exactly when `CT_SERVER_FLAGS` sets
/// `SRVCAP_IPV6`. The pair is served; either half alone is dropped before an
/// id is granted, so a client that splits them fails its login wait.
#[tokio::test]
async fn a_login_must_pair_the_ipv6_tag_with_its_flag_bit() {
    use rmule_ed2k::{LoginAdvert, LoginRequest};
    use rmule_primitives::{Capabilities, CryptStance, Tag, TagValue};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SRVCAP_IPV6: u32 = 0x1000;
    let server = FakeEd2kServer::start().await;
    let identity = identity_with_port(dead_port().await);
    let paired = LoginRequest::from_identity_advertising(
        &identity,
        &Capabilities::shipped(CryptStance::disabled()),
        LoginAdvert {
            ipv6: Some("2001:db8::9".parse().unwrap()),
            udp_ports: None,
        },
    );
    let flags_flipped = |tags: &[Tag]| -> Vec<Tag> {
        tags.iter()
            .map(|tag| match tag.value() {
                TagValue::U32(flags) if tag.name().id() == Some(0x20) => {
                    Tag::new(tag.name().clone(), TagValue::U32(flags ^ SRVCAP_IPV6))
                }
                _ => tag.clone(),
            })
            .collect()
    };
    let rebuilt = |tags: Vec<Tag>| {
        LoginRequest::new(
            paired.user_hash(),
            paired.client_id(),
            paired.tcp_port(),
            tags,
        )
    };
    let tag_alone = rebuilt(flags_flipped(paired.tags()));
    let without_tag: Vec<Tag> = paired
        .tags()
        .iter()
        .filter(|tag| tag.name().id() != Some(0xAE))
        .cloned()
        .collect();
    let flag_alone = rebuilt(without_tag);

    let answered = |login: LoginRequest| {
        let addr = server.local_addr();
        async move {
            let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
            sock.write_all(&login.encode_packet().encode())
                .await
                .unwrap();
            let mut first = [0u8; 1];
            matches!(
                tokio::time::timeout(rmule_testkit::HANG_GUARD, sock.read(&mut first)).await,
                Ok(Ok(1))
            )
        }
    };
    assert!(answered(paired.clone()).await, "the pair is served");
    assert!(
        !answered(tag_alone).await,
        "the tag without the bit is dropped"
    );
    assert!(
        !answered(flag_alone).await,
        "the bit without the tag is dropped"
    );
}
