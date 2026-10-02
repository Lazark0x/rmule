//! The `0x95` direct-callback route (ADR-0061): a
//! firewalled node with no buddy at all dials a requester back where its
//! datagram came from — obfuscated when the requester requires it and our
//! policy allows, never while Kad is down.

use super::*;
use crate::firewalled::direct_callback::DirectCallbackConsume;

/// A firewalled node with no buddy at all — the `0x95` route's own shape, which
/// needs nothing recruited.
fn unbuddied() -> SharedFirewalledSlot {
    std::sync::Arc::new(FirewalledSlot::new(rmule_kad::KadId::from_bytes(
        [OUR_KAD_ID; rmule_kad::KadId::BYTE_LEN],
    )))
}

/// One `0x95` as the client-UDP front routes it: the requester is the datagram
/// source, and the body supplies the TCP port, the hash and the crypt stance.
fn direct_callback(requester: Ipv4Endpoint, connect_options: u8) -> FirewalledCommand {
    FirewalledCommand::DirectCallback(DirectCallbackConsume {
        requester: PeerEndpoint::V4(requester),
        user_hash: UserHash::from_bytes([0x77; UserHash::BYTE_LEN]),
        connect_options,
    })
}

/// The obfuscated dial-back, read off the wire: a `0x95` whose connect
/// options require obfuscation is answered by a dial-back whose **first byte is
/// not a protocol marker** — the crypt handshake's opening, not a plaintext
/// `0xE3` hello — while a requester that advertised no crypt at all still gets
/// the plaintext hello on the same node.
///
/// Loopback is the requester here, unlike this module's rendezvous legs: the
/// `0x95` consume has no public-address guard to weaken (the requester *is* the
/// datagram source, which the ADR-0061 route reads verbatim), so the address is
/// free to be the socket the leg actually reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_0x95_requiring_obfuscation_is_dialed_back_obfuscated() {
    for (connect_options, want_marker) in [(0x07u8, false), (0x00u8, true)] {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let requester = Ipv4Endpoint::new(
            Ipv4Addr::LOCALHOST,
            listener.local_addr().expect("addr").port(),
        );
        let h = crypt_harness(
            &unbuddied(),
            Some(rmule_net::peer::ObfuscationPolicy::Supported),
        );
        let _pipeline = h.start_serving();
        h.front.send(kad_started()).await.expect("front running");
        h.front
            .send(direct_callback(requester, connect_options))
            .await
            .expect("front running");

        let (mut sock, _) = within("the dial-back", async { listener.accept().await.ok() }).await;
        let mut first = [0u8; 1];
        within("the dial-back's first byte", async {
            sock.read_exact(&mut first).await.ok()
        })
        .await;
        assert_eq!(
            rmule_primitives::is_plaintext_marker(first[0]),
            want_marker,
            "connect_options {connect_options:#04x} produced first byte {:#04x}",
            first[0]
        );
        assert_eq!(
            h.diagnostics
                .snapshot()
                .session
                .direct_callbacks_obfuscated_total,
            u64::from(!want_marker),
            "the obfuscated dial-back is counted apart from the plaintext one"
        );
    }
}

/// A callback dial-back enters the serve pipeline through the
/// admit seam, whose options are the accept pump's — so its hello states our
/// ports, Kad version, IPv6 and crypt support exactly as every other hello
/// does. A requester that stated no crypt is dialed plaintext, so the hello is
/// the first thing on the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_0x95_dial_back_hello_states_every_advert() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let requester = Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        listener.local_addr().expect("addr").port(),
    );
    let h = live_harness(&unbuddied());
    let _pipeline = h.start_serving();
    h.front.send(kad_started()).await.expect("front running");
    h.front
        .send(direct_callback(requester, 0x00))
        .await
        .expect("front running");

    let (mut sock, _) = within("the dial-back", async { listener.accept().await.ok() }).await;
    let hello = within("the dial-back's hello", async {
        Some(crate::adapters::tests::hello_wire::read_hello_body(&mut sock).await)
    })
    .await;
    crate::adapters::tests::hello_wire::assert_states_live_adverts(&hello);
}

/// With obfuscation off, a requester that *requires* it is told nothing and
/// dialed nothing — aMule's own `TryToConnect` refusal — and the counter that
/// records our configuration turning somebody away is the only trace.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_required_requester_is_not_dialed_while_our_crypt_is_off() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let requester = Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        listener.local_addr().expect("addr").port(),
    );
    let h = crypt_harness(&unbuddied(), None);
    let _pipeline = h.start_serving();
    h.front.send(kad_started()).await.expect("front running");
    h.front
        .send(direct_callback(requester, 0x07))
        .await
        .expect("front running");

    within("the crypt-incompatible refusal", async {
        for _ in 0..200 {
            let session = h.diagnostics.snapshot().session;
            if session.direct_callbacks_crypt_incompatible_total == 1 {
                assert_eq!(session.direct_callbacks_refused_total, 1);
                assert_eq!(session.direct_callbacks_dialed_total, 0);
                return Some(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    })
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_err(),
        "no socket is opened toward a requester this node's policy cannot meet"
    );
}

/// **Kad Presence**, not a task-local copy: dropping the pump's
/// lease is the only way "Kad stopped" reaches the `0x95` gate — there is no
/// `KadStopped` command to send instead — and it takes effect with no dial
/// identity ever set, since a direct callback needs none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_callback_is_refused_once_the_kad_lease_is_gone() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let requester = Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        listener.local_addr().expect("addr").port(),
    );
    let h = crypt_harness(&unbuddied(), None);
    let _pipeline = h.start_serving();
    drop(h.kad_lease);
    h.front
        .send(direct_callback(requester, 0x00))
        .await
        .expect("front running");

    within("the Kad-down refusal", async {
        for _ in 0..200 {
            let session = h.diagnostics.snapshot().session;
            if session.direct_callbacks_refused_total == 1 {
                assert_eq!(session.direct_callbacks_dialed_total, 0);
                return Some(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    })
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_err(),
        "no socket is opened while Kad presence reads no node"
    );
}

/// The other half of the same proof: the lease held — never a `KadStarted`
/// carrying it, there is nothing for that command to carry any more — is
/// already enough for the same gate to dial back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_callback_is_dialed_back_while_the_kad_lease_is_held() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let requester = Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        listener.local_addr().expect("addr").port(),
    );
    let h = crypt_harness(&unbuddied(), None);
    let _pipeline = h.start_serving();
    h.front
        .send(direct_callback(requester, 0x00))
        .await
        .expect("front running");

    let (mut sock, _) = within("the dial-back", async { listener.accept().await.ok() }).await;
    let mut first = [0u8; 1];
    within("the dial-back's first byte", async {
        sock.read_exact(&mut first).await.ok()
    })
    .await;
    assert!(
        rmule_primitives::is_plaintext_marker(first[0]),
        "an unobfuscated dial-back opens with the plaintext hello marker"
    );
}

/// The `0x95` gate reads **Self Reach**'s Kad TCP verdict at the
/// request (`ClientUDPSocket.cpp:286`, `4e8f2b3c`: Kad running and Kad
/// firewalled) — not a copy the pump pushed, which a full inbox lost and a
/// Kad restart never restated. Once the verdict reads open, the next `0x95`
/// is refused `NotFirewalled` and dialed nowhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_0x95_is_refused_once_self_reach_reads_kad_open() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let requester = Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        listener.local_addr().expect("addr").port(),
    );
    let h = live_harness(&unbuddied());
    let _pipeline = h.start_serving();
    h.front.send(kad_started()).await.expect("front running");
    h.kad.set_tcp(crate::reachability::TcpReachability::Open);
    h.front
        .send(direct_callback(requester, 0x00))
        .await
        .expect("front running");
    until("the refusal", || {
        h.diagnostics
            .snapshot()
            .session
            .direct_callbacks_refused_total
            == 1
    })
    .await;
    assert_eq!(
        h.diagnostics
            .snapshot()
            .session
            .direct_callbacks_dialed_total,
        0
    );
}
