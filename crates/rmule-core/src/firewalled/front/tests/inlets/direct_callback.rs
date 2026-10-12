//! The `0x95` direct-callback route (ADR-0061): a
//! firewalled node with no buddy at all dials a requester back where its
//! datagram came from — keyed on the requester's own hash when it requires
//! obfuscation and our policy allows, never while Kad is down.
//!
//! The dial-back is the dialer's: these legs read what the front asked of it
//! (whom, under which key) on a paused clock. What the real dial-back writes
//! on the wire — the crypt opening, the hello's adverts — is the admit seam's
//! to prove, and is proven there.

use super::*;
use crate::firewalled::direct_callback::DirectCallbackConsume;

/// A requester at a fixed endpoint: nothing is dialed for real here, so the
/// address only has to be recognisable in the dial-back the front asks for.
fn requester_at_9() -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 4662)
}

/// The hash a `0x95` names — the key an obfuscated dial-back is derived from.
fn requester_hash() -> UserHash {
    UserHash::from_bytes([0x77; UserHash::BYTE_LEN])
}

/// One `0x95` as the client-UDP front routes it: the requester is the datagram
/// source, and the body supplies the TCP port, the hash and the crypt stance.
fn direct_callback(requester: Ipv4Endpoint, connect_options: u8) -> FirewalledCommand {
    FirewalledCommand::DirectCallback(DirectCallbackConsume {
        requester: PeerEndpoint::V4(requester),
        user_hash: requester_hash(),
        connect_options,
    })
}

/// A `0x95` whose connect options require obfuscation is dialed back keyed on
/// the hash it named, while a requester that advertised no crypt at all is
/// dialed back in the clear on the same node — and the keyed one is counted
/// apart.
#[tokio::test(start_paused = true)]
async fn a_0x95_requiring_obfuscation_is_dialed_back_keyed_on_its_hash() {
    for (connect_options, key) in [(0x07u8, Some(requester_hash())), (0x00u8, None)] {
        let mut h = crypt_harness(Some(rmule_net::peer::ObfuscationPolicy::Supported));
        h.kad_started();
        h.front
            .send(direct_callback(requester_at_9(), connect_options))
            .await
            .expect("front running");
        assert_eq!(
            h.next_dial_back().await,
            DialBack {
                requester: PeerEndpoint::V4(requester_at_9()),
                obfuscate_toward: key,
            },
            "connect_options {connect_options:#04x}"
        );
        assert_eq!(
            h.diagnostics
                .snapshot()
                .session
                .direct_callbacks_obfuscated_total,
            u64::from(key.is_some()),
            "the obfuscated dial-back is counted apart from the plaintext one"
        );
    }
}

/// With obfuscation off, a requester that *requires* it is told nothing and
/// dialed nothing — aMule's own `TryToConnect` refusal — and the counter that
/// records our configuration turning somebody away is the only trace.
#[tokio::test(start_paused = true)]
async fn a_required_requester_is_not_dialed_while_our_crypt_is_off() {
    let mut h = crypt_harness(None);
    h.kad_started();
    h.front
        .send(direct_callback(requester_at_9(), 0x07))
        .await
        .expect("front running");
    settle().await;
    let session = h.diagnostics.snapshot().session;
    assert_eq!(session.direct_callbacks_crypt_incompatible_total, 1);
    assert_eq!(session.direct_callbacks_refused_total, 1);
    assert_eq!(session.direct_callbacks_dialed_total, 0);
    assert!(
        h.no_dial_back(),
        "no socket is opened toward a requester this node's policy cannot meet"
    );
}

/// **Kad Presence**, not a task-local copy: dropping the pump's
/// lease is the only way "Kad stopped" reaches the `0x95` gate — there is no
/// `KadStopped` command to send instead — and it takes effect with no dial
/// identity ever set, since a direct callback needs none.
#[tokio::test(start_paused = true)]
async fn a_direct_callback_is_refused_once_the_kad_lease_is_gone() {
    let mut h = crypt_harness(None);
    drop(h.kad_lease.take());
    h.front
        .send(direct_callback(requester_at_9(), 0x00))
        .await
        .expect("front running");
    settle().await;
    let session = h.diagnostics.snapshot().session;
    assert_eq!(session.direct_callbacks_refused_total, 1);
    assert_eq!(session.direct_callbacks_dialed_total, 0);
    assert!(
        h.no_dial_back(),
        "no socket is opened while Kad presence reads no node"
    );
}

/// The other half of the same proof: the lease held — with no Kad start
/// published at all, since a start carries no "Kad runs" fact — is already
/// enough for the same gate to dial back.
#[tokio::test(start_paused = true)]
async fn a_direct_callback_is_dialed_back_while_the_kad_lease_is_held() {
    let mut h = crypt_harness(None);
    h.front
        .send(direct_callback(requester_at_9(), 0x00))
        .await
        .expect("front running");
    assert_eq!(
        h.next_dial_back().await,
        DialBack {
            requester: PeerEndpoint::V4(requester_at_9()),
            obfuscate_toward: None,
        }
    );
}

/// The `0x95` gate reads **Self Reach**'s Kad TCP verdict at the
/// request (`ClientUDPSocket.cpp:286`, `4e8f2b3c`: Kad running and Kad
/// firewalled) — not a copy the pump pushed, which a full inbox lost and a
/// Kad restart never restated. Once the verdict reads open, the next `0x95`
/// is refused `NotFirewalled` and dialed nowhere.
#[tokio::test(start_paused = true)]
async fn a_0x95_is_refused_once_self_reach_reads_kad_open() {
    let mut h = live_harness();
    h.kad_started();
    h.kad.set_tcp(crate::reachability::TcpReachability::Open);
    h.front
        .send(direct_callback(requester_at_9(), 0x00))
        .await
        .expect("front running");
    settle().await;
    let session = h.diagnostics.snapshot().session;
    assert_eq!(session.direct_callbacks_refused_total, 1);
    assert_eq!(session.direct_callbacks_dialed_total, 0);
    assert!(h.no_dial_back());
}
