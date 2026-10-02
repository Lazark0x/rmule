//! The **Held Burst**'s clock: a burst held for half the measured round trip
//! leaves on its own deadline — not on whichever 1 s tick comes next — and an
//! attempt that ends first takes its held burst with it.

use super::*;

/// How late past its computed deadline a released burst may reach the send
/// half. Paused tokio time makes the deadline exact; this only absorbs the
/// loop's own turn.
const RELEASE_SLACK: Duration = Duration::from_millis(5);

/// The whole loop, on paused time: the rendezvous leaves at t0, the hint
/// arrives 240 ms later, and the burst leaves 120 ms after that — not at the
/// 1 s tick, which is where a tick-driven release would have put it (runs
/// `1790112805`, `1790117113`, `1790107977` measured 326–986 ms).
#[tokio::test(start_paused = true)]
async fn a_held_burst_leaves_on_its_own_deadline_not_the_next_tick() {
    let Harness {
        front,
        mut sent,
        risen,
        ..
    } = Harness::new();
    let (inbox, inbox_rx) = mpsc::channel::<ClientUdpDatagram>(8);
    let (commands, command_rx) = mpsc::channel::<NattCommand>(8);
    let run = tokio::spawn(front.run(inbox_rx, command_rx, risen));
    let target = hash(0x44);

    commands
        .send(rendezvous_toward(target))
        .await
        .expect("the loop is running");
    let rendezvous = sent.recv().await.expect("the rendezvous leaves");
    assert_eq!(rendezvous.to, PeerEndpoint::V4(buddy()));

    tokio::time::sleep(Duration::from_millis(240)).await;
    let heard = tokio::time::Instant::now();
    inbox
        .send((PeerEndpoint::V4(buddy()), hint_naming(target, at(9, 31999))))
        .await
        .expect("the loop is running");

    let first = sent.recv().await.expect("the burst leaves");
    let waited = heard.elapsed();
    assert_eq!(first.to, PeerEndpoint::V4(at(9, 31999)));
    assert_eq!(first.datagram, holepunch_datagram());
    let hold = Duration::from_millis(120);
    assert!(
        waited >= hold && waited <= hold + RELEASE_SLACK,
        "held {waited:?}, computed {hold:?}"
    );
    run.abort();
}

/// Begin toward `target`, hear its hint 240 ms later naming `endpoint`, and
/// return when the 120 ms hold falls due.
async fn held_toward(harness: &mut Harness, target: UserHash, endpoint: Ipv4Endpoint) -> Instant {
    let t0 = Instant::now();
    harness.begin(target, t0).await;
    let heard = t0 + Duration::from_millis(240);
    harness
        .front
        .on_datagram(
            PeerEndpoint::V4(buddy()),
            hint_naming(target, endpoint),
            heard,
        )
        .await;
    assert!(harness.drained().is_empty(), "the burst is held");
    heard + Duration::from_millis(120)
}

/// An attempt that retires inside the hold takes the burst with it: the
/// deadline passes and nothing is punched and nothing is dialed.
#[tokio::test]
async fn a_retirement_inside_the_hold_cancels_the_burst_and_its_dial() {
    let mut harness = Harness::new();
    let target = hash(0x44);
    let due = held_toward(&mut harness, target, at(9, 31999)).await;

    harness
        .front
        .retire_attempt(
            target,
            AttemptRetirement::Schedule(RetireReason::TimedOut),
            due - Duration::from_millis(60),
        )
        .await;
    harness.front.release_held(due).await;

    assert!(
        harness.drained().is_empty(),
        "no burst after the attempt ended"
    );
    assert!(!harness.front.dials.in_flight(target), "and no dial");
}

/// Run `1790117113`'s shape: the path the burst was aimed at carried a Tunnel
/// that has already closed. A release after that close would dial a second
/// Tunnel toward a peer the first one served, so the close cancels the hold.
#[tokio::test]
async fn a_closed_path_cancels_the_burst_held_toward_it() {
    let mut harness = Harness::new();
    let target = hash(0x44);
    let aimed = at(9, 31999);
    let due = held_toward(&mut harness, target, aimed).await;

    harness
        .front
        .on_risen(Risen::Closed { at: aimed }, due - Duration::from_millis(60))
        .await;
    harness.front.release_held(due).await;

    assert!(harness.drained().is_empty(), "no burst at a closed path");
    assert!(!harness.front.dials.in_flight(target), "and no second dial");
}

/// The hint named one port on an address and the punched path
/// rose on another port of the very same address — the NAT remapped it,
/// which is the whole reason the observed source outranks the hint. With
/// only one peer pending behind that address, attribution needs nothing more
/// than the address, and adoption takes the held burst with it: no burst, no
/// second dial.
#[tokio::test]
async fn an_accepted_path_on_a_remapped_port_ends_its_only_pending_peer() {
    let mut harness = Harness::new();
    let target = hash(0x44);
    let hinted = at(9, 31999);
    let remapped = at(9, 40000);
    let due = held_toward(&mut harness, target, hinted).await;

    let peer = harness.front.attribute_accepted(remapped);
    assert_eq!(
        peer,
        Some(target),
        "the lone pending peer behind the address"
    );
    harness.front.identified(peer.expect("attributed above"));

    harness.front.release_held(due).await;
    assert!(harness.drained().is_empty(), "no burst after adoption");
    assert!(!harness.front.dials.in_flight(target), "and no second dial");
}

/// The narrow case of a Tunnel accepted on a NAT-remapped port: two peers
/// pending behind one address are told apart by nothing an accepted path
/// alone carries, so attribution names
/// none of them — a wrong hash is worse than none. Only the Tunnel's own
/// hello, reported back as [`Risen::Identified`] once something downstream
/// reads it, resolves which one it was; the other's hold is untouched and
/// still fires on its own deadline.
#[tokio::test]
async fn two_peers_behind_one_address_the_hello_resolves_which_hold_dies() {
    let mut harness = Harness::new();
    let (alice, bob) = (hash(0x44), hash(0x55));
    let t0 = Instant::now();
    harness.begin(alice, t0).await;
    harness.begin(bob, t0).await;

    let heard = t0 + Duration::from_millis(240);
    harness
        .front
        .on_datagram(
            PeerEndpoint::V4(buddy()),
            hint_naming(alice, at(9, 31999)),
            heard,
        )
        .await;
    harness
        .front
        .on_datagram(
            PeerEndpoint::V4(buddy()),
            hint_naming(bob, at(9, 32000)),
            heard,
        )
        .await;
    assert!(harness.drained().is_empty(), "both bursts are held");
    let due = heard + Duration::from_millis(120);

    let observed = at(9, 51515);
    assert_eq!(
        harness.front.attribute_accepted(observed),
        None,
        "neither pending peer's port names it; attributed to none"
    );

    harness
        .front
        .on_risen(Risen::Identified { peer: alice }, due)
        .await;

    harness.front.release_held(due).await;
    let fired = harness.drained();
    assert_eq!(
        fired.len(),
        rmule_peer::natt::punch_burst(at(9, 32000)).count(),
        "exactly one burst fires — bob's; alice's died with the hello"
    );
    assert!(
        !harness.front.dials.in_flight(alice),
        "the hello ended alice's attempt"
    );
    assert!(
        harness.front.dials.in_flight(bob),
        "bob's release dialed the endpoint his burst opened"
    );
}

/// A punched path may close on the observed, remapped port
/// before anything routes a Tunnel through the accepted-path attribution at
/// all — `Risen::Closed`'s endpoint alone would miss the hold it should take
/// with it. Attributing the closed address the same way an accepted path is
/// finds the one peer pending there.
#[tokio::test]
async fn a_closed_path_on_a_remapped_port_cancels_the_hold_aimed_at_the_hint() {
    let mut harness = Harness::new();
    let target = hash(0x44);
    let hinted = at(9, 31999);
    let remapped = at(9, 40000);
    let due = held_toward(&mut harness, target, hinted).await;

    harness
        .front
        .on_risen(
            Risen::Closed { at: remapped },
            due - Duration::from_millis(60),
        )
        .await;
    harness.front.release_held(due).await;

    assert!(
        harness.drained().is_empty(),
        "no burst at the closed address"
    );
    assert!(!harness.front.dials.in_flight(target), "and no second dial");
}
