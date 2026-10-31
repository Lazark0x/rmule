//! The **Held Burst**'s clock: a burst held for half the measured round trip
//! leaves on its own deadline — not on whichever 1 s tick comes next — and an
//! attempt that ends first takes its held burst with it.

use super::*;

/// What the triage reports for a hello read at `at` naming `peer`.
fn hello_of(at: Ipv4Endpoint, peer: UserHash) -> Risen {
    let stance = rmule_primitives::CryptStance::disabled();
    Risen::TunnelIdentified {
        at: PeerEndpoint::V4(at),
        peer: PeerUdpCryptTarget::new(peer, stance),
    }
}

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
/// which is the whole reason the observed source outranks the hint. The hello
/// names the peer whatever the port, and takes the held burst with it: no
/// burst, no second dial.
#[tokio::test]
async fn a_hello_on_a_remapped_port_ends_its_only_pending_peer() {
    let mut harness = Harness::new();
    let target = hash(0x44);
    let hinted = at(9, 31999);
    let remapped = at(9, 40000);
    let due = held_toward(&mut harness, target, hinted).await;

    let named = hello_of(remapped, target);
    harness.front.on_risen(named, due).await;

    harness.front.release_held(due).await;
    assert!(harness.drained().is_empty(), "no burst after adoption");
    assert!(!harness.front.dials.in_flight(target), "and no second dial");
}

/// Two peers pending behind one address: only the Tunnel's own hello,
/// reported back once something downstream reads it, resolves which one it
/// was; the other's hold is untouched and still fires on its own deadline.
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
/// — `Risen::Closed`'s endpoint alone would miss the hold it should take
/// with it. Attributing the closed address finds the one peer pending there.
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

/// The stream a forged `ST_SYN` from `from` raises: `librqbit-utp` hands it
/// over at the SYN, so no handshake completes first.
async fn accepted_from(harness: &mut Harness, from: Ipv4Endpoint, now: Instant) -> Risen {
    let mut syn = [0u8; 20];
    syn[0] = 0x41;
    let frame = rmule_peer::natt::NattFrame::Utp(&syn).encode();
    harness
        .front
        .on_datagram(PeerEndpoint::V4(from), frame, now)
        .await;
    let accept = harness.front.demux.utp().accept();
    let tunnel = tokio::time::timeout(Duration::from_secs(5), accept)
        .await
        .expect("the SYN from an expected address is accepted")
        .expect("the dispatcher is running");
    Risen::Accepted { tunnel }
}

/// A forged SYN or a CGNAT neighbour from a lone target's address proves
/// nothing: the traversal goes on until a hello names the target, and a hello
/// naming somebody else does not end it (ADR-0091, security rule 12).
#[tokio::test]
async fn a_syn_from_a_lone_targets_address_leaves_its_traversal_running() {
    let mut harness = Harness::new();
    let target = hash(0x44);
    let neighbour = at(9, 40000);
    let due = held_toward(&mut harness, target, at(9, 31999)).await;
    let early = due - Duration::from_millis(60);

    let accepted = accepted_from(&mut harness, neighbour, early).await;
    harness.front.on_risen(accepted, early).await;
    let named = hello_of(neighbour, hash(0x77));
    harness.front.on_risen(named, early).await;

    harness.front.release_held(due).await;
    assert!(!harness.drained().is_empty(), "the held burst still leaves");
    assert!(
        harness.front.dials.in_flight(target),
        "and so does the dial"
    );

    let named = hello_of(neighbour, target);
    harness.front.on_risen(named, due).await;
    assert!(
        !harness.front.dials.in_flight(target),
        "the hello that names the target ends it"
    );
}

/// A Tunnel that closes before any hello leaves the expectation it found, or
/// a forged opener would turn the real peer's away.
#[tokio::test]
async fn an_unidentified_tunnels_close_keeps_the_expectation() {
    let mut harness = Harness::new();
    let forged = at(9, 40000);
    let due = held_toward(&mut harness, hash(0x44), at(9, 31999)).await;
    let early = due - Duration::from_millis(60);

    let accepted = accepted_from(&mut harness, forged, early).await;
    harness.front.on_risen(accepted, early).await;
    harness
        .front
        .on_risen(Risen::Closed { at: forged }, early)
        .await;

    assert!(harness.front.expectations.expects(forged.ip, early));
}

/// A dial in flight toward `target`, and the Tunnel it "raised" from `from`,
/// just risen: whatever answered at that address has said nothing yet.
async fn dialed_tunnel(harness: &mut Harness, target: UserHash, from: Ipv4Endpoint) -> Instant {
    let due = held_toward(harness, target, at(9, 31999)).await;
    harness.front.release_held(due).await;
    assert!(harness.front.dials.in_flight(target));
    let Risen::Accepted { tunnel } = accepted_from(harness, from, due).await else {
        unreachable!("the fixture raises an accepted stream");
    };
    let risen = Risen::Dialed {
        tunnel,
        peer: target,
    };
    harness.front.on_risen(risen, due).await;
    due
}

/// A rise proves only that something answered: the attempt stands and its
/// dial stays in flight. A hello naming somebody else at the endpoint the
/// schedule aims at then ends the attempt there and then, with no re-dial and
/// no burst at a host that said no (ADR-0091, security rule 12).
#[tokio::test]
async fn a_hello_naming_somebody_else_at_the_aimed_endpoint_ends_the_attempt() {
    let mut harness = Harness::new();
    let target = hash(0x44);
    let aimed = at(9, 31999);
    let due = dialed_tunnel(&mut harness, target, aimed).await;
    assert!(harness.front.attempts.contains(&target), "no hello yet");
    assert!(harness.front.dials.in_flight(target), "no second opener");
    harness.drained();

    let named = hello_of(aimed, hash(0x77));
    harness.front.on_risen(named, due).await;

    assert!(!harness.front.dials.holds(target), "the schedule is over");
    harness.front.on_tick(due + REDIAL_INTERVAL).await;
    assert!(
        harness
            .drained()
            .iter()
            .all(|send| send.to != PeerEndpoint::V4(aimed)),
        "nothing more is aimed at that host"
    );
}

/// A hello refutes an endpoint. One the schedule has left, because a punch
/// corrected it, costs that dial alone: the next goes where the punch came
/// from.
#[tokio::test]
async fn a_corrected_schedule_outlives_a_hello_at_the_old_endpoint() {
    let mut harness = Harness::new();
    let target = hash(0x44);
    let stranger = at(9, 40000);
    let due = dialed_tunnel(&mut harness, target, stranger).await;

    let named = hello_of(stranger, hash(0x77));
    harness.front.on_risen(named, due).await;

    assert!(harness.front.attempts.contains(&target));
    assert!(harness.front.dials.holds(target), "the schedule stands");
    assert!(
        !harness.front.dials.in_flight(target),
        "and the cadence may dial again"
    );
}

/// A dialed Tunnel that closes before any hello spends only that dial.
#[tokio::test]
async fn a_dialed_tunnel_closing_unnamed_gives_its_dial_back() {
    let mut harness = Harness::new();
    let target = hash(0x44);
    let silent = at(9, 40000);
    let due = dialed_tunnel(&mut harness, target, silent).await;

    let closed = Risen::Closed { at: silent };
    harness.front.on_risen(closed, due).await;

    assert!(harness.front.attempts.contains(&target));
    assert!(harness.front.dials.holds(target));
    assert!(!harness.front.dials.in_flight(target));
}

/// The hello that names the dialed peer is what ends the attempt.
#[tokio::test]
async fn a_dialed_tunnels_own_hello_ends_its_attempt() {
    let mut harness = Harness::new();
    let target = hash(0x44);
    let answered = at(9, 40000);
    let due = dialed_tunnel(&mut harness, target, answered).await;

    let named = hello_of(answered, target);
    harness.front.on_risen(named, due).await;

    assert!(!harness.front.attempts.contains(&target));
    assert!(!harness.front.dials.holds(target));
}

/// A stance that requires the layer, as byte 29 or a hello states it.
fn requires_crypt() -> rmule_primitives::CryptStance {
    rmule_primitives::SourceCryptOptions::from_byte(0b111).crypt_stance()
}

/// The front's own punches are the server burst's equal: a peer that requires
/// the layer drops a plain datagram, so the cadence re-dial's burst carries
/// the stance the introduction stated (ADR-0091, security rule 13).
#[tokio::test]
async fn a_re_dials_burst_carries_the_stance_its_introduction_stated() {
    let mut harness = Harness::new();
    let target = hash(0x44);
    let t0 = Instant::now();
    harness
        .front
        .on_command(
            NattCommand::Introduced {
                peer_hash: target,
                target: at(9, 31999),
                role: HolepunchRole::Initiator,
                burst: false,
                source: rmule_peer::natt::PunchTargetSource::Observed,
                crypt: Some(requires_crypt()),
            },
            t0,
        )
        .await;
    let settled = t0 + DIAL_ATTEMPT_TIMEOUT;
    harness
        .front
        .on_risen(Risen::DialSettled { peer: target }, settled)
        .await;

    harness.front.on_tick(t0 + REDIAL_INTERVAL).await;

    let burst = harness.drained();
    assert!(!burst.is_empty(), "the cadence re-dial bursts");
    let stated = PeerUdpCryptTarget::new(target, requires_crypt());
    assert!(burst.iter().all(|send| send.crypt_target == Some(stated)));
}

/// A held burst's attempt holds the stance the reach's source record stated.
#[tokio::test]
async fn a_held_burst_carries_the_stance_its_reach_stated() {
    let mut harness = Harness::new();
    let target = hash(0x44);
    let stated = PeerUdpCryptTarget::new(target, requires_crypt());
    let due = held_toward(&mut harness, target, at(9, 31999)).await;
    harness.front.crypt_targets.state(target, requires_crypt());

    harness.front.release_held(due).await;

    let burst = harness.drained();
    assert!(!burst.is_empty());
    assert!(burst.iter().all(|send| send.crypt_target == Some(stated)));
}

/// A path outlives the attempt that opened it, so its keepalive reads the
/// target the hello bound to the path, and a closed path's goes with it.
#[tokio::test]
async fn a_keepalive_carries_the_crypt_target_its_hello_named() {
    let mut harness = Harness::new();
    let target = hash(0x44);
    let path = at(9, 40000);
    let due = held_toward(&mut harness, target, path).await;
    let accepted = accepted_from(&mut harness, path, due).await;
    harness.front.on_risen(accepted, due).await;
    let hello = PeerUdpCryptTarget::new(target, requires_crypt());
    let named = Risen::TunnelIdentified {
        at: PeerEndpoint::V4(path),
        peer: hello,
    };
    harness.front.on_risen(named, due).await;

    harness
        .front
        .on_tick(due + rmule_peer::natt::PUNCHED_PATH_KEEPALIVE)
        .await;

    let keepalive = harness.drained();
    assert_eq!(keepalive.len(), 1, "one keepalive: {keepalive:?}");
    assert_eq!(keepalive[0].crypt_target, Some(hello));

    let closed = Risen::Closed { at: path };
    harness.front.on_risen(closed, due).await;
    assert_eq!(harness.front.crypt_targets.of_path(path), None);
}

/// A dial's target names its endpoint from the opener on: a forged KEY racing
/// the answer contradicts it, whereas the real one is adopted (ADR-0091,
/// security rule 11).
#[tokio::test]
async fn a_forged_first_key_at_a_dialed_endpoint_is_refused() {
    let mut harness = Harness::new();
    let target = hash(0x44);
    let aimed = at(9, 31999);
    let due = held_toward(&mut harness, target, aimed).await;

    harness.front.release_held(due).await;

    let mut registry = harness.front.registry.lock().expect("registry");
    let endpoint = PeerEndpoint::V4(aimed);
    assert!(!registry.learn_key(endpoint, hash(0x99), due));
    assert!(registry.learn_key(endpoint, target, due));
}
