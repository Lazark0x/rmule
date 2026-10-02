//! Peer-reach route-tree unit tests: the route selector's actor-side half —
//! `enact_route`, `enact_rendezvous`, `enact_buddy_callback`,
//! `enact_direct_udp_for_download` — driven with stubbed front/pump channels
//! so a fallback punch, an ID-only buddy's retirement and a mid-session
//! `OP_IDCHANGE` are each pinned without a live actor.

use std::net::Ipv4Addr;

use rmule_kad::KadId;
use rmule_primitives::{ClientId, Ipv4Endpoint, PeerEndpoint};

use crate::callback::{CallbackSilence, NattCoordinator, SelfReach, callback_target};
use crate::natt::front::{NattCommand, SharedNattFront};
use crate::service::PeerBuddy;

use super::*;

/// The buddy a source channel named, at a public address — the punch
/// guards refuse anything else and none of them is weakened here.
fn buddy_udp() -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000)
}

fn buddy_id() -> KadId {
    KadId::from_bytes([0x7A; KadId::BYTE_LEN])
}

fn hash(byte: u8) -> UserHash {
    UserHash::from_bytes([byte; UserHash::BYTE_LEN])
}

/// A Low-ID candidate exactly as a download's record projects one: no
/// address of its own, a buddy, the NAT-T bit and the user hash the
/// rendezvous ledger is keyed by.
fn punchable_reach() -> PeerReach {
    PeerReach {
        id: ClientId::from_u32(42),
        tcp: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 4662)),
        supports_direct_udp_callback: false,
        kad_udp: None,
        on_our_server: false,
        buddy: Some(PeerBuddy {
            buddy_id: buddy_id(),
            buddy_udp: Some(buddy_udp()),
        }),
        ipv6: None,
        supports_natt: true,
        user_hash: Some(hash(0xAB)),
    }
}

/// Where a test's Callback Walk verdicts land: the retire channel a
/// download's reach carries, keyed by a candidate key of its own.
fn walk_reply() -> (
    crate::adapters::CallbackWalkReply,
    mpsc::Receiver<(
        crate::adapters::CallbackKey,
        crate::diagnostics::NattRetirement,
    )>,
) {
    let (retire_tx, retire_rx) = mpsc::channel(1);
    let key = crate::adapters::CallbackKey {
        server: None,
        low_id: rmule_primitives::ClientId::from_u32(77),
    };
    (
        crate::adapters::CallbackWalkReply { key, retire_tx },
        retire_rx,
    )
}

/// ADR-0061 route 4 for a download: the `0x52` ask reaches
/// the running Kad node naming the record's buddy, the download's file and
/// the port we are to be dialed on — and each missing fact of ours reports
/// "not emitted" rather than a callback nobody sent. A known endpoint never
/// starts a walk.
#[test]
fn a_buddy_callback_reaches_the_kad_node_or_says_it_did_not() {
    let file_hash = rmule_primitives::FileHash::from_bytes([0xCD; 16]);
    let pump = crate::adapters::SharedKadPump::default();
    let emit = |pump: &crate::adapters::SharedKadPump, peer: &PeerReach, port| {
        emit_buddy_callback(pump, true, peer, file_hash, port, walk_reply().0)
    };

    assert_eq!(
        emit(&pump, &punchable_reach(), Some(4662)),
        PeerReachRoute::Buddy {
            buddy_id: buddy_id(),
            emitted_to: None,
        },
        "Kad running, but the pump task itself is gone: no 0x52"
    );

    let (tx, mut rx) = mpsc::channel(1);
    *pump.lock().unwrap() = Some(tx);
    assert_eq!(
        emit(&pump, &punchable_reach(), None),
        PeerReachRoute::Buddy {
            buddy_id: buddy_id(),
            emitted_to: None,
        },
        "no listener, nothing to invite a dial to"
    );
    assert!(rx.try_recv().is_err(), "none of those reached the node");

    assert_eq!(
        emit(&pump, &punchable_reach(), Some(4662)),
        PeerReachRoute::Buddy {
            buddy_id: buddy_id(),
            emitted_to: Some(buddy_udp()),
        }
    );
    let Ok(crate::adapters::KadPumpCommand::BuddyCallback(ask)) = rx.try_recv() else {
        panic!("the ask reached the node's pump, and no walk did");
    };
    assert_eq!(
        ask,
        crate::adapters::BuddyCallbackAsk {
            buddy_udp: buddy_udp(),
            buddy_id: buddy_id(),
            file_hash,
            tcp_port: 4662,
        }
    );
}

/// A record that names its buddy by ID alone hands the node a
/// **Callback Walk** toward that ID, carrying the same `0x52` fields and
/// the download's retire channel for the walk's verdict — and says so on
/// the route rather than claiming a `0x52` it cannot address yet.
#[test]
fn a_buddy_named_by_id_alone_is_walked_toward() {
    let file_hash = rmule_primitives::FileHash::from_bytes([0xCD; 16]);
    let pump = crate::adapters::SharedKadPump::default();
    let (tx, mut rx) = mpsc::channel(1);
    *pump.lock().unwrap() = Some(tx);
    let id_only = PeerReach {
        buddy: Some(PeerBuddy {
            buddy_id: buddy_id(),
            buddy_udp: None,
        }),
        ..punchable_reach()
    };
    let (reply, _retire_rx) = walk_reply();
    let key = reply.key;

    assert_eq!(
        emit_buddy_callback(&pump, true, &id_only, file_hash, Some(4662), reply),
        PeerReachRoute::CallbackWalk {
            buddy_id: buddy_id()
        }
    );
    let Ok(crate::adapters::KadPumpCommand::CallbackWalk(ask)) = rx.try_recv() else {
        panic!("the walk reached the node's pump");
    };
    assert_eq!(
        (ask.buddy_id, ask.file_hash, ask.tcp_port, ask.reply.key),
        (buddy_id(), file_hash, 4662, key)
    );
}

/// With no Kad node running, the buddy-callback road's
/// known-endpoint `0x52` cannot leave, and the candidate's owner hears why at
/// once rather than holding its slot for thirty seconds — aMule's own
/// `Kademlia::CKademlia::IsConnected()` check ahead of both the
/// known-endpoint emit and the `FINDSOURCE` walk (`BaseClient.cpp:2123-2130`,
/// "Kad Firewalled source but not connected to Kad"). The pump task is left
/// running here on purpose: it is `kad_running` that gates this, not the
/// pump's own mailbox — a live pump behind a `false` still sends nothing.
#[test]
fn a_buddy_callback_with_a_known_endpoint_retires_at_once_with_no_kad_node() {
    let file_hash = rmule_primitives::FileHash::from_bytes([0xCD; 16]);
    let pump = crate::adapters::SharedKadPump::default();
    let (tx, mut rx) = mpsc::channel(1);
    *pump.lock().unwrap() = Some(tx);
    let (reply, mut retire_rx) = walk_reply();
    let key = reply.key;

    let routed = emit_buddy_callback(
        &pump,
        false,
        &punchable_reach(),
        file_hash,
        Some(4662),
        reply,
    );

    assert_eq!(
        routed,
        PeerReachRoute::Buddy {
            buddy_id: buddy_id(),
            emitted_to: None,
        },
        "no Kad node, no 0x52"
    );
    assert_eq!(
        retire_rx.try_recv(),
        Ok((key, crate::diagnostics::NattRetirement::KadNotRunning)),
        "the slot's owner hears at once, not after 30 s"
    );
    assert!(
        rx.try_recv().is_err(),
        "the pump task never sees the ask, though it is running"
    );
}

/// The walk sub-case of the same guard: a buddy named by ID
/// alone has no node to walk with either, and retires the same way — the
/// aMule check gates both branches at once, exactly as it does here.
#[test]
fn a_callback_walk_retires_at_once_with_no_kad_node() {
    let file_hash = rmule_primitives::FileHash::from_bytes([0xCD; 16]);
    let pump = crate::adapters::SharedKadPump::default();
    let (tx, mut rx) = mpsc::channel(1);
    *pump.lock().unwrap() = Some(tx);
    let id_only = PeerReach {
        buddy: Some(PeerBuddy {
            buddy_id: buddy_id(),
            buddy_udp: None,
        }),
        ..punchable_reach()
    };
    let (reply, mut retire_rx) = walk_reply();
    let key = reply.key;

    let routed = emit_buddy_callback(&pump, false, &id_only, file_hash, Some(4662), reply);

    assert_eq!(
        routed,
        PeerReachRoute::Buddy {
            buddy_id: buddy_id(),
            emitted_to: None,
        },
        "no Kad node, no walk"
    );
    assert_eq!(
        retire_rx.try_recv(),
        Ok((key, crate::diagnostics::NattRetirement::KadNotRunning)),
        "the slot's owner hears at once, not after 30 s"
    );
    assert!(
        rx.try_recv().is_err(),
        "the pump task never sees the ask, though it is running"
    );
}

/// The far end of the seam: a fallback route chosen from a download
/// candidate's facts is emitted by the same `enact_rendezvous` a
/// `ReachPeer` uses, and the command it puts on the **NAT-T Front** names
/// the record's buddy and the record's target hash — nothing guessed.
#[test]
fn a_fallback_rendezvous_reaches_the_front_naming_the_records_buddy_and_target() {
    let peer = punchable_reach();
    let target = callback_target(&peer);
    let ours = SelfReach {
        reachable: false,
        udp_on: true,
        kad_running: true,
        dial: crate::dialable::DialPosition::default(),
        server_punch: false,
    };
    let route = select_natt_for_download(
        &target,
        &ours,
        &CallbackSilence::After {
            taken: CallbackRoute::Server { low_id: peer.id },
            elapsed: rmule_peer::natt::CALLBACK_SILENCE_FALLBACK,
        },
    )
    .expect("a buddy coordinator introduces the pair");
    let CallbackRoute::NatTraversal {
        coordinator:
            NattCoordinator::Buddy {
                buddy_id: chosen_id,
                buddy_udp: chosen_udp,
            },
    } = route
    else {
        panic!("the record's buddy is the coordinator: {route:?}");
    };

    let front = SharedNattFront::default();
    let (tx, mut rx) = mpsc::channel(1);
    front.install(tx);
    let routed = enact_rendezvous(
        &front,
        chosen_id,
        chosen_udp,
        &TraversalRequest {
            peer: &peer,
            ours: &ours,
            our_user_hash: Some(hash(0x11)),
            claimed_endpoint: None,
            peer_crypt: None,
        },
        None,
    );
    assert_eq!(
        routed,
        PeerReachRoute::NatTraversal {
            buddy_id: buddy_id(),
            buddy_udp: buddy_udp(),
        }
    );
    let command = rx.try_recv().expect("the front is asked to begin");
    let NattCommand::Begin {
        target: begun,
        coordinator,
        facts,
        offer,
        ..
    } = command
    else {
        panic!("a rendezvous begins: {command:?}");
    };
    assert_eq!(
        begun,
        hash(0xAB),
        "the ledger is keyed by the record's hash"
    );
    assert_eq!(
        coordinator,
        crate::natt::front::AttemptCoordinator::Buddy {
            buddy_id: *buddy_id().as_bytes(),
            buddy_udp: buddy_udp(),
        }
    );
    assert_eq!(offer.our_user_hash, hash(0x11));
    assert_eq!(
        facts.buddy.map(|buddy| buddy.buddy_id),
        Some(buddy_id()),
        "the attempt carries the facts that pick the next coordinator"
    );
}

/// The LowID↔LowID road: a candidate no callback was ever
/// possible for reaches the *same* selector with no silence to measure, and
/// the server that holds both ends is chosen without a taken callback to
/// fall back from. What `select_natt_fallback` alone would answer here is
/// `None` — it refuses a route that was never a callback — which is why the
/// two roads share one entry rather than one function.
#[test]
fn a_candidate_with_no_possible_callback_is_punched_through_the_server_at_once() {
    let peer = PeerReach {
        on_our_server: true,
        buddy: None,
        supports_natt: false,
        ..punchable_reach()
    };
    let ours = SelfReach {
        reachable: false,
        udp_on: true,
        kad_running: false,
        dial: crate::dialable::DialPosition::default(),
        server_punch: true,
    };

    assert_eq!(
        select_natt_for_download(
            &callback_target(&peer),
            &ours,
            &CallbackSilence::NoCallbackPossible,
        ),
        Some(CallbackRoute::NatTraversal {
            coordinator: NattCoordinator::Server { low_id: peer.id },
        }),
        "the server that assigned both Low IDs is the coordinator, asked now"
    );
    assert_eq!(
        select_natt_for_download(
            &callback_target(&peer),
            &SelfReach {
                server_punch: false,
                ..ours
            },
            &CallbackSilence::NoCallbackPossible,
        ),
        None,
        "a server whose punch keepalive is not running introduces nobody"
    );
}

/// The candidate record's honest gap, stated where it is enacted: without
/// the target's user hash the ledger has no key and a hint could never be
/// matched, so nothing is emitted and the reason says which fact was
/// missing (ADR-0091's Honest Capability Advertisement, applied to us).
#[test]
fn a_candidate_with_no_user_hash_begins_no_rendezvous() {
    let front = SharedNattFront::default();
    let (tx, mut rx) = mpsc::channel(1);
    front.install(tx);
    let anonymous = PeerReach {
        user_hash: None,
        ..punchable_reach()
    };
    let routed = enact_rendezvous(
        &front,
        buddy_id(),
        Some(buddy_udp()),
        &TraversalRequest {
            peer: &anonymous,
            ours: &SelfReach {
                reachable: false,
                udp_on: true,
                kad_running: true,
                dial: crate::dialable::DialPosition::default(),
                server_punch: false,
            },
            our_user_hash: Some(hash(0x11)),
            claimed_endpoint: None,
            peer_crypt: None,
        },
        None,
    );
    assert_eq!(
        routed,
        PeerReachRoute::NatTraversalUnavailable {
            buddy_id: buddy_id(),
            reason: NatTraversalUnavailableReason::TargetIdentityUnknown,
        }
    );
    assert!(rx.try_recv().is_err(), "nothing was asked of the front");
}

/// A punch toward a buddy named by ID alone has no road at all:
/// eMuleAI's dialect carries `OP_REASKCALLBACKUDP` (`0x94`) only to
/// a known endpoint, never through a Kad walk, so the candidate's owner
/// hears the retirement the moment the endpoint is found missing, rather
/// than holding its slot for a walk that would never carry it.
#[test]
fn a_rendezvous_toward_an_id_only_buddy_retires_at_once_with_the_reason() {
    let front = SharedNattFront::default();
    let (tx, mut rx) = mpsc::channel(1);
    front.install(tx);
    let peer = punchable_reach();
    let ours = SelfReach {
        reachable: false,
        udp_on: true,
        kad_running: true,
        dial: crate::dialable::DialPosition::default(),
        server_punch: false,
    };
    let (retire_tx, mut retire_rx) = mpsc::channel(1);
    let key = crate::adapters::CallbackKey {
        server: None,
        low_id: rmule_primitives::ClientId::from_u32(77),
    };
    let routed = enact_rendezvous(
        &front,
        buddy_id(),
        None,
        &TraversalRequest {
            peer: &peer,
            ours: &ours,
            our_user_hash: Some(hash(0x11)),
            claimed_endpoint: None,
            peer_crypt: None,
        },
        Some(&RetireOnFailure { key, tx: retire_tx }),
    );
    assert_eq!(
        routed,
        PeerReachRoute::NatTraversalUnavailable {
            buddy_id: buddy_id(),
            reason: NatTraversalUnavailableReason::BuddyEndpointUnknown,
        }
    );
    assert!(rx.try_recv().is_err(), "nothing was asked of the front");
    assert_eq!(
        retire_rx.try_recv(),
        Ok((
            key,
            crate::diagnostics::NattRetirement::CoordinatorEndpointUnknown
        )),
        "the slot's owner hears at once, not after 30 s"
    );
}

/// A download's retire channel and the candidate key it is tagged with.
fn retire_channel() -> (
    RetireOnFailure,
    mpsc::Receiver<(
        crate::adapters::CallbackKey,
        crate::diagnostics::NattRetirement,
    )>,
) {
    let (tx, rx) = mpsc::channel(4);
    let key = crate::adapters::CallbackKey {
        server: None,
        low_id: ClientId::from_u32(42),
    };
    (RetireOnFailure { key, tx }, rx)
}

fn low_id_punch_position() -> SelfReach {
    SelfReach {
        reachable: false,
        udp_on: true,
        kad_running: false,
        dial: crate::dialable::DialPosition::default(),
        server_punch: true,
    }
}

/// A plain `0x42` Low-ID source names no User Hash,
/// yet the server coordinator punches it by id alone. The `0x60` leaves, but
/// no **Traversal Attempt** can be keyed, so nothing would ever retire it —
/// and a callback beside it would hold its slot to the traversal bound
/// (~137 s) instead of its own 30 s. The candidate hears `NotEnactable` at
/// once, and the brain's 30 s deadline then releases the slot
/// (`download::state::tests::callbacks`, the retired-traversal legs).
#[test]
fn a_hashless_server_punch_retires_its_candidate_at_once() {
    let front = SharedNattFront::default();
    let (front_tx, mut front_rx) = mpsc::channel(1);
    front.install(front_tx);
    let hashless = PeerReach {
        on_our_server: true,
        buddy: None,
        user_hash: None,
        ..punchable_reach()
    };
    let ours = low_id_punch_position();
    let (retire, mut retire_rx) = retire_channel();
    let request = TraversalRequest {
        peer: &hashless,
        ours: &ours,
        our_user_hash: Some(hash(0x11)),
        claimed_endpoint: None,
        peer_crypt: None,
    };

    let routed = own_server_punch(&front, &request, hashless.id, true, Some(&retire));

    assert_eq!(
        routed,
        PeerReachRoute::ServerPunch {
            low_id: hashless.id
        }
    );
    assert!(front_rx.try_recv().is_err(), "no attempt could be keyed");
    assert_eq!(
        retire_rx.try_recv(),
        Ok((retire.key, crate::diagnostics::NattRetirement::NotEnactable)),
        "the unowned punch is answered, not swallowed"
    );
}

/// The two siblings of the leg above: a front that refuses the `Begin` owns
/// the punch no more than a missing hash does, and a server punch that could
/// not even be asked (no live session, or no bound client-UDP port) is a
/// punch with no coordinator. A punch the front took retires nothing here.
#[test]
fn a_server_punch_the_front_never_took_retires_and_one_it_took_does_not() {
    let peer = PeerReach {
        on_our_server: true,
        buddy: None,
        ..punchable_reach()
    };
    let ours = low_id_punch_position();
    let request = TraversalRequest {
        peer: &peer,
        ours: &ours,
        our_user_hash: Some(hash(0x11)),
        claimed_endpoint: None,
        peer_crypt: None,
    };

    let refusing = SharedNattFront::default();
    let (retire, mut retire_rx) = retire_channel();
    own_server_punch(&refusing, &request, peer.id, true, Some(&retire));
    assert_eq!(
        retire_rx.try_recv(),
        Ok((retire.key, crate::diagnostics::NattRetirement::NotEnactable)),
        "a front with no mailbox refused the Begin"
    );

    let (retire, mut retire_rx) = retire_channel();
    let routed = own_server_punch(&refusing, &request, peer.id, false, Some(&retire));
    assert_eq!(
        routed,
        PeerReachRoute::ServerPunchUnavailable { low_id: peer.id }
    );
    assert_eq!(
        retire_rx.try_recv(),
        Ok((
            retire.key,
            crate::diagnostics::NattRetirement::NoCoordinator
        )),
        "no `0x60` left, so no coordinator was asked"
    );

    let front = SharedNattFront::default();
    let (front_tx, mut front_rx) = mpsc::channel(1);
    front.install(front_tx);
    let (retire, mut retire_rx) = retire_channel();
    own_server_punch(&front, &request, peer.id, true, Some(&retire));
    assert!(
        matches!(front_rx.try_recv(), Ok(NattCommand::Begin { .. })),
        "the front owns this attempt"
    );
    assert!(
        retire_rx.try_recv().is_err(),
        "an owned attempt retires through the front, not here"
    );
}

/// An anonymous candidate's rendezvous toward a known
/// buddy begins nothing, and its owner hears so rather than waiting out the
/// slot for a punch that never started.
#[test]
fn an_anonymous_rendezvous_retires_its_candidate_at_once() {
    let front = SharedNattFront::default();
    let (front_tx, _front_rx) = mpsc::channel(1);
    front.install(front_tx);
    let anonymous = PeerReach {
        user_hash: None,
        ..punchable_reach()
    };
    let (retire, mut retire_rx) = retire_channel();
    let routed = enact_rendezvous(
        &front,
        buddy_id(),
        Some(buddy_udp()),
        &TraversalRequest {
            peer: &anonymous,
            ours: &low_id_punch_position(),
            our_user_hash: Some(hash(0x11)),
            claimed_endpoint: None,
            peer_crypt: None,
        },
        Some(&retire),
    );
    assert_eq!(
        routed,
        PeerReachRoute::NatTraversalUnavailable {
            buddy_id: buddy_id(),
            reason: NatTraversalUnavailableReason::TargetIdentityUnknown,
        }
    );
    assert_eq!(
        retire_rx.try_recv(),
        Ok((retire.key, crate::diagnostics::NattRetirement::NotEnactable))
    );
}

/// A buddy callback with no buddy, or with no
/// listener port to name, sends no `0x52` — and says so to the candidate's
/// owner, which hands the slot to the next road now.
#[test]
fn a_buddy_callback_that_cannot_leave_retires_its_road() {
    let file_hash = rmule_primitives::FileHash::from_bytes([0xCD; 16]);
    let pump = crate::adapters::SharedKadPump::default();
    let (pump_tx, _pump_rx) = mpsc::channel(1);
    *pump.lock().unwrap() = Some(pump_tx);

    for (peer, port, what) in [
        (
            PeerReach {
                buddy: None,
                ..punchable_reach()
            },
            Some(4662),
            "no buddy",
        ),
        (punchable_reach(), None, "no listener port"),
    ] {
        let (reply, mut retire_rx) = walk_reply();
        let key = reply.key;
        emit_buddy_callback(&pump, true, &peer, file_hash, port, reply);
        assert_eq!(
            retire_rx.try_recv(),
            Ok((key, crate::diagnostics::NattRetirement::CallbackNotSent)),
            "{what}: the road ends at once"
        );
    }
}

/// The direct-UDP road with nothing to send from —
/// no bound client-UDP half, or no Kad UDP endpoint for the candidate — ends
/// its road at once; one that left retires nothing.
#[tokio::test]
async fn a_direct_udp_callback_that_cannot_leave_retires_its_road() {
    let with_endpoint = PeerReach {
        kad_udp: Some(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4672)),
        supports_direct_udp_callback: true,
        ..punchable_reach()
    };
    let without_endpoint = PeerReach {
        kad_udp: None,
        ..with_endpoint
    };
    let (udp_tx, _udp_rx) = mpsc::channel(4);

    for (udp, peer, what) in [
        (None, &with_endpoint, "no client-UDP send half"),
        (Some(&udp_tx), &without_endpoint, "no Kad UDP endpoint"),
    ] {
        let (retire, mut retire_rx) = retire_channel();
        let routed =
            direct_udp_for_download(udp, peer, Some(4662), Some(hash(0x11)), None, &retire).await;
        assert!(
            !matches!(routed, PeerReachRoute::DirectUdp { .. }),
            "{what}"
        );
        assert_eq!(
            retire_rx.try_recv(),
            Ok((
                retire.key,
                crate::diagnostics::NattRetirement::CallbackNotSent
            )),
            "{what}: the road ends at once"
        );
    }

    let (retire, mut retire_rx) = retire_channel();
    let routed = direct_udp_for_download(
        Some(&udp_tx),
        &with_endpoint,
        Some(4662),
        Some(hash(0x11)),
        None,
        &retire,
    )
    .await;
    assert!(matches!(routed, PeerReachRoute::DirectUdp { .. }));
    assert!(
        retire_rx.try_recv().is_err(),
        "a sent `0x95` retires nothing"
    );
}
