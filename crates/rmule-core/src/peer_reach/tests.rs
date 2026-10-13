//! **Peer Reach** through its one call, [`PeerReacher::reach`], over real
//! channels: what reached the client-UDP send half (the `0x95`), the NAT-T
//! Front's mailbox (rung 1, server and buddy), the Kad node's pump (the `0x52`
//! and the Callback Walk), the event bus (the road reported) and the
//! candidate's retire channel (a road that never opened). Our own position is
//! whatever the leg moved in the cells Self Reach reads.

use std::net::Ipv4Addr;

use rmule_kad::KadId;
use rmule_peer::DirectCallbackReq;
use rmule_peer::natt::CALLBACK_SILENCE_FALLBACK;
use rmule_primitives::{ClientId, Ipv4Endpoint, PeerEndpoint, UserHash};

use super::*;
use crate::adapters::{KadPresenceLease, KadPresenceView, KadPumpCommand};
use crate::callback::CallbackSilence;
use crate::natt::server_punch::SharedServerPunch;
use crate::own_identity::ConnectedSession;
use crate::reachability::ClientUdpBound;
use crate::service::PeerBuddy;

/// The port our serve listener bound.
const LISTEN_PORT: u16 = 4662;

fn hash(byte: u8) -> UserHash {
    UserHash::from_bytes([byte; UserHash::BYTE_LEN])
}

/// The buddy a source channel named, at a public address.
fn buddy_udp() -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000)
}

fn buddy_id() -> KadId {
    KadId::from_bytes([0x7A; KadId::BYTE_LEN])
}

fn file_hash() -> FileHash {
    FileHash::from_bytes([0xCD; FileHash::BYTE_LEN])
}

/// A Low-ID candidate exactly as a download's record projects one: no
/// address of its own, a buddy at a known endpoint, the NAT-T bit and the
/// user hash the rendezvous ledger is keyed by.
fn punchable() -> PeerReach {
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

/// The same candidate with its buddy named by ID alone.
fn id_only_buddy() -> PeerReach {
    PeerReach {
        buddy: Some(PeerBuddy {
            buddy_id: buddy_id(),
            buddy_udp: None,
        }),
        ..punchable()
    }
}

/// A Low-ID candidate that advertised the direct callback and its Kad UDP
/// endpoint.
fn direct_udp_peer() -> PeerReach {
    PeerReach {
        supports_direct_udp_callback: true,
        kad_udp: Some(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4672)),
        buddy: None,
        ..punchable()
    }
}

/// A download's pending callback down `road`, and the retire channel it is
/// told on.
fn pending(
    road: DownloadAsk,
) -> (
    PendingCallback,
    mpsc::Receiver<(CallbackKey, NattRetirement)>,
) {
    let (retire_tx, retire_rx) = mpsc::channel(4);
    (
        PendingCallback {
            road,
            key: CallbackKey {
                server: None,
                low_id: ClientId::from_u32(77),
                kad_port: None,
            },
            retire_tx,
        },
        retire_rx,
    )
}

/// A callback that has said nothing for twelve seconds.
fn silent(taken: PeerReachRoute) -> DownloadAsk {
    DownloadAsk::Traversal(CallbackSilence::After {
        taken,
        elapsed: CALLBACK_SILENCE_FALLBACK,
    })
}

/// Which of the surfaces Peer Reach reaches through a leg's node has.
#[derive(Clone, Copy)]
struct Has {
    client_udp: bool,
    front: bool,
}

/// A node around one Peer Reach: firewalled (no session), client-UDP bound,
/// Kad running, a listener on [`LISTEN_PORT`], our user hash known — and the
/// receiving half of every surface it reaches.
struct Rig {
    reacher: PeerReacher,
    /// The one obfuscation policy, off until a leg sets it.
    policy: crate::obfuscation_policy::SharedObfuscationPolicy,
    reach: SharedSelfReach,
    own: SharedOwnIdentity,
    punch: SharedServerPunch,
    diagnostics: DiagnosticsState,
    udp: mpsc::Receiver<ClientUdpSend>,
    natt: mpsc::Receiver<NattCommand>,
    kad: mpsc::Receiver<KadPumpCommand>,
    events: mpsc::Receiver<CoreEvent>,
    kad_lease: Option<KadPresenceLease>,
    session: Option<(
        crate::server_session::ServerSessionHandle,
        mpsc::Sender<rmule_ed2k::Ed2kEvent>,
        mpsc::Receiver<rmule_ed2k::Ed2kCommand>,
    )>,
}

impl Rig {
    fn new() -> Self {
        Self::with(Has {
            client_udp: true,
            front: true,
        })
    }

    fn with(has: Has) -> Self {
        let own = SharedOwnIdentity::default();
        own.set_user_hash(hash(0x11));
        let presence = KadPresenceView::default();
        let kad_lease = presence.lease(KadId::from_bytes([0x22; KadId::BYTE_LEN]));
        let bound = ClientUdpBound::default();
        if has.client_udp {
            bound.set();
        }
        let punch = SharedServerPunch::default();
        let reach = SharedSelfReach::new(
            crate::KadReachLevel::fixed(false),
            own.clone(),
            SharedNattFront::default(),
        )
        .with_kad_presence(presence)
        .with_client_udp(bound)
        .with_server_coordinator(punch.coordinator_session());
        reach
            .listener()
            .bind(&tokio::spawn(std::future::pending::<()>()), LISTEN_PORT);

        let (udp_tx, udp) = mpsc::channel(4);
        let natt_front = SharedNattFront::default();
        let (natt_tx, natt) = mpsc::channel(4);
        if has.front {
            natt_front.install(natt_tx);
        }
        let kad_pump = SharedKadPump::default();
        let (kad_tx, kad) = mpsc::channel(4);
        kad_pump.install_for_good(kad_tx);
        let (events_tx, events) = mpsc::channel(8);
        let diagnostics = DiagnosticsState::default();
        let policy = crate::obfuscation_policy::SharedObfuscationPolicy::default();
        let reacher = PeerReacher::new(PeerReachWiring {
            reach: reach.clone(),
            client_udp: has.client_udp.then_some(udp_tx),
            natt: natt_front,
            kad_pump,
            own: own.clone(),
            obfuscation: policy.clone(),
            diagnostics: diagnostics.clone(),
            events: events_tx,
        });
        Self {
            reacher,
            policy,
            reach,
            own,
            punch,
            diagnostics,
            udp,
            natt,
            kad,
            events,
            kad_lease: Some(kad_lease),
            session: None,
        }
    }

    /// Logged in with a High ID: we can be dialed back.
    fn high_id(&self) {
        self.own.set_connected_session(Some(ConnectedSession {
            server: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 1), 4661)),
            client_id: ClientId::from_u32(0x0A00_0001),
        }));
    }

    /// Our session advertised `0xF9` and its keepalive runs: the server can
    /// introduce us.
    fn server_punch_live(&mut self) {
        let session = crate::server_session::tests::fake_session(
            crate::server_session::tests::connected(),
            rmule_ed2k::ServerGrants::default(),
        );
        self.punch.go_live(&session.0);
        self.session = Some(session);
    }

    /// Every road reported so far.
    fn reported(&mut self) -> Vec<PeerReachRoute> {
        std::iter::from_fn(|| self.events.try_recv().ok())
            .filter_map(|event| match event {
                CoreEvent::PeerReachRouted { route, .. } => Some(route),
                _ => None,
            })
            .collect()
    }
}

/// Route 2 for an operator's `ReachPeer`: a High-ID us and a peer that
/// advertised the direct callback get a real `0x95` on the client-UDP half,
/// addressed to its Kad UDP endpoint and naming the port our listener bound
/// and our user hash — and the road is reported. With no listener, nothing
/// leaves: a callback naming a port nothing answers on is a dead invitation.
#[tokio::test]
async fn a_reach_peer_on_the_direct_udp_road_puts_its_0x95_on_the_client_udp_half() {
    let mut rig = Rig::new();
    rig.high_id();
    let peer = direct_udp_peer();
    let kad_udp = peer.kad_udp.expect("the peer named one");

    let routed = rig.reacher.reach(&peer, None).await;

    let sent = PeerReachRoute::DirectUdp {
        target_kad_udp: kad_udp,
    };
    assert_eq!(routed, sent);
    let datagram = rig.udp.try_recv().expect("the 0x95 left");
    assert_eq!(datagram.to, PeerEndpoint::V4(kad_udp));
    assert_eq!(
        DirectCallbackReq::decode_udp(&datagram.datagram),
        Ok(DirectCallbackReq {
            our_tcp_port: LISTEN_PORT,
            our_user_hash: hash(0x11),
            connect_options: 0,
        })
    );
    assert_eq!(rig.reported(), [sent]);

    rig.reach.listener().clear();
    assert_eq!(
        rig.reacher.reach(&peer, None).await,
        PeerReachRoute::DirectUdpUnavailable {
            target_kad_udp: kad_udp
        }
    );
    assert!(rig.udp.try_recv().is_err(), "no listener, no invitation");
}

/// The obfuscation policy changes live (ADR-0046): the `0x95`'s
/// connect-options byte states the policy as it stands at each reach, so the
/// callback sent after a change states the new crypt ladder.
#[tokio::test]
async fn the_0x95_after_a_policy_change_states_the_new_crypt_ladder() {
    let mut rig = Rig::new();
    rig.high_id();
    let peer = direct_udp_peer();
    let sent_options = async |rig: &mut Rig| {
        rig.reacher.reach(&peer, None).await;
        let datagram = rig.udp.try_recv().expect("the 0x95 left");
        DirectCallbackReq::decode_udp(&datagram.datagram)
            .expect("a 0x95")
            .connect_options
    };

    assert_eq!(sent_options(&mut rig).await, 0x00, "off: no crypt bits");
    rig.policy
        .set(Some(rmule_net::peer::ObfuscationPolicy::Requested));
    assert_eq!(
        sent_options(&mut rig).await,
        0x03,
        "requested: supports and requests"
    );
}

/// An operator's `ReachPeer` names no file, and a `0x52` must, so its buddy
/// road is reported and nothing is sent; its server callback is the server's
/// relay to make. Only the roads that put something on the wire send.
#[tokio::test]
async fn a_reach_peers_buddy_and_server_roads_are_reported_and_not_sent() {
    let mut rig = Rig::new();
    rig.high_id();

    assert_eq!(
        rig.reacher.reach(&punchable(), None).await,
        PeerReachRoute::Buddy {
            buddy_id: buddy_id(),
            emitted_to: None,
        }
    );
    let on_our_server = PeerReach {
        on_our_server: true,
        ..punchable()
    };
    assert_eq!(
        rig.reacher.reach(&on_our_server, None).await,
        PeerReachRoute::Server {
            low_id: on_our_server.id
        }
    );
    assert!(rig.kad.try_recv().is_err() && rig.natt.try_recv().is_err());
    assert_eq!(rig.reported().len(), 2);
}

/// A download's direct-UDP road with nothing to send from — no Kad UDP
/// endpoint on its record, or no bound client-UDP half — ends its road at
/// once; one that left retires nothing.
#[tokio::test]
async fn a_download_direct_udp_road_that_cannot_leave_retires_at_once() {
    let mut rig = Rig::new();
    let no_endpoint = PeerReach {
        kad_udp: None,
        ..direct_udp_peer()
    };
    let (ask, mut retire_rx) = pending(DownloadAsk::DirectUdp);
    assert_eq!(
        rig.reacher.reach(&no_endpoint, Some(ask.clone())).await,
        PeerReachRoute::Dropped {
            reason: PeerReachDropReason::NoKadUdpEndpoint
        }
    );
    assert_eq!(
        retire_rx.try_recv(),
        Ok((ask.key, NattRetirement::CallbackNotSent))
    );

    let (ask, mut retire_rx) = pending(DownloadAsk::DirectUdp);
    assert!(matches!(
        rig.reacher.reach(&direct_udp_peer(), Some(ask)).await,
        PeerReachRoute::DirectUdp { .. }
    ));
    assert!(rig.udp.try_recv().is_ok(), "the 0x95 left");
    assert!(retire_rx.try_recv().is_err(), "a sent 0x95 retires nothing");

    let unbound = Rig::with(Has {
        client_udp: false,
        front: true,
    });
    let (ask, mut retire_rx) = pending(DownloadAsk::DirectUdp);
    assert!(matches!(
        unbound
            .reacher
            .reach(&direct_udp_peer(), Some(ask.clone()))
            .await,
        PeerReachRoute::DirectUdpUnavailable { .. }
    ));
    assert_eq!(
        retire_rx.try_recv(),
        Ok((ask.key, NattRetirement::CallbackNotSent))
    );
}

/// ADR-0061 route 4 for a download: the `0x52` ask reaches the running Kad
/// node naming the record's buddy, the download's file and the port we are to
/// be dialed on — and a buddy named by ID alone is walked toward instead, the
/// walk carrying the candidate's retire channel for its verdict.
#[tokio::test]
async fn a_download_buddy_callback_reaches_the_kad_node_or_walks_toward_the_buddy() {
    let mut rig = Rig::new();
    let (ask, mut retire_rx) = pending(DownloadAsk::BuddyCallback {
        file_hash: file_hash(),
    });
    assert_eq!(
        rig.reacher.reach(&punchable(), Some(ask)).await,
        PeerReachRoute::Buddy {
            buddy_id: buddy_id(),
            emitted_to: Some(buddy_udp()),
        }
    );
    let Ok(KadPumpCommand::BuddyCallback(callback)) = rig.kad.try_recv() else {
        panic!("the 0x52 ask reached the node, and no walk did");
    };
    assert_eq!(
        callback,
        crate::adapters::BuddyCallbackAsk {
            buddy_udp: buddy_udp(),
            buddy_id: buddy_id(),
            file_hash: file_hash(),
            tcp_port: LISTEN_PORT,
        }
    );
    assert!(retire_rx.try_recv().is_err());

    let (ask, _retire_rx) = pending(DownloadAsk::BuddyCallback {
        file_hash: file_hash(),
    });
    let key = ask.key;
    assert_eq!(
        rig.reacher.reach(&id_only_buddy(), Some(ask)).await,
        PeerReachRoute::CallbackWalk {
            buddy_id: buddy_id()
        }
    );
    let Ok(KadPumpCommand::CallbackWalk(walk)) = rig.kad.try_recv() else {
        panic!("the walk reached the node");
    };
    assert_eq!(
        (walk.buddy_id, walk.file_hash, walk.tcp_port, walk.reply.key),
        (buddy_id(), file_hash(), LISTEN_PORT, key)
    );
}

/// A buddy callback that cannot leave says so to the candidate at once
/// rather than holding its slot for thirty seconds. With no Kad node running
/// neither the known-endpoint `0x52` nor the walk can leave — aMule's own
/// `Kademlia::CKademlia::IsConnected()` check ahead of both
/// (`BaseClient.cpp:2123-2130`) — and it is Kad running that gates it, not
/// the pump's mailbox, which is still open here. No buddy, or no listener
/// port to name, ends the road the same way.
#[tokio::test]
async fn a_buddy_callback_that_cannot_leave_retires_its_road_at_once() {
    let mut rig = Rig::new();
    let road = || {
        pending(DownloadAsk::BuddyCallback {
            file_hash: file_hash(),
        })
    };

    let (ask, mut retire_rx) = road();
    let no_buddy = PeerReach {
        buddy: None,
        ..punchable()
    };
    assert_eq!(
        rig.reacher.reach(&no_buddy, Some(ask.clone())).await,
        PeerReachRoute::Dropped {
            reason: PeerReachDropReason::NoBuddy
        }
    );
    assert_eq!(
        retire_rx.try_recv(),
        Ok((ask.key, NattRetirement::CallbackNotSent))
    );

    rig.reach.listener().clear();
    let (ask, mut retire_rx) = road();
    rig.reacher.reach(&punchable(), Some(ask.clone())).await;
    assert_eq!(
        retire_rx.try_recv(),
        Ok((ask.key, NattRetirement::CallbackNotSent)),
        "no listener port to name"
    );

    rig.kad_lease = None;
    for peer in [punchable(), id_only_buddy()] {
        let (ask, mut retire_rx) = road();
        assert_eq!(
            rig.reacher.reach(&peer, Some(ask.clone())).await,
            PeerReachRoute::Buddy {
                buddy_id: buddy_id(),
                emitted_to: None,
            }
        );
        assert_eq!(
            retire_rx.try_recv(),
            Ok((ask.key, NattRetirement::KadNotRunning))
        );
    }
    assert!(
        rig.kad.try_recv().is_err(),
        "the pump never sees an ask, though its mailbox is open"
    );
}

/// A running node whose pump refuses the ask — its task gone, or its inbox
/// full — sends no `0x52` and starts no walk, so the road ends at once as one
/// that never left, for the known endpoint and the ID-only buddy alike.
#[tokio::test]
async fn a_buddy_callback_the_pump_refuses_retires_its_road_at_once() {
    let mut rig = Rig::new();
    // The pump's task is gone: its inbox has no reader.
    drop(std::mem::replace(&mut rig.kad, mpsc::channel(1).1));
    for peer in [punchable(), id_only_buddy()] {
        let (ask, mut retire_rx) = pending(DownloadAsk::BuddyCallback {
            file_hash: file_hash(),
        });
        assert_eq!(
            rig.reacher.reach(&peer, Some(ask.clone())).await,
            PeerReachRoute::Buddy {
                buddy_id: buddy_id(),
                emitted_to: None,
            }
        );
        assert_eq!(
            retire_rx.try_recv(),
            Ok((ask.key, NattRetirement::CallbackNotSent))
        );
    }
}

/// The fallback seam: a callback twelve seconds silent, with no server that
/// speaks the punch, falls to the candidate's own buddy — and what reaches
/// the NAT-T Front is one traversal naming that buddy, owned by an attempt
/// keyed by the record's hash, carrying the facts that pick the next
/// coordinator and the offer that names us.
#[tokio::test]
async fn a_silent_callback_falls_to_the_records_buddy_and_the_front_gets_the_traversal() {
    let mut rig = Rig::new();
    let peer = punchable();
    let (ask, mut retire_rx) = pending(silent(PeerReachRoute::Server { low_id: peer.id }));

    let routed = rig.reacher.reach(&peer, Some(ask)).await;

    let taken = PeerReachRoute::NatTraversal {
        buddy_id: buddy_id(),
        buddy_udp: buddy_udp(),
    };
    assert_eq!(routed, taken);
    let Ok(NattCommand::Traverse {
        coordinator,
        owner: Some(owner),
    }) = rig.natt.try_recv()
    else {
        panic!("the front is handed the traversal with its owner");
    };
    assert_eq!(
        coordinator,
        AttemptCoordinator::Buddy {
            buddy_id: *buddy_id().as_bytes(),
            buddy_udp: buddy_udp(),
        }
    );
    assert_eq!(owner.target, hash(0xAB), "keyed by the record's hash");
    assert_eq!(owner.offer.our_user_hash, hash(0x11));
    assert_eq!(
        owner.facts.buddy.map(|buddy| buddy.buddy_id),
        Some(buddy_id())
    );
    assert!(retire_rx.try_recv().is_err());
    assert_eq!(rig.reported(), [taken]);
}

/// The LowID↔LowID road: a candidate no callback was ever possible for, on
/// our punch-capable server, is introduced by the server at once — the front
/// gets the traversal and puts the `0x60` on the session. A plain `0x42`
/// source names no user hash: its `0x60` is handed over all the same, owned
/// by no attempt, and the candidate hears `NotEnactable` at once. A front
/// that is not there sends nothing at all.
#[tokio::test]
async fn a_candidate_no_callback_could_reach_is_introduced_by_our_server_at_once() {
    let mut rig = Rig::new();
    rig.server_punch_live();
    let on_server = PeerReach {
        on_our_server: true,
        buddy: None,
        ..punchable()
    };
    let road = || pending(DownloadAsk::Traversal(CallbackSilence::NoCallbackPossible));

    let (ask, mut retire_rx) = road();
    assert_eq!(
        rig.reacher.reach(&on_server, Some(ask)).await,
        PeerReachRoute::ServerPunch {
            low_id: on_server.id
        }
    );
    assert!(matches!(
        rig.natt.try_recv(),
        Ok(NattCommand::Traverse {
            coordinator: AttemptCoordinator::Server { low_id },
            owner: Some(AttemptOwner { target, .. }),
        }) if low_id == on_server.id && target == hash(0xAB)
    ));
    assert!(retire_rx.try_recv().is_err(), "the front owns the attempt");

    let hashless = PeerReach {
        user_hash: None,
        ..on_server
    };
    let (ask, mut retire_rx) = road();
    assert_eq!(
        rig.reacher.reach(&hashless, Some(ask.clone())).await,
        PeerReachRoute::ServerPunch {
            low_id: hashless.id
        }
    );
    assert!(matches!(
        rig.natt.try_recv(),
        Ok(NattCommand::Traverse { owner: None, .. })
    ));
    assert_eq!(
        retire_rx.try_recv(),
        Ok((ask.key, NattRetirement::NotEnactable)),
        "the unowned punch is answered, not swallowed"
    );

    let mut frontless = Rig::with(Has {
        client_udp: true,
        front: false,
    });
    frontless.server_punch_live();
    let (ask, mut retire_rx) = road();
    assert_eq!(
        frontless.reacher.reach(&on_server, Some(ask.clone())).await,
        PeerReachRoute::ServerPunchUnavailable {
            low_id: on_server.id
        }
    );
    assert_eq!(
        retire_rx.try_recv(),
        Ok((ask.key, NattRetirement::NotEnactable))
    );
}

/// A rendezvous that cannot begin retires its candidate at once, with the
/// reason. Toward a buddy named by ID alone there is no dialect-sanctioned
/// walk for `OP_REASKCALLBACKUDP` (eMuleAI's own fallback never resolves one,
/// `BaseClient.cpp:3273-3323`); toward an anonymous candidate the attempt
/// could never be matched to its own answer. Nothing reaches the front.
#[tokio::test]
async fn a_rendezvous_that_cannot_begin_retires_its_candidate_with_the_reason() {
    let mut rig = Rig::new();
    let silent_server = || {
        pending(silent(PeerReachRoute::Server {
            low_id: punchable().id,
        }))
    };

    let (ask, mut retire_rx) = silent_server();
    assert_eq!(
        rig.reacher.reach(&id_only_buddy(), Some(ask.clone())).await,
        PeerReachRoute::NatTraversalUnavailable {
            buddy_id: buddy_id(),
            reason: NatTraversalUnavailableReason::BuddyEndpointUnknown,
        }
    );
    assert_eq!(
        retire_rx.try_recv(),
        Ok((ask.key, NattRetirement::CoordinatorEndpointUnknown))
    );

    let anonymous = PeerReach {
        user_hash: None,
        ..punchable()
    };
    let (ask, mut retire_rx) = silent_server();
    assert_eq!(
        rig.reacher.reach(&anonymous, Some(ask.clone())).await,
        PeerReachRoute::NatTraversalUnavailable {
            buddy_id: buddy_id(),
            reason: NatTraversalUnavailableReason::TargetIdentityUnknown,
        }
    );
    assert_eq!(
        retire_rx.try_recv(),
        Ok((ask.key, NattRetirement::NotEnactable))
    );
    assert!(
        rig.natt.try_recv().is_err(),
        "nothing was asked of the front"
    );
}

/// A download's punch no coordinator can introduce — no live server punch
/// for a target on our server, no buddy — opens nothing, so the one owner
/// that would report its end never exists: the candidate hears
/// `NoCoordinator` at once, it is counted, and it is reported as dropped
/// for want of a coordinator.
#[tokio::test]
async fn a_punch_no_coordinator_can_introduce_is_retired_and_reported_dropped() {
    let mut rig = Rig::new();
    let stranded = PeerReach {
        on_our_server: true,
        buddy: None,
        ..punchable()
    };
    let (ask, mut retire_rx) = pending(DownloadAsk::Traversal(CallbackSilence::NoCallbackPossible));

    let dropped = PeerReachRoute::Dropped {
        reason: PeerReachDropReason::NoCoordinator,
    };
    assert_eq!(
        rig.reacher.reach(&stranded, Some(ask.clone())).await,
        dropped
    );

    assert_eq!(
        retire_rx.try_recv(),
        Ok((ask.key, NattRetirement::NoCoordinator))
    );
    assert_eq!(
        rig.diagnostics
            .snapshot()
            .session
            .natt_download_adoptions_no_coordinator_total,
        1
    );
    assert_eq!(rig.reported(), [dropped]);
    assert!(rig.natt.try_recv().is_err());
}

/// The single emitter end to end: a server-coordinated punch handed over by
/// `reach` reaches the server as the `0x60` itself, put on our live session
/// by a running NAT-T Front over a real loopback client-UDP socket and naming
/// the port that socket bound — the route reported the moment the front took
/// it.
#[tokio::test]
async fn a_server_punch_reaches_the_session_as_a_0x60_through_a_running_front() {
    let mut rig = Rig::new();
    rig.server_punch_live();
    let socket = std::sync::Arc::new(
        rmule_net::ed2k::ClientUdpSocket::bind_with(
            0,
            rmule_net::family::FamilySelection::v4_only(),
        )
        .await
        .expect("a loopback client-UDP pair binds"),
    );
    let addresses = rig.own.addresses().clone();
    addresses.record_bind(SocketRole::Udp, socket.binds(), socket.local_port());
    let (client_udp, _sent) = mpsc::channel(8);
    let (_inbox_tx, inbox) = mpsc::channel(8);
    let natt = SharedNattFront::default();
    natt.install(
        crate::natt::front::spawn(
            rmule_net::natt::ClientUdpNattSink(std::sync::Arc::clone(&socket)),
            rmule_net::natt::NattIdentity {
                local: crate::natt::front::RMULE_NATT_CLAIM,
            },
            std::sync::Arc::new(rig.own.clone())
                as std::sync::Arc<dyn rmule_net::natt::NattOwnHash>,
            None,
            crate::natt::front::NattWiring {
                client_udp,
                server: rig.punch.coordinator_session(),
                reach: rig.reach.clone(),
                addresses,
                admit: crate::adapters::SharedTunnelAdmit::default(),
                claims: crate::adapters::AwaitedInbound::default(),
                peer_pin: crate::adapters::SharedPeerPin::default(),
                diagnostics: DiagnosticsState::default(),
                prediction: None,
                events: None,
            },
            inbox,
        )
        .expect("the front starts"),
    );
    let (events, mut reported) = mpsc::channel(4);
    let reacher = PeerReacher::new(PeerReachWiring {
        reach: rig.reach.clone(),
        client_udp: None,
        natt,
        kad_pump: SharedKadPump::default(),
        own: rig.own.clone(),
        obfuscation: crate::obfuscation_policy::SharedObfuscationPolicy::default(),
        diagnostics: DiagnosticsState::default(),
        events,
    });
    let on_server = PeerReach {
        on_our_server: true,
        buddy: None,
        ..punchable()
    };
    let (ask, _retire_rx) = pending(DownloadAsk::Traversal(CallbackSilence::NoCallbackPossible));

    let routed = reacher.reach(&on_server, Some(ask)).await;

    let taken = PeerReachRoute::ServerPunch {
        low_id: on_server.id,
    };
    assert_eq!(routed, taken);
    assert!(matches!(
        reported.try_recv(),
        Ok(CoreEvent::PeerReachRouted { route, .. }) if route == taken
    ));
    let (_, _, link) = rig.session.as_mut().expect("the session is live");
    let asked = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let rmule_ed2k::Ed2kCommand::RequestHolepunch {
                target,
                our_udp_port,
            } = link.recv().await.expect("the link is open")
            {
                return (target, our_udp_port);
            }
        }
    })
    .await
    .expect("the 0x60 reached the server");
    assert_eq!(asked, (on_server.id, socket.local_port()));
}

/// A HighID peer is dialed at the endpoint its record carries, and Peer
/// Reach hands that endpoint back in the route it reports.
#[tokio::test]
async fn a_high_id_peer_is_routed_direct_at_its_own_endpoint() {
    let rig = Rig::new();
    let tcp = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 4), 4662));
    let peer = PeerReach {
        id: ClientId::from_u32(0x0102_0304),
        tcp,
        buddy: None,
        ..punchable()
    };
    assert_eq!(
        rig.reacher.reach(&peer, None).await,
        PeerReachRoute::Direct { endpoint: tcp }
    );
}
