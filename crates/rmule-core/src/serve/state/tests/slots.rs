//! The upload queue: who gets a slot inside the shared budget, who waits, and
//! what a disconnect, a cancelled transfer or a credit re-rank does to the
//! order — including the identity proof that binds a waiter to its ledger.

use super::*;
use rmule_peer::{ConnectionEvent, ServerCommand, ServerEvent};

#[test]
fn slot_requests_grant_queue_or_refuse_within_the_shared_budget() {
    let file_hash = hash(0x33);
    let mut state = ServeState::new(UploadSlotQueue::new(1, 1));
    let _ = state.on_share_set(
        vec![entry(file_hash, 4096, "served.bin")],
        std::time::Instant::now(),
        &std::collections::HashMap::new(),
    );
    let t0 = Instant::now();
    let slot_request = |file_hash| ServeInput::Server(ServerEvent::SlotRequested { file_hash });

    // Each new asker is one request the file drew — granted, queued or turned
    // away at the full wait list alike (aMule `UploadQueue.cpp:519-522`).
    assert_eq!(
        state.on_conn_event(t0, peer(1), slot_request(file_hash), &no_modifiers()),
        vec![
            ServeDecision::CountUploadRequest { file_hash },
            send(peer(1), ServerCommand::GrantSlot { file_hash }),
            ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                peer: peer(1),
                file_hash,
                software: None,
                road: crate::GrantRoad::Linked,
            }),
        ],
    );
    assert_eq!(
        state.on_conn_event(t0, peer(2), slot_request(file_hash), &no_modifiers()),
        vec![
            ServeDecision::CountUploadRequest { file_hash },
            send(peer(2), ServerCommand::SetQueueRank { rank: 1 }),
            ServeDecision::Emit(ServeEvent::PeerQueued {
                peer: peer(2),
                rank: 1,
                file_hash,
                software: None,
            }),
        ],
    );
    // The wait list is at its cap: turn the third requester away **in
    // silence**, as both references do (aMule `src/UploadQueue.cpp:534-537`,
    // eMule `srchybrid/UploadQueue.cpp:639-656` both `return` before framing a
    // packet). The event is the refusal's only trace.
    assert_eq!(
        state.on_conn_event(t0, peer(3), slot_request(file_hash), &no_modifiers()),
        vec![
            ServeDecision::CountUploadRequest { file_hash },
            ServeDecision::Emit(ServeEvent::UploadQueueFull { peer: peer(3) }),
        ],
    );
    // A slot ask for a file we do not share draws nothing at all (aMule
    // `ClientTCPSocket.cpp:607-617` acts only on a file it finds).
    assert_eq!(
        state.on_conn_event(t0, peer(4), slot_request(hash(0x99)), &no_modifiers()),
        Vec::new(),
    );
}

/// Converted from the inline serve-task promotion test: a freed
/// slot goes to the highest-credit waiter, not the longest-waiting one.
#[test]
fn disconnect_promotes_the_highest_credit_waiter_and_releases_the_slot() {
    let file_hash = hash(0x88);
    let mut state = serving_state(1, vec![entry(file_hash, 4096, "served.bin")]);
    let t0 = Instant::now();
    let (holder, slow, rich) = (peer(1), peer(2), peer(3));

    let _ = state.on_conn_event(
        t0,
        holder,
        ServeInput::Server(ServerEvent::SlotRequested { file_hash }),
        &no_modifiers(),
    );
    let _ = state.on_conn_event(
        t0 + Duration::from_secs(1),
        slow,
        ServeInput::Server(ServerEvent::SlotRequested { file_hash }),
        &no_modifiers(),
    );
    let _ = state.on_conn_event(
        t0 + Duration::from_secs(2),
        rich,
        ServeInput::Server(ServerEvent::SlotRequested { file_hash }),
        &no_modifiers(),
    );

    // `rich` waited less but carries a 10x credit modifier: it wins the
    // freed slot; `slow` keeps rank 1 (no re-rank noise), and the
    // disconnect is reported last.
    let modifiers: HashMap<PeerEndpoint, f64> = [(rich, 10.0)].into_iter().collect();
    assert_eq!(
        state.on_conn_event(
            t0 + Duration::from_secs(10),
            holder,
            disconnected(),
            &modifiers,
        ),
        vec![
            send(rich, ServerCommand::GrantSlot { file_hash }),
            ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                peer: rich,
                file_hash,
                software: None,
                road: crate::GrantRoad::Linked,
            }),
            ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer: holder }),
        ],
    );
}

/// ADR-0056: `OP_CANCELTRANSFER` runs the exact same release/promote
/// batch as `Disconnected` (same decision shape, same credit-ranked
/// promotion) — the only difference (the connection staying registered)
/// lives in the runner, not this decision batch (pinned end-to-end in
/// `tests/serve_lifecycle.rs`).
#[test]
fn transfer_cancelled_promotes_the_highest_credit_waiter_and_releases_the_slot() {
    let file_hash = hash(0xBB);
    let mut state = serving_state(1, vec![entry(file_hash, 4096, "served.bin")]);
    let t0 = Instant::now();
    let (holder, slow, rich) = (peer(1), peer(2), peer(3));

    let _ = state.on_conn_event(
        t0,
        holder,
        ServeInput::Server(ServerEvent::SlotRequested { file_hash }),
        &no_modifiers(),
    );
    let _ = state.on_conn_event(
        t0 + Duration::from_secs(1),
        slow,
        ServeInput::Server(ServerEvent::SlotRequested { file_hash }),
        &no_modifiers(),
    );
    let _ = state.on_conn_event(
        t0 + Duration::from_secs(2),
        rich,
        ServeInput::Server(ServerEvent::SlotRequested { file_hash }),
        &no_modifiers(),
    );

    let modifiers: HashMap<PeerEndpoint, f64> = [(rich, 10.0)].into_iter().collect();
    assert_eq!(
        state.on_conn_event(
            t0 + Duration::from_secs(10),
            holder,
            ServeInput::Server(ServerEvent::TransferCancelled { file_hash }),
            &modifiers,
        ),
        vec![
            send(rich, ServerCommand::GrantSlot { file_hash }),
            ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                peer: rich,
                file_hash,
                software: None,
                road: crate::GrantRoad::Linked,
            }),
            ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer: holder }),
        ],
    );
}

/// ADR-0056: a cancel wipes the canceller's served ranges, so pending
/// unsent blocks are dropped — a fresh ask for the same range after the
/// cancel reads it again rather than treating it as already served.
#[test]
fn transfer_cancelled_wipes_served_ranges_so_a_fresh_ask_re_reads() {
    let file_hash = hash(0xCC);
    let mut state = serving_state(1, vec![entry(file_hash, 512, "served.bin")]);
    let t = Instant::now();
    let p = peer(1);
    identify(&mut state, p, user(0x0B), t);

    let ranges = PartRanges::new([(0, 100), (0, 0), (0, 0)]);
    let flow_read = |flow| ServeDecision::ReadRange {
        peer: p,
        flow,
        from: ReadFrom::Row("/shared/served.bin".into()),
        block: BlockRead {
            file_hash,
            start: 0,
            end: 100,
        },
    };
    let slot = ServeInput::Server(ServerEvent::SlotRequested { file_hash });
    let _ = state.on_conn_event(t, p, slot.clone(), &no_modifiers());
    assert_eq!(
        state.on_conn_event(
            t,
            p,
            ServeInput::Server(ServerEvent::PartsRequested { file_hash, ranges }),
            &no_modifiers(),
        ),
        vec![flow_read(1)],
    );

    // Cancel wipes the range record (and the credit identity) without
    // the runner ever removing the connection.
    let _ = state.on_conn_event(
        t,
        p,
        ServeInput::Server(ServerEvent::TransferCancelled { file_hash }),
        &no_modifiers(),
    );
    let _ = state.end_slotless_flows();
    let _ = state.on_conn_event(t, p, slot, &no_modifiers());
    assert_eq!(
        state.on_conn_event(
            t,
            p,
            ServeInput::Server(ServerEvent::PartsRequested { file_hash, ranges }),
            &no_modifiers(),
        ),
        vec![flow_read(2)],
        "the same range reads again on the next slot: nothing is stranded as already-served"
    );
}

/// Defends the `is_granted` guard: a cancel for a peer holding no
/// granted slot (never reachable from a correctly-gated session, which
/// only surfaces `TransferCancelled` when `served_slot` was held) claims
/// no release and disturbs nothing.
#[test]
fn transfer_cancelled_for_a_peer_holding_no_granted_slot_is_a_noop() {
    let file_hash = hash(0xDD);
    let mut state = serving_state(1, vec![entry(file_hash, 4096, "served.bin")]);
    let t = Instant::now();
    assert_eq!(
        state.on_conn_event(
            t,
            peer(9),
            ServeInput::Server(ServerEvent::TransferCancelled { file_hash }),
            &no_modifiers(),
        ),
        Vec::new(),
    );
}

/// Converted from the inline serve-task rerank test: a rerank tick
/// reorders waiting peers by live credit, reporting only changed ranks.
#[test]
fn rerank_reorders_waiters_by_live_credit() {
    let file_hash = hash(0x99);
    let mut state = serving_state(1, vec![entry(file_hash, 4096, "served.bin")]);
    let t0 = Instant::now();
    let (holder, slow, rich) = (peer(1), peer(2), peer(3));

    for (t, p) in [
        (t0, holder),
        (t0 + Duration::from_secs(1), slow),
        (t0 + Duration::from_secs(2), rich),
    ] {
        let _ = state.on_conn_event(
            t,
            p,
            ServeInput::Server(ServerEvent::SlotRequested { file_hash }),
            &no_modifiers(),
        );
    }

    let modifiers: HashMap<PeerEndpoint, f64> = [(rich, 5.0)].into_iter().collect();
    assert_eq!(
        state.on_rerank_tick(t0 + Duration::from_secs(62), &modifiers),
        vec![
            send(rich, ServerCommand::SetQueueRank { rank: 1 }),
            ServeDecision::Emit(ServeEvent::PeerQueued {
                peer: rich,
                rank: 1,
                file_hash,
                software: None,
            }),
            send(slow, ServerCommand::SetQueueRank { rank: 2 }),
            ServeDecision::Emit(ServeEvent::PeerQueued {
                peer: slow,
                rank: 2,
                file_hash,
                software: None,
            }),
        ],
    );
    // Unchanged credit re-ranks nothing: no repeat OP_QUEUERANKING spam.
    assert_eq!(
        state.on_rerank_tick(t0 + Duration::from_secs(63), &modifiers),
        Vec::new(),
    );
}

/// A readopted peer (ADR-0039) never held a slot: unlike `Disconnected`
/// it releases nothing and emits nothing, but its flow state is wiped —
/// the enactor stops reading its modifier.
#[test]
fn readopted_peers_leave_no_queue_release_and_lose_their_flow_state() {
    let file_hash = hash(0xAA);
    let mut state = serving_state(1, vec![entry(file_hash, 4096, "served.bin")]);
    let t = Instant::now();
    let (adopted, waiter) = (peer(1), peer(2));
    identify(&mut state, adopted, user(0x0A), t);
    let _ = state.on_conn_event(
        t,
        waiter,
        ServeInput::Server(ServerEvent::SlotRequested { file_hash }),
        &no_modifiers(),
    );

    assert_eq!(
        state.on_conn_event(t, adopted, ServeInput::Readopted, &no_modifiers()),
        Vec::new(),
        "readoption releases no slot and emits no event"
    );
    assert_eq!(
        state.identities().get(&adopted),
        None,
        "the adopted peer's serve-side identity is dropped"
    );
}

/// The **Low-ID abuse guard** at the one admission point (ADR-0031 amendment):
/// while we are Low-ID and the wait list is over fifty, a stranger
/// gets no decision but the fact — no packet, no queue place. The same ask
/// from a peer on our server is admitted, which is what the guard is *for*: a
/// firewalled node's places belong to peers that can actually reach it.
#[test]
fn a_firewalled_node_refuses_strangers_once_the_wait_list_is_over_fifty() {
    let file_hash = hash(0x33);
    let mut state = ServeState::new(UploadSlotQueue::new(1, 500));
    let _ = state.on_share_set(
        vec![entry(file_hash, 4096, "served.bin")],
        std::time::Instant::now(),
        &std::collections::HashMap::new(),
    );
    let t0 = Instant::now();
    let slot_request = ServeInput::Server(ServerEvent::SlotRequested { file_hash });
    let our_server = rmule_primitives::Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 9), 4661);
    state.on_self_position(ServeSelfPosition {
        low_id: true,
        server: Some(our_server),
    });

    // One holder plus fifty-one waiters, each from its own address so the
    // per-address cap is not what refuses.
    for place in 0..52u16 {
        let decisions = state.on_conn_event(
            t0,
            distinct_peer(place),
            slot_request.clone(),
            &no_modifiers(),
        );
        assert!(
            !decisions.is_empty(),
            "waiter {place} is admitted: the wait list is not over fifty yet"
        );
    }

    let stranger = distinct_peer(100);
    assert_eq!(
        state.on_conn_event(t0, stranger, slot_request.clone(), &no_modifiers()),
        vec![ServeDecision::Emit(ServeEvent::UploadLowIdAbuseRefused {
            peer: stranger
        })],
    );

    // The same ask, from a peer whose hello named our own server.
    let neighbour = distinct_peer(101);
    let _ = state.on_conn_event(
        t0,
        neighbour,
        identified_on(Some(our_server)),
        &no_modifiers(),
    );
    assert!(
        matches!(
            state
                .on_conn_event(t0, neighbour, slot_request.clone(), &no_modifiers())
                .as_slice(),
            [
                ServeDecision::CountUploadRequest { .. },
                ServeDecision::Send { .. },
                ServeDecision::Emit(_)
            ]
        ),
        "a peer on our server is queued, not refused"
    );

    // And once the login turns High-ID, the guard stops applying at once.
    state.on_self_position(ServeSelfPosition {
        low_id: false,
        server: Some(our_server),
    });
    let late = distinct_peer(102);
    assert!(
        matches!(
            state
                .on_conn_event(t0, late, slot_request, &no_modifiers())
                .as_slice(),
            [
                ServeDecision::CountUploadRequest { .. },
                ServeDecision::Send { .. },
                ServeDecision::Emit(_)
            ]
        ),
        "a High-ID node guards nothing by refusing"
    );
}

/// A peer at its own IPv4 address, so a test about the wait-list length is not
/// silently about the per-address cap instead.
fn distinct_peer(nth: u16) -> PeerEndpoint {
    PeerEndpoint::V4(rmule_primitives::Ipv4Endpoint::new(
        Ipv4Addr::new(203, 0, 113, 0)
            .to_bits()
            .wrapping_add(u32::from(nth))
            .into(),
        4662,
    ))
}

/// An `Identified` event whose hello named `server` and nothing else of note.
fn identified_on(server: Option<rmule_primitives::Ipv4Endpoint>) -> ServeInput {
    HelloFacts {
        connected_server: server,
        ..HelloFacts::of(user(0x4D))
    }
    .identified()
}

/// The per-address queue cap on the brain's own surface (ADR-0088): the
/// fourth waiter from one address yields **no `Send` decision at all** — the
/// reference frames no packet for this refusal (eMule
/// `srchybrid/UploadQueue.cpp:608-613`, aMule `src/UploadQueue.cpp:510-516`
/// both `return` before sending) — only the fact the counter is kept from.
///
/// The queue-full arm above answers alike; the two differ only in which
/// limit was hit, and so in which counter records it.
#[test]
fn the_fourth_waiter_from_one_address_is_refused_without_a_packet() {
    let file_hash = hash(0x33);
    let mut state = serving_state(1, vec![entry(file_hash, 4096, "served.bin")]);
    let t0 = Instant::now();
    let slot_request = ServeInput::Server(ServerEvent::SlotRequested { file_hash });

    // `peer(port)` varies only the port, so all five share one address.
    let _ = state.on_conn_event(t0, peer(1), slot_request.clone(), &no_modifiers());
    for place in 1..=3u16 {
        assert_eq!(
            state.on_conn_event(t0, peer(place + 1), slot_request.clone(), &no_modifiers()),
            vec![
                ServeDecision::CountUploadRequest { file_hash },
                send(peer(place + 1), ServerCommand::SetQueueRank { rank: place },),
                ServeDecision::Emit(ServeEvent::PeerQueued {
                    peer: peer(place + 1),
                    rank: place,
                    file_hash,
                    software: None,
                }),
            ],
        );
    }
    assert_eq!(
        state.on_conn_event(t0, peer(5), slot_request.clone(), &no_modifiers()),
        vec![ServeDecision::Emit(ServeEvent::UploadAddressCapReached {
            peer: peer(5)
        })],
    );
    // A waiter that is already queued keeps answering its own rank: the cap
    // never reaches the reask path (ADR-0057). Neither the capped asker nor
    // the waiter asking again is a new request.
    assert_eq!(
        state.on_conn_event(t0, peer(2), slot_request, &no_modifiers()),
        vec![
            send(peer(2), ServerCommand::SetQueueRank { rank: 1 }),
            ServeDecision::Emit(ServeEvent::PeerQueued {
                peer: peer(2),
                rank: 1,
                file_hash,
                software: None,
            }),
        ],
    );
}

/// A waiter follows the last file it asked about, and the move is reported, so
/// a consumer's row names the file the waiter now waits for; asking about the
/// same file again moves nothing and reports nothing.
#[test]
fn a_waiter_asking_about_another_file_is_reported_waiting_for_it() {
    let (film, song) = (hash(0x33), hash(0x44));
    let mut state = serving_state(
        1,
        vec![entry(film, 4096, "film.mkv"), entry(song, 4096, "song.mp3")],
    );
    let t0 = Instant::now();
    let _ = slot_request(&mut state, peer(1), film, t0);
    let _ = slot_request(&mut state, peer(2), film, t0);

    let status_ask = |file_hash| ServeInput::Server(ServerEvent::FileIdSet { file_hash });
    let moved = state.on_conn_event(t0, peer(2), status_ask(song), &no_modifiers());
    assert!(
        moved.contains(&ServeDecision::Emit(ServeEvent::PeerQueued {
            peer: peer(2),
            rank: 1,
            file_hash: song,
            software: None,
        })),
        "{moved:?}"
    );
    let again = state.on_conn_event(t0, peer(2), status_ask(song), &no_modifiers());
    assert!(
        !again
            .iter()
            .any(|decision| matches!(decision, ServeDecision::Emit(_))),
        "{again:?}"
    );
}

/// The grant and queue edges name the client each peer's own hello named —
/// here an aMule 2.3.3 hello and an eMule one, not swapped between them.
#[test]
fn grant_and_queue_edges_name_each_peers_own_client() {
    use rmule_primitives::{Ed2kText, Ipv4Endpoint, Tag, TagName, TagValue};
    let file_hash = hash(0x34);
    let mut state = ServeState::new(UploadSlotQueue::new(1, 4));
    let _ = state.on_share_set(
        vec![entry(file_hash, 4096, "served.bin")],
        std::time::Instant::now(),
        &std::collections::HashMap::new(),
    );
    let t0 = Instant::now();
    // The CT_EMULE_VERSION words of the captured aMule 2.3.3 and emule-qt
    // hellos (rmule-peer's client_software_capture).
    let software = |word: u32| {
        rmule_peer::ClientSoftware::from_hello_body(&rmule_peer::PeerHelloBody {
            user_hash: UserHash::from_bytes([7; UserHash::BYTE_LEN]),
            client_id: ClientId::from_u32(0),
            tcp_port: 4662,
            tags: vec![
                Tag::new(
                    TagName::compact_id(0x01),
                    TagValue::String(Ed2kText::from_utf8("peer")),
                ),
                Tag::new(TagName::compact_id(0xFB), TagValue::U32(word)),
            ],
            connected_server: Ipv4Endpoint::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
        })
    };
    let (amule, emule) = (software(0x0304_0D80), software(0x0001_1880));
    for (n, hash_byte, client) in [(1, 0x01, &amule), (2, 0x02, &emule)] {
        let _ = state.on_conn_event(
            t0,
            peer(n),
            HelloFacts {
                extended_requests_version: 0,
                crypt: rmule_primitives::CryptStance::disabled(),
                software: client.clone(),
                ..HelloFacts::of(UserHash::from_bytes([hash_byte; UserHash::BYTE_LEN]))
            }
            .identified(),
            &no_modifiers(),
        );
    }
    let request = ServeInput::Server(ServerEvent::SlotRequested { file_hash });
    let granted = state.on_conn_event(t0, peer(1), request.clone(), &no_modifiers());
    let queued = state.on_conn_event(t0, peer(2), request, &no_modifiers());
    assert!(
        granted.contains(&ServeDecision::Emit(ServeEvent::UploadSlotGranted {
            peer: peer(1),
            file_hash,
            software: Some(amule),
            road: crate::GrantRoad::Linked,
        }))
    );
    assert!(
        queued.contains(&ServeDecision::Emit(ServeEvent::PeerQueued {
            peer: peer(2),
            rank: 1,
            file_hash,
            software: Some(emule),
        }))
    );
}

/// A pre-0.42 mule's `OP_EMULEINFO` names its version after its hello:
/// the upload row it later earns shows the revised software, and a revision for
/// a peer the serve side holds no hello for changes nothing.
#[test]
fn a_software_revision_reaches_the_upload_row() {
    let file_hash = hash(0x33);
    let mut state = ServeState::new(UploadSlotQueue::new(2, 1));
    let _ = state.on_share_set(
        vec![entry(file_hash, 4096, "served.bin")],
        std::time::Instant::now(),
        &std::collections::HashMap::new(),
    );
    let t0 = Instant::now();
    identify(&mut state, peer(1), UserHash::from_bytes([0x11; 16]), t0);
    let named = rmule_peer::ClientSoftware::from_hello_body(&rmule_peer::PeerHelloBody {
        user_hash: UserHash::from_bytes([0x11; 16]),
        client_id: ClientId::from_u32(0),
        tcp_port: 0,
        tags: vec![rmule_primitives::Tag::new(
            rmule_primitives::TagName::compact_id(0x01),
            rmule_primitives::TagValue::String(rmule_primitives::Ed2kText::from_utf8("old")),
        )],
        connected_server: rmule_primitives::Ipv4Endpoint::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
    });
    for p in [peer(1), peer(2)] {
        let revised = ServeInput::Connection(ConnectionEvent::IdentityRevised {
            identity: HelloFacts {
                software: named.clone(),
                ..hello_facts(UserHash::from_bytes([0x11; 16]), 0, 0, 2)
            }
            .identity(),
            what: IdentityChange::Software,
        });
        assert_eq!(
            state.on_conn_event(t0, p, revised, &no_modifiers()),
            Vec::new()
        );
    }
    let granted = |state: &mut ServeState, p| {
        state
            .on_conn_event(
                t0,
                p,
                ServeInput::Server(ServerEvent::SlotRequested { file_hash }),
                &no_modifiers(),
            )
            .into_iter()
            .find_map(|d| match d {
                ServeDecision::Emit(ServeEvent::UploadSlotGranted { software, .. }) => {
                    Some(software)
                }
                _ => None,
            })
    };
    assert_eq!(granted(&mut state, peer(1)), Some(Some(named)));
    assert_eq!(granted(&mut state, peer(2)), Some(None));
}

/// Two peers on a one-slot queue: the first holds the slot, the second waits.
fn holder_and_waiter(file_hash: FileHash, t: Instant) -> (ServeState, PeerEndpoint, PeerEndpoint) {
    let mut state = serving_state(1, vec![entry(file_hash, 64 << 20, "served.bin")]);
    let (holder, waiter) = (peer(4001), peer(4002));
    identify(&mut state, holder, user(1), t);
    identify(&mut state, waiter, user(2), t);
    let _ = slot_request(&mut state, holder, file_hash, t);
    let _ = slot_request(&mut state, waiter, file_hash, t);
    (state, holder, waiter)
}

fn block_left(file_hash: FileHash, bytes: u64) -> ServeInput {
    ServeInput::Server(ServerEvent::BlockLeft {
        file_hash,
        start: 0,
        end: bytes,
    })
}

/// aMule kicks at 10 MiB while someone waits, tells the holder at once and
/// puts it back on the wait list (`UploadQueue.cpp:616-620`,
/// `UploadClient.cpp:493-510`): the slot goes to the waiter in the same batch.
#[test]
fn a_session_past_its_bytes_ends_tells_the_holder_and_moves_the_queue() {
    let file_hash = hash(0x51);
    let t = Instant::now();
    let (mut state, holder, waiter) = holder_and_waiter(file_hash, t);

    let under = state.on_conn_event(
        t,
        holder,
        block_left(file_hash, 10_485_760),
        &no_modifiers(),
    );
    assert!(
        !under.contains(&send(holder, ServerCommand::EndUploadSession)),
        "the bound is strictly more than 10 MiB"
    );

    let over = state.on_conn_event(t, holder, block_left(file_hash, 1), &no_modifiers());
    let told = over
        .iter()
        .position(|d| *d == send(holder, ServerCommand::EndUploadSession))
        .expect("the holder is told");
    let granted = over
        .iter()
        .position(|d| *d == send(waiter, ServerCommand::GrantSlot { file_hash }))
        .expect("the waiter takes the slot");
    assert!(told < granted);
    assert!(over.contains(&send(holder, ServerCommand::SetQueueRank { rank: 1 })));
    assert!(state.queue.is_granted(waiter));
    assert!(state.queue.contains(holder) && !state.queue.is_granted(holder));
}

/// `m_allowKicking` stands only with someone waiting (`UploadQueue.cpp:244-258`).
#[test]
fn a_session_past_its_bytes_runs_on_while_nobody_waits() {
    let file_hash = hash(0x52);
    let t = Instant::now();
    let mut state = serving_state(1, vec![entry(file_hash, 64 << 20, "served.bin")]);
    let holder = peer(4001);
    identify(&mut state, holder, user(1), t);
    let _ = slot_request(&mut state, holder, file_hash, t);

    let decisions = state.on_conn_event(t, holder, block_left(file_hash, 1 << 30), &no_modifiers());

    assert!(!decisions.contains(&send(holder, ServerCommand::EndUploadSession)));
    assert!(state.queue.is_granted(holder));
}

/// A holder that sends nothing cannot sit out the bytes bound: the hour is read
/// at the slot sweep (`UploadQueue.cpp:616`).
#[test]
fn a_session_past_its_hour_ends_at_the_sweep() {
    let file_hash = hash(0x53);
    let t = Instant::now();
    let (mut state, holder, waiter) = holder_and_waiter(file_hash, t);
    // Each sweep before the bound is a live holder, so its slot stands.
    let moved = t + Duration::from_secs(3600);
    state.link_moved(moved, holder);
    assert!(
        !state
            .on_slot_sweep(moved, &no_modifiers())
            .contains(&send(holder, ServerCommand::EndUploadSession))
    );

    let past = moved + Duration::from_secs(1);
    state.link_moved(past, holder);
    let decisions = state.on_slot_sweep(past, &no_modifiers());

    assert!(decisions.contains(&send(holder, ServerCommand::EndUploadSession)));
    assert!(state.queue.is_granted(waiter));
}

/// One kick a cycle, one start a second (`UploadQueue.cpp:244-258`, `:619`).
#[test]
fn sessions_end_one_a_second() {
    let file_hash = hash(0x54);
    let t = Instant::now();
    let mut state = serving_state(2, vec![entry(file_hash, 64 << 20, "served.bin")]);
    let (one, two) = (peer(4001), peer(4002));
    let waiters = [peer(4003), peer(4004)];
    for (index, p) in [one, two, waiters[0], waiters[1]].into_iter().enumerate() {
        identify(&mut state, p, user(index as u8 + 1), t);
        let _ = slot_request(&mut state, p, file_hash, t);
    }
    let full = 11 << 20;
    let first = state.on_conn_event(t, one, block_left(file_hash, full), &no_modifiers());
    let second = state.on_conn_event(t, two, block_left(file_hash, full), &no_modifiers());
    assert!(first.contains(&send(one, ServerCommand::EndUploadSession)));
    assert!(!second.contains(&send(two, ServerCommand::EndUploadSession)));

    let later = t + Duration::from_secs(1);
    let next = state.on_conn_event(later, two, block_left(file_hash, 1), &no_modifiers());
    assert!(next.contains(&send(two, ServerCommand::EndUploadSession)));
}

/// aMule's guard reads `GetDownloadState() == DS_NONE`: "not our source", not
/// "no slot of ours" (`UploadQueue.cpp:405`). A source of ours asks past fifty
/// waiters; a slot holder that is none of ours is a stranger to it.
#[test]
fn the_low_id_guard_spares_our_sources_and_nobody_else() {
    let file_hash = hash(0x55);
    let t = Instant::now();
    let mut state = ServeState::new(UploadSlotQueue::new(1, 64));
    let _ = state.on_share_set(
        vec![entry(file_hash, 4096, "served.bin")],
        t,
        &no_modifiers(),
    );
    state.on_self_position(ServeSelfPosition {
        low_id: true,
        server: None,
    });
    let holder = peer_at([198, 51, 100, 200], 4662);
    let _ = slot_request(&mut state, holder, file_hash, t);
    for n in 0..51 {
        let _ = slot_request(
            &mut state,
            peer_at([198, 51, 100, n + 1], 4662),
            file_hash,
            t,
        );
    }

    let refused = ServeDecision::Emit(ServeEvent::UploadLowIdAbuseRefused { peer: holder });
    assert_eq!(
        slot_request(&mut state, holder, file_hash, t),
        vec![refused]
    );

    state.on_asker(ServeAsker {
        banned: false,
        our_source: true,
    });
    let source = peer_at([198, 51, 100, 201], 4662);
    let refused = ServeDecision::Emit(ServeEvent::UploadLowIdAbuseRefused { peer: source });
    assert!(!slot_request(&mut state, source, file_hash, t).contains(&refused));
}

fn banned_asker() -> ServeAsker {
    ServeAsker {
        banned: true,
        our_source: false,
    }
}

/// A ban lands on an open link: the holder's next ask ends its slot and its
/// link, the next waiter is granted in the same batch, and it is answered
/// nothing (`ClientTCPSocket.cpp:660`, `UploadClient.cpp:628-649`).
#[test]
fn a_banned_holders_next_ask_ends_its_slot_and_moves_the_queue() {
    let file_hash = hash(0x56);
    let t = Instant::now();
    let (mut state, holder, waiter) = holder_and_waiter(file_hash, t);

    state.on_asker(banned_asker());
    let decisions = state.on_conn_event(
        t,
        holder,
        parts(file_hash, [(0, 512), (0, 0), (0, 0)]),
        &no_modifiers(),
    );

    assert!(decisions.contains(&ServeDecision::Disconnect { peer: holder }));
    assert!(decisions.contains(&send(waiter, ServerCommand::GrantSlot { file_hash })));
    assert!(
        decisions.contains(&ServeDecision::Emit(ServeEvent::UploadSlotReleased {
            peer: holder
        }))
    );
    assert!(!state.queue.contains(holder));
}

/// A waiter a ban reaches leaves at the next sort, heard from or not, and is
/// never promoted (`UploadQueue.cpp:98`).
#[test]
fn a_banned_waiter_leaves_at_the_sweep() {
    let file_hash = hash(0x57);
    let t = Instant::now();
    let (mut state, holder, waiter) = holder_and_waiter(file_hash, t);

    let decisions = state.on_banned_standings(t, &[waiter], &no_modifiers());

    assert!(
        decisions.contains(&ServeDecision::Emit(ServeEvent::WaiterLeft {
            peer: waiter,
            cause: WaiterLeaveCause::Banned,
        }))
    );
    assert!(!state.queue.contains(waiter));
    assert!(state.queue.is_granted(holder));
}

/// A source of ours is not banned to the serve side: stock's `IsBanned` reads
/// false for a client it downloads from (`UploadClient.cpp:653`).
#[test]
fn a_ban_spares_a_source_of_ours() {
    let file_hash = hash(0x58);
    let t = Instant::now();
    let (mut state, holder, _) = holder_and_waiter(file_hash, t);

    state.on_asker(ServeAsker {
        banned: true,
        our_source: true,
    });
    let decisions = state.on_conn_event(
        t,
        holder,
        ServeInput::Server(ServerEvent::SlotRequested { file_hash }),
        &no_modifiers(),
    );

    assert!(decisions.contains(&send(holder, ServerCommand::GrantSlot { file_hash })));
    assert!(state.queue.is_granted(holder));
}

/// Five fast slot asks reach the score of ten and ban: stock's arithmetic,
/// charged at `OP_STARTUPLOADREQ` (`ClientTCPSocket.cpp:659`).
#[test]
fn a_fifth_fast_slot_ask_bans_and_a_source_of_ours_is_spared() {
    let file_hash = hash(0x59);
    let t = Instant::now();
    let (mut state, holder, waiter) = holder_and_waiter(file_hash, t);
    for _ in 0..3 {
        let decisions = slot_request(&mut state, waiter, file_hash, t);
        assert!(!decisions.contains(&ServeDecision::Ban { peer: waiter }));
    }

    let banned = slot_request(&mut state, waiter, file_hash, t);

    assert_eq!(banned[0], ServeDecision::Ban { peer: waiter });
    assert!(banned.contains(&ServeDecision::Disconnect { peer: waiter }));
    assert!(!state.queue.contains(waiter));

    state.on_asker(ServeAsker {
        banned: false,
        our_source: true,
    });
    for _ in 0..8 {
        let decisions = slot_request(&mut state, holder, file_hash, t);
        assert!(!decisions.contains(&ServeDecision::Ban { peer: holder }));
    }
}

/// 3.1.0 charges `OP_AICHREQUEST` as a file ask (`ClientTCPSocket.cpp:1768`):
/// the address cap never bounded its walk of known2.
#[test]
fn fast_aich_recovery_asks_ban_too() {
    let file_hash = hash(0x5A);
    let t = Instant::now();
    let mut state = serving_state(1, vec![entry(file_hash, 4096, "served.bin")]);
    let asker = peer(4001);
    identify(&mut state, asker, user(1), t);
    let ask = ServeInput::Server(ServerEvent::AichRequested {
        file_hash,
        part: 0,
        root: rmule_primitives::AichRootHash::from_bytes(
            [1; rmule_primitives::AichRootHash::BYTE_LEN],
        ),
    });
    let mut last = Vec::new();
    for _ in 0..5 {
        last = state.on_conn_event(t, asker, ask.clone(), &no_modifiers());
    }
    assert_eq!(last[0], ServeDecision::Ban { peer: asker });
}

/// A client that proved a key at a place and comes back under another hash
/// inside two hours is banned at the hello (`BaseClient.cpp:780-787`); a place
/// that never proved one changes hash freely.
#[test]
fn a_new_hash_at_a_place_that_proved_another_bans_at_the_hello() {
    let t = Instant::now();
    let mut state = serving_state(1, Vec::new());
    let place = peer(4001);
    identify(&mut state, place, user(1), t);
    let _ = state.on_conn_event(
        t,
        place,
        ServeInput::IdentityBound { user_hash: user(1) },
        &no_modifiers(),
    );

    let back = hello_facts(user(2), 0, 0, 2).identified();
    let decisions = state.on_conn_event(
        t,
        peer_at([10, 0, 0, 9], 4662),
        back.clone(),
        &no_modifiers(),
    );
    assert!(decisions.is_empty(), "another place is another client");

    let decisions = state.on_conn_event(t, place, back, &no_modifiers());
    assert!(decisions.contains(&ServeDecision::Ban { peer: place }));
}

/// A silent link closes, its waiter's place riding its reask (ADR-0057), and a
/// slot holder's is left to the slot sweep, which lends what the kernel holds.
#[test]
fn a_silent_link_closes_unless_it_holds_a_slot() {
    let file_hash = hash(0x5B);
    let t = Instant::now();
    let (mut state, holder, waiter) = holder_and_waiter(file_hash, t);

    let silent = state.on_conn_event(t, waiter, ServeInput::LinkSilent, &no_modifiers());
    assert_eq!(silent, vec![ServeDecision::Disconnect { peer: waiter }]);

    let held = state.on_conn_event(t, holder, ServeInput::LinkSilent, &no_modifiers());
    assert_eq!(held, Vec::new());
}
