//! The upload queue: who gets a slot inside the shared budget, who waits, and
//! what a disconnect, a cancelled transfer or a credit re-rank does to the
//! order — including the identity proof that binds a waiter to its ledger.

use super::*;

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
    let slot_request = |file_hash| ServeConnEvent::SlotRequested { file_hash };

    // Each new asker is one request the file drew — granted, queued or turned
    // away at the full wait list alike (aMule `UploadQueue.cpp:519-522`).
    assert_eq!(
        state.on_conn_event(t0, peer(1), slot_request(file_hash), &no_modifiers()),
        vec![
            ServeDecision::CountUploadRequest { file_hash },
            send(peer(1), ServeConnCommand::GrantSlot { file_hash }),
            ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                peer: peer(1),
                file_hash,
                software: None,
            }),
        ],
    );
    assert_eq!(
        state.on_conn_event(t0, peer(2), slot_request(file_hash), &no_modifiers()),
        vec![
            ServeDecision::CountUploadRequest { file_hash },
            send(peer(2), ServeConnCommand::SetQueueRank { rank: 1 }),
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

/// Converted from the inline serve-task theft test (ADR-0041):
/// the brain forwards every SUI proof as a `BindIdentity` decision —
/// including a thief's under a different key — because only the ledger
/// knows the stored key. Its atomic compare-and-set denies the mismatch
/// (pinned in `tests/credit_store.rs`) and the enactor reports the theft,
/// mirroring the download runner's arm.
#[test]
fn identity_proofs_bind_through_the_ledger_decision() {
    let mut state = serving_state(1, Vec::new());
    let user_hash = user(0x0C);
    let t = Instant::now();

    for (p, key) in [
        (peer(1), b"the-owners-key".as_slice()),
        (peer(2), b"the-thiefs-key".as_slice()),
    ] {
        assert_eq!(
            state.on_conn_event(
                t,
                p,
                ServeConnEvent::IdentityVerified {
                    user_hash,
                    public_key: key.to_vec(),
                },
                &no_modifiers(),
            ),
            vec![ServeDecision::BindIdentity {
                user_hash,
                public_key: key.to_vec(),
            }],
        );
    }
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
        ServeConnEvent::SlotRequested { file_hash },
        &no_modifiers(),
    );
    let _ = state.on_conn_event(
        t0 + Duration::from_secs(1),
        slow,
        ServeConnEvent::SlotRequested { file_hash },
        &no_modifiers(),
    );
    let _ = state.on_conn_event(
        t0 + Duration::from_secs(2),
        rich,
        ServeConnEvent::SlotRequested { file_hash },
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
            ServeConnEvent::Disconnected,
            &modifiers,
        ),
        vec![
            send(rich, ServeConnCommand::GrantSlot { file_hash }),
            ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                peer: rich,
                file_hash,
                software: None,
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
        ServeConnEvent::SlotRequested { file_hash },
        &no_modifiers(),
    );
    let _ = state.on_conn_event(
        t0 + Duration::from_secs(1),
        slow,
        ServeConnEvent::SlotRequested { file_hash },
        &no_modifiers(),
    );
    let _ = state.on_conn_event(
        t0 + Duration::from_secs(2),
        rich,
        ServeConnEvent::SlotRequested { file_hash },
        &no_modifiers(),
    );

    let modifiers: HashMap<PeerEndpoint, f64> = [(rich, 10.0)].into_iter().collect();
    assert_eq!(
        state.on_conn_event(
            t0 + Duration::from_secs(10),
            holder,
            ServeConnEvent::TransferCancelled { file_hash },
            &modifiers,
        ),
        vec![
            send(rich, ServeConnCommand::GrantSlot { file_hash }),
            ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                peer: rich,
                file_hash,
                software: None,
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

    let ranges = PartRanges::new([(0, 100), (0, 0), (0, 0)]).unwrap();
    let read = ServeDecision::ReadRange {
        peer: p,
        path: "/shared/served.bin".into(),
        offset: 0,
        len: 100,
        purpose: ReadPurpose::Block {
            file_hash,
            start: 0,
            end: 100,
        },
    };
    assert_eq!(
        state.on_conn_event(
            t,
            p,
            ServeConnEvent::PartsRequested { file_hash, ranges },
            &no_modifiers(),
        ),
        vec![read.clone()],
    );

    // Cancel wipes the range record (and the credit identity) without
    // the runner ever removing the connection.
    let _ = state.on_conn_event(
        t,
        p,
        ServeConnEvent::TransferCancelled { file_hash },
        &no_modifiers(),
    );
    assert_eq!(
        state.on_conn_event(
            t,
            p,
            ServeConnEvent::PartsRequested { file_hash, ranges },
            &no_modifiers(),
        ),
        vec![read],
        "the same range reads again: nothing is stranded as already-served"
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
            ServeConnEvent::TransferCancelled { file_hash },
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
            ServeConnEvent::SlotRequested { file_hash },
            &no_modifiers(),
        );
    }

    let modifiers: HashMap<PeerEndpoint, f64> = [(rich, 5.0)].into_iter().collect();
    assert_eq!(
        state.on_rerank_tick(t0 + Duration::from_secs(62), &modifiers),
        vec![
            send(rich, ServeConnCommand::SetQueueRank { rank: 1 }),
            ServeDecision::Emit(ServeEvent::PeerQueued {
                peer: rich,
                rank: 1,
                file_hash,
                software: None,
            }),
            send(slow, ServeConnCommand::SetQueueRank { rank: 2 }),
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
        ServeConnEvent::SlotRequested { file_hash },
        &no_modifiers(),
    );

    assert_eq!(
        state.on_conn_event(t, adopted, ServeConnEvent::Readopted, &no_modifiers()),
        Vec::new(),
        "readoption releases no slot and emits no event"
    );
    assert!(
        !state.identified_peers().contains_key(&adopted),
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
    let slot_request = ServeConnEvent::SlotRequested { file_hash };
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
fn identified_on(server: Option<rmule_primitives::Ipv4Endpoint>) -> ServeConnEvent {
    ServeConnEvent::Identified {
        user_hash: user(0x4D),
        client_id: ClientId::from_u32(0x0100_007F),
        connected_server: server,
        tcp_port: 4662,
        udp_port: 0,
        udp_version: 0,
        extended_requests_version: 2,
        crypt: crypt_advert(),
        ipv6: None,
        software: nameless_software(),
    }
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
    let slot_request = ServeConnEvent::SlotRequested { file_hash };

    // `peer(port)` varies only the port, so all five share one address.
    let _ = state.on_conn_event(t0, peer(1), slot_request.clone(), &no_modifiers());
    for place in 1..=3u16 {
        assert_eq!(
            state.on_conn_event(t0, peer(place + 1), slot_request.clone(), &no_modifiers()),
            vec![
                ServeDecision::CountUploadRequest { file_hash },
                send(
                    peer(place + 1),
                    ServeConnCommand::SetQueueRank { rank: place },
                ),
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
            send(peer(2), ServeConnCommand::SetQueueRank { rank: 1 }),
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

    let status_ask = |file_hash| ServeConnEvent::FileIdSet { file_hash };
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
            ServeConnEvent::Identified {
                user_hash: UserHash::from_bytes([hash_byte; UserHash::BYTE_LEN]),
                client_id: ClientId::from_u32(0x0100_007F),
                connected_server: None,
                tcp_port: 4662,
                udp_port: 0,
                udp_version: 0,
                extended_requests_version: 0,
                crypt: rmule_primitives::CryptStance::disabled(),
                ipv6: None,
                software: client.clone(),
            },
            &no_modifiers(),
        );
    }
    let request = ServeConnEvent::SlotRequested { file_hash };
    let granted = state.on_conn_event(t0, peer(1), request.clone(), &no_modifiers());
    let queued = state.on_conn_event(t0, peer(2), request, &no_modifiers());
    assert!(
        granted.contains(&ServeDecision::Emit(ServeEvent::UploadSlotGranted {
            peer: peer(1),
            file_hash,
            software: Some(amule),
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
        let revised = ServeConnEvent::SoftwareRevised {
            software: named.clone(),
        };
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
                ServeConnEvent::SlotRequested { file_hash },
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
