//! Kad Requester role (ADR-0043): the α-concurrent lookup walk and
//! the source search it converges into.
//!
//! Node-level tests drive `KadNode` directly with datagrams and explicit time;
//! the mesh-level acceptance legs are [`super::requester_mesh`], which shares
//! this leg's request and fixture helpers. Real-aMule `0x3B` interop is
//! pinned by `captured_source_result`.

use std::net::Ipv4Addr;

use rmule_kad::{
    Kad2Message, KadCommand, KadContact, KadEvent, KadId, KadInstant, KadNode, KadNodeConfig,
    KadNodeDiagnostic, KadNodeEndpoint, KadSearchEnd, KadSourceDiagnostic, KadSourceLookupRequest,
};
use rmule_primitives::{ClientId, FileHash, PeerSource, SourceLookupTarget};
use rmule_testkit::drain_split;
use rmule_testkit::kad_node::{diagnostics_of, hello_req_from, lookup_res_bytes};

/// The captured `0x34` pair (docs/reference/notes/kad-source-lookup.md): the
/// synthetic file hash and the wire target aMule searched for it.
const CAPTURED_FILE_HASH: [u8; 16] = [
    0x8E, 0x30, 0x2D, 0xB5, 0xB8, 0x06, 0xA2, 0x5C, 0x93, 0x85, 0xFC, 0x23, 0xF2, 0x10, 0x62, 0xD2,
];
const CAPTURED_KAD_TARGET: [u8; 16] = [
    0xB5, 0x2D, 0x30, 0x8E, 0x5C, 0xA2, 0x06, 0xB8, 0x23, 0xFC, 0x85, 0x93, 0xD2, 0x62, 0x10, 0xF2,
];

#[test]
fn kad_target_is_the_captured_word_swap_of_the_file_hash() {
    // The wire lookup target is the file hash with each 32-bit word's bytes
    // reversed — proven by the captured 0x34 whose target equalled the file
    // hash under exactly this transform (KadEvidence::KadIdByteOrder).
    let request = KadSourceLookupRequest::new(SourceLookupTarget::new(
        FileHash::from_bytes(CAPTURED_FILE_HASH),
        65_536,
    ));

    assert_eq!(request.kad_target(), KadId::from_bytes(CAPTURED_KAD_TARGET));
}

#[test]
fn search_source_req_encodes_the_captured_layout() {
    // Captured datagram: e4 34 | target(16) | start position 0000 | file size
    // 0000 0100 0000 0000 (65536 LE) — kad-source-lookup.md, retained pcap.
    let datagram = Kad2Message::SearchSourceReq {
        target: KadId::from_bytes(CAPTURED_KAD_TARGET),
        start_position: 0,
        file_size: 65_536,
    }
    .encode()
    .encode();

    let mut expected = vec![0xE4, 0x34];
    expected.extend_from_slice(&CAPTURED_KAD_TARGET);
    expected.extend_from_slice(&[0x00, 0x00]);
    expected.extend_from_slice(&65_536u64.to_le_bytes());
    assert_eq!(datagram, expected);
}

// --- node-level walk tests ------------------------------------------------

pub(super) const OWN_ID_BYTE: u8 = 0x0F;

/// The committed documentation-provenance `0x3B` payload; its embedded target
/// is `CAPTURED_FILE_HASH` (the handwritten fixture predates the word-swap
/// proof). The word-swap is self-inverse, so [`fixture_request`] — a request
/// whose *file hash* is `CAPTURED_KAD_TARGET` — walks toward exactly that
/// embedded target and consumes the committed bytes unmodified.
const FIXTURE_0X3B: &[u8] = include_bytes!(
    "../fixtures/source_lookup/documentation/0x3b-high-id-documented/result_0x3b_high_id.bin"
);

fn requester_node() -> KadNode {
    KadNode::new(KadNodeConfig {
        id: KadId::from_bytes([OWN_ID_BYTE; KadId::BYTE_LEN]),
        tcp_port: 4662,
        udp_port: 4672,
        user_hash: rmule_kad::UserHash::from_bytes([0xEE; 16]),
    })
}

fn request_for(file_hash: [u8; 16]) -> KadSourceLookupRequest {
    KadSourceLookupRequest::new(SourceLookupTarget::new(
        FileHash::from_bytes(file_hash),
        65_536,
    ))
}

pub(super) fn request() -> KadSourceLookupRequest {
    request_for(CAPTURED_FILE_HASH)
}

pub(super) fn target() -> KadId {
    KadId::from_bytes(CAPTURED_KAD_TARGET)
}

/// A request whose walk target is the fixture's embedded target key.
pub(super) fn fixture_request() -> KadSourceLookupRequest {
    request_for(CAPTURED_KAD_TARGET)
}

pub(super) fn fixture_target() -> KadId {
    KadId::from_bytes(CAPTURED_FILE_HASH)
}

/// An ID whose XOR distance to `target` is exactly `d` under the
/// capture-proven ordering: byte 12 is the least significant byte of the
/// least significant 32-bit word (`word_le_msw_first`).
pub(super) fn id_near(target: KadId, d: u8) -> KadId {
    let mut bytes = *target.as_bytes();
    bytes[12] ^= d;
    KadId::from_bytes(bytes)
}

pub(super) fn endpoint_for(d: u8) -> KadNodeEndpoint {
    KadNodeEndpoint::new(Ipv4Addr::new(203, 0, 113, d), 4_000 + u16::from(d))
}

pub(super) fn contact_near(target: KadId, d: u8) -> KadContact {
    KadContact::new(id_near(target, d), endpoint_for(d), 4662, 8)
}

fn lookup_req_bytes(target: KadId, check: KadId) -> Vec<u8> {
    Kad2Message::LookupReq {
        count: 2,
        target,
        check,
    }
    .encode()
    .encode()
}

fn search_source_req_bytes(target: KadId, file_size: u64) -> Vec<u8> {
    Kad2Message::SearchSourceReq {
        target,
        start_position: 0,
        file_size,
    }
    .encode()
    .encode()
}

pub(super) fn fixture_search_res_datagram() -> Vec<u8> {
    let mut bytes = vec![0xE4, 0x3B];
    bytes.extend_from_slice(FIXTURE_0X3B);
    bytes
}

/// A node whose routing table holds Responded contacts at the given target
/// distances (each helloed us directly from its own endpoint).
fn seeded_node(now: KadInstant, target: KadId, distances: &[u8]) -> KadNode {
    let mut node = requester_node();
    for &d in distances {
        node.handle_datagram(
            now,
            endpoint_for(d),
            &hello_req_from(id_near(target, d), endpoint_for(d)),
        );
    }
    let _ = drain_split(&mut node); // hello responses + ContactAdded events
    node
}

/// Drive a fresh node into the searching phase: three seeds are queried, all
/// answer with no closer contacts, so the walk converges and fans the `0x34`
/// to exactly those three. Returns the node and the fan endpoints.
fn searching_node(
    now: KadInstant,
    request: KadSourceLookupRequest,
) -> (KadNode, [KadNodeEndpoint; 3]) {
    let target = request.kad_target();
    let mut node = seeded_node(now, target, &[10, 20, 30]);
    node.handle_command(now, KadCommand::SearchSources { request });
    let _ = drain_split(&mut node);
    for d in [10, 20, 30] {
        node.handle_datagram(now, endpoint_for(d), &lookup_res_bytes(target, &[]));
    }
    let (datagrams, events) = drain_split(&mut node);
    let expected_search = search_source_req_bytes(target, request.target().file_size());
    assert_eq!(
        datagrams,
        vec![
            (endpoint_for(10), expected_search.clone()),
            (endpoint_for(20), expected_search.clone()),
            (endpoint_for(30), expected_search),
        ],
        "convergence fans the 0x34 to the three responded seeds, closest first"
    );
    assert_eq!(events, vec![], "searching is not an outcome yet");
    (node, [endpoint_for(10), endpoint_for(20), endpoint_for(30)])
}

#[test]
fn search_command_launches_alpha_queries_to_the_closest_seeds() {
    let now = KadInstant::EPOCH;
    let mut node = seeded_node(now, target(), &[50, 10, 40, 20, 30]);

    node.handle_command(now, KadCommand::SearchSources { request: request() });
    let (datagrams, events) = drain_split(&mut node);

    // α = 3 in-flight: the three closest seeds, closest first, each asked
    // with the captured 0x21 shape (count 2, walk target, check = its own ID).
    assert_eq!(
        datagrams,
        vec![
            (
                endpoint_for(10),
                lookup_req_bytes(target(), id_near(target(), 10))
            ),
            (
                endpoint_for(20),
                lookup_req_bytes(target(), id_near(target(), 20))
            ),
            (
                endpoint_for(30),
                lookup_req_bytes(target(), id_near(target(), 30))
            ),
        ]
    );
    assert_eq!(events, vec![], "no walk outcome before any reply");
    assert!(
        node.next_wake().is_some(),
        "the per-query timeout must be armed"
    );
}

#[test]
fn search_command_with_an_empty_table_completes_immediately() {
    let now = KadInstant::EPOCH;
    let mut node = requester_node();

    node.handle_command(now, KadCommand::SearchSources { request: request() });
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(datagrams, vec![]);
    assert_eq!(
        events,
        vec![KadEvent::SourceSearchComplete {
            target: target(),
            result_rows: 0,
            ended_by: KadSearchEnd::NoSearchableContacts,
        }]
    );
    assert!(node.next_wake().is_none(), "nothing left to time out");
}

#[test]
fn duplicate_search_command_keeps_the_existing_walk() {
    let now = KadInstant::EPOCH;
    let mut node = seeded_node(now, target(), &[10, 20, 30]);
    node.handle_command(now, KadCommand::SearchSources { request: request() });
    let _ = drain_split(&mut node);

    node.handle_command(now, KadCommand::SearchSources { request: request() });
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(datagrams, vec![], "no second walk is started");
    assert_eq!(
        events,
        vec![KadEvent::Diagnostic(
            KadNodeDiagnostic::DuplicateSourceSearch { target: target() }
        )]
    );
}

#[test]
fn walk_queries_closer_contacts_learned_from_responses() {
    let now = KadInstant::EPOCH;
    let mut node = seeded_node(now, target(), &[100, 110, 120]);
    node.handle_command(now, KadCommand::SearchSources { request: request() });
    let _ = drain_split(&mut node);

    // The closest seed answers with two strictly closer contacts: its freed
    // slot must go to the closest learned candidate.
    let closer = [contact_near(target(), 1), contact_near(target(), 2)];
    node.handle_datagram(now, endpoint_for(100), &lookup_res_bytes(target(), &closer));
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(
        datagrams,
        vec![(
            endpoint_for(1),
            lookup_req_bytes(target(), id_near(target(), 1))
        )],
        "one slot freed, one launch: the closest unqueried candidate"
    );
    assert_eq!(events, vec![]);

    // The next answer frees the next slot for the remaining learned contact.
    node.handle_datagram(now, endpoint_for(110), &lookup_res_bytes(target(), &[]));
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(
        datagrams,
        vec![(
            endpoint_for(2),
            lookup_req_bytes(target(), id_near(target(), 2))
        )]
    );
}

#[test]
fn walk_never_queries_a_lookup_res_row_naming_its_own_id() {
    // aMule capture (run 1790155945): a lookup answer named the asking
    // node itself, and aMule dialed a Kad2Req(StoreFile) at its own public
    // address. Citing the aMule source settles that neither
    // side of aMule actually stops this — `GetClosestTo` excludes nothing
    // about the asker, and `ProcessKademlia2Response`'s self-guard only
    // keeps the persistent routing table clean, not the search candidates.
    // rmule closes the gap on the requester side: a row naming our own ID
    // is dropped before it can ever be queried, even when it out-distances
    // the responder that named it.
    let now = KadInstant::EPOCH;
    let mut node = seeded_node(now, target(), &[100, 110, 120]);
    node.handle_command(now, KadCommand::SearchSources { request: request() });
    let _ = drain_split(&mut node);

    let self_named = KadContact::new(
        KadId::from_bytes([OWN_ID_BYTE; KadId::BYTE_LEN]),
        endpoint_for(200),
        4662,
        8,
    );
    node.handle_datagram(
        now,
        endpoint_for(100),
        &lookup_res_bytes(target(), &[self_named]),
    );
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(
        datagrams,
        vec![],
        "the self-named row is the only candidate freed and it is never dialed"
    );
    assert_eq!(events, vec![]);

    // Control: a real candidate at the same freed slot *is* dialed, proving
    // the assertion above is the self-filter at work and not an unrelated
    // reason the walk stayed quiet.
    let real = contact_near(target(), 1);
    node.handle_datagram(now, endpoint_for(110), &lookup_res_bytes(target(), &[real]));
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(
        datagrams,
        vec![(
            endpoint_for(1),
            lookup_req_bytes(target(), id_near(target(), 1))
        )],
        "a real candidate at the same kind of freed slot is dialed"
    );
}

#[test]
fn silent_contacts_time_out_and_are_not_searched() {
    let now = KadInstant::EPOCH;
    let mut node = seeded_node(now, target(), &[10, 20, 30, 40]);
    node.handle_command(now, KadCommand::SearchSources { request: request() });
    let _ = drain_split(&mut node);

    // d20 answers first: its freed slot immediately refills with the next
    // unqueried candidate (α stays saturated while the fan is short).
    node.handle_datagram(now, endpoint_for(20), &lookup_res_bytes(target(), &[]));
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(
        datagrams,
        vec![(
            endpoint_for(40),
            lookup_req_bytes(target(), id_near(target(), 40))
        )]
    );

    // d30 and d40 answer too; d10 stays silent past the query timeout, which
    // is what finally empties the in-flight set and converges the walk.
    for d in [30, 40] {
        node.handle_datagram(now, endpoint_for(d), &lookup_res_bytes(target(), &[]));
    }
    let _ = drain_split(&mut node);
    node.tick(now + KadNode::LOOKUP_QUERY_TIMEOUT);
    let (datagrams, events) = drain_split(&mut node);
    let expected_search = search_source_req_bytes(target(), 65_536);
    assert_eq!(
        datagrams,
        vec![
            (endpoint_for(20), expected_search.clone()),
            (endpoint_for(30), expected_search.clone()),
            (endpoint_for(40), expected_search),
        ],
        "the fan is the three closest RESPONDED contacts — never the silent one"
    );
    assert_eq!(events, vec![]);
}

#[test]
fn late_lookup_res_after_its_timeout_is_unsolicited() {
    let now = KadInstant::EPOCH;
    let mut node = seeded_node(now, target(), &[10]);
    node.handle_command(now, KadCommand::SearchSources { request: request() });
    let _ = drain_split(&mut node);

    node.tick(now + KadNode::LOOKUP_QUERY_TIMEOUT);
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        events,
        vec![KadEvent::SourceSearchComplete {
            target: target(),
            result_rows: 0,
            ended_by: KadSearchEnd::NoSearchableContacts,
        }],
        "the only seed timing out ends the walk with nothing searchable"
    );

    // The answer arrives after the deadline: hearsay from nowhere.
    node.handle_datagram(
        now + KadNode::LOOKUP_QUERY_TIMEOUT,
        endpoint_for(10),
        &lookup_res_bytes(target(), &[contact_near(target(), 1)]),
    );
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(datagrams, vec![]);
    assert_eq!(
        diagnostics_of(&events),
        vec![KadNodeDiagnostic::UnsolicitedLookupRes {
            from: endpoint_for(10)
        }]
    );
}

#[test]
fn solicited_fixture_search_res_projects_through_the_sealed_boundary() {
    let now = KadInstant::EPOCH;
    let (mut node, fan) = searching_node(now, fixture_request());

    node.handle_datagram(now, fan[0], &fixture_search_res_datagram());
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(datagrams, vec![]);
    assert_eq!(events.len(), 1);
    let KadEvent::SourcesFound { target, candidates } = &events[0] else {
        panic!("expected SourcesFound, got {events:?}");
    };
    assert_eq!(*target, fixture_target());
    // The five documented rows, projected exactly as the sealed decoder does:
    // one direct High ID Peer Source, four row diagnostics.
    assert_eq!(candidates.len(), 5);
    assert_eq!(
        candidates[0].peer_source(),
        Some(PeerSource::new(ClientId::from_u32(0x0A64_33C6), 4662))
    );
    let refusals: Vec<Option<KadSourceDiagnostic>> =
        candidates[1..].iter().map(|row| row.refusal()).collect();
    assert_eq!(
        refusals,
        [
            Some(KadSourceDiagnostic::LowId {
                client_id: ClientId::from_u32(0x0001_0203),
                tcp_port: 4662,
            }),
            Some(KadSourceDiagnostic::BuddyCallback),
            Some(KadSourceDiagnostic::MissingEndpoint),
            Some(KadSourceDiagnostic::UnsupportedSourceType(2)),
        ]
    );

    // The window then closes with the consumed rows counted.
    node.tick(now + KadNode::SOURCE_SEARCH_WINDOW);
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        events,
        vec![KadEvent::SourceSearchComplete {
            target: fixture_target(),
            result_rows: 5,
            ended_by: KadSearchEnd::WindowElapsed,
        }]
    );
    assert!(node.next_wake().is_none());
}

#[test]
fn search_res_during_the_walk_phase_is_unsolicited() {
    let now = KadInstant::EPOCH;
    let mut node = seeded_node(now, fixture_target(), &[10, 20, 30]);
    node.handle_command(
        now,
        KadCommand::SearchSources {
            request: fixture_request(),
        },
    );
    let _ = drain_split(&mut node);

    // A queried contact volunteers a 0x3B before any 0x34 exists.
    node.handle_datagram(now, endpoint_for(10), &fixture_search_res_datagram());
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        diagnostics_of(&events),
        vec![KadNodeDiagnostic::UnsolicitedSearchRes {
            from: endpoint_for(10)
        }],
        "no 0x34 was sent yet, so no endpoint is solicited"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, KadEvent::SourcesFound { .. })),
        "nothing may reach projection"
    );
}

#[test]
fn search_res_from_a_wrong_endpoint_is_unsolicited() {
    let now = KadInstant::EPOCH;
    let (mut node, _fan) = searching_node(now, fixture_request());

    // d99 was never sent a 0x34 (it was never even queried).
    node.handle_datagram(now, endpoint_for(99), &fixture_search_res_datagram());
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        diagnostics_of(&events),
        vec![KadNodeDiagnostic::UnsolicitedSearchRes {
            from: endpoint_for(99)
        }]
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, KadEvent::SourcesFound { .. })),
        "a wrong-endpoint answer must never reach projection"
    );
}

#[test]
fn search_res_answering_a_different_target_is_diagnosed_and_discarded() {
    let now = KadInstant::EPOCH;
    // This walk's target is NOT the fixture's embedded target.
    let (mut node, fan) = searching_node(now, request());

    node.handle_datagram(now, fan[0], &fixture_search_res_datagram());
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        diagnostics_of(&events),
        vec![KadNodeDiagnostic::SearchResTargetMismatch { from: fan[0] }]
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, KadEvent::SourcesFound { .. })),
        "rows answering the wrong target are discarded"
    );
}

#[test]
fn malformed_search_res_from_a_solicited_endpoint_is_a_diagnostic() {
    let now = KadInstant::EPOCH;
    let (mut node, fan) = searching_node(now, fixture_request());

    // Truncated mid-header: shorter than sender + target.
    let truncated = fixture_search_res_datagram()[..20].to_vec();
    node.handle_datagram(now, fan[0], &truncated);
    let (_, events) = drain_split(&mut node);
    assert_eq!(events.len(), 1);
    assert!(
        matches!(
            events[0],
            KadEvent::Diagnostic(KadNodeDiagnostic::MalformedSearchRes { from, .. })
                if from == fan[0]
        ),
        "got {events:?}"
    );
}

#[test]
fn total_silence_ends_the_walk_within_its_budgets() {
    let now = KadInstant::EPOCH;
    let mut node = seeded_node(now, target(), &[10, 20, 30, 40, 50]);
    node.handle_command(now, KadCommand::SearchSources { request: request() });
    let _ = drain_split(&mut node);

    // Nobody ever answers: drive the node purely by its own announced wakes.
    let mut events = Vec::new();
    let mut final_now = now;
    while let Some(wake) = node.next_wake() {
        node.tick(wake);
        final_now = wake;
        events.extend(drain_split(&mut node).1);
    }

    assert_eq!(
        events,
        vec![KadEvent::SourceSearchComplete {
            target: target(),
            result_rows: 0,
            ended_by: KadSearchEnd::NoSearchableContacts,
        }]
    );
    // Five silent seeds resolve in two α-waves of query timeouts.
    assert_eq!(
        final_now,
        now + KadNode::LOOKUP_QUERY_TIMEOUT + KadNode::LOOKUP_QUERY_TIMEOUT,
        "silence must end the walk after exactly two timeout waves"
    );
}

#[test]
fn steering_adversaries_exhaust_the_query_budget_and_the_walk_still_ends() {
    let now = KadInstant::EPOCH;
    let mut node = seeded_node(now, target(), &[250, 251, 252]);
    node.handle_command(now, KadCommand::SearchSources { request: request() });

    // Every queried endpoint instantly answers with two contacts strictly
    // closer than anything seen before — a walk without a query budget would
    // chase this chain forever.
    let mut steer_distance = 200u8;
    let mut lookups_sent = 0usize;
    let mut searches_sent = Vec::new();
    for _round in 0..100 {
        let (datagrams, events) = drain_split(&mut node);
        assert!(
            diagnostics_of(&events).is_empty(),
            "steering must not trip unrelated diagnostics: {events:?}"
        );
        let mut lookups_this_round = Vec::new();
        for (to, bytes) in datagrams {
            match bytes[1] {
                0x21 => lookups_this_round.push(to),
                0x34 => searches_sent.push(to),
                other => panic!("unexpected opcode {other:#x}"),
            }
        }
        if lookups_this_round.is_empty() {
            break;
        }
        for from in lookups_this_round {
            lookups_sent += 1;
            let closer = [
                contact_near(target(), steer_distance),
                contact_near(target(), steer_distance - 1),
            ];
            steer_distance -= 2;
            node.handle_datagram(now, from, &lookup_res_bytes(target(), &closer));
        }
    }

    assert_eq!(
        lookups_sent,
        KadNode::LOOKUP_QUERY_BUDGET,
        "the steering chain is cut by the query budget, never earlier or later"
    );
    assert_eq!(
        searches_sent.len(),
        KadNode::SEARCH_FANOUT,
        "the walk still converges into a search against the closest responders"
    );

    // And the search window still closes it.
    node.tick(now + KadNode::SOURCE_SEARCH_WINDOW);
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        events,
        vec![KadEvent::SourceSearchComplete {
            target: target(),
            result_rows: 0,
            ended_by: KadSearchEnd::WindowElapsed,
        }]
    );
}

#[test]
fn result_budget_completes_the_search_early() {
    let now = KadInstant::EPOCH;
    let (mut node, fan) = searching_node(now, fixture_request());

    // The fixture carries 5 rows; 60 batches exactly exhaust the 300-row
    // budget. The 61st arrives after the walk is gone: unsolicited.
    let datagram = fixture_search_res_datagram();
    let mut sources_batches = 0usize;
    let mut completes = Vec::new();
    let mut trailing = Vec::new();
    for _ in 0..61 {
        node.handle_datagram(now, fan[0], &datagram);
        for event in drain_split(&mut node).1 {
            match event {
                KadEvent::SourcesFound { .. } => sources_batches += 1,
                KadEvent::SourceSearchComplete { .. } => completes.push(event),
                other => trailing.push(other),
            }
        }
    }

    assert_eq!(sources_batches, 60);
    assert_eq!(
        completes,
        vec![KadEvent::SourceSearchComplete {
            target: fixture_target(),
            result_rows: KadNode::SOURCE_RESULT_BUDGET,
            ended_by: KadSearchEnd::ResultBudget,
        }]
    );
    assert_eq!(
        trailing,
        vec![KadEvent::Diagnostic(
            KadNodeDiagnostic::UnsolicitedSearchRes { from: fan[0] }
        )],
        "the 61st batch hits a finished walk: unsolicited"
    );
    assert!(node.next_wake().is_none());
}
