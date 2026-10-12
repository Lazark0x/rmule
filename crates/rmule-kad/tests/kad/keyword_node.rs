//! Kad keyword **Publisher** + **Requester** + storer dispatch (ADR-0062,
//! execution breakdown 3).
//!
//! Node-level tests drive `KadNode` directly with `0x43`/`0x33`/`0x3B`/`0x4B`
//! datagrams and explicit time; mesh-level acceptance closes the whole keyword
//! publish→store→search loop in an rmule-only `KadMeshSim`. Wire layouts are the
//! documentation-provenance shapes of ADR-0062; capture recipes 1 (rmule
//! publishes → aMule stores) and 3 (rmule searches → aMule serves) are the
//! capture-tier follow-ups — the deterministic tier is green here, the live
//! capture deferred.

use rmule_kad::KadNodeStart;
use std::time::Duration;

use rmule_kad::keyword::keyword_id;
use rmule_kad::keyword_store::{
    KeywordPublishFile, decode_publish_key_req, decode_search_key_res, encode_publish_key_req,
    encode_search_key_req, encode_search_key_res,
};
use rmule_kad::{
    Kad2Message, KadCommand, KadDecoded, KadEvent, KadId, KadInstant, KadKeywordSearchRequest,
    KadNode, KadNodeConfig, KadNodeDiagnostic, KadNodeEndpoint, KadPublishEnd, KadReachability,
    KeywordResultRow, decode_exact,
};
use rmule_primitives::{FileHash, Tag, TagName, TagValue, UserHash, kad_wire_id};
use rmule_testkit::kad_keyword::{file_id, name_tag, size_tag};
use rmule_testkit::kad_mesh::config as mesh_config;
use rmule_testkit::kad_mesh::{A, C, HUB, STORERS, a_endpoint, c_endpoint, hub_endpoint};
use rmule_testkit::kad_node::{hello_req_from, lookup_res_bytes};
use rmule_testkit::kad_source::{contact_endpoint, lan_publisher, searcher};
use rmule_testkit::{KadMeshSim, drain_split};

// The keyword every test targets: the lead token of "keyword …" queries and
// "keyword…" filenames. The Kad ID is the real derivation (MD4 + word-swap).
fn kw() -> KadId {
    keyword_id("keyword")
}

fn config(id: KadId) -> KadNodeConfig {
    KadNodeConfig {
        id,
        tcp_port: 4662,
        udp_port: 4672,
        user_hash: UserHash::from_bytes([0xEE; 16]),
    }
}

/// A storer whose own ID is far from the keyword: LAN senders bypass the
/// tolerance gate, WAN senders sit outside it.
fn far_storer() -> KadNode {
    KadNode::new(KadNodeStart::new(
        config(KadId::from_bytes([0x0F; 16])),
        KadInstant::EPOCH,
    ))
}

/// A stored keyword row as a storer serves it: FILENAME, FILESIZE, and the
/// `TAG_PUBLISHINFO` (`0x33`) word.
fn result_row(id: u8, name: &str, size: u32) -> KeywordResultRow {
    KeywordResultRow {
        file_id: file_id(id),
        tags: vec![
            name_tag(name),
            size_tag(size),
            Tag::new(
                TagName::length_prefixed_id(0x33),
                TagValue::U32(0x0100_0000),
            ),
        ],
    }
}

fn kw_file(id: u8, name: &str, size: u32) -> KeywordPublishFile {
    KeywordPublishFile {
        file_id: file_id(id),
        filename: Some(name.to_owned()),
        size: Some(u64::from(size)),
        tags: Vec::new(),
    }
}

fn publish_key_datagram(keyword: KadId, files: Vec<KeywordPublishFile>) -> Vec<u8> {
    encode_publish_key_req(keyword, &files).encode()
}

fn search_key_datagram(keyword: KadId) -> Vec<u8> {
    encode_search_key_req(keyword, 0, None).encode()
}

fn keyword_result_datagram(sender: KadId, keyword: KadId, rows: &[KeywordResultRow]) -> Vec<u8> {
    let envelopes = encode_search_key_res(sender, keyword, rows);
    assert_eq!(envelopes.len(), 1, "a small answer is one datagram");
    envelopes[0].encode()
}

fn keyword_rows_answered_to(
    datagrams: &[(KadNodeEndpoint, Vec<u8>)],
    to: KadNodeEndpoint,
) -> Vec<KeywordResultRow> {
    datagrams
        .iter()
        .filter(|(dest, _)| *dest == to)
        .flat_map(|(_, bytes)| {
            let KadDecoded::Plain(envelope) =
                decode_exact(bytes).expect("storer answers are well-formed")
            else {
                panic!("storer answers are plain 0xE4");
            };
            decode_search_key_res(&envelope).expect("storer answers re-decode")
        })
        .collect()
}

// --- storer dispatch: 0x43 accept, 0x33 serve, refusal --------------------

#[test]
fn storer_indexes_a_keyword_publish_and_acks_the_load() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();

    node.handle_datagram(
        now,
        lan_publisher(7),
        &publish_key_datagram(kw(), vec![kw_file(0xC1, "keyword.mp3", 4_096)]),
    );
    let (datagrams, events) = drain_split(&mut node);

    // aMule acks the keyword (not the file) with the shared load; a new keyword's
    // first file reports load 1.
    let expected_ack = Kad2Message::PublishRes {
        file: kw(),
        load: 1,
        options: 0,
    }
    .encode()
    .encode();
    assert_eq!(datagrams, vec![(lan_publisher(7), expected_ack)]);
    assert_eq!(
        events,
        vec![
            // The storer's first inbound datagram is also its silent→heard
            // edge.
            KadEvent::HadContact {
                from: lan_publisher(7)
            },
            KadEvent::KeywordPublishServed {
                from: lan_publisher(7),
                keyword: kw(),
                indexed: 1,
                stored: 1,
            }
        ]
    );
}

/// The index's size is known after every change: a publish reports the rows
/// it now holds, and the sweep that expires a stale row reports what remains.
#[test]
fn storer_reports_its_index_size_after_a_publish_and_after_expiry() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();
    node.handle_datagram(
        now,
        lan_publisher(7),
        &publish_key_datagram(
            kw(),
            vec![
                kw_file(0xC1, "keyword.mp3", 4_096),
                kw_file(0xC2, "keyword two.mp3", 4_096),
            ],
        ),
    );
    let (_, events) = drain_split(&mut node);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, KadEvent::KeywordPublishServed { stored: 2, .. })),
        "{events:?}"
    );

    // Past the rows' 24 h lifetime and the 30 min sweep throttle.
    node.tick(now + Duration::from_secs(25 * 60 * 60));
    let (_, events) = drain_split(&mut node);
    assert!(
        events.contains(&KadEvent::KeywordIndexExpired { stored: 0 }),
        "{events:?}"
    );
}

#[test]
fn storer_serves_a_keyword_search_from_the_index() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();
    node.handle_datagram(
        now,
        lan_publisher(7),
        &publish_key_datagram(kw(), vec![kw_file(0xC1, "keyword song.mp3", 4_096)]),
    );
    let _ = drain_split(&mut node);

    node.handle_datagram(now, searcher(), &search_key_datagram(kw()));
    let (datagrams, events) = drain_split(&mut node);

    let rows = keyword_rows_answered_to(&datagrams, searcher());
    assert_eq!(rows.len(), 1);
    let projected = rows[0].project();
    assert_eq!(projected.file_id, file_id(0xC1));
    assert_eq!(projected.filename.as_deref(), Some("keyword song.mp3"));
    assert_eq!(projected.size, Some(4_096));
    assert!(
        projected.publish_info.is_some(),
        "the served row carries TAG_PUBLISHINFO"
    );
    assert_eq!(
        events,
        vec![KadEvent::KeywordSearchServed {
            from: searcher(),
            keyword: kw(),
            rows: 1,
        }]
    );
}

#[test]
fn a_udp_firewalled_storer_refuses_a_keyword_publish_wire_silently() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();
    node.set_reachability(KadReachability {
        udp_firewalled: true,
        ..KadReachability::default()
    });

    node.handle_datagram(
        now,
        lan_publisher(7),
        &publish_key_datagram(kw(), vec![kw_file(0xC1, "keyword.mp3", 4_096)]),
    );
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(datagrams, vec![], "a firewalled storer sends no 0x4B");
    assert_eq!(
        events,
        vec![
            // The refused publish still *reached* the storer: the
            // silent→heard edge is honest either way.
            KadEvent::HadContact {
                from: lan_publisher(7)
            },
            KadEvent::Diagnostic(KadNodeDiagnostic::KeywordPublishRefused {
                from: lan_publisher(7)
            })
        ]
    );

    // And the index stayed empty: a later search misses.
    node.handle_datagram(now, searcher(), &search_key_datagram(kw()));
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(keyword_rows_answered_to(&datagrams, searcher()).len(), 0);
}

#[test]
fn a_malformed_keyword_request_is_diagnosed_without_panic() {
    let now = KadInstant::EPOCH;
    let mut node = far_storer();

    // A 0x43 whose payload is too short to hold even the keyword ID.
    let malformed = rmule_kad::KadEnvelope::plain(0x43, vec![0u8; 4]).encode();
    node.handle_datagram(now, lan_publisher(7), &malformed);
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(datagrams, vec![]);
    // The envelope decoded (a well-formed 0x43 frame with a bad payload), so
    // the silent→heard edge precedes the payload diagnostic.
    assert!(matches!(
        events.as_slice(),
        [
            KadEvent::HadContact { .. },
            KadEvent::Diagnostic(KadNodeDiagnostic::UndecodableKeywordReq { .. })
        ]
    ));
}

// --- requester: walk convergence, merge, dedup, residual filter ------------

/// A contact ID near the keyword: identical in the top 32-bit word (so a WAN
/// publisher clears the tolerance gate) and close in distance (so a walk
/// converges to it).
fn id_near_keyword(d: u8) -> KadId {
    let mut bytes = *kw().as_bytes();
    bytes[12] ^= d;
    KadId::from_bytes(bytes)
}

fn keyword_publish_res(keyword: KadId, load: u8) -> Vec<u8> {
    Kad2Message::PublishRes {
        file: keyword,
        load,
        options: 0,
    }
    .encode()
    .encode()
}

/// A node with three validated contacts near the keyword, driven through a
/// keyword search until it fans the `0x33` to exactly those three.
fn fanned_keyword_searcher(now: KadInstant, query: &str) -> (KadNode, [KadNodeEndpoint; 3]) {
    let mut node = KadNode::new(KadNodeStart::new(
        config(KadId::from_bytes([0x0F; 16])),
        KadInstant::EPOCH,
    ));
    for d in [10, 20, 30] {
        node.handle_datagram(
            now,
            contact_endpoint(d),
            &hello_req_from(id_near_keyword(d), contact_endpoint(d)),
        );
    }
    let _ = drain_split(&mut node);
    node.handle_command(
        now,
        KadCommand::SearchKeywords {
            request: KadKeywordSearchRequest::new(query),
        },
    );
    let _ = drain_split(&mut node);
    for d in [10, 20, 30] {
        node.handle_datagram(now, contact_endpoint(d), &lookup_res_bytes(kw(), &[]));
    }
    (
        node,
        [
            contact_endpoint(10),
            contact_endpoint(20),
            contact_endpoint(30),
        ],
    )
}

#[test]
fn keyword_search_converges_into_the_plain_0x33_fan() {
    let now = KadInstant::EPOCH;
    let (mut node, fan) = fanned_keyword_searcher(now, "keyword");
    let (datagrams, events) = drain_split(&mut node);

    let expected = search_key_datagram(kw());
    assert_eq!(
        datagrams,
        vec![
            (fan[0], expected.clone()),
            (fan[1], expected.clone()),
            (fan[2], expected),
        ],
        "convergence fans the plain lead-keyword 0x33 to the three closest"
    );
    assert_eq!(events, vec![], "searching is not an outcome yet");
    assert_eq!(
        node.next_wake(),
        Some(now + KadNode::SOURCE_SEARCH_WINDOW),
        "the answer window is armed"
    );
}

#[test]
fn keyword_results_merge_deduped_and_residual_filtered_into_one_stream() {
    let now = KadInstant::EPOCH;
    // A two-word query: the walk targets the lead keyword, the residual word
    // filters returned rows client-side.
    let (mut node, fan) = fanned_keyword_searcher(now, "keyword song");
    let _ = drain_split(&mut node);

    // First storer: one matching file and one that lacks the residual word.
    node.handle_datagram(
        now,
        fan[0],
        &keyword_result_datagram(
            id_near_keyword(10),
            kw(),
            &[
                result_row(0xA1, "keyword song.mp3", 4_096),
                result_row(0xB1, "keyword movie.mp3", 8_192),
            ],
        ),
    );
    let (_, events) = drain_split(&mut node);
    let KadEvent::KeywordsFound { keyword, results } = &events[0] else {
        panic!("expected a KeywordsFound, got {events:?}");
    };
    assert_eq!(*keyword, kw());
    assert_eq!(
        results.len(),
        1,
        "the non-'song' row is residual-filtered out"
    );
    assert_eq!(results[0].file_id, file_id(0xA1));
    assert_eq!(results[0].filename.as_deref(), Some("keyword song.mp3"));

    // Second storer: the same file again (deduped) plus a new match.
    node.handle_datagram(
        now,
        fan[1],
        &keyword_result_datagram(
            id_near_keyword(20),
            kw(),
            &[
                result_row(0xA1, "keyword song.mp3", 4_096),
                result_row(0xC1, "the keyword song live.mp3", 1_024),
            ],
        ),
    );
    let (_, events) = drain_split(&mut node);
    let KadEvent::KeywordsFound { results, .. } = &events[0] else {
        panic!("expected a KeywordsFound, got {events:?}");
    };
    assert_eq!(
        results.len(),
        1,
        "the repeat file is deduped; only the new file surfaces"
    );
    assert_eq!(results[0].file_id, file_id(0xC1));
}

#[test]
fn an_unsearchable_query_is_diagnosed() {
    let now = KadInstant::EPOCH;
    let mut node = KadNode::new(KadNodeStart::new(
        config(KadId::from_bytes([0x0F; 16])),
        KadInstant::EPOCH,
    ));
    node.handle_command(
        now,
        KadCommand::SearchKeywords {
            // No token reaches the 3-byte floor, so no keyword target derives.
            request: KadKeywordSearchRequest::new("a b c"),
        },
    );
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        events,
        vec![KadEvent::Diagnostic(
            KadNodeDiagnostic::UnsearchableKeywordQuery
        )]
    );
}

// --- publisher: fan, ack, embargo, gate -----------------------------------

fn mesh_shared_file() -> rmule_kad::KadSharedFile {
    rmule_kad::KadSharedFile {
        file_hash: FileHash::from_bytes([0xD0; 16]),
        filename: "keyword.mp3".to_owned(),
        size: 4_096,
        complete_sources: 5,
        file_type: Some("Audio".to_owned()),
    }
}

/// The wire-form file ID [`mesh_shared_file`] publishes (the file hash's Kad
/// wire form).
fn published_file_id() -> KadId {
    KadId::from_bytes(kad_wire_id([0xD0; 16]))
}

/// A joined node with three contacts near the keyword, driven through a keyword
/// publish until it fans the `0x43` to exactly those three.
fn fanned_keyword_publisher(now: KadInstant) -> (KadNode, [KadNodeEndpoint; 3]) {
    fanned_keyword_publisher_of(now, mesh_shared_file())
}

/// [`fanned_keyword_publisher`] publishing `file`.
fn fanned_keyword_publisher_of(
    now: KadInstant,
    file: rmule_kad::KadSharedFile,
) -> (KadNode, [KadNodeEndpoint; 3]) {
    let mut node = KadNode::new(KadNodeStart::new(
        config(KadId::from_bytes([0x0F; 16])),
        KadInstant::EPOCH,
    ));
    for d in [10, 20, 30] {
        node.handle_datagram(
            now,
            contact_endpoint(d),
            &hello_req_from(id_near_keyword(d), contact_endpoint(d)),
        );
    }
    let _ = drain_split(&mut node);
    node.handle_command(now, KadCommand::PublishKeywords { file });
    let _ = drain_split(&mut node);
    for d in [10, 20, 30] {
        node.handle_datagram(now, contact_endpoint(d), &lookup_res_bytes(kw(), &[]));
    }
    (
        node,
        [
            contact_endpoint(10),
            contact_endpoint(20),
            contact_endpoint(30),
        ],
    )
}

#[test]
fn keyword_publish_converges_into_the_0x43_fan_carrying_the_file() {
    let now = KadInstant::EPOCH;
    let (mut node, fan) = fanned_keyword_publisher(now);
    let (datagrams, events) = drain_split(&mut node);

    let destinations: Vec<KadNodeEndpoint> = datagrams.iter().map(|(dest, _)| *dest).collect();
    assert_eq!(
        destinations,
        fan.to_vec(),
        "the 0x43 fans to the three closest"
    );
    for (_, bytes) in &datagrams {
        let KadDecoded::Plain(envelope) = decode_exact(bytes).unwrap() else {
            panic!("keyword publishes are plain 0xE4");
        };
        let (keyword, files) = decode_publish_key_req(&envelope).expect("a well-formed 0x43");
        assert_eq!(keyword, kw());
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file_id, published_file_id());
        assert_eq!(files[0].filename.as_deref(), Some("keyword.mp3"));
        assert_eq!(files[0].size, Some(4_096));
    }
    assert_eq!(events, vec![]);
    assert_eq!(node.next_wake(), Some(now + KadNode::PUBLISH_ACK_WINDOW));
}

/// A shared file past 4 GiB publishes its size as `UINT64` (type `0x0B`),
/// as aMule's (`CTagVarInt`, kno `Search.cpp:1714`) and eMuleAI's
/// (`Search.cpp:1650`) keyword publishers do, instead of no `TAG_FILESIZE`
/// at all, which every searcher drops.
#[test]
fn a_file_past_four_gib_publishes_its_uint64_size() {
    const FIVE_GIB: u64 = 5 * 1024 * 1024 * 1024;
    let now = KadInstant::EPOCH;
    let file = rmule_kad::KadSharedFile {
        size: FIVE_GIB,
        ..mesh_shared_file()
    };
    let (mut node, _) = fanned_keyword_publisher_of(now, file);
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(datagrams.len(), 3);

    let size_tag = Tag::new(TagName::length_prefixed_id(0x02), TagValue::U64(FIVE_GIB)).encode();
    assert_eq!(size_tag[0], 0x0B, "TAGTYPE_UINT64");
    for (_, bytes) in &datagrams {
        assert!(
            bytes.windows(size_tag.len()).any(|w| w == size_tag),
            "FILESIZE rides as UINT64: {bytes:02X?}"
        );
        let KadDecoded::Plain(envelope) = decode_exact(bytes).unwrap() else {
            panic!("keyword publishes are plain 0xE4");
        };
        let (_, files) = decode_publish_key_req(&envelope).expect("a well-formed 0x43");
        assert_eq!(files[0].size, Some(FIVE_GIB));
    }
}

#[test]
fn all_keyword_acks_complete_the_publish_and_a_heavy_load_embargoes_it() {
    let now = KadInstant::EPOCH;
    let (mut node, fan) = fanned_keyword_publisher(now);
    let _ = drain_split(&mut node);

    for endpoint in fan {
        node.handle_datagram(now, endpoint, &keyword_publish_res(kw(), 100));
    }
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(datagrams, vec![], "acks trigger no further datagrams");
    assert_eq!(
        events,
        vec![
            KadEvent::KeywordPublishAcked {
                keyword: kw(),
                from: fan[0],
                load: 100,
            },
            KadEvent::KeywordPublishAcked {
                keyword: kw(),
                from: fan[1],
                load: 100,
            },
            KadEvent::KeywordPublishAcked {
                keyword: kw(),
                from: fan[2],
                load: 100,
            },
            KadEvent::KeywordPublishComplete {
                keyword: kw(),
                acked_stores: 3,
                ended_by: KadPublishEnd::AllStoresAcked,
            },
        ]
    );
    // Average load 100 embargoes the keyword the full 7 days, past its plain
    // 24 h republish — so the next wake is the embargo, not the cadence.
    assert_eq!(
        node.next_wake(),
        Some(now + Duration::from_secs(7 * 24 * 60 * 60)),
        "a saturated load embargoes the re-publish"
    );
}

/// Drive one joined publisher under a given reachability and report whether it
/// launched a publish walk (a `0x21` lookup went out).
fn publisher_fans_under(reachability: KadReachability) -> bool {
    let now = KadInstant::EPOCH;
    let mut node = KadNode::new(KadNodeStart::new(
        config(KadId::from_bytes([0x0F; 16])),
        KadInstant::EPOCH,
    ));
    for d in [10, 20, 30] {
        node.handle_datagram(
            now,
            contact_endpoint(d),
            &hello_req_from(id_near_keyword(d), contact_endpoint(d)),
        );
    }
    let _ = drain_split(&mut node);
    node.set_reachability(reachability);
    node.handle_command(
        now,
        KadCommand::PublishKeywords {
            file: mesh_shared_file(),
        },
    );
    let (datagrams, _) = drain_split(&mut node);
    datagrams
        .iter()
        .any(|(_, bytes)| bytes.get(1) == Some(&0x21))
}

#[test]
fn the_publish_gate_is_tcp_open_or_buddy_connected() {
    // Open (the assume-open default): publishes.
    assert!(publisher_fans_under(KadReachability::default()));
    // TCP-firewalled, no buddy: silent.
    assert!(!publisher_fans_under(KadReachability {
        tcp_firewalled: true,
        ..KadReachability::default()
    }));
    // TCP-firewalled but a buddy is connected: publishes (buddy-info rows).
    assert!(publisher_fans_under(KadReachability {
        tcp_firewalled: true,
        buddy_connected: true,
        ..KadReachability::default()
    }));
    // Open and a buddy connected: publishes.
    assert!(publisher_fans_under(KadReachability {
        buddy_connected: true,
        ..KadReachability::default()
    }));
}

#[test]
fn an_unjoined_node_does_not_publish_and_does_not_livelock() {
    let now = KadInstant::EPOCH;
    let mut node = KadNode::new(KadNodeStart::new(
        config(KadId::from_bytes([0x0F; 16])),
        KadInstant::EPOCH,
    ));
    // No contacts ⇒ not joined.
    node.handle_command(
        now,
        KadCommand::PublishKeywords {
            file: mesh_shared_file(),
        },
    );
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(datagrams, vec![], "an unjoined node cannot publish");
    assert_eq!(events, vec![]);
    assert_eq!(
        node.next_wake(),
        None,
        "a due-but-gated publish surfaces no wake — it re-drives on the join, not a busy loop"
    );
}

// --- mesh acceptance: the whole keyword loop closes (recipes 1 + 3) --------

// publisher
// requester
/// A bootstrapped mesh: a far hub, three real storers near the keyword, a
/// publisher, and a requester — all TEST-NET (non-LAN), so a keyword publish is
/// accepted only through the storers' tolerance gate.
fn keyword_mesh() -> KadMeshSim {
    let mut sim = KadMeshSim::new()
        .with_node(
            HUB,
            mesh_config(KadId::from_bytes([0xF0; 16]), hub_endpoint(), 0xF0),
            hub_endpoint(),
        )
        .with_node(
            A,
            mesh_config(KadId::from_bytes([0x0F; 16]), a_endpoint(), 0xAA),
            a_endpoint(),
        )
        .with_node(
            C,
            mesh_config(KadId::from_bytes([0xE0; 16]), c_endpoint(), 0xCC),
            c_endpoint(),
        );
    for (label, d) in STORERS {
        sim = sim.with_node(
            label,
            mesh_config(id_near_keyword(d), contact_endpoint(d), d),
            contact_endpoint(d),
        );
    }
    for (label, _) in STORERS {
        sim.command(
            label,
            KadCommand::Bootstrap {
                endpoint: hub_endpoint(),
            },
        );
    }
    sim.run_until_idle(10_000);
    sim.command(
        A,
        KadCommand::Bootstrap {
            endpoint: hub_endpoint(),
        },
    );
    sim.command(
        C,
        KadCommand::Bootstrap {
            endpoint: hub_endpoint(),
        },
    );
    sim.run_until_idle(10_000);
    sim
}

/// The loop closes (ADR-0062 breakdown 3): the whole keyword round trip runs
/// inside an rmule-only mesh — A publishes a shared file's keyword, the three
/// real storers nearest the keyword index it, and C's keyword search returns the
/// file, deduped into one result. Deterministic: two builds produce equal traces.
#[test]
fn mesh_keyword_publish_store_search_closes_the_loop() {
    let build = || {
        let mut sim = keyword_mesh();
        sim.command(
            A,
            KadCommand::PublishKeywords {
                file: mesh_shared_file(),
            },
        );
        let after_publish = sim.now() + Duration::from_secs(30);
        sim.run_until(after_publish, 50_000);
        sim.command(
            C,
            KadCommand::SearchKeywords {
                request: KadKeywordSearchRequest::new("keyword"),
            },
        );
        let after_search = sim.now() + Duration::from_secs(30);
        sim.run_until(after_search, 50_000);
        sim
    };
    let sim = build();

    // The publisher saw every fanned storer ack and completed early.
    let publish_complete: Vec<&KadEvent> = sim
        .trace()
        .iter()
        .filter(|(_, at, event)| {
            *at == A && matches!(event, KadEvent::KeywordPublishComplete { .. })
        })
        .map(|(_, _, event)| event)
        .collect();
    assert_eq!(
        publish_complete,
        vec![&KadEvent::KeywordPublishComplete {
            keyword: kw(),
            acked_stores: 3,
            ended_by: KadPublishEnd::AllStoresAcked,
        }]
    );

    // Each nearest storer indexed A's keyword publish.
    for (label, _) in STORERS {
        let served: Vec<&KadEvent> = sim
            .trace()
            .iter()
            .filter(|(_, at, event)| {
                *at == label && matches!(event, KadEvent::KeywordPublishServed { .. })
            })
            .map(|(_, _, event)| event)
            .collect();
        assert_eq!(
            served,
            vec![&KadEvent::KeywordPublishServed {
                from: a_endpoint(),
                keyword: kw(),
                indexed: 1,
                stored: 1,
            }],
            "{label} indexed exactly A's keyword publish"
        );
    }

    // C surfaced the file exactly once (the three storers' answers dedup into
    // the one search stream).
    let found: Vec<&KadEvent> = sim
        .trace()
        .iter()
        .filter(|(_, at, event)| *at == C && matches!(event, KadEvent::KeywordsFound { .. }))
        .map(|(_, _, event)| event)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "the file surfaces once, deduped across storers"
    );
    let KadEvent::KeywordsFound { keyword, results } = found[0] else {
        unreachable!()
    };
    assert_eq!(*keyword, kw());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].file_id, published_file_id());
    assert_eq!(results[0].filename.as_deref(), Some("keyword.mp3"));

    assert_eq!(sim.trace(), build().trace());
}
