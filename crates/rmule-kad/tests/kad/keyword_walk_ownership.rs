//! Kad walk ownership (ADR-0062): one walk holds a target at a time, and every
//! keyword search command naming a target is answered by one
//! `KeywordSearchComplete` for it — whether it starts a walk, joins one,
//! preempts a keyword publish, or finds the target held by another walk.
//! Driven on `KadNode` with explicit time.

use rmule_kad::KadNodeStart;
use rmule_kad::keyword::keyword_id;
use rmule_kad::keyword_store::{KeywordResultRow, encode_search_key_res};
use rmule_kad::{
    KadCommand, KadEvent, KadId, KadInstant, KadKeywordSearchRequest, KadNode, KadNodeConfig,
    KadNodeDiagnostic, KadNodeEndpoint, KadSearchEnd, KadSourceLookupRequest,
};
use rmule_primitives::{FileHash, SourceLookupTarget, UserHash, kad_wire_id};
use rmule_testkit::drain_split;
use rmule_testkit::kad_keyword::{file_id, name_tag, size_tag};
use rmule_testkit::kad_node::{hello_req_from, lookup_res_bytes};
use rmule_testkit::kad_source::contact_endpoint;

const LOOKUP_REQ: u8 = 0x21;
const SEARCH_KEY_REQ: u8 = 0x33;

fn kw() -> KadId {
    keyword_id("keyword")
}

fn near_keyword(d: u8) -> KadId {
    let mut bytes = *kw().as_bytes();
    bytes[12] ^= d;
    KadId::from_bytes(bytes)
}

const CONTACTS: [u8; 3] = [10, 20, 30];

/// A joined, TCP-open node with three contacts near the keyword.
fn node(now: KadInstant) -> KadNode {
    let mut node = KadNode::new(KadNodeStart::new(
        KadNodeConfig {
            id: KadId::from_bytes([0x0F; 16]),
            tcp_port: 4662,
            udp_port: 4672,
            user_hash: UserHash::from_bytes([0xEE; 16]),
        },
        KadInstant::EPOCH,
    ));
    for d in CONTACTS {
        node.handle_datagram(
            now,
            contact_endpoint(d),
            &hello_req_from(near_keyword(d), contact_endpoint(d)),
        );
    }
    let _ = drain_split(&mut node);
    node
}

fn search(node: &mut KadNode, now: KadInstant, query: &str) {
    node.handle_command(
        now,
        KadCommand::SearchKeywords {
            request: KadKeywordSearchRequest::new(query),
        },
    );
}

fn publish(node: &mut KadNode, now: KadInstant) {
    node.handle_command(
        now,
        KadCommand::PublishKeywords {
            file: rmule_kad::KadSharedFile {
                file_hash: FileHash::from_bytes([0xD0; 16]),
                filename: "keyword.mp3".to_owned(),
                size: 4_096,
                complete_sources: 5,
                file_type: Some("Audio".to_owned()),
            },
        },
    );
}

/// Answer every contact's lookup with no closer contacts, so the walk on the
/// keyword converges and fans its terminal request.
fn converge(node: &mut KadNode, now: KadInstant) {
    for d in CONTACTS {
        node.handle_datagram(now, contact_endpoint(d), &lookup_res_bytes(kw(), &[]));
    }
}

fn opcodes(datagrams: &[(KadNodeEndpoint, Vec<u8>)]) -> Vec<u8> {
    datagrams
        .iter()
        .filter_map(|(_, bytes)| bytes.get(1).copied())
        .collect()
}

fn keyword_completions(events: &[KadEvent]) -> Vec<(KadId, KadSearchEnd)> {
    events
        .iter()
        .filter_map(|event| match event {
            KadEvent::KeywordSearchComplete {
                keyword, ended_by, ..
            } => Some((*keyword, *ended_by)),
            _ => None,
        })
        .collect()
}

/// The operator's search on a keyword the node is publishing takes the target:
/// the publish gives way without a completion, the search walks and ends, and
/// the publish round runs again once the search has freed the keyword.
#[test]
fn a_keyword_search_preempts_the_publish_walk_on_its_keyword_and_the_round_runs_after() {
    let now = KadInstant::EPOCH;
    let mut node = node(now);
    publish(&mut node, now);
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(
        opcodes(&datagrams),
        [LOOKUP_REQ; 3],
        "the publish walk runs"
    );

    search(&mut node, now, "keyword");
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(
        events,
        [KadEvent::Diagnostic(
            KadNodeDiagnostic::KeywordPublishPreempted { keyword: kw() }
        )],
        "the publish ends without a completion"
    );
    assert_eq!(opcodes(&datagrams), [LOOKUP_REQ; 3], "the search walks");

    converge(&mut node, now);
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(opcodes(&datagrams), [SEARCH_KEY_REQ; 3]);
    let window_end = now + KadNode::SOURCE_SEARCH_WINDOW;
    assert_eq!(
        node.next_wake(),
        Some(window_end),
        "the due round waits for the search, it does not wake the node"
    );

    node.tick(window_end);
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(
        keyword_completions(&events),
        [(kw(), KadSearchEnd::WindowElapsed)]
    );
    assert_eq!(
        opcodes(&datagrams),
        [LOOKUP_REQ; 3],
        "the preempted round walks again once the keyword is free"
    );
}

/// A round falling due on a keyword being searched stays due and starts when
/// the search ends, rather than waiting out the 24 h cadence.
#[test]
fn a_publish_due_on_a_searched_keyword_starts_when_the_search_ends() {
    let now = KadInstant::EPOCH;
    let mut node = node(now);
    search(&mut node, now, "keyword");
    let _ = drain_split(&mut node);

    publish(&mut node, now);
    let (datagrams, _) = drain_split(&mut node);
    assert_eq!(datagrams, [], "the keyword is held: no publish walk");

    converge(&mut node, now);
    let _ = drain_split(&mut node);
    let window_end = now + KadNode::SOURCE_SEARCH_WINDOW;
    assert_eq!(node.next_wake(), Some(window_end));

    node.tick(window_end);
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(
        keyword_completions(&events),
        [(kw(), KadSearchEnd::WindowElapsed)]
    );
    assert_eq!(
        opcodes(&datagrams),
        [LOOKUP_REQ; 3],
        "the publish walks now"
    );
}

/// A second search on a walked keyword joins the walk: no second walk, a
/// residual screen that keeps what either query would, and one completion.
#[test]
fn a_second_search_on_a_walked_keyword_joins_the_walk_and_shares_its_completion() {
    let now = KadInstant::EPOCH;
    let mut node = node(now);
    search(&mut node, now, "keyword song");
    let _ = drain_split(&mut node);

    search(&mut node, now, "keyword");
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(datagrams, [], "no second walk");
    assert_eq!(
        events,
        [KadEvent::Diagnostic(
            KadNodeDiagnostic::DuplicateKeywordSearch { target: kw() }
        )]
    );

    converge(&mut node, now);
    let _ = drain_split(&mut node);
    let row = KeywordResultRow {
        file_id: file_id(0xB1),
        tags: vec![name_tag("keyword movie.mp3"), size_tag(8_192)],
        aich_roots: Vec::new(),
    };
    let answer = encode_search_key_res(near_keyword(10), kw(), &[row]);
    node.handle_datagram(now, contact_endpoint(10), &answer[0].encode());
    let (_, events) = drain_split(&mut node);
    assert!(
        matches!(&events[..], [KadEvent::KeywordsFound { results, .. }] if results.len() == 1),
        "a row without 'song' reaches the joined plain search: {events:?}"
    );

    node.tick(now + KadNode::SOURCE_SEARCH_WINDOW);
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        keyword_completions(&events),
        [(kw(), KadSearchEnd::WindowElapsed)]
    );
}

/// A source walk whose file hash equals the keyword's ID holds the target: the
/// search is answered at once, so nobody waits on a walk that never starts.
#[test]
fn a_search_on_a_target_a_source_walk_holds_is_answered_at_once() {
    let now = KadInstant::EPOCH;
    let mut node = node(now);
    let colliding = FileHash::from_bytes(kad_wire_id(*kw().as_bytes()));
    let request = KadSourceLookupRequest::new(SourceLookupTarget::new(colliding, 5));
    assert_eq!(request.kad_target(), kw());
    node.handle_command(now, KadCommand::SearchSources { request });
    let _ = drain_split(&mut node);

    search(&mut node, now, "keyword");
    let (datagrams, events) = drain_split(&mut node);
    assert_eq!(datagrams, []);
    assert_eq!(
        keyword_completions(&events),
        [(kw(), KadSearchEnd::TargetHeld)]
    );
}
