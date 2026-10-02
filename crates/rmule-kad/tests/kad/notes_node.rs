//! Kad notes layer (`0x35`/`0x45`): graceful via **Empty-Storer Parity**
//! (ADR-0063).
//!
//! rmule implements no notes store — no comments/ratings feature — but must
//! behave exactly like an aMule storer whose notes index is permanently empty
//! and permanently refusing: every inbound `0x35`/`0x45` is classified through
//! aMule's own gate order and counted, but never answered. Decode vectors
//! exercise the wire codec directly; `classify_publish` order tests pin the
//! gate sequence in isolation; node-level tests drive `KadNode::
//! handle_datagram` and assert wire silence on every branch (the load-bearing
//! property) through the real dispatch; a mesh-sim walk proves a notes
//! request mid-walk never disturbs an unrelated source search.

use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_kad::notes::{
    NotesDecodeError, NotesPublishRefusal, classify_publish, decode_publish_notes_req,
    decode_search_notes_req,
};
use rmule_kad::{
    Kad2Message, Kad2NodeInfo, KadCommand, KadEnvelope, KadEvent, KadId, KadInstant, KadNode,
    KadNodeConfig, KadNodeDiagnostic, KadNodeEndpoint, KadReachability, KadSearchEnd,
    KadSourceLookupRequest,
};
use rmule_primitives::{Ed2kText, FileHash, SourceLookupTarget, Tag, TagName, TagValue, UserHash};
use rmule_testkit::kad_node::{endpoint, id, lookup_res_bytes};
use rmule_testkit::{FakeKadPeer, KadMeshSim, drain_split};

fn config(id_byte: u8, udp_port: u16) -> KadNodeConfig {
    KadNodeConfig {
        id: id(id_byte),
        tcp_port: 4662,
        udp_port,
        user_hash: UserHash::from_bytes([id_byte; 16]),
    }
}

fn lan_endpoint(host: u8, port: u16) -> KadNodeEndpoint {
    KadNodeEndpoint::new(Ipv4Addr::new(10, 0, 0, host), port)
}

// --- raw wire construction --------------------------------------------------
//
// rmule never emits 0x35/0x45 (Empty-Storer Parity, ADR-0063), so there is no
// production encoder to reuse for building test datagrams — these mirror
// aMule's own emissions by hand, the same posture `mesh_sim.rs`'s adversarial
// barrage datagrams use.

fn search_notes_datagram(target: KadId, file_size: u64) -> Vec<u8> {
    let mut datagram = vec![0xE4, 0x35];
    datagram.extend_from_slice(target.as_bytes());
    datagram.extend_from_slice(&file_size.to_le_bytes());
    datagram
}

fn publish_notes_datagram(key: KadId, source_id: [u8; 16], tags: &[Tag]) -> Vec<u8> {
    let mut datagram = vec![0xE4, 0x45];
    datagram.extend_from_slice(key.as_bytes());
    datagram.extend_from_slice(&source_id);
    datagram.push(u8::try_from(tags.len()).unwrap());
    for tag in tags {
        datagram.extend_from_slice(&tag.encode());
    }
    datagram
}

fn rating_tag(value: u32) -> Tag {
    Tag::new(TagName::length_prefixed_id(0x33), TagValue::U32(value))
}

fn comment_tag(text: &str) -> Tag {
    Tag::new(
        TagName::length_prefixed_id(0x01),
        TagValue::String(Ed2kText::from_utf8(text.to_owned())),
    )
}

// ===========================================================================
// Decode vectors
// ===========================================================================

#[test]
fn decode_search_notes_req_reads_the_24_byte_payload() {
    let mut payload = Vec::new();
    payload.extend_from_slice(id(0x11).as_bytes());
    payload.extend_from_slice(&4_096u64.to_le_bytes());

    let (target, file_size) = decode_search_notes_req(&KadEnvelope::plain(0x35, payload)).unwrap();
    assert_eq!(target, id(0x11));
    assert_eq!(file_size, 4_096);
}

#[test]
fn decode_search_notes_req_rejects_a_truncated_payload() {
    let payload = vec![0u8; 23]; // one byte short of target(16)+filesize(8)
    assert_eq!(
        decode_search_notes_req(&KadEnvelope::plain(0x35, payload)),
        Err(NotesDecodeError::Malformed {
            reason: "notes search file size"
        })
    );
}

#[test]
fn decode_search_notes_req_rejects_trailing_bytes() {
    let mut payload = Vec::new();
    payload.extend_from_slice(id(0x11).as_bytes());
    payload.extend_from_slice(&4_096u64.to_le_bytes());
    payload.push(0xFF); // one byte past the documented 24

    assert_eq!(
        decode_search_notes_req(&KadEnvelope::plain(0x35, payload)),
        Err(NotesDecodeError::Malformed {
            reason: "trailing bytes after the notes search payload"
        })
    );
}

#[test]
fn decode_search_notes_req_rejects_the_wrong_opcode() {
    assert_eq!(
        decode_search_notes_req(&KadEnvelope::plain(0x45, vec![0u8; 24])),
        Err(NotesDecodeError::NotASearchNotesReq { opcode: 0x45 })
    );
}

#[test]
fn decode_publish_notes_req_reads_the_key_past_a_tolerant_tag_list() {
    let tags = vec![comment_tag("nice rip"), rating_tag(5)];
    let mut payload = Vec::new();
    payload.extend_from_slice(id(0x22).as_bytes());
    payload.extend_from_slice(&[0xAB; 16]);
    payload.push(u8::try_from(tags.len()).unwrap());
    for tag in &tags {
        payload.extend_from_slice(&tag.encode());
    }

    let key = decode_publish_notes_req(&KadEnvelope::plain(0x45, payload)).unwrap();
    assert_eq!(key, id(0x22));
}

#[test]
fn decode_publish_notes_req_rejects_a_truncated_header() {
    let payload = vec![0u8; 20]; // short of key(16)+sourceID(16)+tagcnt(1)
    assert_eq!(
        decode_publish_notes_req(&KadEnvelope::plain(0x45, payload)),
        Err(NotesDecodeError::Malformed {
            reason: "notes publish source ID"
        })
    );
}

#[test]
fn decode_publish_notes_req_rejects_an_oversized_tag_count() {
    // Declares five tags but carries none — the tag-bloat decode vector.
    let mut payload = Vec::new();
    payload.extend_from_slice(id(0x22).as_bytes());
    payload.extend_from_slice(&[0xAB; 16]);
    payload.push(5);

    assert_eq!(
        decode_publish_notes_req(&KadEnvelope::plain(0x45, payload)),
        Err(NotesDecodeError::Malformed {
            reason: "notes publish tag is truncated or malformed"
        })
    );
}

#[test]
fn decode_publish_notes_req_rejects_a_malformed_tag_mid_list() {
    // The first tag is well-formed; the second is truncated to a single
    // leading byte with nothing behind it.
    let mut payload = Vec::new();
    payload.extend_from_slice(id(0x22).as_bytes());
    payload.extend_from_slice(&[0xAB; 16]);
    payload.push(2);
    payload.extend_from_slice(&comment_tag("ok").encode());
    payload.push(0x03);

    assert_eq!(
        decode_publish_notes_req(&KadEnvelope::plain(0x45, payload)),
        Err(NotesDecodeError::Malformed {
            reason: "notes publish tag is truncated or malformed"
        })
    );
}

#[test]
fn decode_publish_notes_req_rejects_trailing_bytes() {
    let mut payload = Vec::new();
    payload.extend_from_slice(id(0x22).as_bytes());
    payload.extend_from_slice(&[0xAB; 16]);
    payload.push(0); // no tags
    payload.push(0xFF); // trailing byte past the declared (empty) tag list

    assert_eq!(
        decode_publish_notes_req(&KadEnvelope::plain(0x45, payload)),
        Err(NotesDecodeError::Malformed {
            reason: "trailing bytes after the notes publish tag list"
        })
    );
}

#[test]
fn decode_publish_notes_req_rejects_the_wrong_opcode() {
    assert_eq!(
        decode_publish_notes_req(&KadEnvelope::plain(0x35, vec![0u8; 33])),
        Err(NotesDecodeError::NotAPublishNotesReq { opcode: 0x35 })
    );
}

// ===========================================================================
// Gate-ordered classification, in isolation (`classify_publish`)
// ===========================================================================

#[test]
fn classify_publish_orders_firewalled_before_tolerance() {
    // Firewalled AND outside tolerance: firewalled wins — it is checked
    // first, exactly like aMule's early return before a payload byte past
    // the header is inspected (ADR-0063).
    let own = id(0x00);
    let far_key = id(0xFF); // every top-word bit differs from `own`
    let wan_sender = Ipv4Addr::new(203, 0, 113, 9);

    assert_eq!(
        classify_publish(own, true, wan_sender, far_key),
        NotesPublishRefusal::Firewalled
    );
}

#[test]
fn classify_publish_falls_through_to_tolerance_when_open() {
    let own = id(0x00);
    let far_key = id(0xFF);
    let wan_sender = Ipv4Addr::new(203, 0, 113, 9);

    assert_eq!(
        classify_publish(own, false, wan_sender, far_key),
        NotesPublishRefusal::Tolerance
    );
}

#[test]
fn classify_publish_exempts_lan_senders_from_tolerance() {
    let own = id(0x00);
    let far_key = id(0xFF);
    let lan_sender = Ipv4Addr::new(10, 0, 0, 9);

    assert_eq!(
        classify_publish(own, false, lan_sender, far_key),
        NotesPublishRefusal::Capacity,
        "a LAN sender bypasses the tolerance gate and always reaches capacity"
    );
}

#[test]
fn classify_publish_falls_through_to_capacity_when_every_gate_clears() {
    let own = id(0x00);
    let near_key = id(0x00); // identical top word: within tolerance
    let wan_sender = Ipv4Addr::new(203, 0, 113, 9);

    assert_eq!(
        classify_publish(own, false, wan_sender, near_key),
        NotesPublishRefusal::Capacity,
        "the permanently-empty index is a permanent terminal refusal, never an accept"
    );
}

// ===========================================================================
// Node dispatch: wire silence on every branch (load-bearing) + the four
// classification counters end to end
// ===========================================================================

fn far_node() -> KadNode {
    KadNode::new(config(0x0F, 4672))
}

#[test]
fn a_notes_search_is_served_empty_and_wire_silent() {
    let now = KadInstant::EPOCH;
    let mut node = far_node();
    let searcher = endpoint(9, 4909);

    node.handle_datagram(now, searcher, &search_notes_datagram(id(0x11), 4_096));
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(
        datagrams,
        vec![],
        "0x35 never replies, hit or miss — Empty-Storer Parity"
    );
    assert_eq!(
        events,
        vec![
            KadEvent::HadContact { from: searcher },
            KadEvent::NotesSearchServedEmpty {
                from: searcher,
                target: id(0x11),
            }
        ]
    );
}

#[test]
fn a_udp_firewalled_node_refuses_a_notes_publish_wire_silently() {
    let now = KadInstant::EPOCH;
    let mut node = far_node();
    node.set_reachability(KadReachability {
        udp_firewalled: true,
        ..KadReachability::default()
    });
    let publisher = lan_endpoint(7, 4000);

    node.handle_datagram(
        now,
        publisher,
        &publish_notes_datagram(id(0x0F), [0xAB; 16], &[]),
    );
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(datagrams, vec![], "0x45 never acks — Empty-Storer Parity");
    assert_eq!(
        events,
        vec![
            KadEvent::HadContact { from: publisher },
            KadEvent::Diagnostic(KadNodeDiagnostic::NotesPublishRefused {
                from: publisher,
                reason: NotesPublishRefusal::Firewalled,
            })
        ]
    );
}

#[test]
fn a_notes_publish_outside_tolerance_from_a_wan_sender_is_refused_wire_silently() {
    let now = KadInstant::EPOCH;
    let mut node = far_node(); // own id 0x0F
    let publisher = endpoint(9, 4909); // non-LAN

    // Key 0xFF differs in every top-word bit from the node's own 0x0F id.
    node.handle_datagram(
        now,
        publisher,
        &publish_notes_datagram(id(0xFF), [0xAB; 16], &[]),
    );
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(datagrams, vec![]);
    assert_eq!(
        events,
        vec![
            KadEvent::HadContact { from: publisher },
            KadEvent::Diagnostic(KadNodeDiagnostic::NotesPublishRefused {
                from: publisher,
                reason: NotesPublishRefusal::Tolerance,
            })
        ]
    );
}

#[test]
fn an_in_tolerance_notes_publish_is_refused_at_capacity_wire_silently() {
    let now = KadInstant::EPOCH;
    let mut node = far_node(); // own id 0x0F
    let publisher = endpoint(9, 4909); // non-LAN, but the key is in tolerance

    node.handle_datagram(
        now,
        publisher,
        &publish_notes_datagram(
            id(0x0F),
            [0xAB; 16],
            &[comment_tag("great file"), rating_tag(5)],
        ),
    );
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(datagrams, vec![]);
    assert_eq!(
        events,
        vec![
            KadEvent::HadContact { from: publisher },
            KadEvent::Diagnostic(KadNodeDiagnostic::NotesPublishRefused {
                from: publisher,
                reason: NotesPublishRefusal::Capacity,
            })
        ],
        "the gates cleared, but the permanently-empty index still refuses"
    );
}

#[test]
fn dispatch_orders_firewalled_before_tolerance_through_the_real_handler() {
    let now = KadInstant::EPOCH;
    let mut node = far_node();
    node.set_reachability(KadReachability {
        udp_firewalled: true,
        ..KadReachability::default()
    });
    let publisher = endpoint(9, 4909); // also outside tolerance

    node.handle_datagram(
        now,
        publisher,
        &publish_notes_datagram(id(0xFF), [0xAB; 16], &[]),
    );
    let (_, events) = drain_split(&mut node);

    assert_eq!(
        events,
        vec![
            KadEvent::HadContact { from: publisher },
            KadEvent::Diagnostic(KadNodeDiagnostic::NotesPublishRefused {
                from: publisher,
                reason: NotesPublishRefusal::Firewalled,
            })
        ],
        "firewalled is classified before tolerance even when both gates would fail"
    );
}

#[test]
fn a_malformed_notes_search_is_diagnosed_wire_silently_without_panic() {
    let now = KadInstant::EPOCH;
    let mut node = far_node();
    let sender = endpoint(9, 4909);

    let malformed = KadEnvelope::plain(0x35, vec![0u8; 4]).encode();
    node.handle_datagram(now, sender, &malformed);
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(datagrams, vec![]);
    assert!(matches!(
        events.as_slice(),
        [
            KadEvent::HadContact { .. },
            KadEvent::Diagnostic(KadNodeDiagnostic::UndecodableNotesReq { .. })
        ]
    ));
}

#[test]
fn a_malformed_notes_publish_is_diagnosed_wire_silently_without_panic() {
    let now = KadInstant::EPOCH;
    let mut node = far_node();
    let sender = endpoint(9, 4909);

    let malformed = KadEnvelope::plain(0x45, vec![0u8; 4]).encode();
    node.handle_datagram(now, sender, &malformed);
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(datagrams, vec![]);
    assert!(matches!(
        events.as_slice(),
        [
            KadEvent::HadContact { .. },
            KadEvent::Diagnostic(KadNodeDiagnostic::UndecodableNotesReq { .. })
        ]
    ));
}

// ===========================================================================
// Mesh-sim walk: a notes request mid-walk never disturbs it
// ===========================================================================

const SEARCHER: &str = "searcher";
const SEARCHER_ID_BYTE: u8 = 0x0F;

fn searcher_endpoint() -> KadNodeEndpoint {
    endpoint(1, 4701)
}

fn storer_fake_endpoint() -> KadNodeEndpoint {
    endpoint(2, 4702)
}

fn noise_endpoint() -> KadNodeEndpoint {
    endpoint(9, 4909)
}

fn hello_req_from(sender: KadId, from: KadNodeEndpoint) -> Vec<u8> {
    Kad2Message::HelloReq(Kad2NodeInfo {
        id: sender,
        tcp_port: 4662,
        version: 8,
        udp_port_tag: Some(from.udp_port()),
        misc_options: 0,
    })
    .encode()
    .encode()
}

fn search_target() -> KadId {
    id(0x77)
}

fn search_request() -> KadSourceLookupRequest {
    KadSourceLookupRequest::new(SourceLookupTarget::new(
        FileHash::from_bytes([0x77; 16]),
        4_096,
    ))
}

/// A searcher with one known contact (a scripted fake storer that answers the
/// walk's lookup round with zero new contacts, forcing immediate convergence
/// into the search phase) — everything needed for `SearchSources` to open a
/// real, timed search window.
fn notes_walk_mesh() -> KadMeshSim {
    let storer_id = id(0x78);
    let storer = FakeKadPeer::new()
        .unsolicited_at(
            KadInstant::EPOCH,
            searcher_endpoint(),
            hello_req_from(storer_id, storer_fake_endpoint()),
        )
        .once_on_opcode(0x21, vec![lookup_res_bytes(search_target(), &[])]);
    KadMeshSim::new()
        .with_node(
            SEARCHER,
            config(SEARCHER_ID_BYTE, searcher_endpoint().udp_port()),
            searcher_endpoint(),
        )
        .with_fake(storer_fake_endpoint(), storer)
}

#[test]
fn a_notes_search_mid_walk_is_classified_silently_and_the_walk_still_completes() {
    let build = || {
        // First let the storer's hello land (routing warms) so the walk seeds
        // with a real, servable contact — *then* schedule the notes noise
        // relative to that settled instant, and only then open the search.
        // Issuing the search before the hello lands would seed the walk with
        // zero candidates and end it immediately (`NoSearchableContacts`),
        // proving nothing about mid-walk behavior.
        let mut sim = notes_walk_mesh();
        sim.run_until_idle(1_000);
        let noise_at = sim.now() + Duration::from_millis(5_000);
        sim = sim.with_fake(
            noise_endpoint(),
            FakeKadPeer::new().unsolicited_at(
                noise_at,
                searcher_endpoint(),
                search_notes_datagram(id(0x33), 1_024),
            ),
        );
        sim.command(
            SEARCHER,
            KadCommand::SearchSources {
                request: search_request(),
            },
        );
        sim.run_until_idle(10_000);
        sim
    };
    let sim = build();

    // The bystander's mid-window notes search was classified — served
    // empty — and got no reply routed back to it.
    let notes_served: Vec<&KadEvent> = sim
        .trace()
        .iter()
        .filter(|(_, at, event)| {
            *at == SEARCHER && matches!(event, KadEvent::NotesSearchServedEmpty { .. })
        })
        .map(|(_, _, event)| event)
        .collect();
    assert_eq!(
        notes_served,
        vec![&KadEvent::NotesSearchServedEmpty {
            from: noise_endpoint(),
            target: id(0x33),
        }]
    );
    assert_eq!(
        sim.fake(noise_endpoint()).received(),
        &[],
        "the notes search elicits no reply — Empty-Storer Parity, proven at mesh level"
    );

    // The unrelated real source search, open the whole time the notes noise
    // landed, still completes on schedule — undisturbed.
    let search_complete: Vec<&KadEvent> = sim
        .trace()
        .iter()
        .filter(|(_, at, event)| {
            *at == SEARCHER && matches!(event, KadEvent::SourceSearchComplete { .. })
        })
        .map(|(_, _, event)| event)
        .collect();
    assert_eq!(
        search_complete,
        vec![&KadEvent::SourceSearchComplete {
            target: search_target(),
            result_rows: 0,
            ended_by: KadSearchEnd::WindowElapsed,
        }],
        "the notes noise mid-window never disturbs the real search's completion"
    );

    assert_eq!(
        sim.trace(),
        build().trace(),
        "deterministic: same trace twice"
    );
}
